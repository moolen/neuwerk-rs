use super::*;
use neuwerk::controlplane::service_accounts::{ServiceAccountRole, ServiceAccountStore, TokenMeta};
use time::format_description::well_known::Rfc3339;

#[tokio::test]
async fn http_api_authz_enforces_admin_for_mutations() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let dataplane_config = DataplaneConfigStore::new();
    let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(metrics_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("keyset");

    let admin_token = api_auth::mint_token_with_roles(
        &keyset,
        "admin-user",
        None,
        None,
        Some(vec!["admin".to_string()]),
    )
    .unwrap();
    let readonly_token = api_auth::mint_token_with_roles(
        &keyset,
        "readonly-user",
        None,
        None,
        Some(vec!["readonly".to_string()]),
    )
    .unwrap();
    let missing_roles_token =
        api_auth::mint_token_with_roles(&keyset, "missing-roles-user", None, None, None).unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "authz",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let readonly_post = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&readonly_token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(readonly_post.status(), reqwest::StatusCode::FORBIDDEN);

    let missing_roles_post = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&missing_roles_token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_roles_post.status(), reqwest::StatusCode::FORBIDDEN);

    let admin_post = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&admin_token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(admin_post.status().is_success());

    let readonly_list = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&readonly_token.token)
        .send()
        .await
        .unwrap();
    assert!(readonly_list.status().is_success());

    let readonly_sa_create = client
        .post(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(&readonly_token.token)
        .json(&serde_json::json!({"name": "sa-readonly"}))
        .send()
        .await
        .unwrap();
    assert_eq!(readonly_sa_create.status(), reqwest::StatusCode::FORBIDDEN);

    let admin_sa_create = client
        .post(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({"name": "sa-admin", "role": "admin"}))
        .send()
        .await
        .unwrap();
    assert!(admin_sa_create.status().is_success());

    server.abort();
}

#[tokio::test]
async fn http_api_service_account_roles_authorize_mutations_and_fail_closed_on_downgrade() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let dataplane_config = DataplaneConfigStore::new();
    let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("keyset");
    let admin_token = api_auth::mint_token_with_roles(
        &keyset,
        "admin-user",
        None,
        None,
        Some(vec!["admin".to_string()]),
    )
    .unwrap();

    let create_account = client
        .post(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "terraform-prod",
            "description": "terraform automation",
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert!(create_account.status().is_success());
    let account: serde_json::Value = create_account.json().await.unwrap();
    let account_id = account.get("id").and_then(|value| value.as_str()).unwrap();
    assert_eq!(
        account.get("role").and_then(|value| value.as_str()),
        Some("admin")
    );

    let create_admin_token = client
        .post(format!(
            "https://{bind_addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "terraform-admin",
            "ttl": "1h",
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert!(create_admin_token.status().is_success());
    let admin_sa_token: serde_json::Value = create_admin_token.json().await.unwrap();
    let admin_sa_jwt = admin_sa_token
        .get("token")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        admin_sa_token
            .get("token_meta")
            .and_then(|meta| meta.get("role"))
            .and_then(|value| value.as_str()),
        Some("admin")
    );

    let create_readonly_token = client
        .post(format!(
            "https://{bind_addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "terraform-readonly",
            "ttl": "1h",
            "role": "readonly"
        }))
        .send()
        .await
        .unwrap();
    assert!(create_readonly_token.status().is_success());
    let readonly_sa_token: serde_json::Value = create_readonly_token.json().await.unwrap();
    let readonly_sa_jwt = readonly_sa_token
        .get("token")
        .and_then(|value| value.as_str())
        .unwrap();
    assert_eq!(
        readonly_sa_token
            .get("token_meta")
            .and_then(|meta| meta.get("role"))
            .and_then(|value| value.as_str()),
        Some("readonly")
    );

    let create_payload = serde_json::json!({
        "mode": "audit",
        "policy": {
            "default_policy": "deny",
            "source_groups": []
        }
    });
    let readonly_mutation = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(readonly_sa_jwt)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(readonly_mutation.status(), reqwest::StatusCode::FORBIDDEN);

    let admin_mutation = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(admin_sa_jwt)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert!(admin_mutation.status().is_success());

    let invalid_role = client
        .post(format!(
            "https://{bind_addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "impossible",
            "ttl": "1h",
            "role": "owner"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_role.status(), reqwest::StatusCode::BAD_REQUEST);

    let downgrade = client
        .put(format!(
            "https://{bind_addr}/api/v1/service-accounts/{account_id}"
        ))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "terraform-prod",
            "description": "terraform automation",
            "role": "readonly"
        }))
        .send()
        .await
        .unwrap();
    assert!(downgrade.status().is_success());
    let downgraded: serde_json::Value = downgrade.json().await.unwrap();
    assert_eq!(
        downgraded.get("role").and_then(|value| value.as_str()),
        Some("readonly")
    );

    let readonly_account_admin_token = client
        .post(format!(
            "https://{bind_addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .bearer_auth(&admin_token.token)
        .json(&serde_json::json!({
            "name": "too-broad",
            "ttl": "1h",
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        readonly_account_admin_token.status(),
        reqwest::StatusCode::BAD_REQUEST
    );

    let admin_after_downgrade = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(admin_sa_jwt)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        admin_after_downgrade.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(admin_after_downgrade
        .text()
        .await
        .unwrap()
        .contains("token role exceeds current account role"));

    let readonly_still_reads = client
        .get(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(readonly_sa_jwt)
        .send()
        .await
        .unwrap();
    assert!(readonly_still_reads.status().is_success());

    server.abort();
}

#[tokio::test]
async fn http_api_auth_rejects_tokens_outside_clock_skew_window() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let dataplane_config = DataplaneConfigStore::new();
    let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("keyset");
    let now = OffsetDateTime::now_utc();

    let within_future_skew = api_auth::mint_token_at(
        &keyset,
        "future-skew-ok",
        Some(60),
        None,
        now + TimeDuration::seconds(30),
    )
    .unwrap();
    let beyond_future_skew = api_auth::mint_token_at(
        &keyset,
        "future-skew-reject",
        Some(60),
        None,
        now + TimeDuration::seconds(api_auth::CLOCK_SKEW_SECS + 90),
    )
    .unwrap();
    let within_expiry_skew = api_auth::mint_token_at(
        &keyset,
        "expiry-skew-ok",
        Some(1),
        None,
        now - TimeDuration::seconds(30),
    )
    .unwrap();
    let beyond_expiry_skew = api_auth::mint_token_at(
        &keyset,
        "expiry-skew-reject",
        Some(1),
        None,
        now - TimeDuration::seconds(api_auth::CLOCK_SKEW_SECS + 90),
    )
    .unwrap();

    let within_future_resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&within_future_skew.token)
        .send()
        .await
        .unwrap();
    assert!(within_future_resp.status().is_success());

    let within_expiry_resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&within_expiry_skew.token)
        .send()
        .await
        .unwrap();
    assert!(within_expiry_resp.status().is_success());

    let future_reject = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&beyond_future_skew.token)
        .send()
        .await
        .unwrap();
    assert_eq!(future_reject.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(future_reject
        .text()
        .await
        .unwrap()
        .contains("jwt issued in the future"));

    let expired_reject = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&beyond_expiry_skew.token)
        .send()
        .await
        .unwrap();
    assert_eq!(expired_reject.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(expired_reject.text().await.unwrap().contains("jwt expired"));

    server.abort();
}

#[tokio::test]
async fn http_api_service_account_auth_honors_clock_skew_window() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let dataplane_config = DataplaneConfigStore::new();
    let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("keyset");
    let client = http_api_client(&tls_dir).unwrap();
    let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
    let account = service_accounts
        .create_account(
            "svc-skew".to_string(),
            Some("service-account skew coverage".to_string()),
            "test".to_string(),
        )
        .await
        .unwrap();
    let now = OffsetDateTime::now_utc();

    let within_skew = api_auth::mint_service_account_token(
        &keyset,
        &account.id.to_string(),
        Some(1),
        false,
        None,
        Some(vec![ServiceAccountRole::Readonly.as_str().to_string()]),
        now - TimeDuration::seconds(30),
    )
    .unwrap();
    let within_expiry = OffsetDateTime::from_unix_timestamp(within_skew.exp.unwrap())
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let within_token = TokenMeta::new_with_role(
        account.id,
        Some("within-skew".to_string()),
        "test".to_string(),
        within_skew.kid.clone(),
        Some(within_expiry),
        uuid::Uuid::parse_str(&within_skew.jti).unwrap(),
        ServiceAccountRole::Readonly,
    )
    .unwrap();
    service_accounts.write_token(&within_token).await.unwrap();

    let beyond_skew = api_auth::mint_service_account_token(
        &keyset,
        &account.id.to_string(),
        Some(1),
        false,
        None,
        Some(vec![ServiceAccountRole::Readonly.as_str().to_string()]),
        now - TimeDuration::seconds(api_auth::CLOCK_SKEW_SECS + 90),
    )
    .unwrap();
    let beyond_expiry = OffsetDateTime::from_unix_timestamp(beyond_skew.exp.unwrap())
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let beyond_token = TokenMeta::new_with_role(
        account.id,
        Some("beyond-skew".to_string()),
        "test".to_string(),
        beyond_skew.kid.clone(),
        Some(beyond_expiry),
        uuid::Uuid::parse_str(&beyond_skew.jti).unwrap(),
        ServiceAccountRole::Readonly,
    )
    .unwrap();
    service_accounts.write_token(&beyond_token).await.unwrap();

    let within_resp = client
        .get(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(&within_skew.token)
        .send()
        .await
        .unwrap();
    assert!(within_resp.status().is_success());

    let beyond_resp = client
        .get(format!("https://{bind_addr}/api/v1/service-accounts"))
        .bearer_auth(&beyond_skew.token)
        .send()
        .await
        .unwrap();
    assert_eq!(beyond_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(beyond_resp.text().await.unwrap().contains("jwt expired"));

    server.abort();
}
