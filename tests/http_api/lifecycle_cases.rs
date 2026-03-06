use super::*;

#[tokio::test]
async fn http_api_local_lifecycle() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let policy_store_check = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let local_store_check = local_store.clone();
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
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
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "local-test", None, None).unwrap();
    let expired = api_auth::mint_token_at(
        &keyset,
        "local-test",
        Some(60),
        None,
        OffsetDateTime::now_utc() - TimeDuration::hours(1),
    )
    .unwrap();
    let ca_pem = fs::read(tls_dir.join("ca.crt")).unwrap();
    let ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
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

    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let record: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(record.mode, PolicyMode::Enforce);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let records: Vec<PolicyRecord> = resp.json().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, record.id);
    assert_eq!(local_store_check.active_id().unwrap(), Some(record.id));

    let disabled_payload = serde_json::json!({
        "mode": "disabled",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
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
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/policies/{}", record.id))
        .bearer_auth(&token.token)
        .json(&disabled_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(updated.mode, PolicyMode::Disabled);
    assert_eq!(local_store_check.active_id().unwrap(), None);
    assert_eq!(policy_store_check.active_policy_id(), None);

    let missing = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);

    let expired_resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&expired.token)
        .send()
        .await
        .unwrap();
    assert_eq!(expired_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let metrics = reqwest::Client::new()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics.status().is_success());

    server.abort();
}

#[tokio::test]
async fn http_api_integrations_lifecycle_and_policy_ref_validation() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
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
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "integration-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let create_payload = serde_json::json!({
        "name": "prod-k8s",
        "kind": "kubernetes",
        "api_server_url": "https://127.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "secret-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        created.get("name").and_then(|v| v.as_str()),
        Some("prod-k8s")
    );
    assert_eq!(
        created.get("kind").and_then(|v| v.as_str()),
        Some("kubernetes")
    );
    assert_eq!(
        created.get("token_configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        created.get("auth_type").and_then(|v| v.as_str()),
        Some("service_account_token")
    );
    assert!(
        created.get("service_account_token").is_none(),
        "service_account_token must be redacted from API responses"
    );

    let duplicate_payload = serde_json::json!({
        "name": "PROD-K8S",
        "kind": "kubernetes",
        "api_server_url": "https://10.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "other-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&duplicate_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let listed: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(listed.as_array().map(|arr| arr.len()), Some(1));

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        fetched.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://127.0.0.1:6443")
    );
    assert!(fetched.get("service_account_token").is_none());

    let update_payload = serde_json::json!({
        "api_server_url": "https://10.10.10.10:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
        "service_account_token": "updated-token",
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .json(&update_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        updated.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://10.10.10.10:6443")
    );
    assert!(updated.get("service_account_token").is_none());

    let missing_ref_policy = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "missing",
                                "pod_selector": {
                                    "namespace": "default",
                                    "match_labels": { "app": "web" }
                                }
                            }
                        ]
                    },
                    "rules": [
                        {
                            "id": "deny-all",
                            "action": "deny",
                            "match": {}
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&missing_ref_policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let valid_policy = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "prod-k8s",
                                "pod_selector": {
                                    "namespace": "default",
                                    "match_labels": { "app": "web" }
                                }
                            }
                        ]
                    },
                    "rules": [
                        {
                            "id": "allow-https",
                            "action": "allow",
                            "match": {
                                "proto": "tcp",
                                "dst_ports": [443]
                            }
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&valid_policy)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created_policy: PolicyRecord = resp.json().await.unwrap();

    let bad_update = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "missing",
                                "node_selector": {
                                    "match_labels": { "node-role.kubernetes.io/control-plane": "true" }
                                }
                            }
                        ]
                    }
                }
            ]
        }
    });
    let resp = client
        .put(format!(
            "https://{bind_addr}/api/v1/policies/{}",
            created_policy.id
        ))
        .bearer_auth(&token.token)
        .json(&bad_update)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let resp = client
        .delete(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    server.abort();
}
