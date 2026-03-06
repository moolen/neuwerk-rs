use super::*;

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
        .json(&serde_json::json!({"name": "sa-admin"}))
        .send()
        .await
        .unwrap();
    assert!(admin_sa_create.status().is_success());

    server.abort();
}
