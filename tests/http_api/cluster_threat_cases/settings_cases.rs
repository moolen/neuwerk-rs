use super::*;

#[tokio::test]
async fn http_api_threat_settings_round_trip_local_state() {
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
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "threat-settings-local-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let put_resp = client
        .put(format!("https://{bind_addr}/api/v1/settings/threat-intel"))
        .bearer_auth(&token.token)
        .json(&serde_json::json!({
            "enabled": true,
            "alert_threshold": "high",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), reqwest::StatusCode::OK);
    let put_body: serde_json::Value = put_resp.json().await.unwrap();
    assert_eq!(
        put_body.get("enabled").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        put_body.get("alert_threshold").and_then(|v| v.as_str()),
        Some("high")
    );

    let get_resp = client
        .get(format!("https://{bind_addr}/api/v1/settings/threat-intel"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(get_body, put_body);

    server.abort();
}

#[tokio::test]
async fn http_api_threat_settings_round_trip_cluster_state() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let cluster_dir = dir.path().join("cluster");
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let token_path = dir.path().join("bootstrap.json");
    write_token_file(&token_path);

    let cluster_ip = Ipv4Addr::LOCALHOST;
    let cluster_addr = next_addr(cluster_ip);
    let cluster_join_addr = next_addr(cluster_ip);
    let bind_addr = next_addr(cluster_ip);
    let metrics_addr = next_addr(cluster_ip);

    let mut cluster_cfg = ClusterConfig::disabled();
    cluster_cfg.enabled = true;
    cluster_cfg.bind_addr = cluster_addr;
    cluster_cfg.join_bind_addr = cluster_join_addr;
    cluster_cfg.advertise_addr = cluster_addr;
    cluster_cfg.data_dir = cluster_dir.clone();
    cluster_cfg.node_id_path = cluster_dir.join("node_id");
    cluster_cfg.token_path = token_path.clone();

    let runtime = neuwerk::controlplane::cluster::run_cluster_tasks(
        cluster_cfg,
        None,
        Some(Metrics::new().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    wait_for_leader(&runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
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
        management_ip: IpAddr::V4(cluster_ip),
        token_path: token_path.clone(),
        external_url: None,
        cluster_tls_dir: Some(cluster_dir.join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let server = tokio::spawn(http_api::run_http_api(
        cfg,
        policy_store,
        local_store,
        Some(HttpApiCluster {
            raft: runtime.raft.clone(),
            store: runtime.store.clone(),
        }),
        None,
        None,
        None,
        None,
        Metrics::new().unwrap(),
    ));

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(5))
        .await
        .unwrap();
    let client = http_api_client(&tls_dir).unwrap();
    let token = api_auth_token_from_store(&runtime.store).unwrap();

    let put_resp = client
        .put(format!("https://{bind_addr}/api/v1/settings/threat-intel"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "enabled": true,
            "alert_threshold": "critical",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), reqwest::StatusCode::OK);
    let put_body: serde_json::Value = put_resp.json().await.unwrap();
    assert_eq!(
        put_body.get("enabled").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        put_body
            .get("alert_threshold")
            .and_then(|value| value.as_str()),
        Some("critical")
    );
    assert_eq!(
        put_body.get("source").and_then(|value| value.as_str()),
        Some("cluster")
    );

    let get_resp = client
        .get(format!("https://{bind_addr}/api/v1/settings/threat-intel"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(get_body, put_body);
    assert_eq!(
        get_body.get("source").and_then(|value| value.as_str()),
        Some("cluster")
    );

    server.abort();
    runtime.shutdown().await;
}
