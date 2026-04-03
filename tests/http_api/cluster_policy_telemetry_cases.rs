use super::*;

#[tokio::test]
async fn http_api_policy_telemetry_local_returns_hourly_items() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let telemetry_store = PolicyTelemetryStore::new(dir.path().join("policy-telemetry"));
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    telemetry_store.record_hit("apps", now - (2 * 3_600));
    telemetry_store.record_hit("apps", now - (26 * 3_600));

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
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api_with_policy_telemetry(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(telemetry_store),
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
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "telemetry-local-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let response = client
        .get(format!("https://{bind_addr}/api/v1/policy/telemetry"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        payload["items"][0]["source_group_id"].as_str(),
        Some("apps")
    );
    assert_eq!(payload["items"][0]["current_24h_hits"].as_u64(), Some(1));
    assert_eq!(payload["items"][0]["previous_24h_hits"].as_u64(), Some(1));
    assert_eq!(payload["partial"].as_bool(), Some(false));

    server.abort();
}

#[tokio::test]
async fn http_api_policy_telemetry_cluster_aggregates_and_returns_partial() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let join_dir = TempDir::new().unwrap();
    let seed_token = seed_dir.path().join("bootstrap.json");
    let join_token = join_dir.path().join("bootstrap.json");
    write_token_file(&seed_token);
    write_token_file(&join_token);

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let join_ip = Ipv4Addr::new(127, 0, 0, 2);
    let seed_addr = next_addr(seed_ip);
    let seed_join_addr = next_addr(seed_ip);
    let join_addr = next_addr(join_ip);
    let join_join_addr = next_addr(join_ip);

    let mut seed_cfg = ClusterConfig::disabled();
    seed_cfg.enabled = true;
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.data_dir = seed_dir.path().to_path_buf();
    seed_cfg.node_id_path = seed_dir.path().join("node_id");
    seed_cfg.token_path = seed_token.clone();

    let mut join_cfg = ClusterConfig::disabled();
    join_cfg.enabled = true;
    join_cfg.bind_addr = join_addr;
    join_cfg.join_bind_addr = join_join_addr;
    join_cfg.advertise_addr = join_addr;
    join_cfg.join_seed = Some(seed_join_addr);
    join_cfg.data_dir = join_dir.path().to_path_buf();
    join_cfg.node_id_path = join_dir.path().join("node_id");
    join_cfg.token_path = join_token.clone();

    let seed_runtime = neuwerk::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        None,
        Some(Metrics::new().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = neuwerk::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        None,
        Some(Metrics::new().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;

    let http_port = next_addr(seed_ip).port();
    let seed_http_addr = SocketAddr::new(IpAddr::V4(seed_ip), http_port);
    let join_http_addr = SocketAddr::new(IpAddr::V4(join_ip), http_port);
    let seed_metrics = next_addr(seed_ip);
    let join_metrics = next_addr(join_ip);

    let seed_http = HttpApiConfig {
        bind_addr: seed_http_addr,
        advertise_addr: seed_http_addr,
        metrics_bind: seed_metrics,
        allow_public_metrics_bind: false,
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        external_url: None,
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics,
        allow_public_metrics_bind: false,
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        external_url: None,
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let seed_telemetry_store = PolicyTelemetryStore::new(seed_dir.path().join("policy-telemetry"));
    let join_telemetry_store = PolicyTelemetryStore::new(join_dir.path().join("policy-telemetry"));
    seed_telemetry_store.record_hit("apps", now - (1 * 3_600));
    join_telemetry_store.record_hit("apps", now - (2 * 3_600));

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let seed_raft = seed_runtime.raft.clone();
    let seed_store = seed_runtime.store.clone();
    let join_raft = join_runtime.raft.clone();
    let join_store = join_runtime.store.clone();

    let seed_server = tokio::spawn(async move {
        http_api::run_http_api_with_policy_telemetry(
            seed_http,
            seed_policy,
            seed_local_store,
            Some(HttpApiCluster {
                raft: seed_raft,
                store: seed_store,
            }),
            None,
            Some(seed_telemetry_store),
            None,
            None,
            None,
            Metrics::new().unwrap(),
        )
        .await
        .map_err(|err| format!("seed http api error: {err}"))
    });
    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let join_server = tokio::spawn(async move {
        http_api::run_http_api_with_policy_telemetry(
            join_http,
            join_policy,
            join_local_store,
            Some(HttpApiCluster {
                raft: join_raft,
                store: join_store,
            }),
            None,
            Some(join_telemetry_store),
            None,
            None,
            None,
            Metrics::new().unwrap(),
        )
        .await
        .map_err(|err| format!("join http api error: {err}"))
    });

    wait_for_file(
        &join_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_tcp(seed_http_addr, Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&seed_runtime.store).unwrap();

    let (_leader_id, response) = send_to_current_leader_until_success(
        &seed_runtime.raft,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
        Duration::from_secs(10),
        |client, addr| {
            client
                .get(format!("https://{addr}/api/v1/policy/telemetry"))
                .bearer_auth(&token)
        },
    )
    .await
    .unwrap();

    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        payload["items"][0]["source_group_id"].as_str(),
        Some("apps")
    );
    assert_eq!(payload["items"][0]["current_24h_hits"].as_u64(), Some(2));
    assert_eq!(payload["partial"].as_bool(), Some(false));
    assert_eq!(payload["nodes_responded"].as_u64(), Some(2));

    join_server.abort();
    wait_for_tcp_closed(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let (_leader_id, response) = send_to_current_leader_until_success(
        &seed_runtime.raft,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
        Duration::from_secs(10),
        |client, addr| {
            client
                .get(format!("https://{addr}/api/v1/policy/telemetry"))
                .bearer_auth(&token)
        },
    )
    .await
    .unwrap();

    let payload: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        payload["items"][0]["source_group_id"].as_str(),
        Some("apps")
    );
    assert_eq!(payload["items"][0]["current_24h_hits"].as_u64(), Some(1));
    assert_eq!(payload["partial"].as_bool(), Some(true));
    assert_eq!(
        payload["node_errors"].as_array().map(|v| !v.is_empty()),
        Some(true)
    );

    seed_server.abort();
}
