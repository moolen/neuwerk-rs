use super::*;

#[tokio::test]
async fn http_api_metrics_bind_public_requires_explicit_allow_override() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 8080);

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

    let err = http_api::run_http_api(
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
    .unwrap_err();

    assert!(err.contains("NEUWERK_ALLOW_PUBLIC_METRICS_BIND"));
}

#[tokio::test]
async fn http_api_ready_health_metrics_contract_startup_and_failure_modes() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let dataplane_config = DataplaneConfigStore::new();
    let readiness = ReadinessState::new(dataplane_config.clone(), policy_store.clone(), None, None);
    let readiness_handle = readiness.clone();
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
        .map_err(|err| format!("http api error: {err}"))
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

    let health = client
        .get(format!("https://{bind_addr}/health"))
        .send()
        .await
        .unwrap();
    assert!(health.status().is_success());
    let health_body: serde_json::Value = health.json().await.unwrap();
    assert_eq!(
        health_body.get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let metrics_resp = reqwest::Client::new()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics_resp.status().is_success());
    let metrics_text = metrics_resp.text().await.unwrap();
    assert!(metrics_text.contains("# HELP"));

    let startup_ready = client
        .get(format!("https://{bind_addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        startup_ready.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let startup_body: serde_json::Value = startup_ready.json().await.unwrap();
    assert_eq!(
        startup_body.get("ready").and_then(|v| v.as_bool()),
        Some(false)
    );

    dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 2),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        lease_expiry: Some(123),
    });
    readiness_handle.set_dataplane_running(true);
    readiness_handle.set_policy_ready(true);
    readiness_handle.set_dns_ready(true);
    readiness_handle.set_service_plane_ready(true);

    let ready_ok = client
        .get(format!("https://{bind_addr}/ready"))
        .send()
        .await
        .unwrap();
    assert!(ready_ok.status().is_success());
    let ready_ok_body: serde_json::Value = ready_ok.json().await.unwrap();
    assert_eq!(
        ready_ok_body.get("ready").and_then(|v| v.as_bool()),
        Some(true)
    );

    readiness_handle.set_service_plane_ready(false);

    let degraded_ready = client
        .get(format!("https://{bind_addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        degraded_ready.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let degraded_body: serde_json::Value = degraded_ready.json().await.unwrap();
    assert_eq!(
        degraded_body.get("ready").and_then(|v| v.as_bool()),
        Some(false)
    );

    let health_degraded = client
        .get(format!("https://{bind_addr}/health"))
        .send()
        .await
        .unwrap();
    assert!(health_degraded.status().is_success());

    let metrics_degraded = reqwest::Client::new()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics_degraded.status().is_success());

    server.abort();
}

#[tokio::test]
async fn cluster_ready_degrades_on_quorum_loss_and_recovers() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let join_dir = TempDir::new().unwrap();
    let seed_token = seed_dir.path().join("bootstrap.json");
    let join_token = join_dir.path().join("bootstrap.json");
    write_token_file(&seed_token);
    write_token_file(&join_token);

    let ip = Ipv4Addr::new(127, 0, 0, 1);

    let seed_addr = next_addr(ip);
    let seed_join_addr = next_addr(ip);
    let join_addr = next_addr(ip);
    let join_join_addr = next_addr(ip);

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

    let seed_runtime =
        firewall::controlplane::cluster::run_cluster_tasks(seed_cfg.clone(), None, None)
            .await
            .unwrap()
            .unwrap();
    let join_runtime =
        firewall::controlplane::cluster::run_cluster_tasks(join_cfg.clone(), None, None)
            .await
            .unwrap()
            .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;
    let join_id = join_runtime.raft.metrics().borrow().id;
    assert!(leader_id == seed_id || leader_id == join_id);
    let joiner_node_id = uuid::Uuid::parse_str(
        fs::read_to_string(join_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    wait_for_voter(&seed_runtime.raft, joiner_node_id, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_stable_membership(&seed_runtime.raft, Duration::from_secs(10))
        .await
        .unwrap();

    // Drive readiness from a real follower raft handle, but run HTTP API in local mode
    // to avoid cluster HTTP TLS/bootstrap ordering from dominating this readiness test.
    let (api_raft, api_store, stopped_runtime, restart_cfg) = if leader_id == seed_id {
        (
            join_runtime.raft.clone(),
            join_runtime.store.clone(),
            seed_runtime,
            seed_cfg.clone(),
        )
    } else {
        (
            seed_runtime.raft.clone(),
            seed_runtime.store.clone(),
            join_runtime,
            join_cfg.clone(),
        )
    };

    let api_bind = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_bind = next_addr(Ipv4Addr::LOCALHOST);
    let api_dir = TempDir::new().unwrap();
    let tls_dir = api_dir.path().join("http-tls");
    let local_store = PolicyDiskStore::new(api_dir.path().join("policies"));
    let api_token = api_dir.path().join("token.json");
    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let dataplane_config = DataplaneConfigStore::new();
    dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 2),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x11],
        lease_expiry: Some(123),
    });
    let readiness = ReadinessState::new(
        dataplane_config,
        policy_store.clone(),
        Some(api_store.clone()),
        Some(api_raft.clone()),
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);

    let api_cfg = HttpApiConfig {
        bind_addr: api_bind,
        advertise_addr: api_bind,
        metrics_bind,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: api_token,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let api_task = tokio::spawn(http_api::run_http_api(
        api_cfg,
        policy_store,
        local_store,
        None,
        None,
        None,
        None,
        Some(readiness),
        Metrics::new().unwrap(),
    ));

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(20))
        .await
        .unwrap();
    wait_for_tcp(api_bind, Duration::from_secs(20))
        .await
        .unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    wait_for_ready_status(&client, api_bind, true, Duration::from_secs(5))
        .await
        .unwrap();

    stopped_runtime.shutdown().await;

    wait_for_ready_status(&client, api_bind, false, Duration::from_secs(20))
        .await
        .unwrap();

    let restarted = firewall::controlplane::cluster::run_cluster_tasks(restart_cfg, None, None)
        .await
        .unwrap()
        .unwrap();

    wait_for_ready_status(&client, api_bind, true, Duration::from_secs(20))
        .await
        .unwrap();

    api_task.abort();
    restarted.shutdown().await;
}

#[tokio::test]
async fn http_api_tls_intercept_ca_local_settings_round_trip() {
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
    let token = api_auth::mint_token(&keyset, "local-settings-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let cert_pem = ca_cert.serialize_pem().unwrap();
    let key_pem = ca_cert.serialize_private_key_pem();

    let put_resp = client
        .put(format!(
            "https://{bind_addr}/api/v1/settings/tls-intercept-ca"
        ))
        .bearer_auth(&token.token)
        .json(&serde_json::json!({
            "ca_cert_pem": cert_pem,
            "ca_key_pem": key_pem,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), reqwest::StatusCode::OK);
    let put_body: serde_json::Value = put_resp.json().await.unwrap();
    assert_eq!(
        put_body.get("configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        put_body.get("source").and_then(|v| v.as_str()),
        Some("local")
    );
    assert!(put_body
        .get("fingerprint_sha256")
        .and_then(|v| v.as_str())
        .is_some());

    let get_resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/settings/tls-intercept-ca"
        ))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(
        get_body.get("configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        get_body.get("source").and_then(|v| v.as_str()),
        Some("local")
    );

    let (cert_path, key_path) = local_intercept_ca_paths(&tls_dir);
    assert!(cert_path.exists());
    assert!(key_path.exists());

    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_times_out_when_dataplane_ack_missing() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
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
    let token = api_auth::mint_token(&keyset, "activation-timeout-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

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

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.text().await.unwrap();
    assert!(body.contains("policy activation timed out"));
    assert!(
        elapsed >= Duration::from_millis(1800),
        "policy activation timeout returned too early: {elapsed:?}"
    );

    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_waits_for_dataplane_ack() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let tracker_store = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
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
    let token = api_auth::mint_token(&keyset, "activation-ack-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let ack_task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let generation = tracker_store.policy_generation();
            if generation > 0 {
                tracker_store
                    .policy_applied_tracker()
                    .store(generation, Ordering::Release);
                tracker_store
                    .service_policy_applied_tracker()
                    .store(generation, Ordering::Release);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

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

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();
    let status = resp.status();
    let body = resp.text().await.unwrap();

    assert!(
        status.is_success(),
        "expected success after policy ack, got {}: {}",
        status,
        body
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "policy activation ack path should complete before timeout, took {elapsed:?}"
    );

    ack_task.await.unwrap();
    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_times_out_when_service_plane_ack_missing() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let tracker_store = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
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
    let token =
        api_auth::mint_token(&keyset, "activation-service-timeout-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let ack_task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let generation = tracker_store.policy_generation();
            if generation > 0 {
                // Intentionally acknowledge only dataplane generation to verify service-plane
                // activation is also required.
                tracker_store
                    .policy_applied_tracker()
                    .store(generation, Ordering::Release);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

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

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.text().await.unwrap();
    assert!(body.contains("policy activation timed out"));
    assert!(
        elapsed >= Duration::from_millis(1800),
        "policy activation timeout returned too early: {elapsed:?}"
    );

    ack_task.await.unwrap();
    server.abort();
}
