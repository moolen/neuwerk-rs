use super::*;

#[tokio::test]
async fn http_api_cluster_proxy_lifecycle() {
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
    let shared_http_port = next_addr(seed_ip).port();
    let seed_http_addr = SocketAddr::new(IpAddr::V4(seed_ip), shared_http_port);
    let seed_metrics_addr = next_addr(seed_ip);
    let join_http_addr = SocketAddr::new(IpAddr::V4(join_ip), shared_http_port);
    let join_metrics_addr = next_addr(join_ip);

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

    let seed_metrics = Metrics::new().unwrap();
    let join_metrics = Metrics::new().unwrap();

    let seed_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        None,
        Some(seed_metrics.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        None,
        Some(join_metrics.clone()),
    )
    .await
    .unwrap()
    .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;
    let join_id = join_runtime.raft.metrics().borrow().id;
    assert!(leader_id == seed_id || leader_id == join_id);
    wait_for_voter(&seed_runtime.raft, join_id, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_stable_membership(&seed_runtime.raft, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_stable_membership(&join_runtime.raft, Duration::from_secs(10))
        .await
        .unwrap();

    let seed_http = HttpApiConfig {
        bind_addr: seed_http_addr,
        advertise_addr: seed_http_addr,
        metrics_bind: seed_metrics_addr,
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics_addr,
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let join_local_store_check = join_local_store.clone();

    let seed_http_task = tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy.clone(),
        seed_local_store.clone(),
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        None,
        None,
        None,
        None,
        seed_metrics,
    ));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(
        &seed_runtime.store,
        b"http/ca/cert",
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    wait_for_state_value(
        &join_runtime.store,
        b"http/ca/cert",
        Duration::from_secs(15),
    )
    .await
    .unwrap();

    let join_http_task = tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy.clone(),
        join_local_store.clone(),
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        None,
        None,
        None,
        None,
        join_metrics,
    ));
    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_state_value(
        &seed_runtime.store,
        api_auth::API_KEYS_KEY,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let keyset = api_auth::load_keyset_from_store(&seed_runtime.store)
        .unwrap()
        .expect("missing api keyset");
    let token = api_auth::mint_token(&keyset, "cluster-test", None, None).unwrap();

    let replication_task = tokio::spawn(policy_replication::run_policy_replication(
        join_runtime.store.clone(),
        join_runtime.raft.clone(),
        join_policy.clone(),
        join_local_store.clone(),
        None,
        Duration::from_millis(200),
    ));

    let ca_pem = fs::read(seed_dir.path().join("http-tls").join("ca.crt")).unwrap();
    let ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();
    wait_for_ready_status(&client, seed_http_addr, true, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_ready_status(&client, join_http_addr, true, Duration::from_secs(5))
        .await
        .unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "cluster",
                    "sources": { "ips": ["10.0.0.7"] },
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

    let follower_addr = if leader_id == seed_id {
        join_http_addr
    } else {
        seed_http_addr
    };
    let resp = client
        .post(format!("https://{follower_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.bytes().await.unwrap();
    assert!(
        status.is_success(),
        "policy create via follower failed: status={}, body={}",
        status,
        String::from_utf8_lossy(&body)
    );
    let record: PolicyRecord = serde_json::from_slice(&body).unwrap();
    assert_eq!(record.mode, PolicyMode::Enforce);

    let active = seed_runtime
        .store
        .get_state_value(POLICY_ACTIVE_KEY)
        .unwrap()
        .unwrap();
    let active: PolicyActive = serde_json::from_slice(&active).unwrap();
    assert_eq!(active.id, record.id);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(join_local_store_check.active_id().unwrap(), Some(record.id));

    let disabled_payload = serde_json::json!({
        "mode": "disabled",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "cluster",
                    "sources": { "ips": ["10.0.0.7"] },
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
        .put(format!(
            "https://{follower_addr}/api/v1/policies/{}",
            record.id
        ))
        .bearer_auth(&token.token)
        .json(&disabled_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(updated.mode, PolicyMode::Disabled);
    wait_for_state_absent(
        &seed_runtime.store,
        POLICY_ACTIVE_KEY,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(join_local_store_check.active_id().unwrap(), None);
    assert_eq!(join_policy.active_policy_id(), None);

    seed_http_task.abort();
    join_http_task.abort();
    replication_task.abort();
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

#[tokio::test]
async fn http_api_wiretap_stream_aggregates_cluster() {
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

    let seed_wiretap = WiretapHub::new(32);
    let join_wiretap = WiretapHub::new(32);
    let seed_metrics_registry = Metrics::new().unwrap();
    let join_metrics_registry = Metrics::new().unwrap();

    let seed_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        Some(seed_wiretap.clone()),
        Some(seed_metrics_registry.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        Some(join_wiretap.clone()),
        Some(join_metrics_registry.clone()),
    )
    .await
    .unwrap()
    .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;
    let _join_id = join_runtime.raft.metrics().borrow().id;

    let http_port = next_addr(seed_ip).port();
    let seed_http_addr = SocketAddr::new(IpAddr::V4(seed_ip), http_port);
    let join_http_addr = SocketAddr::new(IpAddr::V4(join_ip), http_port);
    let seed_metrics = next_addr(seed_ip);
    let join_metrics = next_addr(join_ip);

    let seed_http = HttpApiConfig {
        bind_addr: seed_http_addr,
        advertise_addr: seed_http_addr,
        metrics_bind: seed_metrics,
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics,
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let seed_http_task = tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy,
        seed_local_store,
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        None,
        Some(seed_wiretap.clone()),
        None,
        None,
        seed_metrics_registry,
    ));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let join_http_task = tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy,
        join_local_store,
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        None,
        Some(join_wiretap.clone()),
        None,
        None,
        join_metrics_registry,
    ));

    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&join_runtime.store).unwrap();

    let (leader_addr, leader_tls_dir) = if leader_id == seed_id {
        (seed_http_addr, seed_dir.path().join("http-tls"))
    } else {
        (join_http_addr, join_dir.path().join("http-tls"))
    };

    let client = http_api_client(&leader_tls_dir).unwrap();
    let resp = client
        .get(format!("https://{leader_addr}/api/v1/wiretap/stream"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mut stream = resp.bytes_stream();
    let read_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = String::new();
        let mut seen_seed = false;
        let mut seen_join = false;
        while Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    if buf.contains("seed-flow") {
                        seen_seed = true;
                    }
                    if buf.contains("join-flow") {
                        seen_join = true;
                    }
                    if seen_seed && seen_join {
                        return Ok::<(), String>(());
                    }
                }
                Ok(Some(Err(err))) => return Err(format!("stream error: {err}")),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err("wiretap stream did not include both flows".to_string())
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    seed_wiretap.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "seed-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 40000,
        dst_port: 53,
        proto: 17,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: Some("foo.allowed".to_string()),
        node_id: "seed-node".to_string(),
    });
    join_wiretap.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "join-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 3),
        dst_ip: Ipv4Addr::new(198, 51, 100, 20),
        src_port: 40001,
        dst_port: 80,
        proto: 6,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: None,
        node_id: "join-node".to_string(),
    });

    match read_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(err) => panic!("wiretap stream task failed: {err}"),
    }

    seed_http_task.abort();
    join_http_task.abort();
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}
