use super::*;

#[tokio::test]
async fn http_api_audit_findings_local_returns_deduped_items() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let audit_store = AuditStore::new(dir.path().join("audit"), 1024 * 1024);
    let finding = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "apps".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 42)),
        dst_port: Some(443),
        proto: Some(6),
        fqdn: Some("api.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 10,
    };
    audit_store.ingest(finding.clone(), None, "node-a");
    audit_store.ingest(finding, None, "node-a");

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
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            Some(audit_store),
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
    let token = api_auth::mint_token(&keyset, "audit-local-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let response = client
        .get(format!(
            "https://{bind_addr}/api/v1/audit/findings?finding_type=l4_deny&source_group=apps"
        ))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(payload.items.len(), 1);
    assert_eq!(payload.items[0].count, 2);
    assert_eq!(payload.items[0].source_group, "apps");
    assert!(!payload.partial);
    assert_eq!(payload.nodes_queried, 1);
    assert_eq!(payload.nodes_responded, 1);

    server.abort();
}

#[tokio::test]
async fn http_api_audit_findings_cluster_aggregates_and_returns_partial() {
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

    let seed_audit_store = AuditStore::new(seed_dir.path().join("audit"), 1024 * 1024);
    let join_audit_store = AuditStore::new(join_dir.path().join("audit"), 1024 * 1024);
    let common = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "apps".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 9)),
        dst_port: Some(443),
        proto: Some(6),
        fqdn: Some("api.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 1,
    };
    seed_audit_store.ingest(common.clone(), None, "seed-node");
    join_audit_store.ingest(common, None, "join-node");

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let mut seed_http_task = Some(tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy,
        seed_local_store,
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        Some(seed_audit_store),
        None,
        None,
        None,
        Metrics::new().unwrap(),
    )));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let mut join_http_task = Some(tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy,
        join_local_store,
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        Some(join_audit_store),
        None,
        None,
        None,
        Metrics::new().unwrap(),
    )));

    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&join_runtime.store).unwrap();
    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let (leader_addr, leader_tls_dir, _, _) = cluster_http_roles(
        leader_id,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
    );
    let client = http_api_client(&leader_tls_dir).unwrap();

    let response = client
        .get(format!(
            "https://{leader_addr}/api/v1/audit/findings?finding_type=l4_deny"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.partial);
    assert!(payload.nodes_queried >= 2);
    assert!(payload.nodes_responded >= 2);
    assert!(!payload.items.is_empty());
    assert_eq!(payload.items[0].count, 2);
    assert_eq!(payload.items[0].node_ids.len(), 2);

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let (_, _, follower_addr, stop_follower) = cluster_http_roles(
        leader_id,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
    );

    if stop_follower == "join" {
        join_runtime.raft.runtime_config().elect(false);
        if let Some(task) = join_http_task.take() {
            task.abort();
            let _ = task.await;
        }
    } else {
        seed_runtime.raft.runtime_config().elect(false);
        if let Some(task) = seed_http_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
    wait_for_tcp_closed(follower_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let (_, response) = send_to_current_leader_until_success(
        &seed_runtime.raft,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
        Duration::from_secs(5),
        |client, leader_addr| {
            client
                .get(format!(
                    "https://{leader_addr}/api/v1/audit/findings?finding_type=l4_deny"
                ))
                .bearer_auth(&token)
        },
    )
    .await
    .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(payload.partial);
    assert!(payload.nodes_queried >= 2);
    assert!(payload.nodes_responded < payload.nodes_queried);
    assert!(!payload.node_errors.is_empty());

    if let Some(task) = seed_http_task.take() {
        task.abort();
    }
    if let Some(task) = join_http_task.take() {
        task.abort();
    }
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

#[tokio::test]
async fn http_api_audit_findings_persist_across_restart() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let audit_dir = dir.path().join("audit");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let token_path = dir.path().join("token.json");
    let max_bytes = 1024 * 1024;

    let event = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "persist".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 100)),
        dst_port: Some(8443),
        proto: Some(6),
        fqdn: Some("persist.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 42,
    };

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
        token_path: token_path.clone(),
        external_url: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let base_cfg = cfg.clone();
    let start_server = || {
        let cfg = base_cfg.clone();
        let shutdown = http_api::HttpApiShutdown::new();
        let shutdown_for_server = shutdown.clone();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let local_store = PolicyDiskStore::new(local_store_dir.clone());
        let audit_store = AuditStore::new(audit_dir.clone(), max_bytes);
        let metrics = Metrics::new().unwrap();
        let server = tokio::spawn(async move {
            http_api::run_http_api_with_shutdown(
                cfg,
                policy_store,
                local_store,
                None,
                Some(audit_store),
                None,
                None,
                None,
                metrics,
                shutdown_for_server,
            )
            .await
            .map_err(|err| format!("http api error: {err}"))
        });
        (shutdown, server)
    };

    let seed_store = AuditStore::new(audit_dir.clone(), max_bytes);
    seed_store.ingest(event, None, "node-a");
    drop(seed_store);

    let (shutdown, server) = start_server();
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
    let token = api_auth::mint_token(&keyset, "audit-restart-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let query = format!(
        "https://{bind_addr}/api/v1/audit/findings?finding_type=l4_deny&source_group=persist"
    );
    let first = client
        .get(&query)
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = first.status();
    let body = first.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.items.is_empty());

    shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("http audit restart shutdown timeout")
        .expect("http audit restart join")
        .expect("http audit restart result");
    wait_for_tcp_closed(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp_closed(metrics_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let (shutdown, server) = start_server();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let second = client
        .get(&query)
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = second.status();
    let body = second.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.items.is_empty());
    assert!(payload
        .items
        .iter()
        .any(|item| item.source_group == "persist" && item.count >= 1));

    shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("http audit restart final shutdown timeout")
        .expect("http audit restart final join")
        .expect("http audit restart final result");
}
