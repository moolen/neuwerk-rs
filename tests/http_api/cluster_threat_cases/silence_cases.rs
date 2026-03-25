use super::*;

use neuwerk::controlplane::threat_intel::manager::{
    persist_local_feed_status, ThreatFeedIndicatorCounts, ThreatFeedRefreshState,
    ThreatFeedStatusItem, ThreatRefreshOutcome,
};
use neuwerk::controlplane::threat_intel::silences::THREAT_INTEL_SILENCES_KEY;
use neuwerk::controlplane::threat_intel::store::{
    ThreatEnrichmentStatus, ThreatFeedHit, ThreatFinding, ThreatMatchSource, ThreatStore,
};
use neuwerk::controlplane::threat_intel::types::{
    ThreatIndicatorType, ThreatObservationLayer, ThreatSeverity,
};

fn sample_threat_finding(node_id: &str) -> ThreatFinding {
    ThreatFinding {
        indicator: "bad.example.com".to_string(),
        indicator_type: ThreatIndicatorType::Hostname,
        observation_layer: ThreatObservationLayer::Dns,
        match_source: ThreatMatchSource::Stream,
        source_group: "apps".to_string(),
        severity: ThreatSeverity::Critical,
        confidence: Some(95),
        feed_hits: vec![ThreatFeedHit {
            feed: "threatfox".to_string(),
            severity: ThreatSeverity::Critical,
            confidence: Some(95),
            reference_url: Some("https://threatfox.abuse.ch/ioc/123456/".to_string()),
            tags: vec!["botnet".to_string()],
        }],
        first_seen: 10,
        last_seen: 10,
        count: 1,
        sample_node_ids: vec![node_id.to_string()],
        alertable: true,
        audit_links: vec!["audit:dns:apps:bad.example.com".to_string()],
        enrichment_status: ThreatEnrichmentStatus::NotRequested,
    }
}

#[tokio::test]
async fn http_api_threat_findings_and_feed_status_report_disabled_state() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let threat_store_dir = dir.path().join("threats");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    persist_local_feed_status(
        dir.path(),
        &ThreatFeedRefreshState {
            snapshot_version: 7,
            snapshot_generated_at: Some(500),
            last_refresh_started_at: Some(510),
            last_refresh_completed_at: Some(512),
            last_successful_refresh_at: Some(512),
            last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
            feeds: vec![ThreatFeedStatusItem {
                feed: "threatfox".to_string(),
                enabled: true,
                snapshot_age_seconds: Some(12),
                last_refresh_started_at: Some(510),
                last_refresh_completed_at: Some(512),
                last_successful_refresh_at: Some(512),
                last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
                indicator_counts: ThreatFeedIndicatorCounts { hostname: 1, ip: 0 },
            }],
            disabled: false,
        },
    )
    .unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let threat_store = ThreatStore::new(threat_store_dir, 1024 * 1024).unwrap();
    threat_store
        .upsert_finding(sample_threat_finding("node-a"))
        .unwrap();

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
        http_api::run_http_api_with_threat_store(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(threat_store),
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
    let token = api_auth::mint_token(&keyset, "threat-disabled-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let disable_resp = client
        .put(format!("https://{bind_addr}/api/v1/settings/threat-intel"))
        .bearer_auth(&token.token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(disable_resp.status(), reqwest::StatusCode::OK);

    for path in ["/api/v1/threats/findings", "/api/v1/threats/findings/local"] {
        let response = client
            .get(format!("https://{bind_addr}{path}"))
            .bearer_auth(&token.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let payload: serde_json::Value = response.json().await.unwrap();
        assert_eq!(
            payload.get("disabled").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            payload
                .get("items")
                .and_then(|v| v.as_array())
                .map(|items| items.len()),
            Some(0)
        );
        assert_eq!(
            payload.get("partial").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            payload
                .get("nodes_queried")
                .and_then(|value| value.as_u64()),
            Some(0)
        );
        assert_eq!(
            payload
                .get("nodes_responded")
                .and_then(|value| value.as_u64()),
            Some(0)
        );
    }

    let feed_response = client
        .get(format!("https://{bind_addr}/api/v1/threats/feeds/status"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(feed_response.status(), reqwest::StatusCode::OK);
    let feed_payload: serde_json::Value = feed_response.json().await.unwrap();
    assert_eq!(
        feed_payload
            .get("disabled")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    server.abort();
}

#[tokio::test]
async fn http_api_threat_silences_round_trip_cluster_state_and_replicate_to_follower() {
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
    let join_id = join_runtime.raft.metrics().borrow().id;
    wait_for_voter(&seed_runtime.raft, join_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_stable_membership(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();

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
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

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
        None,
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
        None,
        None,
        None,
        None,
        Metrics::new().unwrap(),
    )));
    wait_for_file(
        &join_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let leader_client = http_api_client(&seed_dir.path().join("http-tls")).unwrap();
    let follower_client = http_api_client(&join_dir.path().join("http-tls")).unwrap();
    let token = api_auth_token_from_store(&seed_runtime.store).unwrap();

    let create_response = leader_client
        .post(format!("https://{seed_http_addr}/api/v1/threats/silences"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "kind": "exact",
            "indicator_type": "hostname",
            "value": "Bad.Example.com.",
            "reason": "known false positive"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(create_response.status(), reqwest::StatusCode::OK);
    let created: serde_json::Value = create_response.json().await.unwrap();
    let silence_id = created
        .get("id")
        .and_then(|value| value.as_str())
        .expect("silence id")
        .to_string();
    assert_eq!(
        created.get("value").and_then(|value| value.as_str()),
        Some("bad.example.com")
    );

    wait_for_state_value(
        &join_runtime.store,
        THREAT_INTEL_SILENCES_KEY,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let follower_list = follower_client
        .get(format!("https://{join_http_addr}/api/v1/threats/silences"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(follower_list.status(), reqwest::StatusCode::OK);
    let follower_payload: serde_json::Value = follower_list.json().await.unwrap();
    let items = follower_payload
        .get("items")
        .and_then(|value| value.as_array())
        .expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].get("id").and_then(|value| value.as_str()),
        Some(silence_id.as_str())
    );

    let delete_response = leader_client
        .delete(format!(
            "https://{seed_http_addr}/api/v1/threats/silences/{silence_id}"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(delete_response.status(), reqwest::StatusCode::NO_CONTENT);

    let follower_after_delete = follower_client
        .get(format!("https://{join_http_addr}/api/v1/threats/silences"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(follower_after_delete.status(), reqwest::StatusCode::OK);
    let follower_after_delete_payload: serde_json::Value =
        follower_after_delete.json().await.unwrap();
    assert_eq!(
        follower_after_delete_payload
            .get("items")
            .and_then(|value| value.as_array())
            .map(|items| items.len()),
        Some(0)
    );

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
async fn http_api_threat_silences_reject_invalid_hostname_regex() {
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

    let response = client
        .post(format!("https://{bind_addr}/api/v1/threats/silences"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "kind": "hostname_regex",
            "value": "[unclosed"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);

    server.abort();
    runtime.shutdown().await;
}
