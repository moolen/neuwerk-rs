use super::*;

use neuwerk::controlplane::cluster::types::ClusterCommand;
use neuwerk::controlplane::threat_intel::feeds::{ThreatIndicatorSnapshotItem, ThreatSnapshot};
use neuwerk::controlplane::threat_intel::manager::{
    load_local_feed_status, persist_local_feed_status, ThreatFeedIndicatorCounts,
    ThreatFeedRefreshState, ThreatFeedStatusItem, ThreatRefreshOutcome, THREAT_INTEL_SNAPSHOT_KEY,
};
use neuwerk::controlplane::threat_intel::types::{ThreatIndicatorType, ThreatSeverity};

#[tokio::test]
async fn http_api_threat_feed_status_reads_persisted_local_state() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
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
            feeds: vec![
                ThreatFeedStatusItem {
                    feed: "threatfox".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(12),
                    last_refresh_started_at: Some(510),
                    last_refresh_completed_at: Some(512),
                    last_successful_refresh_at: Some(512),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
                    indicator_counts: ThreatFeedIndicatorCounts { hostname: 1, ip: 0 },
                },
                ThreatFeedStatusItem {
                    feed: "urlhaus".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(12),
                    last_refresh_started_at: Some(510),
                    last_refresh_completed_at: Some(512),
                    last_successful_refresh_at: Some(512),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
                    indicator_counts: ThreatFeedIndicatorCounts { hostname: 2, ip: 0 },
                },
                ThreatFeedStatusItem {
                    feed: "spamhaus_drop".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(12),
                    last_refresh_started_at: Some(510),
                    last_refresh_completed_at: Some(512),
                    last_successful_refresh_at: Some(512),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
                    indicator_counts: ThreatFeedIndicatorCounts { hostname: 0, ip: 3 },
                },
            ],
            disabled: false,
        },
    )
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
    let token = api_auth::mint_token(&keyset, "threat-feed-status-local-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let response = client
        .get(format!("https://{bind_addr}/api/v1/threats/feeds/status"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body.get("snapshot_version")
            .and_then(|value| value.as_u64()),
        Some(7)
    );
    assert_eq!(
        body.get("last_refresh_outcome")
            .and_then(|value| value.as_str()),
        Some("success")
    );
    let feeds = body
        .get("feeds")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(feeds.iter().any(|feed| {
        feed.get("feed").and_then(|value| value.as_str()) == Some("threatfox")
            && feed
                .get("indicator_counts")
                .and_then(|value| value.get("hostname"))
                .and_then(|value| value.as_u64())
                == Some(1)
    }));
    assert!(feeds.iter().any(|feed| {
        feed.get("feed").and_then(|value| value.as_str()) == Some("spamhaus_drop")
            && feed
                .get("indicator_counts")
                .and_then(|value| value.get("ip"))
                .and_then(|value| value.as_u64())
                == Some(3)
    }));

    server.abort();
}

#[tokio::test]
async fn http_api_threat_feed_status_repairs_stale_local_state_from_cluster_snapshot() {
    ensure_rustls_provider();
    let root = TempDir::new().unwrap();
    let cluster_dir = root.path().join("cluster");
    let tls_dir = root.path().join("http-tls");
    let local_store_dir = root.path().join("policies");
    let token_path = root.path().join("bootstrap.json");
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

    let snapshot = ThreatSnapshot::new(
        12,
        5_000,
        vec![
            ThreatIndicatorSnapshotItem {
                indicator: "bad.example.com".to_string(),
                indicator_type: ThreatIndicatorType::Hostname,
                feed: "threatfox".to_string(),
                severity: ThreatSeverity::High,
                confidence: Some(80),
                tags: Vec::new(),
                reference_url: None,
                feed_first_seen: Some(4_900),
                feed_last_seen: Some(5_000),
                expires_at: None,
            },
            ThreatIndicatorSnapshotItem {
                indicator: "203.0.113.10".to_string(),
                indicator_type: ThreatIndicatorType::Ip,
                feed: "spamhaus_drop".to_string(),
                severity: ThreatSeverity::Critical,
                confidence: Some(100),
                tags: vec!["drop".to_string()],
                reference_url: None,
                feed_first_seen: Some(4_900),
                feed_last_seen: Some(5_000),
                expires_at: None,
            },
        ],
    );
    runtime
        .raft
        .client_write(ClusterCommand::Put {
            key: THREAT_INTEL_SNAPSHOT_KEY.to_vec(),
            value: serde_json::to_vec(&snapshot).unwrap(),
        })
        .await
        .unwrap();

    persist_local_feed_status(
        root.path(),
        &ThreatFeedRefreshState {
            snapshot_version: 0,
            snapshot_generated_at: None,
            last_refresh_started_at: Some(200),
            last_refresh_completed_at: Some(201),
            last_successful_refresh_at: Some(201),
            last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
            feeds: vec![
                ThreatFeedStatusItem {
                    feed: "threatfox".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(1),
                    last_refresh_started_at: Some(200),
                    last_refresh_completed_at: Some(201),
                    last_successful_refresh_at: Some(201),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
                    indicator_counts: ThreatFeedIndicatorCounts::default(),
                },
                ThreatFeedStatusItem {
                    feed: "urlhaus".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(1),
                    last_refresh_started_at: Some(200),
                    last_refresh_completed_at: Some(201),
                    last_successful_refresh_at: Some(201),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
                    indicator_counts: ThreatFeedIndicatorCounts::default(),
                },
                ThreatFeedStatusItem {
                    feed: "spamhaus_drop".to_string(),
                    enabled: true,
                    snapshot_age_seconds: Some(1),
                    last_refresh_started_at: Some(200),
                    last_refresh_completed_at: Some(201),
                    last_successful_refresh_at: Some(201),
                    last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
                    indicator_counts: ThreatFeedIndicatorCounts::default(),
                },
            ],
            disabled: false,
        },
    )
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
        .get(format!("https://{bind_addr}/api/v1/threats/feeds/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        body.get("snapshot_version")
            .and_then(|value| value.as_u64()),
        Some(12)
    );
    assert_eq!(
        body.get("snapshot_generated_at")
            .and_then(|value| value.as_u64()),
        Some(5_000)
    );
    assert_eq!(
        body.get("last_refresh_outcome")
            .and_then(|value| value.as_str()),
        None
    );
    let feeds = body
        .get("feeds")
        .and_then(|value| value.as_array())
        .unwrap();
    assert!(feeds.iter().any(|feed| {
        feed.get("feed").and_then(|value| value.as_str()) == Some("threatfox")
            && feed
                .get("indicator_counts")
                .and_then(|value| value.get("hostname"))
                .and_then(|value| value.as_u64())
                == Some(1)
    }));
    assert!(feeds.iter().any(|feed| {
        feed.get("feed").and_then(|value| value.as_str()) == Some("spamhaus_drop")
            && feed
                .get("indicator_counts")
                .and_then(|value| value.get("ip"))
                .and_then(|value| value.as_u64())
                == Some(1)
    }));

    let repaired = load_local_feed_status(root.path())
        .unwrap()
        .expect("repaired local feed status");
    assert_eq!(repaired.snapshot_version, 12);
    assert_eq!(repaired.snapshot_generated_at, Some(5_000));
    assert_eq!(repaired.last_refresh_outcome, None);
    assert!(repaired
        .feeds
        .iter()
        .any(|feed| { feed.feed == "threatfox" && feed.indicator_counts.hostname == 1 }));
    assert!(repaired
        .feeds
        .iter()
        .any(|feed| { feed.feed == "spamhaus_drop" && feed.indicator_counts.ip == 1 }));

    server.abort();
    runtime.shutdown().await;
}
