use super::*;

use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use flate2::read::GzDecoder;
use tar::Archive;

#[tokio::test]
async fn http_api_cluster_sysdump_proxies_and_reports_partial_failures() {
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

    let seed_runtime = neuwerk::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        None,
        Some(seed_metrics.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = neuwerk::controlplane::cluster::run_cluster_tasks(
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
        metrics_bind: join_metrics_addr,
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

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));

    let seed_http_shutdown = http_api::HttpApiShutdown::new();
    let join_http_shutdown = http_api::HttpApiShutdown::new();

    let mut seed_http_task = Some(tokio::spawn(http_api::run_http_api_with_shutdown(
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
        seed_metrics,
        seed_http_shutdown.clone(),
    )));

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

    let mut join_http_task = Some(tokio::spawn(http_api::run_http_api_with_shutdown(
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
        join_metrics,
        join_http_shutdown.clone(),
    )));

    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    let client = http_api_client(&seed_dir.path().join("http-tls")).unwrap();
    wait_for_ready_status(&client, seed_http_addr, true, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_ready_status(&client, join_http_addr, true, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&seed_runtime.store).unwrap();
    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let initial_leader_id_string = leader_id.to_string();
    let (_, _, follower_addr, _) = cluster_http_roles(
        leader_id,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
    );

    let full_response = client
        .post(format!(
            "https://{follower_addr}/api/v1/support/sysdump/cluster"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(
        full_response.status().is_success(),
        "full cluster sysdump via follower failed: status={}",
        full_response.status()
    );
    assert_eq!(
        full_response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/gzip")
    );
    let disposition = full_response
        .headers()
        .get(reqwest::header::CONTENT_DISPOSITION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        disposition.contains("neuwerk-cluster-sysdump-"),
        "missing cluster sysdump filename: {disposition}"
    );
    let full_archive = full_response.bytes().await.unwrap();
    let full_entries = tar_gz_entries(&full_archive);

    assert_cluster_bundle_shape(&full_entries, &[seed_id, join_id]);
    let full_overview = json_entry(&full_entries, "cluster/overview.json");
    assert_eq!(
        full_overview
            .get("leader_node_id")
            .and_then(serde_json::Value::as_str),
        Some(initial_leader_id_string.as_str())
    );
    assert_eq!(
        full_overview
            .get("partial")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        full_overview
            .get("node_count")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        full_overview
            .get("nodes_succeeded")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        full_overview
            .get("nodes_failed")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
    let full_failures = json_entry(&full_entries, "cluster/failures.json");
    assert_eq!(
        full_failures
            .get("failures")
            .and_then(serde_json::Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    if full_entries.contains_key("cluster/membership.json") {
        let membership = json_entry(&full_entries, "cluster/membership.json");
        assert!(
            membership
                .get("node_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                >= 2
        );
    }

    assert_nested_sysdump(&full_entries, &seed_id.to_string());
    assert_nested_sysdump(&full_entries, &join_id.to_string());

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
    let failed_node_id = if stop_follower == "join" {
        join_id.to_string()
    } else {
        seed_id.to_string()
    };
    if stop_follower == "join" {
        join_runtime.raft.runtime_config().elect(false);
        join_http_shutdown.shutdown();
        let task = join_http_task.take().unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("join http shutdown timeout")
            .expect("join http task join")
            .expect("join http shutdown result");
    } else {
        seed_runtime.raft.runtime_config().elect(false);
        seed_http_shutdown.shutdown();
        let task = seed_http_task.take().unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("seed http shutdown timeout")
            .expect("seed http task join")
            .expect("seed http shutdown result");
    }
    wait_for_tcp_closed(follower_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let (partial_leader_id, partial_response) = send_to_current_leader_until_success(
        &seed_runtime.raft,
        seed_id,
        seed_http_addr,
        join_http_addr,
        &seed_dir.path().join("http-tls"),
        &join_dir.path().join("http-tls"),
        Duration::from_secs(5),
        |client, leader_addr| {
            client
                .post(format!(
                    "https://{leader_addr}/api/v1/support/sysdump/cluster"
                ))
                .bearer_auth(&token)
        },
    )
    .await
    .unwrap();
    let partial_archive = partial_response.bytes().await.unwrap();
    let partial_entries = tar_gz_entries(&partial_archive);
    let partial_leader_id_string = partial_leader_id.to_string();

    let partial_overview = json_entry(&partial_entries, "cluster/overview.json");
    assert_eq!(
        partial_overview
            .get("leader_node_id")
            .and_then(serde_json::Value::as_str),
        Some(partial_leader_id_string.as_str())
    );
    assert_eq!(
        partial_overview
            .get("partial")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        partial_overview
            .get("node_count")
            .and_then(serde_json::Value::as_u64),
        Some(2)
    );
    assert_eq!(
        partial_overview
            .get("nodes_succeeded")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );
    assert_eq!(
        partial_overview
            .get("nodes_failed")
            .and_then(serde_json::Value::as_u64),
        Some(1)
    );

    let partial_failures = json_entry(&partial_entries, "cluster/failures.json");
    let failures = partial_failures
        .get("failures")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0]
            .get("node_id")
            .and_then(serde_json::Value::as_str),
        Some(failed_node_id.as_str())
    );
    assert!(
        failures[0]
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "expected non-empty node error"
    );
    if partial_entries.contains_key("cluster/membership.json") {
        let membership = json_entry(&partial_entries, "cluster/membership.json");
        assert!(
            membership
                .get("node_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default()
                >= 2
        );
    }
    assert!(partial_entries.contains_key(&format!("nodes/{}/sysdump.tar.gz", partial_leader_id)));
    assert!(!partial_entries.contains_key(&format!("nodes/{}/sysdump.tar.gz", failed_node_id)));

    if let Some(task) = seed_http_task.take() {
        seed_http_shutdown.shutdown();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("seed http cleanup timeout")
            .expect("seed http cleanup join")
            .expect("seed http cleanup result");
    }
    if let Some(task) = join_http_task.take() {
        join_http_shutdown.shutdown();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("join http cleanup timeout")
            .expect("join http cleanup join")
            .expect("join http cleanup result");
    }
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

fn tar_gz_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let mut entries = BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().to_string();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        entries.insert(path, data);
    }
    entries
}

fn json_entry(entries: &BTreeMap<String, Vec<u8>>, path: &str) -> serde_json::Value {
    serde_json::from_slice(
        entries
            .get(path)
            .unwrap_or_else(|| panic!("missing archive entry {path}")),
    )
    .unwrap_or_else(|err| panic!("invalid json in {path}: {err}"))
}

fn assert_cluster_bundle_shape(entries: &BTreeMap<String, Vec<u8>>, node_ids: &[u128]) {
    assert!(entries.contains_key("manifest.json"));
    assert!(entries.contains_key("cluster/overview.json"));
    assert!(entries.contains_key("cluster/failures.json"));
    for node_id in node_ids {
        assert!(entries.contains_key(&format!("nodes/{node_id}/meta.json")));
        assert!(entries.contains_key(&format!("nodes/{node_id}/sysdump.tar.gz")));
    }
}

fn assert_nested_sysdump(outer_entries: &BTreeMap<String, Vec<u8>>, node_id: &str) {
    let nested_path = format!("nodes/{node_id}/sysdump.tar.gz");
    let nested_entries = tar_gz_entries(
        outer_entries
            .get(&nested_path)
            .unwrap_or_else(|| panic!("missing nested sysdump {nested_path}")),
    );
    assert!(nested_entries.contains_key("summary/manifest.json"));
    assert!(nested_entries.contains_key("summary/state.json"));

    let state = json_entry(&nested_entries, "summary/state.json");
    assert!(
        state
            .get("generated_at")
            .and_then(serde_json::Value::as_str)
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "expected generated_at in nested state summary"
    );
}
