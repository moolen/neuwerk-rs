use std::path::Path;
use std::process::Command;

use super::*;

fn mint_local_http_token(bin: &str, tls_dir: &Path, sub: &str) -> Result<String, String> {
    let output = Command::new(bin)
        .args([
            "auth",
            "token",
            "mint",
            "--sub",
            sub,
            "--ttl",
            "5m",
            "--roles",
            "admin",
            "--http-tls-dir",
            tls_dir
                .to_str()
                .ok_or_else(|| "tls dir not utf8".to_string())?,
        ])
        .output()
        .map_err(|err| format!("spawn neuwerk auth mint failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "auth mint failed: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let token = String::from_utf8(output.stdout)
        .map_err(|err| format!("token output was not utf8: {err}"))?;
    Ok(token.trim().to_string())
}

#[tokio::test]
async fn http_api_cluster_follower_accepts_locally_minted_http_tls_token() {
    ensure_rustls_provider();
    let seed_root = TempDir::new().unwrap();
    let join_root = TempDir::new().unwrap();
    let seed_cluster_dir = seed_root.path().join("cluster");
    let join_cluster_dir = join_root.path().join("cluster");
    let seed_token = seed_root.path().join("bootstrap.json");
    let join_token = join_root.path().join("bootstrap.json");
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
    seed_cfg.data_dir = seed_cluster_dir.clone();
    seed_cfg.node_id_path = seed_cluster_dir.join("node_id");
    seed_cfg.token_path = seed_token.clone();

    let mut join_cfg = ClusterConfig::disabled();
    join_cfg.enabled = true;
    join_cfg.bind_addr = join_addr;
    join_cfg.join_bind_addr = join_join_addr;
    join_cfg.advertise_addr = join_addr;
    join_cfg.join_seed = Some(seed_join_addr);
    join_cfg.data_dir = join_cluster_dir.clone();
    join_cfg.node_id_path = join_cluster_dir.join("node_id");
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
    wait_for_voter(
        &seed_runtime.raft,
        join_runtime.raft.metrics().borrow().id,
        Duration::from_secs(5),
    )
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
        tls_dir: seed_root.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        external_url: None,
        cluster_tls_dir: Some(seed_cluster_dir.join("tls")),
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics,
        allow_public_metrics_bind: false,
        tls_dir: join_root.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        external_url: None,
        cluster_tls_dir: Some(join_cluster_dir.join("tls")),
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_root.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_root.path().join("policies"));
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
        &seed_root.path().join("http-tls").join("ca.crt"),
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
        &join_root.path().join("http-tls").join("ca.crt"),
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

    let cluster_keyset = api_auth::load_keyset_from_store(&join_runtime.store)
        .unwrap()
        .expect("cluster keyset");
    let stale_source_dir = TempDir::new().unwrap();
    let stale_keyset =
        api_auth::ensure_local_keyset(&stale_source_dir.path().join("http-tls")).unwrap();
    assert_ne!(stale_keyset.active_kid, cluster_keyset.active_kid);
    let join_tls_dir = join_root.path().join("http-tls");
    let join_local_keyset_path = api_auth::local_keyset_path(&join_tls_dir);
    api_auth::persist_keyset_to_file(&join_local_keyset_path, &stale_keyset).unwrap();

    let token = mint_local_http_token(
        env!("CARGO_BIN_EXE_neuwerk"),
        &join_tls_dir,
        "threat-cluster-local-follower",
    )
    .unwrap();
    assert!(!token.is_empty());

    let repaired_keyset = api_auth::load_keyset_from_file(&join_local_keyset_path)
        .unwrap()
        .expect("repaired follower keyset");
    assert_eq!(repaired_keyset.active_kid, cluster_keyset.active_kid);

    let client = http_api_client(&join_tls_dir).unwrap();

    let whoami = client
        .get(format!("https://{join_http_addr}/api/v1/auth/whoami"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status(), reqwest::StatusCode::OK);
    let whoami_body: serde_json::Value = whoami.json().await.unwrap();
    assert_eq!(
        whoami_body.get("sub").and_then(|value| value.as_str()),
        Some("threat-cluster-local-follower")
    );

    let feed_status = client
        .get(format!(
            "https://{join_http_addr}/api/v1/threats/feeds/status"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(feed_status.status(), reqwest::StatusCode::OK);

    if let Some(task) = seed_http_task.take() {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = join_http_task.take() {
        task.abort();
        let _ = task.await;
    }
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}
