use super::*;
use uuid::Uuid;

#[tokio::test]
async fn http_api_get_singleton_policy() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let _policy_store_check = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let local_store_check = local_store.clone();
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
    let token = api_auth::mint_token(&keyset, "local-test", None, None).unwrap();
    let expired = api_auth::mint_token_at(
        &keyset,
        "local-test",
        Some(60),
        None,
        OffsetDateTime::now_utc() - TimeDuration::hours(1),
    )
    .unwrap();
    let ca_pem = fs::read(tls_dir.join("ca.crt")).unwrap();
    let ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let policy: neuwerk::controlplane::policy_config::PolicyConfig = resp.json().await.unwrap();
    assert!(matches!(
        policy.default_policy,
        Some(neuwerk::controlplane::policy_config::PolicyValue::String(ref value))
            if value == "deny"
    ));
    assert!(policy.source_groups.is_empty());

    let stored = local_store_check
        .read_state()
        .unwrap()
        .expect("stored singleton after bootstrap");
    assert_eq!(stored.policy.source_groups.len(), 0);

    let old_routes = [
        format!("https://{bind_addr}/api/v1/policies"),
        format!("https://{bind_addr}/api/v1/policies/{}", Uuid::new_v4()),
        format!("https://{bind_addr}/api/v1/policies/by-name/prod-default"),
    ];
    for path in old_routes {
        let resp = client
            .get(path)
            .bearer_auth(&token.token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    }

    let missing = client
        .get(format!("https://{bind_addr}/api/v1/policy"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);

    let expired_resp = client
        .get(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&expired.token)
        .send()
        .await
        .unwrap();
    assert_eq!(expired_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let metrics = reqwest::Client::new()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics.status().is_success());

    server.abort();
}

#[tokio::test]
async fn http_api_put_singleton_policy() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let policy_store_check = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let local_store_check = local_store.clone();
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
    let token = api_auth::mint_token(&keyset, "local-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let payload = serde_json::json!({
        "default_policy": "deny",
        "source_groups": [
            {
                "id": "local",
                "mode": "enforce",
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
    });
    let update = client
        .put(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(update.status().is_success());
    let updated: neuwerk::controlplane::policy_config::PolicyConfig = update.json().await.unwrap();
    assert_eq!(updated.source_groups.len(), 1);
    assert_eq!(updated.source_groups[0].id, "local");
    assert_eq!(
        updated.source_groups[0].mode,
        neuwerk::controlplane::policy_config::MatchModeValue::Enforce
    );

    let stored = local_store_check
        .read_state()
        .unwrap()
        .expect("stored singleton after update");
    assert_eq!(stored.policy.source_groups.len(), 1);
    assert_eq!(stored.policy.source_groups[0].id, "local");
    assert!(local_store_check.active_id().unwrap().is_some());
    assert!(policy_store_check.active_policy_id().is_some());

    let fetch = client
        .get(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(fetch.status().is_success());
    let fetched: neuwerk::controlplane::policy_config::PolicyConfig = fetch.json().await.unwrap();
    assert_eq!(fetched.source_groups.len(), 1);
    assert_eq!(fetched.source_groups[0].id, "local");

    let old_route = client
        .put(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(old_route.status(), reqwest::StatusCode::NOT_FOUND);

    server.abort();
}

#[tokio::test]
async fn http_api_integrations_lifecycle_and_policy_ref_validation() {
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
    let token = api_auth::mint_token(&keyset, "integration-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let create_payload = serde_json::json!({
        "name": "prod-k8s",
        "kind": "kubernetes",
        "api_server_url": "https://127.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "secret-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        created.get("name").and_then(|v| v.as_str()),
        Some("prod-k8s")
    );
    assert_eq!(
        created.get("kind").and_then(|v| v.as_str()),
        Some("kubernetes")
    );
    assert_eq!(
        created.get("token_configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        created.get("auth_type").and_then(|v| v.as_str()),
        Some("service_account_token")
    );
    assert!(
        created.get("service_account_token").is_none(),
        "service_account_token must be redacted from API responses"
    );

    let duplicate_payload = serde_json::json!({
        "name": "PROD-K8S",
        "kind": "kubernetes",
        "api_server_url": "https://10.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "other-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&duplicate_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let listed: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(listed.as_array().map(|arr| arr.len()), Some(1));

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        fetched.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://127.0.0.1:6443")
    );
    assert!(fetched.get("service_account_token").is_none());

    let update_payload = serde_json::json!({
        "api_server_url": "https://10.10.10.10:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
        "service_account_token": "updated-token",
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .json(&update_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        updated.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://10.10.10.10:6443")
    );
    assert!(updated.get("service_account_token").is_none());

    let missing_ref_policy = serde_json::json!({
        "default_policy": "deny",
        "source_groups": [
            {
                "id": "pods",
                "mode": "enforce",
                "sources": {
                    "kubernetes": [
                        {
                            "integration": "missing",
                            "pod_selector": {
                                "namespace": "default",
                                "match_labels": { "app": "web" }
                            }
                        }
                    ]
                },
                "rules": [
                    {
                        "id": "deny-all",
                        "action": "deny",
                        "match": {}
                    }
                ]
            }
        ]
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .json(&missing_ref_policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let valid_policy = serde_json::json!({
        "default_policy": "deny",
        "source_groups": [
            {
                "id": "pods",
                "mode": "enforce",
                "sources": {
                    "kubernetes": [
                        {
                            "integration": "prod-k8s",
                            "pod_selector": {
                                "namespace": "default",
                                "match_labels": { "app": "web" }
                            }
                        }
                    ]
                },
                "rules": [
                    {
                        "id": "allow-https",
                        "action": "allow",
                        "match": {
                            "proto": "tcp",
                            "dst_ports": [443]
                        }
                    }
                ]
            }
        ]
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .json(&valid_policy)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created_policy: neuwerk::controlplane::policy_config::PolicyConfig =
        resp.json().await.unwrap();
    assert_eq!(created_policy.source_groups.len(), 1);
    assert_eq!(created_policy.source_groups[0].id, "pods");

    let bad_update = serde_json::json!({
        "default_policy": "deny",
        "source_groups": [
            {
                "id": "pods",
                "mode": "enforce",
                "sources": {
                    "kubernetes": [
                        {
                            "integration": "missing",
                            "node_selector": {
                                "match_labels": { "node-role.kubernetes.io/control-plane": "true" }
                            }
                        }
                    ]
                }
            }
        ]
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .json(&bad_update)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let resp = client
        .delete(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    server.abort();
}

#[tokio::test]
async fn http_api_shutdown_transitions_readiness_closes_listeners_and_allows_restart() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let dataplane_config = DataplaneConfigStore::new();
    dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 2),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0x02, 0, 0, 0, 0, 1],
        lease_expiry: None,
    });
    let policy_store = PolicyStore::new_with_config(
        DefaultPolicy::Deny,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        dataplane_config.clone(),
    );
    let local_store = PolicyDiskStore::new(local_store_dir.clone());
    let seeded_policy = PolicyRecord::new(
        PolicyMode::Enforce,
        serde_yaml::from_str(
            r#"
default_policy: deny
source_groups:
  - id: local
    mode: enforce
    sources:
      ips:
        - 10.0.0.5
    rules:
      - id: allow-dns
        mode: enforce
        action: allow
        match:
          dns_hostname: example.com
"#,
        )
        .unwrap(),
        Some("shutdown-seeded".to_string()),
    )
    .unwrap();
    local_store.write_record(&seeded_policy).unwrap();
    local_store.set_active(Some(seeded_policy.id)).unwrap();
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
    let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
    let drain_control = neuwerk::dataplane::DrainControl::new();
    readiness.set_drain_control(drain_control.clone());
    let shutdown = http_api::HttpApiShutdown::new();

    let server = tokio::spawn(http_api::run_http_api_with_shutdown(
        cfg.clone(),
        policy_store,
        local_store,
        None,
        None,
        None,
        None,
        Some(readiness.clone()),
        Metrics::new().unwrap(),
        shutdown.clone(),
    ));

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
    wait_for_tcp(metrics_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "shutdown-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    wait_for_ready_status(&client, bind_addr, true, Duration::from_secs(2))
        .await
        .unwrap();

    drain_control.set_draining(true);
    readiness.set_dataplane_running(false);
    readiness.set_dns_ready(false);
    readiness.set_service_plane_ready(false);
    readiness.set_policy_ready(false);
    wait_for_ready_status(&client, bind_addr, false, Duration::from_secs(2))
        .await
        .unwrap();

    shutdown.graceful_shutdown(Some(Duration::from_millis(100)));
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("http shutdown timeout")
        .expect("http join")
        .expect("http shutdown result");
    wait_for_tcp_closed(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp_closed(metrics_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let restart_dataplane = DataplaneConfigStore::new();
    restart_dataplane.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 2),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0x02, 0, 0, 0, 0, 1],
        lease_expiry: None,
    });
    let restarted_policy_store = PolicyStore::new_with_config(
        DefaultPolicy::Deny,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        restart_dataplane.clone(),
    );
    let restarted_readiness = ReadinessState::new(
        restart_dataplane,
        restarted_policy_store.clone(),
        None,
        None,
    );
    restarted_readiness.set_dataplane_running(true);
    restarted_readiness.set_policy_ready(true);
    restarted_readiness.set_dns_ready(true);
    restarted_readiness.set_service_plane_ready(true);
    let restarted_shutdown = http_api::HttpApiShutdown::new();

    let restarted = tokio::spawn(http_api::run_http_api_with_shutdown(
        cfg,
        restarted_policy_store,
        PolicyDiskStore::new(local_store_dir),
        None,
        None,
        None,
        None,
        Some(restarted_readiness),
        Metrics::new().unwrap(),
        restarted_shutdown.clone(),
    ));

    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_ready_status(&client, bind_addr, true, Duration::from_secs(2))
        .await
        .unwrap();
    let listed = client
        .get(format!("https://{bind_addr}/api/v1/policy"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(listed.status().is_success());
    let listed: neuwerk::controlplane::policy_config::PolicyConfig = listed.json().await.unwrap();
    assert_eq!(listed.source_groups.len(), 1);
    assert_eq!(
        listed.source_groups[0].id,
        seeded_policy.policy.source_groups[0].id
    );

    restarted_shutdown.shutdown();
    tokio::time::timeout(Duration::from_secs(2), restarted)
        .await
        .expect("restart shutdown timeout")
        .expect("restart join")
        .expect("restart shutdown result");
}

#[test]
fn http_api_metrics_exposes_threat_series() {
    let metrics = Metrics::new().expect("create metrics");
    metrics.inc_threat_match("domain", "dns", "high", "default", "inline");
    metrics.inc_threat_alertable_match("domain", "dns", "high", "default");
    metrics.observe_threat_feed_refresh("default", "success");
    metrics.set_threat_feed_snapshot_age_seconds("default", 42);
    metrics.set_threat_feed_indicators("default", "domain", 7);
    metrics.inc_threat_backfill_run("success");
    metrics.observe_threat_backfill_duration(Duration::from_secs(3));
    metrics.inc_threat_enrichment_request("provider-a", "success");
    metrics.set_threat_enrichment_queue_depth(2);
    metrics.set_threat_findings_active("high", 1);
    metrics.set_threat_cluster_snapshot_version(9);

    let body = metrics.render().expect("render metrics");

    assert!(body.contains("neuwerk_threat_matches_total"));
    assert!(body.contains("neuwerk_threat_alertable_matches_total"));
    assert!(body.contains("neuwerk_threat_feed_refresh_total"));
    assert!(body.contains("neuwerk_threat_feed_snapshot_age_seconds"));
    assert!(body.contains("neuwerk_threat_feed_indicators"));
    assert!(body.contains("neuwerk_threat_backfill_runs_total"));
    assert!(body.contains("neuwerk_threat_backfill_duration_seconds"));
    assert!(body.contains("neuwerk_threat_enrichment_requests_total"));
    assert!(body.contains("neuwerk_threat_enrichment_queue_depth"));
    assert!(body.contains("neuwerk_threat_findings_active"));
    assert!(body.contains("neuwerk_threat_cluster_snapshot_version"));
}
