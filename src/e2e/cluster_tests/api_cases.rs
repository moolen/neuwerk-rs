use super::*;

pub(super) fn http_api_proxy_to_leader() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-api-proxy")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let http_port = next_port_on(seed_ip);
    let mut metrics_port = next_port_on(seed_ip);
    while metrics_port == http_port {
        metrics_port = next_port_on(seed_ip);
    }

    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5)).await?;
        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;

        let seed_api_addr = SocketAddr::new(seed_ip.into(), http_port);
        let joiner_api_addr = SocketAddr::new(joiner_ip.into(), http_port);
        let seed_metrics_addr = SocketAddr::new(seed_ip.into(), metrics_port);
        let joiner_metrics_addr = SocketAddr::new(joiner_ip.into(), metrics_port);

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");
        let seed_policy_dir = seed_dir.join("policy-store");
        let joiner_policy_dir = joiner_dir.join("policy-store");

        ensure_http_tls(HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.raft.clone()),
            store: Some(seed.store.clone()),
        })
        .await?;

        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, b"http/ca/envelope", Duration::from_secs(5)).await?;

        ensure_http_tls(HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.raft.clone()),
            store: Some(joiner.store.clone()),
        })
        .await?;

        let seed_http = spawn_http_api(
            seed_api_addr,
            seed_metrics_addr,
            seed_tls_dir.clone(),
            seed_policy_dir.clone(),
            token_path.clone(),
            Some(HttpApiCluster {
                raft: seed.raft.clone(),
                store: seed.store.clone(),
            }),
        )?;
        let joiner_http = spawn_http_api(
            joiner_api_addr,
            joiner_metrics_addr,
            joiner_tls_dir.clone(),
            joiner_policy_dir.clone(),
            token_path.clone(),
            Some(HttpApiCluster {
                raft: joiner.raft.clone(),
                store: joiner.store.clone(),
            }),
        )?;

        http_wait_for_health(seed_api_addr, &seed_tls_dir, Duration::from_secs(5)).await?;
        http_wait_for_health(joiner_api_addr, &joiner_tls_dir, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, api_auth::API_KEYS_KEY, Duration::from_secs(5)).await?;
        let token = mint_auth_token(&seed.store)?;

        let seed_id = load_node_id(&seed_dir)?;
        let (leader_addr, leader_tls, follower_addr, follower_tls) = if leader_id == seed_id {
            (
                seed_api_addr,
                seed_tls_dir.clone(),
                joiner_api_addr,
                joiner_tls_dir.clone(),
            )
        } else {
            (
                joiner_api_addr,
                joiner_tls_dir.clone(),
                seed_api_addr,
                seed_tls_dir.clone(),
            )
        };

        let policy = sample_policy("proxy-policy")?;
        let expected = http_set_policy(
            follower_addr,
            &follower_tls,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let leader_policy = http_get_policy(leader_addr, &leader_tls, Some(&token)).await?;
        if serde_json::to_value(&leader_policy).map_err(|e| e.to_string())?
            != serde_json::to_value(&expected).map_err(|e| e.to_string())?
        {
            return Err("leader singleton policy did not match proxied write".to_string());
        }
        let follower_policy = http_get_policy(follower_addr, &follower_tls, Some(&token)).await?;
        if serde_json::to_value(&follower_policy).map_err(|e| e.to_string())?
            != serde_json::to_value(&expected).map_err(|e| e.to_string())?
        {
            return Err("follower singleton policy did not match proxied write".to_string());
        }

        wait_for_state_present(&seed.store, POLICY_STATE_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, POLICY_STATE_KEY, Duration::from_secs(5)).await?;

        seed_http.abort();
        joiner_http.abort();
        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}

pub(super) fn http_api_leader_loss() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-api-leader-loss")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let http_port = next_port_on(seed_ip);
    let mut metrics_port = next_port_on(seed_ip);
    while metrics_port == http_port {
        metrics_port = next_port_on(seed_ip);
    }

    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;
        let mut seed = Some(seed);
        let mut joiner = Some(joiner);

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(
            &seed.as_ref().unwrap().raft,
            joiner_id,
            Duration::from_secs(5),
        )
        .await?;
        let leader_id =
            wait_for_leader(&seed.as_ref().unwrap().raft, Duration::from_secs(5)).await?;
        let seed_id = load_node_id(&seed_dir)?;

        let seed_api_addr = SocketAddr::new(seed_ip.into(), http_port);
        let joiner_api_addr = SocketAddr::new(joiner_ip.into(), http_port);
        let seed_metrics_addr = SocketAddr::new(seed_ip.into(), metrics_port);
        let joiner_metrics_addr = SocketAddr::new(joiner_ip.into(), metrics_port);

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");
        let seed_policy_dir = seed_dir.join("policy-store");
        let joiner_policy_dir = joiner_dir.join("policy-store");

        ensure_http_tls(HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.as_ref().unwrap().raft.clone()),
            store: Some(seed.as_ref().unwrap().store.clone()),
        })
        .await?;

        wait_for_state_present(
            &joiner.as_ref().unwrap().store,
            b"http/ca/cert",
            Duration::from_secs(5),
        )
        .await?;
        wait_for_state_present(
            &joiner.as_ref().unwrap().store,
            b"http/ca/envelope",
            Duration::from_secs(5),
        )
        .await?;

        ensure_http_tls(HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.as_ref().unwrap().raft.clone()),
            store: Some(joiner.as_ref().unwrap().store.clone()),
        })
        .await?;

        let seed_http = spawn_http_api(
            seed_api_addr,
            seed_metrics_addr,
            seed_tls_dir.clone(),
            seed_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: seed.as_ref().unwrap().raft.clone(),
                store: seed.as_ref().unwrap().store.clone(),
            }),
        )?;
        let joiner_http = spawn_http_api(
            joiner_api_addr,
            joiner_metrics_addr,
            joiner_tls_dir.clone(),
            joiner_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: joiner.as_ref().unwrap().raft.clone(),
                store: joiner.as_ref().unwrap().store.clone(),
            }),
        )?;

        http_wait_for_health(seed_api_addr, &seed_tls_dir, Duration::from_secs(5)).await?;
        http_wait_for_health(joiner_api_addr, &joiner_tls_dir, Duration::from_secs(5)).await?;
        wait_for_state_present(
            &seed.as_ref().unwrap().store,
            api_auth::API_KEYS_KEY,
            Duration::from_secs(5),
        )
        .await?;
        let token = mint_auth_token(&seed.as_ref().unwrap().store)?;

        let (leader_is_seed, follower_addr, follower_tls) = if leader_id == seed_id {
            (
                true,
                joiner_api_addr,
                joiner_tls_dir.clone(),
            )
        } else {
            (
                false,
                seed_api_addr,
                seed_tls_dir.clone(),
            )
        };

        if leader_is_seed {
            seed.take().unwrap().shutdown().await;
            seed_http.abort();
        } else {
            joiner.take().unwrap().shutdown().await;
            joiner_http.abort();
        }

        let health = http_api_status(follower_addr, &follower_tls, "/health", None).await?;
        if !health.is_success() {
            return Err(format!("health status unexpected: {health}"));
        }

        http_wait_for_status(
            follower_addr,
            &follower_tls,
            "/api/v1/policy",
            Some(&token),
            &[
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                reqwest::StatusCode::BAD_GATEWAY,
            ],
            Duration::from_secs(20),
        )
        .await?;

        if leader_is_seed {
            joiner_http.abort();
            joiner.take().unwrap().shutdown().await;
        } else {
            seed_http.abort();
            seed.take().unwrap().shutdown().await;
        }
        Ok(())
    })
}

pub(super) fn cluster_audit_findings_live_generation_and_merge() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-audit-live-merge")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
    let http_port = next_port_on(seed_ip);
    let metrics_port = next_port_on(seed_ip);
    let seed_dns_port = next_port_on(seed_ip);
    let joiner_dns_port = next_port_on(joiner_ip);
    let seed_dns_addr = SocketAddr::new(seed_ip.into(), seed_dns_port);
    let joiner_dns_addr = SocketAddr::new(joiner_ip.into(), joiner_dns_port);

    let seed_addr = next_addr_on(seed_ip);
    let seed_join_addr = next_addr_on(seed_ip);
    let joiner_addr = next_addr_on(joiner_ip);
    let joiner_join_addr = next_addr_on(joiner_ip);

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;

        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5)).await?;
        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;
        let seed_id = load_node_id(&seed_dir)?;

        let seed_api_addr = SocketAddr::new(seed_ip.into(), http_port);
        let joiner_api_addr = SocketAddr::new(joiner_ip.into(), http_port);
        let seed_metrics_addr = SocketAddr::new(seed_ip.into(), metrics_port);
        let joiner_metrics_addr = SocketAddr::new(joiner_ip.into(), metrics_port);

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");
        let seed_policy_dir = seed_dir.join("policy-store");
        let joiner_policy_dir = joiner_dir.join("policy-store");
        let seed_audit_store = AuditStore::new(seed_dir.join("audit"), 1024 * 1024);
        let joiner_audit_store = AuditStore::new(joiner_dir.join("audit"), 1024 * 1024);

        ensure_http_tls(HttpTlsConfig {
            tls_dir: seed_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(seed.raft.clone()),
            store: Some(seed.store.clone()),
        })
        .await?;

        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, b"http/ca/envelope", Duration::from_secs(5)).await?;

        ensure_http_tls(HttpTlsConfig {
            tls_dir: joiner_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: joiner_addr,
            management_ip: joiner_addr.ip(),
            token_path: token_path.clone(),
            raft: Some(joiner.raft.clone()),
            store: Some(joiner.store.clone()),
        })
        .await?;

        let seed_http = spawn_http_api_with_audit(
            seed_api_addr,
            seed_metrics_addr,
            seed_tls_dir.clone(),
            seed_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: seed.raft.clone(),
                store: seed.store.clone(),
            }),
            Some(seed_audit_store.clone()),
        )?;
        let joiner_http = spawn_http_api_with_audit(
            joiner_api_addr,
            joiner_metrics_addr,
            joiner_tls_dir.clone(),
            joiner_policy_dir,
            token_path.clone(),
            Some(HttpApiCluster {
                raft: joiner.raft.clone(),
                store: joiner.store.clone(),
            }),
            Some(joiner_audit_store.clone()),
        )?;

        http_wait_for_health(seed_api_addr, &seed_tls_dir, Duration::from_secs(5)).await?;
        http_wait_for_health(joiner_api_addr, &joiner_tls_dir, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, api_auth::API_KEYS_KEY, Duration::from_secs(5)).await?;
        let token = mint_auth_token(&seed.store)?;

        let dns_policy: PolicyConfig = serde_yaml::from_str(
            r#"default_policy: deny
source_groups:
  - id: "apps"
    priority: 0
    mode: enforce
    sources:
      ips: ["127.0.0.1", "127.0.0.2"]
    rules:
      - id: "deny-live"
        priority: 0
        mode: enforce
        action: deny
        match:
          dns_hostname: '^live\.audit\.allowed$'
"#,
        )
        .map_err(|err| format!("policy yaml error: {err}"))?;
        let compiled = dns_policy.compile()?;
        let dns_policy = std::sync::Arc::new(std::sync::RwLock::new(compiled.dns_policy));

        let (seed_start_tx, seed_start_rx) = tokio::sync::oneshot::channel();
        let seed_dns_task = tokio::spawn(run_dns_proxy(
            seed_dns_addr,
            vec![SocketAddr::new(seed_ip.into(), 9)],
            Duration::from_secs(2),
            dns_policy.clone(),
            DnsMap::new(),
            Metrics::new().map_err(|err| format!("metrics init failed: {err}"))?,
            None,
            Some(seed_audit_store.clone()),
            None,
            None,
            "seed-node".to_string(),
            Some(seed_start_tx),
        ));
        match tokio::time::timeout(Duration::from_secs(2), seed_start_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => return Err(format!("seed dns startup failed: {err}")),
            Ok(Err(_)) => return Err("seed dns startup channel dropped".to_string()),
            Err(_) => return Err("seed dns startup timed out".to_string()),
        }

        let (joiner_start_tx, joiner_start_rx) = tokio::sync::oneshot::channel();
        let joiner_dns_task = tokio::spawn(run_dns_proxy(
            joiner_dns_addr,
            vec![SocketAddr::new(joiner_ip.into(), 9)],
            Duration::from_secs(2),
            dns_policy.clone(),
            DnsMap::new(),
            Metrics::new().map_err(|err| format!("metrics init failed: {err}"))?,
            None,
            Some(joiner_audit_store.clone()),
            None,
            None,
            "join-node".to_string(),
            Some(joiner_start_tx),
        ));
        match tokio::time::timeout(Duration::from_secs(2), joiner_start_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(err))) => return Err(format!("joiner dns startup failed: {err}")),
            Ok(Err(_)) => return Err("joiner dns startup channel dropped".to_string()),
            Err(_) => return Err("joiner dns startup timed out".to_string()),
        }

        let seed_resp = dns_query_response(
            SocketAddr::new(seed_ip.into(), 0),
            seed_dns_addr,
            "live.audit.allowed",
        )
        .await?;
        if seed_resp.rcode != 3 {
            return Err(format!(
                "seed dns expected NXDOMAIN, got {}",
                seed_resp.rcode
            ));
        }

        let joiner_resp = dns_query_response(
            SocketAddr::new(joiner_ip.into(), 0),
            joiner_dns_addr,
            "live.audit.allowed",
        )
        .await?;
        if joiner_resp.rcode != 3 {
            return Err(format!(
                "joiner dns expected NXDOMAIN, got {}",
                joiner_resp.rcode
            ));
        }

        let (leader_addr, leader_tls_dir) = if leader_id == seed_id {
            (seed_api_addr, seed_tls_dir.clone())
        } else {
            (joiner_api_addr, joiner_tls_dir.clone())
        };
        let query = "finding_type=dns_deny&source_group=apps&limit=100";
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut merged = None;
        while Instant::now() < deadline {
            let payload =
                http_get_audit_findings(leader_addr, &leader_tls_dir, query, Some(&token)).await?;
            if payload.items.iter().any(|item| {
                item.finding_type == crate::controlplane::audit::AuditFindingType::DnsDeny
                    && item.source_group == "apps"
                    && item.count >= 2
                    && item.node_ids.iter().any(|id| id == "seed-node")
                    && item.node_ids.iter().any(|id| id == "join-node")
            }) {
                merged = Some(payload);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if merged.is_none() {
            return Err("timed out waiting for merged cluster audit findings".to_string());
        }

        seed_dns_task.abort();
        joiner_dns_task.abort();
        seed_http.abort();
        joiner_http.abort();
        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}
