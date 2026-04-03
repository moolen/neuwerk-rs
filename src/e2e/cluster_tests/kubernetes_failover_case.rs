use super::*;
pub(super) fn cluster_kubernetes_resolver_leader_failover() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-k8s-failover")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    let joiner_b_dir = base_dir.join("joiner-b");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_b_dir).map_err(|e| format!("joiner-b dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let mut seed = Some(
            bootstrap::run_cluster(seed_cfg, None, None)
                .await
                .map_err(|err| format!("seed cluster start failed: {err}"))?,
        );

        let mut joiner_a_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_a_cfg.bind_addr = joiner_a_addr;
        joiner_a_cfg.advertise_addr = joiner_a_addr;
        joiner_a_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_a_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_a = Some(
            bootstrap::run_cluster(joiner_a_cfg, None, None)
                .await
                .map_err(|err| format!("joiner-a start failed: {err}"))?,
        );

        let mut joiner_b_cfg = base_config(&joiner_b_dir, &token_path);
        joiner_b_cfg.bind_addr = joiner_b_addr;
        joiner_b_cfg.advertise_addr = joiner_b_addr;
        joiner_b_cfg.join_bind_addr = joiner_b_join_addr;
        joiner_b_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_b = Some(
            bootstrap::run_cluster(joiner_b_cfg, None, None)
                .await
                .map_err(|err| format!("joiner-b start failed: {err}"))?,
        );

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        let joiner_b_id = load_node_id(&joiner_b_dir)?;

        wait_for_voter(
            &seed.as_ref().unwrap().raft,
            joiner_a_id,
            Duration::from_secs(5),
        )
        .await?;
        wait_for_voter(
            &seed.as_ref().unwrap().raft,
            joiner_b_id,
            Duration::from_secs(5),
        )
        .await?;
        wait_for_stable_membership(&seed.as_ref().unwrap().raft, Duration::from_secs(5)).await?;

        let leader_id =
            wait_for_leader(&seed.as_ref().unwrap().raft, Duration::from_secs(5)).await?;

        let seed_policy_store =
            PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let joiner_a_policy_store =
            PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let joiner_b_policy_store =
            PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);

        let seed_integration_store = IntegrationStore::cluster(
            seed.as_ref().unwrap().raft.clone(),
            seed.as_ref().unwrap().store.clone(),
            token_path.clone(),
        );
        let joiner_a_integration_store = IntegrationStore::cluster(
            joiner_a.as_ref().unwrap().raft.clone(),
            joiner_a.as_ref().unwrap().store.clone(),
            token_path.clone(),
        );
        let joiner_b_integration_store = IntegrationStore::cluster(
            joiner_b.as_ref().unwrap().raft.clone(),
            joiner_b.as_ref().unwrap().store.clone(),
            token_path.clone(),
        );

        let mock_token = "mock-k8s-token".to_string();
        let (mock_addr, mock_state, mock_task) =
            start_mock_kubernetes_api(mock_token.clone()).await?;
        let api_server_url = format!("http://{mock_addr}");
        let ca_pem = mock_ca_pem()?;
        let integration_name = "cluster-failover-k8s";

        if leader_id == seed_id {
            seed_integration_store
                .create_kubernetes(
                    integration_name.to_string(),
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        } else if leader_id == joiner_a_id {
            joiner_a_integration_store
                .create_kubernetes(
                    integration_name.to_string(),
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        } else {
            joiner_b_integration_store
                .create_kubernetes(
                    integration_name.to_string(),
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        }

        let policy_yaml = format!(
            r#"default_policy: deny
source_groups:
  - id: cluster-k8s
    mode: enforce
    sources:
      kubernetes:
        - integration: "{integration_name}"
          pod_selector:
            namespace: default
            match_labels:
              app: demo
    rules:
      - id: allow-udp-8080
        action: allow
        match:
          proto: udp
          dst_ports: [8080]
"#
        );
        let policy: PolicyConfig = serde_yaml::from_str(&policy_yaml)
            .map_err(|err| format!("policy yaml error: {err}"))?;
        seed_policy_store.rebuild_from_config(policy.clone())?;
        joiner_a_policy_store.rebuild_from_config(policy.clone())?;
        joiner_b_policy_store.rebuild_from_config(policy)?;

        wait_for_binding_count(&seed_policy_store, 1, Duration::from_secs(5)).await?;
        wait_for_binding_count(&joiner_a_policy_store, 1, Duration::from_secs(5)).await?;
        wait_for_binding_count(&joiner_b_policy_store, 1, Duration::from_secs(5)).await?;

        let seed_resolver = tokio::spawn(run_kubernetes_resolver(
            seed_policy_store.clone(),
            seed_integration_store.clone(),
            Duration::from_secs(10),
            Duration::from_millis(500),
        ));
        let joiner_a_resolver = tokio::spawn(run_kubernetes_resolver(
            joiner_a_policy_store.clone(),
            joiner_a_integration_store.clone(),
            Duration::from_secs(10),
            Duration::from_millis(500),
        ));
        let joiner_b_resolver = tokio::spawn(run_kubernetes_resolver(
            joiner_b_policy_store.clone(),
            joiner_b_integration_store.clone(),
            Duration::from_secs(10),
            Duration::from_millis(500),
        ));

        let old_ip = Ipv4Addr::new(10, 42, 0, 10);
        let new_ip = Ipv4Addr::new(10, 42, 0, 11);
        *mock_state.pod_ip.write().await = Some(old_ip);

        wait_for_dynamic_ips_exact(
            &seed_policy_store,
            BTreeSet::from([old_ip]),
            Duration::from_secs(20),
        )
        .await?;
        wait_for_dynamic_ips_exact(
            &joiner_a_policy_store,
            BTreeSet::from([old_ip]),
            Duration::from_secs(20),
        )
        .await?;
        wait_for_dynamic_ips_exact(
            &joiner_b_policy_store,
            BTreeSet::from([old_ip]),
            Duration::from_secs(20),
        )
        .await?;

        if leader_id == seed_id {
            seed.take().unwrap().shutdown().await;
        } else if leader_id == joiner_a_id {
            joiner_a.take().unwrap().shutdown().await;
        } else {
            joiner_b.take().unwrap().shutdown().await;
        }

        let (raft_a, raft_b) = if leader_id == seed_id {
            (
                joiner_a.as_ref().unwrap().raft.clone(),
                joiner_b.as_ref().unwrap().raft.clone(),
            )
        } else if leader_id == joiner_a_id {
            (
                seed.as_ref().unwrap().raft.clone(),
                joiner_b.as_ref().unwrap().raft.clone(),
            )
        } else {
            (
                seed.as_ref().unwrap().raft.clone(),
                joiner_a.as_ref().unwrap().raft.clone(),
            )
        };
        let new_leader_id =
            wait_for_new_leader([&raft_a, &raft_b], leader_id, Duration::from_secs(10)).await?;

        *mock_state.pod_ip.write().await = Some(new_ip);
        if leader_id != seed_id {
            wait_for_dynamic_ips_exact(
                &seed_policy_store,
                BTreeSet::from([new_ip]),
                Duration::from_secs(20),
            )
            .await?;
        }
        if leader_id != joiner_a_id {
            wait_for_dynamic_ips_exact(
                &joiner_a_policy_store,
                BTreeSet::from([new_ip]),
                Duration::from_secs(20),
            )
            .await?;
        }
        if leader_id != joiner_b_id {
            wait_for_dynamic_ips_exact(
                &joiner_b_policy_store,
                BTreeSet::from([new_ip]),
                Duration::from_secs(20),
            )
            .await?;
        }

        if new_leader_id == seed_id {
            seed_integration_store
                .update_kubernetes(
                    integration_name,
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        } else if new_leader_id == joiner_a_id {
            joiner_a_integration_store
                .update_kubernetes(
                    integration_name,
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        } else {
            joiner_b_integration_store
                .update_kubernetes(
                    integration_name,
                    api_server_url.clone(),
                    ca_pem.clone(),
                    mock_token.clone(),
                )
                .await?;
        }

        let check_store = if leader_id != seed_id {
            &seed_policy_store
        } else if leader_id != joiner_a_id {
            &joiner_a_policy_store
        } else {
            &joiner_b_policy_store
        };
        let allow_new = evaluate_udp_8080(check_store, new_ip, 61000);
        if allow_new != (Action::Forward { out_port: 0 }) {
            return Err(format!(
                "expected allow for new ip {new_ip} after failover, got {allow_new:?}"
            ));
        }
        let deny_old = evaluate_udp_8080(check_store, old_ip, 61001);
        if deny_old != Action::Drop {
            return Err(format!(
                "expected drop for old ip {old_ip} after failover, got {deny_old:?}"
            ));
        }

        seed_resolver.abort();
        joiner_a_resolver.abort();
        joiner_b_resolver.abort();
        mock_task.abort();

        if let Some(seed) = seed.take() {
            seed.shutdown().await;
        }
        if let Some(joiner_a) = joiner_a.take() {
            joiner_a.shutdown().await;
        }
        if let Some(joiner_b) = joiner_b.take() {
            joiner_b.shutdown().await;
        }
        Ok(())
    })
}

#[derive(Clone)]
struct MockKubernetesState {
    token: String,
    pod_ip: Arc<tokio::sync::RwLock<Option<Ipv4Addr>>>,
    resource_version: Arc<AtomicU64>,
}

#[derive(Debug, Deserialize)]
struct MockPodListQuery {
    watch: Option<String>,
    #[serde(rename = "labelSelector")]
    _label_selector: Option<String>,
}

async fn start_mock_kubernetes_api(
    token: String,
) -> Result<(SocketAddr, MockKubernetesState, tokio::task::JoinHandle<()>), String> {
    let state = MockKubernetesState {
        token,
        pod_ip: Arc::new(tokio::sync::RwLock::new(None)),
        resource_version: Arc::new(AtomicU64::new(1)),
    };
    let app = axum::Router::new()
        .route("/api/v1/namespaces/default/pods", get(mock_kubernetes_pods))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|err| format!("mock kubernetes bind failed: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("mock kubernetes local_addr failed: {err}"))?;
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state, task))
}

async fn mock_kubernetes_pods(
    State(state): State<MockKubernetesState>,
    Query(query): Query<MockPodListQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let expected = format!("Bearer {}", state.token);
    let got = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    if got != expected {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if query.watch.as_deref() == Some("true") {
        return StatusCode::GONE.into_response();
    }
    let resource_version = state.resource_version.fetch_add(1, Ordering::SeqCst);
    let pod_ip = *state.pod_ip.read().await;
    let items = if let Some(ip) = pod_ip {
        vec![json!({
            "metadata": {
                "uid": "mock-pod-uid",
                "resourceVersion": resource_version.to_string(),
                "labels": {"app": "demo"}
            },
            "status": {"podIP": ip.to_string()}
        })]
    } else {
        Vec::new()
    };
    Json(json!({
        "items": items,
        "metadata": {"resourceVersion": resource_version.to_string()}
    }))
    .into_response()
}
