use super::*;
pub(super) fn cluster_mtls_enforced() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-mtls")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    let seed_addr = next_addr();
    let seed_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let tls_dir = seed_dir.join("tls");
        let ca =
            fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca cert failed: {e}"))?;
        let cert = fs::read(tls_dir.join("node.crt"))
            .map_err(|e| format!("read node cert failed: {e}"))?;
        let key =
            fs::read(tls_dir.join("node.key")).map_err(|e| format!("read node key failed: {e}"))?;

        let endpoint = Endpoint::from_shared(format!("https://{seed_addr}"))
            .map_err(|e| format!("invalid endpoint: {e}"))?
            .connect_timeout(Duration::from_secs(2));

        let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca.clone()));
        let channel = endpoint
            .clone()
            .tls_config(tls)
            .map_err(|e| format!("tls config failed: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("connect without identity failed: {e}"))?;
        let mut client =
            crate::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
                channel,
            );
        let resp = client
            .vote(crate::controlplane::cluster::rpc::proto::RaftRequest {
                payload: Vec::new(),
            })
            .await;
        match resp {
            Err(status) if status.code() == tonic::Code::InvalidArgument => {
                let _ = seed.shutdown().await;
                return Err(
                    "mTLS not enforced: request reached service without client cert".to_string(),
                );
            }
            Err(_) => {}
            Ok(_) => {
                let _ = seed.shutdown().await;
                return Err("mTLS not enforced: unexpected success without client cert".to_string());
            }
        }

        let identity = Identity::from_pem(cert, key);
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(identity);
        let channel = endpoint
            .tls_config(tls)
            .map_err(|e| format!("tls config failed: {e}"))?
            .connect()
            .await
            .map_err(|e| format!("connect with identity failed: {e}"))?;
        let mut client =
            crate::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
                channel,
            );
        let resp = client
            .vote(crate::controlplane::cluster::rpc::proto::RaftRequest {
                payload: Vec::new(),
            })
            .await;
        match resp {
            Err(status) if status.code() == tonic::Code::InvalidArgument => {}
            Err(status) => {
                let _ = seed.shutdown().await;
                return Err(format!("unexpected mTLS response: {status:?}"));
            }
            Ok(_) => {
                let _ = seed.shutdown().await;
                return Err("unexpected success with empty payload".to_string());
            }
        }

        seed.shutdown().await;
        Ok(())
    })
}

pub(super) fn http_tls_ca_replication_joiner() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-tls-repl")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let joiner_ip = Ipv4Addr::new(127, 0, 0, 2);
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

        let seed_tls_dir = seed_dir.join("http-tls");
        let joiner_tls_dir = joiner_dir.join("http-tls");

        let seed_tls = HttpTlsConfig {
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
        };
        ensure_http_tls(seed_tls).await?;
        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, b"http/ca/envelope", Duration::from_secs(5)).await?;

        let joiner_tls = HttpTlsConfig {
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
        };
        ensure_http_tls(joiner_tls).await?;

        let seed_ca = fs::read(seed_tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        let joiner_ca =
            fs::read(joiner_tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        if seed_ca != joiner_ca {
            return Err("joiner CA does not match seed CA".to_string());
        }

        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}

pub(super) fn http_tls_ca_persists_restart() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("http-tls-restart")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;
    let seed_dir = base_dir.join("seed");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let tls_dir = seed_dir.join("http-tls");
        let tls_cfg = HttpTlsConfig {
            tls_dir: tls_dir.clone(),
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
        };

        ensure_http_tls(tls_cfg.clone()).await?;
        let ca_first = fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        let stored = seed
            .store
            .get_state_value(b"http/ca/cert")?
            .ok_or_else(|| "missing http ca in store".to_string())?;
        if stored != ca_first {
            return Err("stored CA does not match local CA".to_string());
        }

        if tls_dir.exists() {
            fs::remove_dir_all(&tls_dir).map_err(|e| format!("remove tls dir failed: {e}"))?;
        }
        ensure_http_tls(tls_cfg).await?;
        let ca_second = fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read ca: {e}"))?;
        if ca_second != ca_first {
            return Err("CA changed after restart".to_string());
        }

        seed.shutdown().await;
        Ok(())
    })
}

pub(super) fn cluster_replication_put() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-repl")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-a start failed: {err}"))?;

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5)).await?;

        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;
        let leader = if leader_id == seed_id {
            &seed
        } else {
            &joiner_a
        };

        let key = b"rules/active".to_vec();
        let value = b"v1".to_vec();
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: key.clone(),
                value: value.clone(),
            })
            .await
            .map_err(|err| format!("client_write put failed: {err:?}"))?;

        wait_for_state_value(&seed.store, &key, &value, Duration::from_secs(5)).await?;
        wait_for_state_value(&joiner_a.store, &key, &value, Duration::from_secs(5)).await?;

        if leader_id == seed_id {
            joiner_a.shutdown().await;
            seed.shutdown().await;
        } else {
            seed.shutdown().await;
            joiner_a.shutdown().await;
        }
        Ok(())
    })
}

pub(super) fn cluster_gc_deterministic() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-gc")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        let mut seed_cfg = base_config(&seed_dir, &token_path);
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-a start failed: {err}"))?;

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5)).await?;

        let leader_id = wait_for_leader(&seed.raft, Duration::from_secs(5)).await?;
        let leader = if leader_id == seed_id {
            &seed
        } else {
            &joiner_a
        };

        let stale_key = b"dns/last_seen/foo.allowed/203.0.113.10".to_vec();
        let stale_ts =
            bincode::serialize(&10i64).map_err(|e| format!("encode stale ts failed: {e}"))?;
        let stale_map_key = b"dns/map/foo.allowed/203.0.113.10".to_vec();
        let stale_map_val = b"stale".to_vec();

        let fresh_key = b"dns/last_seen/foo.allowed/203.0.113.20".to_vec();
        let fresh_ts =
            bincode::serialize(&200i64).map_err(|e| format!("encode fresh ts failed: {e}"))?;
        let fresh_map_key = b"dns/map/foo.allowed/203.0.113.20".to_vec();
        let fresh_map_val = b"fresh".to_vec();

        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: stale_key.clone(),
                value: stale_ts,
            })
            .await
            .map_err(|err| format!("put stale last_seen failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: stale_map_key.clone(),
                value: stale_map_val.clone(),
            })
            .await
            .map_err(|err| format!("put stale map failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: fresh_key.clone(),
                value: fresh_ts,
            })
            .await
            .map_err(|err| format!("put fresh last_seen failed: {err:?}"))?;
        leader
            .raft
            .client_write(ClusterCommand::Put {
                key: fresh_map_key.clone(),
                value: fresh_map_val.clone(),
            })
            .await
            .map_err(|err| format!("put fresh map failed: {err:?}"))?;

        wait_for_state_present(&seed.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &stale_key, Duration::from_secs(5)).await?;

        leader
            .raft
            .client_write(ClusterCommand::Gc { cutoff_unix: 100 })
            .await
            .map_err(|err| format!("gc command failed: {err:?}"))?;

        wait_for_state_absent(&seed.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_absent(&seed.store, &stale_map_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, &fresh_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, &fresh_map_key, Duration::from_secs(5)).await?;

        wait_for_state_absent(&joiner_a.store, &stale_key, Duration::from_secs(5)).await?;
        wait_for_state_absent(&joiner_a.store, &stale_map_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &fresh_key, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner_a.store, &fresh_map_key, Duration::from_secs(5)).await?;

        if leader_id == seed_id {
            joiner_a.shutdown().await;
            seed.shutdown().await;
        } else {
            seed.shutdown().await;
            joiner_a.shutdown().await;
        }
        Ok(())
    })
}
