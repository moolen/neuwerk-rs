use super::*;

#[tokio::test]
async fn join_flow_promotes_and_restarts() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_addr = next_addr();
    let joiner_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let seed = bootstrap::run_cluster(seed_cfg.clone(), None, None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut joiner_cfg = base_config(&joiner_dir, &token_file);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);

    let joiner = bootstrap::run_cluster(joiner_cfg.clone(), None, None)
        .await
        .unwrap();

    let tls_dir = joiner_dir.path().join("tls");
    assert!(tls_dir.join("node.key").exists());
    assert!(tls_dir.join("node.crt").exists());
    assert!(tls_dir.join("ca.crt").exists());

    let joiner_id_raw = fs::read_to_string(joiner_dir.path().join("node_id")).unwrap();
    let joiner_id = uuid::Uuid::parse_str(joiner_id_raw.trim())
        .unwrap()
        .as_u128();

    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(10))
        .await
        .unwrap();

    joiner.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _joiner_restart = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();
    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(10))
        .await
        .unwrap();
}

#[tokio::test]
async fn membership_change_removes_node() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_a_dir = TempDir::new().unwrap();
    let joiner_b_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();

    let mut joiner_cfg = base_config(&joiner_a_dir, &token_file);
    joiner_cfg.bind_addr = joiner_a_addr;
    joiner_cfg.advertise_addr = joiner_a_addr;
    joiner_cfg.join_bind_addr = joiner_a_join_addr;
    joiner_cfg.join_seed = Some(seed.join_bind_addr);
    let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let mut joiner_cfg = base_config(&joiner_b_dir, &token_file);
    joiner_cfg.bind_addr = joiner_b_addr;
    joiner_cfg.advertise_addr = joiner_b_addr;
    joiner_cfg.join_bind_addr = joiner_b_join_addr;
    joiner_cfg.join_seed = Some(seed.join_bind_addr);
    let _joiner_b = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let joiner_a_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_a_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_b_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_b_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();

    wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_voter(&seed.raft, joiner_b_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_stable_membership(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let seed_id = uuid::Uuid::parse_str(
        fs::read_to_string(seed_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let mut voters = BTreeSet::new();
    voters.insert(seed_id);
    voters.insert(joiner_b_id);
    change_membership_with_retry(&seed.raft, voters, Duration::from_secs(5))
        .await
        .unwrap();

    let mut metrics = seed.raft.metrics();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let m = metrics.borrow().clone();
        let voters: BTreeSet<_> = m.membership_config.membership().voter_ids().collect();
        if !voters.contains(&joiner_a_id) && voters.contains(&joiner_b_id) {
            break;
        }
        if Instant::now() >= deadline {
            panic!("membership change did not apply");
        }
        let remaining = deadline - Instant::now();
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .unwrap()
            .unwrap();
    }

    joiner_a.shutdown().await;
}

#[tokio::test]
async fn mtls_requires_client_cert() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tls_dir = seed_dir.path().join("tls");
    let ca = fs::read(tls_dir.join("ca.crt")).unwrap();
    let cert = fs::read(tls_dir.join("node.crt")).unwrap();
    let key = fs::read(tls_dir.join("node.key")).unwrap();

    let endpoint = Endpoint::from_shared(format!("https://{seed_addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2));
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca.clone()));
    let channel = endpoint
        .clone()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        firewall::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
            channel,
        );
    let resp = client
        .vote(firewall::controlplane::cluster::rpc::proto::RaftRequest {
            payload: Vec::new(),
        })
        .await;
    match resp {
        Err(status) if status.code() == tonic::Code::InvalidArgument => {
            panic!("mTLS not enforced: request reached service without client cert")
        }
        Err(_) => {}
        Ok(_) => panic!("unexpected success without client cert"),
    }

    let identity = Identity::from_pem(cert, key);
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(identity);
    let channel = endpoint.tls_config(tls).unwrap().connect().await.unwrap();
    let mut client =
        firewall::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
            channel,
        );
    let resp = client
        .vote(firewall::controlplane::cluster::rpc::proto::RaftRequest {
            payload: Vec::new(),
        })
        .await;
    match resp {
        Err(status) if status.code() == tonic::Code::InvalidArgument => {}
        Err(status) => panic!("unexpected response: {status:?}"),
        Ok(_) => panic!("unexpected success with empty payload"),
    }

    seed.shutdown().await;
}

#[tokio::test]
async fn leader_failover_can_sign_and_join() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_a_dir = TempDir::new().unwrap();
    let joiner_b_dir = TempDir::new().unwrap();
    let joiner_c_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    let mut seed = Some(
        bootstrap::run_cluster(seed_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let mut joiner_cfg = base_config(&joiner_a_dir, &token_file);
    joiner_cfg.bind_addr = joiner_a_addr;
    joiner_cfg.advertise_addr = joiner_a_addr;
    joiner_cfg.join_bind_addr = joiner_a_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);
    let mut joiner_a = Some(
        bootstrap::run_cluster(joiner_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let mut joiner_cfg = base_config(&joiner_b_dir, &token_file);
    joiner_cfg.bind_addr = joiner_b_addr;
    joiner_cfg.advertise_addr = joiner_b_addr;
    joiner_cfg.join_bind_addr = joiner_b_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);
    let mut joiner_b = Some(
        bootstrap::run_cluster(joiner_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let seed_id = uuid::Uuid::parse_str(
        fs::read_to_string(seed_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_a_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_a_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_b_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_b_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();

    let seed_ref = seed.as_ref().unwrap();
    wait_for_voter(&seed_ref.raft, joiner_a_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_voter(&seed_ref.raft, joiner_b_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_stable_membership(&seed_ref.raft, Duration::from_secs(5))
        .await
        .unwrap();

    wait_for_envelope(&seed_ref.store, seed_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_envelope(
        &joiner_a.as_ref().unwrap().store,
        joiner_a_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_envelope(
        &joiner_b.as_ref().unwrap().store,
        joiner_b_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let leader_id = wait_for_leader(&seed_ref.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let (remaining_a, remaining_b) = if leader_id == seed_id {
        seed.take().unwrap().shutdown().await;
        (joiner_a.as_ref().unwrap(), joiner_b.as_ref().unwrap())
    } else if leader_id == joiner_a_id {
        joiner_a.take().unwrap().shutdown().await;
        (seed.as_ref().unwrap(), joiner_b.as_ref().unwrap())
    } else {
        joiner_b.take().unwrap().shutdown().await;
        (seed.as_ref().unwrap(), joiner_a.as_ref().unwrap())
    };

    let new_leader_id = wait_for_new_leader(
        [&remaining_a.raft, &remaining_b.raft],
        leader_id,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let new_leader_join_addr = if new_leader_id == seed_id {
        seed_join_addr
    } else if new_leader_id == joiner_a_id {
        joiner_a_join_addr
    } else {
        joiner_b_join_addr
    };

    let joiner_c_addr = next_addr();
    let joiner_c_join_addr = next_addr();
    let mut joiner_cfg = base_config(&joiner_c_dir, &token_file);
    joiner_cfg.bind_addr = joiner_c_addr;
    joiner_cfg.advertise_addr = joiner_c_addr;
    joiner_cfg.join_bind_addr = joiner_c_join_addr;
    joiner_cfg.join_seed = Some(new_leader_join_addr);
    let joiner_c = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let joiner_c_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_c_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    wait_for_voter(&remaining_a.raft, joiner_c_id, Duration::from_secs(5))
        .await
        .unwrap();

    if let Some(seed) = seed.take() {
        seed.shutdown().await;
    }
    if let Some(joiner_a) = joiner_a.take() {
        joiner_a.shutdown().await;
    }
    if let Some(joiner_b) = joiner_b.take() {
        joiner_b.shutdown().await;
    }
    joiner_c.shutdown().await;
}
