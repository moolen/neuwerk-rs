use super::*;

#[tokio::test]
async fn termination_event_replay_overwrites_single_instance_record() {
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
    wait_for_leader(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let tls_dir = seed_dir.path().join("tls");
    let tls = RaftTlsConfig::load(tls_dir).expect("tls config");
    let mut client = IntegrationClient::connect(seed.bind_addr, tls)
        .await
        .expect("integration client");

    let instance_id = "i-replay";
    let first = TerminationEvent {
        id: "event-replay-1".to_string(),
        instance_id: instance_id.to_string(),
        deadline_epoch: 111,
    };
    let second = TerminationEvent {
        id: "event-replay-2".to_string(),
        instance_id: instance_id.to_string(),
        deadline_epoch: 222,
    };

    client
        .publish_termination_event(first)
        .await
        .expect("publish first replay event");
    client
        .publish_termination_event(second.clone())
        .await
        .expect("publish second replay event");

    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let entries = seed
            .store
            .scan_state_prefix(TERMINATION_PREFIX)
            .expect("termination scan");
        if entries.len() == 1 {
            let stored: TerminationEvent =
                serde_json::from_slice(&entries[0].1).expect("termination decode");
            if stored == second {
                break;
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for replay overwrite to converge");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    seed.shutdown().await;
}

#[tokio::test]
async fn termination_clear_is_idempotent_and_republishable() {
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
    wait_for_leader(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let tls_dir = seed_dir.path().join("tls");
    let tls = RaftTlsConfig::load(tls_dir).expect("tls config");
    let mut client = IntegrationClient::connect(seed.bind_addr, tls)
        .await
        .expect("integration client");

    let instance_id = "i-clear";
    let key = format!("integration/termination/{instance_id}");
    let first = TerminationEvent {
        id: "event-clear-1".to_string(),
        instance_id: instance_id.to_string(),
        deadline_epoch: 300,
    };
    client
        .publish_termination_event(first)
        .await
        .expect("publish initial termination event");
    wait_for_state_value(
        &seed.store,
        key.as_bytes(),
        &serde_json::to_vec(&TerminationEvent {
            id: "event-clear-1".to_string(),
            instance_id: instance_id.to_string(),
            deadline_epoch: 300,
        })
        .unwrap(),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    client
        .clear_termination_event(instance_id.to_string())
        .await
        .expect("clear termination event");
    wait_for_state_absent(&seed.store, key.as_bytes(), Duration::from_secs(3))
        .await
        .unwrap();

    client
        .clear_termination_event(instance_id.to_string())
        .await
        .expect("clear termination event idempotent");
    wait_for_state_absent(&seed.store, key.as_bytes(), Duration::from_secs(3))
        .await
        .unwrap();

    let second = TerminationEvent {
        id: "event-clear-2".to_string(),
        instance_id: instance_id.to_string(),
        deadline_epoch: 450,
    };
    client
        .publish_termination_event(second.clone())
        .await
        .expect("republish termination event");
    wait_for_state_value(
        &seed.store,
        key.as_bytes(),
        &serde_json::to_vec(&second).unwrap(),
        Duration::from_secs(3),
    )
    .await
    .unwrap();

    seed.shutdown().await;
}

#[tokio::test]
async fn cluster_write_blocks_without_quorum_and_recovers_after_rejoin() {
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

    let mut joiner_cfg = base_config(&joiner_dir, &token_file);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let mut seed = Some(bootstrap::run_cluster(seed_cfg, None, None).await.unwrap());
    let mut joiner = Some(
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
    let joiner_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();

    wait_for_voter(
        &seed.as_ref().unwrap().raft,
        joiner_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_stable_membership(&seed.as_ref().unwrap().raft, Duration::from_secs(5))
        .await
        .unwrap();

    let leader_id = wait_for_leader(&seed.as_ref().unwrap().raft, Duration::from_secs(5))
        .await
        .unwrap();

    let (survivor_raft, survivor_store, restart_cfg, stopped_id) = if leader_id == seed_id {
        let stopped = joiner.take().unwrap();
        stopped.shutdown().await;
        (
            seed.as_ref().unwrap().raft.clone(),
            seed.as_ref().unwrap().store.clone(),
            joiner_cfg,
            joiner_id,
        )
    } else {
        let stopped = seed.take().unwrap();
        stopped.shutdown().await;
        (
            joiner.as_ref().unwrap().raft.clone(),
            joiner.as_ref().unwrap().store.clone(),
            {
                let mut cfg = base_config(&seed_dir, &token_file);
                cfg.bind_addr = seed_addr;
                cfg.advertise_addr = seed_addr;
                cfg.join_bind_addr = seed_join_addr;
                cfg
            },
            seed_id,
        )
    };

    let no_quorum_cmd = ClusterCommand::Put {
        key: b"rules/active".to_vec(),
        value: b"no-quorum".to_vec(),
    };
    let no_quorum = tokio::time::timeout(
        Duration::from_secs(2),
        survivor_raft.client_write(no_quorum_cmd),
    )
    .await;
    if let Ok(Ok(_)) = no_quorum {
        panic!("write unexpectedly succeeded without quorum");
    }

    let restarted = bootstrap::run_cluster(restart_cfg, None, None)
        .await
        .unwrap();
    wait_for_voter(&survivor_raft, stopped_id, Duration::from_secs(8))
        .await
        .unwrap();

    let desired = b"quorum-restored".to_vec();
    write_put_with_retry(
        &[survivor_raft.clone(), restarted.raft.clone()],
        b"rules/active",
        &desired,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    wait_for_state_value(
        &survivor_store,
        b"rules/active",
        &desired,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(
        &restarted.store,
        b"rules/active",
        &desired,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    if let Some(seed) = seed.take() {
        seed.shutdown().await;
    }
    if let Some(joiner) = joiner.take() {
        joiner.shutdown().await;
    }
    restarted.shutdown().await;
}
