use super::*;

#[tokio::test]
async fn integration_client_publishes_termination_event() {
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

    let event = TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 123,
    };
    client
        .publish_termination_event(event.clone())
        .await
        .expect("publish termination event");

    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let entries = seed
            .store
            .scan_state_prefix(TERMINATION_PREFIX)
            .expect("termination scan");
        if let Some((_, value)) = entries.first() {
            let stored: TerminationEvent =
                serde_json::from_slice(value).expect("termination decode");
            assert_eq!(stored.id, event.id);
            assert_eq!(stored.instance_id, event.instance_id);
            assert_eq!(stored.deadline_epoch, event.deadline_epoch);
            break;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for termination event");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    seed.shutdown().await;
}

#[tokio::test]
async fn cluster_state_survives_restart_for_termination_events() {
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
    let restart_cfg = seed_cfg.clone();

    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    wait_for_leader(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let tls_dir = seed_dir.path().join("tls");
    let tls = RaftTlsConfig::load(tls_dir).expect("tls config");
    let mut client = IntegrationClient::connect(seed.bind_addr, tls)
        .await
        .expect("integration client");

    let event = TerminationEvent {
        id: "event-restart-1".to_string(),
        instance_id: "i-restart".to_string(),
        deadline_epoch: 789,
    };
    client
        .publish_termination_event(event.clone())
        .await
        .expect("publish termination event");

    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let entries = seed
            .store
            .scan_state_prefix(TERMINATION_PREFIX)
            .expect("termination scan");
        if entries.iter().any(|(_, value)| {
            let stored: TerminationEvent =
                serde_json::from_slice(value).expect("termination decode");
            stored.id == event.id
                && stored.instance_id == event.instance_id
                && stored.deadline_epoch == event.deadline_epoch
        }) {
            break;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for termination event");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    seed.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let restarted = bootstrap::run_cluster(restart_cfg, None, None)
        .await
        .unwrap();
    wait_for_leader(&restarted.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let entries = restarted
        .store
        .scan_state_prefix(TERMINATION_PREFIX)
        .expect("termination scan after restart");
    assert!(
        entries.iter().any(|(_, value)| {
            let stored: TerminationEvent =
                serde_json::from_slice(value).expect("termination decode");
            stored.id == event.id
                && stored.instance_id == event.instance_id
                && stored.deadline_epoch == event.deadline_epoch
        }),
        "expected termination event to survive restart"
    );

    restarted.shutdown().await;
}

#[tokio::test]
async fn cluster_backup_copy_preserves_termination_events() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let backup_dir = TempDir::new().unwrap();
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

    let event = TerminationEvent {
        id: "event-backup-1".to_string(),
        instance_id: "i-backup".to_string(),
        deadline_epoch: 456,
    };
    client
        .publish_termination_event(event.clone())
        .await
        .expect("publish termination event");

    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let entries = seed
            .store
            .scan_state_prefix(TERMINATION_PREFIX)
            .expect("termination scan");
        if let Some((_, value)) = entries.first() {
            let stored: TerminationEvent =
                serde_json::from_slice(value).expect("termination decode");
            if stored.id == event.id {
                break;
            }
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for termination event");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    seed.shutdown().await;

    let backup_path = backup_dir.path().join("cluster-backup");
    copy_dir_all(seed_dir.path(), &backup_path).expect("backup copy");
    let backup_store = neuwerk::controlplane::cluster::store::ClusterStore::open_read_only(
        backup_path.join("raft"),
    )
    .expect("open backup store read-only");
    let entries = backup_store
        .scan_state_prefix(TERMINATION_PREFIX)
        .expect("backup termination scan");
    assert_eq!(
        entries.len(),
        1,
        "expected one termination record in backup"
    );
    let stored: TerminationEvent = serde_json::from_slice(&entries[0].1).expect("backup decode");
    assert_eq!(stored.id, event.id);
    assert_eq!(stored.instance_id, event.instance_id);
    assert_eq!(stored.deadline_epoch, event.deadline_epoch);
}

#[tokio::test]
async fn cluster_migration_verify_detects_policy_drift() {
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

    let http_tls_dir = seed_dir.path().join("http-tls");
    ensure_http_tls(HttpTlsConfig {
        tls_dir: http_tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        ca_key_path: None,
        san_entries: Vec::new(),
        advertise_addr: seed_addr,
        management_ip: seed_addr.ip(),
        token_path: token_file.clone(),
        raft: None,
        store: None,
    })
    .await
    .expect("ensure local http tls");

    let local_policy_store = PolicyDiskStore::new(seed_dir.path().join("local-policy-store"));
    let local_policy = PolicyRecord::new(
        PolicyMode::Enforce,
        PolicyConfig {
            default_policy: None,
            source_groups: Vec::new(),
        },
        None,
    )
    .expect("policy record");
    local_policy_store
        .write_record(&local_policy)
        .expect("write local policy");

    let node_id = uuid::Uuid::parse_str(
        fs::read_to_string(seed_dir.path().join("node_id"))
            .expect("node id read")
            .trim(),
    )
    .expect("node id parse");
    let local_service_accounts_dir = seed_dir.path().join("service-accounts");

    migration::run(
        &seed.raft,
        &seed.store,
        migration::MigrationConfig {
            enabled: true,
            force: false,
            verify: true,
            http_tls_dir: http_tls_dir.clone(),
            local_policy_store: local_policy_store.clone(),
            local_service_accounts_dir: local_service_accounts_dir.clone(),
            cluster_data_dir: seed_dir.path().to_path_buf(),
            token_path: token_file.clone(),
            node_id,
        },
    )
    .await
    .expect("initial migration run");

    local_policy_store
        .delete_record(local_policy.id)
        .expect("delete local policy to create drift");

    let verify_err = migration::run(
        &seed.raft,
        &seed.store,
        migration::MigrationConfig {
            enabled: false,
            force: false,
            verify: true,
            http_tls_dir,
            local_policy_store,
            local_service_accounts_dir,
            cluster_data_dir: seed_dir.path().to_path_buf(),
            token_path: token_file,
            node_id,
        },
    )
    .await
    .expect_err("verify-only should fail on drift");
    assert!(
        verify_err.contains("policy index mismatch"),
        "unexpected verify error: {verify_err}"
    );

    seed.shutdown().await;
}

#[tokio::test]
async fn rollback_restart_rejoins_and_continues_replication() {
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

    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    let joiner = bootstrap::run_cluster(joiner_cfg.clone(), None, None)
        .await
        .unwrap();

    let joiner_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5))
        .await
        .unwrap();

    let tls_dir = seed_dir.path().join("tls");
    let tls = RaftTlsConfig::load(tls_dir).expect("tls config");
    let mut client = IntegrationClient::connect(seed.bind_addr, tls)
        .await
        .expect("integration client");

    client
        .publish_termination_event(TerminationEvent {
            id: "rollback-event-1".to_string(),
            instance_id: "rollback-a".to_string(),
            deadline_epoch: 111,
        })
        .await
        .expect("publish rollback-event-1");
    wait_for_termination_count(&joiner.store, 1, Duration::from_secs(5))
        .await
        .unwrap();

    joiner.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let joiner_restart = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();
    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_termination_count(&joiner_restart.store, 1, Duration::from_secs(5))
        .await
        .unwrap();

    client
        .publish_termination_event(TerminationEvent {
            id: "rollback-event-2".to_string(),
            instance_id: "rollback-b".to_string(),
            deadline_epoch: 222,
        })
        .await
        .expect("publish rollback-event-2");
    wait_for_termination_count(&joiner_restart.store, 2, Duration::from_secs(5))
        .await
        .unwrap();

    seed.shutdown().await;
    joiner_restart.shutdown().await;
}
