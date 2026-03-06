use super::*;

#[tokio::test]
async fn cluster_concurrent_writes_converge_across_failover() {
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

    let mut joiner_a_cfg = base_config(&joiner_a_dir, &token_file);
    joiner_a_cfg.bind_addr = joiner_a_addr;
    joiner_a_cfg.advertise_addr = joiner_a_addr;
    joiner_a_cfg.join_bind_addr = joiner_a_join_addr;
    joiner_a_cfg.join_seed = Some(seed_join_addr);

    let mut joiner_b_cfg = base_config(&joiner_b_dir, &token_file);
    joiner_b_cfg.bind_addr = joiner_b_addr;
    joiner_b_cfg.advertise_addr = joiner_b_addr;
    joiner_b_cfg.join_bind_addr = joiner_b_join_addr;
    joiner_b_cfg.join_seed = Some(seed_join_addr);

    let mut seed = Some(bootstrap::run_cluster(seed_cfg, None, None).await.unwrap());
    let mut joiner_a = Some(
        bootstrap::run_cluster(joiner_a_cfg, None, None)
            .await
            .unwrap(),
    );
    let mut joiner_b = Some(
        bootstrap::run_cluster(joiner_b_cfg, None, None)
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

    wait_for_voter(
        &seed.as_ref().unwrap().raft,
        joiner_a_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_voter(
        &seed.as_ref().unwrap().raft,
        joiner_b_id,
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

    let all_rafts = vec![
        seed.as_ref().unwrap().raft.clone(),
        joiner_a.as_ref().unwrap().raft.clone(),
        joiner_b.as_ref().unwrap().raft.clone(),
    ];
    let write_values: Vec<Vec<u8>> = (0..12)
        .map(|idx| format!("policy-v{idx:02}").into_bytes())
        .collect();
    let expected_final = write_values.last().unwrap().clone();
    let writer = tokio::spawn({
        let rafts = all_rafts.clone();
        async move {
            for value in &write_values {
                write_put_with_retry(&rafts, b"rules/active", value, Duration::from_secs(10))
                    .await?;
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            Ok::<Vec<u8>, String>(expected_final)
        }
    });

    tokio::time::sleep(Duration::from_millis(120)).await;
    if leader_id == seed_id {
        seed.take().unwrap().shutdown().await;
    } else if leader_id == joiner_a_id {
        joiner_a.take().unwrap().shutdown().await;
    } else {
        joiner_b.take().unwrap().shutdown().await;
    }

    let surviving_rafts: Vec<openraft::Raft<ClusterTypeConfig>> = vec![
        seed.as_ref().map(|rt| rt.raft.clone()),
        joiner_a.as_ref().map(|rt| rt.raft.clone()),
        joiner_b.as_ref().map(|rt| rt.raft.clone()),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert_eq!(
        surviving_rafts.len(),
        2,
        "expected exactly two surviving voters"
    );
    wait_for_new_leader(
        [&surviving_rafts[0], &surviving_rafts[1]],
        leader_id,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    let final_value = writer
        .await
        .expect("writer task join")
        .expect("writer completes with quorum");

    let surviving_stores = vec![
        seed.as_ref().map(|rt| rt.store.clone()),
        joiner_a.as_ref().map(|rt| rt.store.clone()),
        joiner_b.as_ref().map(|rt| rt.store.clone()),
    ];
    for store in surviving_stores.into_iter().flatten() {
        wait_for_state_value(
            &store,
            b"rules/active",
            &final_value,
            Duration::from_secs(8),
        )
        .await
        .unwrap();
    }

    if let Some(seed) = seed.take() {
        seed.shutdown().await;
    }
    if let Some(joiner_a) = joiner_a.take() {
        joiner_a.shutdown().await;
    }
    if let Some(joiner_b) = joiner_b.take() {
        joiner_b.shutdown().await;
    }
}
