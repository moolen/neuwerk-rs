use super::*;
pub(super) fn cluster_leader_failover_can_join() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-failover")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_a_dir = base_dir.join("joiner-a");
    let joiner_b_dir = base_dir.join("joiner-b");
    let joiner_c_dir = base_dir.join("joiner-c");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_a_dir).map_err(|e| format!("joiner-a dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_b_dir).map_err(|e| format!("joiner-b dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_c_dir).map_err(|e| format!("joiner-c dir create failed: {e}"))?;

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
            bootstrap::run_cluster(seed_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("seed cluster start failed: {err}"))?,
        );

        let mut joiner_cfg = base_config(&joiner_a_dir, &token_path);
        joiner_cfg.bind_addr = joiner_a_addr;
        joiner_cfg.advertise_addr = joiner_a_addr;
        joiner_cfg.join_bind_addr = joiner_a_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_a = Some(
            bootstrap::run_cluster(joiner_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("joiner-a start failed: {err}"))?,
        );

        let mut joiner_cfg = base_config(&joiner_b_dir, &token_path);
        joiner_cfg.bind_addr = joiner_b_addr;
        joiner_cfg.advertise_addr = joiner_b_addr;
        joiner_cfg.join_bind_addr = joiner_b_join_addr;
        joiner_cfg.join_seed = Some(seed_join_addr);
        let mut joiner_b = Some(
            bootstrap::run_cluster(joiner_cfg.clone(), None, None)
                .await
                .map_err(|err| format!("joiner-b start failed: {err}"))?,
        );

        let seed_id = load_node_id(&seed_dir)?;
        let joiner_a_id = load_node_id(&joiner_a_dir)?;
        let joiner_b_id = load_node_id(&joiner_b_dir)?;

        let seed_ref = seed.as_ref().unwrap();
        wait_for_voter(&seed_ref.raft, joiner_a_id, Duration::from_secs(5)).await?;
        wait_for_voter(&seed_ref.raft, joiner_b_id, Duration::from_secs(5)).await?;
        wait_for_stable_membership(&seed_ref.raft, Duration::from_secs(5)).await?;

        wait_for_envelope(&seed_ref.store, seed_id, Duration::from_secs(5)).await?;
        wait_for_envelope(
            &joiner_a.as_ref().unwrap().store,
            joiner_a_id,
            Duration::from_secs(5),
        )
        .await?;
        wait_for_envelope(
            &joiner_b.as_ref().unwrap().store,
            joiner_b_id,
            Duration::from_secs(5),
        )
        .await?;

        let leader_id = wait_for_leader(&seed_ref.raft, Duration::from_secs(5)).await?;
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
        .await?;
        let new_leader_join_addr = if new_leader_id == seed_id {
            seed_join_addr
        } else if new_leader_id == joiner_a_id {
            joiner_a_join_addr
        } else {
            joiner_b_join_addr
        };

        let joiner_c_addr = next_addr();
        let joiner_c_join_addr = next_addr();
        let mut joiner_cfg = base_config(&joiner_c_dir, &token_path);
        joiner_cfg.bind_addr = joiner_c_addr;
        joiner_cfg.advertise_addr = joiner_c_addr;
        joiner_cfg.join_bind_addr = joiner_c_join_addr;
        joiner_cfg.join_seed = Some(new_leader_join_addr);
        let joiner_c = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner-c start failed: {err}"))?;

        let joiner_c_id = load_node_id(&joiner_c_dir)?;
        wait_for_voter(&remaining_a.raft, joiner_c_id, Duration::from_secs(5)).await?;

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
        Ok(())
    })
}
