use super::*;

pub(super) fn cluster_migrate_from_local_enforce() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-migrate-enforce")?;
    let token_path = base_dir.join("bootstrap.json");
    write_token_file(&token_path)?;

    let seed_dir = base_dir.join("seed");
    let joiner_dir = base_dir.join("joiner");
    fs::create_dir_all(&seed_dir).map_err(|e| format!("seed dir create failed: {e}"))?;
    fs::create_dir_all(&joiner_dir).map_err(|e| format!("joiner dir create failed: {e}"))?;

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_addr = next_addr();
    let joiner_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_path);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let mut joiner_cfg = base_config(&joiner_dir, &token_path);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_join_addr);

    let http_tls_dir = seed_dir.join("http-tls");
    let local_policy_dir = seed_dir.join("local-policy");
    let local_sa_dir = seed_dir.join("service-accounts");

    api_auth::ensure_local_keyset(&http_tls_dir).map_err(|e| format!("local keyset: {e}"))?;
    let local_policy_store = PolicyDiskStore::new(local_policy_dir.clone());
    let _record = seed_local_policy(&local_policy_store, PolicyMode::Enforce)?;
    seed_local_service_accounts(&local_sa_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        ensure_http_tls(HttpTlsConfig {
            tls_dir: http_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: None,
            store: None,
        })
        .await?;
        seed_local_intercept_ca(&http_tls_dir)?;

        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let node_id = load_node_uuid(&seed_dir)?;
        let migrate_cfg = migration::MigrationConfig {
            enabled: true,
            force: false,
            verify: true,
            http_tls_dir: http_tls_dir.clone(),
            local_policy_store: local_policy_store.clone(),
            local_service_accounts_dir: local_sa_dir.clone(),
            cluster_data_dir: seed_dir.clone(),
            token_path: token_path.clone(),
            node_id,
        };
        let report = migration::run(&seed.raft, &seed.store, migrate_cfg).await?;
        if !report.migrated {
            return Err("migration did not run".to_string());
        }
        if !report.intercept_ca_seeded {
            return Err("migration did not seed tls intercept ca".to_string());
        }

        wait_for_state_present(&seed.store, POLICY_INDEX_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, POLICY_ACTIVE_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(
            &seed.store,
            b"auth/service-accounts/index",
            Duration::from_secs(5),
        )
        .await?;
        wait_for_state_present(&seed.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, INTERCEPT_CA_CERT_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(
            &seed.store,
            INTERCEPT_CA_ENVELOPE_KEY,
            Duration::from_secs(5),
        )
        .await?;

        let local_keyset =
            api_auth::load_keyset_from_file(&api_auth::local_keyset_path(&http_tls_dir))?
                .ok_or_else(|| "missing local keyset".to_string())?;
        let cluster_keyset = api_auth::load_keyset_from_store(&seed.store)?
            .ok_or_else(|| "missing cluster keyset".to_string())?;
        if !keysets_equivalent(&local_keyset, &cluster_keyset) {
            return Err("cluster keyset does not match local keyset".to_string());
        }

        let joiner = bootstrap::run_cluster(joiner_cfg, None, None)
            .await
            .map_err(|err| format!("joiner cluster start failed: {err}"))?;
        let joiner_id = load_node_id(&joiner_dir)?;
        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, POLICY_INDEX_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(
            &joiner.store,
            b"auth/service-accounts/index",
            Duration::from_secs(5),
        )
        .await?;
        wait_for_state_present(&joiner.store, b"http/ca/cert", Duration::from_secs(5)).await?;
        wait_for_state_present(&joiner.store, INTERCEPT_CA_CERT_KEY, Duration::from_secs(5))
            .await?;
        wait_for_state_present(
            &joiner.store,
            INTERCEPT_CA_ENVELOPE_KEY,
            Duration::from_secs(5),
        )
        .await?;

        let verify_report = migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: true,
                force: false,
                verify: true,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await?;
        if verify_report.migrated {
            return Err("migration should have been skipped after marker".to_string());
        }

        seed.shutdown().await;
        joiner.shutdown().await;
        Ok(())
    })
}

pub(super) fn cluster_migrate_from_local_audit() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-migrate-audit")?;
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

    let http_tls_dir = seed_dir.join("http-tls");
    let local_policy_dir = seed_dir.join("local-policy");
    let local_sa_dir = seed_dir.join("service-accounts");

    api_auth::ensure_local_keyset(&http_tls_dir).map_err(|e| format!("local keyset: {e}"))?;
    let local_policy_store = PolicyDiskStore::new(local_policy_dir.clone());
    let record = seed_local_policy(&local_policy_store, PolicyMode::Audit)?;
    seed_local_service_accounts(&local_sa_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        ensure_http_tls(HttpTlsConfig {
            tls_dir: http_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: None,
            store: None,
        })
        .await?;

        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let node_id = load_node_uuid(&seed_dir)?;
        let report = migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: true,
                force: false,
                verify: true,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await?;
        if !report.migrated {
            return Err("migration did not run".to_string());
        }

        wait_for_state_present(&seed.store, POLICY_INDEX_KEY, Duration::from_secs(5)).await?;
        wait_for_state_present(&seed.store, POLICY_ACTIVE_KEY, Duration::from_secs(5)).await?;
        let active_raw = seed
            .store
            .get_state_value(POLICY_ACTIVE_KEY)?
            .ok_or_else(|| "missing cluster active policy".to_string())?;
        let active: crate::controlplane::policy_repository::PolicyActive =
            serde_json::from_slice(&active_raw).map_err(|err| err.to_string())?;
        if active.id != record.id {
            return Err("audit policy should be active after migration".to_string());
        }

        seed.shutdown().await;
        Ok(())
    })
}

pub(super) fn cluster_migrate_requires_http_ca_key() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-migrate-no-ca-key")?;
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

    let http_tls_dir = seed_dir.join("http-tls");
    let local_policy_dir = seed_dir.join("local-policy");
    let local_sa_dir = seed_dir.join("service-accounts");

    api_auth::ensure_local_keyset(&http_tls_dir).map_err(|e| format!("local keyset: {e}"))?;
    let local_policy_store = PolicyDiskStore::new(local_policy_dir.clone());
    let _record = seed_local_policy(&local_policy_store, PolicyMode::Enforce)?;
    seed_local_service_accounts(&local_sa_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        ensure_http_tls(HttpTlsConfig {
            tls_dir: http_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: None,
            store: None,
        })
        .await?;
        let ca_key_path = http_tls_dir.join("ca.key");
        if ca_key_path.exists() {
            fs::remove_file(&ca_key_path).map_err(|e| format!("remove ca.key failed: {e}"))?;
        }

        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let node_id = load_node_uuid(&seed_dir)?;
        let result = migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: true,
                force: false,
                verify: false,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await;
        let err = match result {
            Ok(_) => {
                seed.shutdown().await;
                return Err("migration should have failed without ca.key".to_string());
            }
            Err(err) => err,
        };
        if !err.contains("ca.key") {
            seed.shutdown().await;
            return Err(format!("unexpected migration error: {err}"));
        }

        seed.shutdown().await;
        Ok(())
    })
}

pub(super) fn cluster_migrate_force_overwrites() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-migrate-force")?;
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

    let http_tls_dir = seed_dir.join("http-tls");
    let local_policy_dir = seed_dir.join("local-policy");
    let local_sa_dir = seed_dir.join("service-accounts");

    api_auth::ensure_local_keyset(&http_tls_dir).map_err(|e| format!("local keyset: {e}"))?;
    let local_policy_store = PolicyDiskStore::new(local_policy_dir.clone());
    let record_a = seed_local_policy(&local_policy_store, PolicyMode::Enforce)?;
    seed_local_service_accounts(&local_sa_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        ensure_http_tls(HttpTlsConfig {
            tls_dir: http_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: None,
            store: None,
        })
        .await?;

        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let node_id = load_node_uuid(&seed_dir)?;
        let migrate_cfg = migration::MigrationConfig {
            enabled: true,
            force: false,
            verify: true,
            http_tls_dir: http_tls_dir.clone(),
            local_policy_store: local_policy_store.clone(),
            local_service_accounts_dir: local_sa_dir.clone(),
            cluster_data_dir: seed_dir.clone(),
            token_path: token_path.clone(),
            node_id,
        };
        migration::run(&seed.raft, &seed.store, migrate_cfg).await?;

        local_policy_store
            .delete_record(record_a.id)
            .map_err(|err| format!("local delete policy failed: {err}"))?;
        let record_b = PolicyRecord::new(PolicyMode::Enforce, sample_policy("force-rule")?, None)?;
        local_policy_store
            .write_record(&record_b)
            .map_err(|err| format!("local write policy failed: {err}"))?;
        local_policy_store
            .set_active(Some(record_b.id))
            .map_err(|err| format!("local set active failed: {err}"))?;

        regenerate_local_keyset(&http_tls_dir)?;

        let report = migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: true,
                force: true,
                verify: true,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await?;
        if !report.migrated {
            return Err("force migration did not run".to_string());
        }

        let cluster_index_raw = seed
            .store
            .get_state_value(POLICY_INDEX_KEY)?
            .ok_or_else(|| "missing cluster policy index".to_string())?;
        let cluster_index: crate::controlplane::policy_repository::PolicyIndex =
            serde_json::from_slice(&cluster_index_raw).map_err(|err| err.to_string())?;
        if cluster_index.policies.len() != 1 || cluster_index.policies[0].id != record_b.id {
            return Err("force migration did not replace policy index".to_string());
        }
        let active_raw = seed
            .store
            .get_state_value(POLICY_ACTIVE_KEY)?
            .ok_or_else(|| "missing cluster active policy".to_string())?;
        let active: crate::controlplane::policy_repository::PolicyActive =
            serde_json::from_slice(&active_raw).map_err(|err| err.to_string())?;
        if active.id != record_b.id {
            return Err("force migration did not update active policy".to_string());
        }

        let local_keyset =
            api_auth::load_keyset_from_file(&api_auth::local_keyset_path(&http_tls_dir))?
                .ok_or_else(|| "missing local keyset".to_string())?;
        let cluster_keyset = api_auth::load_keyset_from_store(&seed.store)?
            .ok_or_else(|| "missing cluster keyset".to_string())?;
        if !keysets_equivalent(&local_keyset, &cluster_keyset) {
            return Err("force migration did not overwrite api keyset".to_string());
        }

        seed.shutdown().await;
        Ok(())
    })
}

pub(super) fn cluster_migrate_verify_detects_drift() -> Result<(), String> {
    ensure_rustls_provider();
    let base_dir = create_temp_dir("cluster-migrate-verify-drift")?;
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

    let http_tls_dir = seed_dir.join("http-tls");
    let local_policy_dir = seed_dir.join("local-policy");
    let local_sa_dir = seed_dir.join("service-accounts");

    api_auth::ensure_local_keyset(&http_tls_dir).map_err(|e| format!("local keyset: {e}"))?;
    let local_policy_store = PolicyDiskStore::new(local_policy_dir.clone());
    let record = seed_local_policy(&local_policy_store, PolicyMode::Enforce)?;
    seed_local_service_accounts(&local_sa_dir)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async move {
        ensure_http_tls(HttpTlsConfig {
            tls_dir: http_tls_dir.clone(),
            cert_path: None,
            key_path: None,
            ca_path: None,
            ca_key_path: None,
            san_entries: Vec::new(),
            advertise_addr: seed_addr,
            management_ip: seed_addr.ip(),
            token_path: token_path.clone(),
            raft: None,
            store: None,
        })
        .await?;

        let seed = bootstrap::run_cluster(seed_cfg, None, None)
            .await
            .map_err(|err| format!("seed cluster start failed: {err}"))?;

        let node_id = load_node_uuid(&seed_dir)?;
        migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: true,
                force: false,
                verify: true,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await?;

        local_policy_store
            .delete_record(record.id)
            .map_err(|err| format!("local delete policy failed: {err}"))?;

        let result = migration::run(
            &seed.raft,
            &seed.store,
            migration::MigrationConfig {
                enabled: false,
                force: false,
                verify: true,
                http_tls_dir: http_tls_dir.clone(),
                local_policy_store: local_policy_store.clone(),
                local_service_accounts_dir: local_sa_dir.clone(),
                cluster_data_dir: seed_dir.clone(),
                token_path: token_path.clone(),
                node_id,
            },
        )
        .await;
        let err = match result {
            Ok(_) => {
                seed.shutdown().await;
                return Err("verify should have failed on drift".to_string());
            }
            Err(err) => err,
        };
        if !err.contains("policy index mismatch") {
            seed.shutdown().await;
            return Err(format!("unexpected verify error: {err}"));
        }

        seed.shutdown().await;
        Ok(())
    })
}
