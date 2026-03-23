use std::time::Duration;

use super::*;

pub(super) async fn persist_cluster_policy(
    cluster: &HttpApiCluster,
    record: &PolicyRecord,
) -> Result<(), String> {
    persist_cluster_policy_with_step_delay(cluster, record, None).await
}

async fn persist_cluster_policy_with_step_delay(
    cluster: &HttpApiCluster,
    record: &PolicyRecord,
    step_delay: Option<Duration>,
) -> Result<(), String> {
    let record_bytes = serde_json::to_vec(record).map_err(|err| err.to_string())?;
    let item_key = policy_item_key(record.id);
    let mut index = read_cluster_index(&cluster.store)?;
    let meta = PolicyMeta::from(record);
    if let Some(existing) = index.policies.iter_mut().find(|item| item.id == meta.id) {
        *existing = meta;
    } else {
        index.policies.push(meta);
    }
    index.policies.sort_by(|a, b| {
        let ts = a.created_at.cmp(&b.created_at);
        if ts == std::cmp::Ordering::Equal {
            a.id.as_bytes().cmp(b.id.as_bytes())
        } else {
            ts
        }
    });
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    let mut commands = Vec::new();
    if record.mode.is_active() {
        let active = PolicyActive { id: record.id };
        let active_bytes = serde_json::to_vec(&active).map_err(|err| err.to_string())?;
        commands.push(ClusterCommand::Put {
            key: POLICY_ACTIVE_KEY.to_vec(),
            value: active_bytes,
        });
    } else if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
        if active.id == record.id {
            commands.push(ClusterCommand::Delete {
                key: POLICY_ACTIVE_KEY.to_vec(),
            });
        }
    }
    // Move the active pointer first so leader-local applies are never rolled
    // back by replication while the new record and index are still being
    // persisted to the cluster store.
    commands.push(ClusterCommand::Put {
        key: item_key,
        value: record_bytes,
    });
    commands.push(ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    });

    let last_idx = commands.len().saturating_sub(1);
    for (idx, cmd) in commands.into_iter().enumerate() {
        cluster
            .raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        if idx != last_idx {
            if let Some(delay) = step_delay {
                tokio::time::sleep(delay).await;
            }
        }
    }

    Ok(())
}

pub(super) async fn delete_cluster_policy(
    cluster: &HttpApiCluster,
    id: Uuid,
) -> Result<(), String> {
    let cmd = ClusterCommand::Delete {
        key: policy_item_key(id),
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let mut index = read_cluster_index(&cluster.store)?;
    index.policies.retain(|meta| meta.id != id);
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
        if active.id == id {
            let cmd = ClusterCommand::Delete {
                key: POLICY_ACTIVE_KEY.to_vec(),
            };
            cluster
                .raft
                .client_write(cmd)
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    Ok(())
}

pub(super) fn read_cluster_index(store: &ClusterStore) -> Result<PolicyIndex, String> {
    let raw = store.get_state_value(POLICY_INDEX_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
        None => Ok(PolicyIndex::default()),
    }
}

pub(super) fn read_cluster_active(store: &ClusterStore) -> Result<Option<PolicyActive>, String> {
    let raw = store.get_state_value(POLICY_ACTIVE_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use tempfile::TempDir;

    use crate::controlplane::cluster::bootstrap;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::types::ClusterTypeConfig;
    use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
    use crate::controlplane::policy_replication::run_policy_replication;
    use crate::controlplane::PolicyStore;
    use crate::dataplane::policy::{DefaultPolicy, EnforcementMode};

    fn ensure_rustls_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    fn next_local_addr() -> SocketAddr {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    fn write_token_file(path: &Path) {
        let json = serde_json::json!({
            "tokens": [
                {
                    "kid": "test",
                    "token": "b64:dGVzdC1zZWNyZXQ=",
                    "valid_until": "2027-01-01T00:00:00Z"
                }
            ]
        });
        fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn base_config(data_dir: &TempDir, token_path: &Path) -> ClusterConfig {
        let mut cfg = ClusterConfig::disabled();
        cfg.enabled = true;
        cfg.data_dir = data_dir.path().to_path_buf();
        cfg.token_path = token_path.to_path_buf();
        cfg.node_id_path = data_dir.path().join("node_id");
        cfg
    }

    async fn wait_for_leader(
        raft: &openraft::Raft<ClusterTypeConfig>,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut metrics = raft.metrics();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let snapshot = metrics.borrow().clone();
            if snapshot.current_leader == Some(snapshot.id) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("timed out waiting for cluster leader".to_string());
            }
            metrics.changed().await.map_err(|err| err.to_string())?;
        }
    }

    async fn wait_for_local_active(
        local_store: &PolicyDiskStore,
        id: uuid::Uuid,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if local_store.active_id().map_err(|err| err.to_string())? == Some(id) {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("timed out waiting for local active policy {id}"));
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn allow_policy() -> PolicyConfig {
        serde_yaml::from_str(
            r#"
default_policy: allow
"#,
        )
        .unwrap()
    }

    fn deny_policy() -> PolicyConfig {
        serde_yaml::from_str(
            r#"
default_policy: deny
"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn persist_cluster_policy_does_not_rollback_leader_local_active_state() {
        ensure_rustls_provider();

        let cluster_dir = TempDir::new().unwrap();
        let local_dir = TempDir::new().unwrap();
        let token_path = cluster_dir.path().join("bootstrap.json");
        write_token_file(&token_path);

        let bind_addr = next_local_addr();
        let join_bind_addr = next_local_addr();
        let mut cfg = base_config(&cluster_dir, &token_path);
        cfg.bind_addr = bind_addr;
        cfg.advertise_addr = bind_addr;
        cfg.join_bind_addr = join_bind_addr;

        let cluster = bootstrap::run_cluster(cfg, None, None).await.unwrap();
        wait_for_leader(&cluster.raft, Duration::from_secs(5))
            .await
            .unwrap();
        let http_cluster = HttpApiCluster {
            raft: cluster.raft.clone(),
            store: cluster.store.clone(),
        };

        let baseline = PolicyRecord::new(
            PolicyMode::Enforce,
            allow_policy(),
            Some("baseline".to_string()),
        )
        .unwrap();
        persist_cluster_policy(&http_cluster, &baseline)
            .await
            .unwrap();

        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);
        let local_store = PolicyDiskStore::new(local_dir.path().join("local-policy-store"));
        let task = tokio::spawn(run_policy_replication(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store.clone(),
            None,
            Duration::from_millis(100),
        ));

        wait_for_local_active(&local_store, baseline.id, Duration::from_secs(3))
            .await
            .unwrap();

        let audited = PolicyRecord::new(
            PolicyMode::Audit,
            deny_policy(),
            Some("audited".to_string()),
        )
        .unwrap();
        let compiled = audited.policy.clone().compile().unwrap();
        policy_store
            .rebuild_with_kubernetes_bindings(
                compiled.groups,
                compiled.dns_policy,
                compiled.default_policy,
                EnforcementMode::Audit,
                compiled.kubernetes_bindings,
            )
            .unwrap();
        policy_store.set_active_policy_id(Some(audited.id));
        local_store.write_record(&audited).unwrap();
        local_store.set_active(Some(audited.id)).unwrap();
        persist_cluster_policy_with_step_delay(&http_cluster, &audited, None)
            .await
            .unwrap();

        let replacement = PolicyRecord::new(
            PolicyMode::Enforce,
            allow_policy(),
            Some("replacement".to_string()),
        )
        .unwrap();
        let compiled = replacement.policy.clone().compile().unwrap();
        policy_store
            .rebuild_with_kubernetes_bindings(
                compiled.groups,
                compiled.dns_policy,
                compiled.default_policy,
                EnforcementMode::Enforce,
                compiled.kubernetes_bindings,
            )
            .unwrap();
        policy_store.set_active_policy_id(Some(replacement.id));
        local_store.write_record(&replacement).unwrap();
        local_store.set_active(Some(replacement.id)).unwrap();

        persist_cluster_policy_with_step_delay(
            &http_cluster,
            &replacement,
            Some(Duration::from_millis(150)),
        )
        .await
        .unwrap();

        assert_eq!(
            local_store.active_id().unwrap(),
            Some(replacement.id),
            "cluster persistence should not roll back the leader-local active policy"
        );

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }
}
