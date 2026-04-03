use std::time::Duration;

use super::*;
use crate::controlplane::policy_repository::{StoredPolicy, POLICY_STATE_KEY};

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
    let state = StoredPolicy::from_record(record);
    let state_bytes = serde_json::to_vec(&state).map_err(|err| err.to_string())?;
    let commands = vec![ClusterCommand::Put {
        key: POLICY_STATE_KEY.to_vec(),
        value: state_bytes,
    }];

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

#[allow(dead_code)]
pub(super) fn read_cluster_index(store: &ClusterStore) -> Result<PolicyIndex, String> {
    let raw = store.get_state_value(POLICY_STATE_KEY)?;
    match raw {
        Some(raw) => {
            let state: StoredPolicy =
                serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
            Ok(PolicyIndex {
                policies: vec![PolicyMeta::from(&state.record())],
            })
        }
        None => Ok(PolicyIndex::default()),
    }
}

#[allow(dead_code)]
pub(super) fn read_cluster_active(store: &ClusterStore) -> Result<Option<PolicyActive>, String> {
    let raw = store.get_state_value(POLICY_STATE_KEY)?;
    match raw {
        Some(raw) => {
            let state: StoredPolicy =
                serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
            Ok(state.active_id().map(|id| PolicyActive { id }))
        }
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use tempfile::TempDir;

    use crate::controlplane::cluster::bootstrap;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::types::ClusterTypeConfig;
    use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
    use crate::controlplane::policy_replication::{
        run_policy_replication, run_policy_replication_with_local_apply_guard,
    };
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

    #[tokio::test]
    async fn leader_local_apply_window_is_not_overwritten_before_cluster_persist() {
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

        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);
        let local_store = PolicyDiskStore::new(local_dir.path().join("local-policy-store"));
        let leader_local_policy_apply_count = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn(run_policy_replication_with_local_apply_guard(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store.clone(),
            None,
            Some(leader_local_policy_apply_count.clone()),
            Duration::from_millis(200),
        ));

        // Let the first replication tick observe an empty cluster store so the
        // next tick still sees the committed baseline with an empty cache.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let baseline = PolicyRecord::new(
            PolicyMode::Enforce,
            allow_policy(),
            Some("baseline".to_string()),
        )
        .unwrap();
        persist_cluster_policy(&http_cluster, &baseline)
            .await
            .unwrap();

        let replacement = PolicyRecord::new(
            PolicyMode::Enforce,
            deny_policy(),
            Some("replacement".to_string()),
        )
        .unwrap();
        let compiled = replacement.policy.clone().compile().unwrap();
        leader_local_policy_apply_count.fetch_add(1, Ordering::AcqRel);
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

        tokio::time::sleep(Duration::from_millis(250)).await;

        assert_eq!(
            local_store.active_id().unwrap(),
            Some(replacement.id),
            "leader-local apply should survive replication until cluster persistence completes"
        );

        persist_cluster_policy(&http_cluster, &replacement)
            .await
            .unwrap();
        leader_local_policy_apply_count.fetch_sub(1, Ordering::AcqRel);

        wait_for_local_active(&local_store, replacement.id, Duration::from_secs(3))
            .await
            .unwrap();

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }
}
