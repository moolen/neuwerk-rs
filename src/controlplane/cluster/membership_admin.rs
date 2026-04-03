use std::collections::BTreeSet;

use crate::controlplane::cluster::types::{ClusterTypeConfig, Node, NodeId};

pub struct MembershipAdmin {
    raft: openraft::Raft<ClusterTypeConfig>,
}

impl MembershipAdmin {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>) -> Self {
        Self { raft }
    }

    pub async fn remove_member(
        &self,
        node_id: NodeId,
        force: bool,
        min_voters: u64,
    ) -> Result<(), String> {
        let metrics = self.raft.metrics().borrow().clone();
        ensure_uniform_membership(&metrics)?;
        ensure_safe_removal(&metrics, node_id, force, min_voters)?;
        let mut voters = list_voter_ids(&metrics);
        voters.remove(&node_id);
        self.replace_voter_set(voters).await?;
        Ok(())
    }

    pub async fn replace_voters(
        &self,
        voters: BTreeSet<NodeId>,
        force: bool,
        min_voters: u64,
    ) -> Result<(), String> {
        let metrics = self.raft.metrics().borrow().clone();
        ensure_uniform_membership(&metrics)?;
        ensure_safe_replacement(&metrics, &voters, force, min_voters)?;
        self.replace_voter_set(voters).await?;
        Ok(())
    }

    pub fn list_voters(&self) -> BTreeSet<NodeId> {
        let metrics = self.raft.metrics().borrow().clone();
        list_voter_ids(&metrics)
    }

    pub fn list_members(&self) -> BTreeSet<NodeId> {
        let metrics = self.raft.metrics().borrow().clone();
        list_member_ids(&metrics)
    }

    async fn replace_voter_set(&self, voters: BTreeSet<NodeId>) -> Result<(), String> {
        self.raft
            .change_membership(voters, false)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

fn list_voter_ids(metrics: &openraft::RaftMetrics<NodeId, Node>) -> BTreeSet<NodeId> {
    metrics
        .membership_config
        .membership()
        .voter_ids()
        .collect()
}

fn list_member_ids(metrics: &openraft::RaftMetrics<NodeId, Node>) -> BTreeSet<NodeId> {
    metrics
        .membership_config
        .membership()
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect()
}

fn ensure_uniform_membership(metrics: &openraft::RaftMetrics<NodeId, Node>) -> Result<(), String> {
    if metrics.membership_config.membership().get_joint_config().len() != 1 {
        return Err("joint membership is not supported".to_string());
    }
    Ok(())
}

fn ensure_safe_removal(
    metrics: &openraft::RaftMetrics<NodeId, Node>,
    node_id: NodeId,
    force: bool,
    min_voters: u64,
) -> Result<(), String> {
    let voters = list_voter_ids(metrics);
    if !voters.contains(&node_id) {
        return Err(format!("node {node_id} is not a voter"));
    }
    if !force && metrics.id == node_id {
        return Err("self removal requires force=true".to_string());
    }
    let remaining = voters.len().saturating_sub(1) as u64;
    if !force && remaining < min_voters {
        return Err(format!(
            "removal would violate min_voters safety: remaining={remaining}, min_voters={min_voters}"
        ));
    }
    Ok(())
}

fn ensure_safe_replacement(
    metrics: &openraft::RaftMetrics<NodeId, Node>,
    voters: &BTreeSet<NodeId>,
    force: bool,
    min_voters: u64,
) -> Result<(), String> {
    if !force && (voters.len() as u64) < min_voters {
        return Err(format!(
            "replacement would violate min_voters safety: voters={}, min_voters={min_voters}",
            voters.len()
        ));
    }
    let current_voters = list_voter_ids(metrics);
    if !force && current_voters.contains(&metrics.id) && !voters.contains(&metrics.id) {
        return Err("self removal requires force=true".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use openraft::entry::EntryPayload;
    use openraft::storage::{RaftLogStorageExt, RaftStateMachine};
    use openraft::{BasicNode, Membership, RaftMetrics, StoredMembership};
    use tempfile::TempDir;

    use super::{ensure_safe_removal, ensure_safe_replacement, MembershipAdmin};
    use crate::controlplane::cluster::bootstrap;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::store::ClusterStore;
    use crate::controlplane::cluster::types::{ClusterTypeConfig, Node};
    use crate::controlplane::cluster::ClusterRuntime;

    fn membership_admin_metrics_with_configs(configs: Vec<BTreeSet<u128>>) -> RaftMetrics<u128, BasicNode> {
        let mut metrics = RaftMetrics::new_initial(1);
        let mut nodes = BTreeMap::new();
        nodes.insert(1, BasicNode::new("10.0.0.1:9600"));
        nodes.insert(2, BasicNode::new("10.0.0.2:9600"));
        nodes.insert(3, BasicNode::new("10.0.0.3:9600"));
        metrics.membership_config =
            Arc::new(StoredMembership::new(None, Membership::new(configs, nodes)));
        metrics
    }

    fn next_addr() -> SocketAddr {
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
        let raft_addr = next_addr();
        cfg.enabled = true;
        cfg.data_dir = data_dir.path().to_path_buf();
        cfg.token_path = token_path.to_path_buf();
        cfg.node_id_path = data_dir.path().join("node_id");
        cfg.bind_addr = raft_addr;
        cfg.advertise_addr = raft_addr;
        cfg.join_bind_addr = next_addr();
        cfg
    }

    async fn wait_for_voter(
        raft: &openraft::Raft<ClusterTypeConfig>,
        node_id: u128,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, BasicNode> = metrics.borrow().clone();
            if m.membership_config
                .membership()
                .voter_ids()
                .any(|id| id == node_id)
            {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for voter membership".to_string());
            }
            tokio::time::timeout(deadline - now, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    async fn wait_for_stable_membership(
        raft: &openraft::Raft<ClusterTypeConfig>,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, BasicNode> = metrics.borrow().clone();
            if m.membership_config.membership().get_joint_config().len() == 1 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for stable membership".to_string());
            }
            tokio::time::timeout(deadline - now, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    async fn wait_for_leader(
        raft: &openraft::Raft<ClusterTypeConfig>,
        timeout: Duration,
    ) -> Result<u128, String> {
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, BasicNode> = metrics.borrow().clone();
            if let Some(leader) = m.current_leader {
                return Ok(leader);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for leader".to_string());
            }
            tokio::time::timeout(deadline - now, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    async fn start_cluster(
        data_dir: &TempDir,
        token_path: &Path,
        join_seed: Option<SocketAddr>,
    ) -> ClusterRuntime {
        let mut cfg = base_config(data_dir, token_path);
        cfg.join_seed = join_seed;
        bootstrap::run_cluster(cfg, None, None).await.unwrap()
    }

    #[tokio::test]
    async fn membership_admin_remove_voter_rejects_when_below_min_voters() {
        let seed_dir = TempDir::new().unwrap();
        let joiner_dir = TempDir::new().unwrap();
        let token_file = seed_dir.path().join("bootstrap.json");
        write_token_file(&token_file);

        let seed = start_cluster(&seed_dir, &token_file, None).await;
        wait_for_leader(&seed.raft, Duration::from_secs(10))
            .await
            .unwrap();
        let joiner = start_cluster(&joiner_dir, &token_file, Some(seed.join_bind_addr)).await;
        let joiner_id = joiner.raft.metrics().borrow().id;

        wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(10))
            .await
            .unwrap();
        wait_for_stable_membership(&seed.raft, Duration::from_secs(10))
            .await
            .unwrap();

        let service = MembershipAdmin::new(seed.raft.clone());
        let err = service.remove_member(joiner_id, false, 2).await.unwrap_err();
        assert!(err.contains("min_voters"));

        joiner.shutdown().await;
        seed.shutdown().await;
    }

    #[tokio::test]
    async fn membership_admin_replace_voters_rejects_joint_membership() {
        let seed_dir = TempDir::new().unwrap();
        let token_file = seed_dir.path().join("bootstrap.json");
        write_token_file(&token_file);

        let initial_seed = start_cluster(&seed_dir, &token_file, None).await;
        let seed_id = wait_for_leader(&initial_seed.raft, Duration::from_secs(10))
            .await
            .unwrap();
        let advertise_addr = initial_seed.advertise_addr;
        initial_seed.shutdown().await;

        let joiner_a_id = seed_id.wrapping_add(1);
        let joiner_b_id = seed_id.wrapping_add(2);
        let mut nodes = BTreeMap::new();
        nodes.insert(
            seed_id,
            Node {
                addr: advertise_addr.to_string(),
            },
        );
        nodes.insert(
            joiner_a_id,
            Node {
                addr: "127.0.0.1:47001".to_string(),
            },
        );
        nodes.insert(
            joiner_b_id,
            Node {
                addr: "127.0.0.1:47002".to_string(),
            },
        );

        let joint_membership = Membership::new(
            vec![
                BTreeSet::from([seed_id, joiner_a_id]),
                BTreeSet::from([seed_id, joiner_b_id]),
            ],
            nodes,
        );
        let mut store = ClusterStore::open(seed_dir.path().join("raft")).unwrap();
        let metadata = store.read_metadata().unwrap();
        let next_index = metadata.last_log.unwrap().index + 1;
        let entry = openraft::Entry::<ClusterTypeConfig> {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, seed_id), next_index),
            payload: EntryPayload::Membership(joint_membership),
        };
        store.blocking_append(vec![entry.clone()]).await.unwrap();
        store.apply(vec![entry]).await.unwrap();
        drop(store);

        let seed = start_cluster(&seed_dir, &token_file, None).await;
        let service = MembershipAdmin::new(seed.raft.clone());
        let err = service
            .replace_voters(BTreeSet::from([seed_id, joiner_b_id]), false, 1)
            .await
            .unwrap_err();
        assert!(err.contains("joint membership"));

        seed.shutdown().await;
    }

    #[tokio::test]
    async fn membership_admin_remove_voter_rejects_non_force_self_removal() {
        let metrics = membership_admin_metrics_with_configs(vec![BTreeSet::from([1, 2, 3])]);
        let err = ensure_safe_removal(&metrics, 1, false, 2).unwrap_err();
        assert!(err.contains("self removal"));
    }

    #[tokio::test]
    async fn membership_admin_replace_voters_rejects_non_force_self_removal() {
        let metrics = membership_admin_metrics_with_configs(vec![BTreeSet::from([1, 2, 3])]);
        let err = ensure_safe_replacement(&metrics, &BTreeSet::from([2, 3]), false, 2).unwrap_err();
        assert!(err.contains("self removal"));
    }

    #[tokio::test]
    async fn membership_admin_replace_voters_rejects_when_below_min_voters() {
        let metrics = membership_admin_metrics_with_configs(vec![BTreeSet::from([1, 2, 3])]);
        let err = ensure_safe_replacement(&metrics, &BTreeSet::from([1]), false, 2).unwrap_err();
        assert!(err.contains("min_voters"));
    }
}
