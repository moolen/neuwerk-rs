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
    if voters.is_empty() {
        return Err("voter set cannot be empty".to_string());
    }
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
    use std::sync::Arc;

    use openraft::{BasicNode, Membership, RaftMetrics, StoredMembership};

    use super::{ensure_safe_removal, ensure_safe_replacement, ensure_uniform_membership};

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

    #[tokio::test]
    async fn membership_admin_remove_voter_rejects_when_below_min_voters() {
        let metrics = membership_admin_metrics_with_configs(vec![BTreeSet::from([1, 2])]);
        let err = ensure_safe_removal(&metrics, 2, false, 2).unwrap_err();
        assert!(err.contains("min_voters"));
    }

    #[tokio::test]
    async fn membership_admin_replace_voters_rejects_joint_membership() {
        let metrics =
            membership_admin_metrics_with_configs(vec![BTreeSet::from([1, 2]), BTreeSet::from([1, 3])]);
        let err = ensure_uniform_membership(&metrics).unwrap_err();
        assert!(err.contains("joint membership"));
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
