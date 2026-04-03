use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;

use crate::controlplane::cluster::types::{Node, NodeId};
use crate::controlplane::cloud::types::{
    DrainState, DrainStatus, InstanceRef, MissingMemberState, TerminationEvent,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberCloudStatus {
    Exact(InstanceRef),
    Missing,
    Ambiguous,
    InvalidAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelatedMember {
    pub node_id: NodeId,
    pub addr: String,
    pub is_voter: bool,
    pub status: MemberCloudStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvictionReason {
    TerminatingAndDrained { instance_id: String },
    MissingFromDiscovery { missing_since: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictionCandidate {
    pub node_id: NodeId,
    pub reason: EvictionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingMemberUpdate {
    pub node_id: NodeId,
    pub state: Option<MissingMemberState>,
}

pub fn correlate_members(
    metrics: &openraft::RaftMetrics<NodeId, Node>,
    instances: &[InstanceRef],
) -> Vec<CorrelatedMember> {
    let voters: BTreeSet<NodeId> = metrics
        .membership_config
        .membership()
        .voter_ids()
        .collect();

    metrics
        .membership_config
        .membership()
        .nodes()
        .map(|(node_id, node)| CorrelatedMember {
            node_id: *node_id,
            addr: node.addr.clone(),
            is_voter: voters.contains(node_id),
            status: correlate_member(&node.addr, instances),
        })
        .collect()
}

pub fn plan_missing_member_updates(
    members: &[CorrelatedMember],
    current: &HashMap<NodeId, MissingMemberState>,
    local_node_id: NodeId,
    now: i64,
) -> Vec<MissingMemberUpdate> {
    let mut updates = Vec::new();
    let mut present = HashSet::new();

    for member in members {
        present.insert(member.node_id);
        if !member.is_voter || member.node_id == local_node_id {
            if current.contains_key(&member.node_id) {
                updates.push(MissingMemberUpdate {
                    node_id: member.node_id,
                    state: None,
                });
            }
            continue;
        }

        match member.status {
            MemberCloudStatus::Missing => {
                if !current.contains_key(&member.node_id) {
                    updates.push(MissingMemberUpdate {
                        node_id: member.node_id,
                        state: Some(MissingMemberState {
                            first_missing_epoch: now,
                        }),
                    });
                }
            }
            MemberCloudStatus::Exact(_)
            | MemberCloudStatus::Ambiguous
            | MemberCloudStatus::InvalidAddr => {
                if current.contains_key(&member.node_id) {
                    updates.push(MissingMemberUpdate {
                        node_id: member.node_id,
                        state: None,
                    });
                }
            }
        }
    }

    for node_id in current.keys() {
        if !present.contains(node_id) {
            updates.push(MissingMemberUpdate {
                node_id: *node_id,
                state: None,
            });
        }
    }

    updates
}

pub fn select_eviction_candidate(
    members: &[CorrelatedMember],
    drains: &HashMap<String, DrainState>,
    terminations: &HashMap<String, TerminationEvent>,
    missing: &HashMap<NodeId, MissingMemberState>,
    local_node_id: NodeId,
    auto_evict_terminating: bool,
    stale_after_secs: u64,
    now: i64,
) -> Option<EvictionCandidate> {
    if auto_evict_terminating {
        for member in members {
            if let Some(reason) = eviction_reason_for_member(
                member,
                drains,
                terminations,
                missing,
                local_node_id,
                auto_evict_terminating,
                stale_after_secs,
                now,
            ) {
                if matches!(reason, EvictionReason::TerminatingAndDrained { .. }) {
                    return Some(EvictionCandidate {
                        node_id: member.node_id,
                        reason,
                    });
                }
            }
        }
    }

    if stale_after_secs == 0 {
        return None;
    }

    for member in members {
        if let Some(reason) = eviction_reason_for_member(
            member,
            drains,
            terminations,
            missing,
            local_node_id,
            auto_evict_terminating,
            stale_after_secs,
            now,
        ) {
            if matches!(reason, EvictionReason::MissingFromDiscovery { .. }) {
                return Some(EvictionCandidate {
                    node_id: member.node_id,
                    reason,
                });
            }
        }
    }

    None
}

pub fn eviction_reason_for_member(
    member: &CorrelatedMember,
    drains: &HashMap<String, DrainState>,
    terminations: &HashMap<String, TerminationEvent>,
    missing: &HashMap<NodeId, MissingMemberState>,
    local_node_id: NodeId,
    auto_evict_terminating: bool,
    stale_after_secs: u64,
    now: i64,
) -> Option<EvictionReason> {
    if !member.is_voter || member.node_id == local_node_id {
        return None;
    }

    if auto_evict_terminating {
        if let MemberCloudStatus::Exact(instance) = &member.status {
            if terminations.contains_key(&instance.id) {
                if let Some(drain) = drains.get(&instance.id) {
                    if drain.state == DrainStatus::Drained {
                        return Some(EvictionReason::TerminatingAndDrained {
                            instance_id: instance.id.clone(),
                        });
                    }
                }
            }
        }
    }

    if stale_after_secs == 0 || member.status != MemberCloudStatus::Missing {
        return None;
    }
    let state = missing.get(&member.node_id)?;
    if now - state.first_missing_epoch < stale_after_secs as i64 {
        return None;
    }
    Some(EvictionReason::MissingFromDiscovery {
        missing_since: state.first_missing_epoch,
    })
}

fn correlate_member(addr: &str, instances: &[InstanceRef]) -> MemberCloudStatus {
    let ip = match addr.parse::<SocketAddr>() {
        Ok(addr) => addr.ip(),
        Err(_) => return MemberCloudStatus::InvalidAddr,
    };

    let mut matches = instances
        .iter()
        .filter(|instance| instance.mgmt_ip == ip)
        .cloned()
        .collect::<Vec<_>>();

    match matches.len() {
        0 => MemberCloudStatus::Missing,
        1 => MemberCloudStatus::Exact(matches.pop().expect("single match")),
        _ => MemberCloudStatus::Ambiguous,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use openraft::{Membership, RaftMetrics, StoredMembership};

    use super::*;
    use crate::controlplane::cluster::types::Node;

    fn test_metrics(
        local_node_id: NodeId,
        configs: Vec<BTreeSet<NodeId>>,
        nodes: BTreeMap<NodeId, Node>,
    ) -> openraft::RaftMetrics<NodeId, Node> {
        let mut metrics = RaftMetrics::new_initial(local_node_id);
        metrics.membership_config =
            Arc::new(StoredMembership::new(None, Membership::new(configs, nodes)));
        metrics
    }

    fn test_instance(id: &str, mgmt_ip: Ipv4Addr) -> InstanceRef {
        InstanceRef {
            id: id.to_string(),
            name: id.to_string(),
            zone: "zone-1".to_string(),
            created_at_epoch: 0,
            mgmt_ip: IpAddr::V4(mgmt_ip),
            dataplane_ip: Ipv4Addr::new(10, 1, 0, 1),
            tags: HashMap::new(),
            active: true,
        }
    }

    #[test]
    fn correlate_members_marks_missing_when_no_cloud_match_exists() {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            1,
            Node {
                addr: "127.0.0.11:9600".to_string(),
            },
        );
        nodes.insert(
            2,
            Node {
                addr: "127.0.0.12:9600".to_string(),
            },
        );
        let metrics = test_metrics(1, vec![BTreeSet::from([1, 2])], nodes);
        let members = correlate_members(
            &metrics,
            &[test_instance("i-1", Ipv4Addr::new(127, 0, 0, 11))],
        );
        assert_eq!(members[1].status, MemberCloudStatus::Missing);
    }

    #[test]
    fn stale_candidate_requires_timeout() {
        let members = vec![CorrelatedMember {
            node_id: 2,
            addr: "127.0.0.12:9600".to_string(),
            is_voter: true,
            status: MemberCloudStatus::Missing,
        }];
        let missing = HashMap::from([(
            2,
            MissingMemberState {
                first_missing_epoch: 100,
            },
        )]);

        assert_eq!(
            select_eviction_candidate(
                &members,
                &HashMap::new(),
                &HashMap::new(),
                &missing,
                1,
                true,
                60,
                120,
            ),
            None
        );
        assert_eq!(
            select_eviction_candidate(
                &members,
                &HashMap::new(),
                &HashMap::new(),
                &missing,
                1,
                true,
                60,
                160,
            ),
            Some(EvictionCandidate {
                node_id: 2,
                reason: EvictionReason::MissingFromDiscovery { missing_since: 100 },
            })
        );
    }
}
