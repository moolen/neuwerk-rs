use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use serde::Serialize;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::policy_repository::{StoredPolicy, POLICY_STATE_KEY};
use crate::controlplane::PolicyStore;
use crate::dataplane::{DataplaneConfigStore, DrainControl};

#[derive(Clone)]
pub struct ReadinessState {
    dataplane_config: DataplaneConfigStore,
    policy_store: PolicyStore,
    cluster_store: Option<ClusterStore>,
    raft: Option<openraft::Raft<ClusterTypeConfig>>,
    dataplane_running: Arc<AtomicBool>,
    policy_ready: Arc<AtomicBool>,
    dns_ready: Arc<AtomicBool>,
    service_plane_ready: Arc<AtomicBool>,
    drain_control: Arc<Mutex<Option<DrainControl>>>,
}

#[derive(Debug, Serialize)]
pub struct ReadyCheck {
    pub name: String,
    pub ok: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReadyStatus {
    pub ready: bool,
    pub checks: Vec<ReadyCheck>,
}

impl ReadinessState {
    pub fn new(
        dataplane_config: DataplaneConfigStore,
        policy_store: PolicyStore,
        cluster_store: Option<ClusterStore>,
        raft: Option<openraft::Raft<ClusterTypeConfig>>,
    ) -> Self {
        Self {
            dataplane_config,
            policy_store,
            cluster_store,
            raft,
            dataplane_running: Arc::new(AtomicBool::new(false)),
            policy_ready: Arc::new(AtomicBool::new(false)),
            dns_ready: Arc::new(AtomicBool::new(false)),
            service_plane_ready: Arc::new(AtomicBool::new(false)),
            drain_control: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_dataplane_running(&self, running: bool) {
        self.dataplane_running.store(running, Ordering::Relaxed);
    }

    pub fn dataplane_running(&self) -> bool {
        self.dataplane_running.load(Ordering::Relaxed)
    }

    pub fn set_policy_ready(&self, ready: bool) {
        self.policy_ready.store(ready, Ordering::Relaxed);
    }

    pub fn set_dns_ready(&self, ready: bool) {
        self.dns_ready.store(ready, Ordering::Relaxed);
    }

    pub fn set_service_plane_ready(&self, ready: bool) {
        self.service_plane_ready.store(ready, Ordering::Relaxed);
    }

    pub fn set_drain_control(&self, drain_control: DrainControl) {
        if let Ok(mut lock) = self.drain_control.lock() {
            *lock = Some(drain_control);
        }
    }

    pub fn snapshot(&self) -> ReadyStatus {
        let mut checks = Vec::new();

        let dataplane_running = self.dataplane_running.load(Ordering::Relaxed);
        checks.push(ReadyCheck {
            name: "dataplane_running".to_string(),
            ok: dataplane_running,
            detail: if dataplane_running {
                None
            } else {
                Some("dataplane engine not running".to_string())
            },
        });

        let dhcp_ok = self.dataplane_config.get().is_some();
        checks.push(ReadyCheck {
            name: "dataplane_config".to_string(),
            ok: dhcp_ok,
            detail: if dhcp_ok {
                None
            } else {
                Some("missing dataplane config (dhcp)".to_string())
            },
        });

        let policy_ok = self.policy_ready.load(Ordering::Relaxed);
        checks.push(ReadyCheck {
            name: "policy_ready".to_string(),
            ok: policy_ok,
            detail: if policy_ok {
                None
            } else {
                Some("policy store not initialized".to_string())
            },
        });

        let dns_ok = self.dns_ready.load(Ordering::Relaxed);
        checks.push(ReadyCheck {
            name: "dns_allowlist".to_string(),
            ok: dns_ok,
            detail: if dns_ok {
                None
            } else {
                Some("dns proxy not ready".to_string())
            },
        });

        let service_ok = self.service_plane_ready.load(Ordering::Relaxed);
        checks.push(ReadyCheck {
            name: "service_plane".to_string(),
            ok: service_ok,
            detail: if service_ok {
                None
            } else {
                Some("service-plane runtime not ready".to_string())
            },
        });

        let draining = self
            .drain_control
            .lock()
            .ok()
            .and_then(|lock| lock.as_ref().cloned())
            .map(|control| control.is_draining())
            .unwrap_or(false);
        checks.push(ReadyCheck {
            name: "draining".to_string(),
            ok: !draining,
            detail: if draining {
                Some("instance is draining".to_string())
            } else {
                None
            },
        });

        let cluster_ok = self.cluster_membership_ready();
        checks.push(ReadyCheck {
            name: "cluster".to_string(),
            ok: cluster_ok,
            detail: if cluster_ok {
                None
            } else {
                Some("cluster membership not ready".to_string())
            },
        });

        let replication_ok = self.policy_replication_ready();
        checks.push(ReadyCheck {
            name: "policy_replication".to_string(),
            ok: replication_ok,
            detail: if replication_ok {
                None
            } else {
                Some("policy replication not caught up".to_string())
            },
        });

        let ready = checks.iter().all(|check| check.ok);
        ReadyStatus { ready, checks }
    }

    fn cluster_membership_ready(&self) -> bool {
        let Some(raft) = &self.raft else {
            return true;
        };
        let metrics = raft.metrics();
        let snapshot = metrics.borrow().clone();
        cluster_membership_ready_from_metrics(&snapshot, raft.config().election_timeout_min)
    }

    fn policy_replication_ready(&self) -> bool {
        let Some(store) = &self.cluster_store else {
            return true;
        };
        let state = match store.get_state_value(POLICY_STATE_KEY) {
            Ok(state) => state,
            Err(_) => return false,
        };
        if let Some(state) = state {
            if serde_json::from_slice::<StoredPolicy>(&state).is_err() {
                return false;
            }
        }
        self.policy_ready.load(Ordering::Relaxed) && self.policy_store.policy_generation() > 0
    }
}

fn cluster_membership_ready_from_metrics(
    metrics: &openraft::RaftMetrics<
        crate::controlplane::cluster::types::NodeId,
        crate::controlplane::cluster::types::Node,
    >,
    election_timeout_min_ms: u64,
) -> bool {
    if metrics.running_state.is_err() {
        return false;
    }

    let Some(leader_id) = metrics.current_leader else {
        return false;
    };
    if metrics
        .membership_config
        .membership()
        .get_node(&leader_id)
        .is_none()
    {
        return false;
    }

    match metrics.state {
        openraft::ServerState::Leader => {
            leader_id == metrics.id
                && metrics
                    .millis_since_quorum_ack
                    .is_some_and(|ms| ms <= election_timeout_min_ms)
        }
        openraft::ServerState::Follower | openraft::ServerState::Learner => leader_id != metrics.id,
        openraft::ServerState::Candidate | openraft::ServerState::Shutdown => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::net::Ipv4Addr;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::controlplane::cluster;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::store::ClusterStore;
    use crate::controlplane::cluster::types::ClusterCommand;
    use crate::controlplane::cluster::types::ClusterTypeConfig;
    use crate::dataplane::policy::DefaultPolicy;
    use crate::dataplane::DataplaneConfig;
    use openraft::entry::EntryPayload;
    use openraft::storage::RaftStateMachine;
    use openraft::{BasicNode, Membership, RaftMetrics, ServerState, StoredMembership};
    use openraft::{Entry, LogId};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn ready_state_with_basics() -> ReadinessState {
        let dataplane_config = DataplaneConfigStore::new();
        dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            lease_expiry: None,
        });
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Allow,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            dataplane_config.clone(),
        );
        let readiness = ReadinessState::new(dataplane_config, policy_store, None, None);
        readiness.set_dataplane_running(true);
        readiness.set_policy_ready(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);
        readiness
    }

    #[test]
    fn ready_status_is_not_ready_when_draining() {
        let readiness = ready_state_with_basics();
        let drain_control = DrainControl::new();
        drain_control.set_draining(true);
        readiness.set_drain_control(drain_control);
        let status = readiness.snapshot();
        assert!(!status.ready);
        assert!(status
            .checks
            .iter()
            .any(|check| check.name == "draining" && !check.ok));
    }

    #[test]
    fn ready_status_is_ready_when_not_draining() {
        let readiness = ready_state_with_basics();
        let drain_control = DrainControl::new();
        drain_control.set_draining(false);
        readiness.set_drain_control(drain_control);
        let status = readiness.snapshot();
        assert!(status.ready);
    }

    fn write_token_file(path: &std::path::Path) {
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

    async fn wait_for_leader(
        raft: &openraft::Raft<ClusterTypeConfig>,
        timeout: Duration,
    ) -> Result<u128, String> {
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
            if let Some(leader) = m.current_leader {
                return Ok(leader);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for leader".to_string());
            }
            let remaining = deadline - now;
            tokio::time::timeout(remaining, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    async fn wait_for_voter(
        raft: &openraft::Raft<ClusterTypeConfig>,
        node_id: u128,
        timeout: Duration,
    ) -> Result<(), String> {
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
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
            let remaining = deadline - now;
            tokio::time::timeout(remaining, metrics.changed())
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
            let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
            if m.membership_config.membership().get_joint_config().len() == 1 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for stable membership".to_string());
            }
            let remaining = deadline - now;
            tokio::time::timeout(remaining, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    fn next_local_addr() -> std::net::SocketAddr {
        let listener =
            std::net::TcpListener::bind(std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    async fn write_cluster_policy_state_bytes(
        store: &mut ClusterStore,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        store
            .apply([Entry {
                log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
                payload: EntryPayload::Normal(ClusterCommand::Put {
                    key: POLICY_STATE_KEY.to_vec(),
                    value: bytes,
                }),
            }])
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    #[tokio::test]
    async fn ready_status_is_not_ready_when_policy_replication_payload_is_invalid() {
        let dir = TempDir::new().unwrap();
        let mut store = ClusterStore::open(dir.path()).unwrap();
        write_cluster_policy_state_bytes(&mut store, b"{invalid-json".to_vec())
            .await
            .unwrap();

        let readiness = ReadinessState::new(
            DataplaneConfigStore::new(),
            PolicyStore::new(DefaultPolicy::Allow, Ipv4Addr::new(10, 0, 0, 0), 24),
            Some(store),
            None,
        );
        readiness.set_dataplane_running(true);
        readiness.set_policy_ready(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);

        let status = readiness.snapshot();
        assert!(!status.ready);
        assert!(status
            .checks
            .iter()
            .any(|check| check.name == "policy_replication" && !check.ok));
    }

    #[tokio::test]
    async fn ready_status_is_not_ready_when_cluster_policy_has_not_been_replayed_locally() {
        let dir = TempDir::new().unwrap();
        let mut store = ClusterStore::open(dir.path()).unwrap();
        let payload = serde_json::to_vec(&StoredPolicy::default()).unwrap();
        write_cluster_policy_state_bytes(&mut store, payload)
            .await
            .unwrap();

        let dataplane_config = DataplaneConfigStore::new();
        dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x22],
            lease_expiry: None,
        });
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Allow,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            dataplane_config.clone(),
        );
        let readiness = ReadinessState::new(dataplane_config, policy_store, Some(store), None);
        readiness.set_dataplane_running(true);
        readiness.set_policy_ready(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);

        let status = readiness.snapshot();
        assert!(!status.ready);
        assert!(status
            .checks
            .iter()
            .any(|check| check.name == "policy_replication" && !check.ok));
    }

    #[tokio::test]
    async fn ready_status_cluster_check_degrades_after_quorum_loss() {
        let seed_dir = TempDir::new().unwrap();
        let join_dir = TempDir::new().unwrap();
        let seed_token = seed_dir.path().join("bootstrap.json");
        let join_token = join_dir.path().join("bootstrap.json");
        write_token_file(&seed_token);
        write_token_file(&join_token);

        let seed_addr = next_local_addr();
        let seed_join_addr = next_local_addr();
        let join_addr = next_local_addr();
        let join_join_addr = next_local_addr();

        let mut seed_cfg = ClusterConfig::disabled();
        seed_cfg.enabled = true;
        seed_cfg.bind_addr = seed_addr;
        seed_cfg.join_bind_addr = seed_join_addr;
        seed_cfg.advertise_addr = seed_addr;
        seed_cfg.data_dir = seed_dir.path().to_path_buf();
        seed_cfg.node_id_path = seed_dir.path().join("node_id");
        seed_cfg.token_path = seed_token.clone();

        let mut join_cfg = ClusterConfig::disabled();
        join_cfg.enabled = true;
        join_cfg.bind_addr = join_addr;
        join_cfg.join_bind_addr = join_join_addr;
        join_cfg.advertise_addr = join_addr;
        join_cfg.join_seed = Some(seed_join_addr);
        join_cfg.data_dir = join_dir.path().to_path_buf();
        join_cfg.node_id_path = join_dir.path().join("node_id");
        join_cfg.token_path = join_token.clone();

        let seed_runtime = cluster::run_cluster_tasks(seed_cfg.clone(), None, None)
            .await
            .unwrap()
            .unwrap();
        let join_runtime = cluster::run_cluster_tasks(join_cfg.clone(), None, None)
            .await
            .unwrap()
            .unwrap();

        let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
            .await
            .unwrap();
        let joiner_node_id = Uuid::parse_str(
            fs::read_to_string(join_dir.path().join("node_id"))
                .unwrap()
                .trim(),
        )
        .unwrap()
        .as_u128();
        wait_for_voter(&seed_runtime.raft, joiner_node_id, Duration::from_secs(10))
            .await
            .unwrap();
        wait_for_stable_membership(&seed_runtime.raft, Duration::from_secs(10))
            .await
            .unwrap();

        let (follower_raft, surviving_runtime, stopped_runtime) =
            if leader_id == seed_runtime.raft.metrics().borrow().id {
                (join_runtime.raft.clone(), join_runtime, seed_runtime)
            } else {
                (seed_runtime.raft.clone(), seed_runtime, join_runtime)
            };

        let readiness = ready_state_with_basics();
        let readiness = ReadinessState {
            raft: Some(follower_raft),
            cluster_store: None,
            ..readiness
        };
        assert!(readiness
            .snapshot()
            .checks
            .iter()
            .any(|check| check.name == "cluster" && check.ok));

        stopped_runtime.shutdown().await;

        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let status = readiness.snapshot();
            if status
                .checks
                .iter()
                .any(|check| check.name == "cluster" && !check.ok)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for cluster readiness degradation"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        surviving_runtime.shutdown().await;
    }

    fn test_cluster_metrics() -> RaftMetrics<u128, BasicNode> {
        let mut metrics = RaftMetrics::new_initial(2);
        let mut nodes = BTreeMap::new();
        nodes.insert(1, BasicNode::new("10.0.0.1:9600"));
        nodes.insert(2, BasicNode::new("10.0.0.2:9600"));
        metrics.membership_config = Arc::new(StoredMembership::new(
            None,
            Membership::new(vec![BTreeSet::from([1, 2])], nodes),
        ));
        metrics
    }

    #[test]
    fn cluster_membership_requires_non_candidate_with_known_leader() {
        let mut metrics = test_cluster_metrics();
        metrics.state = ServerState::Candidate;
        metrics.current_leader = Some(1);

        assert!(!cluster_membership_ready_from_metrics(&metrics, 2_000));
    }

    #[test]
    fn cluster_membership_requires_recent_quorum_ack_for_leader() {
        let mut metrics = test_cluster_metrics();
        metrics.state = ServerState::Leader;
        metrics.current_leader = Some(2);
        metrics.millis_since_quorum_ack = Some(2_500);

        assert!(!cluster_membership_ready_from_metrics(&metrics, 2_000));
    }

    #[test]
    fn cluster_membership_accepts_follower_with_known_member_leader() {
        let mut metrics = test_cluster_metrics();
        metrics.state = ServerState::Follower;
        metrics.current_leader = Some(1);

        assert!(cluster_membership_ready_from_metrics(&metrics, 2_000));
    }
}
