use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::Serialize;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::policy_repository::{PolicyActive, POLICY_ACTIVE_KEY};
use crate::controlplane::PolicyStore;
use crate::dataplane::DataplaneConfigStore;

#[derive(Clone)]
pub struct ReadinessState {
    dataplane_config: DataplaneConfigStore,
    policy_store: PolicyStore,
    cluster_store: Option<ClusterStore>,
    raft: Option<openraft::Raft<ClusterTypeConfig>>,
    dataplane_running: Arc<AtomicBool>,
    policy_ready: Arc<AtomicBool>,
    dns_ready: Arc<AtomicBool>,
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
        snapshot.current_leader.is_some()
    }

    fn policy_replication_ready(&self) -> bool {
        let Some(store) = &self.cluster_store else {
            return true;
        };
        let active = match store.get_state_value(POLICY_ACTIVE_KEY) {
            Ok(active) => active,
            Err(_) => return false,
        };
        let Some(active) = active else {
            return true;
        };
        let active: PolicyActive = match serde_json::from_slice(&active) {
            Ok(active) => active,
            Err(_) => return false,
        };
        self.policy_store.active_policy_id() == Some(active.id)
    }
}
