use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::policy_config::{DnsPolicy, PolicyMode};
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyActive, PolicyDiskStore, PolicyRecord, POLICY_ACTIVE_KEY,
};
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::EnforcementMode;

pub async fn run_policy_replication(
    store: ClusterStore,
    raft: openraft::Raft<ClusterTypeConfig>,
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    readiness: Option<crate::controlplane::ready::ReadinessState>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_record: Option<Vec<u8>> = None;

    fn clear_active_policy(
        policy_store: &PolicyStore,
        local_store: &PolicyDiskStore,
    ) -> Result<(), String> {
        policy_store.rebuild(
            Vec::new(),
            DnsPolicy::new(Vec::new()),
            None,
            EnforcementMode::Enforce,
        )?;
        policy_store.set_active_policy_id(None);
        local_store
            .set_active(None)
            .map_err(|err| format!("clear local active policy failed: {err}"))?;
        Ok(())
    }

    loop {
        ticker.tick().await;
        let snapshot = raft.metrics().borrow().clone();
        // Local HTTP API writes are applied directly on the leader; followers
        // mirror from cluster state via this loop.
        let is_leader = snapshot.current_leader == Some(snapshot.id);
        if !snapshot.current_leader.is_some() || is_leader {
            continue;
        }
        let active = match store.get_state_value(POLICY_ACTIVE_KEY) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("policy replication: failed to read active policy: {err}");
                continue;
            }
        };
        let Some(active) = active else {
            let needs_clear = policy_store.active_policy_id().is_some()
                || local_store.active_id().ok().flatten().is_some();
            if needs_clear {
                if let Err(err) = clear_active_policy(&policy_store, &local_store) {
                    eprintln!("policy replication: failed to clear inactive policy: {err}");
                    continue;
                }
                last_record = None;
            }
            if let Some(readiness) = &readiness {
                readiness.set_policy_ready(true);
            }
            continue;
        };
        let active: PolicyActive = match serde_json::from_slice(&active) {
            Ok(active) => active,
            Err(err) => {
                eprintln!("policy replication: invalid active policy: {err}");
                continue;
            }
        };
        let record_key = policy_item_key(active.id);
        let record = match store.get_state_value(&record_key) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("policy replication: failed to read policy record: {err}");
                continue;
            }
        };
        let Some(record) = record else {
            continue;
        };
        if last_record.as_ref().is_some_and(|prev| prev == &record) {
            continue;
        }
        let record_bytes = record;
        let record: PolicyRecord = match serde_json::from_slice(&record_bytes) {
            Ok(record) => record,
            Err(err) => {
                eprintln!("policy replication: invalid policy record: {err}");
                continue;
            }
        };
        if !record.mode.is_active() {
            eprintln!("policy replication: active policy is disabled");
            if policy_store.active_policy_id() == Some(record.id) {
                if let Err(err) = clear_active_policy(&policy_store, &local_store) {
                    eprintln!("policy replication: failed to clear disabled active policy: {err}");
                    continue;
                }
                last_record = None;
            }
            continue;
        }
        if policy_store.active_policy_id() == Some(record.id) {
            last_record = Some(record_bytes);
            if let Some(readiness) = &readiness {
                readiness.set_policy_ready(true);
            }
            continue;
        }
        let enforcement_mode = if record.mode == PolicyMode::Audit {
            EnforcementMode::Audit
        } else {
            EnforcementMode::Enforce
        };
        let compiled = match record.policy.clone().compile() {
            Ok(compiled) => compiled,
            Err(err) => {
                eprintln!("policy replication: policy compile failed: {err}");
                continue;
            }
        };
        if let Err(err) = policy_store.rebuild(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode,
        ) {
            eprintln!("policy replication: policy update failed: {err}");
            continue;
        }
        policy_store.set_active_policy_id(Some(record.id));
        if let Err(err) = local_store.write_record(&record) {
            eprintln!("policy replication: failed to persist policy: {err}");
            continue;
        }
        if let Err(err) = local_store.set_active(Some(record.id)) {
            eprintln!("policy replication: failed to persist active policy: {err}");
            continue;
        }
        last_record = Some(record_bytes);
        if let Some(readiness) = &readiness {
            readiness.set_policy_ready(true);
        }
    }
}
