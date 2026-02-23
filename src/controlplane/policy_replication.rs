use std::time::Duration;

use tokio::time::MissedTickBehavior;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::policy_config::PolicyMode;
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyActive, PolicyDiskStore, PolicyRecord, POLICY_ACTIVE_KEY,
};
use crate::controlplane::PolicyStore;

pub async fn run_policy_replication(
    store: ClusterStore,
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    readiness: Option<crate::controlplane::ready::ReadinessState>,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_record: Option<Vec<u8>> = None;

    loop {
        ticker.tick().await;
        let active = match store.get_state_value(POLICY_ACTIVE_KEY) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("policy replication: failed to read active policy: {err}");
                continue;
            }
        };
        let Some(active) = active else {
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
        if record.mode != PolicyMode::Enforce {
            eprintln!("policy replication: active policy is not enforce mode");
            continue;
        }
        if policy_store.active_policy_id() == Some(record.id) {
            last_record = Some(record_bytes);
            if let Some(readiness) = &readiness {
                readiness.set_policy_ready(true);
            }
            continue;
        }
        if let Err(err) = policy_store.rebuild_from_config(record.policy.clone()) {
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
