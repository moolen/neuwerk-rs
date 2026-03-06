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
        // Local HTTP API writes are applied directly on the leader, but startup
        // must still replay cluster state on every node (including the leader)
        // so in-memory policy/DNS state is restored after restart.
        if !snapshot.current_leader.is_some() {
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
        if let Err(err) = policy_store.rebuild_with_kubernetes_bindings(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode,
            compiled.kubernetes_bindings,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::Instant;

    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::controlplane::cluster::bootstrap;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::types::ClusterCommand;
    use crate::controlplane::policy_config::PolicyConfig;
    use crate::dataplane::policy::DefaultPolicy;

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
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = metrics.borrow().clone();
            if snapshot.current_leader == Some(snapshot.id) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for leader election".to_string());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => return Err("raft metrics channel closed".to_string()),
                Err(_) => return Err("timed out waiting for leader election".to_string()),
            }
        }
    }

    async fn wait_for_active_policy(
        policy_store: &PolicyStore,
        id: Uuid,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if policy_store.active_policy_id() == Some(id) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for policy replication".to_string());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn leader_replays_active_cluster_policy_on_startup() {
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

        let policy: PolicyConfig = serde_yaml::from_str(
            r#"
default_policy: allow
source_groups:
  - id: homenet
    priority: 0
    sources:
      cidrs: ["192.168.178.0/24"]
      ips: []
      kubernetes: []
    rules:
      - id: allow-github
        action: allow
        mode: audit
        match:
          dns_hostname: "github.com"
          dst_ports: ["443"]
    default_action: allow
"#,
        )
        .unwrap();
        let record = PolicyRecord::new(PolicyMode::Audit, policy, None).unwrap();

        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: policy_item_key(record.id),
                value: serde_json::to_vec(&record).unwrap(),
            })
            .await
            .unwrap();
        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: POLICY_ACTIVE_KEY.to_vec(),
                value: serde_json::to_vec(&PolicyActive { id: record.id }).unwrap(),
            })
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
            Duration::from_millis(25),
        ));

        wait_for_active_policy(&policy_store, record.id, Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(
            policy_store.enforcement_mode(),
            EnforcementMode::Audit,
            "policy mode should be replayed into runtime state"
        );

        let src_ip = Ipv4Addr::new(192, 168, 178, 91);
        let source_group = policy_store
            .dns_policy()
            .read()
            .ok()
            .and_then(|dns| dns.source_group_for_ip(src_ip));
        assert_eq!(
            source_group.as_deref(),
            Some("homenet"),
            "dns policy source group should be available after leader replay"
        );

        assert_eq!(local_store.active_id().unwrap(), Some(record.id));
        assert!(local_store.read_record(record.id).unwrap().is_some());

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }
}
