use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

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
    run_policy_replication_with_local_apply_guard(
        store,
        raft,
        policy_store,
        local_store,
        readiness,
        None,
        interval,
    )
    .await;
}

pub async fn run_policy_replication_with_local_apply_guard(
    store: ClusterStore,
    raft: openraft::Raft<ClusterTypeConfig>,
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    readiness: Option<crate::controlplane::ready::ReadinessState>,
    leader_local_policy_apply_count: Option<Arc<AtomicU64>>,
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
        if snapshot.current_leader.is_none() {
            continue;
        }
        if snapshot.current_leader == Some(snapshot.id)
            && leader_local_policy_apply_count
                .as_ref()
                .is_some_and(|count| count.load(Ordering::Acquire) > 0)
        {
            continue;
        }
        let active = match store.get_state_value(POLICY_ACTIVE_KEY) {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, "policy replication failed to read active policy");
                continue;
            }
        };
        let Some(active) = active else {
            let needs_clear = policy_store.active_policy_id().is_some()
                || local_store.active_id().ok().flatten().is_some();
            if needs_clear {
                if let Err(err) = clear_active_policy(&policy_store, &local_store) {
                    error!(error = %err, "policy replication failed to clear inactive policy");
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
                warn!(error = %err, "policy replication active policy record invalid");
                continue;
            }
        };
        let record_key = policy_item_key(active.id);
        let record = match store.get_state_value(&record_key) {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, policy_id = %active.id, "policy replication failed to read policy record");
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
                warn!(error = %err, "policy replication policy record invalid");
                continue;
            }
        };
        if !record.mode.is_active() {
            info!(policy_id = %record.id, mode = ?record.mode, "policy replication observed disabled active policy");
            if policy_store.active_policy_id() == Some(record.id) {
                if let Err(err) = clear_active_policy(&policy_store, &local_store) {
                    error!(error = %err, policy_id = %record.id, "policy replication failed to clear disabled active policy");
                    continue;
                }
                last_record = None;
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
                error!(error = %err, policy_id = %record.id, "policy replication compile failed");
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
            error!(error = %err, policy_id = %record.id, "policy replication update failed");
            continue;
        }
        if let Err(err) = local_store.write_record(&record) {
            error!(error = %err, policy_id = %record.id, "policy replication failed to persist policy");
            continue;
        }
        if let Err(err) = local_store.set_active(Some(record.id)) {
            error!(error = %err, policy_id = %record.id, "policy replication failed to persist active policy");
            continue;
        }
        policy_store.set_active_policy_id(Some(record.id));
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
    use crate::controlplane::ready::ReadinessState;
    use crate::dataplane::policy::DefaultPolicy;
    use crate::dataplane::{DataplaneConfig, DataplaneConfigStore};

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

    async fn wait_for_policy_decision(
        policy_store: &PolicyStore,
        meta: crate::dataplane::policy::PacketMeta,
        expected: crate::dataplane::policy::PolicyDecision,
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            let matches = policy_store
                .snapshot()
                .read()
                .ok()
                .map(|snapshot| snapshot.evaluate(&meta, None, None) == expected)
                .unwrap_or(false);
            if matches {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for policy decision".to_string());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn readiness_with_basics(policy_store: &PolicyStore) -> ReadinessState {
        let dataplane_config = DataplaneConfigStore::new();
        dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            lease_expiry: None,
        });
        let readiness = ReadinessState::new(dataplane_config, policy_store.clone(), None, None);
        readiness.set_dataplane_running(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);
        readiness
    }

    fn policy_ready_check(readiness: &ReadinessState) -> bool {
        readiness
            .snapshot()
            .checks
            .iter()
            .find(|check| check.name == "policy_ready")
            .map(|check| check.ok)
            .unwrap_or(false)
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

    #[tokio::test]
    async fn leader_replays_schema_compatible_cluster_policy_record() {
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
  - id: homes
    sources:
      ips: ["10.0.0.8"]
    rules:
      - id: allow-web
        action: allow
        match:
          proto: tcp
          dst_ports: ["443"]
"#,
        )
        .unwrap();
        let record = PolicyRecord::new(PolicyMode::Enforce, policy.clone(), None).unwrap();
        let raw_record = serde_json::json!({
            "id": record.id,
            "created_at": record.created_at,
            "mode": "enforce",
            "policy": serde_json::to_value(&policy).unwrap(),
            "future_cluster_field": { "version": 2 }
        });

        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: policy_item_key(record.id),
                value: serde_json::to_vec(&raw_record).unwrap(),
            })
            .await
            .unwrap();
        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: POLICY_ACTIVE_KEY.to_vec(),
                value: serde_json::to_vec(&serde_json::json!({
                    "id": record.id,
                    "future_active_field": "ignored"
                }))
                .unwrap(),
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
            EnforcementMode::Enforce,
            "schema-compatible cluster records should still replay"
        );
        assert_eq!(local_store.active_id().unwrap(), Some(record.id));
        assert!(local_store.read_record(record.id).unwrap().is_some());

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn active_policy_updates_replay_even_when_uuid_stays_the_same() {
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

        let initial_policy: PolicyConfig = serde_yaml::from_str(
            r#"
default_policy: allow
"#,
        )
        .unwrap();
        let mut record = PolicyRecord::new(PolicyMode::Enforce, initial_policy, None).unwrap();

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
            local_store,
            None,
            Duration::from_millis(25),
        ));

        wait_for_active_policy(&policy_store, record.id, Duration::from_secs(3))
            .await
            .unwrap();

        let meta = crate::dataplane::policy::PacketMeta {
            src_ip: Ipv4Addr::new(192, 0, 2, 2),
            dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            proto: 6,
            src_port: 40000,
            dst_port: 443,
            icmp_type: None,
            icmp_code: None,
        };
        wait_for_policy_decision(
            &policy_store,
            meta,
            crate::dataplane::policy::PolicyDecision::Allow,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        record.policy = serde_yaml::from_str(
            r#"
default_policy: deny
"#,
        )
        .unwrap();
        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: policy_item_key(record.id),
                value: serde_json::to_vec(&record).unwrap(),
            })
            .await
            .unwrap();

        wait_for_policy_decision(
            &policy_store,
            meta,
            crate::dataplane::policy::PolicyDecision::Deny,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn invalid_active_policy_json_does_not_mark_readiness_ready() {
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

        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: POLICY_ACTIVE_KEY.to_vec(),
                value: b"{not-json".to_vec(),
            })
            .await
            .unwrap();

        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);
        let local_store = PolicyDiskStore::new(local_dir.path().join("local-policy-store"));
        let readiness = readiness_with_basics(&policy_store);
        let task = tokio::spawn(run_policy_replication(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store.clone(),
            Some(readiness.clone()),
            Duration::from_millis(25),
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(!policy_ready_check(&readiness));
        assert_eq!(policy_store.active_policy_id(), None);
        assert_eq!(local_store.active_id().unwrap(), None);

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn disabled_active_policy_clears_runtime_without_marking_ready() {
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
  - id: apps
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: allow-dns
        action: allow
        match:
          proto: udp
          dst_ports: ["53"]
"#,
        )
        .unwrap();
        let record = PolicyRecord::new(PolicyMode::Disabled, policy, None).unwrap();

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
        policy_store.set_active_policy_id(Some(record.id));
        let local_store = PolicyDiskStore::new(local_dir.path().join("local-policy-store"));
        local_store.set_active(Some(record.id)).unwrap();
        let readiness = readiness_with_basics(&policy_store);
        let task = tokio::spawn(run_policy_replication(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store.clone(),
            Some(readiness.clone()),
            Duration::from_millis(25),
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(policy_store.active_policy_id(), None);
        assert_eq!(local_store.active_id().unwrap(), None);
        assert!(!policy_ready_check(&readiness));

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn compile_failure_does_not_mark_readiness_ready() {
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

        let bad_policy: PolicyConfig = serde_yaml::from_str(
            r#"
source_groups:
  - id: "tls"
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: tcp
          tls:
            mode: intercept
"#,
        )
        .unwrap();
        let record = PolicyRecord::new(PolicyMode::Enforce, bad_policy, None).unwrap();

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
        let readiness = readiness_with_basics(&policy_store);
        let task = tokio::spawn(run_policy_replication(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store.clone(),
            Some(readiness.clone()),
            Duration::from_millis(25),
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(policy_store.active_policy_id(), None);
        assert_eq!(local_store.active_id().unwrap(), None);
        assert!(!policy_ready_check(&readiness));

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn local_store_write_failure_keeps_readiness_false() {
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
  - id: apps
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: allow-dns
        action: allow
        match:
          proto: udp
          dst_ports: ["53"]
"#,
        )
        .unwrap();
        let record = PolicyRecord::new(PolicyMode::Enforce, policy, None).unwrap();

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

        let broken_path = local_dir.path().join("not-a-directory");
        fs::write(&broken_path, b"file").unwrap();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);
        let local_store = PolicyDiskStore::new(broken_path);
        let readiness = readiness_with_basics(&policy_store);
        let task = tokio::spawn(run_policy_replication(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store,
            Some(readiness.clone()),
            Duration::from_millis(25),
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        assert_eq!(policy_store.active_policy_id(), None);
        assert!(!policy_ready_check(&readiness));

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }
}
