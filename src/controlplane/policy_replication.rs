use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::policy_repository::{
    singleton_policy_id, PolicyDiskStore, StoredPolicy, POLICY_STATE_KEY,
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

    fn apply_state(
        policy_store: &PolicyStore,
        local_store: &PolicyDiskStore,
        state: &StoredPolicy,
    ) -> Result<(), String> {
        let compiled = state.policy.clone().compile()?;
        policy_store.rebuild_with_kubernetes_bindings(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            EnforcementMode::Enforce,
            compiled.kubernetes_bindings,
        )?;
        local_store
            .write_state(state)
            .map_err(|err| format!("persist local singleton policy failed: {err}"))?;
        policy_store.set_active_policy_id(Some(singleton_policy_id()));
        Ok(())
    }

    fn local_state_matches(local_store: &PolicyDiskStore, state: &StoredPolicy) -> bool {
        local_store
            .read_state()
            .ok()
            .flatten()
            .is_some_and(|local_state| {
                serde_json::to_value(&local_state.policy).ok()
                    == serde_json::to_value(&state.policy).ok()
            })
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
        let record = match store.get_state_value(POLICY_STATE_KEY) {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, "policy replication failed to read singleton policy");
                continue;
            }
        };
        let record =
            record.unwrap_or_else(|| serde_json::to_vec(&StoredPolicy::default()).unwrap());
        if last_record.as_ref().is_some_and(|prev| prev == &record) {
            continue;
        }
        let record_bytes = record;
        let state: StoredPolicy = match serde_json::from_slice(&record_bytes) {
            Ok(state) => state,
            Err(err) => {
                warn!(error = %err, "policy replication singleton policy invalid");
                continue;
            }
        };
        // The leader applies local HTTP API writes synchronously. Reapplying the
        // identical singleton policy on the next replication tick would rebuild the
        // policy store and discard in-memory DNS grants for established flows.
        if snapshot.current_leader == Some(snapshot.id)
            && policy_store.active_policy_id() == Some(singleton_policy_id())
            && local_state_matches(&local_store, &state)
        {
            last_record = Some(record_bytes);
            if let Some(readiness) = &readiness {
                readiness.set_policy_ready(true);
            }
            continue;
        }
        if let Err(err) = apply_state(&policy_store, &local_store, &state) {
            error!(error = %err, "policy replication failed to apply singleton policy");
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

    use crate::controlplane::cluster::bootstrap;
    use crate::controlplane::cluster::config::ClusterConfig;
    use crate::controlplane::cluster::types::ClusterCommand;
    use crate::controlplane::policy_config::PolicyConfig;
    use crate::controlplane::policy_repository::{
        singleton_policy_id, StoredPolicy, POLICY_STATE_KEY,
    };
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
        timeout: Duration,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        loop {
            if policy_store.active_policy_id() == Some(singleton_policy_id()) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for policy replication".to_string());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn put_cluster_policy_state(
        raft: &openraft::Raft<ClusterTypeConfig>,
        state: &StoredPolicy,
    ) {
        raft.client_write(ClusterCommand::Put {
            key: POLICY_STATE_KEY.to_vec(),
            value: serde_json::to_vec(state).unwrap(),
        })
        .await
        .unwrap();
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
    mode: enforce
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
        let state = StoredPolicy::from_policy(policy);
        put_cluster_policy_state(&cluster.raft, &state).await;

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

        wait_for_active_policy(&policy_store, Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(
            policy_store.enforcement_mode(),
            EnforcementMode::Enforce,
            "singleton replication should not reintroduce removed top-level audit mode"
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

        assert_eq!(
            local_store.active_id().unwrap(),
            Some(singleton_policy_id())
        );
        assert!(local_store.read_state().unwrap().is_some());

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
    mode: enforce
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
        let raw_record = serde_json::json!({
            "policy": serde_json::to_value(&policy).unwrap(),
            "future_cluster_field": { "version": 2 }
        });

        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: POLICY_STATE_KEY.to_vec(),
                value: serde_json::to_vec(&raw_record).unwrap(),
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

        wait_for_active_policy(&policy_store, Duration::from_secs(3))
            .await
            .unwrap();

        assert_eq!(
            policy_store.enforcement_mode(),
            EnforcementMode::Enforce,
            "schema-compatible cluster records should still replay"
        );
        assert_eq!(
            local_store.active_id().unwrap(),
            Some(singleton_policy_id())
        );
        assert!(local_store.read_state().unwrap().is_some());

        task.abort();
        let _ = task.await;
        cluster.shutdown().await;
    }

    #[tokio::test]
    async fn policy_state_updates_replay_when_cluster_key_stays_the_same() {
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
        let mut state = StoredPolicy::from_policy(initial_policy);
        put_cluster_policy_state(&cluster.raft, &state).await;

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

        wait_for_active_policy(&policy_store, Duration::from_secs(3))
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

        state.policy = serde_yaml::from_str(
            r#"
default_policy: deny
"#,
        )
        .unwrap();
        put_cluster_policy_state(&cluster.raft, &state).await;

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
    async fn invalid_singleton_policy_json_does_not_mark_readiness_ready() {
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
                key: POLICY_STATE_KEY.to_vec(),
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
    async fn missing_singleton_policy_bootstraps_default_and_marks_ready() {
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

        assert_eq!(policy_store.active_policy_id(), Some(singleton_policy_id()));
        assert_eq!(
            local_store.active_id().unwrap(),
            Some(singleton_policy_id())
        );
        assert!(policy_ready_check(&readiness));
        wait_for_policy_decision(
            &policy_store,
            crate::dataplane::policy::PacketMeta {
                src_ip: Ipv4Addr::new(192, 0, 2, 2),
                dst_ip: Ipv4Addr::new(203, 0, 113, 10),
                proto: 6,
                src_port: 40000,
                dst_port: 443,
                icmp_type: None,
                icmp_code: None,
            },
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
    async fn leader_replication_does_not_clear_existing_dns_grants_for_same_active_policy() {
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
default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    mode: enforce
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-foo"
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
    default_action: deny
"#,
        )
        .unwrap();
        let state = StoredPolicy::from_policy(policy.clone());
        put_cluster_policy_state(&cluster.raft, &state).await;

        let compiled = policy.compile().unwrap();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);
        policy_store
            .rebuild_with_kubernetes_bindings(
                compiled.groups,
                compiled.dns_policy,
                compiled.default_policy,
                EnforcementMode::Enforce,
                compiled.kubernetes_bindings,
            )
            .unwrap();
        policy_store.set_active_policy_id(Some(singleton_policy_id()));

        let granted_ip = Ipv4Addr::new(203, 0, 113, 10);
        policy_store.record_dns_grants("client-primary", "foo.allowed", &[granted_ip], 10);

        let local_store = PolicyDiskStore::new(local_dir.path().join("local-policy-store"));
        local_store.write_state(&state).unwrap();
        let readiness = readiness_with_basics(&policy_store);
        let task = tokio::spawn(run_policy_replication_with_local_apply_guard(
            cluster.store.clone(),
            cluster.raft.clone(),
            policy_store.clone(),
            local_store,
            Some(readiness),
            Some(Arc::new(AtomicU64::new(0))),
            Duration::from_millis(25),
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        let decision = policy_store.snapshot().read().unwrap().evaluate(
            &crate::dataplane::policy::PacketMeta {
                src_ip: Ipv4Addr::new(192, 0, 2, 2),
                dst_ip: granted_ip,
                proto: 6,
                src_port: 40_000,
                dst_port: 80,
                icmp_type: None,
                icmp_code: None,
            },
            None,
            None,
        );
        assert_eq!(decision, crate::dataplane::policy::PolicyDecision::Allow);

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
    mode: enforce
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
        let state = StoredPolicy::from_policy(bad_policy);
        put_cluster_policy_state(&cluster.raft, &state).await;

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
    mode: enforce
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
        let state = StoredPolicy::from_policy(policy);
        put_cluster_policy_state(&cluster.raft, &state).await;

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
