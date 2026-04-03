use std::collections::{BTreeSet, HashMap};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::time::{Duration, Instant};

use openraft::RaftMetrics;
use tempfile::TempDir;

use crate::controlplane::cluster::bootstrap;
use crate::controlplane::cluster::config::ClusterConfig;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::cluster::ClusterRuntime;

const MISSING_MEMBER_PREFIX: &[u8] = b"integration/membership/missing/";

struct MembershipHarness {
    manager: IntegrationManager,
    provider: MockProvider,
    runtimes: Vec<ClusterRuntime>,
    node_ids: HashMap<String, u128>,
}

impl MembershipHarness {
    fn current_voters(&self) -> BTreeSet<u128> {
        let raft = self.manager.raft.as_ref().expect("cluster raft");
        raft.metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect()
    }

    fn local_instance_id(&self) -> &str {
        &self.manager.local_instance_id
    }

    fn remote_instance_id(&self) -> String {
        let mut candidates = self
            .node_ids
            .keys()
            .filter(|instance_id| instance_id.as_str() != self.local_instance_id())
            .cloned()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            panic!("remote instance");
        }
        candidates.sort();
        candidates.remove(0)
    }

    fn node_id_for(&self, instance_id: &str) -> u128 {
        *self.node_ids.get(instance_id).expect("instance node id")
    }

    async fn mark_instance_terminating_and_drained(&self, instance_id: &str) {
        let raft = self.manager.raft.as_ref().expect("cluster raft");
        let event = TerminationEvent {
            id: format!("event-{instance_id}"),
            instance_id: instance_id.to_string(),
            deadline_epoch: unix_now() + 300,
        };
        let drain = DrainState {
            state: DrainStatus::Drained,
            since_epoch: unix_now() - 60,
            deadline_epoch: unix_now() - 1,
        };
        write_cluster_json(raft, termination_key(instance_id), &event).await;
        write_cluster_json(raft, drain_key(instance_id), &drain).await;
    }

    async fn hide_instance_from_discovery(&self, instance_id: &str) {
        let mut instances = self.provider.instances.lock().await;
        instances.retain(|instance| instance.id != instance_id);
    }

    async fn seed_missing_since(&self, node_id: u128, missing_since: i64) {
        let raft = self.manager.raft.as_ref().expect("cluster raft");
        write_cluster_json(
            raft,
            missing_member_key(node_id),
            &MissingMemberState {
                first_missing_epoch: missing_since,
            },
        )
        .await;
    }

    async fn wait_for_voter_absent(&self, node_id: u128, timeout: Duration) -> Result<(), String> {
        let raft = self.manager.raft.as_ref().expect("cluster raft");
        let mut metrics = raft.metrics();
        let deadline = Instant::now() + timeout;
        loop {
            let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
            if !m.membership_config
                .membership()
                .voter_ids()
                .any(|id| id == node_id)
            {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err("timed out waiting for voter removal".to_string());
            }
            tokio::time::timeout(deadline - now, metrics.changed())
                .await
                .map_err(|_| "metrics wait timeout".to_string())?
                .map_err(|_| "metrics channel closed".to_string())?;
        }
    }

    async fn shutdown(self) {
        for runtime in self.runtimes {
            runtime.shutdown().await;
        }
    }
}

fn next_addr(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[cfg(unix)]
fn chmod_token(path: &Path) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn chmod_token(_path: &Path) {}

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
    std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    chmod_token(path);
}

fn cluster_config(
    data_dir: &TempDir,
    token_path: &Path,
    mgmt_ip: Ipv4Addr,
    join_seed: Option<SocketAddr>,
) -> ClusterConfig {
    let mut cfg = ClusterConfig::disabled();
    let raft_addr = next_addr(mgmt_ip);
    cfg.enabled = true;
    cfg.data_dir = data_dir.path().to_path_buf();
    cfg.token_path = token_path.to_path_buf();
    cfg.node_id_path = data_dir.path().join("node_id");
    cfg.bind_addr = raft_addr;
    cfg.advertise_addr = raft_addr;
    cfg.join_bind_addr = next_addr(mgmt_ip);
    cfg.join_seed = join_seed;
    cfg
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
        tokio::time::timeout(deadline - now, metrics.changed())
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
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
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

async fn write_cluster_json<T: serde::Serialize>(
    raft: &openraft::Raft<ClusterTypeConfig>,
    key: Vec<u8>,
    value: &T,
) {
    let value = serde_json::to_vec(value).unwrap();
    raft.client_write(ClusterCommand::Put { key, value })
        .await
        .unwrap();
}

fn missing_member_key(node_id: u128) -> Vec<u8> {
    let mut key = Vec::with_capacity(MISSING_MEMBER_PREFIX.len() + 39);
    key.extend_from_slice(MISSING_MEMBER_PREFIX);
    key.extend_from_slice(node_id.to_string().as_bytes());
    key
}

async fn membership_harness(
    min_voters: u64,
    stale_after_secs: u64,
) -> MembershipHarness {
    let tags = tagged(&[
        ("neuwerk.io/cluster", "demo"),
        ("neuwerk.io/role", "dataplane"),
    ]);
    let seed_dir = TempDir::new().unwrap();
    let joiner_a_dir = TempDir::new().unwrap();
    let joiner_b_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let instance_specs = vec![
        ("i-1".to_string(), Ipv4Addr::new(127, 0, 0, 11), Ipv4Addr::new(10, 1, 0, 11), &seed_dir),
        ("i-2".to_string(), Ipv4Addr::new(127, 0, 0, 12), Ipv4Addr::new(10, 1, 0, 12), &joiner_a_dir),
        ("i-3".to_string(), Ipv4Addr::new(127, 0, 0, 13), Ipv4Addr::new(10, 1, 0, 13), &joiner_b_dir),
    ];

    let seed_cfg = cluster_config(&seed_dir, &token_file, instance_specs[0].1, None);
    let seed_join_addr = seed_cfg.join_bind_addr;
    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    wait_for_leader(&seed.raft, Duration::from_secs(10))
        .await
        .unwrap();

    let joiner_a = bootstrap::run_cluster(
        cluster_config(&joiner_a_dir, &token_file, instance_specs[1].1, Some(seed_join_addr)),
        None,
        None,
    )
    .await
    .unwrap();
    let joiner_a_id = joiner_a.raft.metrics().borrow().id;
    wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(10))
        .await
        .unwrap();

    let joiner_b = bootstrap::run_cluster(
        cluster_config(&joiner_b_dir, &token_file, instance_specs[2].1, Some(seed_join_addr)),
        None,
        None,
    )
    .await
    .unwrap();
    let joiner_b_id = joiner_b.raft.metrics().borrow().id;
    wait_for_voter(&seed.raft, joiner_b_id, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_stable_membership(&seed.raft, Duration::from_secs(10))
        .await
        .unwrap();

    let runtimes = vec![seed, joiner_a, joiner_b];
    let leader_id = wait_for_leader(&runtimes[0].raft, Duration::from_secs(10))
        .await
        .unwrap();
    let leader_index = runtimes
        .iter()
        .position(|runtime| runtime.raft.metrics().borrow().id == leader_id)
        .expect("leader runtime");

    let instances: Vec<InstanceRef> = instance_specs
        .iter()
        .map(|(id, mgmt_ip, dataplane_ip, _)| {
            tagged_instance(id, "zone-1", *mgmt_ip, *dataplane_ip, tags.clone())
        })
        .collect();
    let node_ids: HashMap<String, u128> = instances
        .iter()
        .zip(runtimes.iter())
        .map(|(instance, runtime)| (instance.id.clone(), runtime.raft.metrics().borrow().id))
        .collect();
    let leader_instance_id = instances
        .iter()
        .find(|instance| node_ids[&instance.id] == leader_id)
        .map(|instance| instance.id.clone())
        .expect("leader instance");

    let provider = MockProvider::new(
        instances.clone(),
        Vec::new(),
        IntegrationCapabilities::default(),
        &leader_instance_id,
    );
    let ready = Arc::new(MockReady {
        readiness: instances
            .iter()
            .map(|instance| (instance.mgmt_ip, true))
            .collect(),
    }) as Arc<dyn ReadyChecker>;

    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: stale_after_secs,
        membership_min_voters: min_voters,
        tag_filter: DiscoveryFilter { tags },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let leader_runtime = &runtimes[leader_index];
    let manager = IntegrationManager::new(
        cfg,
        Arc::new(provider.clone()),
        Some(leader_runtime.store.clone()),
        Some(leader_runtime.raft.clone()),
        Metrics::new().unwrap(),
        DrainControl::new(),
        ready,
    )
    .await
    .expect("membership manager");

    MembershipHarness {
        manager,
        provider,
        runtimes,
        node_ids,
    }
}

#[tokio::test]
async fn auto_evicts_drained_terminating_voter_when_safe() {
    let mut harness = membership_harness(2, 0).await;
    let target_instance_id = harness.remote_instance_id();
    let target_node_id = harness.node_id_for(&target_instance_id);

    harness
        .mark_instance_terminating_and_drained(&target_instance_id)
        .await;
    harness.manager.reconcile_once().await.unwrap();

    harness
        .wait_for_voter_absent(target_node_id, Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(harness.current_voters().len(), 2);
    assert!(!harness.current_voters().contains(&target_node_id));

    harness.shutdown().await;
}

#[tokio::test]
async fn stale_member_waits_for_timeout_before_removal() {
    let mut harness = membership_harness(2, 60).await;
    let target_instance_id = harness.remote_instance_id();
    let target_node_id = harness.node_id_for(&target_instance_id);

    harness.hide_instance_from_discovery(&target_instance_id).await;
    harness.manager.reconcile_once().await.unwrap();

    assert!(harness.current_voters().contains(&target_node_id));

    harness.shutdown().await;
}

#[tokio::test]
async fn stale_member_auto_evicts_after_timeout_when_safe() {
    let mut harness = membership_harness(2, 60).await;
    let target_instance_id = harness.remote_instance_id();
    let target_node_id = harness.node_id_for(&target_instance_id);

    harness.hide_instance_from_discovery(&target_instance_id).await;
    harness
        .seed_missing_since(target_node_id, unix_now() - 120)
        .await;
    harness.manager.reconcile_once().await.unwrap();

    harness
        .wait_for_voter_absent(target_node_id, Duration::from_secs(10))
        .await
        .unwrap();
    assert!(!harness.current_voters().contains(&target_node_id));

    harness.shutdown().await;
}

#[tokio::test]
async fn auto_eviction_respects_min_voters() {
    let mut harness = membership_harness(3, 0).await;
    let target_instance_id = harness.remote_instance_id();
    let target_node_id = harness.node_id_for(&target_instance_id);

    harness
        .mark_instance_terminating_and_drained(&target_instance_id)
        .await;
    harness.manager.reconcile_once().await.unwrap();

    assert!(harness.current_voters().contains(&target_node_id));
    assert_eq!(harness.current_voters().len(), 3);

    harness.shutdown().await;
}
