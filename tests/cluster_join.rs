use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;

use firewall::controlplane::cloud::types::TerminationEvent;
use firewall::controlplane::cluster::bootstrap;
use firewall::controlplane::cluster::config::ClusterConfig;
use firewall::controlplane::cluster::rpc::{IntegrationClient, RaftTlsConfig};
use firewall::controlplane::cluster::types::ClusterTypeConfig;
use openraft::error::{ChangeMembershipError, ClientWriteError, RaftError};
use openraft::RaftMetrics;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

fn next_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_token_file(path: &PathBuf) {
    let json = r#"{
  "tokens": [
    { "kid": "test", "token": "b64:dGVzdC1zZWNyZXQ=", "valid_until": "2027-01-01T00:00:00Z" }
  ]
}"#;
    fs::write(path, json).unwrap();
}

fn base_config(data_dir: &TempDir, token_path: &PathBuf) -> ClusterConfig {
    let mut cfg = ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.data_dir = data_dir.path().to_path_buf();
    cfg.token_path = token_path.clone();
    cfg.node_id_path = data_dir.path().join("node_id");
    cfg
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

async fn wait_for_new_leader(
    rafts: [&openraft::Raft<ClusterTypeConfig>; 2],
    old_leader: u128,
    timeout: Duration,
) -> Result<u128, String> {
    let deadline = Instant::now() + timeout;
    loop {
        for raft in rafts {
            let m = raft.metrics().borrow().clone();
            if let Some(leader) = m.current_leader {
                if leader != old_leader {
                    return Ok(leader);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for new leader".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_envelope(
    store: &firewall::controlplane::cluster::store::ClusterStore,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let key = format!("ca/envelope/{node_id}").into_bytes();
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(&key)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for ca envelope".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn change_membership_with_retry(
    raft: &openraft::Raft<ClusterTypeConfig>,
    voters: BTreeSet<u128>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match raft.change_membership(voters.clone(), true).await {
            Ok(_) => return Ok(()),
            Err(err) if is_in_progress(&err) => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for membership change".to_string());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(err) => {
                return Err(format!("change membership failed: {err:?}"));
            }
        }
    }
}

fn is_in_progress(err: &RaftError<u128, ClientWriteError<u128, openraft::BasicNode>>) -> bool {
    matches!(
        err,
        RaftError::APIError(ClientWriteError::ChangeMembershipError(
            ChangeMembershipError::InProgress(_)
        ))
    )
}

#[tokio::test]
async fn join_flow_promotes_and_restarts() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_addr = next_addr();
    let joiner_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let seed = bootstrap::run_cluster(seed_cfg.clone(), None, None)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let mut joiner_cfg = base_config(&joiner_dir, &token_file);
    joiner_cfg.bind_addr = joiner_addr;
    joiner_cfg.advertise_addr = joiner_addr;
    joiner_cfg.join_bind_addr = joiner_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);

    let joiner = bootstrap::run_cluster(joiner_cfg.clone(), None, None)
        .await
        .unwrap();

    let tls_dir = joiner_dir.path().join("tls");
    assert!(tls_dir.join("node.key").exists());
    assert!(tls_dir.join("node.crt").exists());
    assert!(tls_dir.join("ca.crt").exists());

    let joiner_id_raw = fs::read_to_string(joiner_dir.path().join("node_id")).unwrap();
    let joiner_id = uuid::Uuid::parse_str(joiner_id_raw.trim())
        .unwrap()
        .as_u128();

    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5))
        .await
        .unwrap();

    joiner.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let _joiner_restart = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();
    wait_for_voter(&seed.raft, joiner_id, Duration::from_secs(5))
        .await
        .unwrap();
}

#[tokio::test]
async fn membership_change_removes_node() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_a_dir = TempDir::new().unwrap();
    let joiner_b_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();

    let mut joiner_cfg = base_config(&joiner_a_dir, &token_file);
    joiner_cfg.bind_addr = joiner_a_addr;
    joiner_cfg.advertise_addr = joiner_a_addr;
    joiner_cfg.join_bind_addr = joiner_a_join_addr;
    joiner_cfg.join_seed = Some(seed.join_bind_addr);
    let joiner_a = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let mut joiner_cfg = base_config(&joiner_b_dir, &token_file);
    joiner_cfg.bind_addr = joiner_b_addr;
    joiner_cfg.advertise_addr = joiner_b_addr;
    joiner_cfg.join_bind_addr = joiner_b_join_addr;
    joiner_cfg.join_seed = Some(seed.join_bind_addr);
    let _joiner_b = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let joiner_a_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_a_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_b_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_b_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();

    wait_for_voter(&seed.raft, joiner_a_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_voter(&seed.raft, joiner_b_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_stable_membership(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let seed_id = uuid::Uuid::parse_str(
        fs::read_to_string(seed_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let mut voters = BTreeSet::new();
    voters.insert(seed_id);
    voters.insert(joiner_b_id);
    change_membership_with_retry(&seed.raft, voters, Duration::from_secs(5))
        .await
        .unwrap();

    let mut metrics = seed.raft.metrics();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let m = metrics.borrow().clone();
        let voters: BTreeSet<_> = m.membership_config.membership().voter_ids().collect();
        if !voters.contains(&joiner_a_id) && voters.contains(&joiner_b_id) {
            break;
        }
        if Instant::now() >= deadline {
            panic!("membership change did not apply");
        }
        let remaining = deadline - Instant::now();
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .unwrap()
            .unwrap();
    }

    joiner_a.shutdown().await;
}

#[tokio::test]
async fn mtls_requires_client_cert() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let tls_dir = seed_dir.path().join("tls");
    let ca = fs::read(tls_dir.join("ca.crt")).unwrap();
    let cert = fs::read(tls_dir.join("node.crt")).unwrap();
    let key = fs::read(tls_dir.join("node.key")).unwrap();

    let endpoint = Endpoint::from_shared(format!("https://{seed_addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2));
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca.clone()));
    let channel = endpoint
        .clone()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client =
        firewall::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
            channel,
        );
    let resp = client
        .vote(firewall::controlplane::cluster::rpc::proto::RaftRequest {
            payload: Vec::new(),
        })
        .await;
    match resp {
        Err(status) if status.code() == tonic::Code::InvalidArgument => {
            panic!("mTLS not enforced: request reached service without client cert")
        }
        Err(_) => {}
        Ok(_) => panic!("unexpected success without client cert"),
    }

    let identity = Identity::from_pem(cert, key);
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(identity);
    let channel = endpoint.tls_config(tls).unwrap().connect().await.unwrap();
    let mut client =
        firewall::controlplane::cluster::rpc::proto::raft_service_client::RaftServiceClient::new(
            channel,
        );
    let resp = client
        .vote(firewall::controlplane::cluster::rpc::proto::RaftRequest {
            payload: Vec::new(),
        })
        .await;
    match resp {
        Err(status) if status.code() == tonic::Code::InvalidArgument => {}
        Err(status) => panic!("unexpected response: {status:?}"),
        Ok(_) => panic!("unexpected success with empty payload"),
    }

    seed.shutdown().await;
}

#[tokio::test]
async fn leader_failover_can_sign_and_join() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let joiner_a_dir = TempDir::new().unwrap();
    let joiner_b_dir = TempDir::new().unwrap();
    let joiner_c_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let joiner_a_addr = next_addr();
    let joiner_a_join_addr = next_addr();
    let joiner_b_addr = next_addr();
    let joiner_b_join_addr = next_addr();

    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    let mut seed = Some(
        bootstrap::run_cluster(seed_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let mut joiner_cfg = base_config(&joiner_a_dir, &token_file);
    joiner_cfg.bind_addr = joiner_a_addr;
    joiner_cfg.advertise_addr = joiner_a_addr;
    joiner_cfg.join_bind_addr = joiner_a_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);
    let mut joiner_a = Some(
        bootstrap::run_cluster(joiner_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let mut joiner_cfg = base_config(&joiner_b_dir, &token_file);
    joiner_cfg.bind_addr = joiner_b_addr;
    joiner_cfg.advertise_addr = joiner_b_addr;
    joiner_cfg.join_bind_addr = joiner_b_join_addr;
    joiner_cfg.join_seed = Some(seed_cfg.join_bind_addr);
    let mut joiner_b = Some(
        bootstrap::run_cluster(joiner_cfg.clone(), None, None)
            .await
            .unwrap(),
    );

    let seed_id = uuid::Uuid::parse_str(
        fs::read_to_string(seed_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_a_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_a_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    let joiner_b_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_b_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();

    let seed_ref = seed.as_ref().unwrap();
    wait_for_voter(&seed_ref.raft, joiner_a_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_voter(&seed_ref.raft, joiner_b_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_stable_membership(&seed_ref.raft, Duration::from_secs(5))
        .await
        .unwrap();

    wait_for_envelope(&seed_ref.store, seed_id, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_envelope(
        &joiner_a.as_ref().unwrap().store,
        joiner_a_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_envelope(
        &joiner_b.as_ref().unwrap().store,
        joiner_b_id,
        Duration::from_secs(5),
    )
    .await
    .unwrap();

    let leader_id = wait_for_leader(&seed_ref.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let (remaining_a, remaining_b) = if leader_id == seed_id {
        seed.take().unwrap().shutdown().await;
        (joiner_a.as_ref().unwrap(), joiner_b.as_ref().unwrap())
    } else if leader_id == joiner_a_id {
        joiner_a.take().unwrap().shutdown().await;
        (seed.as_ref().unwrap(), joiner_b.as_ref().unwrap())
    } else {
        joiner_b.take().unwrap().shutdown().await;
        (seed.as_ref().unwrap(), joiner_a.as_ref().unwrap())
    };

    let new_leader_id = wait_for_new_leader(
        [&remaining_a.raft, &remaining_b.raft],
        leader_id,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let new_leader_join_addr = if new_leader_id == seed_id {
        seed_join_addr
    } else if new_leader_id == joiner_a_id {
        joiner_a_join_addr
    } else {
        joiner_b_join_addr
    };

    let joiner_c_addr = next_addr();
    let joiner_c_join_addr = next_addr();
    let mut joiner_cfg = base_config(&joiner_c_dir, &token_file);
    joiner_cfg.bind_addr = joiner_c_addr;
    joiner_cfg.advertise_addr = joiner_c_addr;
    joiner_cfg.join_bind_addr = joiner_c_join_addr;
    joiner_cfg.join_seed = Some(new_leader_join_addr);
    let joiner_c = bootstrap::run_cluster(joiner_cfg, None, None)
        .await
        .unwrap();

    let joiner_c_id = uuid::Uuid::parse_str(
        fs::read_to_string(joiner_c_dir.path().join("node_id"))
            .unwrap()
            .trim(),
    )
    .unwrap()
    .as_u128();
    wait_for_voter(&remaining_a.raft, joiner_c_id, Duration::from_secs(5))
        .await
        .unwrap();

    if let Some(seed) = seed.take() {
        seed.shutdown().await;
    }
    if let Some(joiner_a) = joiner_a.take() {
        joiner_a.shutdown().await;
    }
    if let Some(joiner_b) = joiner_b.take() {
        joiner_b.shutdown().await;
    }
    joiner_c.shutdown().await;
}

#[tokio::test]
async fn integration_client_publishes_termination_event() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let token_file = seed_dir.path().join("bootstrap.json");
    write_token_file(&token_file);

    let seed_addr = next_addr();
    let seed_join_addr = next_addr();
    let mut seed_cfg = base_config(&seed_dir, &token_file);
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;

    let seed = bootstrap::run_cluster(seed_cfg, None, None).await.unwrap();
    wait_for_leader(&seed.raft, Duration::from_secs(5))
        .await
        .unwrap();

    let tls_dir = seed_dir.path().join("tls");
    let tls = RaftTlsConfig::load(tls_dir).expect("tls config");
    let mut client = IntegrationClient::connect(seed.bind_addr, tls)
        .await
        .expect("integration client");

    let event = TerminationEvent {
        id: "event-1".to_string(),
        instance_id: "i-a".to_string(),
        deadline_epoch: 123,
    };
    client
        .publish_termination_event(event.clone())
        .await
        .expect("publish termination event");

    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let entries = seed
            .store
            .scan_state_prefix(TERMINATION_PREFIX)
            .expect("termination scan");
        if let Some((_, value)) = entries.first() {
            let stored: TerminationEvent =
                serde_json::from_slice(value).expect("termination decode");
            assert_eq!(stored.id, event.id);
            assert_eq!(stored.instance_id, event.instance_id);
            assert_eq!(stored.deadline_epoch, event.deadline_epoch);
            break;
        }
        if Instant::now() >= deadline {
            panic!("timed out waiting for termination event");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    seed.shutdown().await;
}
