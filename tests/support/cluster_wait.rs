#![allow(dead_code)]

use std::time::{Duration, Instant};

use neuwerk::controlplane::cluster::types::ClusterTypeConfig;
use openraft::RaftMetrics;

pub async fn wait_for_voter(
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

pub async fn wait_for_stable_membership(
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

pub async fn wait_for_leader(
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

pub async fn wait_for_new_leader(
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
