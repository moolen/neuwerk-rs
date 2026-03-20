#![allow(dead_code)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use neuwerk::controlplane::cluster::types::ClusterTypeConfig;
use openraft::error::{ChangeMembershipError, ClientWriteError, RaftError};

pub async fn change_membership_with_retry(
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
