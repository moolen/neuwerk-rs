#![allow(dead_code)]

use std::time::Duration;

use firewall::controlplane::cluster::store::ClusterStore;
use firewall::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub async fn wait_for_envelope(
    store: &ClusterStore,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let key = format!("ca/envelope/{node_id}").into_bytes();
    crate::support::assert::retry_until(timeout, Duration::from_millis(100), || {
        Ok(store.get_state_value(&key)?.is_some())
    })
    .await
    .map_err(|_| "timed out waiting for ca envelope".to_string())
}

pub async fn wait_for_termination_count(
    store: &ClusterStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
    crate::support::assert::retry_until(timeout, Duration::from_millis(100), || {
        Ok(store.scan_state_prefix(TERMINATION_PREFIX)?.len() >= expected)
    })
    .await
    .map_err(|_| format!("timed out waiting for termination count >= {expected}"))
}

pub async fn wait_for_state_value(
    store: &ClusterStore,
    key: &[u8],
    expected: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    crate::support::assert::retry_until(timeout, Duration::from_millis(50), || {
        Ok(store
            .get_state_value(key)?
            .is_some_and(|value| value == expected))
    })
    .await
    .map_err(|_| {
        format!(
            "timed out waiting for state key {:?} to match expected value",
            String::from_utf8_lossy(key)
        )
    })
}

pub async fn wait_for_state_absent(
    store: &ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    crate::support::assert::retry_until(timeout, Duration::from_millis(50), || {
        Ok(store.get_state_value(key)?.is_none())
    })
    .await
    .map_err(|_| {
        format!(
            "timed out waiting for state key {:?} to become absent",
            String::from_utf8_lossy(key)
        )
    })
}

pub async fn write_put_with_retry(
    rafts: &[openraft::Raft<ClusterTypeConfig>],
    key: &[u8],
    value: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    let mut last_err = String::new();
    loop {
        for raft in rafts {
            let cmd = ClusterCommand::Put {
                key: key.to_vec(),
                value: value.to_vec(),
            };
            match raft.client_write(cmd).await {
                Ok(_) => return Ok(()),
                Err(err) => last_err = err.to_string(),
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out writing {:?}: {}",
                String::from_utf8_lossy(key),
                last_err
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
