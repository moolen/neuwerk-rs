#![allow(dead_code)]

use std::time::{Duration, Instant};

pub async fn retry_until<F>(
    timeout: Duration,
    interval: Duration,
    mut check: F,
) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    let deadline = Instant::now() + timeout;
    loop {
        if check()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for condition".to_string());
        }
        tokio::time::sleep(interval).await;
    }
}
