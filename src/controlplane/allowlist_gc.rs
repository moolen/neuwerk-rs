use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::controlplane::wiretap::DnsMap;
use crate::dataplane::policy::DynamicIpSetV4;

pub async fn run_allowlist_gc(
    allowlist: DynamicIpSetV4,
    idle_timeout_secs: u64,
    interval_secs: u64,
    dns_map: Option<DnsMap>,
) {
    let interval_secs = interval_secs.max(1);
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        ticker.tick().await;
        let now = now_secs();
        allowlist.evict_idle(now, idle_timeout_secs);
        if let Some(map) = &dns_map {
            map.evict_idle(now, idle_timeout_secs);
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
