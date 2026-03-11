use std::time::Duration;

use firewall::controlplane::http_api::HttpApiShutdown;
use firewall::controlplane::ready::ReadinessState;
use firewall::dataplane::DrainControl;
use tokio::sync::oneshot;

const HTTP_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);
const READINESS_ANNOUNCE_GRACE: Duration = Duration::from_millis(250);

pub fn apply_runtime_shutdown(readiness: &ReadinessState, drain_control: &DrainControl) {
    drain_control.set_draining(true);
    readiness.set_dataplane_running(false);
    readiness.set_policy_ready(false);
    readiness.set_dns_ready(false);
    readiness.set_service_plane_ready(false);
}

pub fn spawn_signal_shutdown_task(
    readiness: ReadinessState,
    drain_control: DrainControl,
    http_shutdown: HttpApiShutdown,
) -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        apply_runtime_shutdown(&readiness, &drain_control);
        // Keep the listener up briefly so probes can observe readiness=false
        // before graceful shutdown closes the HTTP endpoint.
        tokio::time::sleep(READINESS_ANNOUNCE_GRACE).await;
        http_shutdown.graceful_shutdown(Some(HTTP_SHUTDOWN_GRACE));
        let _ = tx.send(());
    });
    rx
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use firewall::controlplane::PolicyStore;
    use firewall::dataplane::config::{DataplaneConfig, DataplaneConfigStore};
    use firewall::dataplane::policy::DefaultPolicy;

    #[test]
    fn apply_runtime_shutdown_sets_drain_and_readiness_false() {
        let dataplane_config = DataplaneConfigStore::new();
        dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0, 0, 0, 0, 1],
            lease_expiry: None,
        });
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            dataplane_config.clone(),
        );
        let readiness = ReadinessState::new(dataplane_config, policy_store, None, None);
        readiness.set_dataplane_running(true);
        readiness.set_policy_ready(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);
        let drain_control = DrainControl::new();

        apply_runtime_shutdown(&readiness, &drain_control);

        assert!(drain_control.is_draining());
        assert!(!readiness.snapshot().ready);
    }
}
