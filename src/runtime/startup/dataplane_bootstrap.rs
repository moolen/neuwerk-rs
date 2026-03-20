use std::time::{Duration, Instant};

use neuwerk::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use neuwerk::controlplane::metrics::Metrics;
use neuwerk::controlplane::ready::ReadinessState;
use neuwerk::controlplane::PolicyStore;
use neuwerk::dataplane::{DataplaneConfigStore, DhcpRx, DhcpTx};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::runtime::bootstrap::dataplane_config::imds_dataplane_config;
use crate::runtime::cli::{CliConfig, CloudProviderKind};

pub struct DataplaneBootstrap {
    pub dhcp_task: Option<tokio::task::JoinHandle<Result<(), String>>>,
    pub dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    pub dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    pub mac_tx: Option<watch::Sender<[u8; 6]>>,
}

async fn run_imds_fallback<F, Fut>(
    mut mac_rx: watch::Receiver<[u8; 6]>,
    dataplane_config: DataplaneConfigStore,
    dhcp_wait_timeout: Duration,
    poll_interval: Duration,
    imds_lookup: F,
) where
    F: Fn([u8; 6]) -> Fut,
    Fut: std::future::Future<Output = Result<(std::net::Ipv4Addr, u8, std::net::Ipv4Addr), String>>,
{
    let mac = loop {
        let current = *mac_rx.borrow();
        if current != [0u8; 6] {
            break current;
        }
        if mac_rx.changed().await.is_err() {
            warn!("dpdk imds fallback mac channel closed");
            return;
        }
    };

    let deadline = Instant::now() + dhcp_wait_timeout;
    loop {
        if dataplane_config.get().is_some() {
            return;
        }
        if Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(poll_interval).await;
    }
    if dataplane_config.get().is_some() {
        return;
    }
    match imds_lookup(mac).await {
        Ok((ip, prefix, gateway)) => {
            dataplane_config.set(neuwerk::dataplane::DataplaneConfig {
                ip,
                prefix,
                gateway,
                mac,
                lease_expiry: None,
            });
            info!(
                ip = %ip,
                prefix,
                gateway = %gateway,
                "dpdk imds fallback set dataplane config"
            );
        }
        Err(err) => {
            warn!(error = %err, "dpdk imds fallback failed");
        }
    }
}

pub fn bootstrap_dataplane_runtime(
    cfg: &CliConfig,
    dpdk_enabled: bool,
    dataplane_config: DataplaneConfigStore,
    policy_store: PolicyStore,
    metrics: Metrics,
    readiness: ReadinessState,
) -> Result<DataplaneBootstrap, String> {
    let (dp_to_cp_tx, dp_to_cp_rx) = if dpdk_enabled {
        let (tx, rx) = mpsc::channel::<DhcpRx>(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (cp_to_dp_tx, cp_to_dp_rx) = if dpdk_enabled {
        let (tx, rx) = mpsc::channel::<DhcpTx>(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (mac_tx, mac_rx) = if dpdk_enabled {
        let (tx, rx) = watch::channel([0u8; 6]);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let dhcp_task = if dpdk_enabled && dataplane_config.get().is_none() {
        let Some(mac_rx) = mac_rx.as_ref().cloned() else {
            return Err("dhcp: mac receiver unavailable".to_string());
        };
        let Some(rx) = dp_to_cp_rx else {
            return Err("dhcp: rx channel unavailable".to_string());
        };
        let Some(tx) = cp_to_dp_tx else {
            return Err("dhcp: tx channel unavailable".to_string());
        };
        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_secs(cfg.dhcp_timeout_secs),
                retry_max: cfg.dhcp_retry_max,
                lease_min_secs: cfg.dhcp_lease_min_secs,
                hostname: None,
                update_internal_cidr: cfg.internal_cidr.is_none(),
                allow_router_fallback_from_subnet: matches!(
                    cfg.cloud_provider,
                    CloudProviderKind::Azure | CloudProviderKind::Gcp
                ),
            },
            mac_rx,
            rx,
            tx,
            dataplane_config: dataplane_config.clone(),
            policy_store: policy_store.clone(),
            metrics: Some(metrics.clone()),
        };
        Some(tokio::spawn(async move {
            dhcp_client
                .run()
                .await
                .map_err(|err| format!("dhcp client failed: {err}"))
        }))
    } else {
        None
    };

    if dpdk_enabled && dataplane_config.get().is_none() {
        let dataplane_config = dataplane_config.clone();
        let Some(mac_rx) = mac_rx else {
            readiness.set_dataplane_running(false);
            return Err("dpdk imds fallback initialization failed".to_string());
        };
        tokio::spawn(async move {
            run_imds_fallback(
                mac_rx,
                dataplane_config,
                Duration::from_secs(30),
                Duration::from_secs(1),
                imds_dataplane_config,
            )
            .await;
        });
    }

    Ok(DataplaneBootstrap {
        dhcp_task,
        dhcp_tx: dp_to_cp_tx,
        dhcp_rx: cp_to_dp_rx,
        mac_tx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use neuwerk::controlplane::cloud::types::IntegrationMode;
    use neuwerk::controlplane::cluster::config::ClusterConfig;
    use neuwerk::dataplane::policy::DefaultPolicy;
    use neuwerk::dataplane::{DataplaneConfig, EncapMode, SnatMode};

    fn test_cli_config() -> CliConfig {
        CliConfig {
            management_iface: "mgmt0".to_string(),
            data_plane_iface: "data0".to_string(),
            dns_target_ips: Vec::new(),
            dns_upstreams: Vec::new(),
            data_plane_mode: crate::runtime::cli::DataPlaneMode::Dpdk,
            idle_timeout_secs: 300,
            dns_allowlist_idle_secs: 420,
            dns_allowlist_gc_interval_secs: 30,
            default_policy: DefaultPolicy::Deny,
            dhcp_timeout_secs: 5,
            dhcp_retry_max: 5,
            dhcp_lease_min_secs: 60,
            internal_cidr: None,
            snat_mode: SnatMode::None,
            encap_mode: EncapMode::None,
            encap_vni: None,
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: None,
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: 1500,
            http_bind: None,
            http_advertise: None,
            http_external_url: None,
            http_tls_dir: std::env::temp_dir().join("neuwerk-dp-bootstrap-tests"),
            http_cert_path: None,
            http_key_path: None,
            http_ca_path: None,
            http_tls_san: Vec::new(),
            metrics_bind: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))),
            cloud_provider: crate::runtime::cli::CloudProviderKind::None,
            cluster: ClusterConfig::disabled(),
            cluster_migrate_from_local: false,
            cluster_migrate_force: false,
            cluster_migrate_verify: false,
            integration_mode: IntegrationMode::None,
            integration_route_name: "neuwerk-default".to_string(),
            integration_drain_timeout_secs: 300,
            integration_reconcile_interval_secs: 15,
            integration_cluster_name: "neuwerk".to_string(),
            azure_subscription_id: None,
            azure_resource_group: None,
            azure_vmss_name: None,
            aws_region: None,
            aws_vpc_id: None,
            aws_asg_name: None,
            gcp_project: None,
            gcp_region: None,
            gcp_ig_name: None,
        }
    }

    fn readiness(
        dataplane_config: DataplaneConfigStore,
        policy_store: PolicyStore,
    ) -> ReadinessState {
        ReadinessState::new(dataplane_config, policy_store, None, None)
    }

    #[test]
    fn bootstrap_skips_dhcp_when_dataplane_config_already_exists() {
        let cfg = test_cli_config();
        let dataplane_config = DataplaneConfigStore::new();
        dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            lease_expiry: None,
        });
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);

        let bootstrap = bootstrap_dataplane_runtime(
            &cfg,
            true,
            dataplane_config.clone(),
            policy_store.clone(),
            Metrics::new().unwrap(),
            readiness(dataplane_config, policy_store),
        )
        .expect("bootstrap");

        assert!(bootstrap.dhcp_task.is_none());
        assert!(bootstrap.dhcp_tx.is_some());
        assert!(bootstrap.dhcp_rx.is_some());
        assert!(bootstrap.mac_tx.is_some());
    }

    #[test]
    fn bootstrap_disabled_dpdk_returns_no_channels() {
        let cfg = test_cli_config();
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);

        let bootstrap = bootstrap_dataplane_runtime(
            &cfg,
            false,
            dataplane_config.clone(),
            policy_store.clone(),
            Metrics::new().unwrap(),
            readiness(dataplane_config, policy_store),
        )
        .expect("bootstrap");

        assert!(bootstrap.dhcp_task.is_none());
        assert!(bootstrap.dhcp_tx.is_none());
        assert!(bootstrap.dhcp_rx.is_none());
        assert!(bootstrap.mac_tx.is_none());
    }

    #[tokio::test]
    async fn imds_fallback_returns_when_mac_channel_closes() {
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let dataplane_config = DataplaneConfigStore::new();
        let lookups = Arc::new(AtomicUsize::new(0));
        let lookup_counter = lookups.clone();
        drop(mac_tx);

        run_imds_fallback(
            mac_rx,
            dataplane_config.clone(),
            Duration::from_millis(5),
            Duration::from_millis(1),
            move |_| {
                let lookup_counter = lookup_counter.clone();
                async move {
                    lookup_counter.fetch_add(1, Ordering::Relaxed);
                    Ok((Ipv4Addr::new(10, 0, 0, 2), 24, Ipv4Addr::new(10, 0, 0, 1)))
                }
            },
        )
        .await;

        assert!(dataplane_config.get().is_none());
        assert_eq!(lookups.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn imds_fallback_skips_lookup_when_dhcp_populates_config_first() {
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let dataplane_config = DataplaneConfigStore::new();
        let lookups = Arc::new(AtomicUsize::new(0));
        let lookup_counter = lookups.clone();
        let dataplane_config_for_writer = dataplane_config.clone();

        let task = tokio::spawn(run_imds_fallback(
            mac_rx,
            dataplane_config.clone(),
            Duration::from_millis(30),
            Duration::from_millis(2),
            move |_| {
                let lookup_counter = lookup_counter.clone();
                async move {
                    lookup_counter.fetch_add(1, Ordering::Relaxed);
                    Err("lookup should not run".to_string())
                }
            },
        ));

        mac_tx
            .send([0x02, 0x00, 0x00, 0x00, 0x00, 0x10])
            .expect("send mac");
        tokio::time::sleep(Duration::from_millis(5)).await;
        dataplane_config_for_writer.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 9),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x10],
            lease_expiry: None,
        });
        task.await.expect("fallback task");

        assert_eq!(
            dataplane_config.get().expect("dataplane config").ip,
            Ipv4Addr::new(10, 0, 0, 9)
        );
        assert_eq!(lookups.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn imds_fallback_applies_lookup_result_after_deadline() {
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let dataplane_config = DataplaneConfigStore::new();

        let task = tokio::spawn(run_imds_fallback(
            mac_rx,
            dataplane_config.clone(),
            Duration::from_millis(5),
            Duration::from_millis(1),
            |_| async { Ok((Ipv4Addr::new(10, 1, 0, 2), 24, Ipv4Addr::new(10, 1, 0, 1))) },
        ));

        mac_tx
            .send([0x02, 0x00, 0x00, 0x00, 0x00, 0x20])
            .expect("send mac");
        task.await.expect("fallback task");

        assert_eq!(
            dataplane_config.get(),
            Some(DataplaneConfig {
                ip: Ipv4Addr::new(10, 1, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 1, 0, 1),
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x20],
                lease_expiry: None,
            })
        );
    }

    #[tokio::test]
    async fn imds_fallback_leaves_config_unset_when_lookup_fails() {
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let dataplane_config = DataplaneConfigStore::new();
        let lookups = Arc::new(AtomicUsize::new(0));
        let lookup_counter = lookups.clone();

        let task = tokio::spawn(run_imds_fallback(
            mac_rx,
            dataplane_config.clone(),
            Duration::from_millis(5),
            Duration::from_millis(1),
            move |_| {
                let lookup_counter = lookup_counter.clone();
                async move {
                    lookup_counter.fetch_add(1, Ordering::Relaxed);
                    Err("imds unavailable".to_string())
                }
            },
        ));

        mac_tx
            .send([0x02, 0x00, 0x00, 0x00, 0x00, 0x30])
            .expect("send mac");
        task.await.expect("fallback task");

        assert!(dataplane_config.get().is_none());
        assert_eq!(lookups.load(Ordering::Relaxed), 1);
    }
}
