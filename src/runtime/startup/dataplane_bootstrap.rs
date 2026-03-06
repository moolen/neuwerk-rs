use std::time::{Duration, Instant};

use firewall::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use firewall::controlplane::metrics::Metrics;
use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::PolicyStore;
use firewall::dataplane::{DataplaneConfigStore, DhcpRx, DhcpTx};
use tokio::sync::{mpsc, watch};

use crate::runtime::bootstrap::dataplane_config::imds_dataplane_config;
use crate::runtime::cli::{CliConfig, CloudProviderKind};

pub struct DataplaneBootstrap {
    pub dhcp_task: Option<tokio::task::JoinHandle<Result<(), String>>>,
    pub dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    pub dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    pub mac_tx: Option<watch::Sender<[u8; 6]>>,
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
        let Some(mut mac_rx) = mac_rx else {
            readiness.set_dataplane_running(false);
            return Err("dpdk imds fallback initialization failed".to_string());
        };
        tokio::spawn(async move {
            let mac = loop {
                let current = *mac_rx.borrow();
                if current != [0u8; 6] {
                    break current;
                }
                if mac_rx.changed().await.is_err() {
                    eprintln!("dpdk imds fallback: mac channel closed");
                    return;
                }
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if dataplane_config.get().is_some() {
                    return;
                }
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if dataplane_config.get().is_some() {
                return;
            }
            match imds_dataplane_config(mac).await {
                Ok((ip, prefix, gateway)) => {
                    dataplane_config.set(firewall::dataplane::DataplaneConfig {
                        ip,
                        prefix,
                        gateway,
                        mac,
                        lease_expiry: None,
                    });
                    eprintln!(
                        "dpdk imds fallback: set dataplane config ip={}, prefix={}, gateway={}",
                        ip, prefix, gateway
                    );
                }
                Err(err) => {
                    eprintln!("dpdk imds fallback failed: {err}");
                }
            }
        });
    }

    Ok(DataplaneBootstrap {
        dhcp_task,
        dhcp_tx: dp_to_cp_tx,
        dhcp_rx: cp_to_dp_rx,
        mac_tx,
    })
}
