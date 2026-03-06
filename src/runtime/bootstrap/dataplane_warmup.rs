use std::time::{Duration, Instant};

use firewall::dataplane::{DataplaneConfigStore, SnatMode};

use crate::runtime::bootstrap::network::dataplane_ipv4_config;
use crate::runtime::cli::CliConfig;

pub fn maybe_spawn_soft_dataplane_autoconfig_task(
    cfg: &CliConfig,
    dpdk_enabled: bool,
    soft_dp_config_present: bool,
    dataplane_config: DataplaneConfigStore,
) {
    if !dpdk_enabled && !soft_dp_config_present && matches!(cfg.snat_mode, SnatMode::Auto) {
        let iface = cfg.data_plane_iface.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match dataplane_ipv4_config(&iface).await {
                    Ok((ip, prefix, mac)) => {
                        dataplane_config.set(firewall::dataplane::DataplaneConfig {
                            ip,
                            prefix,
                            gateway: std::net::Ipv4Addr::UNSPECIFIED,
                            mac,
                            lease_expiry: None,
                        });
                        break;
                    }
                    Err(err) => {
                        if Instant::now() >= deadline {
                            eprintln!("dataplane interface ip error: {err}");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
}
