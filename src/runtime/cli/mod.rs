mod args;
mod parse_helpers;
mod types;
mod usage;

pub use args::parse_args;
pub use parse_helpers::{
    looks_like_mac, looks_like_pci, parse_cidr, parse_csv_ipv4_list, parse_csv_socket_list,
    parse_default_policy, parse_integration_mode, parse_ipv4, parse_mac, parse_port, parse_socket,
    parse_vni, take_flag_value,
};
pub use types::{CliConfig, CloudProviderKind, DataPlaneMode};
pub use usage::usage;

const DNS_ALLOWLIST_IDLE_SLACK_SECS: u64 = 120;
const DNS_ALLOWLIST_GC_INTERVAL_SECS: u64 = 30;
const DHCP_TIMEOUT_SECS: u64 = 5;
const DHCP_RETRY_MAX: u32 = 5;
const DHCP_LEASE_MIN_SECS: u64 = 60;
const INTEGRATION_ROUTE_NAME: &str = "neuwerk-default";
const INTEGRATION_DRAIN_TIMEOUT_SECS: u64 = 300;
const INTEGRATION_RECONCILE_INTERVAL_SECS: u64 = 15;
const INTEGRATION_CLUSTER_NAME: &str = "neuwerk";

pub fn load_http_ca(cfg: &CliConfig) -> Result<Vec<u8>, String> {
    let path = cfg
        .http_ca_path
        .clone()
        .unwrap_or_else(|| cfg.http_tls_dir.join("ca.crt"));
    std::fs::read(&path).map_err(|err| format!("read http ca {}: {err}", path.display()))
}
