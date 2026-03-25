use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigFile {
    pub version: u16,
    pub bootstrap: BootstrapConfigFile,
    pub dns: DnsConfigFile,
    #[serde(default)]
    pub policy: Option<PolicyConfigFile>,
    #[serde(default)]
    pub http: Option<HttpConfigFile>,
    #[serde(default)]
    pub metrics: Option<MetricsConfigFile>,
    #[serde(default)]
    pub cluster: Option<ClusterConfigFile>,
    #[serde(default)]
    pub integration: Option<IntegrationConfigFile>,
    #[serde(default)]
    pub tls_intercept: Option<TlsInterceptConfigFile>,
    #[serde(default)]
    pub dataplane: Option<DataplaneConfigFile>,
    #[serde(default)]
    pub dpdk: Option<DpdkConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfigFile {
    pub management_interface: String,
    pub data_interface: String,
    pub cloud_provider: String,
    pub data_plane_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfigFile {
    pub target_ips: Vec<Ipv4Addr>,
    pub upstreams: Vec<SocketAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigFile {
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub internal_cidr: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfigFile {
    #[serde(default)]
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub advertise: Option<SocketAddr>,
    #[serde(default)]
    pub external_url: Option<String>,
    #[serde(default)]
    pub tls_dir: Option<PathBuf>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub tls_san: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfigFile {
    #[serde(default)]
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub allow_public_bind: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfigFile {
    #[serde(default)]
    pub bind: Option<SocketAddr>,
    #[serde(default)]
    pub join_bind: Option<SocketAddr>,
    #[serde(default)]
    pub advertise: Option<SocketAddr>,
    #[serde(default)]
    pub join_seed: Option<SocketAddr>,
    #[serde(default)]
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub node_id_path: Option<PathBuf>,
    #[serde(default)]
    pub token_path: Option<PathBuf>,
    #[serde(default)]
    pub migrate_from_local: bool,
    #[serde(default)]
    pub migrate_force: bool,
    #[serde(default)]
    pub migrate_verify: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationConfigFile {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub route_name: Option<String>,
    #[serde(default)]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub drain_timeout_secs: Option<u64>,
    #[serde(default)]
    pub reconcile_interval_secs: Option<u64>,
    #[serde(default)]
    pub aws: Option<AwsIntegrationConfigFile>,
    #[serde(default)]
    pub azure: Option<AzureIntegrationConfigFile>,
    #[serde(default)]
    pub gcp: Option<GcpIntegrationConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsIntegrationConfigFile {
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub vpc_id: Option<String>,
    #[serde(default)]
    pub asg_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureIntegrationConfigFile {
    #[serde(default)]
    pub subscription_id: Option<String>,
    #[serde(default)]
    pub resource_group: Option<String>,
    #[serde(default)]
    pub vmss_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpIntegrationConfigFile {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub ig_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsInterceptConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneConfigFile {
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub dns_allowlist_idle_secs: Option<u64>,
    #[serde(default)]
    pub dns_allowlist_gc_interval_secs: Option<u64>,
    #[serde(default)]
    pub dhcp_timeout_secs: Option<u64>,
    #[serde(default)]
    pub dhcp_retry_max: Option<u32>,
    #[serde(default)]
    pub dhcp_lease_min_secs: Option<u64>,
    #[serde(default)]
    pub snat: Option<SnatConfigFile>,
    #[serde(default)]
    pub encap_mode: Option<String>,
    #[serde(default)]
    pub encap_vni: Option<u32>,
    #[serde(default)]
    pub encap_vni_internal: Option<u32>,
    #[serde(default)]
    pub encap_vni_external: Option<u32>,
    #[serde(default)]
    pub encap_udp_port: Option<u16>,
    #[serde(default)]
    pub encap_udp_port_internal: Option<u16>,
    #[serde(default)]
    pub encap_udp_port_external: Option<u16>,
    #[serde(default)]
    pub encap_mtu: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SnatConfigFile {
    Scalar(String),
    Detailed(SnatDetailedConfigFile),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnatDetailedConfigFile {
    pub mode: String,
    #[serde(default)]
    pub ip: Option<Ipv4Addr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkConfigFile {
    #[serde(default)]
    pub static_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub static_prefix_len: Option<u8>,
    #[serde(default)]
    pub static_gateway: Option<Ipv4Addr>,
    #[serde(default)]
    pub static_mac: Option<String>,
}
