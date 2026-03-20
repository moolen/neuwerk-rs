use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use neuwerk::controlplane;
use neuwerk::controlplane::cloud::types::IntegrationMode;
use neuwerk::dataplane::policy::DefaultPolicy;
use neuwerk::dataplane::{EncapMode, SnatMode, SoftMode};

#[derive(Debug)]
pub struct CliConfig {
    pub management_iface: String,
    pub data_plane_iface: String,
    pub dns_target_ips: Vec<Ipv4Addr>,
    pub dns_upstreams: Vec<SocketAddr>,
    pub data_plane_mode: DataPlaneMode,
    pub idle_timeout_secs: u64,
    pub dns_allowlist_idle_secs: u64,
    pub dns_allowlist_gc_interval_secs: u64,
    pub default_policy: DefaultPolicy,
    pub dhcp_timeout_secs: u64,
    pub dhcp_retry_max: u32,
    pub dhcp_lease_min_secs: u64,
    pub internal_cidr: Option<(Ipv4Addr, u8)>,
    pub snat_mode: SnatMode,
    pub encap_mode: EncapMode,
    pub encap_vni: Option<u32>,
    pub encap_vni_internal: Option<u32>,
    pub encap_vni_external: Option<u32>,
    pub encap_udp_port: Option<u16>,
    pub encap_udp_port_internal: Option<u16>,
    pub encap_udp_port_external: Option<u16>,
    pub encap_mtu: u16,
    pub http_bind: Option<SocketAddr>,
    pub http_advertise: Option<SocketAddr>,
    pub http_external_url: Option<String>,
    pub http_tls_dir: PathBuf,
    pub http_cert_path: Option<PathBuf>,
    pub http_key_path: Option<PathBuf>,
    pub http_ca_path: Option<PathBuf>,
    pub http_tls_san: Vec<String>,
    pub metrics_bind: Option<SocketAddr>,
    pub cloud_provider: CloudProviderKind,
    pub cluster: controlplane::cluster::config::ClusterConfig,
    pub cluster_migrate_from_local: bool,
    pub cluster_migrate_force: bool,
    pub cluster_migrate_verify: bool,
    pub integration_mode: IntegrationMode,
    pub integration_route_name: String,
    pub integration_drain_timeout_secs: u64,
    pub integration_reconcile_interval_secs: u64,
    pub integration_cluster_name: String,
    pub azure_subscription_id: Option<String>,
    pub azure_resource_group: Option<String>,
    pub azure_vmss_name: Option<String>,
    pub aws_region: Option<String>,
    pub aws_vpc_id: Option<String>,
    pub aws_asg_name: Option<String>,
    pub gcp_project: Option<String>,
    pub gcp_region: Option<String>,
    pub gcp_ig_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPlaneMode {
    Soft(SoftMode),
    Dpdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudProviderKind {
    None,
    Azure,
    Aws,
    Gcp,
}

impl CloudProviderKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" | "NONE" => Ok(CloudProviderKind::None),
            "azure" | "AZURE" => Ok(CloudProviderKind::Azure),
            "aws" | "AWS" => Ok(CloudProviderKind::Aws),
            "gcp" | "GCP" => Ok(CloudProviderKind::Gcp),
            _ => Err(format!(
                "--cloud-provider must be azure, aws, gcp, or none, got {value}"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CloudProviderKind::None => "none",
            CloudProviderKind::Azure => "azure",
            CloudProviderKind::Aws => "aws",
            CloudProviderKind::Gcp => "gcp",
        }
    }
}

impl DataPlaneMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dpdk" | "DPDK" => Ok(DataPlaneMode::Dpdk),
            _ => Ok(DataPlaneMode::Soft(SoftMode::parse(value)?)),
        }
    }
}
