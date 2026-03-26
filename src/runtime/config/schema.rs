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
    pub runtime: Option<RuntimeBehaviorConfigFile>,
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
pub struct RuntimeBehaviorConfigFile {
    #[serde(default)]
    pub controlplane_worker_threads: Option<usize>,
    #[serde(default)]
    pub http_worker_threads: Option<usize>,
    #[serde(default)]
    pub kubernetes: Option<KubernetesRuntimeConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesRuntimeConfigFile {
    #[serde(default)]
    pub reconcile_interval_secs: Option<u64>,
    #[serde(default)]
    pub stale_grace_secs: Option<u64>,
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
pub struct TlsInterceptConfigFile {
    #[serde(default)]
    pub upstream_verify: Option<String>,
    #[serde(default)]
    pub io_timeout_secs: Option<u64>,
    #[serde(default)]
    pub listen_backlog: Option<u32>,
    #[serde(default)]
    pub h2: Option<TlsInterceptH2ConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsInterceptH2ConfigFile {
    #[serde(default)]
    pub body_timeout_secs: Option<u64>,
    #[serde(default)]
    pub max_concurrent_streams: Option<u32>,
    #[serde(default)]
    pub max_requests_per_connection: Option<usize>,
    #[serde(default)]
    pub pool_shards: Option<usize>,
    #[serde(default)]
    pub detailed_metrics: bool,
    #[serde(default)]
    pub selection_inflight_weight: Option<u64>,
    #[serde(default)]
    pub reconnect_backoff_base_ms: Option<u64>,
    #[serde(default)]
    pub reconnect_backoff_max_ms: Option<u64>,
}

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
    #[serde(default)]
    pub flow_table_capacity: Option<usize>,
    #[serde(default)]
    pub nat_table_capacity: Option<usize>,
    #[serde(default)]
    pub flow_incomplete_tcp_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub flow_incomplete_tcp_syn_sent_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub syn_only_enabled: bool,
    #[serde(default)]
    pub detailed_observability: bool,
    #[serde(default)]
    pub admission: Option<DataplaneAdmissionConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneAdmissionConfigFile {
    #[serde(default)]
    pub max_active_flows: Option<usize>,
    #[serde(default)]
    pub max_active_nat_entries: Option<usize>,
    #[serde(default)]
    pub max_pending_tls_flows: Option<usize>,
    #[serde(default)]
    pub max_active_flows_per_source_group: Option<usize>,
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
    #[serde(default)]
    pub workers: Option<DpdkWorkersConfigFile>,
    #[serde(default)]
    pub core_ids: Vec<usize>,
    #[serde(default)]
    pub allow_azure_multiworker: bool,
    #[serde(default)]
    pub single_queue_mode: Option<String>,
    #[serde(default)]
    pub perf_mode: Option<String>,
    #[serde(default)]
    pub force_shared_rx_demux: bool,
    #[serde(default)]
    pub pin_https_demux_owner: bool,
    #[serde(default)]
    pub disable_service_lane: bool,
    #[serde(default)]
    pub lockless_queue_per_worker: bool,
    #[serde(default)]
    pub shared_rx_owner_only: bool,
    #[serde(default)]
    pub housekeeping_interval_packets: Option<u64>,
    #[serde(default)]
    pub housekeeping_interval_us: Option<u64>,
    #[serde(default)]
    pub pin_state_shard_guard: bool,
    #[serde(default)]
    pub pin_state_shard_burst: Option<u32>,
    #[serde(default)]
    pub state_shards: Option<usize>,
    #[serde(default)]
    pub disable_in_memory: bool,
    #[serde(default)]
    pub iova_mode: Option<String>,
    #[serde(default)]
    pub force_netvsc: bool,
    #[serde(default)]
    pub gcp_auto_probe: bool,
    #[serde(default)]
    pub driver_preload: Vec<String>,
    #[serde(default)]
    pub skip_bus_pci_preload: bool,
    #[serde(default)]
    pub prefer_pci: bool,
    #[serde(default)]
    pub queue_override: Option<u16>,
    #[serde(default)]
    pub port_mtu: Option<u16>,
    #[serde(default)]
    pub mbuf_data_room: Option<u16>,
    #[serde(default)]
    pub mbuf_pool_size: Option<u32>,
    #[serde(default)]
    pub rx_ring_size: Option<u16>,
    #[serde(default)]
    pub tx_ring_size: Option<u16>,
    #[serde(default)]
    pub tx_checksum_offload: Option<bool>,
    #[serde(default)]
    pub allow_retaless_multi_queue: bool,
    #[serde(default)]
    pub service_lane: Option<DpdkServiceLaneConfigFile>,
    #[serde(default)]
    pub intercept_demux: Option<DpdkInterceptDemuxConfigFile>,
    #[serde(default)]
    pub gateway_mac: Option<String>,
    #[serde(default)]
    pub dhcp_server_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub dhcp_server_mac: Option<String>,
    #[serde(default)]
    pub overlay: Option<DpdkOverlayConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum DpdkWorkersConfigFile {
    Scalar(String),
    Count(usize),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkServiceLaneConfigFile {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub intercept_service_ip: Option<Ipv4Addr>,
    #[serde(default)]
    pub intercept_service_port: Option<u16>,
    #[serde(default)]
    pub multi_queue: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkInterceptDemuxConfigFile {
    #[serde(default)]
    pub gc_interval_ms: Option<u64>,
    #[serde(default)]
    pub max_entries: Option<usize>,
    #[serde(default)]
    pub shard_count: Option<usize>,
    #[serde(default)]
    pub host_frame_queue_max: Option<usize>,
    #[serde(default)]
    pub pending_arp_queue_max: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkOverlayConfigFile {
    #[serde(default)]
    pub swap_tunnels: bool,
    #[serde(default)]
    pub force_tunnel_src_port: bool,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub health_probe_debug: bool,
}
