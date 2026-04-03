use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use neuwerk::controlplane::trafficd::UpstreamTlsVerificationMode;
use neuwerk::dataplane::engine::AdmissionControlConfig;

pub const DNS_UPSTREAM_TIMEOUT_MS_DEFAULT: u64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub version: u16,
    pub bootstrap: BootstrapConfig,
    pub dns: DnsConfig,
    pub runtime: RuntimeBehaviorConfig,
    pub policy: PolicyConfig,
    pub http: HttpConfig,
    pub metrics: MetricsConfig,
    pub cluster: ClusterConfig,
    pub integration: IntegrationConfig,
    pub tls_intercept: Option<TlsInterceptConfig>,
    pub dataplane: DataplaneConfig,
    pub dpdk: Option<DpdkConfig>,
}

pub type LoadedConfig = ValidatedConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    pub management_interface: String,
    pub data_interface: String,
    pub cloud_provider: String,
    pub data_plane_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub target_ips: Vec<Ipv4Addr>,
    pub upstreams: Vec<SocketAddr>,
    pub upstream_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeBehaviorConfig {
    pub controlplane_worker_threads: usize,
    pub http_worker_threads: usize,
    pub kubernetes: KubernetesRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesRuntimeConfig {
    pub reconcile_interval_secs: u64,
    pub stale_grace_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DefaultPolicy {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    pub default: DefaultPolicy,
    pub internal_cidr: Option<(Ipv4Addr, u8)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig {
    pub bind: Option<SocketAddr>,
    pub advertise: Option<SocketAddr>,
    pub external_url: Option<String>,
    pub tls_dir: PathBuf,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    pub tls_san: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsConfig {
    pub bind: Option<SocketAddr>,
    pub allow_public_bind: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    pub join_bind: SocketAddr,
    pub advertise: SocketAddr,
    pub join_seed: Option<SocketAddr>,
    pub data_dir: PathBuf,
    pub node_id_path: PathBuf,
    pub token_path: PathBuf,
    pub migrate_from_local: bool,
    pub migrate_force: bool,
    pub migrate_verify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationConfig {
    pub mode: IntegrationMode,
    pub route_name: String,
    pub cluster_name: String,
    pub drain_timeout_secs: u64,
    pub reconcile_interval_secs: u64,
    pub membership: IntegrationMembershipConfig,
    pub aws: Option<AwsIntegrationConfig>,
    pub azure: Option<AzureIntegrationConfig>,
    pub gcp: Option<GcpIntegrationConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationMembershipConfig {
    pub auto_evict_terminating: bool,
    pub stale_after_secs: u64,
    pub min_voters: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsIntegrationConfig {
    pub region: Option<String>,
    pub vpc_id: Option<String>,
    pub asg_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureIntegrationConfig {
    pub subscription_id: Option<String>,
    pub resource_group: Option<String>,
    pub vmss_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcpIntegrationConfig {
    pub project: Option<String>,
    pub region: Option<String>,
    pub ig_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInterceptConfig {
    pub upstream_verify: UpstreamTlsVerificationMode,
    pub io_timeout_secs: u64,
    pub listen_backlog: u32,
    pub h2: TlsInterceptH2Config,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInterceptH2Config {
    pub body_timeout_secs: u64,
    pub max_concurrent_streams: u32,
    pub max_requests_per_connection: usize,
    pub pool_shards: usize,
    pub detailed_metrics: bool,
    pub selection_inflight_weight: u64,
    pub reconnect_backoff_base_ms: u64,
    pub reconnect_backoff_max_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnatMode {
    #[default]
    Auto,
    None,
    Static(Ipv4Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncapMode {
    #[default]
    None,
    Vxlan,
    Geneve,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneConfig {
    pub idle_timeout_secs: u64,
    pub dns_allowlist_idle_secs: u64,
    pub dns_allowlist_gc_interval_secs: u64,
    pub dhcp_timeout_secs: u64,
    pub dhcp_retry_max: u32,
    pub dhcp_lease_min_secs: u64,
    pub snat: SnatMode,
    pub encap_mode: String,
    pub encap_vni: Option<u32>,
    pub encap_vni_internal: Option<u32>,
    pub encap_vni_external: Option<u32>,
    pub encap_udp_port: Option<u16>,
    pub encap_udp_port_internal: Option<u16>,
    pub encap_udp_port_external: Option<u16>,
    pub encap_mtu: u16,
    pub flow_table_capacity: usize,
    pub nat_table_capacity: usize,
    pub flow_incomplete_tcp_idle_timeout_secs: Option<u64>,
    pub flow_incomplete_tcp_syn_sent_idle_timeout_secs: u64,
    pub syn_only_enabled: bool,
    pub detailed_observability: bool,
    pub admission: AdmissionControlConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdkConfig {
    pub static_ip: Option<Ipv4Addr>,
    pub static_prefix_len: Option<u8>,
    pub static_gateway: Option<Ipv4Addr>,
    pub static_mac: Option<String>,
    pub workers: Option<usize>,
    pub core_ids: Vec<usize>,
    pub allow_azure_multiworker: bool,
    pub single_queue_mode: DpdkSingleQueueMode,
    pub perf_mode: DpdkPerfMode,
    pub force_shared_rx_demux: bool,
    pub pin_https_demux_owner: bool,
    pub disable_service_lane: bool,
    pub lockless_queue_per_worker: bool,
    pub shared_rx_owner_only: bool,
    pub housekeeping_interval_packets: u64,
    pub housekeeping_interval_us: u64,
    pub pin_state_shard_guard: bool,
    pub pin_state_shard_burst: u32,
    pub state_shards: Option<usize>,
    pub disable_in_memory: bool,
    pub iova_mode: Option<DpdkIovaMode>,
    pub force_netvsc: bool,
    pub gcp_auto_probe: bool,
    pub driver_preload: Vec<String>,
    pub skip_bus_pci_preload: bool,
    pub prefer_pci: bool,
    pub queue_override: Option<u16>,
    pub port_mtu: Option<u16>,
    pub mbuf_data_room: Option<u16>,
    pub mbuf_pool_size: Option<u32>,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub tx_checksum_offload: Option<bool>,
    pub allow_retaless_multi_queue: bool,
    pub service_lane: DpdkServiceLaneConfig,
    pub intercept_demux: DpdkInterceptDemuxConfig,
    pub gateway_mac: Option<String>,
    pub dhcp_server_ip: Option<Ipv4Addr>,
    pub dhcp_server_mac: Option<String>,
    pub overlay: DpdkOverlayConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpdkSingleQueueMode {
    #[default]
    Demux,
    SingleWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DpdkPerfMode {
    #[default]
    Standard,
    Aggressive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkIovaMode {
    Va,
    Pa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdkServiceLaneConfig {
    pub interface: String,
    pub intercept_service_ip: Ipv4Addr,
    pub intercept_service_port: u16,
    pub multi_queue: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdkInterceptDemuxConfig {
    pub gc_interval_ms: u64,
    pub max_entries: usize,
    pub shard_count: usize,
    pub host_frame_queue_max: usize,
    pub pending_arp_queue_max: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpdkOverlayConfig {
    pub swap_tunnels: bool,
    pub force_tunnel_src_port: bool,
    pub debug: bool,
    pub health_probe_debug: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataPlaneMode {
    #[default]
    Tun,
    Tap,
    Dpdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegrationMode {
    #[default]
    None,
    AzureVmss,
    AwsAsg,
    GcpMig,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: DefaultPolicy::Deny,
            internal_cidr: None,
        }
    }
}

impl Default for RuntimeBehaviorConfig {
    fn default() -> Self {
        Self {
            controlplane_worker_threads: 4,
            http_worker_threads: 2,
            kubernetes: KubernetesRuntimeConfig::default(),
        }
    }
}

impl Default for KubernetesRuntimeConfig {
    fn default() -> Self {
        Self {
            reconcile_interval_secs: 5,
            stale_grace_secs: 300,
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: None,
            advertise: None,
            external_url: None,
            tls_dir: PathBuf::from("/var/lib/neuwerk/http-tls"),
            cert_path: None,
            key_path: None,
            ca_path: None,
            tls_san: Vec::new(),
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        let bind = SocketAddr::from(([127, 0, 0, 1], 9600));
        let join_bind = SocketAddr::new(bind.ip(), bind.port().saturating_add(1));
        Self {
            enabled: false,
            bind,
            join_bind,
            advertise: bind,
            join_seed: None,
            data_dir: PathBuf::from("/var/lib/neuwerk/cluster"),
            node_id_path: PathBuf::from("/var/lib/neuwerk/node_id"),
            token_path: PathBuf::from("/var/lib/neuwerk/bootstrap-token"),
            migrate_from_local: false,
            migrate_force: false,
            migrate_verify: false,
        }
    }
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        let idle_timeout_secs = neuwerk::dataplane::DEFAULT_IDLE_TIMEOUT_SECS;
        Self {
            idle_timeout_secs,
            dns_allowlist_idle_secs: idle_timeout_secs + 120,
            dns_allowlist_gc_interval_secs: 30,
            dhcp_timeout_secs: 5,
            dhcp_retry_max: 5,
            dhcp_lease_min_secs: 60,
            snat: SnatMode::Auto,
            encap_mode: "none".to_string(),
            encap_vni: None,
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: None,
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: 1500,
            flow_table_capacity: 1 << 15,
            nat_table_capacity: 1 << 15,
            flow_incomplete_tcp_idle_timeout_secs: None,
            flow_incomplete_tcp_syn_sent_idle_timeout_secs: 3,
            syn_only_enabled: false,
            detailed_observability: false,
            admission: AdmissionControlConfig::default(),
        }
    }
}

impl Default for TlsInterceptConfig {
    fn default() -> Self {
        Self {
            upstream_verify: UpstreamTlsVerificationMode::Strict,
            io_timeout_secs: 3,
            listen_backlog: 1024,
            h2: TlsInterceptH2Config::default(),
        }
    }
}

impl Default for TlsInterceptH2Config {
    fn default() -> Self {
        Self {
            body_timeout_secs: 10,
            max_concurrent_streams: 64,
            max_requests_per_connection: 800,
            pool_shards: 1,
            detailed_metrics: false,
            selection_inflight_weight: 128,
            reconnect_backoff_base_ms: 5,
            reconnect_backoff_max_ms: 250,
        }
    }
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            mode: IntegrationMode::None,
            route_name: "neuwerk-default".to_string(),
            cluster_name: "neuwerk".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 15,
            membership: IntegrationMembershipConfig::default(),
            aws: None,
            azure: None,
            gcp: None,
        }
    }
}

impl Default for IntegrationMembershipConfig {
    fn default() -> Self {
        Self {
            auto_evict_terminating: true,
            stale_after_secs: 0,
            min_voters: 3,
        }
    }
}

impl Default for ValidatedConfig {
    fn default() -> Self {
        Self {
            version: 1,
            bootstrap: BootstrapConfig {
                management_interface: "eth0".to_string(),
                data_interface: "eth1".to_string(),
                cloud_provider: "none".to_string(),
                data_plane_mode: "tun".to_string(),
            },
            dns: DnsConfig {
                target_ips: vec![Ipv4Addr::new(10, 0, 0, 53)],
                upstreams: vec![SocketAddr::from(([10, 0, 0, 2], 53))],
                upstream_timeout_ms: DNS_UPSTREAM_TIMEOUT_MS_DEFAULT,
            },
            runtime: RuntimeBehaviorConfig::default(),
            policy: PolicyConfig::default(),
            http: HttpConfig::default(),
            metrics: MetricsConfig::default(),
            cluster: ClusterConfig::default(),
            integration: IntegrationConfig::default(),
            tls_intercept: None,
            dataplane: DataplaneConfig::default(),
            dpdk: None,
        }
    }
}

impl Default for DpdkConfig {
    fn default() -> Self {
        Self {
            static_ip: None,
            static_prefix_len: None,
            static_gateway: None,
            static_mac: None,
            workers: None,
            core_ids: Vec::new(),
            allow_azure_multiworker: false,
            single_queue_mode: DpdkSingleQueueMode::Demux,
            perf_mode: DpdkPerfMode::Standard,
            force_shared_rx_demux: false,
            pin_https_demux_owner: false,
            disable_service_lane: false,
            lockless_queue_per_worker: false,
            shared_rx_owner_only: true,
            housekeeping_interval_packets: 64,
            housekeeping_interval_us: 250,
            pin_state_shard_guard: false,
            pin_state_shard_burst: 64,
            state_shards: None,
            disable_in_memory: false,
            iova_mode: None,
            force_netvsc: false,
            gcp_auto_probe: false,
            driver_preload: Vec::new(),
            skip_bus_pci_preload: false,
            prefer_pci: false,
            queue_override: None,
            port_mtu: None,
            mbuf_data_room: None,
            mbuf_pool_size: None,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            tx_checksum_offload: None,
            allow_retaless_multi_queue: false,
            service_lane: DpdkServiceLaneConfig::default(),
            intercept_demux: DpdkInterceptDemuxConfig::default(),
            gateway_mac: None,
            dhcp_server_ip: None,
            dhcp_server_mac: None,
            overlay: DpdkOverlayConfig::default(),
        }
    }
}

impl Default for DpdkServiceLaneConfig {
    fn default() -> Self {
        Self {
            interface: "svc0".to_string(),
            intercept_service_ip: Ipv4Addr::new(169, 254, 255, 1),
            intercept_service_port: 15443,
            multi_queue: true,
        }
    }
}

impl Default for DpdkInterceptDemuxConfig {
    fn default() -> Self {
        Self {
            gc_interval_ms: 1_000,
            max_entries: 65_536,
            shard_count: 64,
            host_frame_queue_max: 8_192,
            pending_arp_queue_max: 4_096,
        }
    }
}
