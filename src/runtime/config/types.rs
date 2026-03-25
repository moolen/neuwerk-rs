use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub version: u16,
    pub bootstrap: BootstrapConfig,
    pub dns: DnsConfig,
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
    pub aws: Option<AwsIntegrationConfig>,
    pub azure: Option<AzureIntegrationConfig>,
    pub gcp: Option<GcpIntegrationConfig>,
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
pub struct TlsInterceptConfig;

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
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpdkConfig {
    pub static_ip: Option<Ipv4Addr>,
    pub static_prefix_len: Option<u8>,
    pub static_gateway: Option<Ipv4Addr>,
    pub static_mac: Option<String>,
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
            aws: None,
            azure: None,
            gcp: None,
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
            },
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
