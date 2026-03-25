#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig {
    pub version: u16,
    pub bootstrap: BootstrapConfig,
    pub dns: DnsConfig,
    pub policy: Option<PolicyConfig>,
    pub http: Option<HttpConfig>,
    pub metrics: Option<MetricsConfig>,
    pub integration: Option<IntegrationConfig>,
    pub tls_intercept: Option<TlsInterceptConfig>,
    pub dataplane: Option<DataplaneConfig>,
    pub dpdk: Option<DpdkConfig>,
}

pub type LoadedConfig = ValidatedConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    pub management_interface: String,
    pub data_interface: String,
    pub data_plane_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    pub upstreams: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConfig;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsConfig {
    pub bind: Option<String>,
    pub allow_public_bind: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntegrationConfig {
    pub mode: IntegrationMode,
    pub route_name: Option<String>,
    pub cluster_name: Option<String>,
    pub aws: Option<AwsIntegrationConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsIntegrationConfig {
    pub region: Option<String>,
    pub vpc_id: Option<String>,
    pub asg_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInterceptConfig;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataplaneConfig {
    pub snat: SnatMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpdkConfig {
    pub static_ip: Option<String>,
    pub static_prefix_len: Option<u8>,
    pub static_gateway: Option<String>,
    pub static_mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DataPlaneMode {
    #[default]
    Soft,
    Dpdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegrationMode {
    #[default]
    None,
    AwsAsg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SnatMode {
    #[default]
    Auto,
    None,
    Static,
}

impl Default for ValidatedConfig {
    fn default() -> Self {
        Self {
            version: 1,
            bootstrap: BootstrapConfig {
                management_interface: "eth0".to_string(),
                data_interface: "eth1".to_string(),
                data_plane_mode: "soft".to_string(),
            },
            dns: DnsConfig {
                upstreams: vec!["10.0.0.2:53".to_string()],
            },
            policy: None,
            http: None,
            metrics: None,
            integration: None,
            tls_intercept: None,
            dataplane: None,
            dpdk: None,
        }
    }
}
