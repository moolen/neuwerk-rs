#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedConfig {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrationConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsInterceptConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataplaneConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdkConfig;
