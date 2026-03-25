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
    pub data_plane_mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfigFile {
    pub upstreams: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsInterceptConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkConfigFile {}
