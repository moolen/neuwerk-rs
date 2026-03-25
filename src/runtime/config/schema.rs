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
pub struct MetricsConfigFile {
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default)]
    pub allow_public_bind: bool,
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
    pub aws: Option<AwsIntegrationConfigFile>,
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
pub struct TlsInterceptConfigFile {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataplaneConfigFile {
    #[serde(default)]
    pub snat: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkConfigFile {
    #[serde(default)]
    pub static_ip: Option<String>,
    #[serde(default)]
    pub static_prefix_len: Option<u8>,
    #[serde(default)]
    pub static_gateway: Option<String>,
    #[serde(default)]
    pub static_mac: Option<String>,
}
