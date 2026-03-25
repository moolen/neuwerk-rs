use super::schema::RuntimeConfigFile;
use super::types::{
    BootstrapConfig, DataplaneConfig, DnsConfig, DpdkConfig, HttpConfig, IntegrationConfig,
    LoadedConfig, MetricsConfig, PolicyConfig, TlsInterceptConfig,
};

pub(crate) fn validate_config(raw: RuntimeConfigFile) -> Result<LoadedConfig, String> {
    if raw.version != 1 {
        return Err(format!(
            "config validation error: unsupported config version {}, expected 1",
            raw.version
        ));
    }

    Ok(LoadedConfig {
        version: raw.version,
        bootstrap: BootstrapConfig {
            management_interface: raw.bootstrap.management_interface,
            data_interface: raw.bootstrap.data_interface,
            data_plane_mode: raw.bootstrap.data_plane_mode,
        },
        dns: DnsConfig {
            upstreams: raw.dns.upstreams,
        },
        policy: raw.policy.map(|_| PolicyConfig),
        http: raw.http.map(|_| HttpConfig),
        metrics: raw.metrics.map(|_| MetricsConfig),
        integration: raw.integration.map(|_| IntegrationConfig),
        tls_intercept: raw.tls_intercept.map(|_| TlsInterceptConfig),
        dataplane: raw.dataplane.map(|_| DataplaneConfig),
        dpdk: raw.dpdk.map(|_| DpdkConfig),
    })
}

#[cfg(test)]
mod tests {
    use super::super::load_config_str;

    #[test]
    fn load_config_rejects_missing_version() {
        let raw = r#"
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
"#;

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("missing field `version`"), "{err}");
    }

    #[test]
    fn load_config_rejects_unsupported_version() {
        let raw = r#"
version: 2
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
"#;

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("unsupported config version 2"), "{err}");
    }
}
