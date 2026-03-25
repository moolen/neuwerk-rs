use super::schema::RuntimeConfigFile;
use super::types::{
    AwsIntegrationConfig, BootstrapConfig, DataplaneConfig, DnsConfig, DpdkConfig, HttpConfig,
    IntegrationConfig, IntegrationMode, LoadedConfig, MetricsConfig, PolicyConfig, SnatMode,
    TlsInterceptConfig, ValidatedConfig,
};

pub(crate) fn validate_config(raw: RuntimeConfigFile) -> Result<LoadedConfig, String> {
    if raw.version != 1 {
        return Err(format!(
            "config validation error: unsupported config version {}, expected 1",
            raw.version
        ));
    }

    let validated = LoadedConfig {
        version: raw.version,
        bootstrap: BootstrapConfig {
            management_interface: raw.bootstrap.management_interface,
            data_interface: raw.bootstrap.data_interface,
            data_plane_mode: canonical_data_plane_mode(&raw.bootstrap.data_plane_mode)?,
        },
        dns: DnsConfig {
            upstreams: raw.dns.upstreams,
        },
        policy: raw.policy.map(|_| PolicyConfig),
        http: raw.http.map(|_| HttpConfig),
        metrics: raw.metrics.map(|metrics| MetricsConfig {
            bind: metrics.bind,
            allow_public_bind: metrics.allow_public_bind,
        }),
        integration: raw
            .integration
            .map(|integration| -> Result<IntegrationConfig, String> {
                Ok(IntegrationConfig {
                    mode: integration
                        .mode
                        .as_deref()
                        .map(parse_integration_mode)
                        .transpose()?
                        .unwrap_or(IntegrationMode::None),
                    route_name: integration.route_name,
                    cluster_name: integration.cluster_name,
                    aws: integration.aws.map(|aws| AwsIntegrationConfig {
                        region: aws.region,
                        vpc_id: aws.vpc_id,
                        asg_name: aws.asg_name,
                    }),
                })
            })
            .transpose()?,
        tls_intercept: raw.tls_intercept.map(|_| TlsInterceptConfig),
        dataplane: raw
            .dataplane
            .map(|dataplane| -> Result<DataplaneConfig, String> {
                Ok(DataplaneConfig {
                    snat: dataplane
                        .snat
                        .as_deref()
                        .map(parse_snat_mode)
                        .transpose()?
                        .unwrap_or_default(),
                })
            })
            .transpose()?,
        dpdk: raw.dpdk.map(|dpdk| DpdkConfig {
            static_ip: dpdk.static_ip,
            static_prefix_len: dpdk.static_prefix_len,
            static_gateway: dpdk.static_gateway,
            static_mac: dpdk.static_mac,
        }),
    };
    validate_semantics(&validated)?;
    Ok(validated)
}

fn canonical_data_plane_mode(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("soft") {
        return Ok("soft".to_string());
    }
    if value.eq_ignore_ascii_case("dpdk") {
        return Ok("dpdk".to_string());
    }
    Err(format!(
        "config validation error: unsupported bootstrap.data_plane_mode `{value}`"
    ))
}

fn parse_integration_mode(value: &str) -> Result<IntegrationMode, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(IntegrationMode::None);
    }
    if value.eq_ignore_ascii_case("aws-asg") {
        return Ok(IntegrationMode::AwsAsg);
    }
    Err(format!(
        "config validation error: unsupported integration.mode `{value}`"
    ))
}

fn parse_snat_mode(value: &str) -> Result<SnatMode, String> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(SnatMode::Auto);
    }
    if value.eq_ignore_ascii_case("none") {
        return Ok(SnatMode::None);
    }
    if value.eq_ignore_ascii_case("static") {
        return Ok(SnatMode::Static);
    }
    Err(format!(
        "config validation error: unsupported dataplane.snat `{value}`"
    ))
}

pub(crate) fn validate_semantics(cfg: &ValidatedConfig) -> Result<(), String> {
    validate_data_plane_mode(cfg)?;
    validate_dpdk_static_network(cfg)?;
    validate_integration_requirements(cfg)?;
    validate_metrics_bind_policy(cfg)?;
    validate_snat_mode(cfg)?;
    Ok(())
}

fn validate_data_plane_mode(_cfg: &ValidatedConfig) -> Result<(), String> {
    Ok(())
}

fn validate_dpdk_static_network(cfg: &ValidatedConfig) -> Result<(), String> {
    let Some(dpdk) = cfg.dpdk.as_ref() else {
        return Ok(());
    };

    let has_any = dpdk.static_ip.is_some()
        || dpdk.static_prefix_len.is_some()
        || dpdk.static_gateway.is_some()
        || dpdk.static_mac.is_some();
    if !has_any {
        return Ok(());
    }

    let missing = [
        (dpdk.static_ip.is_none(), "dpdk.static_ip"),
        (dpdk.static_prefix_len.is_none(), "dpdk.static_prefix_len"),
        (dpdk.static_gateway.is_none(), "dpdk.static_gateway"),
        (dpdk.static_mac.is_none(), "dpdk.static_mac"),
    ]
    .into_iter()
    .filter_map(|(is_missing, key)| is_missing.then_some(key))
    .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(());
    }

    Err(format!(
        "config validation error: partial dpdk.static configuration, missing {}",
        missing.join(", ")
    ))
}

fn validate_integration_requirements(cfg: &ValidatedConfig) -> Result<(), String> {
    let Some(integration) = cfg.integration.as_ref() else {
        return Ok(());
    };

    if integration.mode != IntegrationMode::AwsAsg {
        return Ok(());
    }

    let aws = integration.aws.as_ref().ok_or_else(|| {
        "config validation error: integration.mode=aws-asg requires integration.aws block"
            .to_string()
    })?;
    if aws
        .region
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err(
            "config validation error: integration.mode=aws-asg requires integration.aws.region"
                .to_string(),
        );
    }
    if aws
        .vpc_id
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err(
            "config validation error: integration.mode=aws-asg requires integration.aws.vpc_id"
                .to_string(),
        );
    }
    if aws
        .asg_name
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .is_none()
    {
        return Err(
            "config validation error: integration.mode=aws-asg requires integration.aws.asg_name"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_metrics_bind_policy(cfg: &ValidatedConfig) -> Result<(), String> {
    let Some(metrics) = cfg.metrics.as_ref() else {
        return Ok(());
    };
    let Some(bind) = metrics.bind.as_deref() else {
        return Ok(());
    };

    let is_public = bind
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| addr.ip().is_unspecified())
        .unwrap_or(false);
    if is_public && !metrics.allow_public_bind {
        return Err(
            "config validation error: metrics.bind is public, set metrics.allow_public_bind=true"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_snat_mode(cfg: &ValidatedConfig) -> Result<(), String> {
    if !cfg.bootstrap.data_plane_mode.eq_ignore_ascii_case("dpdk") {
        return Ok(());
    }

    if matches!(
        cfg.dataplane.as_ref().map(|dp| dp.snat),
        Some(SnatMode::Static)
    ) {
        return Err(
            "config validation error: dataplane.snat=static is not supported with bootstrap.data_plane_mode=dpdk"
                .to_string(),
        );
    }

    Ok(())
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

    #[test]
    fn validate_rejects_partial_static_dpdk_addressing() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
dpdk:
  static_ip: 10.0.2.5
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("dpdk.static"), "{err}");
    }

    #[test]
    fn validate_rejects_aws_asg_missing_required_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: soft
dns:
  upstreams:
    - 10.0.0.2:53
integration:
  mode: aws-asg
  route_name: neuwerk-default
  cluster_name: neuwerk
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("integration.aws"), "{err}");
    }

    #[test]
    fn validate_rejects_public_metrics_bind_without_allow_flag() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: soft
dns:
  upstreams:
    - 10.0.0.2:53
metrics:
  bind: 0.0.0.0:8080
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("metrics.allow_public_bind"), "{err}");
    }

    #[test]
    fn validate_accepts_metrics_fields_when_allow_flag_is_enabled() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: soft
dns:
  upstreams:
    - 10.0.0.2:53
metrics:
  bind: 0.0.0.0:8080
  allow_public_bind: true
"#;
        let cfg = load_config_str(raw).expect("metrics config should load");
        let metrics = cfg.metrics.expect("metrics block should map through");
        assert_eq!(metrics.bind.as_deref(), Some("0.0.0.0:8080"));
        assert!(metrics.allow_public_bind);
    }

    #[test]
    fn validate_rejects_static_snat_with_dpdk_dataplane() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
dataplane:
  snat: static
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("dataplane.snat"), "{err}");
    }

    #[test]
    fn validate_accepts_mixed_case_data_plane_mode_through_load_path() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: DpDk
dns:
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("mixed-case dataplane mode should load");
        assert_eq!(cfg.bootstrap.data_plane_mode, "dpdk");
    }
}
