use super::schema::RuntimeConfigFile;
use super::types::{
    BootstrapConfig, DataplaneConfig, DnsConfig, DpdkConfig, HttpConfig, IntegrationConfig,
    IntegrationMode, LoadedConfig, MetricsConfig, PolicyConfig, SnatMode, TlsInterceptConfig,
    ValidatedConfig,
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
            data_plane_mode: raw.bootstrap.data_plane_mode,
        },
        dns: DnsConfig {
            upstreams: raw.dns.upstreams,
        },
        policy: raw.policy.map(|_| PolicyConfig),
        http: raw.http.map(|_| HttpConfig),
        metrics: raw.metrics.map(|_| MetricsConfig::default()),
        integration: raw.integration.map(|_| IntegrationConfig::default()),
        tls_intercept: raw.tls_intercept.map(|_| TlsInterceptConfig),
        dataplane: raw.dataplane.map(|_| DataplaneConfig::default()),
        dpdk: raw.dpdk.map(|_| DpdkConfig::default()),
    };
    validate_semantics(&validated)?;
    Ok(validated)
}

pub(crate) fn validate_semantics(cfg: &ValidatedConfig) -> Result<(), String> {
    validate_data_plane_mode(cfg)?;
    validate_dpdk_static_network(cfg)?;
    validate_integration_requirements(cfg)?;
    validate_metrics_bind_policy(cfg)?;
    validate_snat_mode(cfg)?;
    Ok(())
}

fn validate_data_plane_mode(cfg: &ValidatedConfig) -> Result<(), String> {
    if cfg.bootstrap.data_plane_mode.eq_ignore_ascii_case("soft")
        || cfg.bootstrap.data_plane_mode.eq_ignore_ascii_case("dpdk")
    {
        return Ok(());
    }
    Err(format!(
        "config validation error: unsupported bootstrap.data_plane_mode `{}`",
        cfg.bootstrap.data_plane_mode
    ))
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
        "config validation error: integration.mode=aws-asg requires integration.aws block".to_string()
    })?;
    if aws.region.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(
            "config validation error: integration.mode=aws-asg requires integration.aws.region"
                .to_string(),
        );
    }
    if aws.vpc_id.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(
            "config validation error: integration.mode=aws-asg requires integration.aws.vpc_id"
                .to_string(),
        );
    }
    if aws.asg_name.as_deref().map(str::trim).filter(|v| !v.is_empty()).is_none() {
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
    use super::super::types::{
        AwsIntegrationConfig, DataplaneConfig, DpdkConfig, IntegrationConfig, IntegrationMode,
        MetricsConfig, SnatMode, ValidatedConfig,
    };
    use super::validate_semantics;

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
        let cfg = ValidatedConfig {
            bootstrap: super::super::types::BootstrapConfig {
                management_interface: "eth0".to_string(),
                data_interface: "eth1".to_string(),
                data_plane_mode: "dpdk".to_string(),
            },
            dpdk: Some(DpdkConfig {
                static_ip: Some("10.0.2.5".to_string()),
                static_prefix_len: None,
                static_gateway: None,
                static_mac: None,
            }),
            ..ValidatedConfig::default()
        };

        let err = validate_semantics(&cfg).unwrap_err();
        assert!(err.contains("dpdk.static"), "{err}");
    }

    #[test]
    fn validate_rejects_aws_asg_missing_required_fields() {
        let cfg = ValidatedConfig {
            integration: Some(IntegrationConfig {
                mode: IntegrationMode::AwsAsg,
                route_name: Some("neuwerk-default".to_string()),
                cluster_name: Some("neuwerk".to_string()),
                aws: Some(AwsIntegrationConfig {
                    region: None,
                    vpc_id: None,
                    asg_name: None,
                }),
            }),
            ..ValidatedConfig::default()
        };

        let err = validate_semantics(&cfg).unwrap_err();
        assert!(err.contains("integration.aws"), "{err}");
    }

    #[test]
    fn validate_rejects_public_metrics_bind_without_allow_flag() {
        let cfg = ValidatedConfig {
            metrics: Some(MetricsConfig {
                bind: Some("0.0.0.0:8080".to_string()),
                allow_public_bind: false,
            }),
            ..ValidatedConfig::default()
        };

        let err = validate_semantics(&cfg).unwrap_err();
        assert!(err.contains("metrics.allow_public_bind"), "{err}");
    }

    #[test]
    fn validate_rejects_static_snat_with_dpdk_dataplane() {
        let cfg = ValidatedConfig {
            bootstrap: super::super::types::BootstrapConfig {
                management_interface: "eth0".to_string(),
                data_interface: "eth1".to_string(),
                data_plane_mode: "dpdk".to_string(),
            },
            dataplane: Some(DataplaneConfig {
                snat: SnatMode::Static,
            }),
            ..ValidatedConfig::default()
        };

        let err = validate_semantics(&cfg).unwrap_err();
        assert!(err.contains("dataplane.snat"), "{err}");
    }
}
