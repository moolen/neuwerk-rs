use super::types::{DataPlaneMode, IntegrationMode, ValidatedConfig};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedRuntimeConfig {
    pub operator: ValidatedConfig,
    pub runtime: RuntimeSettings,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub data_plane_mode: DataPlaneMode,
    pub dpdk_enabled: bool,
    pub integration: DerivedIntegration,
    pub metrics_bind: MetricsBindResolution,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedIntegration {
    pub mode: IntegrationMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsBindResolution {
    Explicit(String),
    FromManagementInterface { port: u16 },
}

pub fn derive_runtime_config(cfg: ValidatedConfig) -> Result<DerivedRuntimeConfig, String> {
    let data_plane_mode = parse_data_plane_mode(&cfg.bootstrap.data_plane_mode)?;
    let dpdk_enabled = matches!(data_plane_mode, DataPlaneMode::Dpdk);
    let integration_mode = cfg
        .integration
        .as_ref()
        .map(|integration| integration.mode)
        .unwrap_or(IntegrationMode::None);
    let metrics_bind = resolve_metrics_bind(cfg.metrics.as_ref());

    Ok(DerivedRuntimeConfig {
        runtime: RuntimeSettings {
            data_plane_mode,
            dpdk_enabled,
            integration: DerivedIntegration {
                mode: integration_mode,
            },
            metrics_bind,
        },
        operator: cfg,
    })
}

fn resolve_metrics_bind(metrics: Option<&super::types::MetricsConfig>) -> MetricsBindResolution {
    match metrics {
        Some(metrics) => match metrics.bind.as_ref() {
            Some(bind) => MetricsBindResolution::Explicit(bind.clone()),
            None => MetricsBindResolution::FromManagementInterface { port: 8080 },
        },
        None => MetricsBindResolution::FromManagementInterface { port: 8080 },
    }
}

fn parse_data_plane_mode(value: &str) -> Result<DataPlaneMode, String> {
    if value.eq_ignore_ascii_case("soft") {
        return Ok(DataPlaneMode::Soft);
    }
    if value.eq_ignore_ascii_case("dpdk") {
        return Ok(DataPlaneMode::Dpdk);
    }
    Err(format!(
        "config derivation error: unsupported bootstrap.data_plane_mode `{value}`"
    ))
}

#[cfg(test)]
mod tests {
    use super::super::load_config_str;
    use super::{derive_runtime_config, MetricsBindResolution};

    #[test]
    fn derive_runtime_marks_dpdk_mode_enabled() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("load config");
        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert!(derived.runtime.dpdk_enabled);
    }

    #[test]
    fn derive_runtime_preserves_integration_mode_for_later_cloud_resolution() {
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
  aws:
    region: us-east-1
    vpc_id: vpc-0123456789abcdef0
    asg_name: neuwerk-asg
"#;
        let cfg = load_config_str(raw).expect("load config");
        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert_eq!(
            derived.runtime.integration.mode,
            super::super::types::IntegrationMode::AwsAsg
        );
    }

    #[test]
    fn derive_runtime_keeps_management_ip_dependent_metrics_bind_unresolved() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: soft
dns:
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("load config");
        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert_eq!(
            derived.runtime.metrics_bind,
            MetricsBindResolution::FromManagementInterface { port: 8080 }
        );
    }

    #[test]
    fn derive_runtime_accepts_mixed_case_validated_data_plane_mode() {
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
        let cfg = load_config_str(raw).expect("load config");
        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert!(derived.runtime.dpdk_enabled);
    }
}
