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
    Disabled,
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
        None => MetricsBindResolution::Disabled,
    }
}

fn parse_data_plane_mode(value: &str) -> Result<DataPlaneMode, String> {
    match value {
        "soft" | "SOFT" => Ok(DataPlaneMode::Soft),
        "dpdk" | "DPDK" => Ok(DataPlaneMode::Dpdk),
        _ => Err(format!(
            "config derivation error: unsupported bootstrap.data_plane_mode `{value}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::{IntegrationConfig, IntegrationMode, MetricsConfig};
    use super::{derive_runtime_config, MetricsBindResolution};

    #[test]
    fn derive_runtime_marks_dpdk_mode_enabled() {
        let mut cfg = super::super::types::ValidatedConfig::default();
        cfg.bootstrap.data_plane_mode = "dpdk".to_string();

        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert!(derived.runtime.dpdk_enabled);
    }

    #[test]
    fn derive_runtime_preserves_integration_mode_for_later_cloud_resolution() {
        let mut cfg = super::super::types::ValidatedConfig::default();
        cfg.integration = Some(IntegrationConfig {
            mode: IntegrationMode::AwsAsg,
            route_name: Some("neuwerk-default".to_string()),
            cluster_name: Some("neuwerk".to_string()),
            aws: None,
        });

        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert_eq!(derived.runtime.integration.mode, IntegrationMode::AwsAsg);
    }

    #[test]
    fn derive_runtime_keeps_management_ip_dependent_metrics_bind_unresolved() {
        let mut cfg = super::super::types::ValidatedConfig::default();
        cfg.metrics = Some(MetricsConfig {
            bind: None,
            allow_public_bind: false,
        });

        let derived = derive_runtime_config(cfg).expect("derive should succeed");
        assert_eq!(
            derived.runtime.metrics_bind,
            MetricsBindResolution::FromManagementInterface { port: 8080 }
        );
    }
}
