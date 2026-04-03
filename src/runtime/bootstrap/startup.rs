use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use neuwerk::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use neuwerk::controlplane::cloud::types::IntegrationMode;
use neuwerk::controlplane::cluster::config::RetryConfig;
use neuwerk::controlplane::cluster::migration;
use neuwerk::controlplane::cluster::ClusterRuntime;
use neuwerk::controlplane::policy_repository::PolicyDiskStore;
use neuwerk::controlplane::trafficd::{TlsInterceptH2Settings, TlsInterceptSettings};
use neuwerk::controlplane::wiretap::WiretapHub;
use neuwerk::dataplane::engine::EngineRuntimeConfig;
use neuwerk::dataplane::{EncapMode, OverlayConfig, SnatMode, SoftMode};
use neuwerk::metrics::Metrics;
use tracing::{info, warn};
use uuid::Uuid;

use crate::runtime::bootstrap::integration::{integration_tag_filter, select_integration_seed};
use crate::runtime::bootstrap::network::management_ipv4;
use crate::runtime::cli::CloudProviderKind;
use crate::runtime::cli::{CliConfig, DataPlaneMode};
use crate::runtime::config::{
    DefaultPolicy as RuntimeDefaultPolicy, DerivedRuntimeConfig, MetricsBindResolution,
    RuntimeIntegrationMode, RuntimeSnatMode,
};

#[derive(Debug, Clone, Copy)]
pub struct Bindings {
    pub management_ip: Ipv4Addr,
    pub http_bind: SocketAddr,
    pub http_advertise: SocketAddr,
    pub metrics_bind: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct DataplaneRuntimeNetworkConfig {
    pub internal_net: Ipv4Addr,
    pub internal_prefix: u8,
    pub public_ip: Ipv4Addr,
    pub overlay: OverlayConfig,
    pub data_port: u16,
}

const DEFAULT_DATAPLANE_PORT: u16 = 0;
pub const DEFAULT_RUNTIME_CONFIG_PATH: &str = "/etc/neuwerk/config.yaml";

pub fn load_runtime_config(path: &Path) -> Result<DerivedRuntimeConfig, String> {
    let loaded = crate::runtime::config::load_config(path)?;
    crate::runtime::config::derive_runtime_config(loaded)
}

pub fn load_default_runtime_config() -> Result<DerivedRuntimeConfig, String> {
    load_runtime_config(Path::new(DEFAULT_RUNTIME_CONFIG_PATH))
}

pub fn build_runtime_cli_config(cfg: &DerivedRuntimeConfig) -> Result<CliConfig, String> {
    let data_plane_mode = match cfg.operator.bootstrap.data_plane_mode.as_str() {
        "tun" => DataPlaneMode::Soft(SoftMode::Tun),
        "tap" => DataPlaneMode::Soft(SoftMode::Tap),
        "dpdk" => DataPlaneMode::Dpdk,
        value => {
            return Err(format!(
                "config bridge error: unsupported bootstrap.data_plane_mode `{value}`"
            ))
        }
    };
    let cloud_provider = match cfg.operator.bootstrap.cloud_provider.as_str() {
        "none" => CloudProviderKind::None,
        "azure" => CloudProviderKind::Azure,
        "aws" => CloudProviderKind::Aws,
        "gcp" => CloudProviderKind::Gcp,
        value => {
            return Err(format!(
                "config bridge error: unsupported bootstrap.cloud_provider `{value}`"
            ))
        }
    };
    let default_policy = match cfg.operator.policy.default {
        RuntimeDefaultPolicy::Allow => neuwerk::dataplane::policy::DefaultPolicy::Allow,
        RuntimeDefaultPolicy::Deny => neuwerk::dataplane::policy::DefaultPolicy::Deny,
    };
    let snat_mode = match cfg.operator.dataplane.snat {
        RuntimeSnatMode::Auto => SnatMode::Auto,
        RuntimeSnatMode::None => SnatMode::None,
        RuntimeSnatMode::Static(ip) => SnatMode::Static(ip),
    };
    let encap_mode = match cfg.operator.dataplane.encap_mode.as_str() {
        "none" => EncapMode::None,
        "vxlan" => EncapMode::Vxlan,
        "geneve" => EncapMode::Geneve,
        value => {
            return Err(format!(
                "config bridge error: unsupported dataplane.encap_mode `{value}`"
            ))
        }
    };
    let integration_mode = match cfg.operator.integration.mode {
        RuntimeIntegrationMode::None => IntegrationMode::None,
        RuntimeIntegrationMode::AzureVmss => IntegrationMode::AzureVmss,
        RuntimeIntegrationMode::AwsAsg => IntegrationMode::AwsAsg,
        RuntimeIntegrationMode::GcpMig => IntegrationMode::GcpMig,
    };
    let cluster = neuwerk::controlplane::cluster::config::ClusterConfig {
        enabled: cfg.operator.cluster.enabled,
        bind_addr: cfg.operator.cluster.bind,
        join_bind_addr: cfg.operator.cluster.join_bind,
        advertise_addr: cfg.operator.cluster.advertise,
        join_seed: cfg.operator.cluster.join_seed,
        data_dir: cfg.operator.cluster.data_dir.clone(),
        node_id_path: cfg.operator.cluster.node_id_path.clone(),
        token_path: cfg.operator.cluster.token_path.clone(),
        join_retry: RetryConfig::default_join(),
    };
    let tls_intercept = cfg.operator.tls_intercept.clone().unwrap_or_default();
    let engine_runtime = EngineRuntimeConfig {
        flow_table_capacity: cfg.operator.dataplane.flow_table_capacity,
        nat_table_capacity: cfg.operator.dataplane.nat_table_capacity,
        flow_incomplete_tcp_idle_timeout_secs: cfg
            .operator
            .dataplane
            .flow_incomplete_tcp_idle_timeout_secs,
        flow_incomplete_tcp_syn_sent_idle_timeout_secs: cfg
            .operator
            .dataplane
            .flow_incomplete_tcp_syn_sent_idle_timeout_secs,
        syn_only_enabled: cfg.operator.dataplane.syn_only_enabled,
        detailed_observability: cfg.operator.dataplane.detailed_observability,
        admission: cfg.operator.dataplane.admission.clone(),
        ..EngineRuntimeConfig::default()
    };

    Ok(CliConfig {
        management_iface: cfg.operator.bootstrap.management_interface.clone(),
        data_plane_iface: cfg.operator.bootstrap.data_interface.clone(),
        dns_target_ips: cfg.operator.dns.target_ips.clone(),
        dns_upstreams: cfg.operator.dns.upstreams.clone(),
        dns_upstream_timeout: Duration::from_millis(cfg.operator.dns.upstream_timeout_ms),
        data_plane_mode,
        idle_timeout_secs: cfg.operator.dataplane.idle_timeout_secs,
        dns_allowlist_idle_secs: cfg.operator.dataplane.dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs: cfg.operator.dataplane.dns_allowlist_gc_interval_secs,
        default_policy,
        dhcp_timeout_secs: cfg.operator.dataplane.dhcp_timeout_secs,
        dhcp_retry_max: cfg.operator.dataplane.dhcp_retry_max,
        dhcp_lease_min_secs: cfg.operator.dataplane.dhcp_lease_min_secs,
        internal_cidr: cfg.operator.policy.internal_cidr,
        snat_mode,
        encap_mode,
        encap_vni: cfg.operator.dataplane.encap_vni,
        encap_vni_internal: cfg.operator.dataplane.encap_vni_internal,
        encap_vni_external: cfg.operator.dataplane.encap_vni_external,
        encap_udp_port: cfg.operator.dataplane.encap_udp_port,
        encap_udp_port_internal: cfg.operator.dataplane.encap_udp_port_internal,
        encap_udp_port_external: cfg.operator.dataplane.encap_udp_port_external,
        encap_mtu: cfg.operator.dataplane.encap_mtu,
        http_external_url: cfg.operator.http.external_url.clone(),
        http_tls_dir: cfg.operator.http.tls_dir.clone(),
        http_cert_path: cfg.operator.http.cert_path.clone(),
        http_key_path: cfg.operator.http.key_path.clone(),
        http_ca_path: cfg.operator.http.ca_path.clone(),
        http_tls_san: cfg.operator.http.tls_san.clone(),
        allow_public_metrics_bind: cfg.operator.metrics.allow_public_bind,
        tls_intercept: TlsInterceptSettings {
            upstream_verify: tls_intercept.upstream_verify,
            io_timeout: Duration::from_secs(tls_intercept.io_timeout_secs),
            listen_backlog: tls_intercept.listen_backlog,
            h2: TlsInterceptH2Settings {
                body_timeout: Duration::from_secs(tls_intercept.h2.body_timeout_secs),
                max_concurrent_streams: tls_intercept.h2.max_concurrent_streams,
                max_requests_per_connection: tls_intercept.h2.max_requests_per_connection,
                pool_shards: tls_intercept.h2.pool_shards,
                detailed_metrics: tls_intercept.h2.detailed_metrics,
                selection_inflight_weight: tls_intercept.h2.selection_inflight_weight,
                reconnect_backoff_base_ms: tls_intercept.h2.reconnect_backoff_base_ms,
                reconnect_backoff_max_ms: tls_intercept.h2.reconnect_backoff_max_ms,
            },
        },
        engine_runtime,
        runtime: cfg.operator.runtime.clone(),
        dpdk: cfg.operator.dpdk.clone().unwrap_or_default(),
        cloud_provider,
        cluster,
        cluster_migrate_from_local: cfg.operator.cluster.migrate_from_local,
        cluster_migrate_force: cfg.operator.cluster.migrate_force,
        cluster_migrate_verify: cfg.operator.cluster.migrate_verify,
        integration_mode,
        integration_route_name: cfg.operator.integration.route_name.clone(),
        integration_drain_timeout_secs: cfg.operator.integration.drain_timeout_secs,
        integration_reconcile_interval_secs: cfg.operator.integration.reconcile_interval_secs,
        integration_cluster_name: cfg.operator.integration.cluster_name.clone(),
        integration_membership_auto_evict_terminating: cfg
            .operator
            .integration
            .membership
            .auto_evict_terminating,
        integration_membership_stale_after_secs: cfg
            .operator
            .integration
            .membership
            .stale_after_secs,
        integration_membership_min_voters: cfg.operator.integration.membership.min_voters,
        azure_subscription_id: cfg
            .operator
            .integration
            .azure
            .as_ref()
            .and_then(|azure| azure.subscription_id.clone()),
        azure_resource_group: cfg
            .operator
            .integration
            .azure
            .as_ref()
            .and_then(|azure| azure.resource_group.clone()),
        azure_vmss_name: cfg
            .operator
            .integration
            .azure
            .as_ref()
            .and_then(|azure| azure.vmss_name.clone()),
        aws_region: cfg
            .operator
            .integration
            .aws
            .as_ref()
            .and_then(|aws| aws.region.clone()),
        aws_vpc_id: cfg
            .operator
            .integration
            .aws
            .as_ref()
            .and_then(|aws| aws.vpc_id.clone()),
        aws_asg_name: cfg
            .operator
            .integration
            .aws
            .as_ref()
            .and_then(|aws| aws.asg_name.clone()),
        gcp_project: cfg
            .operator
            .integration
            .gcp
            .as_ref()
            .and_then(|gcp| gcp.project.clone()),
        gcp_region: cfg
            .operator
            .integration
            .gcp
            .as_ref()
            .and_then(|gcp| gcp.region.clone()),
        gcp_ig_name: cfg
            .operator
            .integration
            .gcp
            .as_ref()
            .and_then(|gcp| gcp.ig_name.clone()),
    })
}

pub fn build_dataplane_runtime_network_config(cfg: &CliConfig) -> DataplaneRuntimeNetworkConfig {
    let (internal_net, internal_prefix) = cfg.internal_cidr.unwrap_or((Ipv4Addr::UNSPECIFIED, 32));
    let public_ip = match cfg.snat_mode {
        SnatMode::Static(ip) => ip,
        SnatMode::None | SnatMode::Auto => Ipv4Addr::UNSPECIFIED,
    };
    let overlay = OverlayConfig {
        mode: cfg.encap_mode,
        udp_port: cfg.encap_udp_port.unwrap_or(0),
        udp_port_internal: cfg.encap_udp_port_internal,
        udp_port_external: cfg.encap_udp_port_external,
        vni: cfg.encap_vni,
        vni_internal: cfg.encap_vni_internal,
        vni_external: cfg.encap_vni_external,
        mtu: cfg.encap_mtu,
    };

    DataplaneRuntimeNetworkConfig {
        internal_net,
        internal_prefix,
        public_ip,
        overlay,
        // The runtime currently exposes a single dataplane egress path.
        data_port: DEFAULT_DATAPLANE_PORT,
    }
}

pub async fn maybe_select_cluster_seed(
    cfg: &mut CliConfig,
    integration_provider: Option<Arc<dyn CloudProviderTrait>>,
) {
    if cfg.integration_mode != IntegrationMode::None
        && cfg.cluster.enabled
        && cfg.cluster.join_seed.is_none()
    {
        if let Some(provider) = integration_provider {
            let filter = integration_tag_filter(cfg);
            match select_integration_seed(provider, &filter, cfg.cluster.bind_addr.port()).await {
                Ok(seed) => {
                    if let Some(seed) = seed {
                        cfg.cluster.join_seed = Some(seed);
                    }
                }
                Err(err) => {
                    warn!(error = %err, "integration seed selection failed");
                }
            }
        }
    }
}

pub fn log_startup_summary(cfg: &DerivedRuntimeConfig) {
    info!(
        management_iface = %cfg.operator.bootstrap.management_interface,
        data_plane_iface = %cfg.operator.bootstrap.data_interface,
        data_plane_mode = %cfg.operator.bootstrap.data_plane_mode,
        idle_timeout_secs = cfg.operator.dataplane.idle_timeout_secs,
        dns_allowlist_idle_secs = cfg.operator.dataplane.dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs = cfg.operator.dataplane.dns_allowlist_gc_interval_secs,
        default_policy = ?cfg.operator.policy.default,
        dns_targets = ?cfg.operator.dns.target_ips,
        dns_upstreams = ?cfg.operator.dns.upstreams,
        dns_upstream_timeout_ms = cfg.operator.dns.upstream_timeout_ms,
        cloud_provider = %cfg.operator.bootstrap.cloud_provider,
        "neuwerk startup configuration"
    );
    if cfg.operator.cluster.enabled {
        info!(
            cluster_bind = %cfg.operator.cluster.bind,
            cluster_join_bind = %cfg.operator.cluster.join_bind,
            cluster_advertise = %cfg.operator.cluster.advertise,
            cluster_join_seed = ?cfg.operator.cluster.join_seed,
            "cluster startup configuration"
        );
    }
    if cfg.operator.integration.mode != RuntimeIntegrationMode::None {
        info!(
            integration_mode = ?cfg.operator.integration.mode,
            integration_route_name = %cfg.operator.integration.route_name,
            integration_drain_timeout_secs = cfg.operator.integration.drain_timeout_secs,
            integration_reconcile_interval_secs = cfg.operator.integration.reconcile_interval_secs,
            integration_cluster_name = %cfg.operator.integration.cluster_name,
            "integration startup configuration"
        );
    }
    info!(snat_mode = ?cfg.operator.dataplane.snat, "snat configuration");
    if cfg.operator.dataplane.encap_mode != "none" {
        info!(
            encap_mode = %cfg.operator.dataplane.encap_mode,
            encap_vni = ?cfg.operator.dataplane.encap_vni,
            encap_vni_internal = ?cfg.operator.dataplane.encap_vni_internal,
            encap_vni_external = ?cfg.operator.dataplane.encap_vni_external,
            encap_udp_port = ?cfg.operator.dataplane.encap_udp_port,
            encap_udp_port_internal = ?cfg.operator.dataplane.encap_udp_port_internal,
            encap_udp_port_external = ?cfg.operator.dataplane.encap_udp_port_external,
            encap_mtu = cfg.operator.dataplane.encap_mtu,
            "overlay encapsulation configuration"
        );
    }
    if let Some((net, prefix)) = cfg.operator.policy.internal_cidr {
        info!(internal_cidr = %format!("{net}/{prefix}"), "internal network configuration");
    }
}

pub fn resolve_runtime_bindings_for_management_ip(
    cfg: &DerivedRuntimeConfig,
    management_ip: Ipv4Addr,
) -> Bindings {
    let http_bind = cfg
        .operator
        .http
        .bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(management_ip), 8443));
    let http_advertise = cfg.operator.http.advertise.unwrap_or(http_bind);
    let mut metrics_bind = match cfg.runtime.metrics_bind {
        MetricsBindResolution::Explicit(bind) => bind,
        MetricsBindResolution::FromManagementInterface { port } => {
            SocketAddr::new(IpAddr::V4(management_ip), port)
        }
    };
    if cfg.runtime.dpdk_enabled
        && cfg.operator.bootstrap.cloud_provider == "azure"
        && metrics_bind.ip().is_unspecified()
    {
        let old_bind = metrics_bind;
        metrics_bind = SocketAddr::new(IpAddr::V4(management_ip), old_bind.port());
        warn!(
            old_bind = %old_bind,
            new_bind = %metrics_bind,
            "azure dpdk metrics bind override applied to avoid dataplane probe listener races"
        );
    }
    Bindings {
        management_ip,
        http_bind,
        http_advertise,
        metrics_bind,
    }
}

pub async fn resolve_bindings(cfg: &DerivedRuntimeConfig) -> Result<Bindings, String> {
    let management_ip = management_ipv4(&cfg.operator.bootstrap.management_interface).await?;
    Ok(resolve_runtime_bindings_for_management_ip(
        cfg,
        management_ip,
    ))
}

pub async fn start_cluster_runtime(
    cfg: &CliConfig,
    wiretap_hub: Option<WiretapHub>,
    metrics: Metrics,
) -> Result<Option<ClusterRuntime>, String> {
    neuwerk::controlplane::cluster::run_cluster_tasks(
        cfg.cluster.clone(),
        wiretap_hub,
        Some(metrics),
    )
    .await
    .map_err(|err| err.to_string())
}

pub async fn run_cluster_migration_if_requested(
    cfg: &CliConfig,
    cluster_runtime: Option<&ClusterRuntime>,
    local_policy_store: PolicyDiskStore,
    local_service_accounts_dir: PathBuf,
    node_id: Uuid,
) -> Result<(), String> {
    if !cfg.cluster_migrate_from_local && !cfg.cluster_migrate_verify {
        return Ok(());
    }
    if !cfg.cluster.enabled {
        return Err("cluster migration requested but cluster mode is disabled".to_string());
    }
    if cfg.cluster.join_seed.is_some() {
        return Err(
            "cluster migration requested but --join is set; run migration only on the seed node"
                .to_string(),
        );
    }
    let Some(runtime) = cluster_runtime else {
        return Err("cluster migration requested but cluster runtime is unavailable".to_string());
    };
    let migrate_cfg = migration::MigrationConfig {
        enabled: cfg.cluster_migrate_from_local,
        force: cfg.cluster_migrate_force,
        verify: cfg.cluster_migrate_verify,
        http_tls_dir: cfg.http_tls_dir.clone(),
        local_policy_store,
        local_service_accounts_dir,
        cluster_data_dir: cfg.cluster.data_dir.clone(),
        token_path: cfg.cluster.token_path.clone(),
        node_id,
    };
    match migration::run(&runtime.raft, &runtime.store, migrate_cfg).await {
        Ok(report) => {
            if report.migrated {
                info!(
                    policies_seeded = report.policies_seeded,
                    service_accounts_seeded = report.service_accounts_seeded,
                    tokens_seeded = report.tokens_seeded,
                    api_keyset_source = %report
                        .api_keyset_source
                        .unwrap_or_else(|| "unknown".to_string()),
                    "cluster migration complete"
                );
            } else if let Some(reason) = report.skipped_reason {
                info!(reason = %reason, "cluster migration skipped");
            }
            Ok(())
        }
        Err(err) => Err(format!("cluster migration failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use crate::runtime::config::{derive_runtime_config, load_config_str};

    use super::{load_runtime_config, resolve_runtime_bindings_for_management_ip};

    fn parse_test_config(raw: &str) -> crate::runtime::config::DerivedRuntimeConfig {
        derive_runtime_config(load_config_str(raw).unwrap()).unwrap()
    }

    #[test]
    fn startup_loads_runtime_config_from_yaml_fixture_path() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        fs::write(
            tmp.path(),
            r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 1.1.1.1:53
"#,
        )
        .expect("write fixture");

        let cfg = load_runtime_config(tmp.path()).expect("startup config should load");
        assert_eq!(cfg.operator.bootstrap.management_interface, "eth0");
        assert_eq!(
            cfg.operator.dns.target_ips,
            vec![Ipv4Addr::new(10, 0, 0, 53)]
        );
    }

    #[test]
    fn startup_reports_missing_runtime_config_file() {
        let missing = std::env::temp_dir().join(format!(
            "neuwerk-missing-config-{}-{}.yaml",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let err = load_runtime_config(&missing).expect_err("missing file must fail");
        assert!(err.contains("config read error"), "{err}");
    }

    #[test]
    fn runtime_bindings_prefer_explicit_yaml_addresses() {
        let cfg = parse_test_config(
            r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 1.1.1.1:53
http:
  bind: 127.0.0.1:8443
  advertise: 10.0.0.2:8443
metrics:
  bind: 127.0.0.1:8080
"#,
        );

        let bindings =
            resolve_runtime_bindings_for_management_ip(&cfg, Ipv4Addr::new(192, 0, 2, 10));

        assert_eq!(
            bindings.http_bind,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
        );
        assert_eq!(
            bindings.http_advertise,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8443)
        );
        assert_eq!(
            bindings.metrics_bind,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn runtime_bindings_default_to_management_ip_when_yaml_omits_bindings() {
        let cfg = parse_test_config(
            r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 1.1.1.1:53
"#,
        );

        let bindings =
            resolve_runtime_bindings_for_management_ip(&cfg, Ipv4Addr::new(192, 0, 2, 20));

        assert_eq!(
            bindings.http_bind,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 8443)
        );
        assert_eq!(bindings.http_advertise, bindings.http_bind);
        assert_eq!(
            bindings.metrics_bind,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)), 8080)
        );
    }
}
