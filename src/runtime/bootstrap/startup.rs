use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use firewall::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use firewall::controlplane::cloud::types::IntegrationMode;
use firewall::controlplane::cluster::migration;
use firewall::controlplane::cluster::ClusterRuntime;
use firewall::controlplane::metrics::Metrics;
use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::wiretap::WiretapHub;
use firewall::dataplane::EncapMode;
use uuid::Uuid;

use crate::runtime::bootstrap::integration::{integration_tag_filter, select_integration_seed};
use crate::runtime::bootstrap::network::management_ipv4;
use crate::runtime::cli::CliConfig;
use crate::runtime::cli::CloudProviderKind;

#[derive(Debug, Clone, Copy)]
pub struct Bindings {
    pub management_ip: Ipv4Addr,
    pub http_bind: SocketAddr,
    pub http_advertise: SocketAddr,
    pub metrics_bind: SocketAddr,
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
                    tracing::warn!(error = %err, "integration seed selection failed");
                }
            }
        }
    }
}

pub fn log_startup_summary(cfg: &CliConfig) {
    tracing::info!(
        management_iface = %cfg.management_iface,
        data_plane_iface = %cfg.data_plane_iface,
        data_plane_mode = ?cfg.data_plane_mode,
        idle_timeout_secs = cfg.idle_timeout_secs,
        dns_allowlist_idle_secs = cfg.dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs = cfg.dns_allowlist_gc_interval_secs,
        default_policy = ?cfg.default_policy,
        dns_targets = ?cfg.dns_target_ips,
        dns_upstreams = ?cfg.dns_upstreams,
        cloud_provider = ?cfg.cloud_provider,
        "firewall startup configuration"
    );
    if cfg.cluster.enabled {
        tracing::info!(
            cluster_bind = %cfg.cluster.bind_addr,
            cluster_join_bind = %cfg.cluster.join_bind_addr,
            cluster_advertise = %cfg.cluster.advertise_addr,
            cluster_join_seed = ?cfg.cluster.join_seed,
            "cluster startup configuration"
        );
    }
    if cfg.integration_mode != IntegrationMode::None {
        tracing::info!(
            integration_mode = ?cfg.integration_mode,
            integration_route_name = %cfg.integration_route_name,
            integration_drain_timeout_secs = cfg.integration_drain_timeout_secs,
            integration_reconcile_interval_secs = cfg.integration_reconcile_interval_secs,
            integration_cluster_name = %cfg.integration_cluster_name,
            "integration startup configuration"
        );
    }
    tracing::info!(snat_mode = ?cfg.snat_mode, "snat configuration");
    if cfg.encap_mode != EncapMode::None {
        tracing::info!(
            encap_mode = ?cfg.encap_mode,
            encap_vni = ?cfg.encap_vni,
            encap_vni_internal = ?cfg.encap_vni_internal,
            encap_vni_external = ?cfg.encap_vni_external,
            encap_udp_port = ?cfg.encap_udp_port,
            encap_udp_port_internal = ?cfg.encap_udp_port_internal,
            encap_udp_port_external = ?cfg.encap_udp_port_external,
            encap_mtu = cfg.encap_mtu,
            "overlay encapsulation configuration"
        );
    }
    if let Some((net, prefix)) = cfg.internal_cidr {
        tracing::info!(
            internal_cidr = %format!("{net}/{prefix}"),
            "internal network configuration"
        );
    }
}

pub async fn resolve_bindings(cfg: &CliConfig, dpdk_enabled: bool) -> Result<Bindings, String> {
    let management_ip = management_ipv4(&cfg.management_iface).await?;
    let http_bind = cfg
        .http_bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(management_ip), 8443));
    let http_advertise = cfg.http_advertise.unwrap_or(http_bind);
    let mut metrics_bind = cfg
        .metrics_bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(management_ip), 8080));
    if dpdk_enabled
        && cfg.cloud_provider == CloudProviderKind::Azure
        && metrics_bind.ip().is_unspecified()
    {
        let old_bind = metrics_bind;
        metrics_bind = SocketAddr::new(IpAddr::V4(management_ip), old_bind.port());
        tracing::warn!(
            old_bind = %old_bind,
            new_bind = %metrics_bind,
            "azure dpdk metrics bind override applied to avoid dataplane probe listener races"
        );
    }
    Ok(Bindings {
        management_ip,
        http_bind,
        http_advertise,
        metrics_bind,
    })
}

pub async fn start_cluster_runtime(
    cfg: &CliConfig,
    wiretap_hub: Option<WiretapHub>,
    metrics: Metrics,
) -> Result<Option<ClusterRuntime>, String> {
    firewall::controlplane::cluster::run_cluster_tasks(
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
                tracing::info!(
                    policies_seeded = report.policies_seeded,
                    service_accounts_seeded = report.service_accounts_seeded,
                    tokens_seeded = report.tokens_seeded,
                    api_keyset_source = %report
                        .api_keyset_source
                        .unwrap_or_else(|| "unknown".to_string()),
                    "cluster migration complete"
                );
            } else if let Some(reason) = report.skipped_reason {
                tracing::info!(reason = %reason, "cluster migration skipped");
            }
            Ok(())
        }
        Err(err) => Err(format!("cluster migration failed: {err}")),
    }
}
