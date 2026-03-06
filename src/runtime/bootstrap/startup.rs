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
                    eprintln!("integration seed selection failed: {err}");
                }
            }
        }
    }
}

pub fn log_startup_summary(cfg: &CliConfig) {
    println!("firewall starting");
    println!("management interface: {}", cfg.management_iface);
    println!("data plane interface: {}", cfg.data_plane_iface);
    println!("data plane mode: {:?}", cfg.data_plane_mode);
    println!("idle timeout (secs): {}", cfg.idle_timeout_secs);
    println!("dns allowlist idle (secs): {}", cfg.dns_allowlist_idle_secs);
    println!(
        "dns allowlist gc interval (secs): {}",
        cfg.dns_allowlist_gc_interval_secs
    );
    println!("default policy: {:?}", cfg.default_policy);
    println!("dns targets: {:?}", cfg.dns_target_ips);
    println!("dns upstreams: {:?}", cfg.dns_upstreams);
    println!("cloud provider: {:?}", cfg.cloud_provider);
    if cfg.cluster.enabled {
        println!("cluster bind: {}", cfg.cluster.bind_addr);
        println!("cluster join bind: {}", cfg.cluster.join_bind_addr);
        println!("cluster advertise: {}", cfg.cluster.advertise_addr);
        if let Some(seed) = cfg.cluster.join_seed {
            println!("cluster join seed: {seed}");
        }
    }
    println!("integration mode: {:?}", cfg.integration_mode);
    if cfg.integration_mode != IntegrationMode::None {
        println!("integration route name: {}", cfg.integration_route_name);
        println!(
            "integration drain timeout (secs): {}",
            cfg.integration_drain_timeout_secs
        );
        println!(
            "integration reconcile interval (secs): {}",
            cfg.integration_reconcile_interval_secs
        );
        println!("integration cluster name: {}", cfg.integration_cluster_name);
    }
    println!("snat mode: {:?}", cfg.snat_mode);
    if cfg.encap_mode != EncapMode::None {
        println!("encap mode: {:?}", cfg.encap_mode);
        if let Some(vni) = cfg.encap_vni {
            println!("encap vni: {vni}");
        }
        if let Some(vni) = cfg.encap_vni_internal {
            println!("encap vni internal: {vni}");
        }
        if let Some(vni) = cfg.encap_vni_external {
            println!("encap vni external: {vni}");
        }
        if let Some(port) = cfg.encap_udp_port {
            println!("encap udp port: {port}");
        }
        if let Some(port) = cfg.encap_udp_port_internal {
            println!("encap udp port internal: {port}");
        }
        if let Some(port) = cfg.encap_udp_port_external {
            println!("encap udp port external: {port}");
        }
        println!("encap mtu: {}", cfg.encap_mtu);
    }
    if let Some((net, prefix)) = cfg.internal_cidr {
        println!("internal cidr: {net}/{prefix}");
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
        eprintln!(
            "azure dpdk: overriding metrics bind {} -> {} to avoid dataplane probe listener races",
            old_bind, metrics_bind
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
                eprintln!(
                    "cluster migration complete: policies={}, service_accounts={}, tokens={}, api_keyset={}",
                    report.policies_seeded,
                    report.service_accounts_seeded,
                    report.tokens_seeded,
                    report
                        .api_keyset_source
                        .unwrap_or_else(|| "unknown".to_string())
                );
            } else if let Some(reason) = report.skipped_reason {
                eprintln!("cluster migration skipped: {reason}");
            }
            Ok(())
        }
        Err(err) => Err(format!("cluster migration failed: {err}")),
    }
}
