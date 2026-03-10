use std::net::SocketAddr;
use std::sync::Arc;

use firewall::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use firewall::controlplane::cloud::types::{IntegrationConfig, IntegrationMode};
use firewall::controlplane::cloud::{IntegrationManager, ReadyChecker, ReadyClient};
use firewall::controlplane::cluster::ClusterRuntime;
use firewall::controlplane::metrics::Metrics;
use firewall::dataplane::DrainControl;

use crate::runtime::bootstrap::integration::integration_tag_filter;
use crate::runtime::cli::{load_http_ca, CliConfig};

pub fn spawn_integration_manager_task(
    cfg: &CliConfig,
    integration_provider: Option<Arc<dyn CloudProviderTrait>>,
    cluster_runtime: Option<&ClusterRuntime>,
    http_advertise: SocketAddr,
    metrics: Metrics,
    drain_control: DrainControl,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    if cfg.integration_mode == IntegrationMode::None {
        return Ok(None);
    }
    let Some(provider) = integration_provider else {
        return Ok(None);
    };

    let integration_cfg = IntegrationConfig {
        cluster_name: cfg.integration_cluster_name.clone(),
        route_name: cfg.integration_route_name.clone(),
        drain_timeout_secs: cfg.integration_drain_timeout_secs,
        reconcile_interval_secs: cfg.integration_reconcile_interval_secs,
        tag_filter: integration_tag_filter(cfg),
        http_ready_port: http_advertise.port(),
        cluster_tls_dir: if cfg.cluster.enabled {
            Some(cfg.cluster.data_dir.join("tls"))
        } else {
            None
        },
    };
    let ready_client = match ReadyClient::new(http_advertise.port(), load_http_ca(cfg)) {
        Ok(client) => Arc::new(client) as Arc<dyn ReadyChecker>,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "integration ready client init failed; falling back to insecure client"
            );
            match ReadyClient::new(http_advertise.port(), None) {
                Ok(client) => Arc::new(client) as Arc<dyn ReadyChecker>,
                Err(fallback_err) => {
                    tracing::error!(
                        error = %fallback_err,
                        "integration ready client fallback init failed"
                    );
                    return Err("integration ready client init failed".to_string());
                }
            }
        }
    };
    let metrics_for_integration = metrics;
    let drain_for_integration = drain_control;
    let store_for_integration = cluster_runtime.map(|runtime| runtime.store.clone());
    let raft_for_integration = cluster_runtime.map(|runtime| runtime.raft.clone());
    let integration_mode = cfg.integration_mode;
    Ok(Some(tokio::spawn(async move {
        match IntegrationManager::new(
            integration_cfg,
            provider,
            store_for_integration,
            raft_for_integration,
            metrics_for_integration,
            drain_for_integration,
            ready_client,
        )
        .await
        {
            Ok(manager) => manager.run(integration_mode).await,
            Err(err) => tracing::warn!(error = %err, "integration manager init failed"),
        }
    })))
}
