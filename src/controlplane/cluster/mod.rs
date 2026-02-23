pub mod auth_admin;
pub mod bootstrap;
pub mod config;
pub mod integration_admin;
pub mod policy_admin;
pub mod rpc;
pub mod store;
pub mod types;

use std::io;
use std::net::SocketAddr;

use crate::controlplane::cluster::config::ClusterConfig;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::metrics::Metrics;

pub struct ClusterRuntime {
    pub raft: openraft::Raft<ClusterTypeConfig>,
    pub store: ClusterStore,
    pub bind_addr: SocketAddr,
    pub join_bind_addr: SocketAddr,
    pub advertise_addr: SocketAddr,
    pub join_seed: Option<SocketAddr>,
    server_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: Option<tokio::sync::watch::Sender<bool>>,
}

impl ClusterRuntime {
    pub async fn shutdown(self) {
        let ClusterRuntime {
            raft,
            server_handle,
            mut shutdown_tx,
            ..
        } = self;
        if let Some(tx) = shutdown_tx.take() {
            let _ = tx.send(true);
        }
        let _ = server_handle.await;
        let _ = raft.shutdown().await;
    }
}

pub async fn run_cluster_tasks(
    cfg: ClusterConfig,
    wiretap_hub: Option<crate::controlplane::wiretap::WiretapHub>,
    metrics: Option<Metrics>,
) -> io::Result<Option<ClusterRuntime>> {
    if !cfg.enabled {
        return Ok(None);
    }

    bootstrap::run_cluster(cfg, wiretap_hub, metrics)
        .await
        .map(Some)
}
