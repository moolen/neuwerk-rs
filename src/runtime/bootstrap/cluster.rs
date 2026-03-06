use std::net::SocketAddr;
use std::path::PathBuf;

pub fn build_cluster_config(
    bind: Option<SocketAddr>,
    join_bind: Option<SocketAddr>,
    advertise: Option<SocketAddr>,
    join: Option<SocketAddr>,
    data_dir: Option<PathBuf>,
    node_id_path: Option<PathBuf>,
    token_path: Option<PathBuf>,
) -> Result<crate::controlplane::cluster::config::ClusterConfig, String> {
    let enabled = bind.is_some()
        || join_bind.is_some()
        || advertise.is_some()
        || join.is_some()
        || data_dir.is_some()
        || node_id_path.is_some()
        || token_path.is_some();

    if !enabled {
        return Ok(crate::controlplane::cluster::config::ClusterConfig::disabled());
    }

    let mut cfg = crate::controlplane::cluster::config::ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.bind_addr = bind.unwrap_or(cfg.bind_addr);
    cfg.join_bind_addr = join_bind
        .unwrap_or_else(|| crate::controlplane::cluster::config::default_join_bind(cfg.bind_addr));
    cfg.advertise_addr = advertise.unwrap_or(cfg.bind_addr);
    cfg.join_seed = join;
    cfg.data_dir = data_dir.unwrap_or(cfg.data_dir);
    cfg.node_id_path = node_id_path.unwrap_or(cfg.node_id_path);
    cfg.token_path = token_path.unwrap_or(cfg.token_path);
    Ok(cfg)
}
