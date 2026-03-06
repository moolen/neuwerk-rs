use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub bind_addr: SocketAddr,
    pub join_bind_addr: SocketAddr,
    pub advertise_addr: SocketAddr,
    pub join_seed: Option<SocketAddr>,
    pub data_dir: PathBuf,
    pub node_id_path: PathBuf,
    pub token_path: PathBuf,
    pub join_retry: RetryConfig,
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter_ms: u64,
}

impl RetryConfig {
    pub fn default_join() -> Self {
        Self {
            max_attempts: 8,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            jitter_ms: 250,
        }
    }
}

impl ClusterConfig {
    pub fn disabled() -> Self {
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 9600));
        let join_bind_addr = default_join_bind(bind_addr);
        Self {
            enabled: false,
            bind_addr,
            join_bind_addr,
            advertise_addr: bind_addr,
            join_seed: None,
            data_dir: PathBuf::from("/var/lib/neuwerk/cluster"),
            node_id_path: PathBuf::from("/var/lib/neuwerk/node_id"),
            token_path: PathBuf::from("/var/lib/neuwerk/bootstrap-token"),
            join_retry: RetryConfig::default_join(),
        }
    }
}

pub fn default_join_bind(bind: SocketAddr) -> SocketAddr {
    let next_port = bind.port().saturating_add(1);
    SocketAddr::new(bind.ip(), next_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_uses_expected_addresses() {
        let cfg = ClusterConfig::disabled();
        assert!(!cfg.enabled);
        assert_eq!(cfg.bind_addr, SocketAddr::from(([127, 0, 0, 1], 9600)));
        assert_eq!(cfg.join_bind_addr, SocketAddr::from(([127, 0, 0, 1], 9601)));
        assert_eq!(cfg.advertise_addr, cfg.bind_addr);
    }
}
