#![allow(dead_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use firewall::controlplane::cluster::config::ClusterConfig;
use tempfile::TempDir;

pub fn next_addr(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

pub fn next_local_addr() -> SocketAddr {
    next_addr(Ipv4Addr::new(127, 0, 0, 1))
}

pub fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn write_token_file(path: &Path) {
    let json = serde_json::json!({
        "tokens": [
            {
                "kid": "test",
                "token": "b64:dGVzdC1zZWNyZXQ=",
                "valid_until": "2027-01-01T00:00:00Z"
            }
        ]
    });
    fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

pub fn base_config(data_dir: &TempDir, token_path: &Path) -> ClusterConfig {
    let mut cfg = ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.data_dir = data_dir.path().to_path_buf();
    cfg.token_path = token_path.to_path_buf();
    cfg.node_id_path = data_dir.path().join("node_id");
    cfg
}
