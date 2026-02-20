pub mod allowlist;
pub mod cluster;
pub mod dns_proxy;

pub use allowlist::Allowlist;

#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub dns_bind: std::net::SocketAddr,
    pub dns_upstream: std::net::SocketAddr,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            dns_bind: "0.0.0.0:53".parse().unwrap(),
            dns_upstream: "1.1.1.1:53".parse().unwrap(),
        }
    }
}
