pub mod allowlist_gc;
pub mod api_auth;
pub mod cluster;
pub mod cloud;
pub mod dhcp;
pub mod dns_proxy;
pub mod http_api;
pub mod http_tls;
pub mod metrics;
pub mod policy_config;
pub mod policy_replication;
pub mod policy_repository;
pub mod policy_store;
pub mod ready;
pub mod service_accounts;
pub mod wiretap;

pub use policy_store::PolicyStore;

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
