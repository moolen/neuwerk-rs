pub mod allowlist_gc;
pub mod api_auth;
pub mod audit;
pub mod cloud;
pub mod cluster;
pub mod dhcp;
pub mod dns_proxy;
pub mod http_api;
pub mod http_tls;
pub mod integrations;
pub mod intercept_tls;
pub mod kubernetes;
pub mod metrics;
pub mod policy_config;
pub mod policy_replication;
pub mod policy_repository;
pub mod policy_store;
pub mod policy_telemetry;
pub mod ready;
pub mod service_accounts;
pub mod sso;
pub mod threat_intel;
pub mod trafficd;
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
            dns_bind: std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, 53)),
            dns_upstream: std::net::SocketAddr::from((std::net::Ipv4Addr::new(1, 1, 1, 1), 53)),
        }
    }
}
