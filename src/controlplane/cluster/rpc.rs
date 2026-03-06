use std::pin::Pin;

use futures::Stream;
use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};
use tonic::Status;

mod management;
mod raft_transport;

pub use management::{
    AuthClient, AuthHandler, AuthServer, IntegrationClient, IntegrationHandler, IntegrationServer,
    JoinClient, JoinHandler, JoinServer, PolicyClient, PolicyHandler, PolicyServer, WiretapClient,
    WiretapHandler, WiretapServer,
};
pub use raft_transport::{RaftGrpcNetwork, RaftGrpcNetworkFactory, RaftServer};

#[derive(Clone)]
pub struct RaftTlsConfig {
    identity: Identity,
    ca_cert: Certificate,
}

impl RaftTlsConfig {
    pub fn load(tls_dir: std::path::PathBuf) -> Result<Self, String> {
        let cert = std::fs::read(tls_dir.join("node.crt"))
            .map_err(|err| format!("failed to read node cert: {err}"))?;
        let key = std::fs::read(tls_dir.join("node.key"))
            .map_err(|err| format!("failed to read node key: {err}"))?;
        let ca = std::fs::read(tls_dir.join("ca.crt"))
            .map_err(|err| format!("failed to read ca cert: {err}"))?;
        Ok(Self {
            identity: Identity::from_pem(cert, key),
            ca_cert: Certificate::from_pem(ca),
        })
    }

    pub fn server_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(self.identity.clone())
            .client_ca_root(self.ca_cert.clone())
    }

    pub fn client_config(&self) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .identity(self.identity.clone())
            .ca_certificate(self.ca_cert.clone())
    }
}

pub mod proto {
    tonic::include_proto!("firewall.cluster");
}

pub type WiretapStream =
    Pin<Box<dyn Stream<Item = Result<proto::WiretapEvent, Status>> + Send + 'static>>;

#[cfg(test)]
mod tests;
