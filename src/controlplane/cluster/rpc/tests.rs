use super::*;
use crate::controlplane::cluster::types::{ClusterTypeConfig, Node};
use openraft::network::RaftNetworkFactory;
use tonic::transport::{Certificate, Identity};

#[test]
fn raft_client_endpoint_rejects_invalid_addr() {
    let tls = test_tls_config();
    let err = super::raft_transport::raft_client_endpoint("bad addr", &tls).unwrap_err();
    assert!(err.contains("invalid raft endpoint"));
}

#[tokio::test]
async fn raft_network_factory_handles_invalid_addr_without_panic() {
    let mut factory = RaftGrpcNetworkFactory::new(test_tls_config(), None);
    let node = Node {
        addr: "bad addr".to_string(),
    };
    let _network = <RaftGrpcNetworkFactory as RaftNetworkFactory<ClusterTypeConfig>>::new_client(
        &mut factory,
        1u128,
        &node,
    )
    .await;
}

fn test_tls_config() -> RaftTlsConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = cert.serialize_pem().unwrap();
    let key_pem = cert.serialize_private_key_pem();
    RaftTlsConfig {
        identity: Identity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()),
        ca_cert: Certificate::from_pem(cert_pem.as_bytes()),
    }
}
