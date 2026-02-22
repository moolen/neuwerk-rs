use std::net::SocketAddr;

use openraft::declare_raft_types;
use std::io::Cursor;

use crate::controlplane::cluster::bootstrap::ca::CaEnvelope;

pub type NodeId = u128;
pub type Node = openraft::BasicNode;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ClusterCommand {
    Put {
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        key: Vec<u8>,
    },
    Gc {
        cutoff_unix: i64,
    },
    SetCaCert {
        pem: Vec<u8>,
    },
    UpsertCaEnvelope {
        node_id: NodeId,
        envelope: CaEnvelope,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum ClusterResponse {
    Ok,
}

declare_raft_types!(
    pub ClusterTypeConfig:
        D = ClusterCommand,
        R = ClusterResponse,
        NodeId = NodeId,
        Node = Node,
        Entry = openraft::Entry<ClusterTypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        Responder = openraft::impls::OneshotResponder<ClusterTypeConfig>,
        AsyncRuntime = openraft::TokioRuntime
);

#[derive(Debug, Clone)]
pub struct JoinRequest {
    pub node_id: uuid::Uuid,
    pub endpoint: SocketAddr,
    pub csr: Vec<u8>,
    pub kid: String,
    pub nonce: Vec<u8>,
    pub psk_hmac: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct JoinResponse {
    pub signed_cert: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

impl ClusterResponse {
    pub fn ok() -> Self {
        ClusterResponse::Ok
    }
}
