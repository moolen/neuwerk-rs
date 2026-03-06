use std::time::{Duration, Instant};

use openraft::error::NetworkError;
use openraft::error::RPCError;
use openraft::error::RaftError;
use openraft::error::Unreachable;
use openraft::network::RPCOption;
use openraft::network::RaftNetwork;
use openraft::network::RaftNetworkFactory;
use openraft::raft::AppendEntriesRequest;
use openraft::raft::AppendEntriesResponse;
use openraft::raft::InstallSnapshotRequest;
use openraft::raft::InstallSnapshotResponse;
use openraft::raft::VoteRequest;
use openraft::raft::VoteResponse;
use openraft::RaftTypeConfig;
use tokio::time::timeout;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

use crate::controlplane::cluster::types::{ClusterTypeConfig, Node, NodeId};
use crate::controlplane::metrics::Metrics;

use super::{proto, RaftTlsConfig};

#[derive(Clone)]
pub struct RaftGrpcNetwork {
    peer_id: String,
    _addr: String,
    client: proto::raft_service_client::RaftServiceClient<Channel>,
    metrics: Option<Metrics>,
}

#[derive(Clone)]
pub struct RaftGrpcNetworkFactory {
    tls: RaftTlsConfig,
    metrics: Option<Metrics>,
}

impl RaftGrpcNetworkFactory {
    pub fn new(tls: RaftTlsConfig, metrics: Option<Metrics>) -> Self {
        Self { tls, metrics }
    }
}

impl RaftNetworkFactory<ClusterTypeConfig> for RaftGrpcNetworkFactory {
    type Network = RaftGrpcNetwork;

    async fn new_client(
        &mut self,
        target: <ClusterTypeConfig as RaftTypeConfig>::NodeId,
        node: &Node,
    ) -> Self::Network {
        let addr = node.addr.clone();
        let endpoint = match raft_client_endpoint(&addr, &self.tls) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                eprintln!(
                    "cluster rpc: failed to build raft endpoint for peer {} ({addr}): {err}; using unreachable fallback",
                    target
                );
                unreachable_fallback_endpoint()
            }
        };
        let channel = endpoint.connect_lazy();
        let client = proto::raft_service_client::RaftServiceClient::new(channel);
        RaftGrpcNetwork {
            peer_id: target.to_string(),
            _addr: addr,
            client,
            metrics: self.metrics.clone(),
        }
    }
}

pub(super) fn raft_client_endpoint(addr: &str, tls: &RaftTlsConfig) -> Result<Endpoint, String> {
    Endpoint::from_shared(format!("https://{addr}"))
        .map_err(|err| format!("invalid raft endpoint: {err}"))?
        .connect_timeout(Duration::from_secs(3))
        .tls_config(tls.client_config())
        .map_err(|err| format!("raft tls config failed: {err}"))
}

fn unreachable_fallback_endpoint() -> Endpoint {
    Endpoint::from_static("http://127.0.0.1:1").connect_timeout(Duration::from_secs(1))
}

impl RaftNetwork<ClusterTypeConfig> for RaftGrpcNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ClusterTypeConfig>,
        option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        RPCError<
            <ClusterTypeConfig as RaftTypeConfig>::NodeId,
            Node,
            RaftError<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        >,
    > {
        let start = Instant::now();
        let payload = encode_rpc(&rpc)?;
        let req = proto::RaftRequest { payload };
        let resp = timeout(option.hard_ttl(), self.client.append_entries(req)).await;
        let elapsed = start.elapsed();
        match resp {
            Err(_) => {
                self.observe_peer_rtt("append_entries", elapsed);
                self.observe_peer_error("append_entries", "timeout");
                Err(RPCError::Unreachable(Unreachable::new(
                    &std::io::Error::new(std::io::ErrorKind::TimedOut, "append_entries timeout"),
                )))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("append_entries", elapsed);
                    self.observe_peer_error("append_entries", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded = decode::<
                    AppendEntriesResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
                >(&resp.payload)
                .map_err(|err| {
                    self.observe_peer_rtt("append_entries", elapsed);
                    self.observe_peer_error("append_entries", "other");
                    RPCError::Network(NetworkError::new(&std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err,
                    )))
                })?;
                self.observe_peer_rtt("append_entries", elapsed);
                Ok(decoded)
            }
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ClusterTypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        RPCError<
            <ClusterTypeConfig as RaftTypeConfig>::NodeId,
            Node,
            RaftError<
                <ClusterTypeConfig as RaftTypeConfig>::NodeId,
                openraft::error::InstallSnapshotError,
            >,
        >,
    > {
        let start = Instant::now();
        let payload = encode_rpc(&rpc)?;
        let req = proto::RaftRequest { payload };
        let resp = timeout(option.hard_ttl(), self.client.install_snapshot(req)).await;
        let elapsed = start.elapsed();
        match resp {
            Err(_) => {
                self.observe_peer_rtt("install_snapshot", elapsed);
                self.observe_peer_error("install_snapshot", "timeout");
                Err(RPCError::Unreachable(Unreachable::new(
                    &std::io::Error::new(std::io::ErrorKind::TimedOut, "install_snapshot timeout"),
                )))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("install_snapshot", elapsed);
                    self.observe_peer_error("install_snapshot", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded = decode::<
                    InstallSnapshotResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
                >(&resp.payload)
                .map_err(|err| {
                    self.observe_peer_rtt("install_snapshot", elapsed);
                    self.observe_peer_error("install_snapshot", "other");
                    RPCError::Network(NetworkError::new(&std::io::Error::new(
                        std::io::ErrorKind::Other,
                        err,
                    )))
                })?;
                self.observe_peer_rtt("install_snapshot", elapsed);
                Ok(decoded)
            }
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        option: RPCOption,
    ) -> Result<
        VoteResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        RPCError<
            <ClusterTypeConfig as RaftTypeConfig>::NodeId,
            Node,
            RaftError<<ClusterTypeConfig as RaftTypeConfig>::NodeId>,
        >,
    > {
        let start = Instant::now();
        let payload = encode_rpc(&rpc)?;
        let req = proto::RaftRequest { payload };
        let resp = timeout(option.hard_ttl(), self.client.vote(req)).await;
        let elapsed = start.elapsed();
        match resp {
            Err(_) => {
                self.observe_peer_rtt("vote", elapsed);
                self.observe_peer_error("vote", "timeout");
                Err(RPCError::Unreachable(Unreachable::new(
                    &std::io::Error::new(std::io::ErrorKind::TimedOut, "vote timeout"),
                )))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("vote", elapsed);
                    self.observe_peer_error("vote", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded =
                    decode::<VoteResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>>(
                        &resp.payload,
                    )
                    .map_err(|err| {
                        self.observe_peer_rtt("vote", elapsed);
                        self.observe_peer_error("vote", "other");
                        RPCError::Network(NetworkError::new(&std::io::Error::new(
                            std::io::ErrorKind::Other,
                            err,
                        )))
                    })?;
                self.observe_peer_rtt("vote", elapsed);
                Ok(decoded)
            }
        }
    }
}

impl RaftGrpcNetwork {
    fn observe_peer_rtt(&self, rpc: &str, duration: Duration) {
        if let Some(metrics) = &self.metrics {
            metrics.observe_raft_peer_rtt(self.peer_id.as_str(), rpc, duration);
        }
    }

    fn observe_peer_error(&self, rpc: &str, kind: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.inc_raft_peer_error(self.peer_id.as_str(), rpc, kind);
        }
    }
}

pub struct RaftServer {
    raft: openraft::Raft<ClusterTypeConfig>,
}

impl RaftServer {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>) -> Self {
        Self { raft }
    }
}

#[tonic::async_trait]
impl proto::raft_service_server::RaftService for RaftServer {
    async fn append_entries(
        &self,
        request: Request<proto::RaftRequest>,
    ) -> Result<Response<proto::RaftResponse>, Status> {
        let payload =
            decode::<AppendEntriesRequest<ClusterTypeConfig>>(&request.into_inner().payload)
                .map_err(|err| Status::invalid_argument(err))?;
        let resp = self
            .raft
            .append_entries(payload)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let encoded = encode(&resp).map_err(|err| Status::internal(err))?;
        Ok(Response::new(proto::RaftResponse { payload: encoded }))
    }

    async fn vote(
        &self,
        request: Request<proto::RaftRequest>,
    ) -> Result<Response<proto::RaftResponse>, Status> {
        let payload = decode::<VoteRequest<<ClusterTypeConfig as RaftTypeConfig>::NodeId>>(
            &request.into_inner().payload,
        )
        .map_err(|err| Status::invalid_argument(err))?;
        let resp = self
            .raft
            .vote(payload)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let encoded = encode(&resp).map_err(|err| Status::internal(err))?;
        Ok(Response::new(proto::RaftResponse { payload: encoded }))
    }

    async fn install_snapshot(
        &self,
        request: Request<proto::RaftRequest>,
    ) -> Result<Response<proto::RaftResponse>, Status> {
        let payload =
            decode::<InstallSnapshotRequest<ClusterTypeConfig>>(&request.into_inner().payload)
                .map_err(|err| Status::invalid_argument(err))?;
        let resp = self
            .raft
            .install_snapshot(payload)
            .await
            .map_err(|err| Status::internal(err.to_string()))?;
        let encoded = encode(&resp).map_err(|err| Status::internal(err))?;
        Ok(Response::new(proto::RaftResponse { payload: encoded }))
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bincode::serialize(value).map_err(|err| err.to_string())
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    bincode::deserialize(bytes).map_err(|err| err.to_string())
}

fn encode_rpc<T: serde::Serialize, E>(value: &T) -> Result<Vec<u8>, RPCError<NodeId, Node, E>>
where
    E: std::error::Error,
{
    bincode::serialize(value).map_err(|err| {
        RPCError::Network(NetworkError::new(&std::io::Error::new(
            std::io::ErrorKind::Other,
            err.to_string(),
        )))
    })
}
