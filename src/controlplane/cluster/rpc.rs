use std::net::SocketAddr;
use std::pin::Pin;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::Stream;
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
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig,
};
use tonic::{Request, Response, Status};

use crate::controlplane::cluster::types::{
    ClusterTypeConfig, JoinRequest, JoinResponse, Node, NodeId,
};
use crate::controlplane::api_auth::{ApiKeyStatus, ApiKeySummary};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::cloud::types::TerminationEvent;

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

#[derive(Clone)]
pub struct JoinClient {
    inner: proto::cluster_management_client::ClusterManagementClient<Channel>,
}

impl JoinClient {
    pub async fn connect(addr: SocketAddr) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("http://{addr}"))
            .map_err(|err| format!("invalid join endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(3));
        let channel = endpoint
            .connect()
            .await
            .map_err(|err| format!("join connect failed: {err}"))?;
        Ok(Self {
            inner: proto::cluster_management_client::ClusterManagementClient::new(channel),
        })
    }

    pub async fn join(&mut self, req: JoinRequest) -> Result<JoinResponse, String> {
        let req = proto::JoinRequest {
            node_id: req.node_id.to_string(),
            endpoint: req.endpoint.to_string(),
            csr: req.csr,
            kid: req.kid,
            nonce: req.nonce,
            psk_hmac: req.psk_hmac,
        };
        let resp = tokio::time::timeout(Duration::from_secs(5), self.inner.join(req))
            .await
            .map_err(|_| "join rpc timed out".to_string())?
            .map_err(|err| format!("join rpc failed: {err}"))?;
        let resp = resp.into_inner();
        Ok(JoinResponse {
            signed_cert: resp.signed_cert,
            ca_cert: resp.ca_cert,
        })
    }
}

pub struct JoinServer<H> {
    handler: H,
}

impl<H> JoinServer<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
pub trait JoinHandler: Send + Sync + 'static {
    async fn handle_join(&self, req: JoinRequest) -> Result<JoinResponse, String>;
}

#[tonic::async_trait]
impl<H> proto::cluster_management_server::ClusterManagement for JoinServer<H>
where
    H: JoinHandler,
{
    async fn join(
        &self,
        request: Request<proto::JoinRequest>,
    ) -> Result<Response<proto::JoinResponse>, Status> {
        let req = request.into_inner();
        let node_id = uuid::Uuid::parse_str(&req.node_id)
            .map_err(|err| Status::invalid_argument(format!("invalid node_id: {err}")))?;
        let endpoint: SocketAddr = req
            .endpoint
            .parse()
            .map_err(|_| Status::invalid_argument("invalid endpoint"))?;
        let join_req = JoinRequest {
            node_id,
            endpoint,
            csr: req.csr,
            kid: req.kid,
            nonce: req.nonce,
            psk_hmac: req.psk_hmac,
        };
        let resp = self
            .handler
            .handle_join(join_req)
            .await
            .map_err(|err| Status::unauthenticated(err))?;
        Ok(Response::new(proto::JoinResponse {
            signed_cert: resp.signed_cert,
            ca_cert: resp.ca_cert,
        }))
    }
}

#[derive(Clone)]
pub struct PolicyClient {
    inner: proto::policy_management_client::PolicyManagementClient<Channel>,
}

impl PolicyClient {
    pub async fn connect(addr: SocketAddr, tls: RaftTlsConfig) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|err| format!("invalid policy endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(3))
            .tls_config(tls.client_config())
            .map_err(|err| format!("policy tls config failed: {err}"))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|err| format!("policy connect failed: {err}"))?;
        Ok(Self {
            inner: proto::policy_management_client::PolicyManagementClient::new(channel),
        })
    }

    pub async fn set_active_policy(&mut self, policy_yaml: Vec<u8>) -> Result<(), String> {
        let req = proto::PolicyUpdateRequest { policy_yaml };
        self.inner
            .set_active_policy(req)
            .await
            .map_err(|err| format!("policy update failed: {err}"))?;
        Ok(())
    }
}

pub struct PolicyServer<H> {
    handler: H,
}

impl<H> PolicyServer<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
pub trait PolicyHandler: Send + Sync + 'static {
    async fn set_active_policy(&self, policy_yaml: Vec<u8>) -> Result<(), String>;
}

#[tonic::async_trait]
impl<H> proto::policy_management_server::PolicyManagement for PolicyServer<H>
where
    H: PolicyHandler,
{
    async fn set_active_policy(
        &self,
        request: Request<proto::PolicyUpdateRequest>,
    ) -> Result<Response<proto::PolicyUpdateResponse>, Status> {
        let req = request.into_inner();
        self.handler
            .set_active_policy(req.policy_yaml)
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        Ok(Response::new(proto::PolicyUpdateResponse { ok: true }))
    }
}

#[derive(Clone)]
pub struct IntegrationClient {
    inner: proto::integration_management_client::IntegrationManagementClient<Channel>,
}

impl IntegrationClient {
    pub async fn connect(addr: SocketAddr, tls: RaftTlsConfig) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|err| format!("invalid integration endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(3))
            .tls_config(tls.client_config())
            .map_err(|err| format!("integration tls config failed: {err}"))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|err| format!("integration connect failed: {err}"))?;
        Ok(Self {
            inner: proto::integration_management_client::IntegrationManagementClient::new(channel),
        })
    }

    pub async fn publish_termination_event(&mut self, event: TerminationEvent) -> Result<(), String> {
        let req = proto::TerminationEventRequest {
            instance_id: event.instance_id,
            event_id: event.id,
            deadline_epoch: event.deadline_epoch,
        };
        self.inner
            .publish_termination_event(req)
            .await
            .map_err(|err| format!("integration publish failed: {err}"))?;
        Ok(())
    }

    pub async fn clear_termination_event(&mut self, instance_id: String) -> Result<(), String> {
        let req = proto::TerminationEventClearRequest { instance_id };
        self.inner
            .clear_termination_event(req)
            .await
            .map_err(|err| format!("integration clear failed: {err}"))?;
        Ok(())
    }
}

pub struct IntegrationServer<H> {
    handler: H,
}

impl<H> IntegrationServer<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
pub trait IntegrationHandler: Send + Sync + 'static {
    async fn publish_termination_event(&self, event: TerminationEvent) -> Result<(), String>;
    async fn clear_termination_event(&self, instance_id: String) -> Result<(), String>;
}

#[tonic::async_trait]
impl<H> proto::integration_management_server::IntegrationManagement for IntegrationServer<H>
where
    H: IntegrationHandler,
{
    async fn publish_termination_event(
        &self,
        request: Request<proto::TerminationEventRequest>,
    ) -> Result<Response<proto::TerminationEventResponse>, Status> {
        let req = request.into_inner();
        let event = TerminationEvent {
            id: req.event_id,
            instance_id: req.instance_id,
            deadline_epoch: req.deadline_epoch,
        };
        self.handler
            .publish_termination_event(event)
            .await
            .map_err(|err| Status::unavailable(err))?;
        Ok(Response::new(proto::TerminationEventResponse { ok: true }))
    }

    async fn clear_termination_event(
        &self,
        request: Request<proto::TerminationEventClearRequest>,
    ) -> Result<Response<proto::TerminationEventResponse>, Status> {
        let req = request.into_inner();
        self.handler
            .clear_termination_event(req.instance_id)
            .await
            .map_err(|err| Status::unavailable(err))?;
        Ok(Response::new(proto::TerminationEventResponse { ok: true }))
    }
}

#[derive(Clone)]
pub struct AuthClient {
    inner: proto::auth_management_client::AuthManagementClient<Channel>,
}

impl AuthClient {
    pub async fn connect(addr: SocketAddr, tls: RaftTlsConfig) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|err| format!("invalid auth endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(3))
            .tls_config(tls.client_config())
            .map_err(|err| format!("auth tls config failed: {err}"))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|err| format!("auth connect failed: {err}"))?;
        Ok(Self {
            inner: proto::auth_management_client::AuthManagementClient::new(channel),
        })
    }

    pub async fn list_keys(&mut self) -> Result<(String, Vec<ApiKeySummary>), String> {
        let resp = self
            .inner
            .list_keys(proto::AuthKeyListRequest {})
            .await
            .map_err(|err| format!("auth list failed: {err}"))?
            .into_inner();
        let keys = resp
            .keys
            .into_iter()
            .map(|entry| ApiKeySummary {
                kid: entry.kid,
                status: parse_status(&entry.status),
                created_at: entry.created_at,
                signing: entry.signing,
            })
            .collect();
        Ok((resp.active_kid, keys))
    }

    pub async fn rotate_key(&mut self) -> Result<ApiKeySummary, String> {
        let resp = self
            .inner
            .rotate_key(proto::AuthKeyRotateRequest {})
            .await
            .map_err(|err| format!("auth rotate failed: {err}"))?
            .into_inner();
        let key = resp.key.ok_or_else(|| "missing key in response".to_string())?;
        Ok(ApiKeySummary {
            kid: key.kid,
            status: parse_status(&key.status),
            created_at: key.created_at,
            signing: key.signing,
        })
    }

    pub async fn retire_key(&mut self, kid: &str) -> Result<(), String> {
        self.inner
            .retire_key(proto::AuthKeyRetireRequest { kid: kid.to_string() })
            .await
            .map_err(|err| format!("auth retire failed: {err}"))?;
        Ok(())
    }

    pub async fn mint_token(
        &mut self,
        sub: &str,
        ttl_secs: Option<i64>,
        kid: Option<&str>,
    ) -> Result<(String, String, i64), String> {
        let req = proto::AuthTokenMintRequest {
            sub: sub.to_string(),
            ttl_secs: ttl_secs.unwrap_or_default(),
            kid: kid.unwrap_or_default().to_string(),
        };
        let resp = self
            .inner
            .mint_token(req)
            .await
            .map_err(|err| format!("auth mint failed: {err}"))?
            .into_inner();
        Ok((resp.token, resp.kid, resp.exp))
    }
}

fn parse_status(status: &str) -> ApiKeyStatus {
    match status.to_ascii_lowercase().as_str() {
        "retired" => ApiKeyStatus::Retired,
        _ => ApiKeyStatus::Active,
    }
}

pub struct AuthServer<H> {
    handler: H,
}

impl<H> AuthServer<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
pub trait AuthHandler: Send + Sync + 'static {
    async fn list_keys(&self) -> Result<(String, Vec<ApiKeySummary>), String>;
    async fn rotate_key(&self) -> Result<ApiKeySummary, String>;
    async fn retire_key(&self, kid: String) -> Result<(), String>;
    async fn mint_token(
        &self,
        sub: String,
        ttl_secs: Option<i64>,
        kid: Option<String>,
    ) -> Result<(String, String, i64), String>;
}

#[tonic::async_trait]
impl<H> proto::auth_management_server::AuthManagement for AuthServer<H>
where
    H: AuthHandler,
{
    async fn list_keys(
        &self,
        _request: Request<proto::AuthKeyListRequest>,
    ) -> Result<Response<proto::AuthKeyListResponse>, Status> {
        let (active_kid, keys) = self
            .handler
            .list_keys()
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        let keys = keys
            .into_iter()
            .map(|key| proto::AuthKeyEntry {
                kid: key.kid,
                status: format!("{:?}", key.status).to_ascii_lowercase(),
                created_at: key.created_at,
                signing: key.signing,
            })
            .collect();
        Ok(Response::new(proto::AuthKeyListResponse {
            active_kid,
            keys,
        }))
    }

    async fn rotate_key(
        &self,
        _request: Request<proto::AuthKeyRotateRequest>,
    ) -> Result<Response<proto::AuthKeyRotateResponse>, Status> {
        let key = self
            .handler
            .rotate_key()
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        Ok(Response::new(proto::AuthKeyRotateResponse {
            key: Some(proto::AuthKeyEntry {
                kid: key.kid,
                status: format!("{:?}", key.status).to_ascii_lowercase(),
                created_at: key.created_at,
                signing: key.signing,
            }),
        }))
    }

    async fn retire_key(
        &self,
        request: Request<proto::AuthKeyRetireRequest>,
    ) -> Result<Response<proto::AuthKeyRetireResponse>, Status> {
        let req = request.into_inner();
        self.handler
            .retire_key(req.kid)
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        Ok(Response::new(proto::AuthKeyRetireResponse { ok: true }))
    }

    async fn mint_token(
        &self,
        request: Request<proto::AuthTokenMintRequest>,
    ) -> Result<Response<proto::AuthTokenMintResponse>, Status> {
        let req = request.into_inner();
        let kid = if req.kid.is_empty() {
            None
        } else {
            Some(req.kid)
        };
        let ttl = if req.ttl_secs <= 0 {
            None
        } else {
            Some(req.ttl_secs)
        };
        let (token, kid, exp) = self
            .handler
            .mint_token(req.sub, ttl, kid)
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        Ok(Response::new(proto::AuthTokenMintResponse { token, kid, exp }))
    }
}

#[derive(Clone)]
pub struct WiretapClient {
    inner: proto::wiretap_client::WiretapClient<Channel>,
}

impl WiretapClient {
    pub async fn connect(addr: SocketAddr, tls: RaftTlsConfig) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("https://{addr}"))
            .map_err(|err| format!("invalid wiretap endpoint: {err}"))?
            .connect_timeout(Duration::from_secs(3))
            .tls_config(tls.client_config())
            .map_err(|err| format!("wiretap tls config failed: {err}"))?;
        let channel = endpoint
            .connect()
            .await
            .map_err(|err| format!("wiretap connect failed: {err}"))?;
        Ok(Self {
            inner: proto::wiretap_client::WiretapClient::new(channel),
        })
    }

    pub async fn subscribe(
        &mut self,
        req: proto::WiretapSubscribeRequest,
    ) -> Result<tonic::Streaming<proto::WiretapEvent>, String> {
        let resp = self
            .inner
            .subscribe(req)
            .await
            .map_err(|err| format!("wiretap subscribe failed: {err}"))?;
        Ok(resp.into_inner())
    }
}

pub struct WiretapServer<H> {
    handler: H,
}

impl<H> WiretapServer<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
pub trait WiretapHandler: Send + Sync + 'static {
    async fn subscribe(&self, req: proto::WiretapSubscribeRequest) -> Result<WiretapStream, String>;
}

#[tonic::async_trait]
impl<H> proto::wiretap_server::Wiretap for WiretapServer<H>
where
    H: WiretapHandler,
{
    type SubscribeStream = WiretapStream;

    async fn subscribe(
        &self,
        request: Request<proto::WiretapSubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let req = request.into_inner();
        let stream = self
            .handler
            .subscribe(req)
            .await
            .map_err(|err| Status::invalid_argument(err))?;
        Ok(Response::new(stream))
    }
}

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
        let endpoint = Endpoint::from_shared(format!("https://{}", addr))
            .expect("valid endpoint")
            .connect_timeout(Duration::from_secs(3))
            .tls_config(self.tls.client_config())
            .expect("tls config");
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
                Err(RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "append_entries timeout",
                ))))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("append_entries", elapsed);
                    self.observe_peer_error("append_entries", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded = decode::<AppendEntriesResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>>(
                    &resp.payload,
                )
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
                Err(RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "install_snapshot timeout",
                ))))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("install_snapshot", elapsed);
                    self.observe_peer_error("install_snapshot", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded = decode::<InstallSnapshotResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>>(
                    &resp.payload,
                )
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
                Err(RPCError::Unreachable(Unreachable::new(&std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "vote timeout",
                ))))
            }
            Ok(resp) => {
                let resp = resp.map_err(|err| {
                    self.observe_peer_rtt("vote", elapsed);
                    self.observe_peer_error("vote", "transport");
                    RPCError::Network(NetworkError::new(&err))
                })?;
                let resp = resp.into_inner();
                let decoded = decode::<VoteResponse<<ClusterTypeConfig as RaftTypeConfig>::NodeId>>(&resp.payload)
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
