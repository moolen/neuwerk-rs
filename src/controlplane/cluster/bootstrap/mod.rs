pub mod ca;
pub mod join;
pub mod token;

use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hmac::{Hmac, Mac};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, IsCa, SanType};
use sha2::Sha256;
use tokio::time::sleep;
use uuid::Uuid;

use tokio::sync::Mutex;

use crate::controlplane::api_auth;
use crate::controlplane::cluster::auth_admin::AuthService;
use crate::controlplane::cluster::bootstrap::ca::CaSigner;
use crate::controlplane::cluster::bootstrap::join::JoinService;
use crate::controlplane::cluster::config::{ClusterConfig, RetryConfig};
use crate::controlplane::cluster::integration_admin::IntegrationService;
use crate::controlplane::cluster::policy_admin::PolicyService;
use crate::controlplane::cluster::rpc::{
    AuthServer, IntegrationServer, JoinClient, JoinServer, PolicyServer, RaftGrpcNetworkFactory,
    RaftServer, RaftTlsConfig, WiretapServer,
};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::JoinRequest;
use crate::controlplane::cluster::types::JoinResponse;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig, Node};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::wiretap::{WiretapGrpcService, WiretapHub};

use std::sync::Arc;
use tonic::transport::Server;

pub async fn run_cluster(
    cfg: ClusterConfig,
    wiretap_hub: Option<WiretapHub>,
    metrics: Option<Metrics>,
) -> io::Result<crate::controlplane::cluster::ClusterRuntime> {
    ensure_rustls_provider();
    let node_id = load_or_create_node_id(&cfg.node_id_path)?;
    let raft_node_id = node_id.as_u128();
    fs::create_dir_all(&cfg.data_dir)?;
    let tls_dir = cfg.data_dir.join("tls");

    let signer: Arc<Mutex<Option<CaSigner>>> = Arc::new(Mutex::new(None));

    if cfg.join_seed.is_none() && !tls_material_exists(&tls_dir) {
        let ca_signer =
            build_ca_signer().map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let (csr, key_pem) = build_csr(cfg.advertise_addr)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let cert_pem = ca_signer
            .sign_csr(&csr)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        persist_tls_material(&cfg.data_dir, &key_pem, &cert_pem, ca_signer.cert_pem())
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let mut guard = signer.lock().await;
        *guard = Some(ca_signer);
    }

    if let Some(seed) = cfg.join_seed {
        join_cluster(
            node_id,
            seed,
            cfg.advertise_addr,
            &cfg.token_path,
            cfg.join_retry.clone(),
            &cfg.data_dir,
        )
        .await
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    }

    let store = ClusterStore::open(cfg.data_dir.join("raft"))
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let tls =
        RaftTlsConfig::load(tls_dir).map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    let raft_config = openraft::Config {
        cluster_name: "neuwerk".to_string(),
        ..Default::default()
    }
    .validate()
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
    let raft = openraft::Raft::new(
        raft_node_id,
        Arc::new(raft_config),
        RaftGrpcNetworkFactory::new(tls.clone(), metrics),
        store.clone(),
        store.clone(),
    )
    .await
    .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

    let join_handler = JoinService::new(
        raft.clone(),
        store.clone(),
        cfg.token_path.clone(),
        raft_node_id,
        signer.clone(),
        cfg.join_retry.clone(),
    );
    let raft_service = RaftServer::new(raft.clone());
    let join_service = JoinServer::new(join_handler);
    let policy_service = PolicyServer::new(PolicyService::new(raft.clone()));
    let auth_service = AuthServer::new(AuthService::new(raft.clone(), store.clone()));
    let integration_service = IntegrationServer::new(IntegrationService::new(raft.clone()));
    let wiretap_service = wiretap_hub
        .map(WiretapGrpcService::new)
        .map(WiretapServer::new);

    let bind_addr = cfg.bind_addr;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        let mut raft_shutdown = shutdown_rx.clone();
        let mut join_shutdown = shutdown_rx.clone();
        let mut raft_builder = Server::builder()
            .tls_config(tls.server_config())
            .expect("tls config")
            .add_service(crate::controlplane::cluster::rpc::proto::raft_service_server::RaftServiceServer::new(raft_service))
            .add_service(crate::controlplane::cluster::rpc::proto::policy_management_server::PolicyManagementServer::new(policy_service))
            .add_service(crate::controlplane::cluster::rpc::proto::auth_management_server::AuthManagementServer::new(auth_service))
            .add_service(crate::controlplane::cluster::rpc::proto::integration_management_server::IntegrationManagementServer::new(integration_service));
        if let Some(wiretap_service) = wiretap_service {
            raft_builder = raft_builder.add_service(
                crate::controlplane::cluster::rpc::proto::wiretap_server::WiretapServer::new(
                    wiretap_service,
                ),
            );
        }
        let raft_server = raft_builder.serve_with_shutdown(bind_addr, async {
            let _ = raft_shutdown.changed().await;
        });

        let join_server = Server::builder()
            .add_service(crate::controlplane::cluster::rpc::proto::cluster_management_server::ClusterManagementServer::new(join_service))
            .serve_with_shutdown(cfg.join_bind_addr, async {
                let _ = join_shutdown.changed().await;
            });

        let _ = tokio::join!(raft_server, join_server);
    });

    if cfg.join_seed.is_none() {
        let initialized = raft
            .is_initialized()
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        if !initialized {
            let mut nodes = std::collections::BTreeMap::new();
            nodes.insert(
                raft_node_id,
                Node {
                    addr: cfg.advertise_addr.to_string(),
                },
            );
            raft.initialize(nodes)
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
            retry_forward_to_leader(|| {
                ensure_ca(
                    raft.clone(),
                    store.clone(),
                    &cfg.token_path,
                    raft_node_id,
                    signer.clone(),
                )
            })
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            retry_forward_to_leader(|| api_auth::ensure_cluster_keyset(&raft, &store))
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        }
    }

    Ok(crate::controlplane::cluster::ClusterRuntime {
        raft,
        store,
        bind_addr: cfg.bind_addr,
        join_bind_addr: cfg.join_bind_addr,
        advertise_addr: cfg.advertise_addr,
        join_seed: cfg.join_seed,
        server_handle,
        shutdown_tx: Some(shutdown_tx),
    })
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_or_create_node_id(path: &Path) -> io::Result<Uuid> {
    if path.exists() {
        let contents = fs::read_to_string(path)?;
        let parsed = Uuid::parse_str(contents.trim()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid node id: {err}"),
            )
        })?;
        return Ok(parsed);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let node_id = Uuid::new_v4();
    fs::write(path, node_id.to_string())?;
    Ok(node_id)
}

async fn join_cluster(
    node_id: Uuid,
    seed: SocketAddr,
    advertise: SocketAddr,
    token_path: &PathBuf,
    retry: RetryConfig,
    data_dir: &Path,
) -> Result<JoinResponse, String> {
    let token_store = token::TokenStore::load(token_path).map_err(|err| err.to_string())?;
    let now = time::OffsetDateTime::now_utc();
    let current = token_store.current(now).map_err(|err| err.to_string())?;

    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match try_join(node_id, seed, advertise, current, data_dir).await {
            Ok(resp) => return Ok(resp),
            Err(err) if attempt < retry.max_attempts => {
                let delay =
                    backoff_delay(attempt, retry.base_delay, retry.max_delay, retry.jitter_ms);
                sleep(delay).await;
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

async fn try_join(
    node_id: Uuid,
    seed: SocketAddr,
    advertise: SocketAddr,
    token: &token::ParsedToken,
    data_dir: &Path,
) -> Result<JoinResponse, String> {
    let mut client = JoinClient::connect(seed).await?;
    let nonce = rand::random::<[u8; 16]>();
    let (csr, key_pem) = build_csr(advertise)?;
    let hmac = join_hmac(&token.token, node_id, advertise, &nonce, &csr);
    let req = JoinRequest {
        node_id,
        endpoint: advertise,
        csr,
        kid: token.kid.clone(),
        nonce: nonce.to_vec(),
        psk_hmac: hmac,
    };

    let resp = client.join(req).await?;
    persist_tls_material(data_dir, &key_pem, &resp.signed_cert, &resp.ca_cert)?;
    Ok(resp)
}

fn join_hmac(psk: &[u8], node_id: Uuid, endpoint: SocketAddr, nonce: &[u8], csr: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk).expect("hmac key");
    mac.update(node_id.as_bytes());
    mac.update(endpoint.to_string().as_bytes());
    mac.update(nonce);
    mac.update(csr);
    mac.finalize().into_bytes().to_vec()
}

fn backoff_delay(attempt: u32, base: Duration, max: Duration, jitter_ms: u64) -> Duration {
    let exp = 2u64.saturating_pow(attempt.saturating_sub(1));
    let mut delay = base.saturating_mul(exp as u32);
    if delay > max {
        delay = max;
    }
    let jitter = rand::random::<u64>() % (jitter_ms + 1);
    delay + Duration::from_millis(jitter)
}

fn build_csr(endpoint: SocketAddr) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut params = CertificateParams::new(Vec::new());
    params.distinguished_name = DistinguishedName::new();
    params
        .subject_alt_names
        .push(SanType::IpAddress(endpoint.ip()));
    let cert = Certificate::from_params(params).map_err(|err| err.to_string())?;
    let csr = cert
        .serialize_request_der()
        .map_err(|err| err.to_string())?;
    let key_pem = cert.serialize_private_key_pem();
    Ok((csr, key_pem.as_bytes().to_vec()))
}

fn persist_tls_material(
    data_dir: &Path,
    key_pem: &[u8],
    cert_pem: &[u8],
    ca_pem: &[u8],
) -> Result<(), String> {
    let tls_dir = data_dir.join("tls");
    fs::create_dir_all(&tls_dir).map_err(|err| err.to_string())?;
    fs::write(tls_dir.join("node.key"), key_pem).map_err(|err| err.to_string())?;
    fs::write(tls_dir.join("node.crt"), cert_pem).map_err(|err| err.to_string())?;
    fs::write(tls_dir.join("ca.crt"), ca_pem).map_err(|err| err.to_string())?;
    Ok(())
}

fn tls_material_exists(tls_dir: &Path) -> bool {
    tls_dir.join("node.key").exists()
        && tls_dir.join("node.crt").exists()
        && tls_dir.join("ca.crt").exists()
}

async fn ensure_ca(
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
    token_path: &Path,
    node_id: u128,
    signer: Arc<Mutex<Option<CaSigner>>>,
) -> Result<(), String> {
    if store.get_state_value(b"ca/cert")?.is_some() {
        return Ok(());
    }
    let token_store = token::TokenStore::load(token_path).map_err(|err| err.to_string())?;
    let now = time::OffsetDateTime::now_utc();
    let current = token_store.current(now).map_err(|err| err.to_string())?;

    let ca_signer = {
        let mut guard = signer.lock().await;
        if guard.is_none() {
            *guard = Some(build_ca_signer()?);
        }
        guard
            .take()
            .ok_or_else(|| "missing ca signer".to_string())?
    };
    let cert_pem = ca_signer.cert_pem().to_vec();
    raft.client_write(ClusterCommand::SetCaCert { pem: cert_pem })
        .await
        .map_err(|err| err.to_string())?;

    let envelope = crate::controlplane::cluster::bootstrap::ca::encrypt_ca_key(
        &current.kid,
        &current.token,
        ca_signer.key_der(),
    )
    .map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::UpsertCaEnvelope { node_id, envelope })
        .await
        .map_err(|err| err.to_string())?;
    let mut guard = signer.lock().await;
    *guard = Some(ca_signer);
    Ok(())
}

async fn retry_forward_to_leader<F, Fut, T>(mut op: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    const MAX_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_ATTEMPTS {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                let is_forward = err.contains("has to forward request")
                    || err.contains("ForwardToLeader")
                    || err.contains("forward request");
                if !is_forward || attempt + 1 == MAX_ATTEMPTS {
                    return Err(err);
                }
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err("cluster operation retry exhausted".to_string())
}

fn build_ca_signer() -> Result<CaSigner, String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    let cert = Certificate::from_params(params).map_err(|err| err.to_string())?;
    CaSigner::new(cert).map_err(|err| err.to_string())
}
