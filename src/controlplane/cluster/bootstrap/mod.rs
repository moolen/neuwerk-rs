mod auth;
pub mod ca;
pub mod join;
pub mod token;

use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, IsCa, SanType};
use tokio::time::sleep;
use uuid::Uuid;

use tokio::sync::Mutex;

use crate::controlplane::api_auth;
use crate::controlplane::cluster::auth_admin::AuthService;
use crate::controlplane::cluster::bootstrap::auth::{
    build_join_request_hmac, decrypt_join_response_payload, verify_join_response_hmac,
};
use crate::controlplane::cluster::bootstrap::ca::CaSigner;
use crate::controlplane::cluster::bootstrap::join::JoinService;
use crate::controlplane::cluster::config::{ClusterConfig, RetryConfig};
use crate::controlplane::cluster::integration_admin::IntegrationService;
use crate::controlplane::cluster::policy_admin::PolicyService;
use crate::controlplane::cluster::rpc::{
    AuthServer, IntegrationServer, JoinClient, JoinServer, PolicyServer, RaftGrpcNetworkFactory,
    RaftServer, RaftTlsConfig, WiretapServer, RAFT_GRPC_MAX_MESSAGE_BYTES,
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
        let ca_signer = build_ca_signer().map_err(io::Error::other)?;
        let (csr, key_pem) = build_csr(cfg.advertise_addr).map_err(io::Error::other)?;
        let cert_pem = ca_signer.sign_csr(&csr).map_err(io::Error::other)?;
        persist_tls_material(&cfg.data_dir, &key_pem, &cert_pem, ca_signer.cert_pem())
            .map_err(io::Error::other)?;
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
        .map_err(io::Error::other)?;
    }

    let store = ClusterStore::open(cfg.data_dir.join("raft")).map_err(io::Error::other)?;
    let tls = RaftTlsConfig::load(tls_dir.clone()).map_err(io::Error::other)?;
    let raft_config = build_raft_config().map_err(|err| io::Error::other(err.to_string()))?;
    let raft = openraft::Raft::new(
        raft_node_id,
        Arc::new(raft_config),
        RaftGrpcNetworkFactory::new(tls.clone(), metrics),
        store.clone(),
        store.clone(),
    )
    .await
    .map_err(|err| io::Error::other(err.to_string()))?;

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

    let mut raft_builder = Server::builder()
        .tls_config(tls.server_config())
        .map_err(|err| io::Error::other(format!("raft tls config: {err}")))?
        .add_service(
            crate::controlplane::cluster::rpc::proto::raft_service_server::RaftServiceServer::new(
                raft_service,
            )
            .max_decoding_message_size(RAFT_GRPC_MAX_MESSAGE_BYTES)
            .max_encoding_message_size(RAFT_GRPC_MAX_MESSAGE_BYTES),
        )
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
    let bind_addr = cfg.bind_addr;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_handle = tokio::spawn(async move {
        let mut raft_shutdown = shutdown_rx.clone();
        let mut join_shutdown = shutdown_rx.clone();
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
            .map_err(|err| io::Error::other(err.to_string()))?;
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
                .map_err(|err| io::Error::other(err.to_string()))?;
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
            .map_err(io::Error::other)?;
            retry_forward_to_leader(|| api_auth::ensure_cluster_keyset(&raft, &store))
                .await
                .map_err(io::Error::other)?;
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

fn build_raft_config() -> Result<openraft::Config, openraft::ConfigError> {
    openraft::Config {
        cluster_name: "neuwerk".to_string(),
        heartbeat_interval: 500,
        election_timeout_min: 2_000,
        election_timeout_max: 4_000,
        install_snapshot_timeout: 5_000,
        // Keep append batches well below the tonic transport cap for large replicated values.
        max_payload_entries: 32,
        ..Default::default()
    }
    .validate()
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
            Err(_err) if attempt < retry.max_attempts => {
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
    let psk_hmac = build_join_request_hmac(&token.token, node_id, advertise, &nonce, &csr)?;
    let req = JoinRequest {
        node_id,
        endpoint: advertise,
        csr,
        kid: token.kid.clone(),
        nonce: nonce.to_vec(),
        psk_hmac,
    };

    let req_for_verify = req.clone();
    let resp = client.join(req).await?;
    verify_join_response_hmac(&token.token, &req_for_verify, &resp)?;
    let (signed_cert, ca_cert) = decrypt_join_response_payload(
        &token.token,
        &req_for_verify,
        &resp.encrypted_payload,
        &resp.payload_nonce,
    )?;
    persist_tls_material(data_dir, &key_pem, &signed_cert, &ca_cert)?;
    Ok(resp)
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
    write_with_mode(&tls_dir.join("node.key"), key_pem, 0o600)?;
    write_with_mode(&tls_dir.join("node.crt"), cert_pem, 0o644)?;
    write_with_mode(&tls_dir.join("ca.crt"), ca_pem, 0o644)?;
    Ok(())
}

fn write_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|err| err.to_string())?;
    file.write_all(contents).map_err(|err| err.to_string())?;
    file.sync_all().map_err(|err| err.to_string())?;
    ensure_permissions(path, mode)?;
    Ok(())
}

fn ensure_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .map_err(|err| err.to_string())?
            .permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).map_err(|err| err.to_string())?;
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn join_request_hmac_is_deterministic() {
        let node_id = Uuid::parse_str("aab25366-9cc6-4955-ba56-9556ca1d1225").unwrap();
        let endpoint = SocketAddr::from(([10, 0, 0, 10], 9600));
        let nonce = b"0123456789abcdef";
        let csr = b"fake-csr";

        let a = build_join_request_hmac(b"psk", node_id, endpoint, nonce, csr).unwrap();
        let b = build_join_request_hmac(b"psk", node_id, endpoint, nonce, csr).unwrap();
        let c = build_join_request_hmac(b"psk-2", node_id, endpoint, nonce, csr).unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn join_response_hmac_verification_rejects_tamper() {
        let node_id = Uuid::parse_str("aab25366-9cc6-4955-ba56-9556ca1d1225").unwrap();
        let endpoint = SocketAddr::from(([10, 0, 0, 10], 9600));
        let req = JoinRequest {
            node_id,
            endpoint,
            csr: b"csr".to_vec(),
            kid: "k1".to_string(),
            nonce: b"nonce".to_vec(),
            psk_hmac: vec![1, 2, 3],
        };
        let signed_cert = b"signed-cert".to_vec();
        let ca_cert = b"ca-cert".to_vec();
        let (encrypted_payload, payload_nonce) =
            super::auth::encrypt_join_response_payload(b"psk", &req, &signed_cert, &ca_cert)
                .unwrap();
        let response_hmac =
            super::auth::build_join_response_hmac(b"psk", &req, &encrypted_payload, &payload_nonce)
                .unwrap();
        let mut resp = JoinResponse {
            encrypted_payload,
            payload_nonce: payload_nonce.to_vec(),
            response_hmac,
        };
        verify_join_response_hmac(b"psk", &req, &resp).expect("valid response hmac");

        resp.encrypted_payload.push(0xff);
        let err = verify_join_response_hmac(b"psk", &req, &resp).unwrap_err();
        assert!(err.contains("invalid join response hmac"));
    }

    #[test]
    fn join_response_payload_decrypt_rejects_tamper() {
        let node_id = Uuid::parse_str("aab25366-9cc6-4955-ba56-9556ca1d1225").unwrap();
        let endpoint = SocketAddr::from(([10, 0, 0, 10], 9600));
        let req = JoinRequest {
            node_id,
            endpoint,
            csr: b"csr".to_vec(),
            kid: "k1".to_string(),
            nonce: b"nonce".to_vec(),
            psk_hmac: vec![1, 2, 3],
        };
        let (mut encrypted_payload, payload_nonce) =
            super::auth::encrypt_join_response_payload(b"psk", &req, b"signed-cert", b"ca-cert")
                .unwrap();
        encrypted_payload[0] ^= 0x01;
        let err = super::auth::decrypt_join_response_payload(
            b"psk",
            &req,
            &encrypted_payload,
            &payload_nonce,
        )
        .unwrap_err();
        assert!(err.contains("decrypt"));
    }

    #[cfg(unix)]
    #[test]
    fn persist_tls_material_sets_private_key_to_600() {
        let dir = TempDir::new().unwrap();
        persist_tls_material(dir.path(), b"node-key", b"node-cert", b"ca-cert").unwrap();

        let key_mode = fs::metadata(dir.path().join("tls/node.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let cert_mode = fs::metadata(dir.path().join("tls/node.crt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let ca_mode = fs::metadata(dir.path().join("tls/ca.crt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(key_mode, 0o600);
        assert_eq!(cert_mode, 0o644);
        assert_eq!(ca_mode, 0o644);
    }

    #[test]
    fn raft_config_is_tuned_for_homelab() {
        let config = build_raft_config().unwrap();

        assert_eq!(config.cluster_name, "neuwerk");
        assert_eq!(config.heartbeat_interval, 500);
        assert_eq!(config.election_timeout_min, 2_000);
        assert_eq!(config.election_timeout_max, 4_000);
        assert_eq!(config.install_snapshot_timeout, 5_000);
        assert_eq!(config.max_payload_entries, 32);
    }

    #[test]
    fn raft_config_keeps_large_append_batches_under_transport_cap() {
        let config = build_raft_config().unwrap();
        let large_entry = openraft::Entry::<ClusterTypeConfig> {
            log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            payload: openraft::EntryPayload::Normal(ClusterCommand::Put {
                key: b"threat_intel/snapshot".to_vec(),
                value: vec![0u8; 261_778],
            }),
        };
        let entry_size = bincode::serialize(&large_entry).unwrap().len() as u64;
        let total_batch_bytes = entry_size * config.max_payload_entries;

        assert!(
            total_batch_bytes < RAFT_GRPC_MAX_MESSAGE_BYTES as u64,
            "representative append batch must fit within raft grpc cap: entry_size={entry_size} max_payload_entries={} total_batch_bytes={} grpc_cap={}",
            config.max_payload_entries,
            total_batch_bytes,
            RAFT_GRPC_MAX_MESSAGE_BYTES,
        );
    }
}
