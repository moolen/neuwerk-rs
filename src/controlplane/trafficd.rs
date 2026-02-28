use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::controlplane::audit::AuditStore;
use crate::controlplane::cluster::bootstrap::ca::CaSigner;
use crate::controlplane::dns_proxy;
use crate::controlplane::intercept_tls::{load_intercept_ca_signer, InterceptCaSource};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::DnsPolicy;
use crate::controlplane::wiretap::DnsMap;
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::{
    CidrV4, DynamicIpSetV4, HttpHeadersMatcher, HttpPathMatcher, HttpQueryMatcher,
    HttpRequestPolicy, HttpResponsePolicy, HttpStringMatcher, PacketMeta, PolicySnapshot,
    PortRange, Proto, RuleAction, TlsInterceptHttpPolicy, TlsMode,
};
use crate::dataplane::SharedInterceptDemuxState;
use axum::http::{Request, Response};
use bytes::Bytes;
use futures::FutureExt;
use h2::{client, server};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const HTTP_MAX_HEADER_BYTES: usize = 64 * 1024;
const HTTP_MAX_BODY_BYTES: usize = 1024 * 1024;
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(3);
const INTERCEPT_LEAF_CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const INTERCEPT_LEAF_CACHE_MAX_ENTRIES: usize = 1024;
const INTERCEPT_CHAIN: &str = "NEUWERK_TLS_INTERCEPT";
const INTERCEPT_REPLY_CHAIN: &str = "NEUWERK_TLS_INTERCEPT_REPLY";
const SO_ORIGINAL_DST: i32 = 80;
const SERVICE_LANE_LOCAL_TABLE: u32 = 190;
const SERVICE_LANE_REPLY_TABLE: u32 = 191;
const SERVICE_LANE_LOCAL_RULE_PREF: u32 = 10940;
const SERVICE_LANE_REPLY_RULE_PREF: u32 = 10941;
const SERVICE_LANE_REPLY_MARK_RULE_PREF: u32 = 10942;
const SERVICE_LANE_TPROXY_FWMARK: u32 = 0x1;
const SERVICE_LANE_REPLY_FWMARK: u32 = 0x2;
const SERVICE_LANE_PEER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 2);
const SERVICE_LANE_PEER_MAC: &str = "02:00:00:00:00:02";

pub struct TrafficdConfig {
    pub dns_bind: std::net::SocketAddr,
    pub dns_upstreams: Vec<std::net::SocketAddr>,
    pub dns_allowlist: DynamicIpSetV4,
    pub dns_policy: Arc<RwLock<DnsPolicy>>,
    pub dns_map: DnsMap,
    pub metrics: Metrics,
    pub policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    pub service_policy_applied_generation: Arc<AtomicU64>,
    pub tls_intercept_ca_ready: Arc<AtomicBool>,
    pub tls_intercept_ca_generation: Arc<AtomicU64>,
    pub tls_intercept_ca_source: InterceptCaSource,
    pub tls_intercept_listen_port: u16,
    pub enable_kernel_intercept_steering: bool,
    pub service_lane_iface: String,
    pub service_lane_ip: Ipv4Addr,
    pub service_lane_prefix: u8,
    pub intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    pub policy_store: PolicyStore,
    pub audit_store: Option<AuditStore>,
    pub node_id: String,
    pub startup_status_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

#[derive(Debug)]
pub struct TlsInterceptRuntimeConfig {
    pub bind_addr: std::net::SocketAddr,
    pub upstream_override: Option<std::net::SocketAddr>,
    pub intercept_ca_cert_pem: Vec<u8>,
    pub intercept_ca_key_der: Vec<u8>,
    pub metrics: Metrics,
    pub policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    pub intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    pub startup_status_tx: Option<oneshot::Sender<Result<(), String>>>,
}

#[derive(Debug, Clone)]
struct ParsedHttpRequest {
    method: String,
    host: String,
    path: String,
    query: BTreeMap<String, Vec<String>>,
    headers: BTreeMap<String, Vec<String>>,
    raw: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ParsedHttpResponse {
    headers: BTreeMap<String, Vec<String>>,
    raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterceptSteeringRule {
    src_cidr: CidrV4,
    dst_cidr: Option<CidrV4>,
    dst_port: Option<PortRange>,
}

#[derive(Debug)]
struct CachedCertifiedKey {
    key: Arc<rustls::sign::CertifiedKey>,
    minted_at: Instant,
}

#[derive(Debug)]
struct InterceptLeafCertResolver {
    ca_cert_pem: Vec<u8>,
    ca_key_der: Vec<u8>,
    ttl: Duration,
    max_entries: usize,
    cache: Mutex<HashMap<String, CachedCertifiedKey>>,
}

impl InterceptLeafCertResolver {
    fn new(
        ca_cert_pem: Vec<u8>,
        ca_key_der: Vec<u8>,
        ttl: Duration,
        max_entries: usize,
    ) -> Result<Self, String> {
        CaSigner::from_cert_and_key(&ca_cert_pem, &ca_key_der)
            .map_err(|err| format!("tls intercept: invalid ca material: {err}"))?;
        Ok(Self {
            ca_cert_pem,
            ca_key_der,
            ttl,
            max_entries: max_entries.max(1),
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn resolve_server_name(
        &self,
        requested: Option<&str>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = canonical_intercept_server_name(requested);
        let mut cache = self.cache.lock().ok()?;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.minted_at) <= self.ttl);
        if let Some(entry) = cache.get(&name) {
            return Some(entry.key.clone());
        }
        let minted = self.mint_certified_key(&name).ok()?;
        if cache.len() >= self.max_entries {
            evict_oldest_cached_cert(&mut cache);
        }
        cache.insert(
            name,
            CachedCertifiedKey {
                key: minted.clone(),
                minted_at: now,
            },
        );
        Some(minted)
    }

    fn mint_certified_key(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
        let signer = CaSigner::from_cert_and_key(&self.ca_cert_pem, &self.ca_key_der)
            .map_err(|err| format!("tls intercept: invalid ca material: {err}"))?;
        let (cert_chain_der, key_der) = mint_intercept_server_cert_for_host(&signer, host)?;
        certified_key_from_der(cert_chain_der, key_der)
    }
}

impl rustls::server::ResolvesServerCert for InterceptLeafCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.resolve_server_name(client_hello.server_name())
    }
}

fn build_intercept_listener(bind_addr: SocketAddr) -> Result<TcpListener, String> {
    let socket = match bind_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|err| format!("trafficd tls intercept socket create failed: {err}"))?;
    socket
        .set_reuseaddr(true)
        .map_err(|err| format!("trafficd tls intercept reuseaddr setup failed: {err}"))?;

    socket
        .bind(bind_addr)
        .map_err(|err| format!("trafficd tls intercept bind failed: {err}"))?;
    socket
        .listen(128)
        .map_err(|err| format!("trafficd tls intercept listen failed: {err}"))
}

pub async fn run_tls_intercept_runtime(cfg: TlsInterceptRuntimeConfig) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let acceptor = build_tls_intercept_acceptor(
        &cfg.intercept_ca_cert_pem,
        &cfg.intercept_ca_key_der,
        INTERCEPT_LEAF_CACHE_TTL,
        INTERCEPT_LEAF_CACHE_MAX_ENTRIES,
    )?;
    let connector_h1 = build_insecure_tls_connector(Vec::new());
    let connector_h2 = build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let listener = build_intercept_listener(cfg.bind_addr)?;

    if let Some(tx) = cfg.startup_status_tx {
        let _ = tx.send(Ok(()));
    }

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("trafficd tls intercept accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let connector_h1 = connector_h1.clone();
        let connector_h2 = connector_h2.clone();
        let metrics = cfg.metrics.clone();
        let policy_snapshot = cfg.policy_snapshot.clone();
        let intercept_demux = cfg.intercept_demux.clone();
        let upstream_override = cfg.upstream_override;
        tokio::spawn(async move {
            match std::panic::AssertUnwindSafe(handle_tls_intercept_client(
                stream,
                acceptor,
                connector_h1,
                connector_h2,
                metrics.clone(),
                policy_snapshot,
                intercept_demux,
                upstream_override,
            ))
            .catch_unwind()
            .await
            {
                Ok(Ok(())) => {
                    metrics.inc_svc_tls_intercept_flow("allow");
                }
                Ok(Err(err)) => {
                    metrics.inc_svc_tls_intercept_flow("deny");
                    let lower = err.to_ascii_lowercase();
                    if lower.contains("timed out")
                        || lower.contains("failed")
                        || lower.contains("invalid")
                        || lower.contains("unsupported")
                        || lower.contains("no matching")
                    {
                        metrics.inc_svc_fail_closed("tls");
                    }
                    eprintln!("trafficd tls intercept connection error: {err}");
                }
                Err(_) => {
                    metrics.inc_svc_tls_intercept_flow("deny");
                    metrics.inc_svc_fail_closed("tls");
                    eprintln!("trafficd tls intercept task panicked");
                }
            }
        });
    }
}

#[cfg(test)]
fn build_tls_acceptor(cert_chain_der: &[Vec<u8>], key_der: &[u8]) -> Result<TlsAcceptor, String> {
    if cert_chain_der.is_empty() {
        return Err("tls intercept requires at least one cert in chain".to_string());
    }
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain_der
        .iter()
        .cloned()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("tls intercept server config failed: {err}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn build_tls_intercept_acceptor(
    ca_cert_pem: &[u8],
    ca_key_der: &[u8],
    ttl: Duration,
    max_entries: usize,
) -> Result<TlsAcceptor, String> {
    let resolver = InterceptLeafCertResolver::new(
        ca_cert_pem.to_vec(),
        ca_key_der.to_vec(),
        ttl,
        max_entries,
    )?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn certified_key_from_der(
    cert_chain_der: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    if cert_chain_der.is_empty() {
        return Err("tls intercept: minted leaf cert is empty".to_string());
    }
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain_der
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let provider = rustls::crypto::ring::default_provider();
    let certified = rustls::sign::CertifiedKey::from_der(cert_chain, key, &provider)
        .map_err(|err| format!("tls intercept: invalid certified key: {err}"))?;
    Ok(Arc::new(certified))
}

fn build_insecure_tls_connector(alpn_protocols: Vec<Vec<u8>>) -> TlsConnector {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    TlsConnector::from(Arc::new(config))
}

async fn handle_tls_intercept_client(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    connector_h1: TlsConnector,
    connector_h2: TlsConnector,
    metrics: Metrics,
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let peer_addr = stream
        .peer_addr()
        .map_err(|err| format!("tls intercept: peer addr unavailable: {err}"))?;
    let src_ip = match peer_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err("tls intercept: ipv6 peers unsupported".to_string()),
    };
    let local_addr = stream
        .local_addr()
        .map_err(|err| format!("tls intercept: local addr unavailable: {err}"))?;
    let mut orig_dst = original_dst_addr(&stream).unwrap_or(local_addr);
    if orig_dst == local_addr {
        if let Some(mapped) =
            lookup_intercept_demux_original_dst(&intercept_demux, src_ip, peer_addr.port())
        {
            orig_dst = mapped;
        }
    }

    let mut policy = None;
    if let Ok(lock) = policy_snapshot.read() {
        let dst_ip = match orig_dst.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err("tls intercept: ipv6 destinations unsupported".to_string()),
        };
        let meta = PacketMeta {
            src_ip,
            dst_ip,
            proto: 6,
            src_port: peer_addr.port(),
            dst_port: orig_dst.port(),
            icmp_type: None,
            icmp_code: None,
        };
        policy = find_intercept_http_policy(&lock, &meta);
        if policy.is_none() && orig_dst == local_addr {
            if let Some(inferred_dst) = infer_intercept_original_dst(&lock, src_ip) {
                let inferred_meta = PacketMeta {
                    src_ip,
                    dst_ip: match inferred_dst.ip() {
                        IpAddr::V4(ip) => ip,
                        IpAddr::V6(_) => {
                            return Err("tls intercept: ipv6 destinations unsupported".to_string());
                        }
                    },
                    proto: 6,
                    src_port: peer_addr.port(),
                    dst_port: inferred_dst.port(),
                    icmp_type: None,
                    icmp_code: None,
                };
                if let Some(inferred_policy) = find_intercept_http_policy(&lock, &inferred_meta) {
                    orig_dst = inferred_dst;
                    policy = Some(inferred_policy);
                }
            }
        }
    }

    let Some(policy) = policy else {
        set_linger_rst(&stream);
        return Err("tls intercept: no matching intercept rule".to_string());
    };

    let mut client_tls = tokio::time::timeout(TLS_IO_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| "tls intercept: client tls handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: client tls handshake failed: {err}"))?;
    let client_alpn = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|value| value.to_vec());

    if client_alpn.as_deref() == Some(b"h2") {
        return handle_tls_intercept_h2(
            client_tls,
            connector_h2,
            metrics,
            policy,
            orig_dst,
            upstream_override,
        )
        .await;
    }

    handle_tls_intercept_http1(
        &mut client_tls,
        connector_h1,
        &metrics,
        policy,
        orig_dst,
        upstream_override,
    )
    .await
}

fn set_linger_rst(stream: &TcpStream) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let _ = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
    }
}

async fn connect_upstream_tls(
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let upstream_tcp = tokio::time::timeout(TLS_IO_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| "tls intercept: upstream tcp connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tcp connect failed: {err}"))?;
    let server_name = if host.is_empty() {
        rustls::pki_types::ServerName::try_from("localhost".to_string())
            .map_err(|_| "tls intercept: invalid default server name".to_string())?
    } else {
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| "tls intercept: invalid host server name".to_string())?
    };
    tokio::time::timeout(TLS_IO_TIMEOUT, connector.connect(server_name, upstream_tcp))
        .await
        .map_err(|_| "tls intercept: upstream tls connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tls connect failed: {err}"))
}

async fn handle_tls_intercept_http1(
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    connector: TlsConnector,
    metrics: &Metrics,
    policy: TlsInterceptHttpPolicy,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let req_bytes = tokio::time::timeout(TLS_IO_TIMEOUT, read_http_message(client_tls))
        .await
        .map_err(|_| "tls intercept: client request read timed out".to_string())??;
    let request = parse_http_request(&req_bytes)?;

    if let Some(req_policy) = policy.request.as_ref() {
        if !request_allowed(req_policy, &request) {
            metrics.inc_svc_http_request("http1", "deny");
            metrics.inc_svc_http_deny("http1", "request", "policy");
            metrics.inc_svc_policy_rst("request_policy");
            metrics.inc_svc_fail_closed("tls");
            set_linger_rst(client_tls.get_mut().0);
            return Err("tls intercept: request denied by policy".to_string());
        }
    }
    metrics.inc_svc_http_request("http1", "allow");

    let upstream_addr = upstream_override.unwrap_or(orig_dst);
    let mut upstream_tls = connect_upstream_tls(connector, upstream_addr, &request.host).await?;
    upstream_tls
        .write_all(&request.raw)
        .await
        .map_err(|err| format!("tls intercept: upstream write failed: {err}"))?;

    let response_bytes = tokio::time::timeout(TLS_IO_TIMEOUT, read_http_message(&mut upstream_tls))
        .await
        .map_err(|_| "tls intercept: upstream response read timed out".to_string())??;
    let response = parse_http_response(&response_bytes)?;

    if let Some(resp_policy) = policy.response.as_ref() {
        if !response_allowed(resp_policy, &response) {
            metrics.inc_svc_http_deny("http1", "response", "policy");
            metrics.inc_svc_policy_rst("response_policy");
            metrics.inc_svc_fail_closed("tls");
            set_linger_rst(client_tls.get_mut().0);
            return Err("tls intercept: response denied by policy".to_string());
        }
    }

    client_tls
        .write_all(&response.raw)
        .await
        .map_err(|err| format!("tls intercept: client write failed: {err}"))?;
    client_tls
        .shutdown()
        .await
        .map_err(|err| format!("tls intercept: client shutdown failed: {err}"))?;
    Ok(())
}

async fn read_h2_body(mut body: h2::RecvStream) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(next) = body.data().await {
        let chunk = next.map_err(|err| format!("h2 body read failed: {err}"))?;
        out.extend_from_slice(&chunk);
        if out.len() > HTTP_MAX_BODY_BYTES {
            return Err("h2 body exceeds max size".to_string());
        }
    }
    Ok(out)
}

fn parse_h2_headers(headers: &axum::http::HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        let value = value
            .to_str()
            .map(|v| v.to_string())
            .unwrap_or_else(|_| String::from_utf8_lossy(value.as_bytes()).to_string());
        out.entry(key).or_insert_with(Vec::new).push(value);
    }
    out
}

fn parsed_request_from_h2(req: &Request<h2::RecvStream>) -> ParsedHttpRequest {
    let target = req
        .uri()
        .path_and_query()
        .map(|value| value.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let headers = parse_h2_headers(req.headers());
    let host = req
        .uri()
        .authority()
        .map(|value| value.host().to_ascii_lowercase())
        .or_else(|| {
            headers
                .get("host")
                .and_then(|values| values.first())
                .map(|value| {
                    value
                        .split(':')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase()
                })
        })
        .unwrap_or_default();
    let (path, query) = parse_request_target(&target);
    ParsedHttpRequest {
        method: req.method().as_str().to_ascii_uppercase(),
        host,
        path,
        query,
        headers,
        raw: Vec::new(),
    }
}

fn parsed_response_from_h2(response: &Response<()>) -> ParsedHttpResponse {
    ParsedHttpResponse {
        headers: parse_h2_headers(response.headers()),
        raw: Vec::new(),
    }
}

fn request_for_upstream_h2(method: &str, target: &str, host: &str) -> Result<Request<()>, String> {
    let mut builder = Request::builder().method(method).uri(target);
    if !host.is_empty() {
        builder = builder.header("host", host);
    }
    builder
        .body(())
        .map_err(|err| format!("tls intercept: build upstream h2 request failed: {err}"))
}

fn response_from_upstream_h2(response: &Response<()>) -> Result<Response<()>, String> {
    let mut builder = Response::builder().status(response.status());
    for (name, value) in response.headers() {
        if name.as_str().eq_ignore_ascii_case("connection")
            || name.as_str().eq_ignore_ascii_case("proxy-connection")
            || name.as_str().eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(())
        .map_err(|err| format!("tls intercept: build downstream h2 response failed: {err}"))
}

async fn handle_tls_intercept_h2(
    client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    connector_h2: TlsConnector,
    metrics: Metrics,
    policy: TlsInterceptHttpPolicy,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let mut client_conn = tokio::time::timeout(TLS_IO_TIMEOUT, server::handshake(client_tls))
        .await
        .map_err(|_| "tls intercept: h2 server handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: h2 server handshake failed: {err}"))?;
    let mut saw_request = false;
    loop {
        let next = if saw_request {
            match tokio::time::timeout(TLS_IO_TIMEOUT, client_conn.accept()).await {
                Ok(next) => next,
                Err(_) => {
                    // No additional streams arrived before timeout; close this
                    // intercept connection after the completed exchange.
                    client_conn.graceful_shutdown();
                    return Ok(());
                }
            }
        } else {
            tokio::time::timeout(TLS_IO_TIMEOUT, client_conn.accept())
                .await
                .map_err(|_| "tls intercept: h2 client request timed out".to_string())?
        };

        let Some(next) = next else {
            return if saw_request {
                Ok(())
            } else {
                Err("tls intercept: h2 client closed before request".to_string())
            };
        };

        saw_request = true;
        let (request, mut respond) =
            next.map_err(|err| format!("tls intercept: h2 accept failed: {err}"))?;
        let parsed_request = parsed_request_from_h2(&request);
        let request_target = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let request_body = read_h2_body(request.into_body()).await?;

        if let Some(req_policy) = policy.request.as_ref() {
            if !request_allowed(req_policy, &parsed_request) {
                metrics.inc_svc_http_request("h2", "deny");
                metrics.inc_svc_http_deny("h2", "request", "policy");
                metrics.inc_svc_policy_rst("request_policy");
                metrics.inc_svc_fail_closed("tls");
                return Err("tls intercept: h2 request denied by policy".to_string());
            }
        }
        metrics.inc_svc_http_request("h2", "allow");

        let upstream_addr = upstream_override.unwrap_or(orig_dst);
        let upstream_host = if parsed_request.host.is_empty() {
            upstream_addr.ip().to_string()
        } else {
            parsed_request.host.clone()
        };
        let upstream_tls =
            connect_upstream_tls(connector_h2.clone(), upstream_addr, &upstream_host).await?;
        let (mut send_request, upstream_conn) =
            tokio::time::timeout(TLS_IO_TIMEOUT, client::handshake(upstream_tls))
                .await
                .map_err(|_| "tls intercept: h2 upstream handshake timed out".to_string())?
                .map_err(|err| format!("tls intercept: h2 upstream handshake failed: {err}"))?;
        tokio::spawn(async move {
            let _ = upstream_conn.await;
        });

        let upstream_req =
            request_for_upstream_h2(&parsed_request.method, &request_target, &upstream_host)?;
        let end_of_stream = request_body.is_empty();
        let (response_fut, mut upstream_send_stream) = send_request
            .send_request(upstream_req, end_of_stream)
            .map_err(|err| format!("tls intercept: h2 upstream send failed: {err}"))?;
        if !request_body.is_empty() {
            upstream_send_stream
                .send_data(Bytes::from(request_body), true)
                .map_err(|err| format!("tls intercept: h2 upstream body send failed: {err}"))?;
        }

        let upstream_response = tokio::time::timeout(TLS_IO_TIMEOUT, response_fut)
            .await
            .map_err(|_| "tls intercept: h2 upstream response timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream response failed: {err}"))?;
        let (upstream_parts, mut upstream_body) = upstream_response.into_parts();
        let upstream_header_response = Response::from_parts(upstream_parts, ());
        let parsed_response = parsed_response_from_h2(&upstream_header_response);
        if let Some(resp_policy) = policy.response.as_ref() {
            if !response_allowed(resp_policy, &parsed_response) {
                metrics.inc_svc_http_deny("h2", "response", "policy");
                metrics.inc_svc_policy_rst("response_policy");
                metrics.inc_svc_fail_closed("tls");
                return Err("tls intercept: h2 response denied by policy".to_string());
            }
        }

        let downstream_response = response_from_upstream_h2(&upstream_header_response)?;
        let mut downstream_send = respond
            .send_response(downstream_response, upstream_body.is_end_stream())
            .map_err(|err| format!("tls intercept: h2 downstream send failed: {err}"))?;
        let mut body_bytes = 0usize;
        while let Some(next) = upstream_body.data().await {
            let chunk =
                next.map_err(|err| format!("tls intercept: h2 upstream body read failed: {err}"))?;
            body_bytes = body_bytes.saturating_add(chunk.len());
            if body_bytes > HTTP_MAX_BODY_BYTES {
                return Err("tls intercept: h2 response body exceeds max size".to_string());
            }
            downstream_send
                .send_data(chunk, upstream_body.is_end_stream())
                .map_err(|err| format!("tls intercept: h2 downstream body send failed: {err}"))?;
        }
    }
}

async fn read_http_message<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let mut total_expected = None::<usize>;

    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|err| format!("http read failed: {err}"))?;
        if n == 0 {
            if buf.is_empty() {
                return Err("http read returned eof".to_string());
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > HTTP_MAX_HEADER_BYTES + HTTP_MAX_BODY_BYTES {
            return Err("http message exceeds max size".to_string());
        }

        if total_expected.is_none() {
            if let Some(header_end) = header_end_offset(&buf) {
                let content_len = parse_content_length(&buf[..header_end])?;
                total_expected = Some(header_end + content_len);
            }
        }
        if let Some(total) = total_expected {
            if buf.len() >= total {
                buf.truncate(total);
                return Ok(buf);
            }
        }
    }

    if total_expected.is_none() {
        return Err("http header terminator missing".to_string());
    }
    Ok(buf)
}

fn header_end_offset(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_content_length(header: &[u8]) -> Result<usize, String> {
    let header_text =
        std::str::from_utf8(header).map_err(|_| "invalid http header utf8".to_string())?;
    for line in header_text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let parsed = value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid content-length".to_string())?;
                if parsed > HTTP_MAX_BODY_BYTES {
                    return Err("content-length exceeds max body size".to_string());
                }
                return Ok(parsed);
            }
        }
    }
    Ok(0)
}

fn parse_http_request(raw: &[u8]) -> Result<ParsedHttpRequest, String> {
    let header_end = header_end_offset(raw)
        .ok_or_else(|| "http request header terminator missing".to_string())?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "invalid http request utf8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "missing request method".to_string())?
        .to_ascii_uppercase();
    let target = parts
        .next()
        .ok_or_else(|| "missing request target".to_string())?;
    let _version = parts
        .next()
        .ok_or_else(|| "missing request version".to_string())?;

    let headers = parse_headers(lines);
    let host = headers
        .get("host")
        .and_then(|values| values.first())
        .map(|value| {
            value
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let (path, query) = parse_request_target(target);

    Ok(ParsedHttpRequest {
        method,
        host,
        path,
        query,
        headers,
        raw: raw.to_vec(),
    })
}

fn parse_http_response(raw: &[u8]) -> Result<ParsedHttpResponse, String> {
    let header_end = header_end_offset(raw)
        .ok_or_else(|| "http response header terminator missing".to_string())?;
    let header_text = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "invalid http response utf8".to_string())?;
    let mut lines = header_text.split("\r\n");
    let _status = lines
        .next()
        .ok_or_else(|| "missing response status line".to_string())?;
    let headers = parse_headers(lines);
    Ok(ParsedHttpResponse {
        headers,
        raw: raw.to_vec(),
    })
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> BTreeMap<String, Vec<String>> {
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let key = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            headers.entry(key).or_insert_with(Vec::new).push(value);
        }
    }
    headers
}

fn parse_request_target(target: &str) -> (String, BTreeMap<String, Vec<String>>) {
    let path_and_query = if target.starts_with('/') {
        target
    } else if let Some(scheme_pos) = target.find("://") {
        let rest = &target[scheme_pos + 3..];
        if let Some(slash) = rest.find('/') {
            &rest[slash..]
        } else {
            "/"
        }
    } else {
        target
    };

    let (path, query_raw) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path_and_query, ""),
    };
    let path = if path.is_empty() { "/" } else { path }.to_string();
    let mut query = BTreeMap::new();
    if !query_raw.is_empty() {
        for pair in query_raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => (pair, ""),
            };
            query
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(value.to_string());
        }
    }
    (path, query)
}

fn request_allowed(policy: &HttpRequestPolicy, req: &ParsedHttpRequest) -> bool {
    if let Some(host) = policy.host.as_ref() {
        if !match_host(host, &req.host) {
            return false;
        }
    }
    if !policy.methods.is_empty()
        && !policy
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(&req.method))
    {
        return false;
    }
    if let Some(path) = policy.path.as_ref() {
        if !match_path(path, &req.path) {
            return false;
        }
    }
    if let Some(query) = policy.query.as_ref() {
        if !match_query(query, &req.query) {
            return false;
        }
    }
    if let Some(headers) = policy.headers.as_ref() {
        if !match_headers(headers, &req.headers) {
            return false;
        }
    }
    true
}

fn response_allowed(policy: &HttpResponsePolicy, response: &ParsedHttpResponse) -> bool {
    if let Some(headers) = policy.headers.as_ref() {
        return match_headers(headers, &response.headers);
    }
    true
}

fn match_host(matcher: &HttpStringMatcher, host: &str) -> bool {
    if matcher.exact.is_empty() && matcher.regex.is_none() {
        return true;
    }
    if matcher
        .exact
        .iter()
        .any(|expected| expected.eq_ignore_ascii_case(host))
    {
        return true;
    }
    matcher
        .regex
        .as_ref()
        .map(|re| re.is_match(host))
        .unwrap_or(false)
}

fn match_path(matcher: &HttpPathMatcher, path: &str) -> bool {
    if matcher.exact.is_empty() && matcher.prefix.is_empty() && matcher.regex.is_none() {
        return true;
    }
    if matcher.exact.iter().any(|expected| expected == path) {
        return true;
    }
    if matcher.prefix.iter().any(|prefix| path.starts_with(prefix)) {
        return true;
    }
    matcher
        .regex
        .as_ref()
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn match_query(matcher: &HttpQueryMatcher, query: &BTreeMap<String, Vec<String>>) -> bool {
    for key in &matcher.keys_present {
        if !query.contains_key(key) {
            return false;
        }
    }
    for (key, allowed_values) in &matcher.key_values_exact {
        let Some(values) = query.get(key) else {
            return false;
        };
        if !values
            .iter()
            .any(|value| allowed_values.iter().any(|allowed| allowed == value))
        {
            return false;
        }
    }
    for (key, regex) in &matcher.key_values_regex {
        let Some(values) = query.get(key) else {
            return false;
        };
        if !values.iter().any(|value| regex.is_match(value)) {
            return false;
        }
    }
    true
}

fn match_headers(matcher: &HttpHeadersMatcher, headers: &BTreeMap<String, Vec<String>>) -> bool {
    for key in &matcher.require_present {
        if !headers.contains_key(&key.to_ascii_lowercase()) {
            return false;
        }
    }
    for key in &matcher.deny_present {
        if headers.contains_key(&key.to_ascii_lowercase()) {
            return false;
        }
    }
    for (key, allowed_values) in &matcher.exact {
        let key = key.to_ascii_lowercase();
        let Some(values) = headers.get(&key) else {
            return false;
        };
        if !values
            .iter()
            .any(|value| allowed_values.iter().any(|allowed| allowed == value))
        {
            return false;
        }
    }
    for (key, regex) in &matcher.regex {
        let key = key.to_ascii_lowercase();
        let Some(values) = headers.get(&key) else {
            return false;
        };
        if !values.iter().any(|value| regex.is_match(value)) {
            return false;
        }
    }
    true
}

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn policy_has_tls_intercept(snapshot: &PolicySnapshot) -> bool {
    snapshot.groups.iter().any(|group| {
        group.rules.iter().any(|rule| {
            matches!(
                rule.matcher.tls.as_ref().map(|tls| tls.mode),
                Some(TlsMode::Intercept)
            )
        })
    })
}

fn compile_intercept_steering_rules(snapshot: &PolicySnapshot) -> Vec<InterceptSteeringRule> {
    let mut out = Vec::new();
    for group in &snapshot.groups {
        if group.sources.has_dynamic() || group.sources.cidrs().is_empty() {
            continue;
        }
        for rule in &group.rules {
            if rule.action != RuleAction::Allow {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if !matches!(rule.matcher.proto, Proto::Tcp | Proto::Any) {
                continue;
            }
            let dst_cidrs = rule
                .matcher
                .dst_ips
                .as_ref()
                .map(|set| set.cidrs().to_vec())
                .unwrap_or_default();
            let dst_ports = if rule.matcher.dst_ports.is_empty() {
                vec![None]
            } else {
                rule.matcher.dst_ports.iter().copied().map(Some).collect()
            };
            let dst_targets = if dst_cidrs.is_empty() {
                vec![None]
            } else {
                dst_cidrs.into_iter().map(Some).collect()
            };
            for src_cidr in group.sources.cidrs() {
                for dst_cidr in &dst_targets {
                    for dst_port in &dst_ports {
                        out.push(InterceptSteeringRule {
                            src_cidr: *src_cidr,
                            dst_cidr: *dst_cidr,
                            dst_port: *dst_port,
                        });
                    }
                }
            }
        }
    }
    out
}

fn run_iptables(args: Vec<String>) -> Result<(), String> {
    let status = Command::new("iptables")
        .args(&args)
        .status()
        .map_err(|err| format!("iptables invocation failed: {err}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!("iptables {:?} failed with status {}", args, status))
}

fn iptables_check(args: Vec<String>) -> bool {
    Command::new("iptables")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn iptables_chain_exists(table: &str, chain: &str) -> bool {
    iptables_check(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-L".to_string(),
        chain.to_string(),
    ])
}

fn delete_chain_jump(
    table: &str,
    parent_chain: &str,
    chain: &str,
    proto: &str,
    iface: Option<&str>,
) {
    let mut check_args = vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-C".to_string(),
        parent_chain.to_string(),
    ];
    if let Some(iface) = iface {
        check_args.push("-i".to_string());
        check_args.push(iface.to_string());
    }
    check_args.push("-p".to_string());
    check_args.push(proto.to_string());
    check_args.push("-j".to_string());
    check_args.push(chain.to_string());
    let mut delete_args = check_args.clone();
    delete_args[3] = "-D".to_string();
    while iptables_check(check_args.clone()) {
        let _ = run_iptables(delete_args.clone());
    }
}

fn delete_prerouting_jump(table: &str, chain: &str, proto: &str, iface: Option<&str>) {
    delete_chain_jump(table, "PREROUTING", chain, proto, iface);
}

fn delete_output_jump(table: &str, chain: &str, proto: &str) {
    delete_chain_jump(table, "OUTPUT", chain, proto, None);
}

fn clear_table_chain(table: &str, chain: &str, proto: &str, iface: &str) {
    if !iptables_chain_exists(table, chain) {
        return;
    }
    delete_prerouting_jump(table, chain, proto, Some(iface));
    delete_prerouting_jump(table, chain, proto, None);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-F".to_string(),
        chain.to_string(),
    ]);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-X".to_string(),
        chain.to_string(),
    ]);
}

fn clear_output_table_chain(table: &str, chain: &str, proto: &str) {
    if !iptables_chain_exists(table, chain) {
        return;
    }
    delete_output_jump(table, chain, proto);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-F".to_string(),
        chain.to_string(),
    ]);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-X".to_string(),
        chain.to_string(),
    ]);
}

fn clear_intercept_steering_rules(service_lane_iface: &str) {
    clear_table_chain("mangle", INTERCEPT_CHAIN, "tcp", service_lane_iface);
    clear_table_chain("nat", INTERCEPT_CHAIN, "tcp", service_lane_iface);
    clear_output_table_chain("mangle", INTERCEPT_REPLY_CHAIN, "tcp");
}

fn ensure_tproxy_chain(chain: &str, proto: &str, iface: &str) -> Result<(), String> {
    if !iptables_chain_exists("mangle", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "mangle".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_prerouting_jump("mangle", chain, proto, Some(iface));
    delete_prerouting_jump("mangle", chain, proto, None);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-I".to_string(),
        "PREROUTING".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn ensure_redirect_chain(chain: &str, proto: &str) -> Result<(), String> {
    if !iptables_chain_exists("nat", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_prerouting_jump("nat", chain, proto, None);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-I".to_string(),
        "PREROUTING".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn ensure_output_mark_chain(chain: &str, proto: &str) -> Result<(), String> {
    if !iptables_chain_exists("mangle", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "mangle".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_output_jump("mangle", chain, proto);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-I".to_string(),
        "OUTPUT".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn cidr_to_iptables_arg(cidr: CidrV4) -> String {
    format!("{}/{}", cidr.addr(), cidr.prefix())
}

fn intercept_tproxy_rule_args(
    rule: &InterceptSteeringRule,
    listen_ip: Ipv4Addr,
    listen_port: u16,
    fwmark: u32,
) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-A".to_string(),
        INTERCEPT_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-d".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--dport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("TPROXY".to_string());
    args.push("--on-ip".to_string());
    args.push(listen_ip.to_string());
    args.push("--on-port".to_string());
    args.push(listen_port.to_string());
    args.push("--tproxy-mark".to_string());
    args.push(format!("0x{fwmark:x}/0x{fwmark:x}"));
    args
}

fn intercept_reply_mark_rule_args(rule: &InterceptSteeringRule, fwmark: u32) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-A".to_string(),
        INTERCEPT_REPLY_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-d".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-s".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--sport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("MARK".to_string());
    args.push("--set-xmark".to_string());
    args.push(format!("0x{fwmark:x}/0x{fwmark:x}"));
    args
}

fn intercept_redirect_rule_args(rule: &InterceptSteeringRule, listen_port: u16) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        INTERCEPT_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-d".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--dport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("REDIRECT".to_string());
    args.push("--to-ports".to_string());
    args.push(listen_port.to_string());
    args
}

fn apply_intercept_steering_rules(
    rules: &[InterceptSteeringRule],
    listen_addr: SocketAddr,
    service_lane_iface: &str,
) -> Result<(), String> {
    let listen_port = listen_addr.port();
    if matches!(listen_addr.ip(), IpAddr::V4(ip) if ip.is_unspecified()) {
        ensure_redirect_chain(INTERCEPT_CHAIN, "tcp")?;
        for rule in rules {
            run_iptables(intercept_redirect_rule_args(rule, listen_port))?;
        }
        return Ok(());
    }

    ensure_tproxy_chain(INTERCEPT_CHAIN, "tcp", service_lane_iface)?;
    ensure_output_mark_chain(INTERCEPT_REPLY_CHAIN, "tcp")?;

    let listen_ip = match listen_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err("trafficd intercept steering requires ipv4 listen addr".to_string()),
    };
    for rule in rules {
        run_iptables(intercept_tproxy_rule_args(
            rule,
            listen_ip,
            listen_port,
            SERVICE_LANE_TPROXY_FWMARK,
        ))?;
        run_iptables(intercept_reply_mark_rule_args(
            rule,
            SERVICE_LANE_REPLY_FWMARK,
        ))?;
    }
    Ok(())
}

fn run_ip(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| format!("ip invocation failed: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(format!(
        "ip {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run_ip_owned(args: Vec<String>) -> Result<String, String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(&refs)
}

fn rule_line_matches(line: &str, required_fragments: &[&str]) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && required_fragments
            .iter()
            .all(|fragment| trimmed.contains(fragment))
}

fn ensure_ip_rule_pref(
    pref: u32,
    required_fragments: &[&str],
    add_tail_args: &[String],
) -> Result<(), String> {
    let pref_str = pref.to_string();
    let existing = run_ip(&["-4", "rule", "show", "pref", &pref_str])?;
    if rule_line_matches(&existing, required_fragments) {
        return Ok(());
    }
    if !existing.trim().is_empty() {
        run_ip(&["-4", "rule", "del", "pref", &pref_str])?;
    }
    let mut args = vec![
        "-4".to_string(),
        "rule".to_string(),
        "add".to_string(),
        "pref".to_string(),
        pref_str,
    ];
    args.extend_from_slice(add_tail_args);
    run_ip_owned(args)?;
    Ok(())
}

fn ensure_service_lane_rp_filter_loose(iface: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
    let current = fs::read_to_string(&path)
        .map_err(|err| format!("read {path} failed: {err}"))?
        .trim()
        .parse::<u8>()
        .map_err(|err| format!("parse {path} failed: {err}"))?;
    if current >= 2 {
        return Ok(());
    }
    fs::write(&path, "2").map_err(|err| format!("write {path} failed: {err}"))?;
    Ok(())
}

fn ensure_service_lane_routing(iface: &str, service_lane_ip: Ipv4Addr) -> Result<(), String> {
    ensure_service_lane_rp_filter_loose(iface)?;

    let local_table = SERVICE_LANE_LOCAL_TABLE.to_string();
    run_ip(&[
        "-4",
        "route",
        "replace",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        &local_table,
    ])?;
    let fwmark_fragment = format!("fwmark 0x{:x}", SERVICE_LANE_TPROXY_FWMARK);
    let local_lookup_fragment = format!("lookup {SERVICE_LANE_LOCAL_TABLE}");
    ensure_ip_rule_pref(
        SERVICE_LANE_LOCAL_RULE_PREF,
        &[fwmark_fragment.as_str(), local_lookup_fragment.as_str()],
        &[
            "fwmark".to_string(),
            format!(
                "0x{:x}/0x{:x}",
                SERVICE_LANE_TPROXY_FWMARK, SERVICE_LANE_TPROXY_FWMARK
            ),
            "lookup".to_string(),
            local_table.clone(),
        ],
    )?;

    let reply_table = SERVICE_LANE_REPLY_TABLE.to_string();
    run_ip(&[
        "-4",
        "neigh",
        "replace",
        SERVICE_LANE_PEER_IP.to_string().as_str(),
        "lladdr",
        SERVICE_LANE_PEER_MAC,
        "nud",
        "permanent",
        "dev",
        iface,
    ])?;
    run_ip(&[
        "-4",
        "route",
        "replace",
        "default",
        "via",
        SERVICE_LANE_PEER_IP.to_string().as_str(),
        "dev",
        iface,
        "table",
        &reply_table,
    ])?;
    let from_cidr = format!("{service_lane_ip}/32");
    let from_fragment = format!("from {service_lane_ip}");
    let reply_lookup_fragment = format!("lookup {SERVICE_LANE_REPLY_TABLE}");
    ensure_ip_rule_pref(
        SERVICE_LANE_REPLY_RULE_PREF,
        &[from_fragment.as_str(), reply_lookup_fragment.as_str()],
        &[
            "from".to_string(),
            from_cidr,
            "lookup".to_string(),
            reply_table.clone(),
        ],
    )?;
    let reply_fwmark_fragment = format!("fwmark 0x{:x}", SERVICE_LANE_REPLY_FWMARK);
    ensure_ip_rule_pref(
        SERVICE_LANE_REPLY_MARK_RULE_PREF,
        &[
            reply_fwmark_fragment.as_str(),
            reply_lookup_fragment.as_str(),
        ],
        &[
            "fwmark".to_string(),
            format!(
                "0x{:x}/0x{:x}",
                SERVICE_LANE_REPLY_FWMARK, SERVICE_LANE_REPLY_FWMARK
            ),
            "lookup".to_string(),
            reply_table,
        ],
    )?;
    Ok(())
}

fn ensure_service_lane_interface(iface: &str, ip: Ipv4Addr, prefix: u8) -> Result<(), String> {
    let exists = run_ip(&["link", "show", "dev", iface]).is_ok();
    if !exists {
        run_ip(&["tuntap", "add", "dev", iface, "mode", "tap"])?;
    }
    run_ip(&["link", "set", "dev", iface, "up"])?;
    let expected = format!("{}/{}", ip, prefix.min(32));
    let addr_show = run_ip(&["-4", "addr", "show", "dev", iface])?;
    if !addr_show.contains(&expected) {
        let _ = run_ip(&["-4", "addr", "add", &expected, "dev", iface]);
    }
    Ok(())
}

fn find_intercept_http_policy(
    snapshot: &PolicySnapshot,
    meta: &PacketMeta,
) -> Option<TlsInterceptHttpPolicy> {
    for group in &snapshot.groups {
        if !group.sources.contains(meta.src_ip) {
            continue;
        }
        for rule in &group.rules {
            if !rule_matches_meta(rule, meta) {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if rule.action != RuleAction::Allow {
                return None;
            }
            return tls.intercept_http.clone();
        }
    }
    None
}

fn lookup_intercept_demux_original_dst(
    demux: &Arc<Mutex<SharedInterceptDemuxState>>,
    src_ip: Ipv4Addr,
    src_port: u16,
) -> Option<SocketAddr> {
    let mut lock = demux.lock().ok()?;
    let (upstream_ip, upstream_port) = lock.lookup(src_ip, src_port)?;
    Some(SocketAddr::new(IpAddr::V4(upstream_ip), upstream_port))
}

fn infer_intercept_original_dst(snapshot: &PolicySnapshot, src_ip: Ipv4Addr) -> Option<SocketAddr> {
    let mut inferred: Option<SocketAddr> = None;
    for group in &snapshot.groups {
        if !group.sources.contains(src_ip) {
            continue;
        }
        for rule in &group.rules {
            if rule.action != RuleAction::Allow {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if !matches!(rule.matcher.proto, Proto::Tcp | Proto::Any) {
                continue;
            }

            let Some(dst_ips) = &rule.matcher.dst_ips else {
                continue;
            };
            let cidrs = dst_ips.cidrs();
            if cidrs.len() != 1 || cidrs[0].prefix() != 32 {
                continue;
            }
            let dst_ip = cidrs[0].addr();

            let dst_port = match rule.matcher.dst_ports.as_slice() {
                [range] if range.start == range.end => range.start,
                _ => continue,
            };

            let candidate = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
            match inferred {
                None => inferred = Some(candidate),
                Some(current) if current == candidate => {}
                Some(_) => return None,
            }
        }
    }
    inferred
}

fn rule_matches_meta(rule: &crate::dataplane::policy::Rule, meta: &PacketMeta) -> bool {
    if let Some(dst_ips) = &rule.matcher.dst_ips {
        if !dst_ips.contains(meta.dst_ip) {
            return false;
        }
    }
    if !rule.matcher.proto.matches(meta.proto) {
        return false;
    }
    if !port_matches(&rule.matcher.src_ports, meta.src_port) {
        return false;
    }
    if !port_matches(&rule.matcher.dst_ports, meta.dst_port) {
        return false;
    }
    true
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|range| range.contains(port))
}

fn original_dst_addr(stream: &TcpStream) -> Result<SocketAddr, String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(format!(
                "tls intercept: SO_ORIGINAL_DST lookup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::new(IpAddr::V4(ip), port));
    }
    #[allow(unreachable_code)]
    Err("tls intercept: SO_ORIGINAL_DST unsupported on this platform".to_string())
}

fn canonical_intercept_server_name(requested: Option<&str>) -> String {
    let Some(raw) = requested else {
        return "intercept.local".to_string();
    };
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return "intercept.local".to_string();
    }
    if rustls::pki_types::ServerName::try_from(trimmed.clone()).is_err() {
        return "intercept.local".to_string();
    }
    trimmed
}

fn evict_oldest_cached_cert(cache: &mut HashMap<String, CachedCertifiedKey>) {
    let mut oldest_key: Option<String> = None;
    let mut oldest_time = Instant::now();
    for (name, entry) in cache.iter() {
        if oldest_key.is_none() || entry.minted_at <= oldest_time {
            oldest_key = Some(name.clone());
            oldest_time = entry.minted_at;
        }
    }
    if let Some(name) = oldest_key {
        cache.remove(&name);
    }
}

fn mint_intercept_server_cert_for_host(
    ca_signer: &CaSigner,
    host: &str,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    use rcgen::{Certificate, CertificateParams, DnType};
    let host = canonical_intercept_server_name(Some(host));
    let mut params = CertificateParams::new(vec![host.clone()]);
    params.distinguished_name.push(DnType::CommonName, &host);
    let leaf = Certificate::from_params(params).map_err(|err| err.to_string())?;
    let csr = leaf
        .serialize_request_der()
        .map_err(|err| err.to_string())?;
    let leaf_pem = ca_signer.sign_csr(&csr).map_err(|err| err.to_string())?;
    let mut leaf_reader = std::io::BufReader::new(leaf_pem.as_slice());
    let leaf_chain = rustls_pemfile::certs(&mut leaf_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    if leaf_chain.is_empty() {
        return Err("tls intercept: minted leaf cert is empty".to_string());
    }
    let mut chain: Vec<Vec<u8>> = leaf_chain
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect();
    let mut ca_reader = std::io::BufReader::new(ca_signer.cert_pem());
    let ca_chain = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    for cert in ca_chain {
        chain.push(cert.as_ref().to_vec());
    }
    Ok((chain, leaf.serialize_private_key_der()))
}

fn spawn_service_policy_observer(
    observer_policy: Arc<RwLock<PolicySnapshot>>,
    observer_applied: Arc<AtomicU64>,
    tls_intercept_ca_ready: Arc<AtomicBool>,
    intercept_ready: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut last = observer_applied.load(Ordering::Acquire);
        loop {
            let snapshot = {
                match observer_policy.read() {
                    Ok(lock) => Some(lock.clone()),
                    Err(_) => None,
                }
            };
            let Some(snapshot) = snapshot else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            if policy_has_tls_intercept(&snapshot)
                && (!tls_intercept_ca_ready.load(Ordering::Acquire)
                    || !intercept_ready.load(Ordering::Acquire))
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            let generation = snapshot.generation();
            if generation != last {
                observer_applied.store(generation, Ordering::Release);
                last = generation;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

fn spawn_tls_intercept_supervisor(
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    tls_intercept_ca_ready: Arc<AtomicBool>,
    tls_intercept_ca_generation: Arc<AtomicU64>,
    tls_intercept_ca_source: InterceptCaSource,
    intercept_ready: Arc<AtomicBool>,
    listen_addr: SocketAddr,
    enable_kernel_intercept_steering: bool,
    service_lane_iface: String,
    intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    metrics: Metrics,
) {
    tokio::spawn(async move {
        let mut runtime_task: Option<tokio::task::JoinHandle<Result<(), String>>> = None;
        let mut runtime_ca_generation: Option<u64> = None;
        let mut applied_steering_rules: Option<Vec<InterceptSteeringRule>> = None;
        loop {
            let desired_ca_generation = tls_intercept_ca_generation.load(Ordering::Acquire);
            if let Some(task) = runtime_task.as_ref() {
                if task.is_finished() {
                    let task = runtime_task.take().expect("runtime task");
                    let _ = task.await;
                    intercept_ready.store(false, Ordering::Release);
                    runtime_ca_generation = None;
                    if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                        clear_intercept_steering_rules(&service_lane_iface);
                        applied_steering_rules = None;
                    }
                } else if runtime_ca_generation != Some(desired_ca_generation) {
                    let task = runtime_task.take().expect("runtime task");
                    task.abort();
                    let _ = task.await;
                    intercept_ready.store(false, Ordering::Release);
                    runtime_ca_generation = None;
                    if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                        clear_intercept_steering_rules(&service_lane_iface);
                        applied_steering_rules = None;
                    }
                }
            }

            let snapshot = {
                match policy_snapshot.read() {
                    Ok(lock) => Some(lock.clone()),
                    Err(_) => None,
                }
            };
            let Some(snapshot) = snapshot else {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };

            let has_intercept_policy = policy_has_tls_intercept(&snapshot);
            if !has_intercept_policy {
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                intercept_ready.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let ca_ready = tls_intercept_ca_ready.load(Ordering::Acquire);
            if !ca_ready {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if runtime_task.is_none() {
                let signer = match load_intercept_ca_signer(&tls_intercept_ca_source) {
                    Ok(signer) => signer,
                    Err(err) => {
                        eprintln!("trafficd: intercept ca load failed: {err}");
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (startup_tx, startup_rx) = oneshot::channel();
                let task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
                    bind_addr: listen_addr,
                    upstream_override: None,
                    intercept_ca_cert_pem: signer.cert_pem().to_vec(),
                    intercept_ca_key_der: signer.key_der().to_vec(),
                    metrics: metrics.clone(),
                    policy_snapshot: policy_snapshot.clone(),
                    intercept_demux: intercept_demux.clone(),
                    startup_status_tx: Some(startup_tx),
                }));
                match tokio::time::timeout(Duration::from_secs(2), startup_rx).await {
                    Ok(Ok(Ok(()))) => {
                        runtime_task = Some(task);
                        runtime_ca_generation = Some(desired_ca_generation);
                    }
                    Ok(Ok(Err(err))) => {
                        eprintln!("trafficd: tls intercept runtime startup failed: {err}");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(Err(_)) => {
                        eprintln!("trafficd: tls intercept runtime startup channel dropped");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(_) => {
                        eprintln!("trafficd: tls intercept runtime startup timed out");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            }

            let rules = compile_intercept_steering_rules(&snapshot);
            if rules.is_empty() {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if enable_kernel_intercept_steering {
                let rules_changed = applied_steering_rules
                    .as_ref()
                    .map(|current| current != &rules)
                    .unwrap_or(true);
                if rules_changed {
                    if let Err(err) =
                        apply_intercept_steering_rules(&rules, listen_addr, &service_lane_iface)
                    {
                        eprintln!("trafficd: intercept steering apply failed: {err}");
                        clear_intercept_steering_rules(&service_lane_iface);
                        applied_steering_rules = None;
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    applied_steering_rules = Some(rules);
                }
            }
            intercept_ready.store(true, Ordering::Release);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

pub async fn run(cfg: TrafficdConfig) -> Result<(), String> {
    if cfg.dns_upstreams.is_empty() {
        return Err("trafficd: at least one dns upstream is required".to_string());
    }
    ensure_service_lane_interface(
        &cfg.service_lane_iface,
        cfg.service_lane_ip,
        cfg.service_lane_prefix,
    )?;
    ensure_service_lane_routing(&cfg.service_lane_iface, cfg.service_lane_ip)?;

    let intercept_listen_ip = if cfg.enable_kernel_intercept_steering {
        Ipv4Addr::UNSPECIFIED
    } else {
        cfg.service_lane_ip
    };
    let intercept_listen_addr =
        SocketAddr::new(IpAddr::V4(intercept_listen_ip), cfg.tls_intercept_listen_port);

    let intercept_ready = Arc::new(AtomicBool::new(false));
    spawn_tls_intercept_supervisor(
        cfg.policy_snapshot.clone(),
        cfg.tls_intercept_ca_ready.clone(),
        cfg.tls_intercept_ca_generation.clone(),
        cfg.tls_intercept_ca_source.clone(),
        intercept_ready.clone(),
        intercept_listen_addr,
        cfg.enable_kernel_intercept_steering,
        cfg.service_lane_iface.clone(),
        cfg.intercept_demux.clone(),
        cfg.metrics.clone(),
    );

    spawn_service_policy_observer(
        cfg.policy_snapshot.clone(),
        cfg.service_policy_applied_generation.clone(),
        cfg.tls_intercept_ca_ready.clone(),
        intercept_ready,
    );

    dns_proxy::run_dns_proxy(
        cfg.dns_bind,
        cfg.dns_upstreams,
        cfg.dns_allowlist,
        cfg.dns_policy,
        cfg.dns_map,
        cfg.metrics,
        Some(cfg.policy_store),
        cfg.audit_store,
        cfg.node_id,
        cfg.startup_status_tx,
    )
    .await
    .map_err(|err| format!("trafficd dns runtime failed: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::policy::{
        CidrV4, DefaultPolicy, HttpPathMatcher, HttpQueryMatcher, HttpRequestPolicy,
        HttpResponsePolicy, HttpStringMatcher, IpSetV4, PortRange, Proto, Rule, RuleAction,
        RuleMatch, SourceGroup, Tls13Uninspectable, TlsInterceptHttpPolicy, TlsMatch,
    };
    use rcgen::{
        generate_simple_self_signed, BasicConstraints, Certificate, CertificateParams, DnType,
        IsCa, KeyUsagePurpose,
    };
    use regex::Regex;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn non_intercept_snapshot(generation: u64) -> PolicySnapshot {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let rule = Rule {
            id: "allow-http".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: None,
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };
        PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], generation)
    }

    fn intercept_snapshot(generation: u64) -> PolicySnapshot {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let rule = Rule {
            id: "intercept".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: None,
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: Some(TlsMatch {
                    mode: TlsMode::Intercept,
                    sni: None,
                    server_san: None,
                    server_cn: None,
                    fingerprints_sha256: Vec::new(),
                    trust_anchors: Vec::new(),
                    tls13_uninspectable: Tls13Uninspectable::Deny,
                    intercept_http: None,
                }),
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };
        PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], generation)
    }

    fn intercept_http_snapshot(generation: u64) -> PolicySnapshot {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(127, 0, 0, 0), 8));
        let rule = Rule {
            id: "intercept-http".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: None,
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: Some(TlsMatch {
                    mode: TlsMode::Intercept,
                    sni: None,
                    server_san: None,
                    server_cn: None,
                    fingerprints_sha256: Vec::new(),
                    trust_anchors: Vec::new(),
                    tls13_uninspectable: Tls13Uninspectable::Deny,
                    intercept_http: Some(intercept_http_policy()),
                }),
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };
        PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], generation)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observer_blocks_intercept_generation_without_ca() {
        let snapshot = Arc::new(RwLock::new(non_intercept_snapshot(0)));
        let applied = Arc::new(AtomicU64::new(0));
        let ca_ready = Arc::new(AtomicBool::new(false));
        let intercept_ready = Arc::new(AtomicBool::new(true));
        spawn_service_policy_observer(
            snapshot.clone(),
            applied.clone(),
            ca_ready.clone(),
            intercept_ready,
        );

        if let Ok(mut lock) = snapshot.write() {
            *lock = non_intercept_snapshot(1);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(applied.load(Ordering::Acquire), 1);

        if let Ok(mut lock) = snapshot.write() {
            *lock = intercept_snapshot(2);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(applied.load(Ordering::Acquire), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn observer_advances_intercept_generation_when_ca_ready() {
        let snapshot = Arc::new(RwLock::new(intercept_snapshot(0)));
        let applied = Arc::new(AtomicU64::new(0));
        let ca_ready = Arc::new(AtomicBool::new(false));
        let intercept_ready = Arc::new(AtomicBool::new(true));
        spawn_service_policy_observer(
            snapshot.clone(),
            applied.clone(),
            ca_ready.clone(),
            intercept_ready,
        );

        if let Ok(mut lock) = snapshot.write() {
            *lock = intercept_snapshot(3);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(applied.load(Ordering::Acquire), 0);

        ca_ready.store(true, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(applied.load(Ordering::Acquire), 3);
    }

    fn intercept_http_policy() -> TlsInterceptHttpPolicy {
        let request = HttpRequestPolicy {
            host: Some(HttpStringMatcher {
                exact: vec!["foo.allowed".to_string()],
                regex: None,
            }),
            methods: vec!["GET".to_string()],
            path: Some(HttpPathMatcher {
                exact: Vec::new(),
                prefix: vec!["/external-secrets/".to_string()],
                regex: None,
            }),
            query: Some(HttpQueryMatcher {
                keys_present: vec!["ref".to_string()],
                key_values_exact: BTreeMap::new(),
                key_values_regex: BTreeMap::new(),
            }),
            headers: None,
        };
        let mut response_regex = BTreeMap::new();
        response_regex.insert("content-type".to_string(), Regex::new("^text/").unwrap());
        let response = HttpResponsePolicy {
            headers: Some(HttpHeadersMatcher {
                require_present: vec!["content-type".to_string()],
                deny_present: vec!["x-forbidden".to_string()],
                exact: BTreeMap::new(),
                regex: response_regex,
            }),
        };
        TlsInterceptHttpPolicy {
            request: Some(request),
            response: Some(response),
        }
    }

    fn cert_der_pair(name: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
        let cert = generate_simple_self_signed(vec![name.to_string()]).unwrap();
        (
            vec![cert.serialize_der().unwrap()],
            cert.serialize_private_key_der(),
        )
    }

    fn ca_pem_der_pair(name: &str) -> (Vec<u8>, Vec<u8>) {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let cert = Certificate::from_params(params).unwrap();
        (
            cert.serialize_pem().unwrap().into_bytes(),
            cert.serialize_private_key_der(),
        )
    }

    async fn run_test_upstream(
        listener: TcpListener,
        cert_chain: Vec<Vec<u8>>,
        key_der: Vec<u8>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        let acceptor = build_tls_acceptor(&cert_chain, &key_der).unwrap();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else {
                        break;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let mut tls = match acceptor.accept(stream).await {
                            Ok(tls) => tls,
                            Err(_) => return,
                        };
                        let req = match read_http_message(&mut tls).await {
                            Ok(req) => req,
                            Err(_) => return,
                        };
                        let parsed = match parse_http_request(&req) {
                            Ok(parsed) => parsed,
                            Err(_) => return,
                        };
                        let (body, extra_header) = if parsed.path == "/external-secrets/external-secrets" {
                            ("ok", None)
                        } else if parsed.path == "/external-secrets/forbidden" {
                            ("forbidden", Some("X-Forbidden: 1\r\n"))
                        } else {
                            ("upstream", None)
                        };
                        let extra = extra_header.unwrap_or("");
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            extra,
                            body.len(),
                            body
                        );
                        let _ = tls.write_all(response.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    });
                }
            }
        }
    }

    async fn tls_get(addr: std::net::SocketAddr, host: &str, path: &str) -> Result<String, String> {
        let connector = build_insecure_tls_connector(Vec::new());
        let tcp = tokio::time::timeout(TLS_IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| "client connect timed out".to_string())?
            .map_err(|err| err.to_string())?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| "invalid host".to_string())?;
        let mut tls = tokio::time::timeout(TLS_IO_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| "client tls handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes())
            .await
            .map_err(|err| err.to_string())?;
        let mut out = Vec::new();
        tokio::time::timeout(TLS_IO_TIMEOUT, tls.read_to_end(&mut out))
            .await
            .map_err(|_| "client read timed out".to_string())?
            .map_err(|err| err.to_string())?;
        if out.is_empty() {
            return Err("empty response".to_string());
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }

    #[test]
    fn request_policy_matchers_apply_host_path_query() {
        let policy = intercept_http_policy();
        let raw = b"GET /external-secrets/external-secrets?ref=main HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
        let request = parse_http_request(raw).unwrap();
        assert!(request_allowed(policy.request.as_ref().unwrap(), &request));

        let raw = b"GET /moolen?ref=main HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
        let request = parse_http_request(raw).unwrap();
        assert!(!request_allowed(policy.request.as_ref().unwrap(), &request));

        let raw = b"GET /external-secrets/external-secrets HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
        let request = parse_http_request(raw).unwrap();
        assert!(!request_allowed(policy.request.as_ref().unwrap(), &request));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tls_intercept_runtime_enforces_request_policy() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
        let (upstream_shutdown_tx, upstream_shutdown_rx) = oneshot::channel();
        let upstream_task = tokio::spawn(run_test_upstream(
            upstream_listener,
            upstream_cert,
            upstream_key,
            upstream_shutdown_rx,
        ));

        let intercept_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let intercept_addr = intercept_listener.local_addr().unwrap();
        drop(intercept_listener);
        let (proxy_ca_cert_pem, proxy_ca_key_der) = ca_pem_der_pair("Intercept Test CA");
        let (startup_tx, startup_rx) = oneshot::channel();
        let policy = Arc::new(RwLock::new(intercept_http_snapshot(1)));
        let proxy_task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
            bind_addr: intercept_addr,
            upstream_override: Some(upstream_addr),
            intercept_ca_cert_pem: proxy_ca_cert_pem,
            intercept_ca_key_der: proxy_ca_key_der,
            metrics: Metrics::new().unwrap(),
            policy_snapshot: policy,
            intercept_demux: Arc::new(Mutex::new(SharedInterceptDemuxState::default())),
            startup_status_tx: Some(startup_tx),
        }));
        let startup = tokio::time::timeout(Duration::from_secs(2), startup_rx)
            .await
            .expect("proxy startup timeout")
            .expect("proxy startup dropped");
        startup.expect("proxy startup failed");

        let ok = tls_get(
            intercept_addr,
            "foo.allowed",
            "/external-secrets/external-secrets?ref=main",
        )
        .await
        .expect("allow request failed");
        assert!(
            ok.starts_with("HTTP/1.1 200"),
            "unexpected allow response: {ok}"
        );

        let denied = tls_get(intercept_addr, "foo.allowed", "/moolen?ref=main").await;
        assert!(denied.is_err(), "deny request unexpectedly succeeded");

        let denied_resp = tls_get(
            intercept_addr,
            "foo.allowed",
            "/external-secrets/forbidden?ref=main",
        )
        .await;
        assert!(
            denied_resp.is_err(),
            "response-policy deny unexpectedly succeeded"
        );

        proxy_task.abort();
        let _ = upstream_shutdown_tx.send(());
        let _ = upstream_task.await;
    }

    #[test]
    fn intercept_cert_resolver_caches_by_host() {
        let (ca_cert_pem, ca_key_der) = ca_pem_der_pair("Resolver Test CA");
        let resolver =
            InterceptLeafCertResolver::new(ca_cert_pem, ca_key_der, Duration::from_secs(60), 8)
                .unwrap();

        let first = resolver.resolve_server_name(Some("foo.allowed")).unwrap();
        let second = resolver.resolve_server_name(Some("foo.allowed")).unwrap();
        assert!(Arc::ptr_eq(&first, &second));

        let third = resolver.resolve_server_name(Some("bar.allowed")).unwrap();
        assert!(!Arc::ptr_eq(&first, &third));
    }

    #[test]
    fn lookup_intercept_demux_original_dst_returns_stored_tuple() {
        let demux = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));
        demux.lock().unwrap().upsert(
            Ipv4Addr::new(10, 0, 0, 42),
            40000,
            Ipv4Addr::new(203, 0, 113, 10),
            443,
        );
        let mapped =
            lookup_intercept_demux_original_dst(&demux, Ipv4Addr::new(10, 0, 0, 42), 40000)
                .expect("expected demux mapping");
        assert_eq!(mapped, "203.0.113.10:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn infer_intercept_original_dst_uses_unique_rule_target() {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 42), 32));
        let mut dst = IpSetV4::new();
        dst.add_cidr(CidrV4::new(Ipv4Addr::new(203, 0, 113, 10), 32));
        let rule = Rule {
            id: "intercept".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(dst),
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: Some(TlsMatch {
                    mode: TlsMode::Intercept,
                    sni: None,
                    server_san: None,
                    server_cn: None,
                    fingerprints_sha256: Vec::new(),
                    trust_anchors: Vec::new(),
                    tls13_uninspectable: Tls13Uninspectable::Deny,
                    intercept_http: Some(intercept_http_policy()),
                }),
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };
        let snapshot = PolicySnapshot::new(DefaultPolicy::Deny, vec![group]);
        let inferred = infer_intercept_original_dst(&snapshot, Ipv4Addr::new(10, 0, 0, 42))
            .expect("expected inferred intercept destination");
        assert_eq!(inferred, "203.0.113.10:443".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn infer_intercept_original_dst_rejects_ambiguous_targets() {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 42), 32));

        let mut dst_a = IpSetV4::new();
        dst_a.add_cidr(CidrV4::new(Ipv4Addr::new(203, 0, 113, 10), 32));
        let mut dst_b = IpSetV4::new();
        dst_b.add_cidr(CidrV4::new(Ipv4Addr::new(198, 51, 100, 8), 32));
        let rule_a = Rule {
            id: "intercept-a".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(dst_a),
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: vec![PortRange {
                    start: 443,
                    end: 443,
                }],
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: Some(TlsMatch {
                    mode: TlsMode::Intercept,
                    sni: None,
                    server_san: None,
                    server_cn: None,
                    fingerprints_sha256: Vec::new(),
                    trust_anchors: Vec::new(),
                    tls13_uninspectable: Tls13Uninspectable::Deny,
                    intercept_http: Some(intercept_http_policy()),
                }),
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let mut rule_b = rule_a.clone();
        rule_b.id = "intercept-b".to_string();
        rule_b.matcher.dst_ips = Some(dst_b);
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule_a, rule_b],
            default_action: None,
        };
        let snapshot = PolicySnapshot::new(DefaultPolicy::Deny, vec![group]);
        let inferred = infer_intercept_original_dst(&snapshot, Ipv4Addr::new(10, 0, 0, 42));
        assert!(inferred.is_none());
    }

    #[test]
    fn rule_line_matches_requires_all_fragments() {
        assert!(rule_line_matches(
            "10941: from 169.254.255.1 lookup 191",
            &["from 169.254.255.1", "lookup 191"],
        ));
        assert!(!rule_line_matches(
            "10941: from 169.254.255.1/32 lookup 191",
            &["from 169.254.255.1/32", "lookup 190"],
        ));
    }

    #[test]
    fn rule_line_matches_rejects_empty_lines() {
        assert!(!rule_line_matches("", &["lookup 191"]));
        assert!(!rule_line_matches("   ", &["lookup 191"]));
    }

    #[test]
    fn rule_line_matches_fwmark_reply_rule() {
        assert!(rule_line_matches(
            "10942: from all fwmark 0x2/0x2 lookup 191",
            &["fwmark 0x2", "lookup 191"],
        ));
    }

    #[test]
    fn intercept_tproxy_rule_args_include_expected_tuple_matches() {
        let rule = InterceptSteeringRule {
            src_cidr: CidrV4::new(Ipv4Addr::new(10, 20, 3, 0), 24),
            dst_cidr: Some(CidrV4::new(Ipv4Addr::new(10, 20, 4, 10), 32)),
            dst_port: Some(PortRange {
                start: 443,
                end: 443,
            }),
        };
        let args = intercept_tproxy_rule_args(&rule, Ipv4Addr::new(169, 254, 255, 1), 15443, 0x1);
        assert!(!args.iter().any(|arg| arg == "-i"));
        assert!(args.windows(2).any(|w| w == ["-s", "10.20.3.0/24"]));
        assert!(args.windows(2).any(|w| w == ["-d", "10.20.4.10/32"]));
        assert!(args.windows(2).any(|w| w == ["--dport", "443"]));
        assert!(args.windows(2).any(|w| w == ["--on-ip", "169.254.255.1"]));
        assert!(args.windows(2).any(|w| w == ["--on-port", "15443"]));
        assert!(args.windows(2).any(|w| w == ["--tproxy-mark", "0x1/0x1"]));
    }

    #[test]
    fn intercept_tproxy_rule_args_render_port_ranges() {
        let rule = InterceptSteeringRule {
            src_cidr: CidrV4::new(Ipv4Addr::new(10, 20, 3, 0), 24),
            dst_cidr: None,
            dst_port: Some(PortRange {
                start: 4000,
                end: 4010,
            }),
        };
        let args = intercept_tproxy_rule_args(&rule, Ipv4Addr::new(169, 254, 255, 1), 15443, 0x1);
        assert!(args.windows(2).any(|w| w == ["--dport", "4000:4010"]));
    }

    #[test]
    fn intercept_reply_mark_rule_args_include_expected_tuple_matches() {
        let rule = InterceptSteeringRule {
            src_cidr: CidrV4::new(Ipv4Addr::new(10, 20, 3, 0), 24),
            dst_cidr: Some(CidrV4::new(Ipv4Addr::new(10, 20, 4, 10), 32)),
            dst_port: Some(PortRange {
                start: 443,
                end: 443,
            }),
        };
        let args = intercept_reply_mark_rule_args(&rule, 0x2);
        assert!(args.windows(2).any(|w| w == ["-d", "10.20.3.0/24"]));
        assert!(args.windows(2).any(|w| w == ["-s", "10.20.4.10/32"]));
        assert!(args.windows(2).any(|w| w == ["--sport", "443"]));
        assert!(args.windows(2).any(|w| w == ["--set-xmark", "0x2/0x2"]));
    }
}
