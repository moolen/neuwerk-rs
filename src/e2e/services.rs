use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyUsagePurpose};
use reqwest::Client;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::controlplane::dns_proxy::extract_ips_from_dns_response;
use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
use crate::controlplane::policy_repository::{PolicyCreateRequest, PolicyRecord};
use crate::controlplane::service_accounts::{ServiceAccount, TokenMeta};

#[derive(Debug, Deserialize)]
pub struct AuthUser {
    pub sub: String,
    pub sa_id: Option<String>,
    pub exp: Option<i64>,
    pub roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub ips: Vec<Ipv4Addr>,
    pub last_seen: u64,
}

#[derive(Debug, Deserialize)]
pub struct DnsCacheResponse {
    pub entries: Vec<DnsCacheEntry>,
}

#[derive(Debug)]
pub struct UpstreamServices {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    pub dns_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    pub udp_echo_addr: SocketAddr,
    pub answer_ip: Ipv4Addr,
    pub answer_ip_alt: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub struct UpstreamTlsMaterial {
    pub ca_pem: Vec<u8>,
    pub cert_chain: Vec<Vec<u8>>,
    pub key_der: Vec<u8>,
}

pub fn generate_upstream_tls_material() -> Result<UpstreamTlsMaterial, String> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Upstream Test CA");
    let ca_cert = Certificate::from_params(ca_params).map_err(|e| format!("ca gen failed: {e}"))?;
    let ca_pem = ca_cert
        .serialize_pem()
        .map_err(|e| format!("ca pem failed: {e}"))?
        .into_bytes();
    let ca_der = ca_cert
        .serialize_der()
        .map_err(|e| format!("ca der failed: {e}"))?;

    let mut leaf_params = CertificateParams::new(vec!["foo.allowed".to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "foo.allowed");
    let leaf_cert =
        Certificate::from_params(leaf_params).map_err(|e| format!("leaf gen failed: {e}"))?;
    let leaf_der = leaf_cert
        .serialize_der_with_signer(&ca_cert)
        .map_err(|e| format!("leaf der failed: {e}"))?;
    let key_der = leaf_cert.serialize_private_key_der();

    Ok(UpstreamTlsMaterial {
        ca_pem,
        cert_chain: vec![leaf_der, ca_der],
        key_der,
    })
}

impl UpstreamServices {
    pub fn start(
        ns: netns_rs::NetNs,
        dns_addr: SocketAddr,
        http_addr: SocketAddr,
        https_addr: SocketAddr,
        udp_echo_addr: SocketAddr,
        answer_ip: Ipv4Addr,
        answer_ip_alt: Ipv4Addr,
        tls: UpstreamTlsMaterial,
    ) -> Result<Self, String> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = ns.run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async move {
                    let dns_task = tokio::spawn(run_dns_server(dns_addr, answer_ip, answer_ip_alt));
                    let http_task = tokio::spawn(run_http_server(http_addr));
                    let http_task_alt =
                        tokio::spawn(run_http_server((answer_ip_alt, http_addr.port()).into()));
                    let https_task = tokio::spawn(run_https_server(https_addr, tls.clone()));
                    let https_task_alt = tokio::spawn(run_https_server(
                        (answer_ip_alt, https_addr.port()).into(),
                        tls.clone(),
                    ));
                    let udp_task = tokio::spawn(run_udp_echo_server(udp_echo_addr));
                    let udp_task_alt = tokio::spawn(run_udp_echo_server(
                        (answer_ip_alt, udp_echo_addr.port()).into(),
                    ));

                    let _ = shutdown_rx.await;
                    dns_task.abort();
                    http_task.abort();
                    http_task_alt.abort();
                    https_task.abort();
                    https_task_alt.abort();
                    udp_task.abort();
                    udp_task_alt.abort();
                    Ok::<(), String>(())
                })
            });
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            dns_addr,
            http_addr,
            https_addr,
            udp_echo_addr,
            answer_ip,
            answer_ip_alt,
        })
    }
}

impl Drop for UpstreamServices {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run_dns_server(
    bind: SocketAddr,
    answer_ip: Ipv4Addr,
    answer_ip_alt: Ipv4Addr,
) -> Result<(), String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("dns bind failed: {e}"))?;
    let mut buf = vec![0u8; 512];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("dns recv failed: {e}"))?;
        let request = &buf[..len];
        let response = build_dns_response(request, answer_ip, answer_ip_alt);
        if let Some(resp) = response {
            socket
                .send_to(&resp, peer)
                .await
                .map_err(|e| format!("dns send failed: {e}"))?;
        }
    }
}

fn build_dns_response(
    request: &[u8],
    answer_ip: Ipv4Addr,
    answer_ip_alt: Ipv4Addr,
) -> Option<Vec<u8>> {
    if request.len() < 12 {
        return None;
    }
    let mut idx = 12;
    let name = parse_qname(request, &mut idx)?;
    let name_norm = name.to_ascii_lowercase();
    if idx + 4 > request.len() {
        return None;
    }
    let qdcount = request[4..6].to_vec();
    let qsection = &request[12..idx + 4];

    let mut resp = Vec::new();
    if name_norm == "spoof.allowed" {
        resp.extend_from_slice(&[0x33, 0x44]); // mismatched transaction ID
    } else {
        resp.extend_from_slice(&request[0..2]); // transaction ID
    }
    if matches_allowed_name(&name_norm) {
        resp.extend_from_slice(&[0x81, 0x80]); // standard response
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x01]); // ancount
    } else {
        resp.extend_from_slice(&[0x81, 0x83]); // NXDOMAIN
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x00]); // ancount
    }
    resp.extend_from_slice(&[0x00, 0x00]); // nscount
    resp.extend_from_slice(&[0x00, 0x00]); // arcount
    resp.extend_from_slice(qsection);

    if matches_allowed_name(&name_norm) {
        let response_ip = if name_norm == "cluster.allowed" {
            answer_ip_alt
        } else {
            answer_ip
        };
        resp.extend_from_slice(&[0xc0, 0x0c]); // name ptr
        resp.extend_from_slice(&[0x00, 0x01]); // type A
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // ttl 30
        resp.extend_from_slice(&[0x00, 0x04]); // rdlen
        resp.extend_from_slice(&response_ip.octets());
    }
    Some(resp)
}

fn matches_allowed_name(name: &str) -> bool {
    matches!(
        name,
        "foo.allowed"
            | "bar.allowed"
            | "baz.allowed"
            | "cluster.allowed"
            | "spoof.allowed"
            | "api.example.com"
            | "very.long.subdomain.name.example.com"
    )
}

fn parse_qname(buf: &[u8], idx: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    while *idx < buf.len() {
        let len = buf[*idx] as usize;
        *idx += 1;
        if len == 0 {
            return Some(labels.join("."));
        }
        if *idx + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[*idx..*idx + len]).to_string());
        *idx += len;
    }
    None
}

async fn run_http_server(bind: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("http bind failed: {e}"))?;
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("http accept failed: {e}"))?;
        tokio::spawn(async move {
            let _ = handle_http(&mut stream, peer).await;
        });
    }
}

async fn run_udp_echo_server(bind: SocketAddr) -> Result<(), String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("udp echo bind failed: {e}"))?;
    let mut buf = vec![0u8; 2048];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("udp echo recv failed: {e}"))?;
        socket
            .send_to(&buf[..len], peer)
            .await
            .map_err(|e| format!("udp echo send failed: {e}"))?;
    }
}

async fn run_https_server(bind: SocketAddr, tls: UpstreamTlsMaterial) -> Result<(), String> {
    ensure_rustls_provider();
    let cert_chain: Vec<CertificateDer<'static>> = tls
        .cert_chain
        .into_iter()
        .map(|cert| CertificateDer::from(cert).into_owned())
        .collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.key_der));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| format!("tls server config failed: {e}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("https bind failed: {e}"))?;
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("https accept failed: {e}"))?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = handle_http(&mut tls, peer).await;
            }
        });
    }
}

async fn handle_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
) -> Result<(), String> {
    let mut buf = [0u8; 1024];
    let read = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..read]);
    let mut parts = req.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if path == "/stream" || path == "/stream-long" {
        let chunk = vec![b'x'; 256];
        let chunks = if path == "/stream-long" {
            60usize
        } else {
            20usize
        };
        let total_len = chunk.len() * chunks;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            total_len
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        for _ in 0..chunks {
            stream.write_all(&chunk).await.map_err(|e| e.to_string())?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = stream.shutdown().await;
        return Ok(());
    }

    if path == "/whoami" {
        let body = peer.ip().to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let body_string;
    let body = if let Some(rest) = path.strip_prefix("/echo/") {
        body_string = rest.to_string();
        body_string.as_bytes()
    } else {
        b"ok"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;
    let _ = stream.shutdown().await;
    Ok(())
}

pub async fn dns_query(
    bind: SocketAddr,
    server: SocketAddr,
    name: &str,
) -> Result<Vec<IpAddr>, String> {
    Ok(dns_query_response(bind, server, name).await?.ips)
}

#[derive(Debug)]
pub struct DnsResponse {
    pub ips: Vec<IpAddr>,
    pub rcode: u8,
}

pub async fn dns_query_response(
    bind: SocketAddr,
    server: SocketAddr,
    name: &str,
) -> Result<DnsResponse, String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("dns client bind failed: {e}"))?;
    let query = build_dns_query(name);
    socket
        .send_to(&query, server)
        .await
        .map_err(|e| format!("dns client send failed: {e}"))?;
    let mut buf = vec![0u8; 512];
    let (len, _) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|e| format!("dns client recv failed: {e}"))?;
    let rcode = parse_rcode(&buf[..len]);
    Ok(DnsResponse {
        ips: extract_ips_from_dns_response(&buf[..len]),
        rcode,
    })
}

fn parse_rcode(msg: &[u8]) -> u8 {
    if msg.len() < 4 {
        return 0;
    }
    msg[3] & 0x0f
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x12, 0x34]); // id
    msg.extend_from_slice(&[0x01, 0x00]); // flags
    msg.extend_from_slice(&[0x00, 0x01]); // qdcount
    msg.extend_from_slice(&[0x00, 0x00]); // ancount
    msg.extend_from_slice(&[0x00, 0x00]); // nscount
    msg.extend_from_slice(&[0x00, 0x00]); // arcount
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01]); // qtype A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass IN
    msg
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

pub async fn http_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    http_get_path(addr, host, "/").await
}

pub async fn http_get_path(addr: SocketAddr, host: &str, path: &str) -> Result<String, String> {
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
            .await
            .map_err(|_| "http connect timed out".to_string())?
            .map_err(|e| format!("http connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("http read failed: {e}"))?;
    let text = String::from_utf8_lossy(&buf).to_string();
    Ok(text)
}

pub async fn http_api_health(addr: SocketAddr, tls_dir: &Path) -> Result<(), String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .get(format!("https://{addr}/health"))
        .send()
        .await
        .map_err(|e| format!("health request failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("health status {}", resp.status()))
    }
}

pub async fn http_api_status(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client.get(format!("https://{addr}{path}"));
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("api status request failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_auth_token_login(
    addr: SocketAddr,
    tls_dir: &Path,
    token: &str,
) -> Result<AuthUser, String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .post(format!("https://{addr}/api/v1/auth/token-login"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|e| format!("auth token-login failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("auth token-login status {}", resp.status()));
    }
    resp.json::<AuthUser>()
        .await
        .map_err(|e| format!("auth token-login decode failed: {e}"))
}

pub async fn http_auth_whoami(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: &str,
) -> Result<AuthUser, String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .get(format!("https://{addr}/api/v1/auth/whoami"))
        .bearer_auth(auth_token)
        .send()
        .await
        .map_err(|e| format!("auth whoami failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("auth whoami status {}", resp.status()));
    }
    resp.json::<AuthUser>()
        .await
        .map_err(|e| format!("auth whoami decode failed: {e}"))
}

pub async fn http_wait_for_health(
    addr: SocketAddr,
    tls_dir: &Path,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match http_api_health(addr, tls_dir).await {
            Ok(()) => return Ok(()),
            Err(_) => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for http api health".to_string());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub async fn http_set_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy: PolicyConfig,
    mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let req = PolicyCreateRequest { mode, policy };
    let mut builder = client
        .post(format!("https://{addr}/api/v1/policies"))
        .json(&req);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy post failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy post status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy decode failed: {e}"))
}

pub async fn http_list_policies(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Vec<PolicyRecord>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policies"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy list status {}", resp.status()));
    }
    resp.json::<Vec<PolicyRecord>>()
        .await
        .map_err(|e| format!("policy list decode failed: {e}"))
}

pub async fn http_get_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policies/{policy_id}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy get failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy get status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy get decode failed: {e}"))
}

pub async fn http_update_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    policy: PolicyConfig,
    mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let req = PolicyCreateRequest { mode, policy };
    let mut builder = client
        .put(format!("https://{addr}/api/v1/policies/{policy_id}"))
        .json(&req);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy update failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy update status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy update decode failed: {e}"))
}

pub async fn http_delete_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!("https://{addr}/api/v1/policies/{policy_id}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy delete failed: {e}"))?;
    Ok(resp.status())
}

#[derive(Debug, Deserialize)]
pub struct ServiceAccountTokenResponse {
    pub token: String,
    pub token_meta: TokenMeta,
}

#[derive(Serialize)]
struct ServiceAccountCreateRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Serialize)]
struct ServiceAccountTokenCreateRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eternal: Option<bool>,
}

pub async fn http_create_service_account(
    addr: SocketAddr,
    tls_dir: &Path,
    name: &str,
    description: Option<&str>,
    auth_token: Option<&str>,
) -> Result<ServiceAccount, String> {
    let client = http_api_client(tls_dir)?;
    let payload = ServiceAccountCreateRequest { name, description };
    let mut builder = client
        .post(format!("https://{addr}/api/v1/service-accounts"))
        .json(&payload);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account create failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("service account create status {}", resp.status()));
    }
    resp.json::<ServiceAccount>()
        .await
        .map_err(|e| format!("service account decode failed: {e}"))
}

pub async fn http_list_service_accounts(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Vec<ServiceAccount>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/service-accounts"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("service account list status {}", resp.status()));
    }
    resp.json::<Vec<ServiceAccount>>()
        .await
        .map_err(|e| format!("service account list decode failed: {e}"))
}

pub async fn http_delete_service_account(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account delete failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_create_service_account_token(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    name: Option<&str>,
    ttl: Option<&str>,
    eternal: Option<bool>,
    auth_token: Option<&str>,
) -> Result<ServiceAccountTokenResponse, String> {
    let client = http_api_client(tls_dir)?;
    let payload = ServiceAccountTokenCreateRequest { name, ttl, eternal };
    let mut builder = client
        .post(format!(
            "https://{addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .json(&payload);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token create failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "service account token create status {}",
            resp.status()
        ));
    }
    resp.json::<ServiceAccountTokenResponse>()
        .await
        .map_err(|e| format!("service account token decode failed: {e}"))
}

pub async fn http_list_service_account_tokens(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    auth_token: Option<&str>,
) -> Result<Vec<TokenMeta>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}/tokens"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "service account token list status {}",
            resp.status()
        ));
    }
    resp.json::<Vec<TokenMeta>>()
        .await
        .map_err(|e| format!("service account token list decode failed: {e}"))
}

pub async fn http_revoke_service_account_token(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    token_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}/tokens/{token_id}"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token revoke failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_get_dns_cache(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<DnsCacheResponse, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/dns-cache"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("dns cache request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("dns cache status {}", resp.status()));
    }
    resp.json::<DnsCacheResponse>()
        .await
        .map_err(|e| format!("dns cache decode failed: {e}"))
}

pub async fn http_get_stats(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Value, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/stats"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("stats request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("stats status {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("stats decode failed: {e}"))
}

fn http_api_client(tls_dir: &Path) -> Result<Client, String> {
    let ca = std::fs::read(tls_dir.join("ca.crt"))
        .map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca =
        reqwest::Certificate::from_pem(&ca).map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

pub fn http_api_client_with_cookie(tls_dir: &Path) -> Result<Client, String> {
    let ca = std::fs::read(tls_dir.join("ca.crt"))
        .map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca =
        reqwest::Certificate::from_pem(&ca).map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .cookie_store(true)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

pub async fn http_api_post_raw(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    body: Vec<u8>,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client
        .post(format!("https://{addr}{path}"))
        .header("content-type", "application/json")
        .body(body);
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("api post request failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_stream(
    addr: SocketAddr,
    host: &str,
    min_duration: std::time::Duration,
    max_duration: std::time::Duration,
) -> Result<usize, String> {
    http_stream_path(addr, host, "/stream", min_duration, max_duration).await
}

pub async fn http_stream_path(
    addr: SocketAddr,
    host: &str,
    path: &str,
    min_duration: std::time::Duration,
    max_duration: std::time::Duration,
) -> Result<usize, String> {
    let mut stream = tokio::time::timeout(max_duration, TcpStream::connect(addr))
        .await
        .map_err(|_| "http stream connect timed out".to_string())?
        .map_err(|e| format!("http stream connect failed: {e}"))?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http stream write failed: {e}"))?;

    let start = std::time::Instant::now();
    let read_result = tokio::time::timeout(max_duration, async {
        let mut buf = [0u8; 512];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok::<usize, String>(total)
    })
    .await;

    let total = match read_result {
        Ok(Ok(total)) => total,
        Ok(Err(err)) => return Err(format!("http stream read failed: {err}")),
        Err(_) => return Err("http stream timed out".to_string()),
    };

    if start.elapsed() < min_duration {
        return Err(format!(
            "http stream ended too early after {:?}",
            start.elapsed()
        ));
    }

    Ok(total)
}

pub async fn https_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path(addr, host, "/").await
}

pub async fn https_get_path(addr: SocketAddr, host: &str, path: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, path, None).await
}

pub async fn https_get_tls12(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, "/", Some(&[&rustls::version::TLS12])).await
}

pub async fn https_get_tls13(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, "/", Some(&[&rustls::version::TLS13])).await
}

async fn https_get_path_with_versions(
    addr: SocketAddr,
    host: &str,
    path: &str,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> Result<String, String> {
    ensure_rustls_provider();
    let builder = match versions {
        Some(versions) => rustls::ClientConfig::builder_with_protocol_versions(versions),
        None => rustls::ClientConfig::builder(),
    };
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "https connect timed out".to_string())?
        .map_err(|e| format!("https connect failed: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "tls connect timed out".to_string())?
    .map_err(|e| format!("tls connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("https write failed: {e}"))?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut buf))
        .await
        .map_err(|_| "https read timed out".to_string())?
        .map_err(|e| format!("https read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub async fn tls_client_hello_raw(
    addr: SocketAddr,
    sni: &str,
    padding_len: usize,
) -> Result<usize, String> {
    ensure_rustls_provider();
    let mut stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "tls raw connect timed out".to_string())?
        .map_err(|e| format!("tls raw connect failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    let record = build_client_hello_record(sni, padding_len)?;

    let mut offset = 0usize;
    let chunk = 1024usize;
    while offset < record.len() {
        let end = (offset + chunk).min(record.len());
        stream
            .write_all(&record[offset..end])
            .await
            .map_err(|e| format!("tls raw write failed: {e}"))?;
        offset = end;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let mut buf = vec![0u8; 2048];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| "tls raw read timed out".to_string())?
        .map_err(|e| format!("tls raw read failed: {e}"))?;
    Ok(read)
}

pub async fn udp_echo(
    bind: SocketAddr,
    server: SocketAddr,
    payload: &[u8],
    timeout: std::time::Duration,
) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("udp client bind failed: {e}"))?;
    socket
        .send_to(payload, server)
        .await
        .map_err(|e| format!("udp client send failed: {e}"))?;
    let mut buf = vec![0u8; payload.len().max(2048)];
    let (len, _) = tokio::time::timeout(timeout, socket.recv_from(&mut buf))
        .await
        .map_err(|_| "udp client recv timed out".to_string())?
        .map_err(|e| format!("udp client recv failed: {e}"))?;
    Ok(buf[..len].to_vec())
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn build_client_hello_record(sni: &str, padding_len: usize) -> Result<Vec<u8>, String> {
    let sni_bytes = sni.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    if padding_len > 0 {
        if padding_len > u16::MAX as usize {
            return Err("padding too large".to_string());
        }
        extensions.extend_from_slice(&0x0015u16.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; padding_len]);
    }

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.push(((body.len() >> 16) & 0xff) as u8);
    handshake.push(((body.len() >> 8) & 0xff) as u8);
    handshake.push((body.len() & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}
