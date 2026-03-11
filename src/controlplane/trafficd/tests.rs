use super::*;
use crate::controlplane::cluster::bootstrap::ca::encrypt_ca_key;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::intercept_tls::{
    InterceptCaSource, INTERCEPT_CA_CERT_KEY, INTERCEPT_CA_ENVELOPE_KEY,
};
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, EnforcementMode, HttpPathMatcher, HttpQueryMatcher, HttpRequestPolicy,
    HttpResponsePolicy, HttpStringMatcher, IpSetV4, PortRange, Proto, Rule, RuleAction, RuleMatch,
    SourceGroup, Tls13Uninspectable, TlsInterceptHttpPolicy, TlsMatch,
};
use openraft::entry::EntryPayload;
use openraft::storage::RaftStateMachine;
use openraft::{CommittedLeaderId, Entry, LogId};
use rcgen::{
    generate_simple_self_signed, BasicConstraints, Certificate, CertificateParams, DnType, IsCa,
    KeyUsagePurpose,
};
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn cluster_put_entry(index: u64, key: &[u8], value: &[u8]) -> Entry<ClusterTypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
        payload: EntryPayload::Normal(ClusterCommand::Put {
            key: key.to_vec(),
            value: value.to_vec(),
        }),
    }
}

async fn put_cluster_state(store: &mut ClusterStore, index: u64, key: &[u8], value: &[u8]) {
    store
        .apply(vec![cluster_put_entry(index, key, value)])
        .await
        .unwrap();
}

fn write_token_file(dir: &TempDir, kid: &str, token: &[u8]) -> std::path::PathBuf {
    let path = dir.path().join("token.json");
    let raw = serde_json::json!({
        "tokens": [
            {
                "kid": kid,
                "token": format!("hex:{}", hex::encode(token)),
            }
        ]
    });
    fs::write(&path, serde_json::to_vec(&raw).unwrap()).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

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

fn intercept_h2_passthrough_snapshot(generation: u64) -> PolicySnapshot {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(127, 0, 0, 0), 8));
    let rule = Rule {
        id: "intercept-h2-passthrough".to_string(),
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
    assert_eq!(applied.load(Ordering::Acquire), 2);

    ca_ready.store(true, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(applied.load(Ordering::Acquire), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn observer_retracts_intercept_generation_when_runtime_unready() {
    let snapshot = Arc::new(RwLock::new(intercept_snapshot(5)));
    let applied = Arc::new(AtomicU64::new(0));
    let ca_ready = Arc::new(AtomicBool::new(true));
    let intercept_ready = Arc::new(AtomicBool::new(true));
    spawn_service_policy_observer(snapshot, applied.clone(), ca_ready, intercept_ready.clone());

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(applied.load(Ordering::Acquire), 5);

    intercept_ready.store(false, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(applied.load(Ordering::Acquire), 4);

    intercept_ready.store(true, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(applied.load(Ordering::Acquire), 5);
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_fails_closed_when_cluster_intercept_ca_cannot_be_loaded() {
    let dir = TempDir::new().unwrap();
    let mut store = ClusterStore::open(dir.path().join("raft")).unwrap();
    let token = b"cluster-secret";
    let token_path = write_token_file(&dir, "kid-1", token);
    let (cert_pem, _cert_key_der) = ca_pem_der_pair("Neuwerk Broken Cluster Cert");
    let (_other_cert_pem, envelope_key_der) = ca_pem_der_pair("Neuwerk Broken Cluster Key");
    let envelope = encrypt_ca_key("kid-1", token, &envelope_key_der).unwrap();
    let encoded = bincode::serialize(&envelope).unwrap();
    put_cluster_state(&mut store, 1, INTERCEPT_CA_CERT_KEY, &cert_pem).await;
    put_cluster_state(&mut store, 2, INTERCEPT_CA_ENVELOPE_KEY, &encoded).await;

    let policy_snapshot = Arc::new(RwLock::new(intercept_snapshot(1)));
    let ca_ready = Arc::new(AtomicBool::new(true));
    let ca_generation = Arc::new(AtomicU64::new(0));
    let intercept_ready = Arc::new(AtomicBool::new(true));
    let intercept_demux = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));

    spawn_tls_intercept_supervisor(
        policy_snapshot,
        ca_ready,
        ca_generation,
        InterceptCaSource::Cluster { store, token_path },
        intercept_ready.clone(),
        "127.0.0.1:0".parse().unwrap(),
        false,
        "data0".to_string(),
        intercept_demux,
        Metrics::new().unwrap(),
    );

    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !intercept_ready.load(Ordering::Acquire),
        "broken cluster CA material must fail intercept readiness closed"
    );
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
                    let req = match http_match::read_http_message(&mut tls).await {
                        Ok(req) => req,
                        Err(_) => return,
                    };
                    let parsed = match http_match::parse_http_request(&req) {
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
    let connector = upstream_tls::build_insecure_tls_connector(Vec::new());
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

async fn tls_h1_get_with_headers(
    addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<String, String> {
    let connector = upstream_tls::build_insecure_tls_connector(Vec::new());
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
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
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

async fn tls_h2_post(
    addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, usize), String> {
    let io_timeout = Duration::from_secs(10);
    let connector = upstream_tls::build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let tcp = tokio::time::timeout(io_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "client connect timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid host".to_string())?;
    let tls = tokio::time::timeout(io_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client tls handshake timed out".to_string())?
        .map_err(|err| err.to_string())?;

    let (mut send_request, connection) =
        tokio::time::timeout(io_timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "client h2 handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("host", host)
        .body(())
        .map_err(|err| format!("build h2 request failed: {err}"))?;
    let (response_fut, mut stream) = send_request
        .send_request(request, body.is_empty())
        .map_err(|err| format!("h2 send request failed: {err}"))?;

    if !body.is_empty() {
        let mut offset = 0usize;
        while offset < body.len() {
            let end = (offset + 16 * 1024).min(body.len());
            stream
                .send_data(
                    Bytes::copy_from_slice(&body[offset..end]),
                    end == body.len(),
                )
                .map_err(|err| format!("h2 send body failed: {err}"))?;
            offset = end;
        }
    }

    let response = tokio::time::timeout(io_timeout, response_fut)
        .await
        .map_err(|_| "h2 response timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let (_parts, mut response_body) = response.into_parts();
    let mut response_len = 0usize;
    while let Some(next) = tokio::time::timeout(io_timeout, response_body.data())
        .await
        .map_err(|_| "h2 response body timed out".to_string())?
    {
        let chunk = next.map_err(|err| err.to_string())?;
        response_len = response_len.saturating_add(chunk.len());
        response_body
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| format!("h2 response flow-control release failed: {err}"))?;
    }
    Ok((status, response_len))
}

async fn tls_h2_get_with_headers(
    addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, usize), String> {
    let io_timeout = Duration::from_secs(10);
    let connector = upstream_tls::build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let tcp = tokio::time::timeout(io_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "client connect timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid host".to_string())?;
    let tls = tokio::time::timeout(io_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client tls handshake timed out".to_string())?
        .map_err(|err| err.to_string())?;

    let (mut send_request, connection) =
        tokio::time::timeout(io_timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "client h2 handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut request_builder = axum::http::Request::builder().method("GET").uri(path);
    request_builder = request_builder.header("host", host);
    for (name, value) in headers {
        request_builder = request_builder.header(*name, *value);
    }
    let request = request_builder
        .body(())
        .map_err(|err| format!("build h2 request failed: {err}"))?;

    let (response_fut, _stream) = send_request
        .send_request(request, true)
        .map_err(|err| format!("h2 send request failed: {err}"))?;
    let response = tokio::time::timeout(io_timeout, response_fut)
        .await
        .map_err(|_| "h2 response timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let (_parts, mut response_body) = response.into_parts();
    let mut response_len = 0usize;
    while let Some(next) = tokio::time::timeout(io_timeout, response_body.data())
        .await
        .map_err(|_| "h2 response body timed out".to_string())?
    {
        let chunk = next.map_err(|err| err.to_string())?;
        response_len = response_len.saturating_add(chunk.len());
        response_body
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| format!("h2 response flow-control release failed: {err}"))?;
    }
    Ok((status, response_len))
}

async fn tls_h2_get_many_concurrent(
    addr: std::net::SocketAddr,
    host: &str,
    path: &str,
    stream_count: usize,
) -> Result<Vec<u16>, String> {
    let io_timeout = Duration::from_secs(10);
    let connector = upstream_tls::build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let tcp = tokio::time::timeout(io_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "client connect timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid host".to_string())?;
    let tls = tokio::time::timeout(io_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client tls handshake timed out".to_string())?
        .map_err(|err| err.to_string())?;

    let (mut send_request, connection) =
        tokio::time::timeout(io_timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "client h2 handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut response_futs = Vec::with_capacity(stream_count);
    for _ in 0..stream_count {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(path)
            .header("host", host)
            .body(())
            .map_err(|err| format!("build h2 request failed: {err}"))?;
        let (response_fut, _stream) = send_request
            .send_request(request, true)
            .map_err(|err| format!("h2 send request failed: {err}"))?;
        response_futs.push(response_fut);
    }

    let mut statuses = Vec::with_capacity(stream_count);
    for response_fut in response_futs {
        let response = tokio::time::timeout(io_timeout, response_fut)
            .await
            .map_err(|_| "h2 response timed out".to_string())?
            .map_err(|err| err.to_string())?;
        statuses.push(response.status().as_u16());
        let (_parts, mut response_body) = response.into_parts();
        while let Some(next) = tokio::time::timeout(io_timeout, response_body.data())
            .await
            .map_err(|_| "h2 response body timed out".to_string())?
        {
            let chunk = next.map_err(|err| err.to_string())?;
            response_body
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|err| format!("h2 response flow-control release failed: {err}"))?;
        }
    }
    Ok(statuses)
}

async fn tls_h2_request_with_headers(
    addr: std::net::SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, usize, Option<String>), String> {
    let io_timeout = Duration::from_secs(10);
    let connector = upstream_tls::build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let tcp = tokio::time::timeout(io_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "client connect timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid host".to_string())?;
    let tls = tokio::time::timeout(io_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client tls handshake timed out".to_string())?
        .map_err(|err| err.to_string())?;

    let (mut send_request, connection) =
        tokio::time::timeout(io_timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "client h2 handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = axum::http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(())
        .map_err(|err| format!("build h2 request failed: {err}"))?;

    let (response_fut, _stream) = send_request
        .send_request(request, true)
        .map_err(|err| format!("h2 send request failed: {err}"))?;
    let response = tokio::time::timeout(io_timeout, response_fut)
        .await
        .map_err(|_| "h2 response timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let (_parts, mut response_body) = response.into_parts();
    let mut response_len = 0usize;
    while let Some(next) = tokio::time::timeout(io_timeout, response_body.data())
        .await
        .map_err(|_| "h2 response body timed out".to_string())?
    {
        let chunk = next.map_err(|err| err.to_string())?;
        response_len = response_len.saturating_add(chunk.len());
        response_body
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| format!("h2 response flow-control release failed: {err}"))?;
    }
    Ok((status, response_len, location))
}

async fn tls_h2_get_paths_same_conn(
    addr: std::net::SocketAddr,
    host: &str,
    paths: &[&str],
) -> Result<Vec<Result<u16, String>>, String> {
    let io_timeout = Duration::from_secs(10);
    let connector = upstream_tls::build_insecure_tls_connector(vec![b"h2".to_vec()]);
    let tcp = tokio::time::timeout(io_timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| "client connect timed out".to_string())?
        .map_err(|err| err.to_string())?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid host".to_string())?;
    let tls = tokio::time::timeout(io_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_| "client tls handshake timed out".to_string())?
        .map_err(|err| err.to_string())?;

    let (mut send_request, connection) =
        tokio::time::timeout(io_timeout, h2::client::handshake(tls))
            .await
            .map_err(|_| "client h2 handshake timed out".to_string())?
            .map_err(|err| err.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut response_futs = Vec::with_capacity(paths.len());
    for path in paths {
        let request = axum::http::Request::builder()
            .method("GET")
            .uri(*path)
            .header("host", host)
            .body(())
            .map_err(|err| format!("build h2 request failed: {err}"))?;
        let (response_fut, _stream) = send_request
            .send_request(request, true)
            .map_err(|err| format!("h2 send request failed: {err}"))?;
        response_futs.push(response_fut);
    }

    let mut out = Vec::with_capacity(paths.len());
    for response_fut in response_futs {
        match tokio::time::timeout(io_timeout, response_fut).await {
            Ok(Ok(response)) => {
                let status = response.status().as_u16();
                let (_parts, mut response_body) = response.into_parts();
                let mut body_err: Option<String> = None;
                while let Some(next) = tokio::time::timeout(io_timeout, response_body.data())
                    .await
                    .map_err(|_| "h2 response body timed out".to_string())?
                {
                    match next {
                        Ok(chunk) => {
                            if let Err(err) =
                                response_body.flow_control().release_capacity(chunk.len())
                            {
                                body_err =
                                    Some(format!("h2 response flow-control release failed: {err}"));
                                break;
                            }
                        }
                        Err(err) => {
                            body_err = Some(err.to_string());
                            break;
                        }
                    }
                }
                if let Some(err) = body_err {
                    out.push(Err(err));
                } else {
                    out.push(Ok(status));
                }
            }
            Ok(Err(err)) => out.push(Err(err.to_string())),
            Err(_) => out.push(Err("h2 response timed out".to_string())),
        }
    }
    Ok(out)
}

fn update_peak(peak: &AtomicUsize, candidate: usize) {
    let mut prev = peak.load(Ordering::Acquire);
    while candidate > prev {
        match peak.compare_exchange(prev, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(observed) => prev = observed,
        }
    }
}

async fn spawn_intercept_runtime_with_policy(
    snapshot: PolicySnapshot,
    upstream_addr: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<Result<(), String>>,
) {
    let intercept_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intercept_addr = intercept_listener.local_addr().unwrap();
    drop(intercept_listener);
    let (proxy_ca_cert_pem, proxy_ca_key_der) = ca_pem_der_pair("Intercept Test CA");
    let (startup_tx, startup_rx) = oneshot::channel();
    let policy = Arc::new(RwLock::new(snapshot));
    let proxy_task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
        bind_addr: intercept_addr,
        upstream_override: Some(upstream_addr),
        upstream_tls_insecure: true,
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
    (intercept_addr, proxy_task)
}

#[test]
fn request_policy_matchers_apply_host_path_query() {
    let policy = intercept_http_policy();
    let raw =
        b"GET /external-secrets/external-secrets?ref=main HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
    let request = http_match::parse_http_request(raw).unwrap();
    assert!(http_match::request_allowed(
        policy.request.as_ref().unwrap(),
        &request
    ));

    let raw = b"GET /moolen?ref=main HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
    let request = http_match::parse_http_request(raw).unwrap();
    assert!(!http_match::request_allowed(
        policy.request.as_ref().unwrap(),
        &request
    ));

    let raw = b"GET /external-secrets/external-secrets HTTP/1.1\r\nHost: foo.allowed\r\n\r\n";
    let request = http_match::parse_http_request(raw).unwrap();
    assert!(!http_match::request_allowed(
        policy.request.as_ref().unwrap(),
        &request
    ));
}

#[test]
fn request_for_upstream_h2_forwards_client_headers() {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/external-secrets/external-secrets")
        .header("host", "github.com")
        .header("accept", "application/json")
        .header("x-requested-with", "XMLHttpRequest")
        .header("connection", "keep-alive")
        .header("proxy-connection", "keep-alive")
        .body(())
        .unwrap();

    let upstream = http_match::request_for_upstream_h2(
        "GET",
        "/external-secrets/external-secrets",
        "github.com",
        request.headers(),
    )
    .unwrap();

    assert_eq!(
        upstream
            .headers()
            .get("accept")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        upstream
            .headers()
            .get("x-requested-with")
            .and_then(|value| value.to_str().ok()),
        Some("XMLHttpRequest")
    );
    assert!(
        upstream.headers().get("connection").is_none(),
        "hop-by-hop connection header must be stripped"
    );
    assert!(
        upstream.headers().get("proxy-connection").is_none(),
        "hop-by-hop proxy-connection header must be stripped"
    );
}

#[test]
fn upstream_tls_verify_mode_parsing_defaults_to_strict() {
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(None),
        upstream_tls::UpstreamTlsVerificationMode::Strict
    );
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(Some("strict")),
        upstream_tls::UpstreamTlsVerificationMode::Strict
    );
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(Some("STRICT")),
        upstream_tls::UpstreamTlsVerificationMode::Strict
    );
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(Some("unexpected")),
        upstream_tls::UpstreamTlsVerificationMode::Strict
    );
}

#[test]
fn upstream_tls_verify_mode_parsing_accepts_insecure() {
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(Some("insecure")),
        upstream_tls::UpstreamTlsVerificationMode::Insecure
    );
    assert_eq!(
        upstream_tls::parse_upstream_tls_verify_mode(Some("INSECURE")),
        upstream_tls::UpstreamTlsVerificationMode::Insecure
    );
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
        upstream_tls_insecure: true,
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

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_audit_mode_allows_policy_denies() {
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
    let mut snapshot = intercept_http_snapshot(2);
    snapshot.set_enforcement_mode(EnforcementMode::Audit);
    let policy = Arc::new(RwLock::new(snapshot));
    let proxy_task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
        bind_addr: intercept_addr,
        upstream_override: Some(upstream_addr),
        upstream_tls_insecure: true,
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

    let request_audit_only = tls_get(intercept_addr, "foo.allowed", "/moolen?ref=main")
        .await
        .expect("audit request should pass through");
    assert!(
        request_audit_only.starts_with("HTTP/1.1 200"),
        "unexpected audit request response: {request_audit_only}"
    );

    let response_audit_only = tls_get(
        intercept_addr,
        "foo.allowed",
        "/external-secrets/forbidden?ref=main",
    )
    .await
    .expect("audit response-policy deny should pass through");
    assert!(
        response_audit_only.starts_with("HTTP/1.1 200"),
        "unexpected audit response-policy response: {response_audit_only}"
    );
    assert!(
        response_audit_only.contains("forbidden"),
        "unexpected audit response body: {response_audit_only}"
    );

    proxy_task.abort();
    let _ = upstream_shutdown_tx.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_allows_large_h2_request_body() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert_chain, key_der) = cert_der_pair("foo.allowed");
    let acceptor = build_tls_acceptor(&cert_chain, &key_der).unwrap();
    let (observed_body_tx, observed_body_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept failed");
        let tls = acceptor.accept(stream).await.expect("tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(1);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("h2 handshake timeout")
            .expect("h2 handshake failed");
        let (request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("request accept timeout")
            .expect("connection closed before request")
            .expect("request accept failed");
        let body = read_h2_request_body_with_conn_progress(&mut conn, request.into_body())
            .await
            .expect("large h2 request body read failed");
        let _ = observed_body_tx.send(body.len());
        let response = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(())
            .expect("response build failed");
        if let Ok(mut send) = respond.send_response(response, false) {
            let _ = send.send_data(Bytes::from_static(b"ok"), true);
        }
    });

    // Exceed the default h2 stream window (65,535 bytes) to ensure
    // flow-control updates are exercised by the intercept h2 body reader.
    let request_body = vec![b'x'; 72 * 1024];
    let _ = tls_h2_post(
        addr,
        "foo.allowed",
        "/webhooks/allowed/intercept",
        &request_body,
    )
    .await;
    let observed_body_len = tokio::time::timeout(Duration::from_secs(2), observed_body_rx)
        .await
        .expect("server did not report body size")
        .expect("server channel dropped");
    assert_eq!(observed_body_len, request_body.len());
    let _ = server_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_forwards_browser_xhr_headers_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let (request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        let headers = request.headers();
        let accept_ok = headers
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("application/json"))
            .unwrap_or(false);
        let xhr_ok = headers
            .get("x-requested-with")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.eq_ignore_ascii_case("XMLHttpRequest"))
            .unwrap_or(false);
        let fetch_mode_ok = headers
            .get("sec-fetch-mode")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.eq_ignore_ascii_case("cors"))
            .unwrap_or(false);
        let all_ok = accept_ok && xhr_ok && fetch_mode_ok;
        let _ = observed_tx.send(all_ok);
        let response = Response::builder()
            .status(if all_ok { 200 } else { 406 })
            .header("content-type", "application/json")
            .body(())
            .expect("response build failed");
        if let Ok(mut send) = respond.send_response(response, false) {
            let _ = send.send_data(Bytes::from_static(b"{}"), true);
        }
        conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), conn.accept()).await;
    });

    let intercept_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intercept_addr = intercept_listener.local_addr().unwrap();
    drop(intercept_listener);
    let (proxy_ca_cert_pem, proxy_ca_key_der) = ca_pem_der_pair("Intercept Test CA");
    let (startup_tx, startup_rx) = oneshot::channel();
    let policy = Arc::new(RwLock::new(intercept_h2_passthrough_snapshot(3)));
    let proxy_task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
        bind_addr: intercept_addr,
        upstream_override: Some(upstream_addr),
        upstream_tls_insecure: true,
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

    let (status, _) = tls_h2_get_with_headers(
        intercept_addr,
        "foo.allowed",
        "/external-secrets/external-secrets/latest-commit",
        &[
            ("accept", "application/json"),
            ("x-requested-with", "XMLHttpRequest"),
            ("sec-fetch-mode", "cors"),
        ],
    )
    .await
    .expect("h2 xhr request failed");
    assert_eq!(status, 200, "unexpected upstream-gated status");
    let observed = tokio::time::timeout(Duration::from_secs(2), observed_rx)
        .await
        .expect("upstream header observation timeout")
        .expect("upstream header observation dropped");
    assert!(
        observed,
        "intercept did not forward required browser xhr headers"
    );

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_processes_parallel_streams_without_serial_queueing() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak_in_flight = Arc::new(AtomicUsize::new(0));
    let (upstream_shutdown_tx, mut upstream_shutdown_rx) = oneshot::channel();
    let upstream_task = {
        let in_flight = in_flight.clone();
        let peak_in_flight = peak_in_flight.clone();
        tokio::spawn(async move {
            let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
            loop {
                tokio::select! {
                    _ = &mut upstream_shutdown_rx => break,
                    accepted = upstream_listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let acceptor = acceptor.clone();
                        let in_flight = in_flight.clone();
                        let peak_in_flight = peak_in_flight.clone();
                        tokio::spawn(async move {
                            let tls = match acceptor.accept(stream).await {
                                Ok(tls) => tls,
                                Err(_) => return,
                            };
                            let mut builder = server::Builder::new();
                            builder.max_concurrent_streams(1);
                            let mut conn = match tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls)).await {
                                Ok(Ok(conn)) => conn,
                                _ => return,
                            };
                            let next = match tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept()).await {
                                Ok(next) => next,
                                Err(_) => return,
                            };
                            let Some(Ok((_request, mut respond))) = next else {
                                return;
                            };
                            let now = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                            update_peak(&peak_in_flight, now);
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            let response = Response::builder()
                                .status(200)
                                .header("content-type", "text/plain")
                                .body(())
                                .expect("response build failed");
                            if let Ok(mut send) = respond.send_response(response, false) {
                                let _ = send.send_data(Bytes::from_static(b"ok"), true);
                            }
                            conn.graceful_shutdown();
                            let _ = tokio::time::timeout(Duration::from_millis(50), conn.accept()).await;
                            in_flight.fetch_sub(1, Ordering::AcqRel);
                        });
                    }
                }
            }
        })
    };

    let intercept_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intercept_addr = intercept_listener.local_addr().unwrap();
    drop(intercept_listener);
    let (proxy_ca_cert_pem, proxy_ca_key_der) = ca_pem_der_pair("Intercept Test CA");
    let (startup_tx, startup_rx) = oneshot::channel();
    let policy = Arc::new(RwLock::new(intercept_h2_passthrough_snapshot(4)));
    let proxy_task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
        bind_addr: intercept_addr,
        upstream_override: Some(upstream_addr),
        upstream_tls_insecure: true,
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

    let start = Instant::now();
    let statuses = tls_h2_get_many_concurrent(
        intercept_addr,
        "foo.allowed",
        "/external-secrets/external-secrets",
        12,
    )
    .await
    .expect("parallel h2 request batch failed");
    let elapsed = start.elapsed();
    assert!(
        statuses.iter().all(|status| *status == 200),
        "unexpected non-200 statuses: {statuses:?}"
    );
    assert!(
        peak_in_flight.load(Ordering::Acquire) >= 2,
        "upstream never observed overlapping requests on parallel stream batch"
    );
    assert!(
        elapsed < Duration::from_millis(2000),
        "parallel stream batch took too long ({elapsed:?}), indicates serialized handling"
    );

    proxy_task.abort();
    let _ = upstream_shutdown_tx.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_client_to_h2_upstream_succeeds() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let (_request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        let response = Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(())
            .expect("response build failed");
        if let Ok(mut send) = respond.send_response(response, false) {
            let _ = send.send_data(Bytes::from_static(b"ok"), true);
        }
        conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), conn.accept()).await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(5), upstream_addr)
            .await;
    let (status, body_len, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/", &[])
            .await
            .expect("h2 request failed");
    assert_eq!(status, 200);
    assert_eq!(body_len, 2);

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_client_to_h1_upstream_fails_closed() {
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

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(6), upstream_addr)
            .await;
    let err = tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/", &[])
        .await
        .expect_err("h2->h1 upstream mismatch unexpectedly succeeded");
    assert!(
        err.contains("h2")
            || err.contains("stream")
            || err.contains("close_notify")
            || err.contains("eof"),
        "unexpected error for h2->h1 mismatch: {err}"
    );

    proxy_task.abort();
    let _ = upstream_shutdown_tx.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h1_upgrade_headers_passthrough_stays_http1() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let mut tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let req = http_match::read_http_message(&mut tls)
            .await
            .expect("upstream read failed");
        let parsed = http_match::parse_http_request(&req).expect("parse request failed");
        let has_upgrade = parsed
            .headers
            .get("upgrade")
            .and_then(|values| values.first())
            .map(|value| value.eq_ignore_ascii_case("h2c"))
            .unwrap_or(false);
        let has_http2_settings = parsed.headers.contains_key("http2-settings");
        let _ = observed_tx.send(has_upgrade && has_http2_settings);
        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let _ = tls.write_all(response.as_bytes()).await;
        let _ = tls.shutdown().await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(7), upstream_addr)
            .await;
    let response = tls_h1_get_with_headers(
        intercept_addr,
        "foo.allowed",
        "/upgrade-check",
        &[
            ("Upgrade", "h2c"),
            ("HTTP2-Settings", "AAMAAABkAARAAAAAAAIAAAAA"),
        ],
    )
    .await
    .expect("h1 request failed");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected h1 response: {response}"
    );
    let observed = tokio::time::timeout(Duration::from_secs(2), observed_rx)
        .await
        .expect("header observation timeout")
        .expect("header observation dropped");
    assert!(
        observed,
        "h1 upgrade-style headers were not forwarded to upstream"
    );

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_forwards_cookie_and_multi_headers() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (observed_tx, observed_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let (request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        let headers = request.headers();
        let accept_ok = headers
            .get("accept")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.contains("text/fragment+html"))
            .unwrap_or(false);
        let cookies: Vec<String> = headers
            .get_all("cookie")
            .iter()
            .filter_map(|value| value.to_str().ok().map(|v| v.to_string()))
            .collect();
        let cookies_ok = cookies.iter().any(|value| value.contains("a=1"))
            && cookies.iter().any(|value| value.contains("b=2"));
        let fetch_dest_ok = headers
            .get("sec-fetch-dest")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.eq_ignore_ascii_case("empty"))
            .unwrap_or(false);
        let all_ok = accept_ok && cookies_ok && fetch_dest_ok;
        let _ = observed_tx.send(all_ok);
        let response = Response::builder()
            .status(if all_ok { 200 } else { 406 })
            .header("content-type", "application/json")
            .body(())
            .expect("response build failed");
        if let Ok(mut send) = respond.send_response(response, false) {
            let _ = send.send_data(Bytes::from_static(b"{}"), true);
        }
        conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), conn.accept()).await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(8), upstream_addr)
            .await;
    let (status, _, _) = tls_h2_request_with_headers(
        intercept_addr,
        "foo.allowed",
        "GET",
        "/cookies",
        &[
            ("accept", "text/fragment+html"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
            ("sec-fetch-dest", "empty"),
        ],
    )
    .await
    .expect("h2 request failed");
    assert_eq!(status, 200);
    let observed = tokio::time::timeout(Duration::from_secs(2), observed_rx)
        .await
        .expect("header observation timeout")
        .expect("header observation dropped");
    assert!(
        observed,
        "expected forwarded headers were not observed upstream"
    );

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_allows_large_upstream_response_body() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let body = vec![b'y'; 512 * 1024];
    let body_len = body.len();
    let (client_done_tx, client_done_rx) = oneshot::channel::<()>();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let (_request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        let response = Response::builder()
            .status(200)
            .header("content-type", "application/octet-stream")
            .body(())
            .expect("response build failed");
        if let Ok(mut send) = respond.send_response(response, false) {
            let chunks: Vec<&[u8]> = body.chunks(16 * 1024).collect();
            for (index, chunk) in chunks.iter().enumerate() {
                let end_stream = index + 1 == chunks.len();
                send.send_data(Bytes::copy_from_slice(chunk), end_stream)
                    .expect("send large response chunk failed");
            }
        }
        let mut client_done_rx = client_done_rx;
        let _ = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    _ = &mut client_done_rx => break,
                    next = conn.accept() => {
                        match next {
                            Some(Ok((_request, mut respond))) => {
                                respond.send_reset(h2::Reason::REFUSED_STREAM);
                            }
                            Some(Err(_)) | None => break,
                        }
                    }
                }
            }
        })
        .await;
        conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(250), conn.accept()).await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(9), upstream_addr)
            .await;
    let (status, response_len, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/large-response", &[])
            .await
            .expect("h2 request failed");
    assert_eq!(status, 200);
    assert_eq!(response_len, body_len);
    let _ = client_done_tx.send(());

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_enforce_denied_stream_does_not_break_allowed_stream() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (upstream_shutdown_tx, mut upstream_shutdown_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        loop {
            tokio::select! {
                _ = &mut upstream_shutdown_rx => break,
                accepted = upstream_listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(tls) => tls,
                            Err(_) => return,
                        };
                        let mut builder = server::Builder::new();
                        builder.max_concurrent_streams(8);
                        let mut conn = match tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls)).await {
                            Ok(Ok(conn)) => conn,
                            _ => return,
                        };
                        let next = match tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept()).await {
                            Ok(next) => next,
                            Err(_) => return,
                        };
                        let Some(Ok((_request, mut respond))) = next else { return; };
                        let response = Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(())
                            .expect("response build failed");
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from_static(b"ok"), true);
                        }
                        conn.graceful_shutdown();
                        let _ = tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
                    });
                }
            }
        }
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_http_snapshot(10), upstream_addr).await;
    let results = tls_h2_get_paths_same_conn(
        intercept_addr,
        "foo.allowed",
        &[
            "/moolen?ref=main",
            "/external-secrets/external-secrets?ref=main",
        ],
    )
    .await
    .expect("batch request failed");
    assert!(
        results[0].is_err(),
        "denied request unexpectedly succeeded: {:?}",
        results[0]
    );
    assert_eq!(
        results[1].as_ref().ok().copied(),
        Some(200),
        "allowed sibling stream should succeed"
    );

    proxy_task.abort();
    let _ = upstream_shutdown_tx.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_upstream_reset_stream_is_handled() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let (_request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
        conn.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), conn.accept()).await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(11), upstream_addr)
            .await;
    let err = tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/reset", &[])
        .await
        .expect_err("upstream reset unexpectedly succeeded");
    assert!(
        err.contains("stream")
            || err.contains("h2")
            || err.contains("close_notify")
            || err.contains("peer closed connection")
            || err.contains("eof"),
        "unexpected error for upstream reset: {err}"
    );

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_preserves_head_204_304_and_redirect_headers() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        for _ in 0..4 {
            let (stream, _) = upstream_listener
                .accept()
                .await
                .expect("upstream accept failed");
            let tls = acceptor
                .accept(stream)
                .await
                .expect("upstream tls accept failed");
            let mut builder = server::Builder::new();
            builder.max_concurrent_streams(8);
            let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
                .await
                .expect("upstream h2 handshake timeout")
                .expect("upstream h2 handshake failed");
            let (request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
                .await
                .expect("upstream request accept timeout")
                .expect("upstream connection closed")
                .expect("upstream request accept failed");
            let path = request.uri().path();
            let method = request.method().as_str();
            let response = match (method, path) {
                ("HEAD", "/head") => Response::builder()
                    .status(200)
                    .header("content-type", "text/plain")
                    .body(())
                    .unwrap(),
                ("GET", "/no-content") => Response::builder().status(204).body(()).unwrap(),
                ("GET", "/not-modified") => Response::builder().status(304).body(()).unwrap(),
                ("GET", "/redirect") => Response::builder()
                    .status(302)
                    .header("location", "/target")
                    .body(())
                    .unwrap(),
                _ => Response::builder().status(500).body(()).unwrap(),
            };
            if let Ok(mut send) = respond.send_response(response, true) {
                let _ = send.send_data(Bytes::new(), true);
            }
            conn.graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
        }
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(12), upstream_addr)
            .await;

    let (status_head, len_head, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "HEAD", "/head", &[])
            .await
            .expect("head request failed");
    assert_eq!(status_head, 200);
    assert_eq!(len_head, 0);

    let (status_204, len_204, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/no-content", &[])
            .await
            .expect("204 request failed");
    assert_eq!(status_204, 204);
    assert_eq!(len_204, 0);

    let (status_304, len_304, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/not-modified", &[])
            .await
            .expect("304 request failed");
    assert_eq!(status_304, 304);
    assert_eq!(len_304, 0);

    let (status_302, _len_302, location_302) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/redirect", &[])
            .await
            .expect("redirect request failed");
    assert_eq!(status_302, 302);
    assert_eq!(location_302.as_deref(), Some("/target"));

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_upstream_response_timeout_is_fail_closed() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        let (stream, _) = upstream_listener
            .accept()
            .await
            .expect("upstream accept failed");
        let tls = acceptor
            .accept(stream)
            .await
            .expect("upstream tls accept failed");
        let mut builder = server::Builder::new();
        builder.max_concurrent_streams(8);
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
            .await
            .expect("upstream h2 handshake timeout")
            .expect("upstream h2 handshake failed");
        let _ = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
            .await
            .expect("upstream request accept timeout")
            .expect("upstream connection closed")
            .expect("upstream request accept failed");
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(13), upstream_addr)
            .await;
    let start = Instant::now();
    let err = tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/timeout", &[])
        .await
        .expect_err("timeout path unexpectedly succeeded");
    let elapsed = start.elapsed();
    assert!(
        err.contains("timed out")
            || err.contains("h2 upstream response")
            || err.contains("stream no longer needed")
            || err.contains("close_notify")
            || err.contains("peer closed connection")
            || err.contains("eof"),
        "unexpected timeout error: {err}"
    );
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(8),
        "unexpected timeout duration: {elapsed:?}"
    );

    proxy_task.abort();
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_audit_mode_allows_mixed_policy_streams() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (upstream_shutdown_tx, mut upstream_shutdown_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        loop {
            tokio::select! {
                _ = &mut upstream_shutdown_rx => break,
                accepted = upstream_listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(tls) => tls,
                            Err(_) => return,
                        };
                        let mut builder = server::Builder::new();
                        builder.max_concurrent_streams(8);
                        let mut conn = match tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls)).await {
                            Ok(Ok(conn)) => conn,
                            _ => return,
                        };
                        let next = match tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept()).await {
                            Ok(next) => next,
                            Err(_) => return,
                        };
                        let Some(Ok((_request, mut respond))) = next else { return; };
                        let response = Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(())
                            .expect("response build failed");
                        if let Ok(mut send) = respond.send_response(response, false) {
                            let _ = send.send_data(Bytes::from_static(b"ok"), true);
                        }
                        conn.graceful_shutdown();
                        let _ = tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
                    });
                }
            }
        }
    });

    let mut snapshot = intercept_http_snapshot(14);
    snapshot.set_enforcement_mode(EnforcementMode::Audit);
    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(snapshot, upstream_addr).await;
    let results = tls_h2_get_paths_same_conn(
        intercept_addr,
        "foo.allowed",
        &[
            "/moolen?ref=main",
            "/external-secrets/external-secrets?ref=main",
        ],
    )
    .await
    .expect("batch request failed");
    assert_eq!(results[0].as_ref().ok().copied(), Some(200));
    assert_eq!(results[1].as_ref().ok().copied(), Some(200));

    proxy_task.abort();
    let _ = upstream_shutdown_tx.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "current_thread")]
async fn tls_intercept_runtime_h2_forwards_authority_host_across_connections() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (upstream_cert, upstream_key) = cert_der_pair("foo.allowed");
    let (hosts_tx, mut hosts_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let upstream_task = tokio::spawn(async move {
        let acceptor = build_tls_acceptor(&upstream_cert, &upstream_key).unwrap();
        for _ in 0..2 {
            let (stream, _) = upstream_listener
                .accept()
                .await
                .expect("upstream accept failed");
            let tls = acceptor
                .accept(stream)
                .await
                .expect("upstream tls accept failed");
            let mut builder = server::Builder::new();
            builder.max_concurrent_streams(8);
            let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake::<_, Bytes>(tls))
                .await
                .expect("upstream h2 handshake timeout")
                .expect("upstream h2 handshake failed");
            let (request, mut respond) = tokio::time::timeout(TLS_IO_TIMEOUT, conn.accept())
                .await
                .expect("upstream request accept timeout")
                .expect("upstream connection closed")
                .expect("upstream request accept failed");
            let host = request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            let _ = hosts_tx.send(host);
            let response = Response::builder()
                .status(200)
                .header("content-type", "text/plain")
                .body(())
                .expect("response build failed");
            if let Ok(mut send) = respond.send_response(response, false) {
                let _ = send.send_data(Bytes::from_static(b"ok"), true);
            }
            conn.graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
        }
    });

    let (intercept_addr, proxy_task) =
        spawn_intercept_runtime_with_policy(intercept_h2_passthrough_snapshot(15), upstream_addr)
            .await;
    let (status_a, _, _) =
        tls_h2_request_with_headers(intercept_addr, "foo.allowed", "GET", "/host-a", &[])
            .await
            .expect("request foo.allowed failed");
    assert_eq!(status_a, 200);
    let (status_b, _, _) =
        tls_h2_request_with_headers(intercept_addr, "bar.allowed", "GET", "/host-b", &[])
            .await
            .expect("request bar.allowed failed");
    assert_eq!(status_b, 200);

    let host_one = tokio::time::timeout(Duration::from_secs(2), hosts_rx.recv())
        .await
        .expect("host recv timeout #1")
        .expect("host channel closed #1");
    let host_two = tokio::time::timeout(Duration::from_secs(2), hosts_rx.recv())
        .await
        .expect("host recv timeout #2")
        .expect("host channel closed #2");
    let mut hosts = vec![host_one, host_two];
    hosts.sort();
    assert_eq!(
        hosts,
        vec!["bar.allowed".to_string(), "foo.allowed".to_string()]
    );

    proxy_task.abort();
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
    let mapped = lookup_intercept_demux_original_dst(&demux, Ipv4Addr::new(10, 0, 0, 42), 40000)
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
