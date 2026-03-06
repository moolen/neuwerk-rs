use super::*;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, EnforcementMode, HttpPathMatcher, HttpQueryMatcher, HttpRequestPolicy,
    HttpResponsePolicy, HttpStringMatcher, IpSetV4, PortRange, Proto, Rule, RuleAction, RuleMatch,
    SourceGroup, Tls13Uninspectable, TlsInterceptHttpPolicy, TlsMatch,
};
use rcgen::{
    generate_simple_self_signed, BasicConstraints, Certificate, CertificateParams, DnType, IsCa,
    KeyUsagePurpose,
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
        let mut conn = tokio::time::timeout(TLS_IO_TIMEOUT, builder.handshake(tls))
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
