use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::controlplane::audit::{
    AuditEvent as ControlplaneAuditEvent, AuditFindingType, AuditStore,
};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::DnsPolicy;
use crate::controlplane::wiretap::DnsMap;
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::DynamicIpSetV4;

static DNS_LOGS: AtomicUsize = AtomicUsize::new(0);
const DNS_UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub async fn run_dns_proxy(
    bind_addr: SocketAddr,
    upstream_addrs: Vec<SocketAddr>,
    allowlist: DynamicIpSetV4,
    policy: std::sync::Arc<std::sync::RwLock<DnsPolicy>>,
    dns_map: DnsMap,
    metrics: Metrics,
    policy_store: Option<PolicyStore>,
    audit_store: Option<AuditStore>,
    node_id: String,
    mut startup_status_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
) -> io::Result<()> {
    fn report_startup(
        tx: &mut Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
        status: Result<(), String>,
    ) {
        if let Some(sender) = tx.take() {
            let _ = sender.send(status);
        }
    }

    if upstream_addrs.is_empty() {
        report_startup(
            &mut startup_status_tx,
            Err("dns proxy requires at least one upstream".to_string()),
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns proxy requires at least one upstream",
        ));
    }
    let upstream_addrs = std::sync::Arc::new(upstream_addrs);
    eprintln!("dns proxy: binding udp {}", bind_addr);
    let listen = match UdpSocket::bind(bind_addr).await {
        Ok(sock) => sock,
        Err(err) => {
            eprintln!("dns proxy: bind {} failed: {err}", bind_addr);
            report_startup(&mut startup_status_tx, Err(err.to_string()));
            return Err(err);
        }
    };
    let tcp_listen = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            report_startup(&mut startup_status_tx, Err(err.to_string()));
            return Err(err);
        }
    };
    eprintln!("dns proxy: listening on {}", bind_addr);
    report_startup(&mut startup_status_tx, Ok(()));

    let tcp_policy = policy.clone();
    let tcp_allowlist = allowlist.clone();
    let tcp_dns_map = dns_map.clone();
    let tcp_metrics = metrics.clone();
    let tcp_upstreams = upstream_addrs.clone();
    let tcp_policy_store = policy_store.clone();
    let tcp_audit_store = audit_store.clone();
    let tcp_node_id = node_id.clone();
    tokio::spawn(async move {
        if let Err(err) = run_dns_proxy_tcp(
            tcp_listen,
            tcp_upstreams,
            tcp_allowlist,
            tcp_policy,
            tcp_dns_map,
            tcp_metrics,
            tcp_policy_store,
            tcp_audit_store,
            tcp_node_id,
        )
        .await
        {
            eprintln!("dns proxy: tcp listener failed: {err}");
        }
    });

    let mut buf = vec![0u8; 2048];

    loop {
        let (len, peer) = listen.recv_from(&mut buf).await?;
        let request = &buf[..len];

        let (allowed, question, source_group, would_deny) = match peer.ip() {
            IpAddr::V4(src_ip) => {
                let question = match parse_dns_question(request) {
                    Some(question) => question,
                    None => {
                        let source_group = match policy.read() {
                            Ok(lock) => lock
                                .source_group_for_ip(src_ip)
                                .unwrap_or_else(|| "default".to_string()),
                            Err(_) => "default".to_string(),
                        };
                        metrics.observe_dns_query("deny", "parse_error", &source_group);
                        metrics.observe_dns_nxdomain("policy");
                        let response = build_nxdomain(request);
                        let _ = listen.send_to(&response, peer).await;
                        continue;
                    }
                };
                let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
                    &policy,
                    policy_store.as_ref(),
                    src_ip,
                    &question.name,
                );
                (allowed, question, source_group, would_deny)
            }
            _ => (false, DnsQuestion::empty(), "default".to_string(), false),
        };

        if DNS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dns proxy: query from={} name={} allowed={} would_deny={} group={}",
                peer, question.name, allowed, would_deny, source_group
            );
        }

        if matches!(peer.ip(), IpAddr::V4(_)) && would_deny {
            ingest_dns_deny_audit(
                audit_store.as_ref(),
                policy_store.as_ref(),
                &node_id,
                &source_group,
                &question,
            );
        }

        if !allowed {
            let reason = if matches!(peer.ip(), IpAddr::V4(_)) {
                if would_deny {
                    "policy_deny"
                } else {
                    "policy_unavailable"
                }
            } else {
                "unsupported_src_ip"
            };
            metrics.observe_dns_query("deny", reason, &source_group);
            metrics.observe_dns_nxdomain("policy");
            let response = build_nxdomain(request);
            listen.send_to(&response, peer).await?;
            continue;
        }

        let response = match forward_dns_query_udp(
            request,
            &question,
            upstream_addrs.as_ref().as_slice(),
            &source_group,
            &metrics,
        )
        .await
        {
            Ok(response) => response,
            Err(UpstreamQueryError::Mismatch) => {
                metrics.observe_dns_query("deny", "upstream_mismatch", &source_group);
                metrics.observe_dns_nxdomain("upstream_mismatch");
                let response = build_nxdomain(request);
                listen.send_to(&response, peer).await?;
                continue;
            }
            Err(UpstreamQueryError::Transport) => {
                metrics.observe_dns_query("deny", "upstream_error", &source_group);
                metrics.observe_dns_nxdomain("upstream_error");
                let response = build_nxdomain(request);
                listen.send_to(&response, peer).await?;
                continue;
            }
        };
        metrics.observe_dns_query("allow", "policy_allow", &source_group);
        if is_nxdomain(&response) {
            metrics.observe_dns_nxdomain("upstream");
        }

        let ips = extract_ips_from_dns_response(&response);
        if !ips.is_empty() {
            let mut v4s = Vec::new();
            for ip in ips {
                if let IpAddr::V4(v4) = ip {
                    v4s.push(v4);
                }
            }
            if !v4s.is_empty() {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                dns_map.insert_many(&question.name, &v4s, now);
                allowlist.insert_many(v4s);
            }
        }

        listen.send_to(&response, peer).await?;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamQueryError {
    Transport,
    Mismatch,
}

async fn forward_dns_query_udp(
    request: &[u8],
    question: &DnsQuestion,
    upstream_addrs: &[SocketAddr],
    source_group: &str,
    metrics: &Metrics,
) -> Result<Vec<u8>, UpstreamQueryError> {
    let mut saw_transport_error = false;
    let mut saw_mismatch = false;

    for upstream_addr in upstream_addrs {
        let upstream = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(sock) => sock,
            Err(_) => {
                saw_transport_error = true;
                continue;
            }
        };

        let start = Instant::now();
        if upstream.send_to(request, upstream_addr).await.is_err() {
            saw_transport_error = true;
            continue;
        }

        let mut upstream_buf = vec![0u8; 2048];
        let recv =
            tokio::time::timeout(DNS_UPSTREAM_TIMEOUT, upstream.recv_from(&mut upstream_buf)).await;
        let (resp_len, resp_peer) = match recv {
            Ok(Ok(value)) => value,
            Ok(Err(_)) | Err(_) => {
                saw_transport_error = true;
                continue;
            }
        };

        if DNS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dns proxy: upstream response from={} bytes={} group={}",
                resp_peer, resp_len, source_group
            );
        }

        let response = &upstream_buf[..resp_len];
        if let Err(reason) = validate_dns_response(question, response, resp_peer, *upstream_addr) {
            saw_mismatch = true;
            metrics.observe_dns_upstream_mismatch(reason.as_label(), source_group);
            continue;
        }

        metrics.observe_dns_upstream_rtt(source_group, start.elapsed());
        return Ok(response.to_vec());
    }

    if saw_mismatch {
        Err(UpstreamQueryError::Mismatch)
    } else if saw_transport_error {
        Err(UpstreamQueryError::Transport)
    } else {
        Err(UpstreamQueryError::Transport)
    }
}

async fn run_dns_proxy_tcp(
    listener: TcpListener,
    upstream_addrs: std::sync::Arc<Vec<SocketAddr>>,
    allowlist: DynamicIpSetV4,
    policy: std::sync::Arc<std::sync::RwLock<DnsPolicy>>,
    dns_map: DnsMap,
    metrics: Metrics,
    policy_store: Option<PolicyStore>,
    audit_store: Option<AuditStore>,
    node_id: String,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let allowlist = allowlist.clone();
        let policy = policy.clone();
        let dns_map = dns_map.clone();
        let metrics = metrics.clone();
        let upstream_addrs = upstream_addrs.clone();
        let policy_store = policy_store.clone();
        let audit_store = audit_store.clone();
        let node_id = node_id.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_dns_tcp_client(
                stream,
                peer,
                upstream_addrs,
                allowlist,
                policy,
                dns_map,
                metrics,
                policy_store,
                audit_store,
                node_id,
            )
            .await
            {
                eprintln!("dns proxy: tcp client {} failed: {err}", peer);
            }
        });
    }
}

async fn handle_dns_tcp_client(
    mut stream: TcpStream,
    peer: SocketAddr,
    upstream_addrs: std::sync::Arc<Vec<SocketAddr>>,
    allowlist: DynamicIpSetV4,
    policy: std::sync::Arc<std::sync::RwLock<DnsPolicy>>,
    dns_map: DnsMap,
    metrics: Metrics,
    policy_store: Option<PolicyStore>,
    audit_store: Option<AuditStore>,
    node_id: String,
) -> Result<(), String> {
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(format!("read tcp length failed: {err}")),
        }
        let req_len = u16::from_be_bytes(len_buf) as usize;
        if req_len == 0 {
            return Ok(());
        }
        let mut request = vec![0u8; req_len];
        stream
            .read_exact(&mut request)
            .await
            .map_err(|e| format!("read tcp query failed: {e}"))?;

        let (allowed, question, source_group, would_deny) = match peer.ip() {
            IpAddr::V4(src_ip) => {
                let question = match parse_dns_question(&request) {
                    Some(question) => question,
                    None => {
                        let source_group = match policy.read() {
                            Ok(lock) => lock
                                .source_group_for_ip(src_ip)
                                .unwrap_or_else(|| "default".to_string()),
                            Err(_) => "default".to_string(),
                        };
                        metrics.observe_dns_query("deny", "parse_error", &source_group);
                        metrics.observe_dns_nxdomain("policy");
                        let response = build_nxdomain(&request);
                        write_dns_tcp_response(&mut stream, &response).await?;
                        continue;
                    }
                };
                let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
                    &policy,
                    policy_store.as_ref(),
                    src_ip,
                    &question.name,
                );
                (allowed, question, source_group, would_deny)
            }
            _ => (false, DnsQuestion::empty(), "default".to_string(), false),
        };

        if DNS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dns proxy: tcp query from={} name={} allowed={} would_deny={} group={}",
                peer, question.name, allowed, would_deny, source_group
            );
        }

        if matches!(peer.ip(), IpAddr::V4(_)) && would_deny {
            ingest_dns_deny_audit(
                audit_store.as_ref(),
                policy_store.as_ref(),
                &node_id,
                &source_group,
                &question,
            );
        }

        if !allowed {
            let reason = if matches!(peer.ip(), IpAddr::V4(_)) {
                if would_deny {
                    "policy_deny"
                } else {
                    "policy_unavailable"
                }
            } else {
                "unsupported_src_ip"
            };
            metrics.observe_dns_query("deny", reason, &source_group);
            metrics.observe_dns_nxdomain("policy");
            let response = build_nxdomain(&request);
            write_dns_tcp_response(&mut stream, &response).await?;
            continue;
        }

        let response = match forward_dns_query_udp(
            &request,
            &question,
            upstream_addrs.as_slice(),
            &source_group,
            &metrics,
        )
        .await
        {
            Ok(response) => {
                metrics.observe_dns_query("allow", "policy_allow", &source_group);
                if is_nxdomain(&response) {
                    metrics.observe_dns_nxdomain("upstream");
                }
                response
            }
            Err(UpstreamQueryError::Mismatch) => {
                metrics.observe_dns_query("deny", "upstream_mismatch", &source_group);
                metrics.observe_dns_nxdomain("upstream_mismatch");
                build_nxdomain(&request)
            }
            Err(UpstreamQueryError::Transport) => {
                metrics.observe_dns_query("deny", "upstream_error", &source_group);
                metrics.observe_dns_nxdomain("upstream_error");
                build_nxdomain(&request)
            }
        };

        if !is_nxdomain(&response) {
            let ips = extract_ips_from_dns_response(&response);
            if !ips.is_empty() {
                let mut v4s = Vec::new();
                for ip in ips {
                    if let IpAddr::V4(v4) = ip {
                        v4s.push(v4);
                    }
                }
                if !v4s.is_empty() {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    dns_map.insert_many(&question.name, &v4s, now);
                    allowlist.insert_many(v4s);
                }
            }
        }

        write_dns_tcp_response(&mut stream, &response).await?;
    }
}

fn evaluate_dns_policy_decision(
    policy: &std::sync::Arc<std::sync::RwLock<DnsPolicy>>,
    policy_store: Option<&PolicyStore>,
    src_ip: Ipv4Addr,
    hostname: &str,
) -> (bool, bool, String) {
    let audit_passthrough = policy_store
        .map(|store| store.enforcement_mode() == crate::dataplane::policy::EnforcementMode::Audit)
        .unwrap_or(false);
    let lock = match policy.read() {
        Ok(lock) => lock,
        Err(_) => return (false, false, "default".to_string()),
    };
    let (raw_allowed, enforce_group) = lock.evaluate_with_source_group(src_ip, hostname);
    let (audit_rule_denied, audit_group) =
        lock.evaluate_audit_denied_with_source_group(src_ip, hostname);
    let source_group = enforce_group
        .or(audit_group)
        .unwrap_or_else(|| "default".to_string());
    let would_deny = !raw_allowed || audit_rule_denied;
    let allowed = raw_allowed || (audit_passthrough && !raw_allowed);
    (allowed, would_deny, source_group)
}

async fn write_dns_tcp_response(stream: &mut TcpStream, response: &[u8]) -> Result<(), String> {
    if response.len() > u16::MAX as usize {
        return Err("tcp dns response too large".to_string());
    }
    let len = (response.len() as u16).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| format!("write tcp response length failed: {e}"))?;
    stream
        .write_all(response)
        .await
        .map_err(|e| format!("write tcp response body failed: {e}"))?;
    Ok(())
}

fn ingest_dns_deny_audit(
    audit_store: Option<&AuditStore>,
    policy_store: Option<&PolicyStore>,
    node_id: &str,
    source_group: &str,
    question: &DnsQuestion,
) {
    let Some(audit_store) = audit_store else {
        return;
    };
    if question.name.is_empty() {
        return;
    }
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let event = ControlplaneAuditEvent {
        finding_type: AuditFindingType::DnsDeny,
        source_group: source_group.to_string(),
        hostname: Some(question.name.clone()),
        dst_ip: None,
        dst_port: None,
        proto: None,
        fqdn: Some(question.name.clone()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: Some(question.qtype),
        observed_at,
    };
    let policy_id = policy_store.and_then(|store| store.active_policy_id());
    audit_store.ingest(event, policy_id, node_id);
}

#[derive(Debug, Clone)]
struct DnsQuestion {
    id: u16,
    name: String,
    qtype: u16,
    qclass: u16,
}

impl DnsQuestion {
    fn empty() -> Self {
        Self {
            id: 0,
            name: String::new(),
            qtype: 0,
            qclass: 0,
        }
    }
}

fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn parse_dns_question(msg: &[u8]) -> Option<DnsQuestion> {
    if msg.len() < 12 {
        return None;
    }
    let id = read_u16(msg, 0)?;
    let qdcount = read_u16(msg, 4)? as usize;
    if qdcount == 0 {
        return None;
    }
    let mut idx = 12usize;
    let name = read_name(msg, &mut idx)?;
    if idx + 4 > msg.len() {
        return None;
    }
    let qtype = read_u16(msg, idx)?;
    let qclass = read_u16(msg, idx + 2)?;
    Some(DnsQuestion {
        id,
        name: normalize_hostname(&name),
        qtype,
        qclass,
    })
}

#[derive(Debug, Clone, Copy)]
enum DnsValidationError {
    Source,
    TxId,
    Question,
    Parse,
}

impl DnsValidationError {
    fn as_label(self) -> &'static str {
        match self {
            DnsValidationError::Source => "source",
            DnsValidationError::TxId => "txid",
            DnsValidationError::Question => "question",
            DnsValidationError::Parse => "parse",
        }
    }
}

fn validate_dns_response(
    question: &DnsQuestion,
    response: &[u8],
    response_peer: SocketAddr,
    upstream_addr: SocketAddr,
) -> Result<(), DnsValidationError> {
    if response_peer != upstream_addr {
        return Err(DnsValidationError::Source);
    }
    let response_q = parse_dns_question(response).ok_or(DnsValidationError::Parse)?;
    if response_q.id != question.id {
        return Err(DnsValidationError::TxId);
    }
    if response_q.name != question.name
        || response_q.qtype != question.qtype
        || response_q.qclass != question.qclass
    {
        return Err(DnsValidationError::Question);
    }
    Ok(())
}

fn dns_rcode(msg: &[u8]) -> Option<u8> {
    if msg.len() < 4 {
        return None;
    }
    Some(msg[3] & 0x0f)
}

fn is_nxdomain(msg: &[u8]) -> bool {
    dns_rcode(msg) == Some(3)
}

fn read_name(buf: &[u8], idx: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *idx;
    let mut jumped = false;
    let mut jumps = 0u8;

    loop {
        if cursor >= buf.len() {
            return None;
        }
        let len = buf[cursor];
        if len & 0b1100_0000 == 0b1100_0000 {
            if cursor + 1 >= buf.len() {
                return None;
            }
            let offset = (((len & 0b0011_1111) as usize) << 8) | buf[cursor + 1] as usize;
            if !jumped {
                *idx = cursor + 2;
                jumped = true;
            }
            cursor = offset;
            jumps = jumps.saturating_add(1);
            if jumps > 8 {
                return None;
            }
            continue;
        }
        cursor += 1;
        if len == 0 {
            if !jumped {
                *idx = cursor;
            }
            break;
        }
        let len = len as usize;
        if cursor + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[cursor..cursor + len]).to_string());
        cursor += len;
        if !jumped {
            *idx = cursor;
        }
    }
    Some(labels.join("."))
}

fn build_nxdomain(request: &[u8]) -> Vec<u8> {
    if request.len() < 12 {
        return Vec::new();
    }

    let mut idx = 12usize;
    let qname_end = match skip_name(request, idx) {
        Some(next) => next,
        None => return Vec::new(),
    };
    idx = qname_end;
    if idx + 4 > request.len() {
        return Vec::new();
    }
    idx += 4;

    let qsection = &request[12..idx];
    let qdcount = read_u16(request, 4).unwrap_or(0);

    let mut resp = Vec::new();
    resp.extend_from_slice(&request[0..2]); // id
    resp.extend_from_slice(&[0x81, 0x83]); // response + NXDOMAIN
    resp.extend_from_slice(&qdcount.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x00]); // ancount
    resp.extend_from_slice(&[0x00, 0x00]); // nscount
    resp.extend_from_slice(&[0x00, 0x00]); // arcount
    resp.extend_from_slice(qsection);
    resp
}

pub fn extract_ips_from_dns_response(msg: &[u8]) -> Vec<IpAddr> {
    if msg.len() < 12 {
        return Vec::new();
    }
    let qdcount = read_u16(msg, 4).unwrap_or(0) as usize;
    let ancount = read_u16(msg, 6).unwrap_or(0) as usize;

    let mut idx = 12usize;
    for _ in 0..qdcount {
        idx = match skip_name(msg, idx) {
            Some(next) => next,
            None => return Vec::new(),
        };
        if idx + 4 > msg.len() {
            return Vec::new();
        }
        idx += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..ancount {
        idx = match skip_name(msg, idx) {
            Some(next) => next,
            None => return ips,
        };
        if idx + 10 > msg.len() {
            return ips;
        }
        let rr_type = read_u16(msg, idx).unwrap_or(0);
        let _class = read_u16(msg, idx + 2).unwrap_or(0);
        let _ttl = read_u32(msg, idx + 4).unwrap_or(0);
        let rdlen = read_u16(msg, idx + 8).unwrap_or(0) as usize;
        idx += 10;
        if idx + rdlen > msg.len() {
            return ips;
        }

        match rr_type {
            1 if rdlen == 4 => {
                let ip = Ipv4Addr::new(msg[idx], msg[idx + 1], msg[idx + 2], msg[idx + 3]);
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlen == 16 => {
                let ip = Ipv6Addr::new(
                    u16::from_be_bytes([msg[idx], msg[idx + 1]]),
                    u16::from_be_bytes([msg[idx + 2], msg[idx + 3]]),
                    u16::from_be_bytes([msg[idx + 4], msg[idx + 5]]),
                    u16::from_be_bytes([msg[idx + 6], msg[idx + 7]]),
                    u16::from_be_bytes([msg[idx + 8], msg[idx + 9]]),
                    u16::from_be_bytes([msg[idx + 10], msg[idx + 11]]),
                    u16::from_be_bytes([msg[idx + 12], msg[idx + 13]]),
                    u16::from_be_bytes([msg[idx + 14], msg[idx + 15]]),
                );
                ips.push(IpAddr::V6(ip));
            }
            _ => {}
        }

        idx += rdlen;
    }

    ips
}

fn skip_name(buf: &[u8], mut idx: usize) -> Option<usize> {
    if idx >= buf.len() {
        return None;
    }
    loop {
        let len = *buf.get(idx)?;
        if len & 0b1100_0000 == 0b1100_0000 {
            if idx + 1 >= buf.len() {
                return None;
            }
            return Some(idx + 2);
        }
        if len == 0 {
            return Some(idx + 1);
        }
        idx = idx.checked_add(1 + len as usize)?;
        if idx > buf.len() {
            return None;
        }
    }
}

fn read_u16(buf: &[u8], idx: usize) -> Option<u16> {
    if idx + 2 > buf.len() {
        return None;
    }
    Some(u16::from_be_bytes([buf[idx], buf[idx + 1]]))
}

fn read_u32(buf: &[u8], idx: usize) -> Option<u32> {
    if idx + 4 > buf.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        buf[idx],
        buf[idx + 1],
        buf[idx + 2],
        buf[idx + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::metrics::Metrics;
    use crate::controlplane::policy_config::{DnsRule, DnsSourceGroup};
    use crate::controlplane::PolicyStore;
    use crate::dataplane::policy::{
        DefaultPolicy, EnforcementMode, IpSetV4, RuleAction, RuleMode as DataplaneRuleMode,
    };
    use regex::Regex;
    use tokio::net::UdpSocket;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum UpstreamMode {
        Valid(Ipv4Addr),
        TxIdMismatch(Ipv4Addr),
        QuestionMismatch(Ipv4Addr),
    }

    async fn spawn_test_upstream(mode: UpstreamMode) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 2048];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let req = &buf[..len];
            let response = match mode {
                UpstreamMode::Valid(ip) => {
                    let q = parse_dns_question(req).unwrap();
                    build_dns_response(&q.name, ip)
                }
                UpstreamMode::TxIdMismatch(ip) => {
                    let q = parse_dns_question(req).unwrap();
                    let mut resp = build_dns_response(&q.name, ip);
                    resp[0] = 0x33;
                    resp[1] = 0x44;
                    resp
                }
                UpstreamMode::QuestionMismatch(ip) => build_dns_response("other.allowed", ip),
            };
            let _ = socket.send_to(&response, peer).await;
        });
        (addr, handle)
    }

    fn build_dns_query(name: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x12, 0x34]); // id
        msg.extend_from_slice(&[0x01, 0x00]); // flags
        msg.extend_from_slice(&[0x00, 0x01]); // qdcount
        msg.extend_from_slice(&[0x00, 0x00]); // ancount
        msg.extend_from_slice(&[0x00, 0x00]); // nscount
        msg.extend_from_slice(&[0x00, 0x00]); // arcount
        for label in name.trim_end_matches('.').split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0x00, 0x01]); // qtype A
        msg.extend_from_slice(&[0x00, 0x01]); // qclass IN
        msg
    }

    fn build_dns_response(name: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x12, 0x34]); // id
        msg.extend_from_slice(&[0x81, 0x80]); // flags
        msg.extend_from_slice(&[0x00, 0x01]); // qdcount
        msg.extend_from_slice(&[0x00, 0x01]); // ancount
        msg.extend_from_slice(&[0x00, 0x00]); // nscount
        msg.extend_from_slice(&[0x00, 0x00]); // arcount
        for label in name.trim_end_matches('.').split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0x00, 0x01]); // qtype A
        msg.extend_from_slice(&[0x00, 0x01]); // qclass IN

        msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
        msg.extend_from_slice(&[0x00, 0x01]); // type A
        msg.extend_from_slice(&[0x00, 0x01]); // class IN
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x04]); // rdlen
        msg.extend_from_slice(&ip.octets());
        msg
    }

    fn single_group_policy(rules: Vec<DnsRule>) -> DnsPolicy {
        let mut sources = IpSetV4::new();
        sources.add_ip(Ipv4Addr::new(192, 0, 2, 2));
        DnsPolicy::new(vec![DnsSourceGroup {
            id: "client-primary".to_string(),
            priority: 0,
            sources,
            rules,
        }])
    }

    fn dns_rule(
        id: &str,
        priority: u32,
        action: RuleAction,
        mode: DataplaneRuleMode,
        host_re: &str,
    ) -> DnsRule {
        DnsRule {
            id: id.to_string(),
            priority,
            action,
            mode,
            hostname: Regex::new(host_re).unwrap(),
        }
    }

    #[test]
    fn skip_name_handles_root() {
        let msg = [0u8, 0u8];
        assert_eq!(skip_name(&msg, 0), Some(1));
    }

    #[test]
    fn parse_dns_query_name_handles_long_labels() {
        let name = format!("{}.{}.example.com", "a".repeat(63), "b".repeat(63));
        let query = build_dns_query(&name);
        let parsed = parse_dns_question(&query).unwrap();
        assert_eq!(parsed.name, name);
    }

    #[test]
    fn build_nxdomain_preserves_id_and_question() {
        let query = build_dns_query("foo.allowed");
        let response = build_nxdomain(&query);
        assert!(response.len() >= 12);
        assert_eq!(&response[0..2], &query[0..2]);
        assert_eq!(response[3] & 0x0f, 3);
        let qdcount = read_u16(&response, 4).unwrap();
        assert_eq!(qdcount, 1);
    }

    #[test]
    fn extract_ips_populates_dns_map() {
        let ip = Ipv4Addr::new(93, 184, 216, 34);
        let response = build_dns_response("Example.COM.", ip);
        let ips = extract_ips_from_dns_response(&response);
        assert_eq!(ips, vec![IpAddr::V4(ip)]);

        let map = DnsMap::new();
        let v4s: Vec<Ipv4Addr> = ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .collect();
        map.insert_many("Example.COM.", &v4s, 42);
        assert_eq!(map.lookup(ip), Some("example.com".to_string()));
    }

    #[test]
    fn dns_rcode_detects_nxdomain() {
        let query = build_dns_query("foo.allowed");
        let response = build_nxdomain(&query);
        assert_eq!(dns_rcode(&response), Some(3));
        assert!(is_nxdomain(&response));
    }

    #[test]
    fn dns_rcode_handles_success() {
        let ip = Ipv4Addr::new(203, 0, 113, 1);
        let response = build_dns_response("example.com.", ip);
        assert_eq!(dns_rcode(&response), Some(0));
        assert!(!is_nxdomain(&response));
    }

    #[test]
    fn evaluate_dns_policy_decision_enforce_mode_denies() {
        let policy = std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new())));
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
            &policy,
            Some(&store),
            Ipv4Addr::new(192, 0, 2, 2),
            "foo.allowed",
        );
        assert!(!allowed);
        assert!(would_deny);
        assert_eq!(source_group, "default");
    }

    #[test]
    fn evaluate_dns_policy_decision_audit_mode_passthroughs_raw_deny() {
        let policy = std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new())));
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        store
            .rebuild(
                Vec::new(),
                DnsPolicy::new(Vec::new()),
                None,
                EnforcementMode::Audit,
            )
            .unwrap();
        let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
            &policy,
            Some(&store),
            Ipv4Addr::new(192, 0, 2, 2),
            "foo.allowed",
        );
        assert!(allowed);
        assert!(would_deny);
        assert_eq!(source_group, "default");
    }

    #[test]
    fn evaluate_dns_policy_decision_marks_audit_rule_deny_without_blocking() {
        let policy = std::sync::Arc::new(std::sync::RwLock::new(single_group_policy(vec![
            dns_rule(
                "allow-enforce",
                0,
                RuleAction::Allow,
                DataplaneRuleMode::Enforce,
                r"^foo\.allowed$",
            ),
            dns_rule(
                "deny-audit",
                1,
                RuleAction::Deny,
                DataplaneRuleMode::Audit,
                r"^foo\.allowed$",
            ),
        ])));
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let (allowed, would_deny, source_group) = evaluate_dns_policy_decision(
            &policy,
            Some(&store),
            Ipv4Addr::new(192, 0, 2, 2),
            "foo.allowed",
        );
        assert!(allowed);
        assert!(would_deny);
        assert_eq!(source_group, "client-primary");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_upstream_failover_recovers_after_mismatch() {
        let request = build_dns_query("spoof.allowed");
        let question = parse_dns_question(&request).unwrap();
        let metrics = Metrics::new().unwrap();

        let (bad_addr, bad_task) =
            spawn_test_upstream(UpstreamMode::TxIdMismatch(Ipv4Addr::new(203, 0, 113, 10))).await;
        let expected = Ipv4Addr::new(203, 0, 113, 11);
        let (good_addr, good_task) = spawn_test_upstream(UpstreamMode::Valid(expected)).await;

        let response = forward_dns_query_udp(
            &request,
            &question,
            &[bad_addr, good_addr],
            "unit",
            &metrics,
        )
        .await
        .expect("query should succeed via fallback upstream");
        assert_eq!(
            extract_ips_from_dns_response(&response),
            vec![IpAddr::V4(expected)]
        );

        let _ = bad_task.await;
        let _ = good_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn udp_upstream_failover_returns_mismatch_when_all_invalid() {
        let request = build_dns_query("spoof.allowed");
        let question = parse_dns_question(&request).unwrap();
        let metrics = Metrics::new().unwrap();

        let (bad_txid_addr, bad_txid_task) =
            spawn_test_upstream(UpstreamMode::TxIdMismatch(Ipv4Addr::new(203, 0, 113, 12))).await;
        let (bad_question_addr, bad_question_task) = spawn_test_upstream(
            UpstreamMode::QuestionMismatch(Ipv4Addr::new(203, 0, 113, 13)),
        )
        .await;

        let result = forward_dns_query_udp(
            &request,
            &question,
            &[bad_txid_addr, bad_question_addr],
            "unit",
            &metrics,
        )
        .await;
        assert_eq!(result, Err(UpstreamQueryError::Mismatch));

        let _ = bad_txid_task.await;
        let _ = bad_question_task.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_status_reports_empty_upstream_error() {
        let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

        let result = run_dns_proxy(
            bind_addr,
            Vec::new(),
            DynamicIpSetV4::new(),
            std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new()))),
            DnsMap::new(),
            Metrics::new().unwrap(),
            None,
            None,
            "node-test".to_string(),
            Some(startup_tx),
        )
        .await;
        assert!(result.is_err());

        let startup = startup_rx
            .await
            .expect("startup channel should be reported");
        assert!(startup.is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_status_reports_bind_error() {
        let occupied = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let bind_addr = occupied.local_addr().unwrap();
        let (startup_tx, startup_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

        let result = run_dns_proxy(
            bind_addr,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53)],
            DynamicIpSetV4::new(),
            std::sync::Arc::new(std::sync::RwLock::new(DnsPolicy::new(Vec::new()))),
            DnsMap::new(),
            Metrics::new().unwrap(),
            None,
            None,
            "node-test".to_string(),
            Some(startup_tx),
        )
        .await;
        assert!(result.is_err());

        let startup = startup_rx
            .await
            .expect("startup channel should be reported");
        assert!(startup.is_err());
    }
}
