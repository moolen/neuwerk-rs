use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::DnsPolicy;
use crate::controlplane::wiretap::DnsMap;
use crate::dataplane::policy::DynamicIpSetV4;

pub async fn run_dns_proxy(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    allowlist: DynamicIpSetV4,
    policy: std::sync::Arc<std::sync::RwLock<DnsPolicy>>,
    dns_map: DnsMap,
    metrics: Metrics,
) -> io::Result<()> {
    eprintln!("dns proxy: binding udp {}", bind_addr);
    let listen = match UdpSocket::bind(bind_addr).await {
        Ok(sock) => sock,
        Err(err) => {
            eprintln!("dns proxy: bind {} failed: {err}", bind_addr);
            return Err(err);
        }
    };
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;
    eprintln!("dns proxy: listening on {}", bind_addr);

    let mut buf = vec![0u8; 2048];
    let mut upstream_buf = vec![0u8; 2048];

    static DNS_LOGS: AtomicUsize = AtomicUsize::new(0);

    loop {
        let (len, peer) = listen.recv_from(&mut buf).await?;
        let request = &buf[..len];

        let (allowed, question, source_group) = match peer.ip() {
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
                let hostname = question.name.clone();
                let (allowed, source_group) = match policy.read() {
                    Ok(lock) => lock.evaluate_with_source_group(src_ip, &hostname),
                    Err(_) => (false, None),
                };
                (
                    allowed,
                    question,
                    source_group.unwrap_or_else(|| "default".to_string()),
                )
            }
            _ => (false, DnsQuestion::empty(), "default".to_string()),
        };

        if DNS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dns proxy: query from={} name={} allowed={} group={}",
                peer, question.name, allowed, source_group
            );
        }

        if !allowed {
            let reason = if matches!(peer.ip(), IpAddr::V4(_)) {
                "policy_deny"
            } else {
                "unsupported_src_ip"
            };
            metrics.observe_dns_query("deny", reason, &source_group);
            metrics.observe_dns_nxdomain("policy");
            let response = build_nxdomain(request);
            listen.send_to(&response, peer).await?;
            continue;
        }

        let start = Instant::now();
        if let Err(err) = upstream.send_to(request, upstream_addr).await {
            metrics.observe_dns_query("deny", "upstream_error", &source_group);
            return Err(err);
        }

        let (resp_len, resp_peer) = match upstream.recv_from(&mut upstream_buf).await {
            Ok(value) => value,
            Err(err) => {
                metrics.observe_dns_query("deny", "upstream_error", &source_group);
                return Err(err);
            }
        };
        if DNS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dns proxy: upstream response from={} bytes={} group={}",
                resp_peer, resp_len, source_group
            );
        }
        let response = &upstream_buf[..resp_len];
        if let Err(reason) = validate_dns_response(&question, response, resp_peer, upstream_addr) {
            metrics.observe_dns_query("deny", "upstream_mismatch", &source_group);
            metrics.observe_dns_upstream_mismatch(reason.as_label(), &source_group);
            metrics.observe_dns_nxdomain("upstream_mismatch");
            let response = build_nxdomain(request);
            listen.send_to(&response, peer).await?;
            continue;
        }
        metrics.observe_dns_upstream_rtt(&source_group, start.elapsed());
        metrics.observe_dns_query("allow", "policy_allow", &source_group);
        if is_nxdomain(response) {
            metrics.observe_dns_nxdomain("upstream");
        }

        let ips = extract_ips_from_dns_response(response);
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

        listen.send_to(response, peer).await?;
    }
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
}
