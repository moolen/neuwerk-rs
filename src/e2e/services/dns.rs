use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsServerBehavior {
    Primary,
    Secondary,
}

pub(crate) async fn run_dns_server(
    bind: SocketAddr,
    answer_ip: Ipv4Addr,
    answer_ip_alt: Ipv4Addr,
    behavior: DnsServerBehavior,
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
        let response = build_dns_response(request, answer_ip, answer_ip_alt, behavior);
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
    behavior: DnsServerBehavior,
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
    let force_mismatch = name_norm == "spoof-fail.allowed"
        || (name_norm == "spoof.allowed" && behavior == DnsServerBehavior::Primary);
    if force_mismatch {
        resp.extend_from_slice(&[0x33, 0x44]);
    } else {
        resp.extend_from_slice(&request[0..2]);
    }
    if matches_allowed_name(&name_norm) {
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x01]);
    } else {
        resp.extend_from_slice(&[0x81, 0x83]);
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x00]);
    }
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(qsection);

    if matches_allowed_name(&name_norm) {
        let response_ip = if name_norm == "cluster.allowed" {
            answer_ip_alt
        } else {
            answer_ip
        };
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]);
        resp.extend_from_slice(&[0x00, 0x04]);
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
            | "spoof-fail.allowed"
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

pub async fn dns_query_response_tcp(
    bind: SocketAddr,
    server: SocketAddr,
    name: &str,
) -> Result<DnsResponse, String> {
    let socket = tokio::net::TcpSocket::new_v4()
        .map_err(|e| format!("dns tcp client socket failed: {e}"))?;
    socket
        .bind(bind)
        .map_err(|e| format!("dns tcp client bind failed: {e}"))?;
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(2), socket.connect(server))
            .await
            .map_err(|_| "dns tcp connect timed out".to_string())?
            .map_err(|e| format!("dns tcp connect failed: {e}"))?;

    let query = build_dns_query(name);
    if query.len() > u16::MAX as usize {
        return Err("dns tcp query too large".to_string());
    }
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(&query);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| format!("dns tcp write failed: {e}"))?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_exact(&mut len_buf),
    )
    .await
    .map_err(|_| "dns tcp length read timed out".to_string())?
    .map_err(|e| format!("dns tcp length read failed: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    if resp_len == 0 {
        return Err("dns tcp response length is zero".to_string());
    }
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_exact(&mut resp),
    )
    .await
    .map_err(|_| "dns tcp response read timed out".to_string())?
    .map_err(|e| format!("dns tcp response read failed: {e}"))?;
    let rcode = parse_rcode(&resp);
    Ok(DnsResponse {
        ips: extract_ips_from_dns_response(&resp),
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
    msg.extend_from_slice(&[0x12, 0x34]);
    msg.extend_from_slice(&[0x01, 0x00]);
    msg.extend_from_slice(&[0x00, 0x01]);
    msg.extend_from_slice(&[0x00, 0x00]);
    msg.extend_from_slice(&[0x00, 0x00]);
    msg.extend_from_slice(&[0x00, 0x00]);
    let name = name.trim_end_matches('.');
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01]);
    msg.extend_from_slice(&[0x00, 0x01]);
    msg
}
