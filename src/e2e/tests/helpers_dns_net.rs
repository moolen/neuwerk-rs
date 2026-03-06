use super::*;
pub(in crate::e2e::tests) fn assert_dns_allowed(
    resp: &crate::e2e::services::DnsResponse,
    expected_ip: Ipv4Addr,
) -> Result<(), String> {
    if resp.rcode != 0 {
        return Err(format!("dns response unexpected rcode: {}", resp.rcode));
    }
    if !resp.ips.contains(&IpAddr::V4(expected_ip)) {
        return Err(format!("dns response missing {}", expected_ip));
    }
    Ok(())
}

pub(in crate::e2e::tests) fn assert_dns_nxdomain(
    resp: &crate::e2e::services::DnsResponse,
) -> Result<(), String> {
    if resp.rcode != 3 {
        return Err(format!(
            "dns response expected NXDOMAIN, got rcode {}",
            resp.rcode
        ));
    }
    Ok(())
}

pub(in crate::e2e::tests) fn send_udp_once(
    bind: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind(bind).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(payload, dst)
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(())
}

pub(in crate::e2e::tests) fn send_udp_with_payload_from_port(
    bind_ip: Ipv4Addr,
    bind_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind((bind_ip, bind_port))
        .map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(payload, (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(())
}

pub(in crate::e2e::tests) fn send_udp_with_ttl(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ttl: u32,
) -> Result<u16, String> {
    let socket =
        std::net::UdpSocket::bind((bind_ip, 0)).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .set_ttl(ttl)
        .map_err(|e| format!("set ttl failed: {e}"))?;
    socket
        .send_to(b"ttl", (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(socket
        .local_addr()
        .map_err(|e| format!("udp local addr failed: {e}"))?
        .port())
}

pub(in crate::e2e::tests) fn send_udp_with_ttl_payload(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ttl: u32,
    payload: &[u8],
) -> Result<u16, String> {
    let socket =
        std::net::UdpSocket::bind((bind_ip, 0)).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .set_ttl(ttl)
        .map_err(|e| format!("set ttl failed: {e}"))?;
    socket
        .send_to(payload, (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(socket
        .local_addr()
        .map_err(|e| format!("udp local addr failed: {e}"))?
        .port())
}
