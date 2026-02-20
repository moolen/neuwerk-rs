use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;

use crate::dataplane::policy::DynamicIpSetV4;

pub async fn run_dns_proxy(
    bind_addr: SocketAddr,
    upstream_addr: SocketAddr,
    allowlist: DynamicIpSetV4,
) -> io::Result<()> {
    let listen = UdpSocket::bind(bind_addr).await?;
    let upstream = UdpSocket::bind("0.0.0.0:0").await?;

    let mut buf = vec![0u8; 2048];
    let mut upstream_buf = vec![0u8; 2048];

    loop {
        let (len, peer) = listen.recv_from(&mut buf).await?;
        upstream.send_to(&buf[..len], upstream_addr).await?;

        let (resp_len, _) = upstream.recv_from(&mut upstream_buf).await?;
        let response = &upstream_buf[..resp_len];

        let ips = extract_ips_from_dns_response(response);
        if !ips.is_empty() {
            for ip in ips {
                if let IpAddr::V4(v4) = ip {
                    allowlist.insert(v4);
                }
            }
        }

        listen.send_to(response, peer).await?;
    }
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

    #[test]
    fn skip_name_handles_root() {
        let msg = [0u8, 0u8];
        assert_eq!(skip_name(&msg, 0), Some(1));
    }
}
