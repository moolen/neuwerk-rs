use super::*;
use crate::dataplane::config::DataplaneConfig;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction, RuleMatch,
    SourceGroup, Tls13Uninspectable, TlsMatch, TlsMode,
};
use crate::metrics::Metrics;
use crate::support::runtime_knobs::{with_runtime_knobs, RuntimeKnobs};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

#[derive(Default)]
struct RecordingIo {
    sent: Vec<Vec<u8>>,
}

impl FrameIo for RecordingIo {
    fn recv_frame(&mut self, _buf: &mut [u8]) -> Result<usize, String> {
        Ok(0)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.sent.push(frame.to_vec());
        Ok(())
    }
}

fn metric_value(rendered: &str, name: &str) -> Option<f64> {
    for line in rendered.lines() {
        if line.starts_with('#') || !line.starts_with(name) {
            continue;
        }
        if line.contains('{') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let metric = parts.next()?;
        if metric != name {
            continue;
        }
        let value = parts.next()?;
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

fn with_test_runtime_knobs<R>(
    configure: impl FnOnce(&mut RuntimeKnobs),
    f: impl FnOnce() -> R,
) -> R {
    let mut knobs = RuntimeKnobs::default();
    configure(&mut knobs);
    with_runtime_knobs(knobs, f)
}

fn with_intercept_env<R>(ip: Option<&str>, port: Option<&str>, f: impl FnOnce() -> R) -> R {
    with_test_runtime_knobs(
        |knobs| {
            if let Some(value) = ip {
                knobs.dpdk.service_lane_intercept_service_ip =
                    value.parse().expect("intercept ip");
            }
            if let Some(value) = port {
                knobs.dpdk.service_lane_intercept_service_port =
                    value.parse().expect("intercept port");
            }
        },
        f,
    )
}

fn with_default_intercept_env<R>(f: impl FnOnce() -> R) -> R {
    with_intercept_env(None, None, f)
}

fn with_gateway_trust_env<R>(
    gateway_mac: Option<&str>,
    dhcp_server_ip: Option<&str>,
    dhcp_server_mac: Option<&str>,
    f: impl FnOnce() -> R,
) -> R {
    with_test_runtime_knobs(
        |knobs| {
            knobs.dpdk.gateway_mac = gateway_mac.map(ToOwned::to_owned);
            knobs.dpdk.dhcp_server_ip =
                dhcp_server_ip.map(|value| value.parse().expect("dhcp server ip"));
            knobs.dpdk.dhcp_server_mac = dhcp_server_mac.map(ToOwned::to_owned);
        },
        f,
    )
}

fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

fn build_udp_ipv4_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_udp_frame(
        src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload,
    )
}

fn build_tcp_syn_ipv4_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    build_tcp_ipv4_frame_with_flags(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 0x02)
}

fn build_tcp_ipv4_frame_with_flags(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
) -> Vec<u8> {
    let total_len = 20 + 20;
    let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_off = ETH_HDR_LEN;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 6;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64240u16.to_be_bytes());
    buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&0u16.to_be_bytes());
    buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&0u16.to_be_bytes());

    let mut pkt = Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + inner.len()];
    buf[0] = 0x08;
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[8..].copy_from_slice(inner);
    buf
}

fn parse_vxlan_outer_udp(frame: &[u8]) -> Result<(u16, u16, u32), String> {
    if frame.len() < ETH_HDR_LEN + 20 + 8 + 8 {
        return Err("frame too short".to_string());
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETH_TYPE_IPV4 {
        return Err("not ipv4 ethernet frame".to_string());
    }
    let ipv4 = parse_ipv4(frame, ETH_HDR_LEN).ok_or_else(|| "parse ipv4 failed".to_string())?;
    if ipv4.proto != 17 {
        return Err("not udp".to_string());
    }
    let udp = parse_udp(frame, ipv4.l4_offset).ok_or_else(|| "parse udp failed".to_string())?;
    if udp.payload_len < 8 {
        return Err("vxlan payload too short".to_string());
    }
    let payload = &frame[udp.payload_offset..udp.payload_offset + udp.payload_len];
    if payload[0] & 0x08 == 0 {
        return Err("vxlan I-bit not set".to_string());
    }
    let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
    Ok((udp.src_port, udp.dst_port, vni))
}

fn intercept_policy_snapshot() -> PolicySnapshot {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let rule = Rule {
        id: "tls-intercept".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![crate::dataplane::policy::PortRange {
                start: 443,
                end: 443,
            }],
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: Some(TlsMatch {
                mode: TlsMode::Intercept,
                sni: None,
                server_dn: None,
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
    PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], 1)
}

include!("tests/frame_arp_dhcp_cases.rs");
include!("tests/intercept_overlay_cases.rs");
include!("tests/service_lane_cases.rs");
