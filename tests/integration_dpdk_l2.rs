use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use firewall::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PolicySnapshot, PortRange, Proto, Rule, RuleAction, RuleMatch,
    RuleMode, SourceGroup, Tls13Uninspectable, TlsMatch, TlsMode,
};
use firewall::dataplane::{DataplaneConfig, DpdkAdapter, EngineState};

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;

fn build_udp_ipv4_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
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
    buf[ip_off + 9] = 17;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);
    buf
}

fn build_arp_reply(
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&2u16.to_be_bytes());
    buf[22..28].copy_from_slice(&src_mac);
    buf[28..32].copy_from_slice(&src_ip.octets());
    buf[32..38].copy_from_slice(&dst_mac);
    buf[38..42].copy_from_slice(&dst_ip.octets());
    buf
}

#[test]
fn integration_dpdk_l2_rewrite_uses_gateway_mac() {
    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Allow,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 20, 3, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 20, 2, 4),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 20, 2, 1),
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        lease_expiry: None,
    });

    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let payload = b"hello";
    let frame = build_udp_ipv4_frame(
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        Ipv4Addr::new(10, 20, 3, 4),
        Ipv4Addr::new(10, 20, 4, 4),
        12345,
        80,
        payload,
    );

    assert!(adapter.process_frame(&frame, &mut state).is_none());
    let arp_req = adapter.next_dhcp_frame(&state).expect("arp request queued");
    assert_eq!(u16::from_be_bytes([arp_req[12], arp_req[13]]), ETH_TYPE_ARP);
    assert_eq!(&arp_req[38..42], &Ipv4Addr::new(10, 20, 2, 1).octets());

    let gw_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let arp_reply = build_arp_reply(
        gw_mac,
        Ipv4Addr::new(10, 20, 2, 1),
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        Ipv4Addr::new(10, 20, 2, 4),
    );
    assert!(adapter.process_frame(&arp_reply, &mut state).is_none());

    let forwarded = adapter
        .process_frame(&frame, &mut state)
        .expect("forwarded frame");
    assert_eq!(&forwarded[0..6], &gw_mac);
    assert_eq!(&forwarded[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
}

#[test]
fn integration_dpdk_intercept_steers_to_service_lane_queue() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let rule = Rule {
        id: "tls-intercept".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
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
                intercept_http: None,
            }),
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    };
    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };
    let policy = Arc::new(RwLock::new(PolicySnapshot::new_with_generation(
        DefaultPolicy::Deny,
        vec![group],
        1,
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(std::sync::Arc::new(
        std::sync::atomic::AtomicU64::new(1),
    ));
    state.set_intercept_to_host_steering(true);
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        lease_expiry: None,
    });

    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let syn = {
        let total_len = 20 + 20;
        let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
        buf[0..6].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        buf[6..12].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
        buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        let ip_off = ETH_HDR_LEN;
        buf[ip_off] = 0x45;
        buf[ip_off + 2..ip_off + 4].copy_from_slice(&(40u16).to_be_bytes());
        buf[ip_off + 8] = 64;
        buf[ip_off + 9] = 6;
        buf[ip_off + 12..ip_off + 16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
        buf[ip_off + 16..ip_off + 20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 10).octets());
        let tcp_off = ip_off + 20;
        buf[tcp_off..tcp_off + 2].copy_from_slice(&40000u16.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&443u16.to_be_bytes());
        buf[tcp_off + 12] = 0x50;
        buf[tcp_off + 13] = 0x02;
        let mut pkt = firewall::dataplane::packet::Packet::new(buf);
        assert!(pkt.recalc_checksums());
        pkt.buffer().to_vec()
    };

    let out = adapter.process_frame(&syn, &mut state);
    assert!(
        out.is_none(),
        "intercept steer should not emit dataplane egress"
    );
    let host_frame = adapter
        .next_host_frame()
        .expect("expected intercept frame queued for service lane");
    assert_eq!(
        u16::from_be_bytes([host_frame[12], host_frame[13]]),
        ETH_TYPE_IPV4
    );
}

#[test]
fn integration_dpdk_service_lane_return_path_emits_arp_on_miss() {
    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        lease_expiry: None,
    });

    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let client_ip = Ipv4Addr::new(10, 0, 0, 99);
    let service_egress = {
        let total_len = 20 + 20;
        let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
        buf[0..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        buf[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        let ip_off = ETH_HDR_LEN;
        buf[ip_off] = 0x45;
        buf[ip_off + 2..ip_off + 4].copy_from_slice(&(40u16).to_be_bytes());
        buf[ip_off + 8] = 64;
        buf[ip_off + 9] = 6;
        buf[ip_off + 12..ip_off + 16].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 10).octets());
        buf[ip_off + 16..ip_off + 20].copy_from_slice(&client_ip.octets());
        let tcp_off = ip_off + 20;
        buf[tcp_off..tcp_off + 2].copy_from_slice(&443u16.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&40000u16.to_be_bytes());
        buf[tcp_off + 12] = 0x50;
        buf[tcp_off + 13] = 0x10;
        let mut pkt = firewall::dataplane::packet::Packet::new(buf);
        assert!(pkt.recalc_checksums());
        pkt.buffer().to_vec()
    };

    let out = adapter.process_service_lane_egress_frame(&service_egress, &state);
    assert!(out.is_none(), "expected ARP miss for unknown client");
    let arp_req = adapter.next_dhcp_frame(&state).expect("arp request queued");
    assert_eq!(u16::from_be_bytes([arp_req[12], arp_req[13]]), ETH_TYPE_ARP);
    assert_eq!(&arp_req[38..42], &client_ip.octets());
}
