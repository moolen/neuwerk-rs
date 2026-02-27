use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use firewall::dataplane::policy::{DefaultPolicy, PolicySnapshot};
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
