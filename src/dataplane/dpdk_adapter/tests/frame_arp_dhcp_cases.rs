#[test]
fn process_frame_replies_to_arp_for_dataplane_ip() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let metrics = Metrics::new().unwrap();
    let mut state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
    state.set_metrics(metrics.clone());
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            lease_expiry: None,
        });
        store
    });

    let req = build_arp_request(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
    );
    let reply = adapter.process_frame(&req, &mut state).expect("arp reply");
    assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    assert_eq!(&reply[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 2);

    let rendered = metrics.render().unwrap();
    let value = metric_value(&rendered, "dp_arp_handled_total").unwrap_or(0.0);
    assert!(value >= 1.0, "metrics:\n{rendered}");
}

#[test]
fn process_frame_sends_dhcp_payload_to_control_plane() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    adapter.set_dhcp_tx(tx);
    let mut state = EngineState::new(
        Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        ))),
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::UNSPECIFIED,
        0,
    );

    let payload = b"dhcp-test";
    let frame = build_udp_ipv4_frame(
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        [0xff; 6],
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::BROADCAST,
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
        payload,
    );
    assert!(adapter.process_frame(&frame, &mut state).is_none());
    let msg = rx.try_recv().expect("dhcp rx");
    assert_eq!(msg.src_ip, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(msg.payload, payload);
}

#[test]
fn process_frame_learns_arp_from_dhcp_server_frame() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let mut state = EngineState::new(
        Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        ))),
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    let server_ip = Ipv4Addr::new(10, 0, 0, 254);
    let server_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let frame = build_udp_ipv4_frame(
        server_mac,
        [0xff; 6],
        server_ip,
        Ipv4Addr::BROADCAST,
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
        b"dhcp-test",
    );

    assert!(adapter.process_frame(&frame, &mut state).is_none());
    assert_eq!(adapter.lookup_arp(server_ip), Some(server_mac));
}

#[test]
fn next_dhcp_frame_builds_broadcast_frame() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

    let (tx, rx) = mpsc::channel(1);
    adapter.set_dhcp_rx(rx);
    tx.try_send(DhcpTx::Broadcast {
        payload: b"hello".to_vec(),
    })
    .unwrap();

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
    let frame = adapter.next_dhcp_frame(&state).expect("dhcp frame");
    assert_eq!(&frame[0..6], &[0xff; 6]);
    assert_eq!(&frame[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_TYPE_IPV4);
    let udp_off = ETH_HDR_LEN + 20;
    assert_eq!(
        u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]),
        DHCP_CLIENT_PORT
    );
    assert_eq!(
        u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]),
        DHCP_SERVER_PORT
    );
}

#[test]
fn process_packet_in_place_forward_returns_borrowed_and_rewrites_l2() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let gw_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let gw_ip = Ipv4Addr::new(10, 20, 2, 1);
    let fw_ip = Ipv4Addr::new(10, 20, 2, 4);
    adapter.set_mac(fw_mac);
    adapter.insert_arp(gw_ip, gw_mac);

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
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: gw_ip,
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let frame = build_udp_ipv4_frame(
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
        fw_mac,
        Ipv4Addr::new(10, 20, 3, 4),
        Ipv4Addr::new(10, 20, 4, 4),
        12345,
        80,
        b"hello",
    );
    let mut pkt = Packet::new(frame);

    match adapter.process_packet_in_place(&mut pkt, &mut state) {
        Some(FrameOut::Borrowed(out)) => {
            assert_eq!(out.as_ptr(), pkt.buffer().as_ptr());
            assert_eq!(&pkt.buffer()[0..6], &gw_mac);
            assert_eq!(&pkt.buffer()[6..12], &fw_mac);
        }
        Some(FrameOut::Owned(_)) => panic!("expected borrowed frame for forward path"),
        None => panic!("expected forwarded frame"),
    }
}

#[test]
fn process_packet_in_place_arp_returns_owned() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let req = build_arp_request(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        Ipv4Addr::new(10, 0, 0, 1),
        fw_ip,
    );
    let mut pkt = Packet::new(req);
    match adapter.process_packet_in_place(&mut pkt, &mut state) {
        Some(FrameOut::Owned(reply)) => {
            assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
            assert_eq!(&reply[6..12], &fw_mac);
            assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 2);
        }
        Some(FrameOut::Borrowed(_)) => panic!("expected owned reply for arp path"),
        None => panic!("expected arp reply"),
    }
}

#[test]
fn process_packet_in_place_health_probe_returns_owned() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    let client_ip = Ipv4Addr::new(10, 0, 0, 99);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let syn = build_tcp_syn_ipv4_frame(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        client_ip,
        fw_ip,
        40000,
        HEALTH_PROBE_PORT,
    );
    let mut pkt = Packet::new(syn);
    match adapter.process_packet_in_place(&mut pkt, &mut state) {
        Some(FrameOut::Owned(reply)) => {
            let ipv4 = parse_ipv4(&reply, ETH_HDR_LEN).expect("ipv4");
            let tcp = parse_tcp(&reply, ipv4.l4_offset).expect("tcp");
            assert_eq!(ipv4.src, fw_ip);
            assert_eq!(ipv4.dst, client_ip);
            assert_eq!(tcp.src_port, HEALTH_PROBE_PORT);
            assert_eq!(tcp.dst_port, 40000);
            assert_eq!(tcp.flags & 0x12, 0x12);
        }
        Some(FrameOut::Borrowed(_)) => panic!("expected owned reply for health probe path"),
        None => panic!("expected health probe synack"),
    }
}

#[test]
fn process_frame_health_probe_reply_uses_probe_destination_ip() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    let ilb_vip = Ipv4Addr::new(10, 0, 0, 10);
    let client_ip = Ipv4Addr::new(10, 0, 0, 99);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let syn = build_tcp_syn_ipv4_frame(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        client_ip,
        ilb_vip,
        40000,
        HEALTH_PROBE_PORT,
    );
    let out = adapter
        .process_frame(&syn, &mut state)
        .expect("health probe syn should get synack");
    let ipv4 = parse_ipv4(&out, ETH_HDR_LEN).expect("ipv4");
    let tcp = parse_tcp(&out, ipv4.l4_offset).expect("tcp");
    assert_eq!(ipv4.src, ilb_vip);
    assert_eq!(ipv4.dst, client_ip);
    assert_eq!(tcp.src_port, HEALTH_PROBE_PORT);
    assert_eq!(tcp.dst_port, 40000);
    assert_eq!(tcp.flags & 0x12, 0x12);
}

#[test]
fn process_frame_health_probe_non_syn_is_ignored() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let ack = build_tcp_ipv4_frame_with_flags(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        Ipv4Addr::new(10, 0, 0, 99),
        fw_ip,
        40000,
        HEALTH_PROBE_PORT,
        0x10,
    );
    assert!(
        adapter.process_frame(&ack, &mut state).is_none(),
        "non-SYN packet to health probe port should not trigger SYN-ACK"
    );
}

#[test]
fn process_frame_gcp_health_probe_port_80_from_hc_range_is_accepted() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let syn = build_tcp_syn_ipv4_frame(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        Ipv4Addr::new(35, 191, 10, 10),
        fw_ip,
        40000,
        80,
    );
    let out = adapter
        .process_frame(&syn, &mut state)
        .expect("gcp health checker source to port 80 should get synack");
    let ipv4 = parse_ipv4(&out, ETH_HDR_LEN).expect("ipv4");
    let tcp = parse_tcp(&out, ipv4.l4_offset).expect("tcp");
    assert_eq!(ipv4.src, fw_ip);
    assert_eq!(ipv4.dst, Ipv4Addr::new(35, 191, 10, 10));
    assert_eq!(tcp.src_port, 80);
    assert_eq!(tcp.dst_port, 40000);
    assert_eq!(tcp.flags & 0x12, 0x12);
}

#[test]
fn process_frame_port_80_from_non_hc_range_is_ignored() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let syn = build_tcp_syn_ipv4_frame(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        Ipv4Addr::new(10, 0, 0, 99),
        fw_ip,
        40000,
        80,
    );
    assert!(
        adapter.process_frame(&syn, &mut state).is_none(),
        "regular data traffic to port 80 must not be intercepted by health probe path"
    );
}

#[test]
fn process_frame_health_probe_fin_returns_ack() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    let client_ip = Ipv4Addr::new(10, 0, 0, 99);
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let fin = build_tcp_ipv4_frame_with_flags(
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        fw_mac,
        client_ip,
        fw_ip,
        40000,
        HEALTH_PROBE_PORT,
        0x11,
    );
    let out = adapter
        .process_frame(&fin, &mut state)
        .expect("health probe fin should get ack");
    let ipv4 = parse_ipv4(&out, ETH_HDR_LEN).expect("ipv4");
    let tcp = parse_tcp(&out, ipv4.l4_offset).expect("tcp");
    assert_eq!(ipv4.src, fw_ip);
    assert_eq!(ipv4.dst, client_ip);
    assert_eq!(tcp.src_port, HEALTH_PROBE_PORT);
    assert_eq!(tcp.dst_port, 40000);
    assert_eq!(tcp.flags & TCP_FLAG_ACK, TCP_FLAG_ACK);
    assert_eq!(tcp.flags & TCP_FLAG_SYN, 0);
}

#[test]
fn build_dhcp_frame_unicast_uses_server_hint_when_ip_matches() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let server_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::new(10, 0, 0, 254);
    adapter.set_mac(fw_mac);
    adapter.dhcp_server_hint = Some(DhcpServerHint {
        ip: server_ip,
        mac: server_mac,
    });

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
    state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: fw_mac,
        lease_expiry: None,
    });

    let frame = adapter
        .build_dhcp_frame(
            &state,
            DhcpTx::Unicast {
                payload: b"renew".to_vec(),
                dst_ip: server_ip,
            },
        )
        .expect("dhcp unicast frame");
    assert_eq!(&frame[0..6], &server_mac);
    assert_eq!(&frame[6..12], &fw_mac);
    let ipv4 = parse_ipv4(&frame, ETH_HDR_LEN).expect("ipv4");
    let udp = parse_udp(&frame, ipv4.l4_offset).expect("udp");
    assert_eq!(ipv4.src, fw_ip);
    assert_eq!(ipv4.dst, server_ip);
    assert_eq!(udp.src_port, DHCP_CLIENT_PORT);
    assert_eq!(udp.dst_port, DHCP_SERVER_PORT);
}

#[test]
fn build_dhcp_frame_unicast_falls_back_to_broadcast_mac_on_hint_miss() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
    adapter.set_mac(fw_mac);
    adapter.dhcp_server_hint = Some(DhcpServerHint {
        ip: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    });

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
    state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: fw_mac,
        lease_expiry: None,
    });

    let dst_ip = Ipv4Addr::new(10, 0, 0, 200);
    let frame = adapter
        .build_dhcp_frame(
            &state,
            DhcpTx::Unicast {
                payload: b"renew".to_vec(),
                dst_ip,
            },
        )
        .expect("dhcp unicast frame");
    assert_eq!(&frame[0..6], &[0xff; 6]);
    assert_eq!(&frame[6..12], &fw_mac);
    let ipv4 = parse_ipv4(&frame, ETH_HDR_LEN).expect("ipv4");
    assert_eq!(ipv4.src, fw_ip);
    assert_eq!(ipv4.dst, dst_ip);
}

#[test]
fn shared_arp_cooldown_prevents_duplicate_arp_requests_across_adapters() {
    let shared = Arc::new(Mutex::new(SharedArpState::default()));
    let mut a = DpdkAdapter::new("data0".to_string()).unwrap();
    let mut b = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    a.set_mac(fw_mac);
    b.set_mac(fw_mac);
    a.set_shared_arp(shared.clone());
    b.set_shared_arp(shared);

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Allow,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: fw_mac,
        lease_expiry: None,
    });

    let frame = build_udp_ipv4_frame(
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
        fw_mac,
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        12345,
        80,
        b"hello",
    );
    assert!(a.process_frame(&frame, &mut state).is_none());
    assert!(b.process_frame(&frame, &mut state).is_none());

    assert!(
        a.next_dhcp_frame(&state).is_some(),
        "first adapter should queue ARP request"
    );
    assert!(
        b.next_dhcp_frame(&state).is_none(),
        "shared cooldown should suppress duplicate ARP request"
    );
}

#[test]
fn lookup_arp_evicts_stale_entries_and_falls_back_to_fresh_shared_cache() {
    let shared = Arc::new(Mutex::new(SharedArpState::default()));
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    adapter.set_shared_arp(shared.clone());

    let stale_ip = Ipv4Addr::new(10, 0, 0, 99);
    let stale_mac = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50];
    adapter.insert_arp(stale_ip, stale_mac);

    let stale_seen = Instant::now() - Duration::from_secs(ARP_CACHE_TTL_SECS + 1);
    adapter.arp_cache.insert(
        stale_ip,
        ArpEntry {
            mac: stale_mac,
            last_seen: stale_seen,
        },
    );
    {
        let mut guard = shared.lock().expect("shared arp lock");
        guard.cache.insert(
            stale_ip,
            ArpEntry {
                mac: stale_mac,
                last_seen: stale_seen,
            },
        );
    }

    assert_eq!(adapter.lookup_arp(stale_ip), None);
    assert!(
        !adapter.arp_cache.contains_key(&stale_ip),
        "stale local ARP entry should be removed"
    );
    assert!(
        !shared
            .lock()
            .expect("shared arp lock")
            .cache
            .contains_key(&stale_ip),
        "stale shared ARP entry should be removed"
    );

    let fresh_ip = Ipv4Addr::new(10, 0, 0, 100);
    let stale_local_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
    let fresh_shared_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
    adapter.arp_cache.insert(
        fresh_ip,
        ArpEntry {
            mac: stale_local_mac,
            last_seen: stale_seen,
        },
    );
    {
        let mut guard = shared.lock().expect("shared arp lock");
        guard.cache.insert(
            fresh_ip,
            ArpEntry {
                mac: fresh_shared_mac,
                last_seen: Instant::now(),
            },
        );
    }

    assert_eq!(adapter.lookup_arp(fresh_ip), Some(fresh_shared_mac));
    assert_eq!(
        adapter.arp_cache.get(&fresh_ip).map(|entry| entry.mac),
        Some(fresh_shared_mac),
        "lookup should refresh local cache from shared cache"
    );
}
