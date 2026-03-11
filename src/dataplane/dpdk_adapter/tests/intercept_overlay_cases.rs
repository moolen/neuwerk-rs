#[test]
fn process_frame_intercept_uses_env_overridden_service_endpoint() {
    with_intercept_env(Some("169.254.200.9"), Some("18080"), || {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let outbound = build_tcp_syn_ipv4_frame(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            fw_mac,
            Ipv4Addr::new(10, 0, 0, 42),
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );
        assert!(adapter.process_frame(&outbound, &mut state).is_none());
        let host_frame = adapter.next_host_frame().expect("expected host frame");
        let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.dst, Ipv4Addr::new(169, 254, 200, 9));
        assert_eq!(tcp.dst_port, 18080);
    })
}

#[test]
fn intercept_demux_removed_on_client_fin_prevents_tuple_restore() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        adapter.set_mac(fw_mac);
        adapter.insert_arp(client_ip, client_mac);

        let mut state = EngineState::new(
            Arc::new(RwLock::new(intercept_policy_snapshot())),
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let syn = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );
        assert!(adapter.process_frame(&syn, &mut state).is_none());
        let _ = adapter
            .next_host_frame()
            .expect("expected initial host frame");

        let fin = build_tcp_ipv4_frame_with_flags(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
            0x11,
        );
        assert!(adapter.process_frame(&fin, &mut state).is_none());
        let _ = adapter.next_host_frame().expect("expected fin host frame");

        let egress = build_tcp_syn_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            INTERCEPT_SERVICE_IP_DEFAULT,
            client_ip,
            INTERCEPT_SERVICE_PORT_DEFAULT,
            40000,
        );
        let forwarded = adapter
            .process_service_lane_egress_frame(&egress, &state)
            .expect("service-lane frame should still forward");
        let ipv4 = parse_ipv4(&forwarded, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&forwarded, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, INTERCEPT_SERVICE_IP_DEFAULT);
        assert_eq!(tcp.src_port, INTERCEPT_SERVICE_PORT_DEFAULT);
    });
}

#[test]
fn process_frame_overlay_dual_tunnel_swaps_and_forces_src_port() {
    let _env_guard = ENV_LOCK.lock().expect("env lock");
    let old_swap = std::env::var("NEUWERK_GWLB_SWAP_TUNNELS").ok();
    let old_force = std::env::var("NEUWERK_GWLB_TUNNEL_SRC_PORT").ok();
    std::env::set_var("NEUWERK_GWLB_SWAP_TUNNELS", "1");
    std::env::set_var("NEUWERK_GWLB_TUNNEL_SRC_PORT", "1");

    {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

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
        state.set_snat_mode(crate::dataplane::overlay::SnatMode::None);
        state.set_overlay_config(crate::dataplane::overlay::OverlayConfig {
            mode: EncapMode::Vxlan,
            udp_port: 0,
            udp_port_internal: Some(10800),
            udp_port_external: Some(10801),
            vni: None,
            vni_internal: Some(800),
            vni_external: Some(801),
            mtu: 1500,
        });

        let inner = build_udp_ipv4_frame(
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            [0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
            Ipv4Addr::new(10, 0, 0, 42),
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            80,
            b"hello",
        );
        let payload = build_vxlan_payload(&inner, 800);
        let outer = build_udp_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 11),
            5555,
            10800,
            &payload,
        );

        let out = adapter
            .process_frame(&outer, &mut state)
            .expect("overlay frame should forward");
        let (src_port, dst_port, vni) = parse_vxlan_outer_udp(&out).expect("parse output vxlan");
        assert_eq!(dst_port, 10801, "reply should switch to external tunnel");
        assert_eq!(vni, 801, "reply should switch to external vni");
        assert_eq!(
            src_port, 10801,
            "outer src port should be forced to tunnel port"
        );
    }

    match old_swap {
        Some(value) => std::env::set_var("NEUWERK_GWLB_SWAP_TUNNELS", value),
        None => std::env::remove_var("NEUWERK_GWLB_SWAP_TUNNELS"),
    }
    match old_force {
        Some(value) => std::env::set_var("NEUWERK_GWLB_TUNNEL_SRC_PORT", value),
        None => std::env::remove_var("NEUWERK_GWLB_TUNNEL_SRC_PORT"),
    }

}

#[test]
fn process_frame_intercept_fail_closed_returns_rst() {
    let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    adapter.set_mac(fw_mac);

    let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(0)));
    state.set_dataplane_config({
        let store = crate::dataplane::config::DataplaneConfigStore::new();
        store.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });
        store
    });

    let client_ip = Ipv4Addr::new(10, 0, 0, 42);
    let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    adapter.insert_arp(client_ip, client_mac);
    let outbound = build_tcp_syn_ipv4_frame(
        client_mac,
        fw_mac,
        client_ip,
        Ipv4Addr::new(198, 51, 100, 10),
        40000,
        443,
    );

    let rst = adapter
        .process_frame(&outbound, &mut state)
        .expect("expected fail-closed rst frame");
    assert_eq!(&rst[0..6], &client_mac);
    assert_eq!(&rst[6..12], &fw_mac);
    let ipv4 = parse_ipv4(&rst, ETH_HDR_LEN).expect("ipv4");
    let tcp = parse_tcp(&rst, ipv4.l4_offset).expect("tcp");
    assert!(
        tcp.flags & 0x04 != 0,
        "tcp rst flag missing: {:02x}",
        tcp.flags
    );
    assert_eq!(ipv4.src, Ipv4Addr::new(198, 51, 100, 10));
    assert_eq!(ipv4.dst, client_ip);
}

#[test]
fn process_frame_intercept_ready_queues_service_lane_frame() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );

        let out = adapter.process_frame(&outbound, &mut state);
        assert!(
            out.is_none(),
            "intercept-eligible flow should not egress dataplane directly"
        );
        let host_frame = adapter
            .next_host_frame()
            .expect("expected service-lane frame");
        assert_eq!(host_frame.len(), outbound.len());
        assert_eq!(&host_frame[0..6], &[0xff; 6]);
        assert_eq!(
            u16::from_be_bytes([host_frame[12], host_frame[13]]),
            ETH_TYPE_IPV4
        );
        let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, client_ip);
        assert_eq!(ipv4.dst, INTERCEPT_SERVICE_IP_DEFAULT);
        assert_eq!(tcp.dst_port, INTERCEPT_SERVICE_PORT_DEFAULT);
    });
}

#[test]
fn process_frame_intercept_ready_targets_service_lane_mac_when_known() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let svc_mac = [0x4a, 0x0e, 0x7b, 0x9e, 0x36, 0x7d];
        adapter.set_mac(fw_mac);
        adapter.service_lane_mac = Some(svc_mac);

        let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );

        let out = adapter.process_frame(&outbound, &mut state);
        assert!(
            out.is_none(),
            "intercept-eligible flow should not egress dataplane directly"
        );
        let host_frame = adapter
            .next_host_frame()
            .expect("expected service-lane frame");
        assert_eq!(host_frame.len(), outbound.len());
        assert_eq!(&host_frame[0..6], &svc_mac);
        let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, client_ip);
        assert_eq!(ipv4.dst, INTERCEPT_SERVICE_IP_DEFAULT);
        assert_eq!(tcp.dst_port, INTERCEPT_SERVICE_PORT_DEFAULT);
    });
}
