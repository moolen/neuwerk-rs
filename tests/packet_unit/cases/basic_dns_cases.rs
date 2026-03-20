// Extracted from packet_unit/cases.rs (basic parse, fragment, DNS/no-SNAT routing)
#[test]
fn test_ipv4_parsing() {
    let pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        1234,
        53,
        b"hello",
    );
    assert_eq!(pkt.src_ip(), Some(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(pkt.dst_ip(), Some(Ipv4Addr::new(1, 1, 1, 1)));
}

#[test]
fn test_ipv4_fragment_drops_with_metric() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(93, 184, 216, 34));
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );
    let metrics = Metrics::new().unwrap();
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_metrics(metrics.clone());

    let mut pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        80,
        b"frag",
    );
    {
        let buf = pkt.buffer_mut();
        buf[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    }
    pkt.recalc_checksums();

    let action = handle_packet(&mut pkt, &mut state);
    assert!(matches!(action, Action::Drop));

    let rendered = metrics.render().unwrap();
    let value = metric_value(&rendered, "dp_ipv4_fragments_dropped_total").unwrap_or(0.0);
    assert!(value >= 1.0, "metrics:\n{rendered}");
}

#[test]
fn dns_target_udp_short_circuits_policy_and_round_trips() {
    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    set_dataplane_ip(&mut state, Ipv4Addr::new(10, 0, 0, 1));
    let dns_target = Ipv4Addr::new(198, 51, 100, 53);
    state.set_dns_target_ips(vec![dns_target]);

    let client_ip = Ipv4Addr::new(10, 0, 0, 42);
    let mut outbound = build_ipv4_udp(client_ip, dns_target, 40000, 53, b"dns-udp");
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(outbound.src_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
    let external_port = outbound.ports().map(|(src, _)| src).unwrap_or(0);
    assert_ne!(external_port, 40000);

    let mut inbound = build_ipv4_udp(
        dns_target,
        Ipv4Addr::new(10, 0, 0, 1),
        53,
        external_port,
        b"ok",
    );
    let action = handle_packet(&mut inbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(inbound.dst_ip(), Some(client_ip));
    assert_eq!(inbound.ports().map(|(_, dst)| dst), Some(40000));
}

#[test]
fn dns_target_tcp_short_circuits_policy() {
    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    set_dataplane_ip(&mut state, Ipv4Addr::new(10, 0, 0, 1));
    let dns_target = Ipv4Addr::new(198, 51, 100, 53);
    state.set_dns_target_ips(vec![dns_target]);

    let mut outbound = build_ipv4_tcp(Ipv4Addr::new(10, 0, 0, 42), dns_target, 40001, 53, b"");
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(outbound.src_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn no_snat_plain_inbound_reverse_flow_round_trip() {
    let allowlist = DynamicIpSetV4::new();
    let server_ip = Ipv4Addr::new(198, 51, 100, 10);
    let client_ip = Ipv4Addr::new(10, 0, 0, 42);
    allowlist.insert(server_ip);
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_snat_mode(SnatMode::None);

    let src_port = 40000u16;
    let dst_port = 5201u16;
    let mut outbound = build_ipv4_tcp(client_ip, server_ip, src_port, dst_port, &[]);
    set_tcp_flags(&mut outbound, 0x02);
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(outbound.src_ip(), Some(client_ip));
    assert_eq!(outbound.dst_ip(), Some(server_ip));
    assert_eq!(outbound.ports(), Some((src_port, dst_port)));

    let mut inbound = build_ipv4_tcp(server_ip, client_ip, dst_port, src_port, &[]);
    set_tcp_flags(&mut inbound, 0x12);
    let action = handle_packet(&mut inbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(inbound.src_ip(), Some(server_ip));
    assert_eq!(inbound.dst_ip(), Some(client_ip));
    assert_eq!(inbound.ports(), Some((dst_port, src_port)));
}

#[test]
fn dns_non_target_still_uses_policy_path() {
    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        Vec::new(),
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    set_dataplane_ip(&mut state, Ipv4Addr::new(10, 0, 0, 1));
    state.set_dns_target_ips(vec![Ipv4Addr::new(198, 51, 100, 53)]);

    let mut outbound = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 54),
        40002,
        53,
        b"dns-udp",
    );
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Drop);
}
