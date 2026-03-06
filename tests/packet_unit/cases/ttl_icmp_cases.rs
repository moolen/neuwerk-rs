// Extracted from packet_unit/cases.rs (TTL + ICMP behavior)
#[test]
fn test_ttl_decrement_on_forward() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(93, 184, 216, 34));
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

    let mut pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        80,
        b"ttl",
    );
    {
        let buf = pkt.buffer_mut();
        buf[8] = 2;
    }
    pkt.recalc_checksums();

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(pkt.ipv4_ttl(), Some(1));
    assert!(ipv4_checksum_valid(pkt.buffer()));
}

#[test]
fn test_ttl_expired_sends_icmp_time_exceeded() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(93, 184, 216, 34));
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
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0; 6],
        lease_expiry: None,
    });

    let orig_src = Ipv4Addr::new(10, 0, 0, 2);
    let orig_dst = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkt = build_ipv4_udp(orig_src, orig_dst, 40000, 80, b"ttl-expired");
    {
        let buf = pkt.buffer_mut();
        buf[8] = 1;
    }
    pkt.recalc_checksums();

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(pkt.protocol(), Some(1));
    assert_eq!(pkt.src_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(pkt.dst_ip(), Some(orig_src));

    let buf = pkt.buffer();
    let ihl = (buf[0] & 0x0f) as usize * 4;
    let icmp_off = ihl;
    assert_eq!(buf[icmp_off], 11);
    assert_eq!(buf[icmp_off + 1], 0);
    assert!(icmp_checksum_valid(buf));
    let embedded = &buf[icmp_off + 8..icmp_off + 8 + 20];
    assert_eq!(embedded[12..16], orig_src.octets());
    assert_eq!(embedded[16..20], orig_dst.octets());
}

#[test]
fn test_icmp_echo_nat_round_trip() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
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
    let dp_ip = Ipv4Addr::new(10, 0, 0, 1);
    set_dataplane_ip(&mut state, dp_ip);

    let internal_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
    let mut echo = build_ipv4_icmp_echo(internal_ip, remote_ip, 8, 0, 0x1234, 1, b"ping");
    let action = handle_packet(&mut echo, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(echo.src_ip(), Some(dp_ip));
    let external_id = echo.icmp_identifier().unwrap();
    assert_ne!(external_id, 0x1234);

    let mut reply = build_ipv4_icmp_echo(remote_ip, dp_ip, 0, 0, external_id, 1, b"pong");
    let action = handle_packet(&mut reply, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(reply.dst_ip(), Some(internal_ip));
    assert_eq!(reply.icmp_identifier(), Some(0x1234));
    assert!(icmp_checksum_valid(reply.buffer()));
}

#[test]
fn test_icmp_decision_metrics() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
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
    let dp_ip = Ipv4Addr::new(10, 0, 0, 1);
    set_dataplane_ip(&mut state, dp_ip);

    let mut allow = build_ipv4_icmp_echo(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 51, 100, 10),
        8,
        0,
        0x1234,
        1,
        b"ping",
    );
    let action = handle_packet(&mut allow, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    let mut deny = build_ipv4_icmp_echo(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(198, 51, 100, 11),
        8,
        0,
        0x1235,
        1,
        b"nope",
    );
    let action = handle_packet(&mut deny, &mut state);
    assert!(matches!(action, Action::Drop));

    let rendered = metrics.render().unwrap();
    assert!(
        metric_has(
            &rendered,
            "dp_icmp_decisions_total",
            &[
                ("direction", "outbound"),
                ("type", "8"),
                ("code", "0"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        ),
        "metrics:\n{rendered}"
    );
    assert!(
        metric_has(
            &rendered,
            "dp_icmp_decisions_total",
            &[
                ("direction", "outbound"),
                ("type", "8"),
                ("code", "0"),
                ("decision", "deny"),
                ("source_group", "default"),
            ],
        ),
        "metrics:\n{rendered}"
    );
}

#[test]
fn test_icmp_error_outbound_rewrites_embedded_dst() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
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
    let dp_ip = Ipv4Addr::new(10, 0, 0, 1);
    set_dataplane_ip(&mut state, dp_ip);

    let internal_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
    let internal_port = 40000;
    let remote_port = 8080;

    let mut outbound = build_ipv4_udp(
        internal_ip,
        remote_ip,
        internal_port,
        remote_port,
        b"payload",
    );
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    let external_port = outbound.ports().unwrap().0;

    let embedded = build_ipv4_udp(
        remote_ip,
        internal_ip,
        remote_port,
        internal_port,
        b"payload",
    );
    let embedded_len = 20 + 8;
    let embedded_slice = embedded.buffer()[..embedded_len].to_vec();
    let mut icmp_err = build_ipv4_icmp_error(internal_ip, remote_ip, 3, 3, &embedded_slice);

    let action = handle_packet(&mut icmp_err, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(icmp_err.src_ip(), Some(dp_ip));

    let inner = icmp_err.icmp_inner_tuple().expect("inner tuple");
    assert_eq!(inner.dst_ip, dp_ip);
    assert_eq!(inner.dst_port, external_port);
}

#[test]
fn test_icmp_error_reverse_nat() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
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
    let dp_ip = Ipv4Addr::new(10, 0, 0, 1);
    set_dataplane_ip(&mut state, dp_ip);

    let internal_ip = Ipv4Addr::new(10, 0, 0, 2);
    let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
    let mut outbound = build_ipv4_udp(internal_ip, remote_ip, 40000, 8080, b"payload");
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    let external_port = outbound.ports().unwrap().0;

    let embedded = build_ipv4_udp(dp_ip, remote_ip, external_port, 8080, b"payload");
    let embedded_len = 20 + 8;
    let embedded_slice = embedded.buffer()[..embedded_len].to_vec();
    let mut icmp_err = build_ipv4_icmp_error(remote_ip, dp_ip, 3, 4, &embedded_slice);
    let action = handle_packet(&mut icmp_err, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(icmp_err.dst_ip(), Some(internal_ip));

    let buf = icmp_err.buffer();
    let ihl = (buf[0] & 0x0f) as usize * 4;
    let inner_off = ihl + 8;
    assert_eq!(buf[inner_off + 12..inner_off + 16], internal_ip.octets());
    assert_eq!(
        u16::from_be_bytes([buf[inner_off + 20], buf[inner_off + 21]]),
        40000
    );
    assert!(icmp_checksum_valid(buf));
}

