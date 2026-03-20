// Extracted from packet_unit/cases.rs (TLS decision/intercept behavior)
#[test]
fn test_tls_sni_allows_flow() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    let tls = TlsMatch {
        mode: TlsMode::Metadata,
        sni: Some(TlsNameMatch {
            exact: vec!["api.example.com".to_string()],
            regex: None,
        }),
        server_san: None,
        server_cn: None,
        fingerprints_sha256: Vec::new(),
        trust_anchors: Vec::new(),
        tls13_uninspectable: Tls13Uninspectable::Deny,
        intercept_http: None,
    };

    let rule = Rule {
        id: "tls".to_string(),
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
            tls: Some(tls),
        },
        action: RuleAction::Allow,
        mode: neuwerk::dataplane::policy::RuleMode::Enforce,
    };

    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![group],
    )));

    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );

    let payload = tls_client_hello_record("api.example.com");
    let mut pkt = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        443,
        &payload,
    );

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
}

#[test]
fn test_tls_application_data_before_handshake_denies() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    let tls = TlsMatch {
        mode: TlsMode::Metadata,
        sni: Some(TlsNameMatch {
            exact: vec!["api.example.com".to_string()],
            regex: None,
        }),
        server_san: None,
        server_cn: None,
        fingerprints_sha256: Vec::new(),
        trust_anchors: Vec::new(),
        tls13_uninspectable: Tls13Uninspectable::Deny,
        intercept_http: None,
    };

    let rule = Rule {
        id: "tls".to_string(),
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
            tls: Some(tls),
        },
        action: RuleAction::Allow,
        mode: neuwerk::dataplane::policy::RuleMode::Enforce,
    };

    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![group],
    )));

    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );

    let payload = tls_application_data_record(b"app-data");
    let mut pkt = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        443,
        &payload,
    );

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Drop);
}

#[test]
fn test_tls_intercept_fail_closed_sends_rst() {
    let policy = Arc::new(RwLock::new(policy_with_tls_intercept(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        1,
    )));

    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(0)));

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkt = build_ipv4_tcp(client_ip, server_ip, 40000, 443, &[]);
    {
        let buf = pkt.buffer_mut();
        let l4_off = 20;
        buf[l4_off + 4..l4_off + 8].copy_from_slice(&100u32.to_be_bytes());
        buf[l4_off + 8..l4_off + 12].copy_from_slice(&77u32.to_be_bytes());
        buf[l4_off + 13] = 0x10; // ACK
    }
    assert!(pkt.recalc_checksums());

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(pkt.src_ip(), Some(server_ip));
    assert_eq!(pkt.dst_ip(), Some(client_ip));
    assert_eq!(pkt.ports(), Some((443, 40000)));
    assert_eq!(pkt.tcp_flags(), Some(0x14)); // RST + ACK
    assert_eq!(pkt.tcp_seq(), Some(77));
    assert_eq!(pkt.tcp_ack(), Some(100));

    let flow = FlowKey {
        src_ip: client_ip,
        dst_ip: server_ip,
        src_port: 40000,
        dst_port: 443,
        proto: 6,
    };
    assert!(!state.flows.contains(&flow));
}

#[test]
fn test_tls_intercept_allows_when_service_plane_ready() {
    let policy = Arc::new(RwLock::new(policy_with_tls_intercept(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        1,
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    let mut pkt = build_ipv4_tcp(client_ip, server_ip, 40000, 443, &[]);
    set_tcp_flags(&mut pkt, 0x02);
    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(pkt.src_ip(), Some(Ipv4Addr::new(203, 0, 113, 1)));
    assert_eq!(pkt.dst_ip(), Some(server_ip));
    assert_eq!(pkt.tcp_flags().unwrap() & 0x04, 0);

    let flow = FlowKey {
        src_ip: client_ip,
        dst_ip: server_ip,
        src_port: 40000,
        dst_port: 443,
        proto: 6,
    };
    assert!(state.flows.contains(&flow));
}

#[test]
fn test_tls_intercept_steers_to_host_when_enabled() {
    let policy = Arc::new(RwLock::new(policy_with_tls_intercept(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        1,
    )));
    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_intercept_to_host_steering(true);

    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    let original_sport = 40000u16;
    let mut pkt = build_ipv4_tcp(client_ip, server_ip, original_sport, 443, &[]);
    set_tcp_flags(&mut pkt, 0x02);
    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::ToHost);
    assert_eq!(pkt.src_ip(), Some(client_ip));
    assert_eq!(pkt.dst_ip(), Some(server_ip));
    assert_eq!(pkt.ports(), Some((original_sport, 443)));

    let flow = FlowKey {
        src_ip: client_ip,
        dst_ip: server_ip,
        src_port: original_sport,
        dst_port: 443,
        proto: 6,
    };
    assert!(state.flows.contains(&flow));
}

#[test]
fn test_tls_intercept_fail_closed_sends_rst_on_generation_recheck() {
    let allowlist = DynamicIpSetV4::new();
    let server_ip = Ipv4Addr::new(93, 184, 216, 34);
    allowlist.insert(server_ip);
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );
    let mut state = EngineState::new(
        policy.clone(),
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    let service_applied_generation = Arc::new(AtomicU64::new(0));
    state.set_service_policy_applied_generation(service_applied_generation.clone());
    let client_ip = Ipv4Addr::new(10, 0, 0, 2);
    let flow = FlowKey {
        src_ip: client_ip,
        dst_ip: server_ip,
        src_port: 40000,
        dst_port: 443,
        proto: 6,
    };

    let mut first = build_ipv4_tcp(client_ip, server_ip, 40000, 443, &[]);
    set_tcp_flags(&mut first, 0x02);
    let first_action = handle_packet(&mut first, &mut state);
    assert_eq!(first_action, Action::Forward { out_port: 0 });
    assert!(state.flows.contains(&flow));

    if let Ok(mut lock) = policy.write() {
        *lock = policy_with_tls_intercept(Ipv4Addr::new(10, 0, 0, 0), 24, 1);
    } else {
        panic!("policy lock poisoned");
    }
    refresh_policy_state(&mut state);

    let mut second = build_ipv4_tcp(client_ip, server_ip, 40000, 443, &[]);
    {
        let buf = second.buffer_mut();
        let l4_off = 20;
        buf[l4_off + 4..l4_off + 8].copy_from_slice(&300u32.to_be_bytes());
        buf[l4_off + 8..l4_off + 12].copy_from_slice(&90u32.to_be_bytes());
        buf[l4_off + 13] = 0x10; // ACK
    }
    assert!(second.recalc_checksums());

    let second_action = handle_packet(&mut second, &mut state);
    assert_eq!(second_action, Action::Forward { out_port: 0 });
    assert_eq!(second.src_ip(), Some(server_ip));
    assert_eq!(second.dst_ip(), Some(client_ip));
    assert_eq!(second.ports(), Some((443, 40000)));
    assert_eq!(second.tcp_flags(), Some(0x14)); // RST + ACK
    assert_eq!(second.tcp_seq(), Some(90));
    assert_eq!(second.tcp_ack(), Some(300));
    assert!(!state.flows.contains(&flow));
}
