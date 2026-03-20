// Extracted from packet_unit/cases.rs (NAT/flow lifecycle behavior)
#[test]
fn test_udp_parsing() {
    let pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        1234,
        53,
        b"hello",
    );
    assert_eq!(pkt.ports(), Some((1234, 53)));
}

#[test]
fn test_tcp_parsing() {
    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(1, 1, 1, 1),
        10000,
        443,
        b"data",
    );
    assert_eq!(pkt.ports(), Some((10000, 443)));
}

#[test]
fn test_nat_rewrite_and_flow() {
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
    let dp_ip = Ipv4Addr::new(10, 0, 0, 1);
    set_dataplane_ip(&mut state, dp_ip);

    let mut pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        80,
        b"ping",
    );

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip: Ipv4Addr::new(93, 184, 216, 34),
        src_port: 40000,
        dst_port: 80,
        proto: 17,
    };
    let entry = state.nat.get_entry(&flow).unwrap();
    assert_eq!(pkt.src_ip(), Some(dp_ip));
    assert_eq!(pkt.ports().unwrap().0, entry.external_port);
    assert!(state.flows.contains(&flow));
    assert!(ipv4_checksum_valid(pkt.buffer()));
    assert!(udp_checksum_valid(pkt.buffer()));
}

#[test]
fn test_flow_end_emits_wiretap() {
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
    state.flows = FlowTable::new_with_timeout(1);
    state.nat = NatTable::new_with_timeout(1);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    state.set_wiretap_emitter(WiretapEmitter::new(tx, 60));
    state.set_time_override(Some(1));

    let mut pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        80,
        b"ping",
    );

    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    state.set_time_override(Some(3));
    state.evict_expired_now();

    let event = rx.try_recv().expect("expected flow end event");
    assert_eq!(event.event_type, WiretapEventType::FlowEnd);
    assert_eq!(event.src_ip, Ipv4Addr::new(10, 0, 0, 2));
    assert_eq!(event.dst_ip, Ipv4Addr::new(93, 184, 216, 34));
    assert_eq!(event.src_port, 40000);
    assert_eq!(event.dst_port, 80);
    assert_eq!(event.proto, 17);
    assert_eq!(event.packets_in, 0);
    assert_eq!(event.packets_out, 1);
    assert_eq!(event.last_seen, 1);
}

#[test]
fn test_reverse_lookup() {
    let mut nat = neuwerk::dataplane::NatTable::new();
    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 3),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 5555,
        dst_port: 53,
        proto: 17,
    };
    let external_port = nat.get_or_create(&flow, 0).unwrap();
    let reverse = neuwerk::dataplane::ReverseKey {
        external_port,
        remote_ip: flow.dst_ip,
        remote_port: flow.dst_port,
        proto: flow.proto,
    };
    let found = nat.reverse_lookup(&reverse).unwrap();
    assert_eq!(found, flow);
}

#[test]
fn test_drop_vs_forward() {
    let allowlist = DynamicIpSetV4::new();
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
        b"ping",
    );
    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Drop);
}

#[test]
fn test_nat_eviction_after_idle_timeout() {
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
    let timeout = state.nat.idle_timeout_secs();

    state.set_time_override(Some(100));
    let mut pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(93, 184, 216, 34),
        40000,
        80,
        b"ping",
    );
    let action = handle_packet(&mut pkt, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip: Ipv4Addr::new(93, 184, 216, 34),
        src_port: 40000,
        dst_port: 80,
        proto: 17,
    };
    assert!(state.nat.get_entry(&flow).is_some());
    assert!(state.flows.contains(&flow));

    state.set_time_override(Some(100 + timeout + 1));
    state.evict_expired_now();
    assert!(state.nat.get_entry(&flow).is_none());
    assert!(!state.flows.contains(&flow));
}

#[test]
fn established_udp_flow_is_dropped_after_policy_generation_denies_it() {
    let allowlist = DynamicIpSetV4::new();
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    allowlist.insert(dst_ip);

    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![Rule {
            id: "allowlist".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(IpSetV4::with_dynamic(allowlist.clone())),
                proto: Proto::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: neuwerk::dataplane::policy::RuleMode::Enforce,
        }],
        default_action: None,
    };

    let initial_snapshot = PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], 1);
    let policy = Arc::new(RwLock::new(initial_snapshot.clone()));
    let shared_snapshot = Arc::new(arc_swap::ArcSwap::from_pointee(initial_snapshot.clone()));
    let policy_generation = Arc::new(AtomicU64::new(initial_snapshot.generation()));

    let mut state = EngineState::new(
        policy.clone(),
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_policy_snapshot(shared_snapshot.clone());
    state.set_exact_source_policy_index(new_shared_exact_source_group_index(&initial_snapshot));
    state.set_policy_applied_generation(policy_generation.clone());
    state.set_dns_allowlist(allowlist.clone());
    state.set_snat_mode(SnatMode::Static(Ipv4Addr::new(203, 0, 113, 1)));

    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip,
        src_port: 40000,
        dst_port: 9000,
        proto: 17,
    };

    let mut open = build_ipv4_udp(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, b"before");
    assert_eq!(
        handle_packet(&mut open, &mut state),
        Action::Forward { out_port: 0 }
    );
    assert!(state.flows.contains(&flow));
    assert!(state.nat.get_entry(&flow).is_some());

    allowlist.clear();
    let updated_snapshot = PolicySnapshot::new_with_generation(
        DefaultPolicy::Deny,
        vec![policy.read().unwrap().groups[0].clone()],
        2,
    );
    *policy.write().unwrap() = updated_snapshot.clone();
    shared_snapshot.store(Arc::new(updated_snapshot.clone()));
    state.set_exact_source_policy_index(new_shared_exact_source_group_index(&updated_snapshot));
    policy_generation.store(
        updated_snapshot.generation(),
        std::sync::atomic::Ordering::Release,
    );
    assert!(!allowlist.contains(dst_ip));
    assert_eq!(
        updated_snapshot.evaluate(
            &neuwerk::dataplane::policy::PacketMeta {
                src_ip: flow.src_ip,
                dst_ip: flow.dst_ip,
                proto: flow.proto,
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                icmp_type: None,
                icmp_code: None,
            },
            None,
            None,
        ),
        neuwerk::dataplane::policy::PolicyDecision::Deny
    );
    assert_eq!(
        state.flows.get_entry(&flow).unwrap().policy_generation,
        initial_snapshot.generation()
    );

    let mut after =
        build_ipv4_udp(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, b"after");
    assert_eq!(handle_packet(&mut after, &mut state), Action::Drop);
    assert!(!state.flows.contains(&flow));
    assert!(state.nat.get_entry(&flow).is_none());
}

#[test]
fn test_inbound_updates_last_seen() {
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
    let timeout = state.nat.idle_timeout_secs();

    state.set_time_override(Some(200));
    let mut outbound = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        8080,
        b"hello",
    );
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    let nat_src_port = outbound.ports().unwrap().0;

    state.set_time_override(Some(200 + timeout - 1));
    let mut inbound = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(203, 0, 113, 1),
        8080,
        nat_src_port,
        b"world",
    );
    let action = handle_packet(&mut inbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 50000,
        dst_port: 8080,
        proto: 17,
    };

    state.set_time_override(Some(200 + timeout - 1 + timeout - 1));
    state.evict_expired_now();
    assert!(state.flows.contains(&flow));

    state.set_time_override(Some(200 + timeout - 1 + timeout + 1));
    state.evict_expired_now();
    assert!(!state.flows.contains(&flow));
}
