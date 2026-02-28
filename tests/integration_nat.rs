use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use firewall::dataplane::config::DataplaneConfig;
use firewall::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction,
    RuleMatch, SourceGroup,
};
use firewall::dataplane::{handle_packet, Action, EngineState, Packet};

fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 17;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let l4_off = 20;
    buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[l4_off + 4..l4_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[l4_off + 6..l4_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 8..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn set_dataplane_ip(state: &mut EngineState, ip: Ipv4Addr) {
    state.dataplane_config.set(DataplaneConfig {
        ip,
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0; 6],
        lease_expiry: None,
    });
}

fn policy_with_allowlist(
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    default_policy: DefaultPolicy,
    allowlist: DynamicIpSetV4,
) -> Arc<RwLock<PolicySnapshot>> {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(internal_net, internal_prefix));

    let rule = Rule {
        id: "allowlist".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: Some(IpSetV4::with_dynamic(allowlist)),
            proto: Proto::Any,
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: None,
        },
        action: RuleAction::Allow,
        mode: firewall::dataplane::policy::RuleMode::Enforce,
    };

    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };

    Arc::new(RwLock::new(PolicySnapshot::new(
        default_policy,
        vec![group],
    )))
}

#[test]
fn integration_nat_flow() {
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

    let mut outbound = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        8080,
        b"hello",
    );

    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(outbound.src_ip(), Some(dp_ip));

    let nat_src_port = outbound.ports().unwrap().0;

    let mut inbound = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        dp_ip,
        8080,
        nat_src_port,
        b"world",
    );

    let action = handle_packet(&mut inbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(inbound.dst_ip(), Some(Ipv4Addr::new(10, 0, 0, 42)));
    assert_eq!(inbound.ports().unwrap().1, 50000);
}

#[test]
fn integration_existing_flow_ignores_policy_updates() {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );

    let mut state = EngineState::new_with_idle_timeout(
        policy.clone(),
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
        300,
    );

    let mut outbound = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        8080,
        b"hello",
    );
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    if let Ok(mut lock) = policy.write() {
        *lock = PolicySnapshot::new(DefaultPolicy::Deny, Vec::new());
    }

    let mut followup = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        8080,
        b"followup",
    );
    let action = handle_packet(&mut followup, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
}

#[test]
fn integration_allowlist_gc_removes_after_flow_idle() {
    let allowlist = DynamicIpSetV4::new();
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    allowlist.insert_at(dst_ip, 0);

    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist.clone(),
    );

    let mut state = EngineState::new_with_idle_timeout(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
        10,
    );
    state.set_dns_allowlist(allowlist.clone());

    state.set_time_override(Some(100));
    let mut outbound = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 2), dst_ip, 40000, 80, b"ping");
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    state.set_time_override(Some(111));
    state.evict_expired_now();

    let removed = allowlist.evict_idle(200, 20);
    assert_eq!(removed, 1);
    assert!(!allowlist.contains(dst_ip));

    state.set_time_override(Some(200));
    let mut retry = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 2), dst_ip, 40001, 80, b"retry");
    let action = handle_packet(&mut retry, &mut state);
    assert_eq!(action, Action::Drop);
}

#[test]
fn integration_allowlist_gc_keeps_active_flow() {
    let allowlist = DynamicIpSetV4::new();
    let dst_ip = Ipv4Addr::new(198, 51, 100, 20);
    allowlist.insert_at(dst_ip, 0);

    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist.clone(),
    );

    let mut state = EngineState::new_with_idle_timeout(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
        300,
    );
    state.set_dns_allowlist(allowlist.clone());

    state.set_time_override(Some(100));
    let mut outbound = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 3), dst_ip, 45000, 443, b"hello");
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });

    let removed = allowlist.evict_idle(300, 60);
    assert_eq!(removed, 0);
    assert!(allowlist.contains(dst_ip));

    state.set_time_override(Some(300));
    let mut keepalive =
        build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 3), dst_ip, 45000, 443, b"keepalive");
    let action = handle_packet(&mut keepalive, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
}
