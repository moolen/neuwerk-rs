use std::net::Ipv4Addr;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use crossbeam_queue::ArrayQueue;
use neuwerk::controlplane::metrics::Metrics;
use neuwerk::dataplane::config::DataplaneConfig;
use neuwerk::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, ExactSourceGroupIndex, IpSetV4, PacketMeta,
    PolicySnapshot, Proto, Rule, RuleAction, RuleMatch, RuleMode, SourceGroup,
};
use neuwerk::dataplane::tls::TlsVerifier;
use neuwerk::dataplane::{
    handle_packet, Action, AuditEmitter, DpdkAdapter, EngineState, FlowEntry, FlowKey, FlowTable,
    FrameIo, FrameOut, NatTable, Packet, ReverseKey, SnatMode, WiretapEmitter,
};
use tokio::sync::mpsc;

const BENCH_NOW_SECS: u64 = 1;
const BENCH_NAT_PORT_MIN: u16 = 40_000;

fn make_flow(index: u32) -> FlowKey {
    FlowKey {
        src_ip: Ipv4Addr::new(10, 0, ((index / 250) % 250) as u8, (index % 250) as u8 + 1),
        dst_ip: Ipv4Addr::new(
            198,
            51 + ((index / 50_000) % 2) as u8,
            100,
            ((index / 250) % 250) as u8 + 1,
        ),
        src_port: 40_000 + (index % 10_000) as u16,
        dst_port: 443,
        proto: 6,
    }
}

fn nat_flow_hash(key: &FlowKey) -> u32 {
    let src_ip = u32::from_be_bytes(key.src_ip.octets());
    let dst_ip = u32::from_be_bytes(key.dst_ip.octets());
    let ports = ((key.src_port as u32) << 16) | key.dst_port as u32;
    let seed = src_ip.wrapping_mul(0x9e37_79b1)
        ^ dst_ip.rotate_left(7).wrapping_mul(0x85eb_ca6b)
        ^ ports.rotate_left(13).wrapping_mul(0xc2b2_ae35)
        ^ (key.proto as u32).wrapping_mul(0x27d4_eb2d);
    finalize_hash32(seed)
}

fn finalize_hash32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x85eb_ca6b);
    value ^= value >> 13;
    value = value.wrapping_mul(0xc2b2_ae35);
    value ^ (value >> 16)
}

fn reset_eth_ipv4_tcp_packet_tuple(
    packet: &mut Packet,
    base_bytes: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) {
    packet.buffer_mut().copy_from_slice(base_bytes);
    {
        let buf = packet.buffer_mut();
        buf[26..30].copy_from_slice(&src_ip.octets());
        buf[30..34].copy_from_slice(&dst_ip.octets());
        buf[34..36].copy_from_slice(&src_port.to_be_bytes());
        buf[36..38].copy_from_slice(&dst_port.to_be_bytes());
    }
    assert!(packet.recalc_checksums());
}

fn build_dpdk_sized_transfer_packet(packet_len: usize) -> Packet {
    let mut packet = Packet::new(vec![0u8; 65_536]);
    packet.truncate(packet_len);
    packet
}

fn legacy_flow_steer_payload(pkt: &mut Packet) -> Vec<u8> {
    if pkt.is_borrowed() {
        pkt.buffer().to_vec()
    } else {
        std::mem::replace(pkt, Packet::new(Vec::new())).into_vec()
    }
}

#[derive(Debug, Clone, Copy)]
struct BorrowedFlowSteerPayload {
    ptr: NonNull<u8>,
    len: usize,
}

// Safety: benchmark payloads are only transferred within the same thread while the
// backing storage remains alive for the duration of each iteration.
unsafe impl Send for BorrowedFlowSteerPayload {}

fn borrowed_flow_steer_payload(pkt: &mut Packet) -> BorrowedFlowSteerPayload {
    let len = pkt.len();
    let ptr = NonNull::new(pkt.buffer_mut().as_mut_ptr()).expect("packet ptr");
    BorrowedFlowSteerPayload { ptr, len }
}

fn make_colliding_flows(preferred_port: u16, count: usize) -> Vec<FlowKey> {
    let target_offset = (preferred_port - BENCH_NAT_PORT_MIN) as u32;
    let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
    let remote_port = 443;
    let mut flows = Vec::with_capacity(count);
    let mut seed = 0u32;

    while flows.len() < count {
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 2, ((seed / 250) % 250) as u8, (seed % 250) as u8 + 1),
            dst_ip: remote_ip,
            src_port: 10_000 + (seed % 50_000) as u16,
            dst_port: remote_port,
            proto: 6,
        };
        if nat_flow_hash(&flow) % NatTable::port_range_len() == target_offset {
            flows.push(flow);
        }
        seed += 1;
    }

    flows
}

fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    build_ipv4_tcp_flags(src_ip, dst_ip, src_port, dst_port, payload, 0x10)
}

fn build_ipv4_tcp_flags(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    flags: u8,
) -> Packet {
    let total_len = 20 + 20 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 6;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let l4_off = 20;
    buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[l4_off + 12] = 0x50;
    buf[l4_off + 13] = flags;
    buf[l4_off + 16..l4_off + 18].copy_from_slice(&1024u16.to_be_bytes());
    buf[l4_off + 18..l4_off + 20].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 20..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

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
    buf[l4_off + 4..l4_off + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    buf[l4_off + 6..l4_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 8..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn build_eth_ipv4_tcp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let inner = build_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, payload).into_vec();
    let mut frame = Vec::with_capacity(14 + inner.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&inner);
    Packet::new(frame)
}

fn build_eth_ipv4_udp(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let inner = build_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload).into_vec();
    let mut frame = Vec::with_capacity(14 + inner.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&inner);
    Packet::new(frame)
}

fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

fn build_allow_rule(id: &str, dst_ip: Ipv4Addr) -> Rule {
    let mut dst_ips = IpSetV4::new();
    dst_ips.add_ip(dst_ip);
    Rule {
        id: id.to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: Some(dst_ips),
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: None,
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    }
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
        mode: RuleMode::Enforce,
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

fn policy_with_many_rules(group_count: usize, rules_per_group: usize) -> PolicySnapshot {
    policy_with_many_rules_for_source(Ipv4Addr::new(10, 0, 0, 42), group_count, rules_per_group)
}

fn policy_with_many_rules_for_source(
    src_ip: Ipv4Addr,
    group_count: usize,
    rules_per_group: usize,
) -> PolicySnapshot {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);

    for group_idx in 0..group_count {
        let mut sources = IpSetV4::new();
        sources.add_ip(src_ip);

        let mut rules = Vec::with_capacity(rules_per_group);
        for rule_idx in 0..rules_per_group {
            let dst_ip = if group_idx + 1 == group_count && rule_idx + 1 == rules_per_group {
                target_dst
            } else {
                Ipv4Addr::new(
                    203,
                    (group_idx % 200) as u8,
                    ((rule_idx / 200) % 200) as u8,
                    (rule_idx % 200) as u8,
                )
            };
            let mut rule = build_allow_rule(&format!("rule-{group_idx}-{rule_idx}"), dst_ip);
            rule.priority = rule_idx as u32;
            rules.push(rule);
        }

        groups.push(SourceGroup {
            id: format!("group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules,
            default_action: None,
        });
    }

    PolicySnapshot::new(DefaultPolicy::Deny, groups)
}

fn policy_with_many_groups_single_rule(group_count: usize, src_ip: Ipv4Addr) -> PolicySnapshot {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);

    for group_idx in 0..group_count {
        let mut sources = IpSetV4::new();
        sources.add_ip(src_ip);
        let dst_ip = if group_idx + 1 == group_count {
            target_dst
        } else {
            Ipv4Addr::new(
                203,
                0,
                ((group_idx / 200) % 200) as u8,
                (group_idx % 200) as u8,
            )
        };
        let rule = build_allow_rule(&format!("group-rule-{group_idx}"), dst_ip);
        groups.push(SourceGroup {
            id: format!("group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules: vec![rule],
            default_action: None,
        });
    }

    PolicySnapshot::new(DefaultPolicy::Deny, groups)
}

fn policy_with_many_groups_single_rule_cidr(
    group_count: usize,
    src_ip: Ipv4Addr,
    prefix: u8,
) -> PolicySnapshot {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);

    for group_idx in 0..group_count {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(src_ip, prefix));
        let dst_ip = if group_idx + 1 == group_count {
            target_dst
        } else {
            Ipv4Addr::new(
                203,
                2,
                ((group_idx / 200) % 200) as u8,
                (group_idx % 200) as u8,
            )
        };
        let rule = build_allow_rule(&format!("cidr-group-rule-{group_idx}"), dst_ip);
        groups.push(SourceGroup {
            id: format!("cidr-group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules: vec![rule],
            default_action: None,
        });
    }

    PolicySnapshot::new(DefaultPolicy::Deny, groups)
}

fn policy_with_many_groups_unique_sources(group_count: usize) -> (PolicySnapshot, Ipv4Addr) {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut groups = Vec::with_capacity(group_count);
    let mut matched_src_ip = Ipv4Addr::UNSPECIFIED;

    for group_idx in 0..group_count {
        let src_ip = Ipv4Addr::new(
            172,
            16,
            ((group_idx / 250) % 250) as u8,
            (group_idx % 250) as u8 + 1,
        );
        let mut sources = IpSetV4::new();
        sources.add_ip(src_ip);
        let dst_ip = if group_idx + 1 == group_count {
            matched_src_ip = src_ip;
            target_dst
        } else {
            Ipv4Addr::new(
                203,
                1,
                ((group_idx / 200) % 200) as u8,
                (group_idx % 200) as u8,
            )
        };
        let rule = build_allow_rule(&format!("unique-group-rule-{group_idx}"), dst_ip);
        groups.push(SourceGroup {
            id: format!("unique-group-{group_idx}"),
            priority: group_idx as u32,
            sources,
            rules: vec![rule],
            default_action: None,
        });
    }

    (
        PolicySnapshot::new(DefaultPolicy::Deny, groups),
        matched_src_ip,
    )
}

fn policy_with_many_groups_unique_sources_mixed(
    exact_group_count: usize,
) -> (PolicySnapshot, Ipv4Addr) {
    let (mut policy, matched_src_ip) = policy_with_many_groups_unique_sources(exact_group_count);
    let mut fallback_sources = IpSetV4::new();
    fallback_sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 10, 0, 0), 16));
    policy.groups.push(SourceGroup {
        id: "fallback-cidr".to_string(),
        priority: policy.groups.len() as u32,
        sources: fallback_sources,
        rules: vec![build_allow_rule(
            "fallback-cidr-rule",
            Ipv4Addr::new(203, 0, 113, 200),
        )],
        default_action: None,
    });
    (
        PolicySnapshot::new(policy.default_policy, policy.groups),
        matched_src_ip,
    )
}

fn policy_with_many_rules_for_source_sparse_audit(
    src_ip: Ipv4Addr,
    group_count: usize,
    rules_per_group: usize,
) -> PolicySnapshot {
    let mut policy = policy_with_many_rules_for_source(src_ip, group_count, rules_per_group);
    let audit_target = Ipv4Addr::new(203, 0, 113, 250);
    if let Some(group) = policy.groups.last_mut() {
        group.rules.push(Rule {
            id: "sparse-audit".to_string(),
            priority: group.rules.len() as u32,
            matcher: RuleMatch {
                dst_ips: Some({
                    let mut ips = IpSetV4::new();
                    ips.add_ip(audit_target);
                    ips
                }),
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Deny,
            mode: RuleMode::Audit,
        });
    }
    PolicySnapshot::new(policy.default_policy, policy.groups)
}

fn policy_with_single_group_many_rules(rule_count: usize, src_ip: Ipv4Addr) -> PolicySnapshot {
    let target_dst = Ipv4Addr::new(198, 51, 100, 10);
    let mut sources = IpSetV4::new();
    sources.add_ip(src_ip);

    let mut rules = Vec::with_capacity(rule_count);
    for rule_idx in 0..rule_count {
        let dst_ip = if rule_idx + 1 == rule_count {
            target_dst
        } else {
            Ipv4Addr::new(
                203,
                (rule_idx % 200) as u8,
                ((rule_idx / 200) % 200) as u8,
                ((rule_idx / 40_000) % 200) as u8,
            )
        };
        let mut rule = build_allow_rule(&format!("rule-{rule_idx}"), dst_ip);
        rule.priority = rule_idx as u32;
        rules.push(rule);
    }

    PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![SourceGroup {
            id: "group-0".to_string(),
            priority: 0,
            sources,
            rules,
            default_action: None,
        }],
    )
}

fn new_engine_state(snat_mode: SnatMode) -> EngineState {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );

    let public_ip = match snat_mode {
        SnatMode::None => Ipv4Addr::UNSPECIFIED,
        _ => Ipv4Addr::new(203, 0, 113, 1),
    };
    let mut state = EngineState::new(policy, Ipv4Addr::new(10, 0, 0, 0), 24, public_ip, 0);
    state.set_snat_mode(snat_mode);
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0; 6],
        lease_expiry: None,
    });
    state.set_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_time_override(Some(BENCH_NOW_SECS));
    state
}

fn new_engine_state_with_policy(policy: PolicySnapshot, snat_mode: SnatMode) -> EngineState {
    let public_ip = match snat_mode {
        SnatMode::None => Ipv4Addr::UNSPECIFIED,
        _ => Ipv4Addr::new(203, 0, 113, 1),
    };
    let mut state = EngineState::new(
        Arc::new(RwLock::new(policy)),
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        public_ip,
        0,
    );
    state.set_snat_mode(snat_mode);
    state.dataplane_config.set(DataplaneConfig {
        ip: Ipv4Addr::new(10, 0, 0, 1),
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: [0; 6],
        lease_expiry: None,
    });
    state.set_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
    state.set_time_override(Some(BENCH_NOW_SECS));
    state
}

fn attach_metrics(state: &mut EngineState) {
    state.set_metrics_handle(Arc::new(Metrics::new().expect("metrics")));
}

fn attach_wiretap(state: &mut EngineState) {
    let (tx, mut rx) = mpsc::channel(131_072);
    let _handle = thread::spawn(move || while rx.blocking_recv().is_some() {});
    state.set_wiretap_emitter(WiretapEmitter::new(tx, 1));
}

fn attach_audit(state: &mut EngineState) {
    let (tx, mut rx) = mpsc::channel(131_072);
    let _handle = thread::spawn(move || while rx.blocking_recv().is_some() {});
    state.set_audit_emitter(AuditEmitter::new(tx, 1));
}

fn clone_bench_state(template: &EngineState) -> EngineState {
    let mut state = template.clone_for_shard();
    state.evict_expired_now();
    state
}

fn bench_new_tcp_flow_no_snat(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::None);
    let packet_bytes = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    )
    .into_vec();

    c.bench_function("dataplane_handle_packet_new_tcp_no_snat", |b| {
        b.iter_batched(
            || {
                (
                    clone_bench_state(&template_state),
                    Packet::from_bytes(&packet_bytes),
                )
            },
            |(mut state, mut packet)| {
                black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_new_tcp_flow_snat(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::Auto);
    let packet_bytes = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    )
    .into_vec();

    c.bench_function("dataplane_handle_packet_new_tcp_snat", |b| {
        b.iter_batched(
            || {
                (
                    clone_bench_state(&template_state),
                    Packet::from_bytes(&packet_bytes),
                )
            },
            |(mut state, mut packet)| {
                black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_established_tcp_flow_no_snat(c: &mut Criterion) {
    let packet_bytes = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    )
    .into_vec();

    let mut state = new_engine_state(SnatMode::None);
    state.evict_expired_now();
    let mut seed_packet = Packet::from_bytes(&packet_bytes);
    assert_eq!(
        handle_packet(&mut seed_packet, &mut state),
        Action::Forward { out_port: 0 }
    );

    c.bench_function("dataplane_handle_packet_established_tcp_no_snat", |b| {
        b.iter_batched(
            || Packet::from_bytes(&packet_bytes),
            |mut packet| black_box(handle_packet(black_box(&mut packet), black_box(&mut state))),
            BatchSize::SmallInput,
        )
    });
}

fn bench_established_tcp_flow_inbound_snat_persistent_state(c: &mut Criterion) {
    let mut state = new_engine_state(SnatMode::Auto);
    state.evict_expired_now();
    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 40_000,
        dst_port: 443,
        proto: 6,
    };
    let mut outbound = build_ipv4_tcp(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        b"hello",
    );
    assert_eq!(
        handle_packet(&mut outbound, &mut state),
        Action::Forward { out_port: 0 }
    );
    let external_port = state.nat.get_entry(&flow).expect("nat entry").external_port;
    let packet_bytes = build_ipv4_tcp(
        flow.dst_ip,
        Ipv4Addr::new(203, 0, 113, 1),
        flow.dst_port,
        external_port,
        b"world",
    )
    .into_vec();

    c.bench_function(
        "dataplane_handle_packet_established_tcp_inbound_snat_persistent_state",
        |b| {
            b.iter_batched(
                || Packet::from_bytes(&packet_bytes),
                |mut packet| {
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_policy_eval_allow_small(c: &mut Criterion) {
    let allowlist = DynamicIpSetV4::new();
    allowlist.insert(Ipv4Addr::new(198, 51, 100, 10));
    let policy = policy_with_allowlist(
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        DefaultPolicy::Deny,
        allowlist,
    );
    let meta = PacketMeta {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function("dataplane_policy_eval_allow_small", |b| {
        b.iter(|| {
            let policy = policy.read().expect("policy");
            let (effective, raw, group, intercept_requires_service) = policy
                .evaluate_with_source_group_effective_and_raw_borrowed(
                    black_box(&meta),
                    None,
                    Some(black_box(&verifier)),
                );
            black_box((effective, raw, group.is_some(), intercept_requires_service))
        })
    });
}

fn bench_policy_read_lock_only(c: &mut Criterion) {
    let policy = Arc::new(RwLock::new(policy_with_many_rules(16, 64)));

    c.bench_function("dataplane_policy_read_lock_only", |b| {
        b.iter(|| {
            let policy = policy.read().expect("policy");
            let generation = black_box(policy.generation());
            let mode = black_box(policy.enforcement_mode());
            black_box((generation, mode))
        })
    });
}

fn bench_policy_eval_allow_large(c: &mut Criterion) {
    let policy = policy_with_many_rules(16, 64);
    let meta = PacketMeta {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function("dataplane_policy_eval_allow_large", |b| {
        b.iter(|| {
            let (effective, raw, group, intercept_requires_service) = policy
                .evaluate_with_source_group_effective_and_raw_borrowed(
                    black_box(&meta),
                    None,
                    Some(black_box(&verifier)),
                );
            black_box((effective, raw, group.is_some(), intercept_requires_service))
        })
    });
}

fn bench_policy_eval_allow_large_group_scan(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let policy = policy_with_many_groups_single_rule(1024, src_ip);
    let meta = PacketMeta {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function("dataplane_policy_eval_allow_large_group_scan", |b| {
        b.iter(|| {
            let (effective, raw, group, intercept_requires_service) = policy
                .evaluate_with_source_group_effective_and_raw_borrowed(
                    black_box(&meta),
                    None,
                    Some(black_box(&verifier)),
                );
            black_box((effective, raw, group.is_some(), intercept_requires_service))
        })
    });
}

fn bench_policy_eval_allow_large_group_scan_cidr_source(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let policy = policy_with_many_groups_single_rule_cidr(1024, src_ip, 24);
    let meta = PacketMeta {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function(
        "dataplane_policy_eval_allow_large_group_scan_cidr_source",
        |b| {
            b.iter(|| {
                let (effective, raw, group, intercept_requires_service) = policy
                    .evaluate_with_source_group_effective_and_raw_borrowed(
                        black_box(&meta),
                        None,
                        Some(black_box(&verifier)),
                    );
                black_box((effective, raw, group.is_some(), intercept_requires_service))
            })
        },
    );
}

fn bench_policy_eval_allow_large_rule_scan(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let policy = policy_with_single_group_many_rules(1024, src_ip);
    let meta = PacketMeta {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function("dataplane_policy_eval_allow_large_rule_scan", |b| {
        b.iter(|| {
            let (effective, raw, group, intercept_requires_service) = policy
                .evaluate_with_source_group_effective_and_raw_borrowed(
                    black_box(&meta),
                    None,
                    Some(black_box(&verifier)),
                );
            black_box((effective, raw, group.is_some(), intercept_requires_service))
        })
    });
}

fn bench_policy_eval_allow_large_unique_source(c: &mut Criterion) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let meta = PacketMeta {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function("dataplane_policy_eval_allow_large_unique_source", |b| {
        b.iter(|| {
            let (effective, raw, group, intercept_requires_service) = policy
                .evaluate_with_source_group_effective_and_raw_borrowed(
                    black_box(&meta),
                    None,
                    Some(black_box(&verifier)),
                );
            black_box((effective, raw, group.is_some(), intercept_requires_service))
        })
    });
}

fn bench_policy_eval_allow_large_unique_source_exact_index(c: &mut Criterion) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let exact_source_index = ExactSourceGroupIndex::for_snapshot(&policy);
    let meta = PacketMeta {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 50000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let verifier = TlsVerifier::new();

    c.bench_function(
        "dataplane_policy_eval_allow_large_unique_source_exact_index",
        |b| {
            b.iter(|| {
                let (effective, raw, group, intercept_requires_service) = policy
                    .evaluate_with_source_group_effective_and_raw_exact_index_borrowed(
                        black_box(&exact_source_index),
                        black_box(&meta),
                        None,
                        Some(black_box(&verifier)),
                    );
                black_box((effective, raw, group.is_some(), intercept_requires_service))
            })
        },
    );
}

fn bench_is_internal(c: &mut Criterion) {
    let state = new_engine_state(SnatMode::None);
    let internal_ip = Ipv4Addr::new(10, 0, 0, 42);
    let external_ip = Ipv4Addr::new(198, 51, 100, 10);

    c.bench_function("dataplane_is_internal_internal_ip", |b| {
        b.iter(|| black_box(state.is_internal(black_box(internal_ip))))
    });

    c.bench_function("dataplane_is_internal_external_ip", |b| {
        b.iter(|| black_box(state.is_internal(black_box(external_ip))))
    });
}

fn bench_is_internal_large_policy(c: &mut Criterion) {
    let state = new_engine_state_with_policy(
        policy_with_many_rules_for_source(Ipv4Addr::new(172, 16, 0, 42), 16, 64),
        SnatMode::None,
    );
    let policy_internal_ip = Ipv4Addr::new(172, 16, 0, 42);
    let external_ip = Ipv4Addr::new(198, 51, 100, 10);

    c.bench_function(
        "dataplane_is_internal_policy_internal_ip_large_policy",
        |b| b.iter(|| black_box(state.is_internal(black_box(policy_internal_ip)))),
    );

    c.bench_function("dataplane_is_internal_external_ip_large_policy", |b| {
        b.iter(|| black_box(state.is_internal(black_box(external_ip))))
    });
}

fn bench_is_internal_large_unique_source_policy(c: &mut Criterion) {
    let (policy, policy_internal_ip) = policy_with_many_groups_unique_sources(1024);
    let state = new_engine_state_with_policy(policy, SnatMode::None);
    let external_ip = Ipv4Addr::new(198, 51, 100, 10);

    c.bench_function(
        "dataplane_is_internal_policy_internal_ip_large_unique_source_policy",
        |b| b.iter(|| black_box(state.is_internal(black_box(policy_internal_ip)))),
    );

    c.bench_function(
        "dataplane_is_internal_external_ip_large_unique_source_policy",
        |b| b.iter(|| black_box(state.is_internal(black_box(external_ip)))),
    );
}

fn bench_dynamic_ip_set_contains(c: &mut Criterion) {
    let set = DynamicIpSetV4::new();
    let hit_ip = Ipv4Addr::new(198, 51, 100, 10);
    let miss_ip = Ipv4Addr::new(198, 51, 100, 11);
    set.insert(hit_ip);

    c.bench_function("dataplane_dynamic_ip_set_contains_hit", |b| {
        b.iter(|| black_box(set.contains(black_box(hit_ip))))
    });

    c.bench_function("dataplane_dynamic_ip_set_contains_miss", |b| {
        b.iter(|| black_box(set.contains(black_box(miss_ip))))
    });
}

fn bench_flow_table_insert(c: &mut Criterion) {
    c.bench_function("dataplane_flow_table_insert_empty", |b| {
        b.iter_batched(
            || {
                (
                    FlowTable::new(),
                    FlowKey {
                        src_ip: Ipv4Addr::new(10, 0, 0, 42),
                        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
                        src_port: 50000,
                        dst_port: 443,
                        proto: 6,
                    },
                )
            },
            |(mut table, key)| {
                table.insert(black_box(key), FlowEntry::new(BENCH_NOW_SECS));
                black_box(table)
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("dataplane_flow_table_insert_persistent", |b| {
        let mut table = FlowTable::new();
        let mut index = 0u32;
        b.iter(|| {
            let flow = make_flow(index);
            index += 1;
            table.insert(black_box(flow), FlowEntry::new(BENCH_NOW_SECS));
            if index == 4096 {
                table = FlowTable::new();
                index = 0;
            }
        })
    });

    c.bench_function("dataplane_flow_table_insert_then_get_mut_persistent", |b| {
        let mut table = FlowTable::new();
        let mut index = 0u32;
        b.iter(|| {
            let flow = make_flow(index);
            index += 1;
            table.insert(black_box(flow), FlowEntry::new(BENCH_NOW_SECS));
            let last_seen = table
                .get_entry_mut(black_box(&flow))
                .map(|entry| {
                    entry.last_seen = BENCH_NOW_SECS;
                    entry.last_seen
                })
                .unwrap_or_default();
            if index == 4096 {
                table = FlowTable::new();
                index = 0;
            }
            black_box(last_seen)
        })
    });

    c.bench_function("dataplane_flow_table_insert_and_get_mut_persistent", |b| {
        let mut table = FlowTable::new();
        let mut index = 0u32;
        b.iter(|| {
            let flow = make_flow(index);
            index += 1;
            let last_seen = {
                let entry =
                    table.insert_and_get_mut(black_box(flow), FlowEntry::new(BENCH_NOW_SECS));
                entry.last_seen = BENCH_NOW_SECS;
                entry.last_seen
            };
            if index == 4096 {
                table = FlowTable::new();
                index = 0;
            }
            black_box(last_seen)
        })
    });

    c.bench_function("dataplane_flow_table_probe_then_insert_persistent", |b| {
        let mut table = FlowTable::new();
        let mut index = 0u32;
        b.iter(|| {
            let flow = make_flow(index);
            index += 1;
            let is_hit = table.probe(black_box(&flow)).is_hit();
            table.insert(black_box(flow), FlowEntry::new(BENCH_NOW_SECS));
            if index == 4096 {
                table = FlowTable::new();
                index = 0;
            }
            black_box(is_hit)
        })
    });

    c.bench_function(
        "dataplane_flow_table_probe_then_insert_with_probe_persistent",
        |b| {
            let mut table = FlowTable::new();
            let mut index = 0u32;
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let probe = table.probe(black_box(&flow));
                let last_seen = {
                    let entry = table.insert_with_probe_and_get_mut(
                        black_box(flow),
                        FlowEntry::new(BENCH_NOW_SECS),
                        probe,
                    );
                    entry.last_seen = BENCH_NOW_SECS;
                    entry.last_seen
                };
                if index == 4096 {
                    table = FlowTable::new();
                    index = 0;
                }
                black_box(last_seen)
            })
        },
    );

    c.bench_function(
        "dataplane_flow_table_probe_then_insert_with_probe_source_group_persistent",
        |b| {
            let mut table = FlowTable::new();
            let mut index = 0u32;
            let source_group = Arc::<str>::from("unique-group-1023");
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let probe = table.probe(black_box(&flow));
                let last_seen = {
                    let entry = table.insert_with_probe_and_get_mut(
                        black_box(flow),
                        FlowEntry::with_source_group_arc(
                            BENCH_NOW_SECS,
                            Some(black_box(source_group.clone())),
                        ),
                        probe,
                    );
                    entry.last_seen = BENCH_NOW_SECS;
                    entry.last_seen
                };
                if index == 4096 {
                    table = FlowTable::new();
                    index = 0;
                }
                black_box(last_seen)
            })
        },
    );
}

fn bench_flow_open_bookkeeping_metrics(c: &mut Criterion) {
    let metrics = Metrics::new().expect("metrics");

    c.bench_function("dataplane_metrics_flow_open_bookkeeping_default", |b| {
        b.iter(|| {
            metrics.inc_dp_flow_open("tcp", "default");
            metrics.add_dp_active_flows_shard(0, 1);
            black_box(())
        })
    });

    c.bench_function("dataplane_metrics_flow_close_bookkeeping_default", |b| {
        b.iter(|| {
            metrics.observe_dp_flow_close("default", "idle_timeout", 30.0);
            metrics.add_dp_active_flows_shard(0, -1);
            black_box(())
        })
    });
}

fn bench_nat_get_or_create(c: &mut Criterion) {
    c.bench_function("dataplane_nat_get_or_create_new", |b| {
        b.iter_batched(
            || {
                (
                    NatTable::new(),
                    FlowKey {
                        src_ip: Ipv4Addr::new(10, 0, 0, 42),
                        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
                        src_port: 50000,
                        dst_port: 443,
                        proto: 6,
                    },
                )
            },
            |(mut nat, key)| {
                black_box(nat.get_or_create_with_status(black_box(&key), BENCH_NOW_SECS))
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("dataplane_nat_get_or_create_persistent", |b| {
        let mut nat = NatTable::new();
        let mut index = 0u32;
        b.iter(|| {
            let flow = make_flow(index);
            index += 1;
            black_box(nat.get_or_create_with_status(black_box(&flow), BENCH_NOW_SECS))
                .expect("nat");
            if index == 4096 {
                nat = NatTable::new();
                index = 0;
            }
        })
    });

    c.bench_function("dataplane_nat_get_or_create_hit", |b| {
        let mut nat = NatTable::new();
        let flow = make_flow(0);
        nat.get_or_create_with_status(&flow, BENCH_NOW_SECS)
            .expect("nat");

        b.iter(|| black_box(nat.get_or_create_with_status(black_box(&flow), BENCH_NOW_SECS)))
    });

    c.bench_function("dataplane_nat_get_or_create_high_occupancy", |b| {
        let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
        let remote_port = 443;
        let mut nat = NatTable::new();
        for i in 0..10_000u32 {
            let flow = FlowKey {
                src_ip: Ipv4Addr::new(10, 1, (i / 250) as u8, (i % 250) as u8 + 1),
                dst_ip: remote_ip,
                src_port: 10_000 + i as u16,
                dst_port: remote_port,
                proto: 6,
            };
            nat.get_or_create_with_status(&flow, BENCH_NOW_SECS)
                .expect("prefill");
        }
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 250, 0, 1),
            dst_ip: remote_ip,
            src_port: 55_555,
            dst_port: remote_port,
            proto: 6,
        };

        b.iter(|| {
            black_box(nat.get_or_create_with_status(black_box(&flow), BENCH_NOW_SECS))
                .expect("nat");
            black_box(nat.remove(black_box(&flow)));
        })
    });

    c.bench_function("dataplane_nat_get_or_create_colliding_preferred", |b| {
        let flows = make_colliding_flows(BENCH_NAT_PORT_MIN, 4097);
        let mut nat = NatTable::new();
        for flow in &flows[..4096] {
            nat.get_or_create_with_status(flow, BENCH_NOW_SECS)
                .expect("prefill");
        }
        let flow = flows[4096];

        b.iter(|| {
            black_box(nat.get_or_create_with_status(black_box(&flow), BENCH_NOW_SECS))
                .expect("nat");
            black_box(nat.remove(black_box(&flow)));
        })
    });

    c.bench_function("dataplane_nat_reverse_lookup_hit", |b| {
        let mut nat = NatTable::new();
        let flow = make_flow(0);
        let port = nat
            .get_or_create_with_status(&flow, BENCH_NOW_SECS)
            .expect("nat")
            .0;
        let reverse = ReverseKey {
            external_port: port,
            remote_ip: flow.dst_ip,
            remote_port: flow.dst_port,
            proto: flow.proto,
        };

        b.iter(|| black_box(nat.reverse_lookup(black_box(&reverse))))
    });
}

fn bench_new_udp_flow_no_snat_persistent_state(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_udp_no_snat_persistent_state",
        |b| {
            b.iter(|| {
                let flow = FlowKey {
                    proto: 17,
                    ..make_flow(index)
                };
                index += 1;
                let mut packet =
                    build_ipv4_udp(flow.src_ip, flow.dst_ip, flow.src_port, 53, payload);
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_packet_parse_core(c: &mut Criterion) {
    let packet = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    );

    c.bench_function("dataplane_packet_parse_core", |b| {
        b.iter(|| {
            black_box(packet.src_ip());
            black_box(packet.dst_ip());
            black_box(packet.is_ipv4_fragment());
            black_box(packet.protocol());
            black_box(packet.ports());
        })
    });
}

fn bench_packet_rewrite_snat(c: &mut Criterion) {
    let packet_bytes = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    )
    .into_vec();
    let new_ip = Ipv4Addr::new(203, 0, 113, 1);
    let new_port = 40000;

    c.bench_function("dataplane_packet_rewrite_snat", |b| {
        b.iter_batched(
            || Packet::from_bytes(&packet_bytes),
            |mut packet| {
                black_box(packet.set_src_ip(black_box(new_ip)));
                black_box(packet.set_src_port(black_box(new_port)));
                black_box(packet)
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_packet_reset_eth_ipv4_tcp_tuple(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(10, 0, 0, 42);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    let base_bytes =
        build_eth_ipv4_tcp([0; 6], [0; 6], src_ip, dst_ip, 10_000, 443, b"hello").into_vec();
    let mut packet = Packet::from_bytes(&base_bytes);
    let mut index = 0u32;

    c.bench_function("dataplane_packet_reset_eth_ipv4_tcp_tuple", |b| {
        b.iter(|| {
            let src_port = 10_000 + index as u16;
            index = (index + 1) & 4095;
            reset_eth_ipv4_tcp_packet_tuple(
                &mut packet,
                &base_bytes,
                src_ip,
                dst_ip,
                black_box(src_port),
                443,
            );
            black_box(packet.buffer()[34])
        })
    });
}

fn bench_packet_from_bytes(c: &mut Criterion) {
    let packet_bytes = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        443,
        b"hello",
    )
    .into_vec();

    c.bench_function("dataplane_packet_from_bytes", |b| {
        b.iter(|| black_box(Packet::from_bytes(black_box(&packet_bytes))))
    });
}

fn bench_state_clone_for_shard(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::None);
    c.bench_function("dataplane_state_clone_for_shard", |b| {
        b.iter(|| black_box(clone_bench_state(black_box(&template_state))))
    });
}

fn bench_new_tcp_flow_no_snat_persistent_state(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_persistent_state(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::Auto);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_short_lived_churn(c: &mut Criterion) {
    let template_state = new_engine_state(SnatMode::Auto);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_short_lived_churn",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                state.set_time_override(Some(BENCH_NOW_SECS + (index / 128) as u64));

                let mut open = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let open_result = handle_packet(black_box(&mut open), black_box(&mut state));

                let mut rst = build_ipv4_tcp_flags(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    &[],
                    0x04,
                );
                let close_result = handle_packet(black_box(&mut rst), black_box(&mut state));

                let result = black_box((
                    open_result,
                    close_result,
                    black_box(state.flows.len()),
                    black_box(state.nat.len()),
                ));
                if index == 8192 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_persistent_state_metrics(c: &mut Criterion) {
    let mut template_state = new_engine_state(SnatMode::Auto);
    attach_metrics(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state_metrics",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_persistent_state_metrics_reuse_packet(c: &mut Criterion) {
    let mut template_state = new_engine_state(SnatMode::Auto);
    attach_metrics(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let first_flow = make_flow(0);
    let base_bytes = build_eth_ipv4_tcp(
        [0; 6],
        [0; 6],
        first_flow.src_ip,
        first_flow.dst_ip,
        first_flow.src_port,
        first_flow.dst_port,
        payload,
    )
    .into_vec();
    let mut packet = Packet::from_bytes(&base_bytes);
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state_metrics_reuse_packet",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                reset_eth_ipv4_tcp_packet_tuple(
                    &mut packet,
                    &base_bytes,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_flow_steer_payload_dpdk_buffer(c: &mut Criterion) {
    const RX_BUFFER_LEN: usize = 65_536;
    const PACKET_LEN: usize = 64;

    c.bench_function("dataplane_flow_steer_payload_dpdk_buffer_legacy", |b| {
        b.iter_batched(
            || build_dpdk_sized_transfer_packet(PACKET_LEN),
            |mut packet| {
                let payload = legacy_flow_steer_payload(&mut packet);
                packet.prepare_for_rx(RX_BUFFER_LEN);
                black_box((payload.len(), packet.len()))
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("dataplane_flow_steer_payload_dpdk_buffer_compact", |b| {
        b.iter_batched(
            || build_dpdk_sized_transfer_packet(PACKET_LEN),
            |mut packet| {
                let payload = packet.take_transfer_bytes();
                packet.prepare_for_rx(RX_BUFFER_LEN);
                black_box((payload.len(), packet.len()))
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_flow_steer_dispatch_queue(c: &mut Criterion) {
    const QUEUE_CAPACITY: usize = 1024;
    let payload = vec![0u8; 64];

    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(QUEUE_CAPACITY);
    c.bench_function("dataplane_flow_steer_dispatch_sync_channel", |b| {
        b.iter(|| {
            tx.send(payload.clone()).expect("send");
            let received = rx.try_recv().expect("recv");
            black_box(received.len())
        })
    });

    let queue = ArrayQueue::new(QUEUE_CAPACITY);
    c.bench_function("dataplane_flow_steer_dispatch_array_queue", |b| {
        b.iter(|| {
            queue.push(payload.clone()).expect("push");
            let received = queue.pop().expect("pop");
            black_box(received.len())
        })
    });
}

fn bench_flow_steer_borrowed_handoff(c: &mut Criterion) {
    const QUEUE_CAPACITY: usize = 1024;
    let packet_template = build_ipv4_tcp(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(198, 51, 100, 10),
        40_000,
        443,
        b"hello",
    );

    let copy_queue = ArrayQueue::new(QUEUE_CAPACITY);
    c.bench_function("dataplane_flow_steer_borrowed_handoff_copy", |b| {
        b.iter_batched(
            || {
                let mut backing = packet_template.buffer().to_vec();
                let pkt = unsafe {
                    Packet::from_borrowed_mut(backing.as_mut_ptr(), backing.len())
                        .expect("borrowed packet")
                };
                (backing, pkt)
            },
            |(_backing, mut pkt)| {
                let payload = pkt.take_transfer_bytes();
                copy_queue.push(payload).expect("push");
                let frame = copy_queue.pop().expect("pop");
                let rebuilt = Packet::new(frame);
                black_box((rebuilt.protocol(), rebuilt.ports()))
            },
            BatchSize::SmallInput,
        )
    });

    let zero_copy_queue = ArrayQueue::new(QUEUE_CAPACITY);
    c.bench_function(
        "dataplane_flow_steer_borrowed_handoff_zero_copy_simulated",
        |b| {
            b.iter_batched(
                || {
                    let mut backing = packet_template.buffer().to_vec();
                    let pkt = unsafe {
                        Packet::from_borrowed_mut(backing.as_mut_ptr(), backing.len())
                            .expect("borrowed packet")
                    };
                    (backing, pkt)
                },
                |(_backing, mut pkt)| {
                    let payload = borrowed_flow_steer_payload(&mut pkt);
                    zero_copy_queue.push(payload).expect("push");
                    let payload = zero_copy_queue.pop().expect("pop");
                    let rebuilt =
                        unsafe { Packet::from_borrowed_mut(payload.ptr.as_ptr(), payload.len) }
                            .expect("rebuild borrowed packet");
                    black_box((rebuilt.protocol(), rebuilt.ports()))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_flow_steer_metrics_handles(c: &mut Criterion) {
    let metrics = Metrics::new().expect("metrics");
    let flow_steer_metrics = metrics.bind_dpdk_flow_steer_metrics(4);
    let wait = Duration::from_nanos(32);

    c.bench_function("dataplane_flow_steer_metrics_label_lookup", |b| {
        b.iter(|| {
            metrics.observe_dpdk_flow_steer_queue_wait(1, wait);
            metrics.inc_dpdk_flow_steer_dispatch(0, 1);
            metrics.add_dpdk_flow_steer_bytes(0, 1, 64);
            metrics.set_dpdk_flow_steer_queue_depth(1, 3);
            black_box(())
        })
    });

    c.bench_function("dataplane_flow_steer_metrics_bound_handles", |b| {
        b.iter(|| {
            flow_steer_metrics.observe_dispatch(0, 1, 64, wait);
            flow_steer_metrics.set_queue_depth(1, 3);
            black_box(())
        })
    });
}

#[derive(Default)]
struct MockTurnIo {
    rx_packets: usize,
    tx_bytes: usize,
}

impl neuwerk::dataplane::FrameIo for MockTurnIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        let len = buf.len().min(64);
        buf[..len].fill(0);
        self.rx_packets += 1;
        Ok(len)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.tx_bytes += frame.len();
        Ok(())
    }

    fn finish_rx_packet(&mut self) {}

    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
}

fn bench_shared_io_turn_lock(c: &mut Criterion) {
    let shared = Mutex::new(MockTurnIo::default());
    let mut packet = Packet::new(vec![0u8; 256]);

    c.bench_function("dataplane_shared_io_turn_mutex_reacquire", |b| {
        b.iter(|| {
            {
                let mut io = shared.lock().expect("lock");
                black_box(io.recv_packet(&mut packet).expect("recv"));
            }
            {
                let mut io = shared.lock().expect("lock");
                io.send_borrowed_frame(packet.buffer()).expect("send");
            }
            {
                let mut io = shared.lock().expect("lock");
                io.finish_rx_packet();
            }
            {
                let mut io = shared.lock().expect("lock");
                io.flush().expect("flush");
            }
        })
    });

    c.bench_function("dataplane_shared_io_turn_single_lock", |b| {
        b.iter(|| {
            let mut io = shared.lock().expect("lock");
            black_box(io.recv_packet(&mut packet).expect("recv"));
            io.send_borrowed_frame(packet.buffer()).expect("send");
            io.finish_rx_packet();
            io.flush().expect("flush");
        })
    });
}

fn bench_new_tcp_flow_snat_persistent_state_wiretap(c: &mut Criterion) {
    let mut template_state = new_engine_state(SnatMode::Auto);
    attach_wiretap(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state_wiretap",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_persistent_state_audit(c: &mut Criterion) {
    let mut template_state = new_engine_state(SnatMode::Auto);
    attach_audit(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state_audit",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_snat_persistent_state_observability(c: &mut Criterion) {
    let mut template_state = new_engine_state(SnatMode::Auto);
    attach_metrics(&mut template_state);
    attach_wiretap(&mut template_state);
    attach_audit(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_snat_persistent_state_observability",
        |b| {
            b.iter(|| {
                let flow = make_flow(index);
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_established_tcp_flow_no_snat_generation_churn(c: &mut Criterion) {
    let tracker = Arc::new(AtomicU64::new(1));
    let mut state = new_engine_state(SnatMode::None);
    state.set_policy_applied_generation(tracker.clone());
    state.evict_expired_now();
    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 50000,
        dst_port: 443,
        proto: 6,
    };
    let packet_bytes = build_ipv4_tcp(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        b"hello",
    )
    .into_vec();
    let mut seed_packet = Packet::from_bytes(&packet_bytes);
    assert_eq!(
        handle_packet(&mut seed_packet, &mut state),
        Action::Forward { out_port: 0 }
    );
    let mut generation = 2u64;

    c.bench_function(
        "dataplane_handle_packet_established_tcp_no_snat_generation_churn",
        |b| {
            b.iter_batched(
                || Packet::from_bytes(&packet_bytes),
                |mut packet| {
                    tracker.store(generation, std::sync::atomic::Ordering::Release);
                    generation += 1;
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_established_tcp_flow_no_snat_large_policy(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let template_state = new_engine_state_with_policy(
        policy_with_many_rules_for_source(src_ip, 16, 64),
        SnatMode::None,
    );
    let mut state = clone_bench_state(&template_state);
    let flow = FlowKey {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 50_000,
        dst_port: 443,
        proto: 6,
    };
    let packet_bytes = build_ipv4_tcp(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        b"hello",
    )
    .into_vec();
    let mut seed_packet = Packet::from_bytes(&packet_bytes);
    assert_eq!(
        handle_packet(&mut seed_packet, &mut state),
        Action::Forward { out_port: 0 }
    );

    c.bench_function(
        "dataplane_handle_packet_established_tcp_no_snat_large_policy",
        |b| {
            b.iter_batched(
                || Packet::from_bytes(&packet_bytes),
                |mut packet| {
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_established_tcp_flow_no_snat_large_policy_generation_churn(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let tracker = Arc::new(AtomicU64::new(1));
    let mut state = new_engine_state_with_policy(
        policy_with_many_rules_for_source(src_ip, 16, 64),
        SnatMode::None,
    );
    state.set_policy_applied_generation(tracker.clone());
    state.evict_expired_now();
    let flow = FlowKey {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 50_000,
        dst_port: 443,
        proto: 6,
    };
    let packet_bytes = build_ipv4_tcp(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        b"hello",
    )
    .into_vec();
    let mut seed_packet = Packet::from_bytes(&packet_bytes);
    assert_eq!(
        handle_packet(&mut seed_packet, &mut state),
        Action::Forward { out_port: 0 }
    );
    let mut generation = 2u64;

    c.bench_function(
        "dataplane_handle_packet_established_tcp_no_snat_large_policy_generation_churn",
        |b| {
            b.iter_batched(
                || Packet::from_bytes(&packet_bytes),
                |mut packet| {
                    tracker.store(generation, std::sync::atomic::Ordering::Release);
                    generation += 1;
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_established_tcp_flow_no_snat_large_policy_unique_source_generation_churn(
    c: &mut Criterion,
) {
    let tracker = Arc::new(AtomicU64::new(1));
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let mut state = new_engine_state_with_policy(policy, SnatMode::None);
    state.set_policy_applied_generation(tracker.clone());
    state.evict_expired_now();
    let flow = FlowKey {
        src_ip,
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 50_000,
        dst_port: 443,
        proto: 6,
    };
    let packet_bytes = build_ipv4_tcp(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        b"hello",
    )
    .into_vec();
    let mut seed_packet = Packet::from_bytes(&packet_bytes);
    assert_eq!(
        handle_packet(&mut seed_packet, &mut state),
        Action::Forward { out_port: 0 }
    );
    let mut generation = 2u64;

    c.bench_function(
        "dataplane_handle_packet_established_tcp_no_snat_large_policy_unique_source_generation_churn",
        |b| {
            b.iter_batched(
                || Packet::from_bytes(&packet_bytes),
                |mut packet| {
                    tracker.store(generation, std::sync::atomic::Ordering::Release);
                    generation += 1;
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)))
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy(c: &mut Criterion) {
    let template_state =
        new_engine_state_with_policy(policy_with_many_rules(16, 64), SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy",
        |b| {
            b.iter(|| {
                let flow = FlowKey {
                    src_ip: Ipv4Addr::new(10, 0, 0, 42),
                    dst_ip: Ipv4Addr::new(198, 51, 100, 10),
                    src_port: 10_000 + index as u16,
                    dst_port: 443,
                    proto: 6,
                };
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_reuse_packet(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(10, 0, 0, 42);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    let template_state = new_engine_state_with_policy(
        policy_with_many_rules_for_source(src_ip, 16, 64),
        SnatMode::None,
    );
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let base_bytes =
        build_eth_ipv4_tcp([0; 6], [0; 6], src_ip, dst_ip, 10_000, 443, payload).into_vec();
    let mut packet = Packet::from_bytes(&base_bytes);
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_reuse_packet",
        |b| {
            b.iter(|| {
                let src_port = 10_000 + index as u16;
                index += 1;
                reset_eth_ipv4_tcp_packet_tuple(
                    &mut packet,
                    &base_bytes,
                    src_ip,
                    dst_ip,
                    src_port,
                    443,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source(c: &mut Criterion) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let template_state = new_engine_state_with_policy(policy, SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_unique_source",
        |b| {
            b.iter(|| {
                let src_port = 10_000 + index as u16;
                index += 1;
                let mut packet = build_ipv4_tcp(
                    src_ip,
                    Ipv4Addr::new(198, 51, 100, 10),
                    src_port,
                    443,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_reuse_packet(
    c: &mut Criterion,
) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    let template_state = new_engine_state_with_policy(policy, SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let base_bytes =
        build_eth_ipv4_tcp([0; 6], [0; 6], src_ip, dst_ip, 10_000, 443, payload).into_vec();
    let mut packet = Packet::from_bytes(&base_bytes);
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_unique_source_reuse_packet",
        |b| {
            b.iter(|| {
                let src_port = 10_000 + index as u16;
                index += 1;
                reset_eth_ipv4_tcp_packet_tuple(
                    &mut packet,
                    &base_bytes,
                    src_ip,
                    dst_ip,
                    src_port,
                    443,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_handle_only(
    c: &mut Criterion,
) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources(1024);
    let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
    let template_state = new_engine_state_with_policy(policy, SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let packet_bytes = (0..4096u32)
        .map(|index| {
            build_eth_ipv4_tcp(
                [0; 6],
                [0; 6],
                src_ip,
                dst_ip,
                10_000 + index as u16,
                443,
                payload,
            )
            .into_vec()
        })
        .collect::<Vec<_>>();
    let mut index = 0usize;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_unique_source_handle_only",
        |b| {
            b.iter_batched(
                || {
                    let packet = Packet::from_bytes(&packet_bytes[index]);
                    index += 1;
                    let reset_state = if index == packet_bytes.len() {
                        index = 0;
                        true
                    } else {
                        false
                    };
                    (packet, reset_state)
                },
                |(mut packet, reset_state)| {
                    let result =
                        black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                    if reset_state {
                        state = clone_bench_state(&template_state);
                    }
                    result
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_mixed(c: &mut Criterion) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources_mixed(1024);
    let template_state = new_engine_state_with_policy(policy, SnatMode::None);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_unique_source_mixed",
        |b| {
            b.iter(|| {
                let src_port = 10_000 + index as u16;
                index += 1;
                let mut packet = build_ipv4_tcp(
                    src_ip,
                    Ipv4Addr::new(198, 51, 100, 10),
                    src_port,
                    443,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_mixed_full_scan(
    c: &mut Criterion,
) {
    let (policy, src_ip) = policy_with_many_groups_unique_sources_mixed(1024);
    let mut template_state = new_engine_state_with_policy(policy, SnatMode::None);
    template_state.set_exact_source_policy_index(Arc::new(arc_swap::ArcSwap::from_pointee(
        Default::default(),
    )));
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_unique_source_mixed_full_scan",
        |b| {
            b.iter(|| {
                let src_port = 10_000 + index as u16;
                index += 1;
                let mut packet = build_ipv4_tcp(
                    src_ip,
                    Ipv4Addr::new(198, 51, 100, 10),
                    src_port,
                    443,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_new_tcp_flow_no_snat_persistent_state_large_policy_sparse_audit(c: &mut Criterion) {
    let src_ip = Ipv4Addr::new(172, 16, 0, 42);
    let mut template_state = new_engine_state_with_policy(
        policy_with_many_rules_for_source_sparse_audit(src_ip, 16, 64),
        SnatMode::None,
    );
    attach_audit(&mut template_state);
    let mut state = clone_bench_state(&template_state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_handle_packet_new_tcp_no_snat_persistent_state_large_policy_sparse_audit",
        |b| {
            b.iter(|| {
                let flow = FlowKey {
                    src_ip,
                    dst_ip: Ipv4Addr::new(198, 51, 100, 10),
                    src_port: 10_000 + index as u16,
                    dst_port: 443,
                    proto: 6,
                };
                index += 1;
                let mut packet = build_ipv4_tcp(
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    flow.dst_port,
                    payload,
                );
                let result =
                    black_box(handle_packet(black_box(&mut packet), black_box(&mut state)));
                if index == 4096 {
                    state = clone_bench_state(&template_state);
                    index = 0;
                }
                result
            })
        },
    );
}

fn bench_dpdk_adapter_process_packet_in_place_udp(c: &mut Criterion) {
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let host_mac = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
    let gw_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let gw_ip = Ipv4Addr::new(10, 0, 0, 254);
    let fw_ip = Ipv4Addr::new(10, 0, 0, 1);

    let template_state = new_engine_state(SnatMode::None);
    template_state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: gw_ip,
        mac: fw_mac,
        lease_expiry: None,
    });

    let mut state = clone_bench_state(&template_state);
    let mut adapter = DpdkAdapter::new("bench0".to_string()).expect("adapter");
    adapter.set_mac(fw_mac);
    let arp = build_arp_request(gw_mac, gw_ip, fw_ip);
    let _ = adapter.process_frame(&arp, &mut state);
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function("dataplane_dpdk_adapter_process_packet_in_place_udp", |b| {
        b.iter(|| {
            let flow = FlowKey {
                proto: 17,
                ..make_flow(index)
            };
            index += 1;
            let mut packet = build_eth_ipv4_udp(
                host_mac,
                fw_mac,
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                53,
                payload,
            );
            let result = match adapter.process_packet_in_place(&mut packet, &mut state) {
                Some(FrameOut::Borrowed(frame)) => frame.len(),
                Some(FrameOut::Owned(frame)) => frame.len(),
                None => 0,
            };
            if index == 4096 {
                state = clone_bench_state(&template_state);
                adapter = DpdkAdapter::new("bench0".to_string()).expect("adapter");
                adapter.set_mac(fw_mac);
                let arp = build_arp_request(gw_mac, gw_ip, fw_ip);
                let _ = adapter.process_frame(&arp, &mut state);
                index = 0;
            }
            black_box(result)
        })
    });
}

fn bench_dpdk_adapter_process_packet_in_place_udp_mutex_state(c: &mut Criterion) {
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let host_mac = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
    let gw_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let gw_ip = Ipv4Addr::new(10, 0, 0, 254);
    let fw_ip = Ipv4Addr::new(10, 0, 0, 1);

    let template_state = new_engine_state(SnatMode::None);
    template_state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: gw_ip,
        mac: fw_mac,
        lease_expiry: None,
    });

    let state = std::sync::Mutex::new(clone_bench_state(&template_state));
    let mut adapter = DpdkAdapter::new("bench0".to_string()).expect("adapter");
    adapter.set_mac(fw_mac);
    {
        let mut guard = state.lock().expect("state");
        let arp = build_arp_request(gw_mac, gw_ip, fw_ip);
        let _ = adapter.process_frame(&arp, &mut guard);
    }
    let payload = b"hello";
    let mut index = 0u32;

    c.bench_function(
        "dataplane_dpdk_adapter_process_packet_in_place_udp_mutex_state",
        |b| {
            b.iter(|| {
                let flow = FlowKey {
                    proto: 17,
                    ..make_flow(index)
                };
                index += 1;
                let mut packet = build_eth_ipv4_udp(
                    host_mac,
                    fw_mac,
                    flow.src_ip,
                    flow.dst_ip,
                    flow.src_port,
                    53,
                    payload,
                );
                let result = {
                    let mut guard = state.lock().expect("state");
                    match adapter.process_packet_in_place(&mut packet, &mut guard) {
                        Some(FrameOut::Borrowed(frame)) => frame.len(),
                        Some(FrameOut::Owned(frame)) => frame.len(),
                        None => 0,
                    }
                };
                if index == 4096 {
                    let mut guard = state.lock().expect("state");
                    *guard = clone_bench_state(&template_state);
                    adapter = DpdkAdapter::new("bench0".to_string()).expect("adapter");
                    adapter.set_mac(fw_mac);
                    let arp = build_arp_request(gw_mac, gw_ip, fw_ip);
                    let _ = adapter.process_frame(&arp, &mut guard);
                    index = 0;
                }
                black_box(result)
            })
        },
    );
}

criterion_group!(
    dataplane_benches,
    bench_new_tcp_flow_no_snat,
    bench_new_tcp_flow_no_snat_persistent_state,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_reuse_packet,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_sparse_audit,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_reuse_packet,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_handle_only,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_mixed,
    bench_new_tcp_flow_no_snat_persistent_state_large_policy_unique_source_mixed_full_scan,
    bench_new_tcp_flow_snat_persistent_state,
    bench_new_tcp_flow_snat_short_lived_churn,
    bench_new_tcp_flow_snat_persistent_state_metrics,
    bench_new_tcp_flow_snat_persistent_state_metrics_reuse_packet,
    bench_new_tcp_flow_snat_persistent_state_wiretap,
    bench_new_tcp_flow_snat_persistent_state_audit,
    bench_new_tcp_flow_snat_persistent_state_observability,
    bench_new_tcp_flow_snat,
    bench_new_udp_flow_no_snat_persistent_state,
    bench_established_tcp_flow_no_snat,
    bench_established_tcp_flow_inbound_snat_persistent_state,
    bench_established_tcp_flow_no_snat_generation_churn,
    bench_established_tcp_flow_no_snat_large_policy,
    bench_established_tcp_flow_no_snat_large_policy_generation_churn,
    bench_established_tcp_flow_no_snat_large_policy_unique_source_generation_churn,
    bench_policy_eval_allow_small,
    bench_policy_eval_allow_large,
    bench_policy_eval_allow_large_group_scan,
    bench_policy_eval_allow_large_group_scan_cidr_source,
    bench_policy_eval_allow_large_rule_scan,
    bench_policy_eval_allow_large_unique_source,
    bench_policy_eval_allow_large_unique_source_exact_index,
    bench_policy_read_lock_only,
    bench_is_internal,
    bench_is_internal_large_policy,
    bench_is_internal_large_unique_source_policy,
    bench_dynamic_ip_set_contains,
    bench_flow_table_insert,
    bench_flow_open_bookkeeping_metrics,
    bench_nat_get_or_create,
    bench_packet_parse_core,
    bench_packet_rewrite_snat,
    bench_packet_reset_eth_ipv4_tcp_tuple,
    bench_packet_from_bytes,
    bench_shared_io_turn_lock,
    bench_flow_steer_dispatch_queue,
    bench_flow_steer_borrowed_handoff,
    bench_flow_steer_metrics_handles,
    bench_flow_steer_payload_dpdk_buffer,
    bench_state_clone_for_shard,
    bench_dpdk_adapter_process_packet_in_place_udp,
    bench_dpdk_adapter_process_packet_in_place_udp_mutex_state
);
criterion_main!(dataplane_benches);
