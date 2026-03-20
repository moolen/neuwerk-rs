use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use firewall::controlplane::metrics::Metrics;
use firewall::dataplane::config::DataplaneConfig;
use firewall::dataplane::policy::{
    new_shared_exact_source_group_index, CidrV4, DefaultPolicy, DynamicIpSetV4, IpSetV4,
    PolicySnapshot, PortRange, Proto, Rule, RuleAction, RuleMatch, SourceGroup, Tls13Uninspectable,
    TlsMatch, TlsMode, TlsNameMatch,
};
use firewall::dataplane::{
    handle_packet, Action, EngineState, FlowKey, FlowTable, NatTable, Packet, WiretapEmitter,
    WiretapEventType,
};
use firewall::dataplane::{EncapMode, OverlayConfig, SnatMode};

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

fn build_ipv4_tcp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
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
    buf[l4_off + 13] = 0x10;
    buf[l4_off + 16..l4_off + 18].copy_from_slice(&1024u16.to_be_bytes());
    buf[l4_off + 18..l4_off + 20].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 20..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn set_tcp_flags(pkt: &mut Packet, flags: u8) {
    let l4_off = 20;
    pkt.buffer_mut()[l4_off + 13] = flags;
    assert!(pkt.recalc_checksums());
}

fn refresh_policy_state(state: &mut EngineState) {
    let snapshot = state.policy.read().expect("policy lock poisoned").clone();
    state.set_exact_source_policy_index(new_shared_exact_source_group_index(&snapshot));
    state.set_policy_snapshot(Arc::new(arc_swap::ArcSwap::from_pointee(snapshot)));
}

fn build_ipv4_icmp_echo(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Packet {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 1;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let icmp_off = 20;
    buf[icmp_off] = icmp_type;
    buf[icmp_off + 1] = icmp_code;
    buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&0u16.to_be_bytes());
    buf[icmp_off + 4..icmp_off + 6].copy_from_slice(&identifier.to_be_bytes());
    buf[icmp_off + 6..icmp_off + 8].copy_from_slice(&sequence.to_be_bytes());
    buf[icmp_off + 8..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn build_ipv4_icmp_error(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    icmp_type: u8,
    icmp_code: u8,
    embedded: &[u8],
) -> Packet {
    let icmp_len = 8 + embedded.len();
    let total_len = 20 + icmp_len;
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 1;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let icmp_off = 20;
    buf[icmp_off] = icmp_type;
    buf[icmp_off + 1] = icmp_code;
    buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&0u16.to_be_bytes());
    buf[icmp_off + 4..icmp_off + 8].copy_from_slice(&0u32.to_be_bytes());
    buf[icmp_off + 8..icmp_off + 8 + embedded.len()].copy_from_slice(embedded);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn tls_client_hello_record(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![
        1,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn tls_application_data_record(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::new();
    record.push(23);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + inner.len()];
    buf[0] = 0x08;
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[8..].copy_from_slice(inner);
    buf
}

#[test]
fn overlay_vxlan_policy_applies_to_inner() {
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
        Ipv4Addr::UNSPECIFIED,
        0,
    );
    state.set_snat_mode(SnatMode::None);
    state.set_overlay_config(OverlayConfig {
        mode: EncapMode::Vxlan,
        udp_port: 10800,
        udp_port_internal: None,
        udp_port_external: None,
        vni: Some(800),
        vni_internal: None,
        vni_external: None,
        mtu: 1500,
    });

    let inner = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 42),
        Ipv4Addr::new(198, 51, 100, 10),
        50000,
        8080,
        b"hello",
    );
    let payload = build_vxlan_payload(inner.buffer(), 800);
    let outer = build_ipv4_udp(
        Ipv4Addr::new(192, 0, 2, 10),
        Ipv4Addr::new(192, 0, 2, 11),
        5555,
        10800,
        &payload,
    );

    let overlay =
        firewall::dataplane::overlay::decap(outer.buffer(), &state.overlay, None).expect("decap");
    let mut pkt = overlay.inner;
    let action = handle_packet(&mut pkt, &mut state);
    assert!(matches!(action, Action::Forward { .. }));
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

fn policy_with_tls_intercept(
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    generation: u64,
) -> PolicySnapshot {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(internal_net, internal_prefix));

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
        mode: firewall::dataplane::policy::RuleMode::Enforce,
    };

    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };

    PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], generation)
}

fn checksum_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    sum
}

fn checksum_finalize(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_checksum_valid(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl {
        return false;
    }
    checksum_finalize(checksum_sum(&buf[..ihl])) == 0
}

fn udp_checksum_valid(buf: &[u8]) -> bool {
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 8 {
        return false;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let l4 = &buf[ihl..total_len];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let mut sum = 0u32;
    sum += checksum_sum(&src.octets());
    sum += checksum_sum(&dst.octets());
    sum += 17u32;
    sum += l4.len() as u32;
    sum += checksum_sum(l4);
    checksum_finalize(sum) == 0
}

fn icmp_checksum_valid(buf: &[u8]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let ihl = (buf[0] & 0x0f) as usize * 4;
    if buf.len() < ihl + 8 {
        return false;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < ihl + 8 || buf.len() < total_len {
        return false;
    }
    let icmp = &buf[ihl..total_len];
    checksum_finalize(checksum_sum(icmp)) == 0
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

#[test]
fn dataplane_metrics_track_allow_and_deny() {
    let internal_net = Ipv4Addr::new(10, 0, 0, 0);
    let internal_prefix = 24;
    let public_ip = Ipv4Addr::new(203, 0, 113, 1);
    let allow_dst = Ipv4Addr::new(1, 1, 1, 1);
    let deny_dst = Ipv4Addr::new(2, 2, 2, 2);

    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(internal_net, internal_prefix));
    let mut dst_ips = IpSetV4::new();
    dst_ips.add_ip(allow_dst);
    let rule = Rule {
        id: "allow".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: Some(dst_ips),
            proto: Proto::Udp,
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
        default_action: Some(RuleAction::Deny),
    };

    let policy = Arc::new(RwLock::new(PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![group],
    )));

    let metrics = Metrics::new().unwrap();
    let mut state = EngineState::new(policy, internal_net, internal_prefix, public_ip, 0);
    state.set_metrics(metrics.clone());

    let mut allow_pkt = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 10), allow_dst, 1234, 53, b"ok");
    let allow_action = handle_packet(&mut allow_pkt, &mut state);
    assert!(matches!(allow_action, Action::Forward { .. }));

    let mut deny_pkt = build_ipv4_udp(Ipv4Addr::new(10, 0, 0, 11), deny_dst, 1234, 53, b"nope");
    let deny_action = handle_packet(&mut deny_pkt, &mut state);
    assert!(matches!(deny_action, Action::Drop));

    let rendered = metrics.render().unwrap();
    assert!(
        metric_has(
            &rendered,
            "dp_packets_total",
            &[
                ("direction", "outbound"),
                ("proto", "udp"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        ),
        "metrics:\n{rendered}"
    );
    assert!(
        metric_has(
            &rendered,
            "dp_packets_total",
            &[
                ("direction", "outbound"),
                ("proto", "udp"),
                ("decision", "deny"),
                ("source_group", "internal"),
            ],
        ),
        "metrics:\n{rendered}"
    );
    assert!(
        metric_has(
            &rendered,
            "dp_flow_opens_total",
            &[("proto", "udp"), ("source_group", "internal")],
        ),
        "metrics:\n{rendered}"
    );
}

fn metric_has(rendered: &str, name: &str, labels: &[(&str, &str)]) -> bool {
    for line in rendered.lines() {
        if !line.starts_with(name) || line.starts_with("#") {
            continue;
        }
        let brace_start = match line.find('{') {
            Some(idx) => idx,
            None => continue,
        };
        let brace_end = match line[brace_start..].find('}') {
            Some(idx) => brace_start + idx,
            None => continue,
        };
        let label_str = &line[brace_start + 1..brace_end];
        let mut matched = 0usize;
        for (k, v) in labels {
            let needle = format!("{k}=\"{v}\"");
            if label_str.contains(&needle) {
                matched += 1;
            }
        }
        if matched == labels.len() {
            return true;
        }
    }
    false
}

fn metric_value(rendered: &str, name: &str) -> Option<f64> {
    for line in rendered.lines() {
        if line.starts_with('#') || !line.starts_with(name) {
            continue;
        }
        if line.contains('{') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let metric = parts.next()?;
        if metric != name {
            continue;
        }
        let value = parts.next()?;
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

#[path = "packet_unit/cases.rs"]
mod cases;
