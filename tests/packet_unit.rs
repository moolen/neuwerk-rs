use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use firewall::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction,
    PortRange, RuleMatch, SourceGroup, Tls13Uninspectable, TlsMatch, TlsNameMatch,
};
use firewall::controlplane::metrics::Metrics;
use firewall::dataplane::{
    handle_packet, Action, EngineState, FlowKey, FlowTable, NatTable, Packet, WiretapEmitter,
    WiretapEventType,
};
use firewall::dataplane::config::DataplaneConfig;

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

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.push(((body.len() >> 16) & 0xff) as u8);
    handshake.push(((body.len() >> 8) & 0xff) as u8);
    handshake.push((body.len() & 0xff) as u8);
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
    let mut state =
        EngineState::new(policy, internal_net, internal_prefix, public_ip, 0);
    state.set_metrics(metrics.clone());

    let mut allow_pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 10),
        allow_dst,
        1234,
        53,
        b"ok",
    );
    let allow_action = handle_packet(&mut allow_pkt, &mut state);
    assert!(matches!(allow_action, Action::Forward { .. }));

    let mut deny_pkt = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 11),
        deny_dst,
        1234,
        53,
        b"nope",
    );
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
    let mut pkt = build_ipv4_udp(
        orig_src,
        orig_dst,
        40000,
        80,
        b"ttl-expired",
    );
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
    let mut echo = build_ipv4_icmp_echo(
        internal_ip,
        remote_ip,
        8,
        0,
        0x1234,
        1,
        b"ping",
    );
    let action = handle_packet(&mut echo, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    assert_eq!(echo.src_ip(), Some(dp_ip));
    let external_id = echo.icmp_identifier().unwrap();
    assert_ne!(external_id, 0x1234);

    let mut reply = build_ipv4_icmp_echo(
        remote_ip,
        dp_ip,
        0,
        0,
        external_id,
        1,
        b"pong",
    );
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
    let mut icmp_err = build_ipv4_icmp_error(
        internal_ip,
        remote_ip,
        3,
        3,
        &embedded_slice,
    );

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
    let mut outbound = build_ipv4_udp(
        internal_ip,
        remote_ip,
        40000,
        8080,
        b"payload",
    );
    let action = handle_packet(&mut outbound, &mut state);
    assert_eq!(action, Action::Forward { out_port: 0 });
    let external_port = outbound.ports().unwrap().0;

    let embedded = build_ipv4_udp(
        dp_ip,
        remote_ip,
        external_port,
        8080,
        b"payload",
    );
    let embedded_len = 20 + 8;
    let embedded_slice = embedded.buffer()[..embedded_len].to_vec();
    let mut icmp_err = build_ipv4_icmp_error(
        remote_ip,
        dp_ip,
        3,
        4,
        &embedded_slice,
    );
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
    let mut nat = firewall::dataplane::NatTable::new();
    let flow = FlowKey {
        src_ip: Ipv4Addr::new(10, 0, 0, 3),
        dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        src_port: 5555,
        dst_port: 53,
        proto: 17,
    };
    let external_port = nat.get_or_create(&flow, 0).unwrap();
    let reverse = firewall::dataplane::ReverseKey {
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

#[test]
fn test_tls_sni_allows_flow() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    let tls = TlsMatch {
        sni: Some(TlsNameMatch {
            exact: vec!["api.example.com".to_string()],
            regex: None,
        }),
        server_san: None,
        server_cn: None,
        fingerprints_sha256: Vec::new(),
        trust_anchors: Vec::new(),
        tls13_uninspectable: Tls13Uninspectable::Deny,
    };

    let rule = Rule {
        id: "tls".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![PortRange { start: 443, end: 443 }],
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: Some(tls),
        },
        action: RuleAction::Allow,
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
        sni: Some(TlsNameMatch {
            exact: vec!["api.example.com".to_string()],
            regex: None,
        }),
        server_san: None,
        server_cn: None,
        fingerprints_sha256: Vec::new(),
        trust_anchors: Vec::new(),
        tls13_uninspectable: Tls13Uninspectable::Deny,
    };

    let rule = Rule {
        id: "tls".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![PortRange { start: 443, end: 443 }],
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: Some(tls),
        },
        action: RuleAction::Allow,
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
