use std::net::Ipv4Addr;

use super::*;

#[test]
fn allowlist_gc_respects_active_flows() {
    let allowlist = DynamicIpSetV4::new();
    let ip = Ipv4Addr::new(203, 0, 113, 10);

    allowlist.insert_at(ip, 100);
    allowlist.flow_open(ip, 120);

    let removed = allowlist.evict_idle(1000, 10);
    assert_eq!(removed, 0);
    assert!(allowlist.contains(ip));

    allowlist.flow_close(ip, 500);
    let removed = allowlist.evict_idle(560, 50);
    assert_eq!(removed, 1);
    assert!(!allowlist.contains(ip));
}

#[test]
fn allowlist_insert_preserves_active_flow_count() {
    let allowlist = DynamicIpSetV4::new();
    let ip = Ipv4Addr::new(198, 51, 100, 7);

    allowlist.insert_at(ip, 10);
    allowlist.flow_open(ip, 20);
    allowlist.insert_at(ip, 30);

    let removed = allowlist.evict_idle(1000, 10);
    assert_eq!(removed, 0);
    assert!(allowlist.contains(ip));
}

#[test]
fn policy_snapshot_is_internal_checks_all_groups() {
    let mut group_a = SourceGroup {
        id: "a".to_string(),
        priority: 0,
        sources: IpSetV4::new(),
        rules: Vec::new(),
        default_action: None,
    };
    group_a
        .sources
        .add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

    let mut group_b = SourceGroup {
        id: "b".to_string(),
        priority: 1,
        sources: IpSetV4::new(),
        rules: Vec::new(),
        default_action: None,
    };
    group_b
        .sources
        .add_cidr(CidrV4::new(Ipv4Addr::new(192, 168, 1, 0), 24));

    let snapshot = PolicySnapshot::new(DefaultPolicy::Deny, vec![group_a, group_b]);
    assert!(snapshot.is_internal(Ipv4Addr::new(10, 0, 0, 5)));
    assert!(snapshot.is_internal(Ipv4Addr::new(192, 168, 1, 50)));
    assert!(!snapshot.is_internal(Ipv4Addr::new(203, 0, 113, 5)));
}

#[test]
fn evaluate_audit_rules_reports_matched_rule() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(192, 0, 2, 0), 24));
    let group = SourceGroup {
        id: "audit".to_string(),
        priority: 0,
        sources,
        rules: vec![Rule {
            id: "audit-allow".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some({
                    let mut ips = IpSetV4::new();
                    ips.add_cidr(CidrV4::new(Ipv4Addr::new(203, 0, 113, 10), 32));
                    ips
                }),
                proto: Proto::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: RuleMode::Audit,
        }],
        default_action: None,
    };
    let policy = PolicySnapshot::new(DefaultPolicy::Deny, vec![group]);

    let meta = PacketMeta {
        src_ip: Ipv4Addr::new(192, 0, 2, 9),
        dst_ip: Ipv4Addr::new(203, 0, 113, 10),
        proto: 6,
        src_port: 12345,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let (decision, group, matched) =
        policy.evaluate_audit_rules_with_source_group(&meta, None, None);
    assert_eq!(decision, PolicyDecision::Allow);
    assert_eq!(group.as_deref(), Some("audit"));
    assert!(matched);

    let no_match_meta = PacketMeta {
        dst_ip: Ipv4Addr::new(203, 0, 113, 11),
        ..meta
    };
    let (decision, group, matched) =
        policy.evaluate_audit_rules_with_source_group(&no_match_meta, None, None);
    assert_eq!(decision, PolicyDecision::Allow);
    assert!(group.is_none());
    assert!(!matched);
}
