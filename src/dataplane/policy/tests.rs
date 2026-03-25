use std::net::Ipv4Addr;

use super::*;
use crate::controlplane::policy_config::{
    PolicyConfig, PolicyValue, PortSpec, ProtoValue, RuleConfig, RuleMatchConfig,
    RuleMode as ConfigRuleMode, SourceGroupConfig, SourcesConfig, TlsMatchConfig,
};
use crate::dataplane::tls::{TlsCertChain, TlsObservation, TlsVerifier};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyUsagePurpose};
use x509_parser::parse_x509_certificate;

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
fn allowlist_remove_many_removes_only_matching_entries() {
    let allowlist = DynamicIpSetV4::new();
    let keep_ip = Ipv4Addr::new(198, 51, 100, 8);
    let remove_ip = Ipv4Addr::new(198, 51, 100, 9);

    allowlist.insert(keep_ip);
    allowlist.insert(remove_ip);

    let removed = allowlist.remove_many([remove_ip, Ipv4Addr::new(198, 51, 100, 10)]);
    assert_eq!(removed, 1);
    assert!(allowlist.contains(keep_ip));
    assert!(!allowlist.contains(remove_ip));
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

#[test]
fn evaluate_prefers_earlier_wildcard_rule_over_later_exact_rule() {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let target_ip = Ipv4Addr::new(198, 51, 100, 10);

    let rules = vec![
        Rule {
            id: "allow-any".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: None,
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: RuleMode::Enforce,
        },
        Rule {
            id: "deny-target".to_string(),
            priority: 1,
            matcher: RuleMatch {
                dst_ips: Some({
                    let mut ips = IpSetV4::new();
                    ips.add_ip(target_ip);
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
            mode: RuleMode::Enforce,
        },
    ];

    let policy = PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![SourceGroup {
            id: "group".to_string(),
            priority: 0,
            sources,
            rules,
            default_action: None,
        }],
    );

    let meta = PacketMeta {
        src_ip: Ipv4Addr::new(10, 0, 0, 42),
        dst_ip: target_ip,
        proto: 6,
        src_port: 12345,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };

    let (decision, group) = policy.evaluate_with_source_group(&meta, None, None);
    assert_eq!(decision, PolicyDecision::Allow);
    assert_eq!(group.as_deref(), Some("group"));
}

#[test]
fn evaluate_exact_source_group_dispatch_matches_expected_group() {
    let target_ip = Ipv4Addr::new(198, 51, 100, 10);
    let src_a = Ipv4Addr::new(172, 16, 0, 1);
    let src_b = Ipv4Addr::new(172, 16, 0, 2);

    let mut sources_a = IpSetV4::new();
    sources_a.add_ip(src_a);
    let mut sources_b = IpSetV4::new();
    sources_b.add_ip(src_b);

    let policy = PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![
            SourceGroup {
                id: "a".to_string(),
                priority: 0,
                sources: sources_a,
                rules: vec![Rule {
                    id: "allow-a".to_string(),
                    priority: 0,
                    matcher: RuleMatch {
                        dst_ips: Some({
                            let mut ips = IpSetV4::new();
                            ips.add_ip(Ipv4Addr::new(203, 0, 113, 1));
                            ips
                        }),
                        proto: Proto::Tcp,
                        src_ports: Vec::new(),
                        dst_ports: Vec::new(),
                        icmp_types: Vec::new(),
                        icmp_codes: Vec::new(),
                        tls: None,
                    },
                    action: RuleAction::Allow,
                    mode: RuleMode::Enforce,
                }],
                default_action: None,
            },
            SourceGroup {
                id: "b".to_string(),
                priority: 1,
                sources: sources_b,
                rules: vec![Rule {
                    id: "allow-b".to_string(),
                    priority: 0,
                    matcher: RuleMatch {
                        dst_ips: Some({
                            let mut ips = IpSetV4::new();
                            ips.add_ip(target_ip);
                            ips
                        }),
                        proto: Proto::Tcp,
                        src_ports: Vec::new(),
                        dst_ports: Vec::new(),
                        icmp_types: Vec::new(),
                        icmp_codes: Vec::new(),
                        tls: None,
                    },
                    action: RuleAction::Allow,
                    mode: RuleMode::Enforce,
                }],
                default_action: None,
            },
        ],
    );

    let meta = PacketMeta {
        src_ip: src_b,
        dst_ip: target_ip,
        proto: 6,
        src_port: 12345,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };

    let (decision, group) = policy.evaluate_with_source_group(&meta, None, None);
    assert_eq!(decision, PolicyDecision::Allow);
    assert_eq!(group.as_deref(), Some("b"));
    assert!(policy.is_internal(src_b));
    assert!(!policy.is_internal(Ipv4Addr::new(172, 16, 0, 99)));
}

fn ca_cert(name: &str) -> Certificate {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    Certificate::from_params(params).unwrap()
}

fn leaf_cert_der(signer: &Certificate, common_name: &str, organization: &str) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, organization);
    Certificate::from_params(params)
        .unwrap()
        .serialize_der_with_signer(signer)
        .unwrap()
}

#[test]
fn server_dn_matches_full_subject_dn_not_just_common_name() {
    let ca = ca_cert("policy-root");
    let ca_pem = ca.serialize_pem().unwrap();
    let leaf_der = leaf_cert_der(&ca, "api.example.com", "Example Corp");
    let (_, leaf_cert) = parse_x509_certificate(&leaf_der).unwrap();
    let subject_dn = leaf_cert.subject().to_string();

    let cfg = PolicyConfig {
        default_policy: Some(PolicyValue::String("deny".to_string())),
        source_groups: vec![SourceGroupConfig {
            id: "tls-users".to_string(),
            priority: Some(0),
            sources: SourcesConfig {
                cidrs: vec!["10.40.0.0/24".to_string()],
                ips: Vec::new(),
                kubernetes: Vec::new(),
            },
            rules: vec![RuleConfig {
                id: "allow-server-dn".to_string(),
                priority: Some(0),
                action: PolicyValue::String("allow".to_string()),
                mode: ConfigRuleMode::Enforce,
                matcher: RuleMatchConfig {
                    dst_cidrs: Vec::new(),
                    dst_ips: vec!["203.0.113.10".to_string()],
                    dns_hostname: None,
                    proto: Some(ProtoValue::String("tcp".to_string())),
                    src_ports: Vec::new(),
                    dst_ports: vec![PortSpec::Number(443)],
                    icmp_types: Vec::new(),
                    icmp_codes: Vec::new(),
                    tls: Some(TlsMatchConfig {
                        mode: None,
                        sni: None,
                        server_dn: Some(subject_dn),
                        server_san: None,
                        server_cn: None,
                        fingerprint_sha256: Vec::new(),
                        trust_anchors_pem: vec![ca_pem],
                        tls13_uninspectable: None,
                        http: None,
                    }),
                },
            }],
            default_action: Some(PolicyValue::String("deny".to_string())),
        }],
    };
    let compiled = cfg.compile().unwrap();
    let policy = PolicySnapshot::new(DefaultPolicy::Deny, compiled.groups);

    let observation = TlsObservation {
        client_hello_seen: true,
        server_hello_seen: true,
        certificate_seen: true,
        tls13: false,
        sni: None,
        cert_chain: Some(TlsCertChain::from_der_chain(vec![leaf_der]).unwrap()),
    };
    let meta = PacketMeta {
        src_ip: Ipv4Addr::new(10, 40, 0, 5),
        dst_ip: Ipv4Addr::new(203, 0, 113, 10),
        proto: 6,
        src_port: 40000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };
    let decision = policy.evaluate(&meta, Some(&observation), Some(&TlsVerifier::new()));
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn exact_source_group_index_keeps_fallback_groups_and_preserves_priority_order() {
    let target_ip = Ipv4Addr::new(198, 51, 100, 10);
    let src_ip = Ipv4Addr::new(172, 16, 0, 2);

    let mut exact_sources = IpSetV4::new();
    exact_sources.add_ip(src_ip);
    let mut fallback_sources = IpSetV4::new();
    fallback_sources.add_cidr(CidrV4::new(Ipv4Addr::new(172, 16, 0, 0), 24));

    let policy = PolicySnapshot::new(
        DefaultPolicy::Deny,
        vec![
            SourceGroup {
                id: "fallback".to_string(),
                priority: 0,
                sources: fallback_sources,
                rules: vec![Rule {
                    id: "deny-target".to_string(),
                    priority: 0,
                    matcher: RuleMatch {
                        dst_ips: Some({
                            let mut ips = IpSetV4::new();
                            ips.add_ip(target_ip);
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
                    mode: RuleMode::Enforce,
                }],
                default_action: None,
            },
            SourceGroup {
                id: "exact".to_string(),
                priority: 1,
                sources: exact_sources,
                rules: vec![Rule {
                    id: "allow-target".to_string(),
                    priority: 0,
                    matcher: RuleMatch {
                        dst_ips: Some({
                            let mut ips = IpSetV4::new();
                            ips.add_ip(target_ip);
                            ips
                        }),
                        proto: Proto::Tcp,
                        src_ports: Vec::new(),
                        dst_ports: Vec::new(),
                        icmp_types: Vec::new(),
                        icmp_codes: Vec::new(),
                        tls: None,
                    },
                    action: RuleAction::Allow,
                    mode: RuleMode::Enforce,
                }],
                default_action: None,
            },
        ],
    );
    let index = ExactSourceGroupIndex::for_snapshot(&policy);
    let meta = PacketMeta {
        src_ip,
        dst_ip: target_ip,
        proto: 6,
        src_port: 12345,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    };

    let (effective, raw, group_idx, _) = policy
        .evaluate_with_source_group_effective_and_raw_index_for_group_indices_borrowed(
            index.group_indices(src_ip),
            index.fallback_group_indices(),
            &meta,
            None,
            None,
        );

    assert_eq!(effective, PolicyDecision::Deny);
    assert_eq!(raw, PolicyDecision::Deny);
    assert_eq!(group_idx, Some(0));
}
