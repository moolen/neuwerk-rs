use std::net::Ipv4Addr;

use firewall::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PolicyDecision, PolicySnapshot, PortRange, Proto, Rule,
    RuleAction, RuleMatch, SourceGroup, Tls13Uninspectable, TlsMatch, TlsNameMatch,
};
use firewall::dataplane::tls::{TlsCertChain, TlsObservation, TlsVerifier};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyUsagePurpose};

fn build_chain(san: &str, cn: &str) -> (Vec<u8>, TlsCertChain) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Policy Test CA");
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let ca_der = ca_cert.serialize_der().unwrap();

    let mut leaf_params = CertificateParams::new(vec![san.to_string()]);
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, cn);
    let leaf_cert = Certificate::from_params(leaf_params).unwrap();
    let leaf_der = leaf_cert.serialize_der_with_signer(&ca_cert).unwrap();

    let chain = TlsCertChain::from_der_chain(vec![leaf_der, ca_der.clone()]).unwrap();
    (ca_der, chain)
}

fn policy_with_tls_match(tls: TlsMatch) -> PolicySnapshot {
    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
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
    PolicySnapshot::new(DefaultPolicy::Deny, vec![group])
}

fn base_tls_match() -> TlsMatch {
    TlsMatch {
        sni: None,
        server_san: None,
        server_cn: None,
        fingerprints_sha256: Vec::new(),
        trust_anchors: Vec::new(),
        tls13_uninspectable: Tls13Uninspectable::Deny,
    }
}

fn meta() -> firewall::dataplane::policy::PacketMeta {
    firewall::dataplane::policy::PacketMeta {
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        proto: 6,
        src_port: 40000,
        dst_port: 443,
        icmp_type: None,
        icmp_code: None,
    }
}

#[test]
fn tls_policy_san_mismatch_cn_match_denies() {
    let (ca_der, chain) = build_chain("bar.allowed", "foo.allowed");
    let obs = TlsObservation {
        certificate_seen: true,
        cert_chain: Some(chain),
        ..TlsObservation::default()
    };

    let tls = TlsMatch {
        server_san: Some(TlsNameMatch {
            exact: vec!["foo.allowed".to_string()],
            regex: None,
        }),
        server_cn: Some(TlsNameMatch {
            exact: vec!["foo.allowed".to_string()],
            regex: None,
        }),
        trust_anchors: vec![ca_der],
        ..base_tls_match()
    };

    let policy = policy_with_tls_match(tls);
    let verifier = TlsVerifier::new();
    let decision = policy.evaluate(&meta(), Some(&obs), Some(&verifier));
    assert_eq!(decision, PolicyDecision::Deny);
}

#[test]
fn tls_policy_fingerprint_match_allows_and_mismatch_denies() {
    let (ca_der, chain) = build_chain("foo.allowed", "foo.allowed");
    let obs = TlsObservation {
        certificate_seen: true,
        cert_chain: Some(chain.clone()),
        ..TlsObservation::default()
    };

    let tls_match = TlsMatch {
        fingerprints_sha256: vec![chain.leaf_fingerprint],
        trust_anchors: vec![ca_der.clone()],
        ..base_tls_match()
    };
    let policy = policy_with_tls_match(tls_match);
    let verifier = TlsVerifier::new();
    let decision = policy.evaluate(&meta(), Some(&obs), Some(&verifier));
    assert_eq!(decision, PolicyDecision::Allow);

    let tls_mismatch = TlsMatch {
        fingerprints_sha256: vec![[0u8; 32]],
        trust_anchors: vec![ca_der],
        ..base_tls_match()
    };

    let policy = policy_with_tls_match(tls_mismatch);
    let decision = policy.evaluate(&meta(), Some(&obs), Some(&verifier));
    assert_eq!(decision, PolicyDecision::Deny);
}

#[test]
fn tls_policy_trust_anchor_mismatch_denies() {
    let (ca_der, chain) = build_chain("foo.allowed", "foo.allowed");
    let obs = TlsObservation {
        certificate_seen: true,
        cert_chain: Some(chain),
        ..TlsObservation::default()
    };

    let mut wrong_ca_params = CertificateParams::default();
    wrong_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    wrong_ca_params.key_usages =
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    wrong_ca_params
        .distinguished_name
        .push(DnType::CommonName, "Wrong CA");
    let wrong_ca = Certificate::from_params(wrong_ca_params).unwrap();
    let wrong_ca_der = wrong_ca.serialize_der().unwrap();

    let tls = TlsMatch {
        trust_anchors: vec![wrong_ca_der.clone(), ca_der],
        ..base_tls_match()
    };

    let policy = policy_with_tls_match(tls);
    let verifier = TlsVerifier::new();
    let decision = policy.evaluate(&meta(), Some(&obs), Some(&verifier));
    assert_eq!(decision, PolicyDecision::Allow);

    let tls_bad = TlsMatch {
        trust_anchors: vec![wrong_ca_der],
        ..base_tls_match()
    };
    let policy = policy_with_tls_match(tls_bad);
    let decision = policy.evaluate(&meta(), Some(&obs), Some(&verifier));
    assert_eq!(decision, PolicyDecision::Deny);
}
