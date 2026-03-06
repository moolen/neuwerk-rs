use super::*;

mod tests {
    use super::*;

    #[test]
    fn compile_policy_from_yaml() {
        let yaml = r#"
default_policy: deny
source_groups:
  - id: "k8s"
    sources:
      cidrs: ["10.0.0.0/24"]
      ips: ["10.0.1.5"]
    default_action: deny
    rules:
      - id: "web"
        action: allow
        match:
          dst_ips: ["93.184.216.34"]
          proto: tcp
          dst_ports: [443, "80-81"]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        assert_eq!(compiled.default_policy, Some(DefaultPolicy::Deny));
        assert_eq!(compiled.groups.len(), 1);

        let group = &compiled.groups[0];
        assert!(group.sources.contains("10.0.0.42".parse().unwrap()));
        assert!(group.sources.contains("10.0.1.5".parse().unwrap()));
        assert!(!group.sources.contains("10.0.2.1".parse().unwrap()));

        let rule = &group.rules[0];
        assert_eq!(rule.action, RuleAction::Allow);
        assert_eq!(rule.matcher.proto, Proto::Tcp);
        assert!(rule
            .matcher
            .dst_ips
            .as_ref()
            .unwrap()
            .contains("93.184.216.34".parse().unwrap()));
        assert!(rule.matcher.dst_ports[0].contains(443));
        assert!(rule.matcher.dst_ports[1].contains(80));
        assert!(rule.matcher.dst_ports[1].contains(81));
    }

    #[test]
    fn empty_sources_rejected() {
        let yaml = r#"
source_groups:
  - id: "empty"
    sources: {}
    rules: []
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("sources cannot be empty"));
    }

    #[test]
    fn dns_hostname_regex_allows_case_insensitive() {
        let yaml = r#"
source_groups:
  - id: "dns"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow"
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let policy = compiled.dns_policy;
        assert!(policy.allows("192.0.2.2".parse().unwrap(), "FoO.AlLoWeD."));
        assert!(!policy.allows("192.0.2.2".parse().unwrap(), "bar.allowed"));
    }

    #[test]
    fn dns_hostname_invalid_regex_rejected() {
        let yaml = r#"
source_groups:
  - id: "dns"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "bad"
        action: allow
        match:
          dns_hostname: "["
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("invalid dns_hostname regex"));
    }

    #[test]
    fn dns_hostname_empty_rejected() {
        let yaml = r#"
source_groups:
  - id: "dns"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "empty"
        action: allow
        match:
          dns_hostname: "   "
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("dns_hostname cannot be empty"));
    }

    #[test]
    fn dns_hostname_long_name_match() {
        let yaml = r#"
source_groups:
  - id: "dns"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-long"
        action: allow
        match:
          dns_hostname: '^very\.long\.subdomain\.name\.example\.com$'
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let policy = compiled.dns_policy;
        assert!(policy.allows(
            "192.0.2.2".parse().unwrap(),
            "very.long.subdomain.name.example.com"
        ));
    }

    #[test]
    fn dns_hostname_priority_first_match_wins() {
        let yaml = r#"
source_groups:
  - id: "dns"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "deny-specific"
        priority: 0
        action: deny
        match:
          dns_hostname: '^bar\.allowed$'
      - id: "allow-wildcard"
        priority: 1
        action: allow
        match:
          dns_hostname: '.*\.allowed$'
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let policy = compiled.dns_policy;
        assert!(!policy.allows("192.0.2.2".parse().unwrap(), "bar.allowed"));
        assert!(policy.allows("192.0.2.2".parse().unwrap(), "baz.allowed"));
    }

    #[test]
    fn audit_rules_are_mode_filtered() {
        let yaml = r#"
source_groups:
  - id: "mixed"
    sources:
      ips: ["192.0.2.9"]
    rules:
      - id: "audit-rule"
        mode: audit
        action: allow
        match:
          dst_ips: ["203.0.113.10"]
      - id: "enforce-rule"
        mode: enforce
        action: deny
        match:
          dst_ips: ["203.0.113.11"]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let policy = crate::dataplane::policy::PolicySnapshot::new(
            crate::dataplane::policy::DefaultPolicy::Deny,
            compiled.groups,
        );
        let enforce_meta = crate::dataplane::policy::PacketMeta {
            src_ip: "192.0.2.9".parse().unwrap(),
            dst_ip: "203.0.113.11".parse().unwrap(),
            proto: 6,
            src_port: 12345,
            dst_port: 443,
            icmp_type: None,
            icmp_code: None,
        };
        let audit_meta = crate::dataplane::policy::PacketMeta {
            dst_ip: "203.0.113.10".parse().unwrap(),
            ..enforce_meta
        };
        assert_eq!(
            policy
                .evaluate_with_source_group_detailed_raw(&enforce_meta, None, None)
                .0,
            crate::dataplane::policy::PolicyDecision::Deny
        );
        assert_eq!(
            policy
                .evaluate_with_source_group_detailed_raw(&audit_meta, None, None)
                .0,
            crate::dataplane::policy::PolicyDecision::Deny
        );
        let (audit_decision, _, audit_matched) =
            policy.evaluate_audit_rules_with_source_group(&audit_meta, None, None);
        assert!(audit_matched);
        assert_eq!(
            audit_decision,
            crate::dataplane::policy::PolicyDecision::Allow
        );
    }

    #[test]
    fn icmp_match_requires_icmp_proto() {
        let yaml = r#"
source_groups:
  - id: "icmp"
    sources:
      ips: ["192.0.2.9"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: tcp
          icmp_types: [8]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("icmp type/code matches require proto icmp or any"));
    }

    #[test]
    fn icmp_ports_rejected() {
        let yaml = r#"
source_groups:
  - id: "icmp"
    sources:
      ips: ["192.0.2.9"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: icmp
          dst_ports: [80]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("port matches are not valid for icmp rules"));
    }

    #[test]
    fn icmp_defaults_apply_when_empty() {
        let yaml = r#"
source_groups:
  - id: "icmp"
    sources:
      ips: ["192.0.2.9"]
    rules:
      - id: "icmp-default"
        action: allow
        match:
          proto: icmp
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let matcher = &compiled.groups[0].rules[0].matcher;
        assert_eq!(matcher.icmp_types, vec![0, 3, 11]);
        assert_eq!(matcher.icmp_codes, vec![0, 4]);
    }

    #[test]
    fn tls_intercept_http_policy_compiles() {
        let yaml = r#"
source_groups:
  - id: "tls"
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: "intercept"
        action: allow
        match:
          proto: tcp
          dst_ports: [443]
          tls:
            mode: intercept
            http:
              request:
                host:
                  exact: ["example.com"]
                methods: ["GET", "post"]
                path:
                  prefix: ["/api/"]
              response:
                headers:
                  require_present: ["content-type"]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = cfg.compile().unwrap();
        let tls = compiled.groups[0].rules[0].matcher.tls.as_ref().unwrap();
        assert!(matches!(tls.mode, TlsMode::Intercept));
        let http = tls.intercept_http.as_ref().unwrap();
        let req = http.request.as_ref().unwrap();
        assert_eq!(req.methods, vec!["GET".to_string(), "POST".to_string()]);
    }

    #[test]
    fn tls_http_requires_intercept_mode() {
        let yaml = r#"
source_groups:
  - id: "tls"
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: tcp
          tls:
            http:
              request:
                host:
                  exact: ["example.com"]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("tls.http is only valid when tls.mode is intercept"));
    }

    #[test]
    fn tls_intercept_requires_http_constraints() {
        let yaml = r#"
source_groups:
  - id: "tls"
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: tcp
          tls:
            mode: intercept
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("tls.mode intercept requires tls.http constraints"));
    }

    #[test]
    fn tls_intercept_rejects_metadata_matchers() {
        let yaml = r#"
source_groups:
  - id: "tls"
    sources:
      ips: ["10.0.0.2"]
    rules:
      - id: "bad"
        action: allow
        match:
          proto: tcp
          tls:
            mode: intercept
            sni: ["example.com"]
            http:
              request:
                host:
                  exact: ["example.com"]
"#;
        let cfg: PolicyConfig = serde_yaml::from_str(yaml).unwrap();
        let err = cfg.compile().unwrap_err();
        assert!(err.contains("cannot be combined with metadata matchers"));
    }
}
