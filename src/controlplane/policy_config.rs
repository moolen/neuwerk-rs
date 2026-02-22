use std::net::Ipv4Addr;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PortRange, Proto, Rule, RuleAction, RuleMatch, SourceGroup,
    Tls13Uninspectable, TlsMatch, TlsNameMatch,
};
use x509_parser::pem::parse_x509_pem;

#[derive(Debug)]
pub struct CompiledPolicy {
    pub default_policy: Option<DefaultPolicy>,
    pub groups: Vec<SourceGroup>,
    pub dns_policy: DnsPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Audit,
    Enforce,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Enforce
    }
}

#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub groups: Vec<DnsSourceGroup>,
}

impl DnsPolicy {
    pub fn new(mut groups: Vec<DnsSourceGroup>) -> Self {
        groups.sort_by_key(|group| group.priority);
        for group in &mut groups {
            group.rules.sort_by_key(|rule| rule.priority);
        }
        Self { groups }
    }

    pub fn allows(&self, src_ip: Ipv4Addr, hostname: &str) -> bool {
        self.evaluate_with_source_group(src_ip, hostname).0
    }

    pub fn evaluate_with_source_group(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
    ) -> (bool, Option<String>) {
        let hostname = normalize_hostname(hostname);
        for group in &self.groups {
            if !group.sources.contains(src_ip) {
                continue;
            }
            for rule in &group.rules {
                if rule.hostname.is_match(&hostname) {
                    return (rule.action == RuleAction::Allow, Some(group.id.clone()));
                }
            }
            return (false, Some(group.id.clone()));
        }
        (false, None)
    }

    pub fn source_group_for_ip(&self, src_ip: Ipv4Addr) -> Option<String> {
        self.groups
            .iter()
            .find(|group| group.sources.contains(src_ip))
            .map(|group| group.id.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DnsSourceGroup {
    pub id: String,
    pub priority: u32,
    pub sources: IpSetV4,
    pub rules: Vec<DnsRule>,
}

#[derive(Debug, Clone)]
pub struct DnsRule {
    pub id: String,
    pub priority: u32,
    pub action: RuleAction,
    pub hostname: Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub default_policy: Option<PolicyValue>,
    #[serde(default)]
    pub source_groups: Vec<SourceGroupConfig>,
}

impl PolicyConfig {
    pub fn compile(self) -> Result<CompiledPolicy, String> {
        let default_policy = match self.default_policy {
            Some(value) => Some(parse_default_policy(value)?),
            None => None,
        };

        let mut groups = Vec::with_capacity(self.source_groups.len());
        let mut dns_groups = Vec::with_capacity(self.source_groups.len());
        for (idx, group) in self.source_groups.into_iter().enumerate() {
            let (group, dns_group) = group.compile(idx as u32)?;
            groups.push(group);
            dns_groups.push(dns_group);
        }

        Ok(CompiledPolicy {
            default_policy,
            groups,
            dns_policy: DnsPolicy::new(dns_groups),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceGroupConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub sources: SourcesConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    pub default_action: Option<PolicyValue>,
}

impl SourceGroupConfig {
    fn compile(self, fallback_priority: u32) -> Result<(SourceGroup, DnsSourceGroup), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let sources = self.sources.compile(&self.id)?;
        let default_action = match self.default_action {
            Some(value) => Some(parse_rule_action(value)?),
            None => None,
        };

        let mut rules = Vec::with_capacity(self.rules.len());
        let mut dns_rules = Vec::with_capacity(self.rules.len());
        for (idx, rule) in self.rules.into_iter().enumerate() {
            let (rule, dns_rule) = rule.compile(idx as u32)?;
            if let Some(rule) = rule {
                rules.push(rule);
            }
            if let Some(dns_rule) = dns_rule {
                dns_rules.push(dns_rule);
            }
        }

        let group = SourceGroup {
            id: self.id.clone(),
            priority,
            sources: sources.clone(),
            rules,
            default_action,
        };

        let dns_group = DnsSourceGroup {
            id: self.id,
            priority,
            sources,
            rules: dns_rules,
        };

        Ok((group, dns_group))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcesConfig {
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
}

impl SourcesConfig {
    fn compile(self, group_id: &str) -> Result<IpSetV4, String> {
        let mut sources = IpSetV4::new();

        for cidr in self.cidrs {
            let cidr = parse_cidr_v4(&cidr).map_err(|err| format!("group {group_id}: {err}"))?;
            sources.add_cidr(cidr);
        }

        for ip in self.ips {
            let ip = parse_ipv4(&ip).map_err(|err| format!("group {group_id}: {err}"))?;
            sources.add_ip(ip);
        }

        if sources.is_empty() {
            return Err(format!("group {group_id}: sources cannot be empty"));
        }

        Ok(sources)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub action: PolicyValue,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(rename = "match")]
    pub matcher: RuleMatchConfig,
}

impl RuleConfig {
    fn compile(self, fallback_priority: u32) -> Result<(Option<Rule>, Option<DnsRule>), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let action = parse_rule_action(self.action)?;
        let dns_rule = compile_dns_rule(
            &self.id,
            priority,
            action,
            self.matcher.dns_hostname.as_deref(),
        )?;
        let matcher = self.matcher.compile(&self.id)?;

        if self.mode == PolicyMode::Audit {
            return Ok((None, None));
        }

        let rule = Rule {
            id: self.id,
            priority,
            matcher,
            action,
        };

        Ok((Some(rule), dns_rule))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatchConfig {
    #[serde(default)]
    pub dst_cidrs: Vec<String>,
    #[serde(default)]
    pub dst_ips: Vec<String>,
    #[serde(default)]
    pub dns_hostname: Option<String>,
    pub proto: Option<ProtoValue>,
    #[serde(default)]
    pub src_ports: Vec<PortSpec>,
    #[serde(default)]
    pub dst_ports: Vec<PortSpec>,
    #[serde(default)]
    pub icmp_types: Vec<u8>,
    #[serde(default)]
    pub icmp_codes: Vec<u8>,
    pub tls: Option<TlsMatchConfig>,
}

impl RuleMatchConfig {
    fn compile(self, rule_id: &str) -> Result<RuleMatch, String> {
        let dst_ips = if self.dst_cidrs.is_empty() && self.dst_ips.is_empty() {
            None
        } else {
            let mut set = IpSetV4::new();
            for cidr in self.dst_cidrs {
                let cidr = parse_cidr_v4(&cidr).map_err(|err| format!("rule {rule_id}: {err}"))?;
                set.add_cidr(cidr);
            }
            for ip in self.dst_ips {
                let ip = parse_ipv4(&ip).map_err(|err| format!("rule {rule_id}: {err}"))?;
                set.add_ip(ip);
            }
            Some(set)
        };

        let proto = match self.proto {
            Some(value) => parse_proto(value).map_err(|err| format!("rule {rule_id}: {err}"))?,
            None => Proto::Any,
        };

        let mut src_ports = Vec::with_capacity(self.src_ports.len());
        for spec in self.src_ports {
            src_ports.push(parse_port_range(spec).map_err(|err| format!("rule {rule_id}: {err}"))?);
        }

        let mut dst_ports = Vec::with_capacity(self.dst_ports.len());
        for spec in self.dst_ports {
            dst_ports.push(parse_port_range(spec).map_err(|err| format!("rule {rule_id}: {err}"))?);
        }

        let tls = match self.tls {
            Some(tls) => Some(tls.compile(rule_id)?),
            None => None,
        };

        if tls.is_some() && !matches!(proto, Proto::Tcp | Proto::Any) {
            return Err(format!(
                "rule {rule_id}: tls matches require proto tcp or any"
            ));
        }

        if (!self.icmp_types.is_empty() || !self.icmp_codes.is_empty())
            && !matches!(proto, Proto::Icmp | Proto::Any)
        {
            return Err(format!(
                "rule {rule_id}: icmp type/code matches require proto icmp or any"
            ));
        }

        if matches!(proto, Proto::Icmp) && (!src_ports.is_empty() || !dst_ports.is_empty()) {
            return Err(format!(
                "rule {rule_id}: port matches are not valid for icmp rules"
            ));
        }

        let mut icmp_types = self.icmp_types;
        let mut icmp_codes = self.icmp_codes;
        if matches!(proto, Proto::Icmp) && icmp_types.is_empty() && icmp_codes.is_empty() {
            icmp_types = vec![0, 3, 11];
            icmp_codes = vec![0, 4];
        }

        Ok(RuleMatch {
            dst_ips,
            proto,
            src_ports,
            dst_ports,
            icmp_types,
            icmp_codes,
            tls,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsMatchConfig {
    pub sni: Option<TlsNameMatchConfig>,
    pub server_dn: Option<String>,
    pub server_san: Option<TlsNameMatchConfig>,
    pub server_cn: Option<TlsNameMatchConfig>,
    #[serde(default)]
    pub fingerprint_sha256: Vec<String>,
    #[serde(default)]
    pub trust_anchors_pem: Vec<String>,
    #[serde(default)]
    pub tls13_uninspectable: Option<Tls13UninspectableValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tls13UninspectableValue {
    Allow,
    Deny,
}

impl From<Tls13UninspectableValue> for Tls13Uninspectable {
    fn from(value: Tls13UninspectableValue) -> Self {
        match value {
            Tls13UninspectableValue::Allow => Tls13Uninspectable::Allow,
            Tls13UninspectableValue::Deny => Tls13Uninspectable::Deny,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TlsNameMatchConfig {
    String(String),
    List(Vec<String>),
    Object {
        #[serde(default)]
        exact: Vec<String>,
        regex: Option<String>,
    },
}

impl TlsNameMatchConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<TlsNameMatch, String> {
        let (mut exact, regex) = match self {
            TlsNameMatchConfig::String(value) => (Vec::new(), Some(value)),
            TlsNameMatchConfig::List(values) => (values, None),
            TlsNameMatchConfig::Object { exact, regex } => (exact, regex),
        };

        for value in &mut exact {
            *value = normalize_hostname(value);
        }
        exact.retain(|value| !value.is_empty());

        let regex = match regex {
            Some(pattern) => {
                let pattern = pattern.trim();
                if pattern.is_empty() {
                    return Err(format!("rule {rule_id}: {field} regex cannot be empty"));
                }
                Some(
                    RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .map_err(|err| {
                            format!("rule {rule_id}: invalid {field} regex: {err}")
                        })?,
                )
            }
            None => None,
        };

        let matcher = TlsNameMatch { exact, regex };
        if matcher.is_empty() {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(matcher)
    }
}

impl TlsMatchConfig {
    fn compile(self, rule_id: &str) -> Result<TlsMatch, String> {
        let sni = match self.sni {
            Some(config) => Some(config.compile(rule_id, "tls.sni")?),
            None => None,
        };

        let server_cn = match (self.server_cn, self.server_dn) {
            (Some(config), _) => Some(config.compile(rule_id, "tls.server_cn")?),
            (None, Some(legacy)) => Some(
                TlsNameMatchConfig::String(legacy).compile(rule_id, "tls.server_dn")?,
            ),
            _ => None,
        };

        let server_san = match self.server_san {
            Some(config) => Some(config.compile(rule_id, "tls.server_san")?),
            None => None,
        };

        let mut fingerprints_sha256 = Vec::with_capacity(self.fingerprint_sha256.len());
        for fp in self.fingerprint_sha256 {
            fingerprints_sha256.push(
                parse_sha256_fingerprint(&fp)
                    .map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let mut trust_anchors = Vec::new();
        for pem in self.trust_anchors_pem {
            trust_anchors.extend(
                parse_pem_cert_chain(&pem)
                    .map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let tls13_uninspectable = self
            .tls13_uninspectable
            .unwrap_or(Tls13UninspectableValue::Deny)
            .into();

        Ok(TlsMatch {
            sni,
            server_san,
            server_cn,
            fingerprints_sha256,
            trust_anchors,
            tls13_uninspectable,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyValue {
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtoValue {
    String(String),
    Number(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Number(u16),
    String(String),
}

fn parse_default_policy(value: PolicyValue) -> Result<DefaultPolicy, String> {
    match value {
        PolicyValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "allow" => Ok(DefaultPolicy::Allow),
            "deny" => Ok(DefaultPolicy::Deny),
            _ => Err(format!("invalid default policy: {value}")),
        },
    }
}

fn parse_rule_action(value: PolicyValue) -> Result<RuleAction, String> {
    match value {
        PolicyValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "allow" => Ok(RuleAction::Allow),
            "deny" => Ok(RuleAction::Deny),
            _ => Err(format!("invalid rule action: {value}")),
        },
    }
}

fn parse_proto(value: ProtoValue) -> Result<Proto, String> {
    match value {
        ProtoValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "any" => Ok(Proto::Any),
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "icmp" => Ok(Proto::Icmp),
            other => other
                .parse::<u8>()
                .map(parse_proto_number)
                .map_err(|_| format!("invalid proto value: {value}")),
        },
        ProtoValue::Number(value) => Ok(parse_proto_number(value)),
    }
}

fn parse_proto_number(value: u8) -> Proto {
    match value {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        1 => Proto::Icmp,
        _ => Proto::Other(value),
    }
}

fn parse_port_range(spec: PortSpec) -> Result<PortRange, String> {
    match spec {
        PortSpec::Number(value) => Ok(PortRange {
            start: value,
            end: value,
        }),
        PortSpec::String(value) => {
            if let Some((start, end)) = value.split_once('-') {
                let start = start
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range start: {value}"))?;
                let end = end
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range end: {value}"))?;
                if start > end {
                    return Err(format!("invalid port range: {value}"));
                }
                Ok(PortRange { start, end })
            } else {
                let port = value
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: {value}"))?;
                Ok(PortRange {
                    start: port,
                    end: port,
                })
            }
        }
    }
}

fn parse_cidr_v4(value: &str) -> Result<CidrV4, String> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let addr = parse_ipv4(addr)?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| format!("invalid prefix length: {value}"))?;
        if prefix > 32 {
            return Err(format!("invalid prefix length: {value}"));
        }
        Ok(CidrV4::new(addr, prefix))
    } else {
        let addr = parse_ipv4(value)?;
        Ok(CidrV4::new(addr, 32))
    }
}

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address: {value}"))
}

fn parse_sha256_fingerprint(value: &str) -> Result<[u8; 32], String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if cleaned.len() != 64 {
        return Err(format!("invalid sha256 fingerprint length: {value}"));
    }
    let bytes = hex::decode(cleaned).map_err(|_| format!("invalid sha256 fingerprint: {value}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_pem_cert_chain(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut input = value.as_bytes();
    let mut certs = Vec::new();
    loop {
        while let Some(b) = input.first() {
            if b.is_ascii_whitespace() {
                input = &input[1..];
            } else {
                break;
            }
        }
        if input.is_empty() {
            break;
        }
        let (rest, pem) =
            parse_x509_pem(input).map_err(|_| "invalid PEM certificate".to_string())?;
        if pem.label != "CERTIFICATE" {
            return Err("unsupported PEM label for trust anchor".to_string());
        }
        certs.push(pem.contents.to_vec());
        input = rest;
    }
    if certs.is_empty() {
        return Err("trust_anchors_pem cannot be empty".to_string());
    }
    Ok(certs)
}

fn compile_dns_rule(
    rule_id: &str,
    priority: u32,
    action: RuleAction,
    hostname: Option<&str>,
) -> Result<Option<DnsRule>, String> {
    let Some(hostname) = hostname else {
        return Ok(None);
    };
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err(format!("rule {rule_id}: dns_hostname cannot be empty"));
    }
    let regex = RegexBuilder::new(hostname)
        .case_insensitive(true)
        .build()
        .map_err(|err| format!("rule {rule_id}: invalid dns_hostname regex: {err}"))?;
    Ok(Some(DnsRule {
        id: rule_id.to_string(),
        priority,
        action,
        hostname: regex,
    }))
}

fn normalize_hostname(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
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
    fn audit_rules_are_ignored() {
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
        let group = &compiled.groups[0];
        assert_eq!(group.rules.len(), 1);
        assert_eq!(group.rules[0].id, "enforce-rule");
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
}
