use std::net::Ipv4Addr;

use serde::Deserialize;

use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PortRange, Proto, Rule, RuleAction, RuleMatch, SourceGroup,
    TlsMatch,
};

#[derive(Debug)]
pub struct CompiledPolicy {
    pub default_policy: Option<DefaultPolicy>,
    pub groups: Vec<SourceGroup>,
}

#[derive(Debug, Deserialize)]
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
        for (idx, group) in self.source_groups.into_iter().enumerate() {
            groups.push(group.compile(idx as u32)?);
        }

        Ok(CompiledPolicy {
            default_policy,
            groups,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct SourceGroupConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub sources: SourcesConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    pub default_action: Option<PolicyValue>,
}

impl SourceGroupConfig {
    fn compile(self, fallback_priority: u32) -> Result<SourceGroup, String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let sources = self.sources.compile(&self.id)?;
        let default_action = match self.default_action {
            Some(value) => Some(parse_rule_action(value)?),
            None => None,
        };

        let mut rules = Vec::with_capacity(self.rules.len());
        for (idx, rule) in self.rules.into_iter().enumerate() {
            rules.push(rule.compile(idx as u32)?);
        }

        Ok(SourceGroup {
            id: self.id,
            priority,
            sources,
            rules,
            default_action,
        })
    }
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub action: PolicyValue,
    #[serde(rename = "match")]
    pub matcher: RuleMatchConfig,
}

impl RuleConfig {
    fn compile(self, fallback_priority: u32) -> Result<Rule, String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let action = parse_rule_action(self.action)?;
        let matcher = self.matcher.compile(&self.id)?;

        Ok(Rule {
            id: self.id,
            priority,
            matcher,
            action,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleMatchConfig {
    #[serde(default)]
    pub dst_cidrs: Vec<String>,
    #[serde(default)]
    pub dst_ips: Vec<String>,
    pub proto: Option<ProtoValue>,
    #[serde(default)]
    pub src_ports: Vec<PortSpec>,
    #[serde(default)]
    pub dst_ports: Vec<PortSpec>,
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

        let tls = self.tls.map(|tls| TlsMatch {
            sni: tls.sni,
            server_dn: tls.server_dn,
            server_san: tls.server_san,
        });

        Ok(RuleMatch {
            dst_ips,
            proto,
            src_ports,
            dst_ports,
            tls,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct TlsMatchConfig {
    pub sni: Option<String>,
    pub server_dn: Option<String>,
    #[serde(default)]
    pub server_san: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PolicyValue {
    String(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ProtoValue {
    String(String),
    Number(u8),
}

#[derive(Debug, Deserialize)]
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
}
