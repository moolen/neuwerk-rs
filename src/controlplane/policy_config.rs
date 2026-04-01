use std::net::Ipv4Addr;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::ToSchema;

use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, HttpHeadersMatcher, HttpPathMatcher, HttpQueryMatcher,
    HttpRequestPolicy, HttpResponsePolicy, HttpStringMatcher, IpSetV4, PortRange, Proto, Rule,
    RuleAction, RuleMatch, RuleMode as DataplaneRuleMode, SourceGroup, Tls13Uninspectable,
    TlsInterceptHttpPolicy, TlsMatch, TlsMode, TlsNameMatch,
};
use crate::dataplane::tls::normalize_distinguished_name;
use x509_parser::pem::parse_x509_pem;

mod parse;
use parse::*;

#[derive(Debug)]
pub struct CompiledPolicy {
    pub default_policy: Option<DefaultPolicy>,
    pub groups: Vec<SourceGroup>,
    pub dns_policy: DnsPolicy,
    pub kubernetes_bindings: Vec<KubernetesSelectorBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Disabled,
    Audit,
    #[default]
    Enforce,
}

impl PolicyMode {
    pub fn is_active(self) -> bool {
        !matches!(self, PolicyMode::Disabled)
    }

    pub fn is_enforcing(self) -> bool {
        matches!(self, PolicyMode::Enforce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Audit,
    #[default]
    Enforce,
}

impl From<RuleMode> for DataplaneRuleMode {
    fn from(value: RuleMode) -> Self {
        match value {
            RuleMode::Audit => DataplaneRuleMode::Audit,
            RuleMode::Enforce => DataplaneRuleMode::Enforce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MatchModeValue {
    Audit,
    Enforce,
}

impl From<MatchModeValue> for DataplaneRuleMode {
    fn from(value: MatchModeValue) -> Self {
        match value {
            MatchModeValue::Audit => DataplaneRuleMode::Audit,
            MatchModeValue::Enforce => DataplaneRuleMode::Enforce,
        }
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
        let (effective_allowed, _, group) =
            self.evaluate_with_source_group_effective_and_raw(src_ip, hostname);
        (effective_allowed, group)
    }

    pub fn evaluate_with_source_group_effective_and_raw(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
    ) -> (bool, bool, Option<String>) {
        let (allowed, mode, group) =
            self.evaluate_with_source_group_raw(src_ip, hostname, None, true);
        let effective_allowed = if !allowed && mode == Some(DataplaneRuleMode::Audit) {
            true
        } else {
            allowed
        };
        (effective_allowed, allowed, group)
    }

    pub fn evaluate_audit_denied_with_source_group(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
    ) -> (bool, Option<String>) {
        let (allowed, _, group) = self.evaluate_with_source_group_raw(
            src_ip,
            hostname,
            Some(DataplaneRuleMode::Audit),
            false,
        );
        (!allowed, group)
    }

    fn evaluate_with_source_group_raw(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
        mode_filter: Option<DataplaneRuleMode>,
        include_group_default_deny: bool,
    ) -> (bool, Option<DataplaneRuleMode>, Option<String>) {
        let hostname = normalize_hostname(hostname);
        for group in &self.groups {
            if !group.sources.contains(src_ip) {
                continue;
            }
            for rule in &group.rules {
                if mode_filter.is_some() && mode_filter != Some(rule.mode) {
                    continue;
                }
                if rule.hostname.is_match(&hostname) {
                    return (
                        rule.action == RuleAction::Allow,
                        Some(rule.mode),
                        Some(group.id.clone()),
                    );
                }
            }
            if include_group_default_deny {
                return (false, Some(group.mode), Some(group.id.clone()));
            }
        }
        if include_group_default_deny {
            return (false, None, None);
        }
        (true, None, None)
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
    pub mode: DataplaneRuleMode,
    pub sources: IpSetV4,
    pub rules: Vec<DnsRule>,
}

#[derive(Debug, Clone)]
pub struct DnsRule {
    pub id: String,
    pub priority: u32,
    pub action: RuleAction,
    pub mode: DataplaneRuleMode,
    pub hostname: Regex,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PolicyConfig {
    pub default_policy: Option<PolicyValue>,
    #[serde(default)]
    pub source_groups: Vec<SourceGroupConfig>,
}

impl<'de> Deserialize<'de> for PolicyConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPolicyConfig {
            default_policy: Option<PolicyValue>,
            #[serde(default)]
            source_groups: Vec<SourceGroupConfig>,
            #[serde(default)]
            mode: Option<serde::de::IgnoredAny>,
        }

        let raw = RawPolicyConfig::deserialize(deserializer)?;
        if raw.mode.is_some() {
            return Err(serde::de::Error::custom(
                "top-level policy mode is no longer supported",
            ));
        }

        Ok(Self {
            default_policy: raw.default_policy,
            source_groups: raw.source_groups,
        })
    }
}

impl PolicyConfig {
    pub fn compile(self) -> Result<CompiledPolicy, String> {
        let default_policy = match self.default_policy {
            Some(value) => Some(parse_default_policy(value)?),
            None => None,
        };

        let mut groups = Vec::with_capacity(self.source_groups.len());
        let mut dns_groups = Vec::with_capacity(self.source_groups.len());
        let mut kubernetes_bindings = Vec::new();
        for (idx, group) in self.source_groups.into_iter().enumerate() {
            let (group, dns_group, mut group_bindings) = group.compile(idx as u32)?;
            groups.push(group);
            dns_groups.push(dns_group);
            kubernetes_bindings.append(&mut group_bindings);
        }

        Ok(CompiledPolicy {
            default_policy,
            groups,
            dns_policy: DnsPolicy::new(dns_groups),
            kubernetes_bindings,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KubernetesSourceSelector {
    Pod {
        namespace: String,
        match_labels: std::collections::BTreeMap<String, String>,
    },
    Node {
        match_labels: std::collections::BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone)]
pub struct KubernetesSelectorBinding {
    pub source_group_id: String,
    pub integration: String,
    pub selector: KubernetesSourceSelector,
    pub dynamic_set: DynamicIpSetV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourceGroupConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub mode: MatchModeValue,
    pub sources: SourcesConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    pub default_action: Option<PolicyValue>,
}

impl SourceGroupConfig {
    fn compile(
        self,
        fallback_priority: u32,
    ) -> Result<(SourceGroup, DnsSourceGroup, Vec<KubernetesSelectorBinding>), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let group_mode: DataplaneRuleMode = self.mode.into();
        let compiled_sources = self.sources.compile(&self.id)?;
        let sources = compiled_sources.sources;
        let default_action = match self.default_action {
            Some(value) => Some(parse_rule_action(value)?),
            None => None,
        };

        let mut rules = Vec::with_capacity(self.rules.len());
        let mut dns_rules = Vec::with_capacity(self.rules.len());
        for (idx, rule) in self.rules.into_iter().enumerate() {
            let (rule, dns_rule) = rule.compile(idx as u32, group_mode)?;
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
            mode: group_mode,
            sources: sources.clone(),
            rules,
            default_action,
        };

        let dns_group = DnsSourceGroup {
            id: self.id,
            priority,
            mode: group_mode,
            sources,
            rules: dns_rules,
        };

        Ok((group, dns_group, compiled_sources.kubernetes_bindings))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SourcesConfig {
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
    #[serde(default)]
    pub kubernetes: Vec<KubernetesSourceConfig>,
}

impl SourcesConfig {
    fn compile(self, group_id: &str) -> Result<CompiledSourcesConfig, String> {
        let dynamic_set = if self.kubernetes.is_empty() {
            None
        } else {
            Some(DynamicIpSetV4::new())
        };
        let mut sources = match dynamic_set.clone() {
            Some(dynamic) => IpSetV4::with_dynamic(dynamic),
            None => IpSetV4::new(),
        };
        let mut kubernetes_bindings = Vec::with_capacity(self.kubernetes.len());

        for cidr in self.cidrs {
            let cidr = parse_cidr_v4(&cidr).map_err(|err| format!("group {group_id}: {err}"))?;
            sources.add_cidr(cidr);
        }

        for ip in self.ips {
            let ip = parse_ipv4(&ip).map_err(|err| format!("group {group_id}: {err}"))?;
            sources.add_ip(ip);
        }

        if let Some(dynamic) = dynamic_set {
            for source in self.kubernetes {
                let binding = source.compile(group_id, dynamic.clone())?;
                kubernetes_bindings.push(binding);
            }
        }

        if sources.is_empty() {
            return Err(format!("group {group_id}: sources cannot be empty"));
        }

        Ok(CompiledSourcesConfig {
            sources,
            kubernetes_bindings,
        })
    }
}

#[derive(Debug, Clone)]
struct CompiledSourcesConfig {
    sources: IpSetV4,
    kubernetes_bindings: Vec<KubernetesSelectorBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KubernetesSourceConfig {
    pub integration: String,
    #[serde(default)]
    pub pod_selector: Option<KubernetesPodSelectorConfig>,
    #[serde(default)]
    pub node_selector: Option<KubernetesNodeSelectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KubernetesPodSelectorConfig {
    pub namespace: String,
    #[serde(default)]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KubernetesNodeSelectorConfig {
    #[serde(default)]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

impl KubernetesSourceConfig {
    fn compile(
        self,
        group_id: &str,
        dynamic_set: DynamicIpSetV4,
    ) -> Result<KubernetesSelectorBinding, String> {
        let integration = self.integration.trim().to_string();
        if integration.is_empty() {
            return Err(format!(
                "group {group_id}: kubernetes source integration is required"
            ));
        }

        let selector = match (self.pod_selector, self.node_selector) {
            (Some(pod), None) => {
                let namespace = pod.namespace.trim().to_string();
                if namespace.is_empty() {
                    return Err(format!(
                        "group {group_id}: kubernetes pod_selector.namespace is required"
                    ));
                }
                let labels = normalize_match_labels(pod.match_labels, group_id, "pod_selector")?;
                KubernetesSourceSelector::Pod {
                    namespace,
                    match_labels: labels,
                }
            }
            (None, Some(node)) => {
                let labels =
                    normalize_match_labels(node.match_labels, group_id, "node_selector")?;
                KubernetesSourceSelector::Node {
                    match_labels: labels,
                }
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "group {group_id}: kubernetes source must set exactly one of pod_selector or node_selector"
                ))
            }
            (None, None) => {
                return Err(format!(
                    "group {group_id}: kubernetes source must set pod_selector or node_selector"
                ))
            }
        };

        Ok(KubernetesSelectorBinding {
            source_group_id: group_id.to_string(),
            integration,
            selector,
            dynamic_set,
        })
    }
}

fn normalize_match_labels(
    labels: std::collections::BTreeMap<String, String>,
    group_id: &str,
    field: &str,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut out = std::collections::BTreeMap::new();
    for (key, value) in labels {
        let key = key.trim().to_string();
        let value = value.trim().to_string();
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "group {group_id}: kubernetes {field}.match_labels entries must have non-empty key and value"
            ));
        }
        out.insert(key, value);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RuleConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub action: PolicyValue,
    #[serde(default)]
    pub mode: Option<MatchModeValue>,
    #[serde(rename = "match")]
    pub matcher: RuleMatchConfig,
}

impl RuleConfig {
    fn compile(
        self,
        fallback_priority: u32,
        group_mode: DataplaneRuleMode,
    ) -> Result<(Option<Rule>, Option<DnsRule>), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let action = parse_rule_action(self.action)?;
        let mode = self.mode.map(Into::into).unwrap_or(group_mode);
        let dns_rule = compile_dns_rule(
            &self.id,
            priority,
            action,
            mode,
            self.matcher.dns_hostname.as_deref(),
        )?;
        let matcher = self.matcher.compile(&self.id)?;

        let rule = if dns_rule.is_some()
            && matcher.dst_ips.is_none()
            && matches!(matcher.proto, Proto::Any)
            && matcher.src_ports.is_empty()
            && matcher.dst_ports.is_empty()
            && matcher.icmp_types.is_empty()
            && matcher.icmp_codes.is_empty()
            && matcher.tls.is_none()
        {
            None
        } else {
            Some(Rule {
                id: self.id,
                priority,
                matcher,
                action,
                mode,
            })
        };

        Ok((rule, dns_rule))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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

include!("policy_config/tls_http.rs");
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PolicyValue {
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum ProtoValue {
    String(String),
    Number(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum PortSpec {
    Number(u16),
    String(String),
}

#[cfg(test)]
mod tests;
