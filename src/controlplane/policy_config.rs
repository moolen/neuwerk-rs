use std::net::Ipv4Addr;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, HttpHeadersMatcher, HttpPathMatcher, HttpQueryMatcher,
    HttpRequestPolicy, HttpResponsePolicy, HttpStringMatcher, IpSetV4, PortRange, Proto, Rule,
    RuleAction, RuleMatch, RuleMode as DataplaneRuleMode, SourceGroup, Tls13Uninspectable,
    TlsInterceptHttpPolicy, TlsMatch, TlsMode, TlsNameMatch,
};
use x509_parser::pem::parse_x509_pem;

#[derive(Debug)]
pub struct CompiledPolicy {
    pub default_policy: Option<DefaultPolicy>,
    pub groups: Vec<SourceGroup>,
    pub dns_policy: DnsPolicy,
    pub kubernetes_bindings: Vec<KubernetesSelectorBinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    Disabled,
    Audit,
    Enforce,
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Enforce
    }
}

impl PolicyMode {
    pub fn is_active(self) -> bool {
        !matches!(self, PolicyMode::Disabled)
    }

    pub fn is_enforcing(self) -> bool {
        matches!(self, PolicyMode::Enforce)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleMode {
    Audit,
    Enforce,
}

impl Default for RuleMode {
    fn default() -> Self {
        RuleMode::Enforce
    }
}

impl From<RuleMode> for DataplaneRuleMode {
    fn from(value: RuleMode) -> Self {
        match value {
            RuleMode::Audit => DataplaneRuleMode::Audit,
            RuleMode::Enforce => DataplaneRuleMode::Enforce,
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
        self.evaluate_with_source_group_for_mode(src_ip, hostname, DataplaneRuleMode::Enforce, true)
    }

    pub fn evaluate_audit_denied_with_source_group(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
    ) -> (bool, Option<String>) {
        let (allowed, group) = self.evaluate_with_source_group_for_mode(
            src_ip,
            hostname,
            DataplaneRuleMode::Audit,
            false,
        );
        (!allowed, group)
    }

    fn evaluate_with_source_group_for_mode(
        &self,
        src_ip: Ipv4Addr,
        hostname: &str,
        mode: DataplaneRuleMode,
        include_group_default_deny: bool,
    ) -> (bool, Option<String>) {
        let hostname = normalize_hostname(hostname);
        for group in &self.groups {
            if !group.sources.contains(src_ip) {
                continue;
            }
            for rule in &group.rules {
                if rule.mode != mode {
                    continue;
                }
                if rule.hostname.is_match(&hostname) {
                    return (rule.action == RuleAction::Allow, Some(group.id.clone()));
                }
            }
            if include_group_default_deny && mode == DataplaneRuleMode::Enforce {
                return (false, Some(group.id.clone()));
            }
        }
        if include_group_default_deny && mode == DataplaneRuleMode::Enforce {
            return (false, None);
        }
        (true, None)
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
    pub mode: DataplaneRuleMode,
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
    fn compile(
        self,
        fallback_priority: u32,
    ) -> Result<(SourceGroup, DnsSourceGroup, Vec<KubernetesSelectorBinding>), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let compiled_sources = self.sources.compile(&self.id)?;
        let sources = compiled_sources.sources;
        let default_action = match self.default_action {
            Some(value) => Some(parse_rule_action(value)?),
            None => None,
        };

        let mut rules = Vec::with_capacity(self.rules.len());
        let mut dns_rules = Vec::with_capacity(self.rules.len());
        for (idx, rule) in self.rules.into_iter().enumerate() {
            let (rule, dns_rule) = rule.compile(idx as u32)?;
            rules.push(rule);
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

        Ok((group, dns_group, compiled_sources.kubernetes_bindings))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesSourceConfig {
    pub integration: String,
    #[serde(default)]
    pub pod_selector: Option<KubernetesPodSelectorConfig>,
    #[serde(default)]
    pub node_selector: Option<KubernetesNodeSelectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesPodSelectorConfig {
    pub namespace: String,
    #[serde(default)]
    pub match_labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: Option<u32>,
    pub action: PolicyValue,
    #[serde(default)]
    pub mode: RuleMode,
    #[serde(rename = "match")]
    pub matcher: RuleMatchConfig,
}

impl RuleConfig {
    fn compile(self, fallback_priority: u32) -> Result<(Rule, Option<DnsRule>), String> {
        let priority = self.priority.unwrap_or(fallback_priority);
        let action = parse_rule_action(self.action)?;
        let mode: DataplaneRuleMode = self.mode.into();
        let dns_rule = compile_dns_rule(
            &self.id,
            priority,
            action,
            mode,
            self.matcher.dns_hostname.as_deref(),
        )?;
        let matcher = self.matcher.compile(&self.id)?;

        let rule = Rule {
            id: self.id,
            priority,
            matcher,
            action,
            mode,
        };

        Ok((rule, dns_rule))
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
    #[serde(default)]
    pub mode: Option<TlsModeValue>,
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
    #[serde(default)]
    pub http: Option<HttpPolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsModeValue {
    Metadata,
    Intercept,
}

impl From<TlsModeValue> for TlsMode {
    fn from(value: TlsModeValue) -> Self {
        match value {
            TlsModeValue::Metadata => TlsMode::Metadata,
            TlsModeValue::Intercept => TlsMode::Intercept,
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpPolicyConfig {
    #[serde(default)]
    pub request: Option<HttpRequestPolicyConfig>,
    #[serde(default)]
    pub response: Option<HttpResponsePolicyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpRequestPolicyConfig {
    #[serde(default)]
    pub host: Option<HttpStringMatcherConfig>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub path: Option<HttpPathMatcherConfig>,
    #[serde(default)]
    pub query: Option<HttpQueryMatcherConfig>,
    #[serde(default)]
    pub headers: Option<HttpHeadersMatcherConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpResponsePolicyConfig {
    #[serde(default)]
    pub headers: Option<HttpHeadersMatcherConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpStringMatcherConfig {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpPathMatcherConfig {
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub prefix: Vec<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpQueryMatcherConfig {
    #[serde(default)]
    pub keys_present: Vec<String>,
    #[serde(default)]
    pub key_values_exact: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub key_values_regex: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpHeadersMatcherConfig {
    #[serde(default)]
    pub require_present: Vec<String>,
    #[serde(default)]
    pub deny_present: Vec<String>,
    #[serde(default)]
    pub exact: std::collections::BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub regex: std::collections::BTreeMap<String, String>,
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
                        .map_err(|err| format!("rule {rule_id}: invalid {field} regex: {err}"))?,
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

impl HttpPolicyConfig {
    fn compile(self, rule_id: &str) -> Result<TlsInterceptHttpPolicy, String> {
        let request = match self.request {
            Some(request) => Some(request.compile(rule_id)?),
            None => None,
        };
        let response = match self.response {
            Some(response) => Some(response.compile(rule_id)?),
            None => None,
        };

        if request.is_none() && response.is_none() {
            return Err(format!(
                "rule {rule_id}: tls.http requires request and/or response constraints"
            ));
        }

        Ok(TlsInterceptHttpPolicy { request, response })
    }
}

impl HttpRequestPolicyConfig {
    fn compile(self, rule_id: &str) -> Result<HttpRequestPolicy, String> {
        let host = match self.host {
            Some(host) => Some(host.compile(rule_id, "tls.http.request.host")?),
            None => None,
        };
        let mut methods = Vec::new();
        for method in self.methods {
            let method = method.trim().to_ascii_uppercase();
            if method.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.methods entries cannot be empty"
                ));
            }
            methods.push(method);
        }
        let path = match self.path {
            Some(path) => Some(path.compile(rule_id)?),
            None => None,
        };
        let query = match self.query {
            Some(query) => Some(query.compile(rule_id)?),
            None => None,
        };
        let headers = match self.headers {
            Some(headers) => Some(headers.compile(rule_id, "tls.http.request.headers")?),
            None => None,
        };

        Ok(HttpRequestPolicy {
            host,
            methods,
            path,
            query,
            headers,
        })
    }
}

impl HttpResponsePolicyConfig {
    fn compile(self, rule_id: &str) -> Result<HttpResponsePolicy, String> {
        let headers = match self.headers {
            Some(headers) => Some(headers.compile(rule_id, "tls.http.response.headers")?),
            None => None,
        };
        Ok(HttpResponsePolicy { headers })
    }
}

impl HttpStringMatcherConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<HttpStringMatcher, String> {
        let mut exact = Vec::new();
        for value in self.exact {
            let value = value.trim().to_ascii_lowercase();
            if !value.is_empty() {
                exact.push(value);
            }
        }
        let regex = compile_optional_regex(self.regex, rule_id, field, true)?;
        if exact.is_empty() && regex.is_none() {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(HttpStringMatcher { exact, regex })
    }
}

impl HttpPathMatcherConfig {
    fn compile(self, rule_id: &str) -> Result<HttpPathMatcher, String> {
        let exact = self
            .exact
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        let prefix = self
            .prefix
            .into_iter()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        let regex = compile_optional_regex(self.regex, rule_id, "tls.http.request.path", false)?;
        if exact.is_empty() && prefix.is_empty() && regex.is_none() {
            return Err(format!(
                "rule {rule_id}: tls.http.request.path matcher cannot be empty"
            ));
        }
        Ok(HttpPathMatcher {
            exact,
            prefix,
            regex,
        })
    }
}

impl HttpQueryMatcherConfig {
    fn compile(self, rule_id: &str) -> Result<HttpQueryMatcher, String> {
        let keys_present = self
            .keys_present
            .into_iter()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();

        let mut key_values_exact = std::collections::BTreeMap::new();
        for (key, values) in self.key_values_exact {
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_exact has empty key"
                ));
            }
            let values = values
                .into_iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_exact[{key}] cannot be empty"
                ));
            }
            key_values_exact.insert(key, values);
        }

        let mut key_values_regex = std::collections::BTreeMap::new();
        for (key, regex) in self.key_values_regex {
            let key = key.trim().to_string();
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: tls.http.request.query.key_values_regex has empty key"
                ));
            }
            let compiled = compile_regex(
                &regex,
                rule_id,
                &format!("tls.http.request.query.key_values_regex[{key}]"),
                false,
            )?;
            key_values_regex.insert(key, compiled);
        }

        if keys_present.is_empty() && key_values_exact.is_empty() && key_values_regex.is_empty() {
            return Err(format!(
                "rule {rule_id}: tls.http.request.query matcher cannot be empty"
            ));
        }
        Ok(HttpQueryMatcher {
            keys_present,
            key_values_exact,
            key_values_regex,
        })
    }
}

impl HttpHeadersMatcherConfig {
    fn compile(self, rule_id: &str, field: &str) -> Result<HttpHeadersMatcher, String> {
        let require_present = self
            .require_present
            .into_iter()
            .map(|key| normalize_header_name(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        let deny_present = self
            .deny_present
            .into_iter()
            .map(|key| normalize_header_name(&key))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();

        let mut exact = std::collections::BTreeMap::new();
        for (key, values) in self.exact {
            let key = normalize_header_name(&key);
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.exact has empty header name"
                ));
            }
            let values = values
                .into_iter()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.exact[{key}] cannot be empty"
                ));
            }
            exact.insert(key, values);
        }

        let mut regex = std::collections::BTreeMap::new();
        for (key, pattern) in self.regex {
            let key = normalize_header_name(&key);
            if key.is_empty() {
                return Err(format!(
                    "rule {rule_id}: {field}.regex has empty header name"
                ));
            }
            let compiled =
                compile_regex(&pattern, rule_id, &format!("{field}.regex[{key}]"), false)?;
            regex.insert(key, compiled);
        }

        if require_present.is_empty()
            && deny_present.is_empty()
            && exact.is_empty()
            && regex.is_empty()
        {
            return Err(format!("rule {rule_id}: {field} matcher cannot be empty"));
        }
        Ok(HttpHeadersMatcher {
            require_present,
            deny_present,
            exact,
            regex,
        })
    }
}

impl TlsMatchConfig {
    fn compile(self, rule_id: &str) -> Result<TlsMatch, String> {
        let mode = self.mode.unwrap_or(TlsModeValue::Metadata).into();

        let sni = match self.sni {
            Some(config) => Some(config.compile(rule_id, "tls.sni")?),
            None => None,
        };

        let server_cn = match (self.server_cn, self.server_dn) {
            (Some(config), _) => Some(config.compile(rule_id, "tls.server_cn")?),
            (None, Some(legacy)) => {
                Some(TlsNameMatchConfig::String(legacy).compile(rule_id, "tls.server_dn")?)
            }
            _ => None,
        };

        let server_san = match self.server_san {
            Some(config) => Some(config.compile(rule_id, "tls.server_san")?),
            None => None,
        };

        let mut fingerprints_sha256 = Vec::with_capacity(self.fingerprint_sha256.len());
        for fp in self.fingerprint_sha256 {
            fingerprints_sha256.push(
                parse_sha256_fingerprint(&fp).map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let mut trust_anchors = Vec::new();
        for pem in self.trust_anchors_pem {
            trust_anchors.extend(
                parse_pem_cert_chain(&pem).map_err(|err| format!("rule {rule_id}: {err}"))?,
            );
        }

        let tls13_uninspectable = self
            .tls13_uninspectable
            .unwrap_or(Tls13UninspectableValue::Deny)
            .into();

        let intercept_http = match self.http {
            Some(http) => Some(http.compile(rule_id)?),
            None => None,
        };

        match mode {
            TlsMode::Metadata => {
                if intercept_http.is_some() {
                    return Err(format!(
                        "rule {rule_id}: tls.http is only valid when tls.mode is intercept"
                    ));
                }
            }
            TlsMode::Intercept => {
                if sni.is_some()
                    || server_cn.is_some()
                    || server_san.is_some()
                    || !fingerprints_sha256.is_empty()
                    || !trust_anchors.is_empty()
                {
                    return Err(format!(
                        "rule {rule_id}: tls.mode intercept cannot be combined with metadata matchers"
                    ));
                }
                if intercept_http.is_none() {
                    return Err(format!(
                        "rule {rule_id}: tls.mode intercept requires tls.http constraints"
                    ));
                }
            }
        }

        Ok(TlsMatch {
            mode,
            sni,
            server_san,
            server_cn,
            fingerprints_sha256,
            trust_anchors,
            tls13_uninspectable,
            intercept_http,
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
    mode: DataplaneRuleMode,
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
        mode,
        hostname: regex,
    }))
}

fn normalize_hostname(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn compile_optional_regex(
    pattern: Option<String>,
    rule_id: &str,
    field: &str,
    case_insensitive: bool,
) -> Result<Option<Regex>, String> {
    match pattern {
        Some(pattern) => Ok(Some(compile_regex(
            &pattern,
            rule_id,
            field,
            case_insensitive,
        )?)),
        None => Ok(None),
    }
}

fn compile_regex(
    pattern: &str,
    rule_id: &str,
    field: &str,
    case_insensitive: bool,
) -> Result<Regex, String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(format!("rule {rule_id}: {field} regex cannot be empty"));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|err| format!("rule {rule_id}: invalid {field} regex: {err}"))
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
