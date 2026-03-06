use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use regex::Regex;

use crate::dataplane::tls::normalize_hostname;

use super::IpSetV4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Proto {
    pub fn matches(&self, proto: u8) -> bool {
        match *self {
            Proto::Any => true,
            Proto::Tcp => proto == 6,
            Proto::Udp => proto == 17,
            Proto::Icmp => proto == 1,
            Proto::Other(value) => proto == value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Debug, Clone)]
pub struct TlsMatch {
    pub mode: TlsMode,
    pub sni: Option<TlsNameMatch>,
    pub server_san: Option<TlsNameMatch>,
    pub server_cn: Option<TlsNameMatch>,
    pub fingerprints_sha256: Vec<[u8; 32]>,
    pub trust_anchors: Vec<Vec<u8>>,
    pub tls13_uninspectable: Tls13Uninspectable,
    pub intercept_http: Option<TlsInterceptHttpPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Metadata,
    Intercept,
}

#[derive(Debug, Clone)]
pub struct TlsInterceptHttpPolicy {
    pub request: Option<HttpRequestPolicy>,
    pub response: Option<HttpResponsePolicy>,
}

#[derive(Debug, Clone)]
pub struct HttpRequestPolicy {
    pub host: Option<HttpStringMatcher>,
    pub methods: Vec<String>,
    pub path: Option<HttpPathMatcher>,
    pub query: Option<HttpQueryMatcher>,
    pub headers: Option<HttpHeadersMatcher>,
}

#[derive(Debug, Clone)]
pub struct HttpResponsePolicy {
    pub headers: Option<HttpHeadersMatcher>,
}

#[derive(Debug, Clone)]
pub struct HttpStringMatcher {
    pub exact: Vec<String>,
    pub regex: Option<Regex>,
}

#[derive(Debug, Clone)]
pub struct HttpPathMatcher {
    pub exact: Vec<String>,
    pub prefix: Vec<String>,
    pub regex: Option<Regex>,
}

#[derive(Debug, Clone)]
pub struct HttpQueryMatcher {
    pub keys_present: Vec<String>,
    pub key_values_exact: BTreeMap<String, Vec<String>>,
    pub key_values_regex: BTreeMap<String, Regex>,
}

#[derive(Debug, Clone)]
pub struct HttpHeadersMatcher {
    pub require_present: Vec<String>,
    pub deny_present: Vec<String>,
    pub exact: BTreeMap<String, Vec<String>>,
    pub regex: BTreeMap<String, Regex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13Uninspectable {
    Allow,
    Deny,
}

impl Default for Tls13Uninspectable {
    fn default() -> Self {
        Tls13Uninspectable::Deny
    }
}

#[derive(Debug, Clone)]
pub struct TlsNameMatch {
    pub exact: Vec<String>,
    pub regex: Option<Regex>,
}

impl TlsNameMatch {
    pub fn is_match(&self, value: &str) -> bool {
        let value = normalize_hostname(value);
        if !self.exact.is_empty() && !self.exact.iter().any(|v| v == &value) {
            return false;
        }
        if let Some(regex) = &self.regex {
            return regex.is_match(&value);
        }
        true
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.regex.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
    PendingTls,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub dst_ips: Option<IpSetV4>,
    pub proto: Proto,
    pub src_ports: Vec<PortRange>,
    pub dst_ports: Vec<PortRange>,
    pub icmp_types: Vec<u8>,
    pub icmp_codes: Vec<u8>,
    pub tls: Option<TlsMatch>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub priority: u32,
    pub matcher: RuleMatch,
    pub action: RuleAction,
    pub mode: RuleMode,
}

#[derive(Debug, Clone)]
pub struct SourceGroup {
    pub id: String,
    pub priority: u32,
    pub sources: IpSetV4,
    pub rules: Vec<Rule>,
    pub default_action: Option<RuleAction>,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub default_policy: DefaultPolicy,
    pub groups: Vec<SourceGroup>,
    pub generation: u64,
    pub enforcement_mode: EnforcementMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy)]
pub struct PacketMeta {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
}

impl PolicySnapshot {
    pub fn new(default_policy: DefaultPolicy, groups: Vec<SourceGroup>) -> Self {
        Self::new_with_generation(default_policy, groups, 0)
    }

    pub fn new_with_generation(
        default_policy: DefaultPolicy,
        mut groups: Vec<SourceGroup>,
        generation: u64,
    ) -> Self {
        groups.sort_by_key(|group| group.priority);
        for group in &mut groups {
            group.rules.sort_by_key(|rule| rule.priority);
        }
        Self {
            default_policy,
            groups,
            generation,
            enforcement_mode: EnforcementMode::Enforce,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn enforcement_mode(&self) -> EnforcementMode {
        self.enforcement_mode
    }

    pub fn set_enforcement_mode(&mut self, mode: EnforcementMode) {
        self.enforcement_mode = mode;
    }

    pub fn audit_passthrough_enabled(&self) -> bool {
        self.enforcement_mode == EnforcementMode::Audit
    }
}
