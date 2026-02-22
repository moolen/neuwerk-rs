use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use regex::Regex;

use crate::dataplane::tls::{normalize_hostname, TlsObservation, TlsVerifier};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrV4 {
    addr: Ipv4Addr,
    prefix: u8,
    mask: u32,
    net: u32,
}

impl CidrV4 {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        let net = u32::from(addr) & mask;
        Self {
            addr,
            prefix,
            mask,
            net,
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let addr = u32::from(ip) & self.mask;
        addr == self.net
    }
}

#[derive(Debug, Clone, Copy)]
struct DynamicIpEntry {
    last_seen: u64,
    active_flows: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicIpSetV4 {
    inner: Arc<RwLock<HashMap<Ipv4Addr, DynamicIpEntry>>>,
}

impl DynamicIpSetV4 {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, ip: Ipv4Addr) {
        self.insert_at(ip, now_secs());
    }

    pub fn insert_many<I>(&self, ips: I)
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        let now = now_secs();
        if let Ok(mut lock) = self.inner.write() {
            for ip in ips {
                lock.entry(ip)
                    .and_modify(|entry| {
                        entry.last_seen = entry.last_seen.max(now);
                    })
                    .or_insert(DynamicIpEntry {
                        last_seen: now,
                        active_flows: 0,
                    });
            }
        }
    }

    pub fn insert_at(&self, ip: Ipv4Addr, now: u64) {
        if let Ok(mut lock) = self.inner.write() {
            lock.entry(ip)
                .and_modify(|entry| {
                    entry.last_seen = entry.last_seen.max(now);
                })
                .or_insert(DynamicIpEntry {
                    last_seen: now,
                    active_flows: 0,
                });
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        match self.inner.read() {
            Ok(lock) => lock.contains_key(&ip),
            Err(_) => false,
        }
    }

    pub fn flow_open(&self, ip: Ipv4Addr, now: u64) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(entry) = lock.get_mut(&ip) {
                entry.last_seen = entry.last_seen.max(now);
                entry.active_flows = entry.active_flows.saturating_add(1);
            }
        }
    }

    pub fn flow_close(&self, ip: Ipv4Addr, last_seen: u64) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(entry) = lock.get_mut(&ip) {
                entry.last_seen = entry.last_seen.max(last_seen);
                entry.active_flows = entry.active_flows.saturating_sub(1);
            }
        }
    }

    pub fn evict_idle(&self, now: u64, idle_timeout_secs: u64) -> usize {
        match self.inner.write() {
            Ok(mut lock) => {
                let before = lock.len();
                lock.retain(|_, entry| {
                    if entry.active_flows > 0 {
                        return true;
                    }
                    now.saturating_sub(entry.last_seen) <= idle_timeout_secs
                });
                before - lock.len()
            }
            Err(_) => 0,
        }
    }

    pub fn len(&self) -> usize {
        match self.inner.read() {
            Ok(lock) => lock.len(),
            Err(_) => 0,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Default)]
pub struct IpSetV4 {
    cidrs: Vec<CidrV4>,
    dynamic: Option<DynamicIpSetV4>,
}

impl IpSetV4 {
    pub fn new() -> Self {
        Self {
            cidrs: Vec::new(),
            dynamic: None,
        }
    }

    pub fn with_dynamic(dynamic: DynamicIpSetV4) -> Self {
        Self {
            cidrs: Vec::new(),
            dynamic: Some(dynamic),
        }
    }

    pub fn set_dynamic(&mut self, dynamic: DynamicIpSetV4) {
        self.dynamic = Some(dynamic);
    }

    pub fn add_cidr(&mut self, cidr: CidrV4) {
        self.cidrs.push(cidr);
    }

    pub fn add_ip(&mut self, ip: Ipv4Addr) {
        self.cidrs.push(CidrV4::new(ip, 32));
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.dynamic.is_none()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if let Some(dynamic) = &self.dynamic {
            if dynamic.contains(ip) {
                return true;
            }
        }
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

#[derive(Debug, Clone)]
pub struct TlsMatch {
    pub sni: Option<TlsNameMatch>,
    pub server_san: Option<TlsNameMatch>,
    pub server_cn: Option<TlsNameMatch>,
    pub fingerprints_sha256: Vec<[u8; 32]>,
    pub trust_anchors: Vec<Vec<u8>>,
    pub tls13_uninspectable: Tls13Uninspectable,
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
    pub fn new(default_policy: DefaultPolicy, mut groups: Vec<SourceGroup>) -> Self {
        groups.sort_by_key(|group| group.priority);
        for group in &mut groups {
            group.rules.sort_by_key(|rule| rule.priority);
        }
        Self {
            default_policy,
            groups,
        }
    }

    pub fn evaluate(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> PolicyDecision {
        self.evaluate_with_source_group(meta, tls, verifier).0
    }

    pub fn evaluate_with_source_group(
        &self,
        meta: &PacketMeta,
        tls: Option<&TlsObservation>,
        verifier: Option<&TlsVerifier>,
    ) -> (PolicyDecision, Option<String>) {
        for group in &self.groups {
            if !group.sources.contains(meta.src_ip) {
                continue;
            }

            for rule in &group.rules {
                if !rule_matches_basic(&rule.matcher, meta) {
                    continue;
                }
                if let Some(tls_match) = &rule.matcher.tls {
                    if meta.proto != 6 {
                        continue;
                    }
                    let Some(obs) = tls else {
                        return (PolicyDecision::PendingTls, Some(group.id.clone()));
                    };
                    let Some(verifier) = verifier else {
                        return (PolicyDecision::Deny, Some(group.id.clone()));
                    };
                    match tls_match.evaluate(obs, verifier) {
                        TlsMatchOutcome::Match => {
                            return (
                                match rule.action {
                                    RuleAction::Allow => PolicyDecision::Allow,
                                    RuleAction::Deny => PolicyDecision::Deny,
                                },
                                Some(group.id.clone()),
                            );
                        }
                        TlsMatchOutcome::Mismatch => continue,
                        TlsMatchOutcome::Pending => {
                            return (PolicyDecision::PendingTls, Some(group.id.clone()))
                        }
                        TlsMatchOutcome::Deny => {
                            return (PolicyDecision::Deny, Some(group.id.clone()))
                        }
                    }
                } else {
                    return (
                        match rule.action {
                            RuleAction::Allow => PolicyDecision::Allow,
                            RuleAction::Deny => PolicyDecision::Deny,
                        },
                        Some(group.id.clone()),
                    );
                }
            }

            if let Some(action) = group.default_action {
                return (
                    match action {
                        RuleAction::Allow => PolicyDecision::Allow,
                        RuleAction::Deny => PolicyDecision::Deny,
                    },
                    Some(group.id.clone()),
                );
            }
        }

        (
            match self.default_policy {
                DefaultPolicy::Allow => PolicyDecision::Allow,
                DefaultPolicy::Deny => PolicyDecision::Deny,
            },
            None,
        )
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        self.groups.iter().any(|group| group.sources.contains(ip))
    }
}

fn rule_matches_basic(matcher: &RuleMatch, meta: &PacketMeta) -> bool {
    if let Some(dst_ips) = &matcher.dst_ips {
        if !dst_ips.contains(meta.dst_ip) {
            return false;
        }
    }

    if !matcher.proto.matches(meta.proto) {
        return false;
    }

    if !port_matches(&matcher.src_ports, meta.src_port) {
        return false;
    }

    if !port_matches(&matcher.dst_ports, meta.dst_port) {
        return false;
    }

    if !matcher.icmp_types.is_empty() || !matcher.icmp_codes.is_empty() {
        let Some(icmp_type) = meta.icmp_type else {
            return false;
        };
        if !matcher.icmp_types.is_empty() && !matcher.icmp_types.contains(&icmp_type) {
            return false;
        }
        if let Some(icmp_code) = meta.icmp_code {
            if !matcher.icmp_codes.is_empty() && !matcher.icmp_codes.contains(&icmp_code) {
                return false;
            }
        } else if !matcher.icmp_codes.is_empty() {
            return false;
        }
    }

    true
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }

    ranges.iter().any(|range| range.contains(port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsMatchOutcome {
    Match,
    Mismatch,
    Pending,
    Deny,
}

impl TlsMatch {
    fn evaluate(&self, obs: &TlsObservation, verifier: &TlsVerifier) -> TlsMatchOutcome {
        if let Some(sni) = &self.sni {
            if !obs.client_hello_seen {
                return TlsMatchOutcome::Pending;
            }
            match obs.sni.as_deref() {
                Some(value) if sni.is_match(value) => {}
                _ => return TlsMatchOutcome::Mismatch,
            }
        }

        let needs_cert = self.requires_certificate();
        if needs_cert {
            if obs.tls13 {
                return match self.tls13_uninspectable {
                    Tls13Uninspectable::Allow => TlsMatchOutcome::Match,
                    Tls13Uninspectable::Deny => TlsMatchOutcome::Deny,
                };
            }

            if !obs.certificate_seen {
                return TlsMatchOutcome::Pending;
            }

            let Some(chain) = &obs.cert_chain else {
                return TlsMatchOutcome::Deny;
            };

            if !verifier.verify_chain(chain, &self.trust_anchors) {
                return TlsMatchOutcome::Deny;
            }

            if let Some(server_san) = &self.server_san {
                if !chain.leaf_san.iter().any(|value| server_san.is_match(value)) {
                    return TlsMatchOutcome::Mismatch;
                }
            }

            if let Some(server_cn) = &self.server_cn {
                if !chain.leaf_cn.iter().any(|value| server_cn.is_match(value)) {
                    return TlsMatchOutcome::Mismatch;
                }
            }

            if !self.fingerprints_sha256.is_empty()
                && !self
                    .fingerprints_sha256
                    .iter()
                    .any(|fp| fp == &chain.leaf_fingerprint)
            {
                return TlsMatchOutcome::Mismatch;
            }
        }

        TlsMatchOutcome::Match
    }

    fn requires_certificate(&self) -> bool {
        self.server_san.is_some()
            || self.server_cn.is_some()
            || !self.fingerprints_sha256.is_empty()
            || !self.trust_anchors.is_empty()
    }
}

#[cfg(test)]
mod tests {
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
        group_a.sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

        let mut group_b = SourceGroup {
            id: "b".to_string(),
            priority: 1,
            sources: IpSetV4::new(),
            rules: Vec::new(),
            default_action: None,
        };
        group_b.sources.add_cidr(CidrV4::new(Ipv4Addr::new(192, 168, 1, 0), 24));

        let snapshot = PolicySnapshot::new(DefaultPolicy::Deny, vec![group_a, group_b]);
        assert!(snapshot.is_internal(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(snapshot.is_internal(Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!snapshot.is_internal(Ipv4Addr::new(203, 0, 113, 5)));
    }
}
