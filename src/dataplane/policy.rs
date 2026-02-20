use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

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

#[derive(Debug, Clone, Default)]
pub struct DynamicIpSetV4 {
    inner: Arc<RwLock<HashSet<Ipv4Addr>>>,
}

impl DynamicIpSetV4 {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn insert(&self, ip: Ipv4Addr) {
        if let Ok(mut lock) = self.inner.write() {
            lock.insert(ip);
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        match self.inner.read() {
            Ok(lock) => lock.contains(&ip),
            Err(_) => false,
        }
    }
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
    pub sni: Option<String>,
    pub server_dn: Option<String>,
    pub server_san: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub dst_ips: Option<IpSetV4>,
    pub proto: Proto,
    pub src_ports: Vec<PortRange>,
    pub dst_ports: Vec<PortRange>,
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

    pub fn evaluate(&self, meta: &PacketMeta) -> RuleAction {
        for group in &self.groups {
            if !group.sources.contains(meta.src_ip) {
                continue;
            }

            for rule in &group.rules {
                if rule_matches(&rule.matcher, meta) {
                    return rule.action;
                }
            }

            if let Some(action) = group.default_action {
                return action;
            }
        }

        match self.default_policy {
            DefaultPolicy::Allow => RuleAction::Allow,
            DefaultPolicy::Deny => RuleAction::Deny,
        }
    }
}

fn rule_matches(matcher: &RuleMatch, meta: &PacketMeta) -> bool {
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

    if matcher.tls.is_some() {
        return false;
    }

    true
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }

    ranges.iter().any(|range| range.contains(port))
}
