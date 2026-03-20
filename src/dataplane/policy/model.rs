use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use regex::Regex;

use crate::dataplane::tls::normalize_hostname;

use super::{CidrV4, DynamicIpSetV4, IpSetV4};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tls13Uninspectable {
    Allow,
    #[default]
    Deny,
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
    has_audit_rules: bool,
    audit_group_indices: Box<[usize]>,
    group_has_audit_rules: Box<[bool]>,
    internal_exact_sources: Box<[u32]>,
    internal_static_sources: Box<[CidrV4]>,
    internal_dynamic_sources: Box<[DynamicIpSetV4]>,
    compiled_group_id_arcs: Vec<Arc<str>>,
    compiled_groups: Vec<CompiledSourceGroup>,
}

#[derive(Debug, Clone, Default)]
pub struct ExactSourceGroupIndex {
    generation: Option<u64>,
    candidates: Option<SortedExactIpv4Index>,
    fallback_group_indices: Option<Box<[usize]>>,
}

pub type SharedExactSourceGroupIndex = Arc<ArcSwap<ExactSourceGroupIndex>>;
pub type SharedPolicySnapshot = Arc<ArcSwap<PolicySnapshot>>;
type CompiledInternalSourceSets = (Box<[u32]>, Box<[CidrV4]>, Box<[DynamicIpSetV4]>);

const EXACT_SOURCE_GROUP_INDEX_MAX_BUCKET_LEN: usize = 4;

#[derive(Debug, Clone, Default)]
struct CompiledSourceGroup {
    enforce: CompiledModeIndex,
    audit: CompiledModeIndex,
}

#[derive(Debug, Clone, Default)]
struct CompiledModeIndex {
    tcp: CompiledRuleBucket,
    udp: CompiledRuleBucket,
    icmp: CompiledRuleBucket,
    any_other: CompiledRuleBucket,
    other: HashMap<u8, CompiledRuleBucket>,
}

#[derive(Debug, Clone, Default)]
struct CompiledRuleBucket {
    all: Box<[usize]>,
    fallback: Box<[usize]>,
    exact_dst: SortedExactIpv4Index,
}

#[derive(Debug, Clone, Default)]
struct SortedExactIpv4Index {
    entries: Box<[(u32, Box<[usize]>)]>,
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
        let mut has_audit_rules = false;
        let mut audit_group_indices = Vec::new();
        let mut group_has_audit_rules = Vec::with_capacity(groups.len());
        for (group_idx, group) in groups.iter().enumerate() {
            let group_has_audit = group.rules.iter().any(|rule| rule.mode == RuleMode::Audit);
            has_audit_rules |= group_has_audit;
            group_has_audit_rules.push(group_has_audit);
            if group_has_audit {
                audit_group_indices.push(group_idx);
            }
        }
        let compiled_group_id_arcs = groups
            .iter()
            .map(|group| Arc::<str>::from(group.id.as_str()))
            .collect();
        let compiled_groups = groups.iter().map(CompiledSourceGroup::new).collect();
        let (internal_exact_sources, internal_static_sources, internal_dynamic_sources) =
            compile_internal_source_sets(&groups);
        Self {
            default_policy,
            groups,
            generation,
            enforcement_mode: EnforcementMode::Enforce,
            has_audit_rules,
            audit_group_indices: audit_group_indices.into_boxed_slice(),
            group_has_audit_rules: group_has_audit_rules.into_boxed_slice(),
            internal_exact_sources,
            internal_static_sources,
            internal_dynamic_sources,
            compiled_group_id_arcs,
            compiled_groups,
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

    #[inline(always)]
    pub(crate) fn has_audit_rules(&self) -> bool {
        self.has_audit_rules
    }

    #[inline(always)]
    pub(crate) fn audit_group_indices(&self) -> &[usize] {
        self.audit_group_indices.as_ref()
    }

    #[inline(always)]
    pub(crate) fn group_has_audit_rules(&self, group_idx: usize) -> bool {
        self.group_has_audit_rules
            .get(group_idx)
            .copied()
            .unwrap_or(false)
    }

    #[inline(always)]
    pub(crate) fn internal_static_sources(&self) -> &[CidrV4] {
        self.internal_static_sources.as_ref()
    }

    #[inline(always)]
    pub(crate) fn contains_internal_exact_source(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        self.internal_exact_sources.binary_search(&ip).is_ok()
    }

    #[inline(always)]
    pub(crate) fn internal_dynamic_sources(&self) -> &[DynamicIpSetV4] {
        self.internal_dynamic_sources.as_ref()
    }

    #[inline(always)]
    pub(crate) fn candidate_rule_indices_for_group(
        &self,
        group_idx: usize,
        mode: RuleMode,
        proto: u8,
        dst_ip: Ipv4Addr,
    ) -> Option<&[usize]> {
        self.compiled_groups
            .get(group_idx)
            .map(|group| group.for_mode(mode).candidate_rule_indices(proto, dst_ip))
    }

    #[inline(always)]
    pub(crate) fn group_id_arc(&self, group_idx: usize) -> Option<Arc<str>> {
        self.compiled_group_id_arcs.get(group_idx).cloned()
    }
}

impl ExactSourceGroupIndex {
    pub fn for_snapshot(snapshot: &PolicySnapshot) -> Self {
        let compiled = compile_exact_source_group_candidates(&snapshot.groups);
        Self {
            generation: Some(snapshot.generation()),
            candidates: compiled.as_ref().map(|index| index.candidates.clone()),
            fallback_group_indices: compiled.and_then(|index| index.fallback_group_indices),
        }
    }

    #[inline(always)]
    pub(crate) fn matches_generation(&self, generation: u64) -> bool {
        self.generation == Some(generation)
    }

    #[inline(always)]
    pub(crate) fn has_candidates(&self) -> bool {
        self.candidates.is_some() || self.fallback_group_indices.is_some()
    }

    #[inline(always)]
    pub(crate) fn group_indices(&self, src_ip: Ipv4Addr) -> Option<&[usize]> {
        self.candidates
            .as_ref()
            .and_then(|groups| groups.get(src_ip))
    }

    #[inline(always)]
    pub(crate) fn fallback_group_indices(&self) -> Option<&[usize]> {
        self.fallback_group_indices.as_deref()
    }
}

pub fn new_shared_exact_source_group_index(
    snapshot: &PolicySnapshot,
) -> SharedExactSourceGroupIndex {
    Arc::new(ArcSwap::from_pointee(ExactSourceGroupIndex::for_snapshot(
        snapshot,
    )))
}

impl CompiledSourceGroup {
    fn new(group: &SourceGroup) -> Self {
        Self {
            enforce: CompiledModeIndex::new(group, RuleMode::Enforce),
            audit: CompiledModeIndex::new(group, RuleMode::Audit),
        }
    }

    fn for_mode(&self, mode: RuleMode) -> &CompiledModeIndex {
        match mode {
            RuleMode::Enforce => &self.enforce,
            RuleMode::Audit => &self.audit,
        }
    }
}

impl SortedExactIpv4Index {
    fn from_map(entries: HashMap<Ipv4Addr, Vec<usize>>) -> Self {
        let mut entries = entries
            .into_iter()
            .map(|(ip, indices)| (u32::from(ip), indices.into_boxed_slice()))
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|(ip, _)| *ip);
        Self {
            entries: entries.into_boxed_slice(),
        }
    }

    #[inline(always)]
    fn get(&self, ip: Ipv4Addr) -> Option<&[usize]> {
        let ip = u32::from(ip);
        self.entries
            .binary_search_by_key(&ip, |(entry_ip, _)| *entry_ip)
            .ok()
            .map(|idx| self.entries[idx].1.as_ref())
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CompiledModeIndex {
    fn new(group: &SourceGroup, mode: RuleMode) -> Self {
        let tcp = CompiledRuleBucket::new(group, collect_matching_rule_indices(group, mode, 6));
        let udp = CompiledRuleBucket::new(group, collect_matching_rule_indices(group, mode, 17));
        let icmp = CompiledRuleBucket::new(group, collect_matching_rule_indices(group, mode, 1));
        let any_other = CompiledRuleBucket::new(group, collect_any_other_rule_indices(group, mode));

        let mut other = HashMap::new();
        for proto in collect_other_protocols(group, mode) {
            other.insert(
                proto,
                CompiledRuleBucket::new(group, collect_matching_rule_indices(group, mode, proto)),
            );
        }

        Self {
            tcp,
            udp,
            icmp,
            any_other,
            other,
        }
    }

    fn candidate_rule_indices(&self, proto: u8, dst_ip: Ipv4Addr) -> &[usize] {
        match proto {
            6 => self.tcp.candidate_rule_indices(dst_ip),
            17 => self.udp.candidate_rule_indices(dst_ip),
            1 => self.icmp.candidate_rule_indices(dst_ip),
            _ => self
                .other
                .get(&proto)
                .unwrap_or(&self.any_other)
                .candidate_rule_indices(dst_ip),
        }
    }
}

impl CompiledRuleBucket {
    fn new(group: &SourceGroup, all: Vec<usize>) -> Self {
        if all.is_empty() {
            return Self::default();
        }

        let classifications = all
            .iter()
            .copied()
            .map(|idx| {
                (
                    idx,
                    group
                        .rules
                        .get(idx)
                        .map(|rule| classify_destination_match(&rule.matcher)),
                )
            })
            .collect::<Vec<_>>();

        let exact_ips = collect_exact_destination_ips(&classifications);
        let fallback = classifications
            .iter()
            .filter_map(|(idx, class)| match class {
                Some(DestinationMatchClass::General) => Some(*idx),
                _ => None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        let mut exact_dst = HashMap::with_capacity(exact_ips.len());
        for ip in exact_ips {
            let matching = classifications
                .iter()
                .filter_map(|(idx, class)| match class {
                    Some(DestinationMatchClass::General) => Some(*idx),
                    Some(DestinationMatchClass::Exact(ips)) if ips.contains(&ip) => Some(*idx),
                    _ => None,
                })
                .collect::<Vec<_>>();
            exact_dst.insert(ip, matching);
        }

        Self {
            all: all.into_boxed_slice(),
            fallback,
            exact_dst: SortedExactIpv4Index::from_map(exact_dst),
        }
    }

    fn candidate_rule_indices(&self, dst_ip: Ipv4Addr) -> &[usize] {
        if self.exact_dst.is_empty() {
            return &self.all;
        }
        self.exact_dst.get(dst_ip).unwrap_or(&self.fallback)
    }
}

fn collect_matching_rule_indices(group: &SourceGroup, mode: RuleMode, proto: u8) -> Vec<usize> {
    group
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.mode == mode && rule.matcher.proto.matches(proto))
        .map(|(idx, _)| idx)
        .collect()
}

#[derive(Debug, Clone)]
struct CompiledExactSourceGroupIndex {
    candidates: SortedExactIpv4Index,
    fallback_group_indices: Option<Box<[usize]>>,
}

fn compile_exact_source_group_candidates(
    groups: &[SourceGroup],
) -> Option<CompiledExactSourceGroupIndex> {
    let mut candidates = HashMap::<Ipv4Addr, Vec<usize>>::new();
    let mut fallback_group_indices = Vec::new();
    let mut has_any = false;

    for (group_idx, group) in groups.iter().enumerate() {
        match exact_source_ips(&group.sources) {
            Some(exact_ips) => {
                if !exact_ips.is_empty() {
                    has_any = true;
                }
                for ip in exact_ips {
                    candidates.entry(ip).or_default().push(group_idx);
                }
            }
            None => fallback_group_indices.push(group_idx),
        }
    }

    let max_bucket_len = candidates.values().map(Vec::len).max().unwrap_or(0);
    (has_any && max_bucket_len <= EXACT_SOURCE_GROUP_INDEX_MAX_BUCKET_LEN).then(|| {
        CompiledExactSourceGroupIndex {
            candidates: SortedExactIpv4Index::from_map(candidates),
            fallback_group_indices: (!fallback_group_indices.is_empty())
                .then(|| fallback_group_indices.into_boxed_slice()),
        }
    })
}

fn compile_internal_source_sets(groups: &[SourceGroup]) -> CompiledInternalSourceSets {
    let mut static_seen = HashSet::new();
    let mut exact_sources = Vec::new();
    let mut static_sources = Vec::new();
    let mut dynamic_sources = Vec::new();

    for group in groups {
        for &cidr in group.sources.cidrs() {
            if cidr.prefix() == 32 {
                exact_sources.push(u32::from(cidr.addr()));
            } else if static_seen.insert(cidr) {
                static_sources.push(cidr);
            }
        }
        if let Some(dynamic) = group.sources.dynamic_set() {
            dynamic_sources.push(dynamic);
        }
    }

    exact_sources.sort_unstable();
    exact_sources.dedup();

    (
        exact_sources.into_boxed_slice(),
        static_sources.into_boxed_slice(),
        dynamic_sources.into_boxed_slice(),
    )
}

fn exact_source_ips(sources: &IpSetV4) -> Option<Vec<Ipv4Addr>> {
    if sources.has_dynamic() {
        return None;
    }
    let cidrs = sources.cidrs();
    if cidrs.iter().all(|cidr| cidr.prefix() == 32) {
        return Some(cidrs.iter().map(|cidr| cidr.addr()).collect());
    }
    None
}

fn collect_any_other_rule_indices(group: &SourceGroup, mode: RuleMode) -> Vec<usize> {
    group
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.mode == mode && matches!(rule.matcher.proto, Proto::Any))
        .map(|(idx, _)| idx)
        .collect()
}

fn collect_other_protocols(group: &SourceGroup, mode: RuleMode) -> BTreeSet<u8> {
    group
        .rules
        .iter()
        .filter(|rule| rule.mode == mode)
        .filter_map(|rule| match rule.matcher.proto {
            Proto::Other(proto) if !matches!(proto, 1 | 6 | 17) => Some(proto),
            _ => None,
        })
        .collect()
}

#[derive(Debug, Clone)]
enum DestinationMatchClass {
    General,
    Exact(Vec<Ipv4Addr>),
}

fn collect_exact_destination_ips(
    classifications: &[(usize, Option<DestinationMatchClass>)],
) -> Vec<Ipv4Addr> {
    let mut ips = BTreeSet::new();
    for (_, class) in classifications {
        if let Some(DestinationMatchClass::Exact(exact_ips)) = class {
            ips.extend(exact_ips.iter().copied());
        }
    }
    ips.into_iter().collect()
}

fn classify_destination_match(matcher: &RuleMatch) -> DestinationMatchClass {
    let Some(dst_ips) = &matcher.dst_ips else {
        return DestinationMatchClass::General;
    };
    if dst_ips.has_dynamic() {
        return DestinationMatchClass::General;
    }
    let cidrs = dst_ips.cidrs();
    if cidrs.iter().all(|cidr| cidr.prefix() == 32) {
        return DestinationMatchClass::Exact(cidrs.iter().map(|cidr| cidr.addr()).collect());
    }
    DestinationMatchClass::General
}
