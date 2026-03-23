use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::controlplane::policy_config::{
    DnsPolicy, KubernetesSelectorBinding, PolicyConfig, PolicyMode,
};
use crate::controlplane::wiretap::DnsMap;
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::policy::{
    new_shared_exact_source_group_index, CidrV4, DefaultPolicy, DynamicIpSetV4,
    EnforcementMode, ExactSourceGroupIndex, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction,
    RuleMatch, RuleMode, SharedExactSourceGroupIndex, SharedPolicySnapshot, SourceGroup,
    DNS_ALLOWLIST_RULE_ID,
};
use uuid::Uuid;

const BASE_GROUP_PRIORITY: u32 = u32::MAX;
const DNS_ALLOWLIST_PRIORITY: u32 = u32::MAX;

#[derive(Debug, Clone)]
struct DnsGroupGrantState {
    allowlist: DynamicIpSetV4,
    dns_map: DnsMap,
}

#[derive(Debug, Clone)]
struct PolicyStoreState {
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    default_policy: DefaultPolicy,
    enforcement_mode: EnforcementMode,
    extra_groups: Vec<SourceGroup>,
    kubernetes_bindings: Vec<KubernetesSelectorBinding>,
    dns_group_grants: HashMap<String, DnsGroupGrantState>,
    generation: u64,
    active_policy_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    snapshot: Arc<RwLock<PolicySnapshot>>,
    shared_snapshot: SharedPolicySnapshot,
    exact_source_group_index: SharedExactSourceGroupIndex,
    dns_policy: Arc<RwLock<DnsPolicy>>,
    dataplane_config: DataplaneConfigStore,
    state: Arc<RwLock<PolicyStoreState>>,
    policy_applied_generation: Arc<AtomicU64>,
    service_policy_applied_generation: Arc<AtomicU64>,
}

impl PolicyStore {
    pub fn new(default_policy: DefaultPolicy, internal_net: Ipv4Addr, internal_prefix: u8) -> Self {
        Self::new_with_config(
            default_policy,
            internal_net,
            internal_prefix,
            DataplaneConfigStore::new(),
        )
    }

    pub fn new_with_config(
        default_policy: DefaultPolicy,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        dataplane_config: DataplaneConfigStore,
    ) -> Self {
        let initial_snapshot = Self::build_snapshot(
            default_policy,
            internal_net,
            internal_prefix,
            0,
            Vec::new(),
            EnforcementMode::Enforce,
        );
        let snapshot = Arc::new(RwLock::new(initial_snapshot.clone()));
        let shared_snapshot = Arc::new(arc_swap::ArcSwap::from_pointee(initial_snapshot));
        let exact_source_group_index = {
            let lock = snapshot.read().expect("policy snapshot initialized");
            new_shared_exact_source_group_index(&lock)
        };
        let dns_policy = Arc::new(RwLock::new(DnsPolicy::new(Vec::new())));
        let policy_applied_generation = Arc::new(AtomicU64::new(0));
        let service_policy_applied_generation = Arc::new(AtomicU64::new(0));
        let state = Arc::new(RwLock::new(PolicyStoreState {
            internal_net,
            internal_prefix,
            default_policy,
            enforcement_mode: EnforcementMode::Enforce,
            extra_groups: Vec::new(),
            dns_group_grants: HashMap::new(),
            generation: 0,
            active_policy_id: None,
            kubernetes_bindings: Vec::new(),
        }));

        Self {
            snapshot,
            shared_snapshot,
            exact_source_group_index,
            dns_policy,
            dataplane_config,
            state,
            policy_applied_generation,
            service_policy_applied_generation,
        }
    }

    pub fn snapshot(&self) -> Arc<RwLock<PolicySnapshot>> {
        self.snapshot.clone()
    }

    pub fn shared_snapshot(&self) -> SharedPolicySnapshot {
        self.shared_snapshot.clone()
    }

    pub fn exact_source_group_index(&self) -> SharedExactSourceGroupIndex {
        self.exact_source_group_index.clone()
    }

    pub fn dns_policy(&self) -> Arc<RwLock<DnsPolicy>> {
        self.dns_policy.clone()
    }

    pub fn dataplane_config(&self) -> DataplaneConfigStore {
        self.dataplane_config.clone()
    }

    pub fn policy_generation(&self) -> u64 {
        match self.state.read() {
            Ok(state) => state.generation,
            Err(_) => 0,
        }
    }

    pub fn policy_applied_generation(&self) -> u64 {
        self.policy_applied_generation.load(Ordering::Acquire)
    }

    pub fn policy_applied_tracker(&self) -> Arc<AtomicU64> {
        self.policy_applied_generation.clone()
    }

    pub fn service_policy_applied_generation(&self) -> u64 {
        self.service_policy_applied_generation
            .load(Ordering::Acquire)
    }

    pub fn service_policy_applied_tracker(&self) -> Arc<AtomicU64> {
        self.service_policy_applied_generation.clone()
    }

    pub fn base_group(&self) -> SourceGroup {
        let (internal_net, internal_prefix) = self.internal_cidr();
        Self::build_base_group(internal_net, internal_prefix)
    }

    pub fn record_dns_grants(
        &self,
        source_group_id: &str,
        hostname: &str,
        ips: &[Ipv4Addr],
        now: u64,
    ) -> usize {
        if ips.is_empty() {
            return 0;
        }
        let grant = match self.state.read() {
            Ok(state) => state.dns_group_grants.get(source_group_id).cloned(),
            Err(_) => None,
        };
        let Some(grant) = grant else {
            return 0;
        };
        grant.dns_map.insert_many(hostname, ips, now);
        grant.allowlist.insert_many(ips.iter().copied());
        ips.len()
    }

    pub fn revoke_dns_grants(&self, source_group_id: &str, hostname: &str) -> usize {
        let grant = match self.state.read() {
            Ok(state) => state.dns_group_grants.get(source_group_id).cloned(),
            Err(_) => None,
        };
        let Some(grant) = grant else {
            return 0;
        };
        let removed = grant.dns_map.remove_hostname(hostname);
        let removed_len = removed.len();
        if removed_len > 0 {
            grant.allowlist.remove_many(removed.into_iter());
        }
        removed_len
    }

    pub fn evict_dns_grant_caches(&self, now: u64, idle_timeout_secs: u64) {
        if let Ok(state) = self.state.read() {
            for grant in state.dns_group_grants.values() {
                grant.allowlist.evict_idle(now, idle_timeout_secs);
                grant.dns_map.evict_idle(now, idle_timeout_secs);
            }
        }
    }

    pub fn rebuild(
        &self,
        extra_groups: Vec<SourceGroup>,
        dns_policy: DnsPolicy,
        default_policy: Option<DefaultPolicy>,
        enforcement_mode: EnforcementMode,
    ) -> Result<u64, String> {
        self.rebuild_with_kubernetes_bindings(
            extra_groups,
            dns_policy,
            default_policy,
            enforcement_mode,
            Vec::new(),
        )
    }

    pub fn rebuild_with_kubernetes_bindings(
        &self,
        extra_groups: Vec<SourceGroup>,
        dns_policy: DnsPolicy,
        default_policy: Option<DefaultPolicy>,
        enforcement_mode: EnforcementMode,
        kubernetes_bindings: Vec<KubernetesSelectorBinding>,
    ) -> Result<u64, String> {
        let dns_group_grants = Self::build_dns_group_grants(&dns_policy);
        let extra_groups_with_dns =
            Self::attach_dns_group_allowlists(extra_groups.clone(), &dns_group_grants);
        let (internal_net, internal_prefix, effective_default, effective_mode, generation) =
            match self.state.write() {
                Ok(mut state) => {
                    for grant in state.dns_group_grants.values() {
                        grant.allowlist.clear();
                    }
                    if let Some(policy) = default_policy {
                        state.default_policy = policy;
                    }
                    state.enforcement_mode = enforcement_mode;
                    state.extra_groups = extra_groups.clone();
                    state.kubernetes_bindings = kubernetes_bindings;
                    state.dns_group_grants = dns_group_grants.clone();
                    state.generation = state.generation.wrapping_add(1);
                    (
                        state.internal_net,
                        state.internal_prefix,
                        state.default_policy,
                        state.enforcement_mode,
                        state.generation,
                    )
                }
                Err(_) => return Err("policy store internal state unavailable".to_string()),
            };

        let mut groups = Vec::with_capacity(1 + extra_groups_with_dns.len());
        groups.push(Self::build_base_group(internal_net, internal_prefix));
        groups.extend(extra_groups_with_dns);

        let policy = Self::build_snapshot(
            effective_default,
            internal_net,
            internal_prefix,
            generation,
            groups,
            effective_mode,
        );
        let exact_source_group_index = Arc::new(ExactSourceGroupIndex::for_snapshot(&policy));

        if let Ok(mut lock) = self.snapshot.write() {
            *lock = policy.clone();
        } else {
            return Err("policy snapshot unavailable".to_string());
        }
        self.shared_snapshot.store(Arc::new(policy.clone()));
        self.exact_source_group_index
            .store(exact_source_group_index);

        if let Ok(mut lock) = self.dns_policy.write() {
            *lock = dns_policy;
        } else {
            return Err("dns policy unavailable".to_string());
        }

        Ok(generation)
    }

    pub fn update_internal_cidr(
        &self,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
    ) -> Result<(), String> {
        let (extra_groups, default_policy, enforcement_mode, kubernetes_bindings) = match self
            .state
            .write()
        {
            Ok(mut state) => {
                if state.internal_net == internal_net && state.internal_prefix == internal_prefix {
                    return Ok(());
                }
                state.internal_net = internal_net;
                state.internal_prefix = internal_prefix;
                (
                    state.extra_groups.clone(),
                    state.default_policy,
                    state.enforcement_mode,
                    state.kubernetes_bindings.clone(),
                )
            }
            Err(_) => return Err("policy store internal state unavailable".to_string()),
        };

        let dns_policy = match self.dns_policy.read() {
            Ok(lock) => lock.clone(),
            Err(_) => return Err("dns policy unavailable".to_string()),
        };

        self.rebuild_with_kubernetes_bindings(
            extra_groups,
            dns_policy,
            Some(default_policy),
            enforcement_mode,
            kubernetes_bindings,
        )?;
        Ok(())
    }

    pub fn rebuild_from_yaml(&self, yaml: &str) -> Result<(), String> {
        let config: PolicyConfig =
            serde_yaml::from_str(yaml).map_err(|err| format!("policy yaml error: {err}"))?;
        self.rebuild_from_config(config)?;
        Ok(())
    }

    pub fn rebuild_from_yaml_path(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read policy config {}: {err}", path.display()))?;
        self.rebuild_from_yaml(&contents)?;
        Ok(())
    }

    pub fn rebuild_from_json(&self, json: &str) -> Result<(), String> {
        let config: PolicyConfig =
            serde_json::from_str(json).map_err(|err| format!("policy json error: {err}"))?;
        self.rebuild_from_config(config)?;
        Ok(())
    }

    pub fn rebuild_from_config(&self, config: PolicyConfig) -> Result<u64, String> {
        self.rebuild_from_config_with_mode(config, PolicyMode::Enforce)
    }

    pub fn rebuild_from_config_with_mode(
        &self,
        config: PolicyConfig,
        mode: PolicyMode,
    ) -> Result<u64, String> {
        let compiled = config.compile()?;
        let enforcement_mode = if mode == PolicyMode::Audit {
            EnforcementMode::Audit
        } else {
            EnforcementMode::Enforce
        };
        self.rebuild_with_kubernetes_bindings(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode,
            compiled.kubernetes_bindings,
        )
    }

    pub fn set_active_policy_id(&self, id: Option<Uuid>) {
        if let Ok(mut state) = self.state.write() {
            state.active_policy_id = id;
        }
    }

    pub fn active_policy_id(&self) -> Option<Uuid> {
        match self.state.read() {
            Ok(state) => state.active_policy_id,
            Err(_) => None,
        }
    }

    pub fn enforcement_mode(&self) -> EnforcementMode {
        match self.state.read() {
            Ok(state) => state.enforcement_mode,
            Err(_) => EnforcementMode::Enforce,
        }
    }

    pub fn kubernetes_bindings(&self) -> Vec<KubernetesSelectorBinding> {
        match self.state.read() {
            Ok(state) => state.kubernetes_bindings.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn build_snapshot(
        default_policy: DefaultPolicy,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        generation: u64,
        mut groups: Vec<SourceGroup>,
        enforcement_mode: EnforcementMode,
    ) -> PolicySnapshot {
        if groups.is_empty() {
            groups.push(Self::build_base_group(internal_net, internal_prefix));
        }
        let mut snapshot = PolicySnapshot::new_with_generation(default_policy, groups, generation);
        snapshot.set_enforcement_mode(enforcement_mode);
        snapshot
    }

    fn internal_cidr(&self) -> (Ipv4Addr, u8) {
        match self.state.read() {
            Ok(state) => (state.internal_net, state.internal_prefix),
            Err(_) => (Ipv4Addr::new(0, 0, 0, 0), 0),
        }
    }

    fn build_base_group(
        internal_net: Ipv4Addr,
        internal_prefix: u8,
    ) -> SourceGroup {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(internal_net, internal_prefix));

        SourceGroup {
            id: "internal".to_string(),
            priority: BASE_GROUP_PRIORITY,
            sources,
            rules: Vec::new(),
            default_action: None,
        }
    }

    fn build_dns_group_grants(dns_policy: &DnsPolicy) -> HashMap<String, DnsGroupGrantState> {
        dns_policy
            .groups
            .iter()
            .filter(|group| !group.rules.is_empty())
            .map(|group| {
                (
                    group.id.clone(),
                    DnsGroupGrantState {
                        allowlist: DynamicIpSetV4::new(),
                        dns_map: DnsMap::new(),
                    },
                )
            })
            .collect()
    }

    fn attach_dns_group_allowlists(
        mut groups: Vec<SourceGroup>,
        dns_group_grants: &HashMap<String, DnsGroupGrantState>,
    ) -> Vec<SourceGroup> {
        for group in &mut groups {
            let Some(grant) = dns_group_grants.get(&group.id) else {
                continue;
            };
            group.rules.push(Rule {
                id: DNS_ALLOWLIST_RULE_ID.to_string(),
                priority: DNS_ALLOWLIST_PRIORITY,
                matcher: RuleMatch {
                    dst_ips: Some(IpSetV4::with_dynamic(grant.allowlist.clone())),
                    proto: Proto::Any,
                    src_ports: Vec::new(),
                    dst_ports: Vec::new(),
                    icmp_types: Vec::new(),
                    icmp_codes: Vec::new(),
                    tls: None,
                },
                action: RuleAction::Allow,
                mode: RuleMode::Enforce,
            });
            group.rules.sort_by_key(|rule| rule.priority);
        }
        groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::policy_config::PolicyConfig;

    #[test]
    fn update_internal_cidr_rebuilds_base_group() {
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);

        let mut group_sources = IpSetV4::new();
        group_sources.add_cidr(CidrV4::new(Ipv4Addr::new(192, 168, 1, 0), 24));
        let group = SourceGroup {
            id: "apps".to_string(),
            priority: 1,
            sources: group_sources,
            rules: Vec::new(),
            default_action: None,
        };

        store
            .rebuild(
                vec![group],
                DnsPolicy::new(Vec::new()),
                None,
                EnforcementMode::Enforce,
            )
            .expect("initial policy rebuild");
        store
            .update_internal_cidr(Ipv4Addr::new(172, 16, 0, 0), 16)
            .expect("update internal cidr");

        let snapshot = store.snapshot();
        let lock = snapshot.read().expect("snapshot read");
        let internal = lock
            .groups
            .iter()
            .find(|group| group.id == "internal")
            .expect("internal group");
        assert!(internal.sources.contains(Ipv4Addr::new(172, 16, 5, 5)));
        assert!(!internal.sources.contains(Ipv4Addr::new(10, 0, 0, 5)));

        let apps = lock
            .groups
            .iter()
            .find(|group| group.id == "apps")
            .expect("apps group");
        assert!(apps.sources.contains(Ipv4Addr::new(192, 168, 1, 42)));
    }

    #[test]
    fn base_group_is_sorted_after_explicit_groups() {
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);

        let mut group_sources = IpSetV4::new();
        group_sources.add_cidr(CidrV4::new(Ipv4Addr::new(192, 168, 1, 0), 24));
        let group = SourceGroup {
            id: "apps".to_string(),
            priority: 0,
            sources: group_sources,
            rules: Vec::new(),
            default_action: None,
        };

        store
            .rebuild(
                vec![group],
                DnsPolicy::new(Vec::new()),
                None,
                EnforcementMode::Enforce,
            )
            .expect("policy rebuild");

        let snapshot = store.snapshot();
        let lock = snapshot.read().expect("snapshot read");
        assert_eq!(
            lock.groups.first().map(|group| group.id.as_str()),
            Some("apps")
        );
        assert_eq!(
            lock.groups.last().map(|group| group.id.as_str()),
            Some("internal")
        );
    }

    #[test]
    fn dns_grants_are_scoped_to_the_matching_source_group() {
        let store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let cfg: PolicyConfig = serde_yaml::from_str(
            r#"
default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-foo"
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
    default_action: deny
  - id: "client-secondary"
    priority: 1
    sources:
      ips: ["192.0.2.3"]
    rules: []
    default_action: deny
"#,
        )
        .unwrap();
        let compiled = cfg.compile().unwrap();
        store
            .rebuild(
                compiled.groups,
                compiled.dns_policy,
                compiled.default_policy,
                EnforcementMode::Enforce,
            )
            .unwrap();

        let granted_ip = Ipv4Addr::new(203, 0, 113, 10);
        store.record_dns_grants("client-primary", "foo.allowed", &[granted_ip], 10);

        let snapshot = store.snapshot();
        let lock = snapshot.read().unwrap();
        let primary = lock.evaluate(
            &crate::dataplane::policy::PacketMeta {
                src_ip: Ipv4Addr::new(192, 0, 2, 2),
                dst_ip: granted_ip,
                proto: 6,
                src_port: 40000,
                dst_port: 443,
                icmp_type: None,
                icmp_code: None,
            },
            None,
            None,
        );
        let secondary = lock.evaluate(
            &crate::dataplane::policy::PacketMeta {
                src_ip: Ipv4Addr::new(192, 0, 2, 3),
                dst_ip: granted_ip,
                proto: 6,
                src_port: 40001,
                dst_port: 443,
                icmp_type: None,
                icmp_code: None,
            },
            None,
            None,
        );

        assert_eq!(primary, crate::dataplane::policy::PolicyDecision::Allow);
        assert_eq!(secondary, crate::dataplane::policy::PolicyDecision::Deny);
    }
}
