use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::controlplane::policy_config::{DnsPolicy, PolicyConfig, PolicyMode};
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, EnforcementMode, IpSetV4, PolicySnapshot, Proto, Rule,
    RuleAction, RuleMatch, RuleMode, SourceGroup,
};
use uuid::Uuid;

const BASE_GROUP_PRIORITY: u32 = u32::MAX;

#[derive(Debug, Clone)]
struct PolicyStoreState {
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    default_policy: DefaultPolicy,
    enforcement_mode: EnforcementMode,
    extra_groups: Vec<SourceGroup>,
    generation: u64,
    active_policy_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct PolicyStore {
    snapshot: Arc<RwLock<PolicySnapshot>>,
    dns_policy: Arc<RwLock<DnsPolicy>>,
    dns_allowlist: DynamicIpSetV4,
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
        let dns_allowlist = DynamicIpSetV4::new();
        let snapshot = Arc::new(RwLock::new(Self::build_snapshot(
            default_policy,
            internal_net,
            internal_prefix,
            0,
            dns_allowlist.clone(),
            Vec::new(),
            EnforcementMode::Enforce,
        )));
        let dns_policy = Arc::new(RwLock::new(DnsPolicy::new(Vec::new())));
        let policy_applied_generation = Arc::new(AtomicU64::new(0));
        let service_policy_applied_generation = Arc::new(AtomicU64::new(0));
        let state = Arc::new(RwLock::new(PolicyStoreState {
            internal_net,
            internal_prefix,
            default_policy,
            enforcement_mode: EnforcementMode::Enforce,
            extra_groups: Vec::new(),
            generation: 0,
            active_policy_id: None,
        }));

        Self {
            snapshot,
            dns_policy,
            dns_allowlist,
            dataplane_config,
            state,
            policy_applied_generation,
            service_policy_applied_generation,
        }
    }

    pub fn snapshot(&self) -> Arc<RwLock<PolicySnapshot>> {
        self.snapshot.clone()
    }

    pub fn dns_allowlist(&self) -> DynamicIpSetV4 {
        self.dns_allowlist.clone()
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
        Self::build_base_group(internal_net, internal_prefix, self.dns_allowlist.clone())
    }

    pub fn rebuild(
        &self,
        mut extra_groups: Vec<SourceGroup>,
        dns_policy: DnsPolicy,
        default_policy: Option<DefaultPolicy>,
        enforcement_mode: EnforcementMode,
    ) -> Result<u64, String> {
        // Clear DNS allowlist entries so policy changes immediately revoke prior DNS grants.
        self.dns_allowlist.clear();
        let (internal_net, internal_prefix, effective_default, effective_mode, generation) =
            match self.state.write() {
                Ok(mut state) => {
                    if let Some(policy) = default_policy {
                        state.default_policy = policy;
                    }
                    state.enforcement_mode = enforcement_mode;
                    state.extra_groups = extra_groups.clone();
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

        let mut groups = Vec::with_capacity(1 + extra_groups.len());
        groups.push(Self::build_base_group(
            internal_net,
            internal_prefix,
            self.dns_allowlist.clone(),
        ));
        groups.append(&mut extra_groups);

        let policy = Self::build_snapshot(
            effective_default,
            internal_net,
            internal_prefix,
            generation,
            self.dns_allowlist.clone(),
            groups,
            effective_mode,
        );

        if let Ok(mut lock) = self.snapshot.write() {
            *lock = policy;
        } else {
            return Err("policy snapshot unavailable".to_string());
        }

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
        let (extra_groups, default_policy, enforcement_mode) = match self.state.write() {
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
                )
            }
            Err(_) => return Err("policy store internal state unavailable".to_string()),
        };

        let dns_policy = match self.dns_policy.read() {
            Ok(lock) => lock.clone(),
            Err(_) => return Err("dns policy unavailable".to_string()),
        };

        self.rebuild(
            extra_groups,
            dns_policy,
            Some(default_policy),
            enforcement_mode,
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
        self.rebuild(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode,
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

    fn build_snapshot(
        default_policy: DefaultPolicy,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        generation: u64,
        dns_allowlist: DynamicIpSetV4,
        mut groups: Vec<SourceGroup>,
        enforcement_mode: EnforcementMode,
    ) -> PolicySnapshot {
        if groups.is_empty() {
            groups.push(Self::build_base_group(
                internal_net,
                internal_prefix,
                dns_allowlist,
            ));
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
        dns_allowlist: DynamicIpSetV4,
    ) -> SourceGroup {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(internal_net, internal_prefix));

        let rule = Rule {
            id: "dns-allowlist".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(IpSetV4::with_dynamic(dns_allowlist)),
                proto: Proto::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: RuleMode::Enforce,
        };

        SourceGroup {
            id: "internal".to_string(),
            // Keep the DNS allowlist fallback last so explicit policy groups
            // (including TLS intercept rules) are evaluated first.
            priority: BASE_GROUP_PRIORITY,
            sources,
            rules: vec![rule],
            default_action: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
