use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use crate::controlplane::policy_config::PolicyConfig;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, DynamicIpSetV4, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction,
    RuleMatch, SourceGroup,
};

#[derive(Debug, Clone)]
pub struct PolicyStore {
    snapshot: Arc<RwLock<PolicySnapshot>>,
    dns_allowlist: DynamicIpSetV4,
    default_policy: DefaultPolicy,
    internal_net: Ipv4Addr,
    internal_prefix: u8,
}

impl PolicyStore {
    pub fn new(default_policy: DefaultPolicy, internal_net: Ipv4Addr, internal_prefix: u8) -> Self {
        let dns_allowlist = DynamicIpSetV4::new();
        let snapshot = Arc::new(RwLock::new(Self::build_snapshot(
            default_policy,
            internal_net,
            internal_prefix,
            dns_allowlist.clone(),
            Vec::new(),
        )));

        Self {
            snapshot,
            dns_allowlist,
            default_policy,
            internal_net,
            internal_prefix,
        }
    }

    pub fn snapshot(&self) -> Arc<RwLock<PolicySnapshot>> {
        self.snapshot.clone()
    }

    pub fn dns_allowlist(&self) -> DynamicIpSetV4 {
        self.dns_allowlist.clone()
    }

    pub fn base_group(&self) -> SourceGroup {
        Self::build_base_group(
            self.internal_net,
            self.internal_prefix,
            self.dns_allowlist.clone(),
        )
    }

    pub fn rebuild(
        &self,
        mut extra_groups: Vec<SourceGroup>,
        default_policy: Option<DefaultPolicy>,
    ) {
        let mut groups = Vec::with_capacity(1 + extra_groups.len());
        groups.push(Self::build_base_group(
            self.internal_net,
            self.internal_prefix,
            self.dns_allowlist.clone(),
        ));
        groups.append(&mut extra_groups);

        let policy = Self::build_snapshot(
            default_policy.unwrap_or(self.default_policy),
            self.internal_net,
            self.internal_prefix,
            self.dns_allowlist.clone(),
            groups,
        );

        if let Ok(mut lock) = self.snapshot.write() {
            *lock = policy;
        }
    }

    pub fn rebuild_from_yaml(&self, yaml: &str) -> Result<(), String> {
        let config: PolicyConfig =
            serde_yaml::from_str(yaml).map_err(|err| format!("policy yaml error: {err}"))?;
        let compiled = config.compile()?;
        self.rebuild(compiled.groups, compiled.default_policy);
        Ok(())
    }

    pub fn rebuild_from_yaml_path(&self, path: impl AsRef<Path>) -> Result<(), String> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|err| format!("failed to read policy config {}: {err}", path.display()))?;
        self.rebuild_from_yaml(&contents)
    }

    fn build_snapshot(
        default_policy: DefaultPolicy,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        dns_allowlist: DynamicIpSetV4,
        mut groups: Vec<SourceGroup>,
    ) -> PolicySnapshot {
        if groups.is_empty() {
            groups.push(Self::build_base_group(
                internal_net,
                internal_prefix,
                dns_allowlist,
            ));
        }
        PolicySnapshot::new(default_policy, groups)
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
                tls: None,
            },
            action: RuleAction::Allow,
        };

        SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        }
    }
}
