use std::path::PathBuf;

use neuwerk::controlplane::policy_repository::{singleton_policy_id, PolicyDiskStore};
use neuwerk::controlplane::PolicyStore;

use crate::runtime::cli::CliConfig;

pub(crate) const LOCAL_DATA_DIR_ENV: &str = "NEUWERK_LOCAL_DATA_DIR";

pub struct LocalControlplaneState {
    pub local_policy_store: PolicyDiskStore,
    pub local_service_accounts_dir: PathBuf,
    pub local_integrations_dir: PathBuf,
}

pub(crate) fn local_controlplane_data_root() -> PathBuf {
    std::env::var_os(LOCAL_DATA_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/neuwerk"))
}

pub fn init_local_controlplane_state(
    cfg: &CliConfig,
    policy_store: &PolicyStore,
) -> Result<LocalControlplaneState, String> {
    let local_policy_store =
        PolicyDiskStore::new(local_controlplane_data_root().join("local-policy-store"));
    init_local_controlplane_state_with_store(cfg, policy_store, local_policy_store)
}

fn init_local_controlplane_state_with_store(
    cfg: &CliConfig,
    policy_store: &PolicyStore,
    local_policy_store: PolicyDiskStore,
) -> Result<LocalControlplaneState, String> {
    let local_data_root = match local_policy_store.base_dir().parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => local_policy_store.base_dir().to_path_buf(),
    };
    let local_service_accounts_dir = local_data_root.join("service-accounts");
    let local_integrations_dir = local_data_root.join("integrations");

    if !cfg.cluster.enabled {
        let stored = local_policy_store
            .load_or_bootstrap_singleton()
            .map_err(|err| format!("local policy read error: {err}"))?;
        if let Err(err) = policy_store.rebuild_from_config(stored.policy) {
            return Err(format!("local policy error: {err}"));
        }
        policy_store.set_active_policy_id(Some(singleton_policy_id()));
    }

    Ok(LocalControlplaneState {
        local_policy_store,
        local_service_accounts_dir,
        local_integrations_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use neuwerk::controlplane::cloud::types::IntegrationMode;
    use neuwerk::controlplane::cluster::config::ClusterConfig;
    use neuwerk::controlplane::policy_config::PolicyConfig;
    use neuwerk::controlplane::policy_repository::{PolicyRecord, StoredPolicy};
    use neuwerk::controlplane::trafficd::TlsInterceptSettings;
    use neuwerk::dataplane::engine::EngineRuntimeConfig;
    use neuwerk::dataplane::policy::DefaultPolicy;
    use neuwerk::dataplane::{EncapMode, SnatMode, SoftMode};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn test_cli_config() -> CliConfig {
        let http_tls_dir =
            std::env::temp_dir().join(format!("neuwerk-policy-state-test-{}", Uuid::new_v4()));
        CliConfig {
            management_iface: "mgmt0".to_string(),
            data_plane_iface: "data0".to_string(),
            dns_target_ips: Vec::new(),
            dns_upstreams: Vec::new(),
            data_plane_mode: crate::runtime::cli::DataPlaneMode::Soft(SoftMode::Tun),
            idle_timeout_secs: 300,
            dns_allowlist_idle_secs: 420,
            dns_allowlist_gc_interval_secs: 30,
            default_policy: DefaultPolicy::Deny,
            dhcp_timeout_secs: 5,
            dhcp_retry_max: 5,
            dhcp_lease_min_secs: 60,
            internal_cidr: None,
            snat_mode: SnatMode::None,
            encap_mode: EncapMode::None,
            encap_vni: None,
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: None,
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: 1500,
            http_external_url: None,
            http_tls_dir,
            http_cert_path: None,
            http_key_path: None,
            http_ca_path: None,
            http_tls_san: Vec::new(),
            allow_public_metrics_bind: false,
            tls_intercept: TlsInterceptSettings::default(),
            engine_runtime: EngineRuntimeConfig::default(),
            runtime: crate::runtime::config::RuntimeBehaviorSettings::default(),
            dpdk: crate::runtime::config::RuntimeDpdkConfig::default(),
            cloud_provider: crate::runtime::cli::CloudProviderKind::None,
            cluster: ClusterConfig::disabled(),
            cluster_migrate_from_local: false,
            cluster_migrate_force: false,
            cluster_migrate_verify: false,
            integration_mode: IntegrationMode::None,
            integration_route_name: "neuwerk-default".to_string(),
            integration_drain_timeout_secs: 300,
            integration_reconcile_interval_secs: 15,
            integration_cluster_name: "neuwerk".to_string(),
            azure_subscription_id: None,
            azure_resource_group: None,
            azure_vmss_name: None,
            aws_region: None,
            aws_vpc_id: None,
            aws_asg_name: None,
            gcp_project: None,
            gcp_region: None,
            gcp_ig_name: None,
        }
    }

    fn policy_store() -> PolicyStore {
        PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24)
    }

    fn parse_policy(yaml: &str) -> PolicyConfig {
        serde_yaml::from_str(yaml).expect("policy yaml")
    }

    fn write_state(store: &PolicyDiskStore, policy: PolicyConfig) {
        store
            .write_state(&StoredPolicy::from_policy(policy))
            .expect("write state");
    }

    #[test]
    fn bootstrap_singleton_policy_when_missing() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));

        let state =
            init_local_controlplane_state_with_store(&cfg, &policy_store, local_store.clone())
                .expect("init local state");

        assert_eq!(policy_store.policy_generation(), 1);
        assert_eq!(state.local_policy_store.base_dir(), local_store.base_dir());
        assert_eq!(
            state.local_service_accounts_dir,
            dir.path().join("service-accounts")
        );
        assert_eq!(
            state.local_integrations_dir,
            dir.path().join("integrations")
        );
        let stored = local_store.read_state().unwrap().expect("stored singleton");
        assert!(matches!(
            stored.policy.default_policy,
            Some(neuwerk::controlplane::policy_config::PolicyValue::String(ref value))
                if value == "deny"
        ));
        assert!(stored.policy.source_groups.is_empty());
    }

    #[test]
    fn local_state_root_uses_env_override() {
        let dir = TempDir::new().unwrap();
        std::env::set_var(LOCAL_DATA_DIR_ENV, dir.path());

        let root = local_controlplane_data_root();

        std::env::remove_var(LOCAL_DATA_DIR_ENV);
        assert_eq!(root, dir.path());
    }

    #[test]
    fn local_boot_reports_corrupted_stored_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        std::fs::write(local_store.base_dir().join("policy.json"), b"{not-json")
            .expect("corrupt record");

        let err = init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .err()
            .expect("expected corrupted record error");

        assert!(err.contains("local policy read error"));
        assert_eq!(policy_store.policy_generation(), 0);
    }

    #[test]
    fn local_boot_reports_compile_failure_for_stored_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        write_state(
            &local_store,
            parse_policy(
                r#"
source_groups:
  - id: "broken"
    sources: {}
    rules: []
"#,
            ),
        );

        let err = init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .err()
            .expect("expected compile failure");

        assert!(err.contains("local policy error"));
        assert_eq!(policy_store.policy_generation(), 0);
    }

    #[test]
    fn local_boot_restores_stored_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        write_state(
            &local_store,
            parse_policy(
                r#"
default_policy: allow
source_groups:
  - id: "apps"
    sources:
      cidrs: ["10.0.0.0/24"]
    rules: []
"#,
            ),
        );

        init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .expect("init local state");

        assert_eq!(policy_store.policy_generation(), 1);
    }
}
