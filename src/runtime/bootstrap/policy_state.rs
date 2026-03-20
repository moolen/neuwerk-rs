use std::path::PathBuf;

use neuwerk::controlplane::policy_repository::PolicyDiskStore;
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
        if let Ok(Some(active_id)) = local_policy_store.active_id() {
            match local_policy_store.read_record(active_id) {
                Ok(Some(record)) if record.mode.is_active() => {
                    if let Err(err) =
                        policy_store.rebuild_from_config_with_mode(record.policy, record.mode)
                    {
                        return Err(format!("local policy error: {err}"));
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    return Err(format!("local policy read error: {err}"));
                }
            }
        }
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
    use std::net::{Ipv4Addr, SocketAddr};

    use neuwerk::controlplane::cloud::types::IntegrationMode;
    use neuwerk::controlplane::cluster::config::ClusterConfig;
    use neuwerk::controlplane::policy_config::{PolicyConfig, PolicyMode};
    use neuwerk::controlplane::policy_repository::PolicyRecord;
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
            http_bind: None,
            http_advertise: None,
            http_external_url: None,
            http_tls_dir,
            http_cert_path: None,
            http_key_path: None,
            http_ca_path: None,
            http_tls_san: Vec::new(),
            metrics_bind: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080))),
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

    fn write_record(
        store: &PolicyDiskStore,
        mode: PolicyMode,
        policy: PolicyConfig,
    ) -> PolicyRecord {
        let record = PolicyRecord {
            id: Uuid::new_v4(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            name: Some("test".to_string()),
            mode,
            policy,
        };
        store.write_record(&record).expect("write record");
        record
    }

    #[test]
    fn local_boot_ignores_missing_active_record() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        let missing_id = Uuid::new_v4();
        local_store
            .set_active(Some(missing_id))
            .expect("set active");

        let state =
            init_local_controlplane_state_with_store(&cfg, &policy_store, local_store.clone())
                .expect("init local state");

        assert_eq!(policy_store.policy_generation(), 0);
        assert_eq!(state.local_policy_store.base_dir(), local_store.base_dir());
        assert_eq!(
            state.local_service_accounts_dir,
            dir.path().join("service-accounts")
        );
        assert_eq!(
            state.local_integrations_dir,
            dir.path().join("integrations")
        );
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
    fn local_boot_ignores_disabled_active_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        let record = write_record(
            &local_store,
            PolicyMode::Disabled,
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
        local_store.set_active(Some(record.id)).expect("set active");

        init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .expect("init local state");

        assert_eq!(policy_store.policy_generation(), 0);
    }

    #[test]
    fn local_boot_reports_corrupted_active_policy_record() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        let record = write_record(
            &local_store,
            PolicyMode::Enforce,
            parse_policy(
                r#"
default_policy: deny
source_groups:
  - id: "apps"
    sources:
      cidrs: ["10.0.0.0/24"]
    rules: []
"#,
            ),
        );
        local_store.set_active(Some(record.id)).expect("set active");
        let record_path = local_store
            .base_dir()
            .join("policies")
            .join(format!("{}.json", record.id));
        std::fs::write(&record_path, b"{not-json").expect("corrupt record");

        let err = init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .err()
            .expect("expected corrupted record error");

        assert!(err.contains("local policy read error"));
        assert_eq!(policy_store.policy_generation(), 0);
    }

    #[test]
    fn local_boot_reports_compile_failure_for_active_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        let record = write_record(
            &local_store,
            PolicyMode::Enforce,
            parse_policy(
                r#"
source_groups:
  - id: "broken"
    sources: {}
    rules: []
"#,
            ),
        );
        local_store.set_active(Some(record.id)).expect("set active");

        let err = init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .err()
            .expect("expected compile failure");

        assert!(err.contains("local policy error"));
        assert_eq!(policy_store.policy_generation(), 0);
    }

    #[test]
    fn local_boot_restores_active_enforcing_policy() {
        let cfg = test_cli_config();
        let policy_store = policy_store();
        let dir = TempDir::new().unwrap();
        let local_store = PolicyDiskStore::new(dir.path().join("local-policy-store"));
        let record = write_record(
            &local_store,
            PolicyMode::Enforce,
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
        local_store.set_active(Some(record.id)).expect("set active");

        init_local_controlplane_state_with_store(&cfg, &policy_store, local_store)
            .expect("init local state");

        assert_eq!(policy_store.policy_generation(), 1);
    }
}
