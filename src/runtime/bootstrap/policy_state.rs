use std::path::PathBuf;

use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::PolicyStore;

use crate::runtime::cli::CliConfig;

pub struct LocalControlplaneState {
    pub local_policy_store: PolicyDiskStore,
    pub local_service_accounts_dir: PathBuf,
    pub local_integrations_dir: PathBuf,
}

pub fn init_local_controlplane_state(
    cfg: &CliConfig,
    policy_store: &PolicyStore,
) -> Result<LocalControlplaneState, String> {
    let local_policy_store =
        PolicyDiskStore::new(PathBuf::from("/var/lib/neuwerk/local-policy-store"));
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
