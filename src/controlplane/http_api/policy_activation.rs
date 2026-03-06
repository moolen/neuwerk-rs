use std::time::{Duration, Instant};

use crate::controlplane::policy_config::PolicyMode;
use crate::controlplane::ready::ReadinessState;
use crate::controlplane::PolicyStore;
use crate::dataplane::policy::EnforcementMode;

const POLICY_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(2);
const POLICY_ACTIVATION_POLL: Duration = Duration::from_millis(10);

pub(super) async fn wait_for_policy_activation(
    policy_store: &PolicyStore,
    readiness: Option<&ReadinessState>,
    generation: u64,
) -> Result<(), String> {
    if readiness.is_none() {
        return Ok(());
    }
    if let Some(state) = readiness {
        if !state.dataplane_running() {
            return Ok(());
        }
    }
    if policy_store.policy_applied_generation() >= generation
        && policy_store.service_policy_applied_generation() >= generation
    {
        return Ok(());
    }
    let deadline = Instant::now() + POLICY_ACTIVATION_TIMEOUT;
    loop {
        let dataplane_applied = policy_store.policy_applied_generation();
        let service_applied = policy_store.service_policy_applied_generation();
        if dataplane_applied >= generation && service_applied >= generation {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "policy activation timed out waiting for generation {generation} (dataplane={dataplane_applied}, service_plane={service_applied})"
            ));
        }
        tokio::time::sleep(POLICY_ACTIVATION_POLL).await;
    }
}

pub(super) fn enforcement_mode_for_policy_mode(mode: PolicyMode) -> EnforcementMode {
    if mode == PolicyMode::Audit {
        EnforcementMode::Audit
    } else {
        EnforcementMode::Enforce
    }
}
