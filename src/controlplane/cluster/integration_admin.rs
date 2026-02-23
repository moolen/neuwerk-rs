use crate::controlplane::cloud::termination_key;
use crate::controlplane::cloud::types::TerminationEvent;
use crate::controlplane::cluster::rpc::IntegrationHandler;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub struct IntegrationService {
    raft: openraft::Raft<ClusterTypeConfig>,
}

impl IntegrationService {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>) -> Self {
        Self { raft }
    }
}

#[async_trait::async_trait]
impl IntegrationHandler for IntegrationService {
    async fn publish_termination_event(&self, event: TerminationEvent) -> Result<(), String> {
        let key = termination_key(&event.instance_id);
        let value =
            serde_json::to_vec(&event).map_err(|err| format!("termination encode: {err}"))?;
        let cmd = ClusterCommand::Put { key, value };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    async fn clear_termination_event(&self, instance_id: String) -> Result<(), String> {
        let key = termination_key(&instance_id);
        let cmd = ClusterCommand::Delete { key };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}
