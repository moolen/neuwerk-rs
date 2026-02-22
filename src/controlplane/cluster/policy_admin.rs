use crate::controlplane::cluster::rpc::PolicyHandler;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub struct PolicyService {
    raft: openraft::Raft<ClusterTypeConfig>,
}

impl PolicyService {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>) -> Self {
        Self { raft }
    }
}

#[async_trait::async_trait]
impl PolicyHandler for PolicyService {
    async fn set_active_policy(&self, policy_yaml: Vec<u8>) -> Result<(), String> {
        let cmd = ClusterCommand::Put {
            key: b"rules/active".to_vec(),
            value: policy_yaml,
        };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}
