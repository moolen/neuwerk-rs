use std::io;

#[derive(Debug, Clone)]
pub struct ClusterConfig {
    pub node_id: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
        }
    }
}

pub async fn run_cluster_tasks(_cfg: ClusterConfig) -> io::Result<()> {
    Ok(())
}
