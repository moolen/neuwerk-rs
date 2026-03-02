use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceRef {
    pub id: String,
    pub name: String,
    pub zone: String,
    pub created_at_epoch: i64,
    pub mgmt_ip: IpAddr,
    pub dataplane_ip: Ipv4Addr,
    pub tags: HashMap<String, String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubnetRef {
    pub id: String,
    pub name: String,
    pub zone: String,
    pub cidr: String,
    pub route_table_id: String,
    pub tags: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteRef {
    pub id: String,
    pub name: String,
    pub subnet_id: String,
    pub next_hop: Ipv4Addr,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteChange {
    Unchanged,
    Created,
    Updated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityResult {
    Applied,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrationCapabilities {
    pub instance_protection: bool,
    pub termination_notice: bool,
    pub lifecycle_hook: bool,
}

impl Default for IntegrationCapabilities {
    fn default() -> Self {
        Self {
            instance_protection: false,
            termination_notice: false,
            lifecycle_hook: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DrainStatus {
    Active,
    Draining,
    Drained,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DrainState {
    pub state: DrainStatus,
    pub since_epoch: i64,
    pub deadline_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceObservation {
    pub ready: bool,
    pub last_seen_epoch: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerminationEvent {
    pub id: String,
    pub instance_id: String,
    pub deadline_epoch: i64,
}

#[derive(Debug, Clone, Default)]
pub struct DiscoveryFilter {
    pub tags: HashMap<String, String>,
}

impl DiscoveryFilter {
    fn tag_value<'a>(tags: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
        if let Some(value) = tags.get(key) {
            return Some(value);
        }
        if key.contains('/') {
            let alt = key.replace('/', ".");
            return tags.get(&alt);
        }
        None
    }

    pub fn matches(&self, tags: &HashMap<String, String>) -> bool {
        self.tags
            .iter()
            .all(|(key, value)| Self::tag_value(tags, key) == Some(value))
    }
}

#[derive(Debug, Clone)]
pub struct IntegrationConfig {
    pub cluster_name: String,
    pub route_name: String,
    pub drain_timeout_secs: u64,
    pub reconcile_interval_secs: u64,
    pub tag_filter: DiscoveryFilter,
    pub http_ready_port: u16,
    pub cluster_tls_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrationMode {
    None,
    AzureVmss,
    AwsAsg,
    GcpMig,
}

#[cfg(test)]
mod tests {
    use super::DiscoveryFilter;
    use std::collections::HashMap;

    #[test]
    fn discovery_filter_matches_dot_style_when_slash_requested() {
        let mut filter_tags = HashMap::new();
        filter_tags.insert("neuwerk.io/cluster".to_string(), "neuwerk".to_string());
        filter_tags.insert("neuwerk.io/role".to_string(), "dataplane".to_string());
        let filter = DiscoveryFilter { tags: filter_tags };

        let mut resource_tags = HashMap::new();
        resource_tags.insert("neuwerk.io.cluster".to_string(), "neuwerk".to_string());
        resource_tags.insert("neuwerk.io.role".to_string(), "dataplane".to_string());

        assert!(filter.matches(&resource_tags));
    }
}
