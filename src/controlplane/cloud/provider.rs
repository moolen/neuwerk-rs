use async_trait::async_trait;
use std::net::Ipv4Addr;

use super::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange, RouteRef,
    SubnetRef, TerminationEvent,
};

#[derive(Debug, thiserror::Error)]
pub enum CloudError {
    #[error("unsupported operation")]
    Unsupported,
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("not found: {0}")]
    NotFound(String),
}

#[async_trait]
pub trait CloudProvider: Send + Sync {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError>;
    async fn discover_instances(&self, filter: &DiscoveryFilter) -> Result<Vec<InstanceRef>, CloudError>;
    async fn discover_subnets(&self, filter: &DiscoveryFilter) -> Result<Vec<SubnetRef>, CloudError>;
    async fn get_route(&self, subnet: &SubnetRef, route_name: &str) -> Result<Option<RouteRef>, CloudError>;
    async fn ensure_default_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError>;
    async fn set_instance_protection(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError>;
    async fn poll_termination_notice(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError>;
    async fn complete_termination_action(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError>;

    fn capabilities(&self) -> IntegrationCapabilities;
}
