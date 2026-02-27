use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;

use crate::controlplane::cloud::provider::{CloudError, CloudProvider};
use crate::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange, RouteRef,
    SubnetRef, TerminationEvent,
};

#[derive(Clone)]
pub struct AwsProvider {
    #[allow(dead_code)]
    region: String,
    #[allow(dead_code)]
    vpc_id: String,
    #[allow(dead_code)]
    asg_name: String,
}

impl AwsProvider {
    pub fn new(region: String, vpc_id: String, asg_name: String) -> Self {
        Self {
            region,
            vpc_id,
            asg_name,
        }
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[async_trait]
impl CloudProvider for AwsProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
        Err(CloudError::Unsupported)
    }

    async fn discover_instances(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        Err(CloudError::Unsupported)
    }

    async fn discover_subnets(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        Err(CloudError::Unsupported)
    }

    async fn get_route(
        &self,
        _subnet: &SubnetRef,
        _route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
        Err(CloudError::Unsupported)
    }

    async fn ensure_default_route(
        &self,
        _subnet: &SubnetRef,
        _route_name: &str,
        _next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        Err(CloudError::Unsupported)
    }

    async fn set_instance_protection(
        &self,
        _instance: &InstanceRef,
        _enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        Ok(CapabilityResult::Unsupported)
    }

    async fn poll_termination_notice(
        &self,
        _instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        Ok(None)
    }

    async fn complete_termination_action(
        &self,
        _event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        Ok(CapabilityResult::Unsupported)
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        IntegrationCapabilities::default()
    }
}
