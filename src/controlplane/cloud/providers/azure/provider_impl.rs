include!("provider_impl/identity.rs");
include!("provider_impl/discovery.rs");
include!("provider_impl/routes.rs");
include!("provider_impl/lifecycle.rs");

#[async_trait]
impl CloudProvider for AzureProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
        self.self_identity_provider().await
    }

    async fn discover_instances(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        self.discover_instances_provider(filter).await
    }

    async fn discover_subnets(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        self.discover_subnets_provider(filter).await
    }

    async fn get_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
        self.get_route_provider(subnet, route_name).await
    }

    async fn ensure_default_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        self.ensure_default_route_provider(subnet, route_name, next_hop)
            .await
    }

    async fn set_instance_protection(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        self.set_instance_protection_provider(instance, enabled).await
    }

    async fn poll_termination_notice(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        self.poll_termination_notice_provider(instance).await
    }

    async fn complete_termination_action(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        self.complete_termination_action_provider(event).await
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.capabilities_provider()
    }
}
