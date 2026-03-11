impl AzureProvider {
    async fn get_route_provider(
        &self,
        _subnet: &SubnetRef,
        _route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
        Ok(None)
    }

    async fn ensure_default_route_provider(
        &self,
        _subnet: &SubnetRef,
        _route_name: &str,
        _next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        Ok(RouteChange::Unchanged)
    }
}
