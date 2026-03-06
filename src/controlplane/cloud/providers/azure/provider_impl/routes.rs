impl AzureProvider {
    async fn get_route_provider(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
        if subnet.route_table_id.is_empty() {
            return Ok(None);
        }
        let url = format!(
            "{}/routes/{}?api-version={NETWORK_API_VERSION}",
            subnet.route_table_id, route_name
        );
        let response = self
            .client
            .get(url)
            .bearer_auth(self.token().await?)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "route fetch failed: {status}"
            )));
        }
        let route: RouteResource = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        let next_hop = route
            .properties
            .and_then(|props| props.next_hop_ip_address)
            .and_then(|value| value.parse::<Ipv4Addr>().ok())
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        Ok(Some(RouteRef {
            id: route.id.unwrap_or_default(),
            name: route.name.unwrap_or_default(),
            subnet_id: subnet.id.clone(),
            next_hop,
        }))
    }

    async fn ensure_default_route_provider(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        let existing = self.get_route_provider(subnet, route_name).await?;
        if let Some(route) = &existing {
            if route.next_hop == next_hop {
                return Ok(RouteChange::Unchanged);
            }
        }
        let url = format!(
            "{}/routes/{}?api-version={NETWORK_API_VERSION}",
            subnet.route_table_id, route_name
        );
        let body = RouteRequest {
            properties: RouteRequestProperties {
                address_prefix: "0.0.0.0/0".to_string(),
                next_hop_type: "VirtualAppliance".to_string(),
                next_hop_ip_address: next_hop.to_string(),
            },
        };
        let response = self
            .client
            .put(url)
            .bearer_auth(self.token().await?)
            .json(&body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "route update failed: {status}"
            )));
        }
        Ok(if existing.is_some() {
            RouteChange::Updated
        } else {
            RouteChange::Created
        })
    }
}
