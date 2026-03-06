impl AzureProvider {
    async fn self_identity_provider(&self) -> Result<InstanceRef, CloudError> {
        let url = format!("{}/instance?api-version={}", IMDS_BASE, IMDS_API_VERSION);
        let response = self
            .client
            .get(url)
            .header("Metadata", "true")
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "imds instance failed: {status}"
            )));
        }
        let payload: ImdsInstance = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        let compute = payload.compute;
        let subscription_id = compute
            .subscription_id
            .as_deref()
            .ok_or_else(|| CloudError::InvalidResponse("missing subscriptionId".to_string()))?;
        let resource_group = compute
            .resource_group_name
            .as_deref()
            .ok_or_else(|| CloudError::InvalidResponse("missing resourceGroupName".to_string()))?;
        let vmss_name = compute
            .vm_scale_set_name
            .as_deref()
            .ok_or_else(|| CloudError::InvalidResponse("missing vmScaleSetName".to_string()))?;
        let instance_id = self
            .resolve_instance_id(&compute, subscription_id, resource_group, vmss_name)
            .await?;
        self.ensure_termination_notifications_enabled(subscription_id, resource_group, vmss_name)
            .await?;
        let nics = if let Some(resource_id) = compute.resource_id.as_deref() {
            let rg_nics = self
                .list_rg_nics(subscription_id, resource_group)
                .await?
                .into_iter()
                .filter(|nic| AzureProvider::resource_id_matches(nic, resource_id))
                .collect::<Vec<_>>();
            if rg_nics.is_empty() {
                self.list_vmss_nics(subscription_id, resource_group, vmss_name, &instance_id)
                    .await?
            } else {
                rg_nics
            }
        } else {
            self.list_vmss_nics(subscription_id, resource_group, vmss_name, &instance_id)
                .await?
        };
        let (mgmt_ip, dataplane_ip) = AzureProvider::select_mgmt_dataplane_ips(&nics)?;
        let zone = compute
            .zone
            .clone()
            .unwrap_or_else(|| compute.location.clone());
        let tags = AzureProvider::parse_tags(compute.tags.as_deref(), None);
        Ok(InstanceRef {
            // Use VMSS instance_id (not VM UUID) so local identity keys match discover_instances.
            id: instance_id,
            name: compute.name,
            zone,
            created_at_epoch: AzureProvider::parse_time(compute.time_created.as_deref()),
            mgmt_ip: IpAddr::V4(mgmt_ip),
            dataplane_ip,
            tags,
            active: true,
        })
    }
}
