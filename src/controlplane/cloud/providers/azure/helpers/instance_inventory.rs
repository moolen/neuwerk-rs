impl AzureProvider {
    async fn list_vmss_nics(
        &self,
        subscription_id: &str,
        resource_group: &str,
        vmss_name: &str,
        instance_id: &str,
    ) -> Result<Vec<NicResource>, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}/virtualMachines/{instance_id}/networkInterfaces?api-version={COMPUTE_API_VERSION}",
        );
        let list: VmssNicList = self.get_json(url).await?;
        let mut nics = Vec::new();
        for nic in list.value {
            let Some(id) = nic.id else {
                continue;
            };
            nics.push(self.fetch_nic(&id).await?);
        }
        Ok(nics)
    }

    async fn list_rg_nics(
        &self,
        subscription_id: &str,
        resource_group: &str,
    ) -> Result<Vec<NicResource>, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/networkInterfaces?api-version={NETWORK_API_VERSION}",
        );
        let list: NicList = self.get_json(url).await?;
        Ok(list.value)
    }

    fn resource_id_matches(nic: &NicResource, resource_id: &str) -> bool {
        let top = nic
            .virtual_machine
            .as_ref()
            .and_then(|vm| vm.id.as_deref())
            .map(|id| id.eq_ignore_ascii_case(resource_id))
            .unwrap_or(false);
        let nested = nic
            .properties
            .as_ref()
            .and_then(|props| props.virtual_machine.as_ref())
            .and_then(|vm| vm.id.as_deref())
            .map(|id| id.eq_ignore_ascii_case(resource_id))
            .unwrap_or(false);
        top || nested
    }

    fn vm_name_matches(nic: &NicResource, vm_name: &str) -> bool {
        let suffix = format!("/virtualMachines/{vm_name}");
        let top = nic
            .virtual_machine
            .as_ref()
            .and_then(|vm| vm.id.as_deref())
            .map(|id| id.ends_with(&suffix))
            .unwrap_or(false);
        let nested = nic
            .properties
            .as_ref()
            .and_then(|props| props.virtual_machine.as_ref())
            .and_then(|vm| vm.id.as_deref())
            .map(|id| id.ends_with(&suffix))
            .unwrap_or(false);
        top || nested
    }

    async fn resolve_instance_id(
        &self,
        compute: &ImdsCompute,
        subscription_id: &str,
        resource_group: &str,
        vmss_name: &str,
    ) -> Result<String, CloudError> {
        if let Some(instance_id) = compute.instance_id.as_deref() {
            return Ok(instance_id.to_string());
        }
        if let Some(raw) = compute.name.rsplit('_').next() {
            if raw.chars().all(|ch| ch.is_ascii_digit()) {
                return Ok(raw.to_string());
            }
        }
        let url = format!(
            "{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}/virtualMachines?api-version={COMPUTE_API_VERSION}",
        );
        let list: VmssInstanceList = self.get_json(url).await?;
        for entry in list.value {
            if entry.name == compute.name {
                if let Some(instance_id) = entry.instance_id {
                    return Ok(instance_id);
                }
            }
        }
        Err(CloudError::InvalidResponse(
            "missing instanceId; unable to resolve from VMSS list".to_string(),
        ))
    }
}
