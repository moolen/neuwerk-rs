impl AzureProvider {
    async fn discover_instances_provider(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachineScaleSets/{}/virtualMachines?api-version={COMPUTE_API_VERSION}",
            self.subscription_id, self.resource_group, self.vmss_name
        );
        let list: VmssInstanceList = self.get_json(url).await?;
        let mut instances = Vec::new();
        let mut rg_nics_cache: Option<Vec<NicResource>> = None;
        for entry in list.value {
            let instance_id = entry
                .instance_id
                .clone()
                .unwrap_or_else(|| entry.name.clone());
            let network_interfaces = entry
                .properties
                .and_then(|props| props.network_profile)
                .and_then(|profile| profile.network_interfaces)
                .unwrap_or_default();
            let mut nic_resources = Vec::new();
            for nic in network_interfaces {
                if let Some(id) = nic.id {
                    let resource = self.fetch_nic(&id).await.map_err(|err| {
                        CloudError::RequestFailed(format!(
                            "instance {} nic fetch failed: {err}",
                            entry.name
                        ))
                    })?;
                    nic_resources.push(resource);
                }
            }
            if nic_resources.is_empty() {
                if let Some(instance_id) = entry.instance_id.as_deref() {
                    if !instance_id.chars().all(|ch| ch.is_ascii_digit()) {
                        // Flexible VMSS uses non-numeric instance IDs; skip the VMSS NIC list API.
                        // We'll fall back to resource-group NIC discovery below.
                    } else {
                        match self
                            .list_vmss_nics(
                                &self.subscription_id,
                                &self.resource_group,
                                &self.vmss_name,
                                instance_id,
                            )
                            .await
                        {
                            Ok(nics) => nic_resources = nics,
                            Err(err) => tracing::warn!(
                                "azure integration: vmss nic list failed for {} ({instance_id}): {err}",
                                entry.name
                            ),
                        }
                    }
                }
            }
            if nic_resources.is_empty() {
                let Some(resource_id) = entry.id.as_deref() else {
                    tracing::warn!(
                        "azure integration: instance {} missing resource id; cannot match rg nics",
                        entry.name
                    );
                    continue;
                };
                if rg_nics_cache.is_none() {
                    rg_nics_cache = Some(
                        self.list_rg_nics(&self.subscription_id, &self.resource_group)
                            .await?,
                    );
                }
                if let Some(rg_nics) = rg_nics_cache.as_ref() {
                    let vm_name = entry.name.clone();
                    nic_resources = rg_nics
                        .iter()
                        .filter(|nic| {
                            AzureProvider::resource_id_matches(nic, resource_id)
                                || AzureProvider::vm_name_matches(nic, &vm_name)
                        })
                        .cloned()
                        .collect();
                }
            }
            let (mgmt_ip, dataplane_ip) = AzureProvider::select_mgmt_dataplane_ips(&nic_resources)
                .map_err(|err| {
                    CloudError::InvalidResponse(format!(
                        "instance {} missing tagged or named nics: {err}",
                        entry.name
                    ))
                })?;
            let zone = entry
                .zones
                .as_ref()
                .and_then(|zones| zones.first().cloned())
                .unwrap_or_else(|| entry.location.clone().unwrap_or_default());
            let tags = AzureProvider::parse_tags(None, entry.tags.as_ref());
            instances.push(InstanceRef {
                id: instance_id,
                name: entry.name,
                zone,
                created_at_epoch: AzureProvider::parse_time(entry.time_created.as_deref()),
                mgmt_ip: IpAddr::V4(mgmt_ip),
                dataplane_ip,
                tags,
                active: true,
            });
        }
        Ok(instances)
    }

    async fn discover_subnets_provider(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/virtualNetworks?api-version={NETWORK_API_VERSION}",
            self.subscription_id, self.resource_group
        );
        let list: VnetList = self.get_json(url).await?;
        let mut subnets = Vec::new();
        for vnet in list.value {
            let location = vnet.location.clone().unwrap_or_default();
            let vnet_tags = vnet.tags.clone().unwrap_or_default();
            let vnet_subnets = vnet
                .properties
                .and_then(|props| props.subnets)
                .unwrap_or_default();
            for subnet in vnet_subnets {
                let subnet_name = subnet.name.clone().unwrap_or_default();
                let tags = subnet.tags.clone().unwrap_or_else(|| vnet_tags.clone());
                if AzureProvider::is_management_subnet(&subnet_name, &tags) {
                    continue;
                }
                if !filter.matches(&tags) {
                    continue;
                }
                let route_table_id = subnet
                    .properties
                    .as_ref()
                    .and_then(|props| props.route_table.as_ref())
                    .and_then(|rt| rt.id.clone())
                    .unwrap_or_default();
                if route_table_id.is_empty() {
                    continue;
                }
                let cidr = subnet
                    .properties
                    .as_ref()
                    .and_then(|props| props.address_prefix.clone())
                    .or_else(|| {
                        subnet
                            .properties
                            .as_ref()
                            .and_then(|props| props.address_prefixes.as_ref())
                            .and_then(|prefixes| prefixes.first().cloned())
                    })
                    .unwrap_or_default();
                subnets.push(SubnetRef {
                    id: subnet.id.unwrap_or_default(),
                    name: subnet_name,
                    zone: location.clone(),
                    cidr,
                    route_table_id,
                    tags,
                });
            }
        }
        Ok(subnets)
    }
}
