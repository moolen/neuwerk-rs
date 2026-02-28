use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::{Rfc2822, Rfc3339};
use time::OffsetDateTime;

use crate::controlplane::cloud::provider::{CloudError, CloudProvider};
use crate::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange, RouteRef,
    SubnetRef, TerminationEvent,
};

const IMDS_BASE: &str = "http://169.254.169.254/metadata";
const IMDS_API_VERSION: &str = "2021-02-01";
const IMDS_TOKEN_VERSION: &str = "2018-02-01";
const IMDS_SCHEDULED_EVENTS_VERSION: &str = "2020-07-01";
const ARM_BASE: &str = "https://management.azure.com";
const COMPUTE_API_VERSION: &str = "2023-09-01";
const NETWORK_API_VERSION: &str = "2023-05-01";
const TAG_NIC_MANAGEMENT: &[&str] = &["neuwerk.io/management", "neuwerk.io.management"];
const TAG_NIC_DATAPLANE: &[&str] = &["neuwerk.io/dataplane", "neuwerk.io.dataplane"];
const TERMINATION_EVENT_TYPES: &[&str] = &[
    "terminate",
    "preempt",
    "redeploy",
    "reboot",
    "freeze",
    "deallocate",
    "scalein",
];

#[derive(Clone)]
pub struct AzureProvider {
    subscription_id: String,
    resource_group: String,
    vmss_name: String,
    client: reqwest::Client,
}

impl AzureProvider {
    pub fn new(subscription_id: String, resource_group: String, vmss_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("azure client");
        Self {
            subscription_id,
            resource_group,
            vmss_name,
            client,
        }
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    async fn token(&self) -> Result<String, CloudError> {
        let url = format!(
            "{}/identity/oauth2/token?api-version={}&resource=https%3A%2F%2Fmanagement.azure.com%2F",
            IMDS_BASE, IMDS_TOKEN_VERSION
        );
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
                "token request failed: {status}"
            )));
        }
        let payload: ImdsToken = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        Ok(payload.access_token)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: String) -> Result<T, CloudError> {
        let token = self.token().await?;
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        if !status.is_success() {
            let snippet = body.chars().take(4096).collect::<String>();
            return Err(CloudError::RequestFailed(format!(
                "request failed: {status}, body={snippet}"
            )));
        }
        serde_json::from_str::<T>(&body).map_err(|err| {
            let snippet = body.chars().take(4096).collect::<String>();
            CloudError::InvalidResponse(format!(
                "error decoding response body: {err}, body={snippet}"
            ))
        })
    }

    async fn fetch_nic(&self, nic_id: &str) -> Result<NicResource, CloudError> {
        let url = format!("{nic_id}?api-version={NETWORK_API_VERSION}");
        self.get_json(url).await
    }

    fn extract_nic_ips(nic: &NicResource) -> Vec<Ipv4Addr> {
        let mut ips = Vec::new();
        if let Some(configs) = nic
            .properties
            .as_ref()
            .and_then(|props| props.ip_configurations.as_ref())
        {
            for cfg in configs {
                if let Some(ip) = cfg
                    .properties
                    .as_ref()
                    .and_then(|props| props.private_ip_address.clone())
                    .and_then(|addr| addr.parse::<Ipv4Addr>().ok())
                {
                    ips.push(ip);
                }
            }
        }
        ips
    }

    fn nic_has_tag(nic: &NicResource, tags: &[&str]) -> bool {
        nic.tags
            .as_ref()
            .map_or(false, |map| tags.iter().any(|tag| map.contains_key(*tag)))
    }

    fn select_tagged_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        let mut mgmt_ip = None;
        let mut dataplane_ip = None;
        for nic in nics {
            let ips = AzureProvider::extract_nic_ips(nic);
            if ips.is_empty() {
                continue;
            }
            if mgmt_ip.is_none() && AzureProvider::nic_has_tag(nic, TAG_NIC_MANAGEMENT) {
                mgmt_ip = ips.first().copied();
            }
            if dataplane_ip.is_none() && AzureProvider::nic_has_tag(nic, TAG_NIC_DATAPLANE) {
                dataplane_ip = ips.first().copied();
            }
        }
        match (mgmt_ip, dataplane_ip) {
            (Some(mgmt_ip), Some(dataplane_ip)) => Ok((mgmt_ip, dataplane_ip)),
            _ => Err(CloudError::InvalidResponse(
                "missing tagged nic (neuwerk.io/management or neuwerk.io.management, neuwerk.io/dataplane or neuwerk.io.dataplane)".to_string(),
            )),
        }
    }

    fn select_named_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        let mut mgmt_ip = None;
        let mut dataplane_ip = None;
        for nic in nics {
            let nic_name = nic.name.as_deref().unwrap_or_default();
            let configs = nic
                .properties
                .as_ref()
                .and_then(|props| props.ip_configurations.as_ref());
            if let Some(configs) = configs {
                for cfg in configs {
                    let cfg_name = cfg.name.as_deref().unwrap_or_default();
                    let ip = cfg
                        .properties
                        .as_ref()
                        .and_then(|props| props.private_ip_address.clone())
                        .or_else(|| cfg.private_ip_address.clone())
                        .and_then(|addr| addr.parse::<Ipv4Addr>().ok());
                    let Some(ip) = ip else { continue };
                    if mgmt_ip.is_none() && (cfg_name == "mgmt-ipcfg" || nic_name.contains("mgmt0"))
                    {
                        mgmt_ip = Some(ip);
                    }
                    if dataplane_ip.is_none()
                        && (cfg_name == "data-ipcfg" || nic_name.contains("data0"))
                    {
                        dataplane_ip = Some(ip);
                    }
                }
            }
        }
        match (mgmt_ip, dataplane_ip) {
            (Some(mgmt_ip), Some(dataplane_ip)) => Ok((mgmt_ip, dataplane_ip)),
            _ => {
                for nic in nics {
                    let nic_name = nic.name.as_deref().unwrap_or("<unknown>");
                    let cfgs = nic
                        .properties
                        .as_ref()
                        .and_then(|props| props.ip_configurations.as_ref())
                        .map(|cfgs| {
                            cfgs.iter()
                                .map(|cfg| cfg.name.as_deref().unwrap_or("<no-name>"))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    eprintln!("azure integration: nic name={nic_name}, ipcfgs={:?}", cfgs);
                }
                Err(CloudError::InvalidResponse(
                    "missing mgmt/data nic by name (mgmt-ipcfg/data-ipcfg or mgmt0/data0)"
                        .to_string(),
                ))
            }
        }
    }

    fn select_mgmt_dataplane_ips(nics: &[NicResource]) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
        match AzureProvider::select_tagged_ips(nics) {
            Ok(pair) => Ok(pair),
            Err(err) => {
                eprintln!("azure integration: {err}; falling back to name-based NIC selection");
                AzureProvider::select_named_ips(nics)
            }
        }
    }

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

    fn deserialize_zones<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let zones = Option::<Vec<Option<String>>>::deserialize(deserializer)?;
        let Some(zones) = zones else {
            return Ok(None);
        };
        let filtered: Vec<String> = zones.into_iter().filter_map(|zone| zone).collect();
        if filtered.is_empty() {
            Ok(None)
        } else {
            Ok(Some(filtered))
        }
    }

    fn parse_tags(
        tag_string: Option<&str>,
        tag_map: Option<&HashMap<String, String>>,
    ) -> HashMap<String, String> {
        if let Some(tags) = tag_map {
            return tags.clone();
        }
        let mut parsed = HashMap::new();
        let Some(raw) = tag_string else {
            return parsed;
        };
        for entry in raw.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((key, value)) = entry.split_once(':').or_else(|| entry.split_once('=')) {
                parsed.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        parsed
    }

    fn parse_time(value: Option<&str>) -> i64 {
        let Some(raw) = value else {
            return 0;
        };
        OffsetDateTime::parse(raw, &Rfc3339)
            .map(|dt| dt.unix_timestamp())
            .unwrap_or(0)
    }

    async fn ensure_termination_notifications_enabled(
        &self,
        subscription_id: &str,
        resource_group: &str,
        vmss_name: &str,
    ) -> Result<(), CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmss_name}?api-version={COMPUTE_API_VERSION}",
        );
        let value: serde_json::Value = self.get_json(url).await?;
        let enabled = value
            .get("properties")
            .and_then(|value| value.get("virtualMachineProfile"))
            .and_then(|value| value.get("scheduledEventsProfile"))
            .and_then(|value| value.get("terminateNotificationProfile"))
            .and_then(|value| value.get("enable").or_else(|| value.get("enabled")))
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if enabled {
            Ok(())
        } else {
            Err(CloudError::InvalidResponse(
                "vmss termination notifications disabled (terminateNotificationProfile.enable != true)"
                    .to_string(),
            ))
        }
    }
}

#[async_trait]
impl CloudProvider for AzureProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
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
                let instance_id = self
                    .resolve_instance_id(&compute, subscription_id, resource_group, vmss_name)
                    .await?;
                self.list_vmss_nics(subscription_id, resource_group, vmss_name, &instance_id)
                    .await?
            } else {
                rg_nics
            }
        } else {
            let instance_id = self
                .resolve_instance_id(&compute, subscription_id, resource_group, vmss_name)
                .await?;
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
            id: compute.vm_id,
            name: compute.name,
            zone,
            created_at_epoch: AzureProvider::parse_time(compute.time_created.as_deref()),
            mgmt_ip: IpAddr::V4(mgmt_ip),
            dataplane_ip,
            tags,
            active: true,
        })
    }

    async fn discover_instances(
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
                            Err(err) => eprintln!(
                            "azure integration: vmss nic list failed for {} ({instance_id}): {err}",
                            entry.name
                        ),
                        }
                    }
                }
            }
            if nic_resources.is_empty() {
                let Some(resource_id) = entry.id.as_deref() else {
                    eprintln!(
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

    async fn discover_subnets(
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
                let tags = subnet.tags.clone().unwrap_or_else(|| vnet_tags.clone());
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
                    name: subnet.name.unwrap_or_default(),
                    zone: location.clone(),
                    cidr,
                    route_table_id,
                    tags,
                });
            }
        }
        Ok(subnets)
    }

    async fn get_route(
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

    async fn ensure_default_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        let existing = self.get_route(subnet, route_name).await?;
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

    async fn set_instance_protection(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        let url = format!(
            "{ARM_BASE}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachineScaleSets/{}/virtualMachines/{}?api-version={COMPUTE_API_VERSION}",
            self.subscription_id, self.resource_group, self.vmss_name, instance.id
        );
        let body = VmssVmUpdateRequest {
            properties: VmssVmUpdateProperties {
                protection_policy: VmssVmProtectionPolicy {
                    protect_from_scale_in: enabled,
                    protect_from_scale_set_actions: enabled,
                },
            },
        };
        let response = self
            .client
            .patch(url)
            .bearer_auth(self.token().await?)
            .json(&body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "instance protection update failed: {status}"
            )));
        }
        Ok(CapabilityResult::Applied)
    }

    async fn poll_termination_notice(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        let url = format!(
            "{}/scheduledevents?api-version={}",
            IMDS_BASE, IMDS_SCHEDULED_EVENTS_VERSION
        );
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
                "scheduled events request failed: {status}"
            )));
        }
        let payload: ScheduledEventsResponse = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(err.to_string()))?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for event in payload.events {
            if !event.is_termination() {
                continue;
            }
            if !event.applies_to(instance) {
                continue;
            }
            let deadline_epoch = event
                .not_before
                .as_deref()
                .and_then(|raw| OffsetDateTime::parse(raw, &Rfc2822).ok())
                .map(|dt| dt.unix_timestamp())
                .or_else(|| event.duration_in_seconds.map(|secs| now + secs as i64))
                .unwrap_or(now);
            return Ok(Some(TerminationEvent {
                id: event.event_id.clone(),
                instance_id: instance.id.clone(),
                deadline_epoch,
            }));
        }
        Ok(None)
    }

    async fn complete_termination_action(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        let url = format!(
            "{}/scheduledevents?api-version={}",
            IMDS_BASE, IMDS_SCHEDULED_EVENTS_VERSION
        );
        let body = ScheduledEventAck {
            start_requests: vec![ScheduledEventStartRequest {
                event_id: event.id.clone(),
            }],
        };
        let response = self
            .client
            .post(url)
            .header("Metadata", "true")
            .json(&body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(err.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "scheduled events acknowledge failed: {status}"
            )));
        }
        Ok(CapabilityResult::Applied)
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        IntegrationCapabilities {
            instance_protection: true,
            termination_notice: true,
            lifecycle_hook: false,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ImdsToken {
    access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsInstance {
    compute: ImdsCompute,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsCompute {
    vm_id: String,
    instance_id: Option<String>,
    name: String,
    location: String,
    zone: Option<String>,
    time_created: Option<String>,
    tags: Option<String>,
    subscription_id: Option<String>,
    resource_group_name: Option<String>,
    vm_scale_set_name: Option<String>,
    resource_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VmssInstanceList {
    value: Vec<VmssInstance>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmssInstance {
    id: Option<String>,
    name: String,
    instance_id: Option<String>,
    location: Option<String>,
    #[serde(default, deserialize_with = "AzureProvider::deserialize_zones")]
    zones: Option<Vec<String>>,
    time_created: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<VmssInstanceProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VmssInstanceProperties {
    network_profile: Option<NetworkProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkProfile {
    network_interfaces: Option<Vec<NetworkInterfaceRef>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkInterfaceRef {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VmssNicList {
    value: Vec<NetworkInterfaceRef>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NicResource {
    name: Option<String>,
    tags: Option<HashMap<String, String>>,
    virtual_machine: Option<NicVmRef>,
    properties: Option<NicProperties>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NicProperties {
    ip_configurations: Option<Vec<NicIpConfiguration>>,
    virtual_machine: Option<NicVmRef>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NicIpConfiguration {
    name: Option<String>,
    properties: Option<NicIpProperties>,
    #[serde(rename = "privateIPAddress")]
    private_ip_address: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NicIpProperties {
    #[serde(rename = "privateIPAddress")]
    private_ip_address: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct NicVmRef {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NicList {
    value: Vec<NicResource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetList {
    value: Vec<VnetResource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetResource {
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<VnetProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetProperties {
    subnets: Option<Vec<SubnetResource>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubnetResource {
    id: Option<String>,
    name: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<SubnetProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubnetProperties {
    address_prefix: Option<String>,
    address_prefixes: Option<Vec<String>>,
    route_table: Option<RouteTableRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteTableRef {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteResource {
    id: Option<String>,
    name: Option<String>,
    properties: Option<RouteProperties>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteProperties {
    next_hop_ip_address: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteRequest {
    properties: RouteRequestProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteRequestProperties {
    address_prefix: String,
    next_hop_type: String,
    next_hop_ip_address: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VmssVmUpdateRequest {
    properties: VmssVmUpdateProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VmssVmUpdateProperties {
    protection_policy: VmssVmProtectionPolicy,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VmssVmProtectionPolicy {
    protect_from_scale_in: bool,
    protect_from_scale_set_actions: bool,
}

#[derive(Debug, Deserialize)]
struct ScheduledEventsResponse {
    #[serde(rename = "Events", default)]
    events: Vec<ScheduledEvent>,
}

#[derive(Debug, Deserialize)]
struct ScheduledEvent {
    #[serde(rename = "EventId")]
    event_id: String,
    #[serde(rename = "EventType")]
    event_type: String,
    #[serde(rename = "EventStatus")]
    event_status: Option<String>,
    #[serde(rename = "Resources")]
    resources: Option<Vec<String>>,
    #[serde(rename = "NotBefore")]
    not_before: Option<String>,
    #[serde(rename = "DurationInSeconds")]
    duration_in_seconds: Option<i64>,
}

impl ScheduledEvent {
    fn is_termination(&self) -> bool {
        let status = self
            .event_status
            .as_deref()
            .unwrap_or("Scheduled")
            .to_ascii_lowercase();
        if status != "scheduled" && status != "started" {
            return false;
        }
        let event_type = self.event_type.to_ascii_lowercase();
        TERMINATION_EVENT_TYPES
            .iter()
            .any(|value| *value == event_type)
    }

    fn applies_to(&self, instance: &InstanceRef) -> bool {
        let Some(resources) = &self.resources else {
            return false;
        };
        resources
            .iter()
            .any(|resource| resource == &instance.name || resource == &instance.id)
    }
}

#[derive(Debug, Serialize)]
struct ScheduledEventAck {
    #[serde(rename = "StartRequests")]
    start_requests: Vec<ScheduledEventStartRequest>,
}

#[derive(Debug, Serialize)]
struct ScheduledEventStartRequest {
    #[serde(rename = "EventId")]
    event_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn nic_with_tags(tags: &[&str], ip: &str) -> NicResource {
        let mut map = HashMap::new();
        for tag in tags {
            map.insert((*tag).to_string(), "true".to_string());
        }
        NicResource {
            name: Some("nic-test".to_string()),
            tags: Some(map),
            virtual_machine: None,
            properties: Some(NicProperties {
                virtual_machine: None,
                ip_configurations: Some(vec![NicIpConfiguration {
                    name: Some("ipcfg-test".to_string()),
                    private_ip_address: None,
                    properties: Some(NicIpProperties {
                        private_ip_address: Some(ip.to_string()),
                    }),
                }]),
            }),
        }
    }

    #[test]
    fn nic_tag_enforcement_requires_both_tags() {
        let mgmt_only = vec![nic_with_tags(TAG_NIC_MANAGEMENT, "10.0.0.1")];
        assert!(AzureProvider::select_tagged_ips(&mgmt_only).is_err());

        let dataplane_only = vec![nic_with_tags(TAG_NIC_DATAPLANE, "10.0.1.1")];
        assert!(AzureProvider::select_tagged_ips(&dataplane_only).is_err());

        let both = vec![
            nic_with_tags(TAG_NIC_MANAGEMENT, "10.0.0.1"),
            nic_with_tags(TAG_NIC_DATAPLANE, "10.0.1.1"),
        ];
        let ips = AzureProvider::select_tagged_ips(&both).expect("tagged ips");
        assert_eq!(ips.0, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips.1, Ipv4Addr::new(10, 0, 1, 1));
    }

    #[test]
    fn scheduled_events_parse_and_match_instance() {
        let json = r#"{
            "DocumentIncarnation": 2,
            "Events": [
                {
                    "EventId": "C7061BAC-AFDC-4513-B24B-AA5F13A16123",
                    "EventStatus": "Scheduled",
                    "EventType": "Freeze",
                    "ResourceType": "VirtualMachine",
                    "Resources": ["WestNO_0", "WestNO_1"],
                    "NotBefore": "Mon, 11 Apr 2022 22:26:58 GMT",
                    "Description": "Virtual machine is being paused because of a memory-preserving Live Migration operation.",
                    "EventSource": "Platform",
                    "DurationInSeconds": 5
                }
            ]
        }"#;
        let payload: ScheduledEventsResponse =
            serde_json::from_str(json).expect("scheduled events parse");
        assert_eq!(payload.events.len(), 1);
        let event = &payload.events[0];
        assert_eq!(event.event_id, "C7061BAC-AFDC-4513-B24B-AA5F13A16123");
        assert!(event.is_termination());

        let instance = InstanceRef {
            id: "vm-id".to_string(),
            name: "WestNO_0".to_string(),
            zone: "zone-1".to_string(),
            created_at_epoch: 0,
            mgmt_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dataplane_ip: Ipv4Addr::new(10, 0, 1, 1),
            tags: HashMap::new(),
            active: true,
        };
        assert!(event.applies_to(&instance));

        let canceled = ScheduledEvent {
            event_id: "event-cancel".to_string(),
            event_type: "Freeze".to_string(),
            event_status: Some("Canceled".to_string()),
            resources: Some(vec!["WestNO_0".to_string()]),
            not_before: None,
            duration_in_seconds: None,
        };
        assert!(!canceled.is_termination());
    }

    #[test]
    fn scheduled_event_ack_serializes_start_requests() {
        let ack = ScheduledEventAck {
            start_requests: vec![ScheduledEventStartRequest {
                event_id: "event-1".to_string(),
            }],
        };
        let value = serde_json::to_value(&ack).expect("serialize ack");
        let start_requests = value
            .get("StartRequests")
            .and_then(|value| value.as_array())
            .expect("start requests");
        assert_eq!(start_requests.len(), 1);
        let event_id = start_requests[0]
            .get("EventId")
            .and_then(|value| value.as_str())
            .expect("event id");
        assert_eq!(event_id, "event-1");
    }
}
