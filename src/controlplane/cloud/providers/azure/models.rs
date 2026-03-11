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

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetList {
    value: Vec<VnetResource>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetResource {
    location: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<VnetProperties>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VnetProperties {
    subnets: Option<Vec<SubnetResource>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubnetResource {
    id: Option<String>,
    name: Option<String>,
    tags: Option<HashMap<String, String>>,
    properties: Option<SubnetProperties>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SubnetProperties {
    address_prefix: Option<String>,
    address_prefixes: Option<Vec<String>>,
    route_table: Option<RouteTableRef>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteTableRef {
    id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteResource {
    id: Option<String>,
    name: Option<String>,
    properties: Option<RouteProperties>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RouteProperties {
    next_hop_ip_address: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RouteRequest {
    properties: RouteRequestProperties,
}

#[allow(dead_code)]
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
        let instance_name = instance.name.to_ascii_lowercase();
        let instance_id = instance.id.to_ascii_lowercase();
        let instance_name_suffix = instance_name
            .rsplit('_')
            .next()
            .unwrap_or(instance_name.as_str());
        resources.iter().any(|resource| {
            let resource = resource.trim().to_ascii_lowercase();
            if resource == instance_name
                || resource == instance_id
                || resource.ends_with(&format!("/{instance_name}"))
                || resource.ends_with(&format!("/{instance_id}"))
            {
                return true;
            }
            let path_tail = resource.rsplit('/').next().unwrap_or(resource.as_str());
            if path_tail == instance_name
                || path_tail == instance_id
                || path_tail == instance_name_suffix
            {
                return true;
            }
            let underscore_tail = resource.rsplit('_').next().unwrap_or(resource.as_str());
            underscore_tail == instance_id || underscore_tail == instance_name_suffix
        })
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
