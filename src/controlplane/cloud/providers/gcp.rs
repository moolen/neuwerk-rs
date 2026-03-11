use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::new_connection;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::controlplane::cloud::provider::{CloudError, CloudProvider};
use crate::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange, RouteRef,
    SubnetRef, TerminationEvent,
};

const METADATA_BASE: &str = "http://metadata.google.internal/computeMetadata/v1";
const COMPUTE_API_BASE: &str = "https://compute.googleapis.com/compute/v1";
const TERMINATION_EVENT_PREFIX: &str = "gcp-mig:";
const TERMINATION_NOTICE_SECS: i64 = 300;
const TERMINATING_ACTIONS: &[&str] = &["DELETING", "ABANDONING", "RECREATING"];

#[derive(Clone)]
pub struct GcpProvider {
    project: String,
    region: String,
    ig_name: String,
    client: reqwest::Client,
    token: Arc<Mutex<Option<GcpToken>>>,
    local_instance_name: Arc<Mutex<Option<String>>>,
    local_zone: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Clone)]
struct GcpToken {
    access_token: String,
    expiry_epoch: i64,
}

#[derive(Debug, Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct MigListManagedInstancesResponse {
    #[serde(rename = "managedInstances", default)]
    managed_instances: Vec<MigManagedInstance>,
}

#[derive(Debug, Clone, Deserialize)]
struct MigManagedInstance {
    instance: String,
    #[serde(rename = "currentAction", default)]
    current_action: String,
    #[serde(rename = "instanceStatus")]
    instance_status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GcpInstance {
    name: String,
    zone: String,
    #[serde(rename = "creationTimestamp")]
    creation_timestamp: Option<String>,
    status: Option<String>,
    labels: Option<HashMap<String, String>>,
    tags: Option<GcpInstanceTags>,
    #[serde(rename = "networkInterfaces", default)]
    network_interfaces: Vec<GcpNetworkInterface>,
}

#[derive(Debug, Deserialize)]
struct GcpInstanceTags {
    #[serde(default)]
    items: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct GcpNetworkInterface {
    #[serde(rename = "networkIP")]
    network_ip: Option<String>,
    subnetwork: Option<String>,
}

impl GcpProvider {
    pub fn new(project: String, region: String, ig_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            project,
            region,
            ig_name,
            client,
            token: Arc::new(Mutex::new(None)),
            local_instance_name: Arc::new(Mutex::new(None)),
            local_zone: Arc::new(Mutex::new(None)),
        }
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    async fn self_identity_provider(&self) -> Result<InstanceRef, CloudError> {
        let (instance_name, zone) = self.resolve_local_identity().await?;
        let instance = self.fetch_instance(&zone, &instance_name).await?;
        self.to_instance_ref(&instance, None)
    }

    async fn discover_instances_provider(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        let managed = self.list_managed_instances().await?;
        let mut instances = Vec::new();
        for item in managed {
            if item.instance_status.as_deref() != Some("RUNNING") {
                continue;
            }
            let Some((zone, instance_name)) = parse_instance_url(&item.instance) else {
                continue;
            };
            let instance = self.fetch_instance(&zone, &instance_name).await?;
            instances.push(self.to_instance_ref(&instance, Some(item.current_action.as_str()))?);
        }
        Ok(instances)
    }

    async fn discover_subnets_provider(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        // GCP MIG integration is lifecycle-only in ILB steering mode.
        // Route ownership stays external to the firewall integration.
        Ok(Vec::new())
    }

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

    async fn set_instance_protection_provider(
        &self,
        _instance: &InstanceRef,
        _enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        Ok(CapabilityResult::Unsupported)
    }

    async fn poll_termination_notice_provider(
        &self,
        _instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        let local_name = self.local_instance_name().await?;
        let managed = self.list_managed_instances().await?;
        let maybe_state = managed.into_iter().find(|item| {
            parse_instance_url(&item.instance)
                .map(|(_, name)| name == local_name)
                .unwrap_or(false)
        });
        let Some(state) = maybe_state else {
            return Ok(None);
        };
        if !is_terminating_action(&state.current_action) {
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc().unix_timestamp();
        Ok(Some(TerminationEvent {
            id: termination_event_id(&local_name),
            instance_id: local_name,
            deadline_epoch: now + TERMINATION_NOTICE_SECS,
        }))
    }

    async fn complete_termination_action_provider(
        &self,
        _event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        // GCP MIG does not require explicit lifecycle completion ACK.
        Ok(CapabilityResult::Applied)
    }

    fn capabilities_provider(&self) -> IntegrationCapabilities {
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        }
    }

    async fn list_managed_instances(&self) -> Result<Vec<MigManagedInstance>, CloudError> {
        if self.ig_name.is_empty() {
            return Err(CloudError::InvalidResponse(
                "gcp mig name is empty".to_string(),
            ));
        }
        let project = self.project_id().await?;

        let mut attempts: Vec<String> = Vec::new();
        let mut seen = HashSet::new();

        if !self.region.is_empty() {
            attempts.push(format!(
                "{COMPUTE_API_BASE}/projects/{project}/regions/{}/instanceGroupManagers/{}/listManagedInstances",
                self.region, self.ig_name
            ));
            seen.insert(format!("region:{}", self.region));
        }

        let cached_zone = self.local_zone.lock().await.clone();
        let metadata_zone = if cached_zone.is_some() {
            None
        } else {
            self.local_zone_metadata().await.ok()
        };
        if let Some(local_zone) = cached_zone.or(metadata_zone) {
            if seen.insert(format!("zone:{local_zone}")) {
                attempts.push(format!(
                    "{COMPUTE_API_BASE}/projects/{project}/zones/{local_zone}/instanceGroupManagers/{}/listManagedInstances",
                    self.ig_name
                ));
            }
        }

        let mut last_err: Option<CloudError> = None;
        for url in attempts {
            match self
                .compute_post_json::<MigListManagedInstancesResponse>(&url, &serde_json::json!({}))
                .await
            {
                Ok(response) => return Ok(response.managed_instances),
                Err(CloudError::RequestFailed(msg))
                    if msg.contains("404")
                        || msg.contains("notFound")
                        || msg.contains("Not Found") =>
                {
                    last_err = Some(CloudError::RequestFailed(msg));
                    continue;
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_err.unwrap_or_else(|| {
            CloudError::InvalidResponse(
                "unable to resolve MIG endpoint (regional or zonal)".to_string(),
            )
        }))
    }

    async fn fetch_instance(
        &self,
        zone: &str,
        instance_name: &str,
    ) -> Result<GcpInstance, CloudError> {
        let project = self.project_id().await?;
        let url =
            format!("{COMPUTE_API_BASE}/projects/{project}/zones/{zone}/instances/{instance_name}");
        self.compute_get_json(&url).await
    }

    fn to_instance_ref(
        &self,
        instance: &GcpInstance,
        _current_action: Option<&str>,
    ) -> Result<InstanceRef, CloudError> {
        let (mgmt_ip, dataplane_ip) =
            select_management_and_dataplane_ips(&instance.network_interfaces)?;
        let zone = trailing_segment(&instance.zone).unwrap_or_default();
        let created_at_epoch = instance
            .creation_timestamp
            .as_deref()
            .map(parse_epoch)
            .unwrap_or(0);
        let status = instance.status.as_deref().unwrap_or_default();
        let active = status.eq_ignore_ascii_case("RUNNING");

        let tags = build_gcp_tags(instance.labels.as_ref(), instance.tags.as_ref());

        Ok(InstanceRef {
            // Keep ID aligned with MIG instance naming and local metadata name.
            id: instance.name.clone(),
            name: instance.name.clone(),
            zone,
            created_at_epoch,
            mgmt_ip: IpAddr::V4(mgmt_ip),
            dataplane_ip,
            tags,
            active,
        })
    }

    async fn project_id(&self) -> Result<String, CloudError> {
        if !self.project.is_empty() {
            return Ok(self.project.clone());
        }
        let value = self.metadata_get("project/project-id").await?;
        let project = value.trim().to_string();
        if project.is_empty() {
            return Err(CloudError::InvalidResponse(
                "gcp metadata project-id empty".to_string(),
            ));
        }
        Ok(project)
    }

    async fn local_instance_name(&self) -> Result<String, CloudError> {
        if let Some(cached) = self.local_instance_name.lock().await.clone() {
            return Ok(cached);
        }
        let (name, _) = self.resolve_local_identity().await?;
        Ok(name)
    }

    async fn local_instance_name_metadata(&self) -> Result<String, CloudError> {
        let value = self.metadata_get("instance/name").await?;
        let name = value.trim().to_string();
        if name.is_empty() {
            return Err(CloudError::InvalidResponse(
                "gcp metadata instance/name empty".to_string(),
            ));
        }
        Ok(name)
    }

    async fn local_zone_metadata(&self) -> Result<String, CloudError> {
        let value = self.metadata_get("instance/zone").await?;
        let zone = trailing_segment(&value).unwrap_or_default();
        if zone.is_empty() {
            return Err(CloudError::InvalidResponse(
                "gcp metadata instance/zone empty".to_string(),
            ));
        }
        Ok(zone)
    }

    async fn resolve_local_identity(&self) -> Result<(String, String), CloudError> {
        if let (Some(name), Some(zone)) = (
            self.local_instance_name.lock().await.clone(),
            self.local_zone.lock().await.clone(),
        ) {
            return Ok((name, zone));
        }

        if let (Ok(name), Ok(zone)) = (
            self.local_instance_name_metadata().await,
            self.local_zone_metadata().await,
        ) {
            self.cache_local_identity(&name, &zone).await;
            return Ok((name, zone));
        }

        let (name, zone) = self.resolve_local_identity_from_inventory().await?;
        self.cache_local_identity(&name, &zone).await;
        Ok((name, zone))
    }

    async fn cache_local_identity(&self, name: &str, zone: &str) {
        *self.local_instance_name.lock().await = Some(name.to_string());
        *self.local_zone.lock().await = Some(zone.to_string());
    }

    async fn resolve_local_identity_from_inventory(&self) -> Result<(String, String), CloudError> {
        let local_ips = self.local_ipv4_addrs().await?;
        if local_ips.is_empty() {
            return Err(CloudError::NotFound(
                "unable to discover local IPv4 addresses".to_string(),
            ));
        }

        let managed = self.list_managed_instances().await?;
        let mut matches: Vec<(String, String)> = Vec::new();
        for item in managed {
            let Some((zone, instance_name)) = parse_instance_url(&item.instance) else {
                continue;
            };
            let instance = self.fetch_instance(&zone, &instance_name).await?;
            if instance_has_local_ip(&instance, &local_ips) {
                matches.push((instance_name, zone));
            }
        }

        if matches.len() == 1 {
            return Ok(matches.remove(0));
        }
        if matches.is_empty() {
            return Err(CloudError::NotFound(
                "unable to match local IPs to MIG managed instance".to_string(),
            ));
        }

        matches.sort();
        Err(CloudError::InvalidResponse(format!(
            "multiple MIG instances matched local IPs: {}",
            matches
                .into_iter()
                .map(|(name, zone)| format!("{name}@{zone}"))
                .collect::<Vec<_>>()
                .join(",")
        )))
    }

    async fn local_ipv4_addrs(&self) -> Result<HashSet<Ipv4Addr>, CloudError> {
        let (connection, handle, _) = new_connection()
            .map_err(|err| CloudError::RequestFailed(format!("gcp local netlink: {err}")))?;
        let task = tokio::spawn(connection);

        let mut link_names: HashMap<u32, String> = HashMap::new();
        let mut links = handle.link().get().execute();
        while let Some(msg) = links.try_next().await.map_err(|err| {
            CloudError::RequestFailed(format!("gcp local netlink link list: {err}"))
        })? {
            let ifname = msg.attributes.iter().find_map(|attr| match attr {
                LinkAttribute::IfName(name) => Some(name.clone()),
                _ => None,
            });
            if let Some(ifname) = ifname {
                link_names.insert(msg.header.index, ifname);
            }
        }

        let mut addrs = handle.address().get().execute();
        let mut ips = HashSet::new();
        while let Some(msg) = addrs.try_next().await.map_err(|err| {
            CloudError::RequestFailed(format!("gcp local netlink addr list: {err}"))
        })? {
            let ifname = match link_names.get(&msg.header.index) {
                Some(name) => name.as_str(),
                None => continue,
            };
            if ifname == "lo" {
                continue;
            }
            for attr in msg.attributes {
                match attr {
                    AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                        if let IpAddr::V4(v4) = ip {
                            ips.insert(v4);
                        }
                    }
                    _ => {}
                }
            }
        }
        task.abort();
        Ok(ips)
    }

    async fn metadata_get(&self, path: &str) -> Result<String, CloudError> {
        let url = format!("{METADATA_BASE}/{path}");
        let response = self
            .client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("gcp metadata {path}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "gcp metadata {path} failed: {status}"
            )));
        }
        response
            .text()
            .await
            .map_err(|err| CloudError::InvalidResponse(format!("gcp metadata {path} body: {err}")))
    }

    async fn access_token(&self) -> Result<String, CloudError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(cached) = self.token.lock().await.clone() {
            if cached.expiry_epoch > now + 60 {
                return Ok(cached.access_token);
            }
        }

        let url = format!("{METADATA_BASE}/instance/service-accounts/default/token");
        let response = self
            .client
            .get(url)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("gcp token request: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "gcp token request failed: {status}"
            )));
        }
        let token: MetadataTokenResponse = response
            .json()
            .await
            .map_err(|err| CloudError::InvalidResponse(format!("gcp token decode: {err}")))?;
        let expiry_epoch = now + token.expires_in.max(60);
        let cached = GcpToken {
            access_token: token.access_token,
            expiry_epoch,
        };
        let access_token = cached.access_token.clone();
        *self.token.lock().await = Some(cached);
        Ok(access_token)
    }

    async fn compute_get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, CloudError> {
        let token = self.access_token().await?;
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("gcp get request: {err}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable-body>".to_string());
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "gcp get request failed: {status}: {}",
                abbreviate(&body, 800)
            )));
        }
        serde_json::from_str(&body)
            .map_err(|err| CloudError::InvalidResponse(format!("gcp get decode: {err}")))
    }

    async fn compute_post_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T, CloudError> {
        let token = self.access_token().await?;
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("gcp post request: {err}")))?;
        let status = response.status();
        let raw = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable-body>".to_string());
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "gcp post request failed: {status}: {}",
                abbreviate(&raw, 800)
            )));
        }
        serde_json::from_str(&raw)
            .map_err(|err| CloudError::InvalidResponse(format!("gcp post decode: {err}")))
    }
}

#[async_trait]
impl CloudProvider for GcpProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
        self.self_identity_provider().await
    }

    async fn discover_instances(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        let instances = self.discover_instances_provider(filter).await?;
        Ok(instances
            .into_iter()
            .filter(|instance| filter.matches(&instance.tags))
            .collect())
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
        self.set_instance_protection_provider(instance, enabled)
            .await
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

fn parse_instance_url(value: &str) -> Option<(String, String)> {
    let zone = between_segment(value, "zones")?;
    let name = between_segment(value, "instances")?;
    Some((zone, name))
}

fn between_segment(value: &str, segment: &str) -> Option<String> {
    let parts: Vec<&str> = value.split('/').collect();
    for idx in 0..parts.len() {
        if parts[idx] != segment {
            continue;
        }
        if idx + 1 < parts.len() {
            let next = parts[idx + 1].trim();
            if !next.is_empty() {
                return Some(next.to_string());
            }
        }
    }
    None
}

fn trailing_segment(value: &str) -> Option<String> {
    value
        .split('/')
        .rev()
        .map(str::trim)
        .find(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
}

fn select_management_and_dataplane_ips(
    interfaces: &[GcpNetworkInterface],
) -> Result<(Ipv4Addr, Ipv4Addr), CloudError> {
    let mut mgmt_ip = None;
    let mut dataplane_ip = None;

    for iface in interfaces {
        let Some(ip) = iface
            .network_ip
            .as_deref()
            .and_then(|raw| raw.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        let subnet = iface
            .subnetwork
            .as_deref()
            .and_then(trailing_segment)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if mgmt_ip.is_none() && (subnet.contains("mgmt") || subnet.contains("management")) {
            mgmt_ip = Some(ip);
        }
        if dataplane_ip.is_none() && (subnet.contains("data") || subnet.contains("dataplane")) {
            dataplane_ip = Some(ip);
        }
    }

    let parsed_ips: Vec<Ipv4Addr> = interfaces
        .iter()
        .filter_map(|iface| iface.network_ip.as_deref())
        .filter_map(|raw| raw.parse::<Ipv4Addr>().ok())
        .collect();

    if dataplane_ip.is_none() {
        dataplane_ip = parsed_ips.first().copied();
    }
    if mgmt_ip.is_none() {
        mgmt_ip = parsed_ips
            .get(1)
            .copied()
            .or_else(|| parsed_ips.first().copied());
    }

    let mgmt_ip = mgmt_ip.ok_or_else(|| {
        CloudError::InvalidResponse("instance missing management nic ip".to_string())
    })?;
    let dataplane_ip = dataplane_ip.ok_or_else(|| {
        CloudError::InvalidResponse("instance missing dataplane nic ip".to_string())
    })?;
    Ok((mgmt_ip, dataplane_ip))
}

fn instance_has_local_ip(instance: &GcpInstance, local_ips: &HashSet<Ipv4Addr>) -> bool {
    instance
        .network_interfaces
        .iter()
        .filter_map(|iface| iface.network_ip.as_deref())
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .any(|ip| local_ips.contains(&ip))
}

fn build_gcp_tags(
    labels: Option<&HashMap<String, String>>,
    tags: Option<&GcpInstanceTags>,
) -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Some(labels) = labels {
        for (key, value) in labels {
            out.insert(key.clone(), value.clone());
            if let Some(rest) = key.strip_prefix("neuwerk-io-") {
                out.insert(format!("neuwerk.io/{rest}"), value.clone());
                out.insert(format!("neuwerk.io.{rest}"), value.clone());
            }
            if let Some(rest) = key.strip_prefix("neuwerk.io.") {
                out.insert(format!("neuwerk.io/{rest}"), value.clone());
            }
        }
    }
    if let Some(tags) = tags {
        for item in &tags.items {
            out.insert(format!("gcp.tag/{item}"), "true".to_string());
        }
    }
    out
}

fn parse_epoch(raw: &str) -> i64 {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map(|value| value.unix_timestamp())
        .unwrap_or(0)
}

fn is_terminating_action(action: &str) -> bool {
    TERMINATING_ACTIONS
        .iter()
        .any(|value| action.eq_ignore_ascii_case(value))
}

fn termination_event_id(instance_name: &str) -> String {
    format!("{TERMINATION_EVENT_PREFIX}{instance_name}")
}

fn abbreviate(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_string();
    }
    let mut truncated = value.chars().take(limit).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_instance_url_extracts_zone_and_name() {
        let value = "https://www.googleapis.com/compute/v1/projects/demo/zones/us-central1-a/instances/fw-1";
        let parsed = parse_instance_url(value).expect("instance url");
        assert_eq!(parsed.0, "us-central1-a");
        assert_eq!(parsed.1, "fw-1");
    }

    #[test]
    fn select_ips_prefers_named_subnets() {
        let interfaces = vec![
            GcpNetworkInterface {
                network_ip: Some("10.10.2.5".to_string()),
                subnetwork: Some(
                    "https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1/subnetworks/dataplane-subnet".to_string(),
                ),
            },
            GcpNetworkInterface {
                network_ip: Some("10.10.1.5".to_string()),
                subnetwork: Some(
                    "https://www.googleapis.com/compute/v1/projects/demo/regions/us-central1/subnetworks/mgmt-subnet".to_string(),
                ),
            },
        ];

        let (mgmt, dataplane) =
            select_management_and_dataplane_ips(&interfaces).expect("selected ips");
        assert_eq!(mgmt, "10.10.1.5".parse::<Ipv4Addr>().expect("mgmt parse"));
        assert_eq!(
            dataplane,
            "10.10.2.5".parse::<Ipv4Addr>().expect("dataplane parse")
        );
    }

    #[test]
    fn build_tags_adds_neuwerk_label_aliases() {
        let mut labels = HashMap::new();
        labels.insert("neuwerk-io-cluster".to_string(), "neuwerk".to_string());
        labels.insert("neuwerk-io-role".to_string(), "dataplane".to_string());
        let tags = build_gcp_tags(Some(&labels), None);
        assert_eq!(tags.get("neuwerk.io/cluster"), Some(&"neuwerk".to_string()));
        assert_eq!(tags.get("neuwerk.io/role"), Some(&"dataplane".to_string()));
    }

    #[test]
    fn terminating_action_detection_is_case_insensitive() {
        assert!(is_terminating_action("deleting"));
        assert!(is_terminating_action("RECREATING"));
        assert!(!is_terminating_action("NONE"));
    }

    #[test]
    fn instance_has_local_ip_matches_any_interface_ip() {
        let instance = GcpInstance {
            name: "fw-1".to_string(),
            zone: "projects/demo/zones/us-central1-a".to_string(),
            creation_timestamp: None,
            status: Some("RUNNING".to_string()),
            labels: None,
            tags: None,
            network_interfaces: vec![
                GcpNetworkInterface {
                    network_ip: Some("10.30.1.5".to_string()),
                    subnetwork: Some("mgmt".to_string()),
                },
                GcpNetworkInterface {
                    network_ip: Some("10.30.2.5".to_string()),
                    subnetwork: Some("data".to_string()),
                },
            ],
        };
        let local_ips = HashSet::from([
            "10.30.2.5".parse::<Ipv4Addr>().expect("dataplane"),
            "10.0.0.1".parse::<Ipv4Addr>().expect("extra"),
        ]);
        assert!(instance_has_local_ip(&instance, &local_ips));
    }

    #[test]
    fn instance_has_local_ip_returns_false_without_match() {
        let instance = GcpInstance {
            name: "fw-2".to_string(),
            zone: "projects/demo/zones/us-central1-a".to_string(),
            creation_timestamp: None,
            status: Some("RUNNING".to_string()),
            labels: None,
            tags: None,
            network_interfaces: vec![GcpNetworkInterface {
                network_ip: Some("10.30.1.6".to_string()),
                subnetwork: Some("mgmt".to_string()),
            }],
        };
        let local_ips = HashSet::from(["10.30.2.5".parse::<Ipv4Addr>().expect("dataplane")]);
        assert!(!instance_has_local_ip(&instance, &local_ips));
    }
}
