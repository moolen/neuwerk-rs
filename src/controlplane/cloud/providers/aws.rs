use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use roxmltree::Document;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::controlplane::cloud::provider::{CloudError, CloudProvider};
use crate::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange, RouteRef,
    SubnetRef, TerminationEvent,
};

const IMDS_BASE: &str = "http://169.254.169.254/latest";
const EC2_API_VERSION: &str = "2016-11-15";
const AUTOSCALING_API_VERSION: &str = "2011-01-01";
const LIFECYCLE_TRANSITION_TERMINATING: &str = "autoscaling:EC2_INSTANCE_TERMINATING";
const LIFECYCLE_WAIT_STATE: &str = "terminating:wait";
const LIFECYCLE_EVENT_PREFIX: &str = "aws-asg-hook:";

const TAG_NIC_MANAGEMENT: &[&str] = &["neuwerk.io/management", "neuwerk.io.management"];
const TAG_NIC_DATAPLANE: &[&str] = &["neuwerk.io/dataplane", "neuwerk.io.dataplane"];

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AwsProvider {
    region: String,
    asg_name: String,
    client: reqwest::Client,
    local_instance_id: Arc<Mutex<Option<String>>>,
    credentials: Arc<Mutex<Option<AwsCredentials>>>,
}

#[derive(Debug, Clone)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration_epoch: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImdsRoleCredentials {
    code: String,
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct AsgInstanceState {
    instance_id: String,
    lifecycle_state: String,
    health_status: String,
}

#[derive(Debug, Clone)]
struct AsgLifecycleInfo {
    asg_name: String,
    lifecycle_state: String,
}

#[derive(Debug, Clone)]
struct LifecycleHookInfo {
    name: String,
    transition: String,
    heartbeat_timeout_secs: i64,
}

#[derive(Debug, Clone)]
struct Ec2InstanceData {
    id: String,
    name: String,
    zone: String,
    created_at_epoch: i64,
    tags: HashMap<String, String>,
    state: String,
    interfaces: Vec<Ec2InterfaceRef>,
}

#[derive(Debug, Clone)]
struct Ec2InterfaceRef {
    id: String,
    private_ip: Option<Ipv4Addr>,
    device_index: Option<u32>,
}

#[derive(Debug, Clone)]
struct Ec2NetworkInterfaceData {
    id: String,
    private_ip: Option<Ipv4Addr>,
    attachment_device_index: Option<u32>,
    tags: HashMap<String, String>,
}

impl AwsProvider {
    pub fn new(region: String, _vpc_id: String, asg_name: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            region,
            asg_name,
            client,
            local_instance_id: Arc::new(Mutex::new(None)),
            credentials: Arc::new(Mutex::new(None)),
        }
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }

    async fn self_identity_provider(&self) -> Result<InstanceRef, CloudError> {
        let instance_id = self.local_instance_id().await?;
        let instances = self
            .describe_instances_by_ids(&[instance_id.clone()])
            .await?;
        let instance = instances
            .into_iter()
            .find(|entry| entry.id == instance_id)
            .ok_or_else(|| CloudError::NotFound(format!("instance {instance_id}")))?;
        let interface_ids: Vec<String> = instance
            .interfaces
            .iter()
            .map(|iface| iface.id.clone())
            .collect();
        let interfaces = self
            .describe_network_interfaces_by_ids(&interface_ids)
            .await?;
        let interface_map: HashMap<String, Ec2NetworkInterfaceData> = interfaces
            .into_iter()
            .map(|iface| (iface.id.clone(), iface))
            .collect();
        self.to_instance_ref(&instance, None, None, &interface_map)
    }

    async fn discover_instances_provider(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        let members = self.describe_asg_members().await?;
        if members.is_empty() {
            return Ok(Vec::new());
        }

        let instance_ids: Vec<String> = members
            .iter()
            .map(|member| member.instance_id.clone())
            .collect();
        let lifecycle_by_id: HashMap<String, AsgInstanceState> = members
            .iter()
            .map(|member| (member.instance_id.clone(), member.clone()))
            .collect();

        let ec2_instances = self.describe_instances_by_ids(&instance_ids).await?;
        let interface_ids: Vec<String> = ec2_instances
            .iter()
            .flat_map(|instance| instance.interfaces.iter().map(|iface| iface.id.clone()))
            .collect();
        let interface_map: HashMap<String, Ec2NetworkInterfaceData> = self
            .describe_network_interfaces_by_ids(&interface_ids)
            .await?
            .into_iter()
            .map(|iface| (iface.id.clone(), iface))
            .collect();

        let mut instances = Vec::new();
        for instance in ec2_instances {
            let lifecycle = lifecycle_by_id.get(&instance.id);
            let lifecycle_state = lifecycle.map(|value| value.lifecycle_state.as_str());
            let health_status = lifecycle.map(|value| value.health_status.as_str());
            match self.to_instance_ref(&instance, lifecycle_state, health_status, &interface_map) {
                Ok(item) => instances.push(item),
                Err(CloudError::InvalidResponse(msg)) if is_transient_missing_nic_error(&msg) => {
                    // During ASG terminating transitions, ENIs can be detached between
                    // autoscaling and EC2 describe calls. Skip those transient entries
                    // instead of failing the full reconcile cycle.
                    tracing::warn!("aws discover instances: skipping {}: {msg}", instance.id);
                }
                Err(err) => return Err(err),
            }
        }
        Ok(instances)
    }

    async fn discover_subnets_provider(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        // AWS ASG integration is lifecycle-only in GWLB/NLB steering mode.
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
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        if self.asg_name.is_empty() {
            return Ok(CapabilityResult::Unsupported);
        }
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "SetInstanceProtection".to_string());
        params.insert("AutoScalingGroupName".to_string(), self.asg_name.clone());
        params.insert("InstanceIds.member.1".to_string(), instance.id.to_string());
        params.insert(
            "ProtectedFromScaleIn".to_string(),
            if enabled {
                "true".to_string()
            } else {
                "false".to_string()
            },
        );
        let _ = self.autoscaling_query(params).await?;
        Ok(CapabilityResult::Applied)
    }

    async fn poll_termination_notice_provider(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        if self.asg_name.is_empty() {
            return Ok(None);
        }

        let Some(status) = self.describe_autoscaling_instance(&instance.id).await? else {
            return Ok(None);
        };

        if status.asg_name != self.asg_name {
            return Ok(None);
        }

        if status.lifecycle_state.trim().to_ascii_lowercase() != LIFECYCLE_WAIT_STATE {
            return Ok(None);
        }

        let hook = self
            .describe_terminating_lifecycle_hook()
            .await?
            .ok_or_else(|| {
                CloudError::InvalidResponse(
                    "asg in terminating:wait without terminating lifecycle hook".to_string(),
                )
            })?;

        let now = OffsetDateTime::now_utc().unix_timestamp();
        let timeout = hook.heartbeat_timeout_secs.max(30);
        let event = TerminationEvent {
            id: lifecycle_event_id(&hook.name),
            instance_id: instance.id.clone(),
            deadline_epoch: now + timeout,
        };
        Ok(Some(event))
    }

    async fn complete_termination_action_provider(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        let Some(hook_name) = lifecycle_event_hook(&event.id) else {
            return Ok(CapabilityResult::Unsupported);
        };

        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "CompleteLifecycleAction".to_string());
        params.insert("AutoScalingGroupName".to_string(), self.asg_name.clone());
        params.insert("LifecycleActionResult".to_string(), "CONTINUE".to_string());
        params.insert("LifecycleHookName".to_string(), hook_name.to_string());
        params.insert("InstanceId".to_string(), event.instance_id.clone());

        match self.autoscaling_query(params).await {
            Ok(_) => Ok(CapabilityResult::Applied),
            Err(CloudError::RequestFailed(msg))
                if msg.contains("No active Lifecycle Action found") =>
            {
                Ok(CapabilityResult::Applied)
            }
            Err(err) => Err(err),
        }
    }

    async fn record_termination_heartbeat_provider(
        &self,
        event: &TerminationEvent,
    ) -> Result<Option<i64>, CloudError> {
        let Some(hook_name) = lifecycle_event_hook(&event.id) else {
            return Ok(None);
        };
        if self.asg_name.is_empty() {
            return Ok(None);
        }

        let hook = self
            .describe_terminating_lifecycle_hook()
            .await?
            .ok_or_else(|| {
                CloudError::InvalidResponse("asg missing terminating lifecycle hook".to_string())
            })?;
        let timeout = hook.heartbeat_timeout_secs.max(30);

        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "RecordLifecycleActionHeartbeat".to_string(),
        );
        params.insert("AutoScalingGroupName".to_string(), self.asg_name.clone());
        params.insert("LifecycleHookName".to_string(), hook_name.to_string());
        params.insert("InstanceId".to_string(), event.instance_id.clone());

        match self.autoscaling_query(params).await {
            Ok(_) => {
                let now = OffsetDateTime::now_utc().unix_timestamp();
                Ok(Some(now + timeout))
            }
            Err(CloudError::RequestFailed(msg))
                if msg.contains("No active Lifecycle Action found") =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    fn capabilities_provider(&self) -> IntegrationCapabilities {
        IntegrationCapabilities {
            instance_protection: true,
            termination_notice: true,
            lifecycle_hook: true,
        }
    }

    async fn describe_asg_members(&self) -> Result<Vec<AsgInstanceState>, CloudError> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "DescribeAutoScalingGroups".to_string(),
        );
        params.insert(
            "AutoScalingGroupNames.member.1".to_string(),
            self.asg_name.clone(),
        );
        let body = self.autoscaling_query(params).await?;
        parse_asg_members(&body, &self.asg_name)
    }

    async fn describe_autoscaling_instance(
        &self,
        instance_id: &str,
    ) -> Result<Option<AsgLifecycleInfo>, CloudError> {
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "DescribeAutoScalingInstances".to_string(),
        );
        params.insert("InstanceIds.member.1".to_string(), instance_id.to_string());
        let body = self.autoscaling_query(params).await?;
        Ok(parse_autoscaling_instance_status(&body, instance_id))
    }

    async fn describe_terminating_lifecycle_hook(
        &self,
    ) -> Result<Option<LifecycleHookInfo>, CloudError> {
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DescribeLifecycleHooks".to_string());
        params.insert("AutoScalingGroupName".to_string(), self.asg_name.clone());
        let body = self.autoscaling_query(params).await?;
        let mut hooks = parse_lifecycle_hooks(&body)?;
        hooks.retain(|hook| {
            hook.transition
                .eq_ignore_ascii_case(LIFECYCLE_TRANSITION_TERMINATING)
        });
        hooks.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(hooks.into_iter().next())
    }

    async fn describe_instances_by_ids(
        &self,
        instance_ids: &[String],
    ) -> Result<Vec<Ec2InstanceData>, CloudError> {
        if instance_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut params = BTreeMap::new();
        params.insert("Action".to_string(), "DescribeInstances".to_string());
        for (idx, instance_id) in instance_ids.iter().enumerate() {
            params.insert(format!("InstanceId.{}", idx + 1), instance_id.clone());
        }
        let body = self.ec2_query(params).await?;
        parse_ec2_instances(&body)
    }

    async fn describe_network_interfaces_by_ids(
        &self,
        interface_ids: &[String],
    ) -> Result<Vec<Ec2NetworkInterfaceData>, CloudError> {
        if interface_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut params = BTreeMap::new();
        params.insert(
            "Action".to_string(),
            "DescribeNetworkInterfaces".to_string(),
        );
        for (idx, iface_id) in interface_ids.iter().enumerate() {
            params.insert(format!("NetworkInterfaceId.{}", idx + 1), iface_id.clone());
        }
        let body = self.ec2_query(params).await?;
        parse_network_interfaces(&body)
    }

    fn to_instance_ref(
        &self,
        instance: &Ec2InstanceData,
        _lifecycle_state: Option<&str>,
        health_status: Option<&str>,
        interface_map: &HashMap<String, Ec2NetworkInterfaceData>,
    ) -> Result<InstanceRef, CloudError> {
        let mut mgmt_ip = None;
        let mut dataplane_ip = None;

        for iface_ref in &instance.interfaces {
            let detail = interface_map.get(&iface_ref.id);
            let ip = detail
                .and_then(|item| item.private_ip)
                .or(iface_ref.private_ip);
            let Some(ip) = ip else { continue };

            if mgmt_ip.is_none() {
                if let Some(item) = detail {
                    if tag_enabled(&item.tags, TAG_NIC_MANAGEMENT) {
                        mgmt_ip = Some(ip);
                    }
                }
            }
            if dataplane_ip.is_none() {
                if let Some(item) = detail {
                    if tag_enabled(&item.tags, TAG_NIC_DATAPLANE) {
                        dataplane_ip = Some(ip);
                    }
                }
            }
        }

        for iface_ref in &instance.interfaces {
            let detail = interface_map.get(&iface_ref.id);
            let ip = detail
                .and_then(|item| item.private_ip)
                .or(iface_ref.private_ip);
            let Some(ip) = ip else { continue };
            let device_index = detail
                .and_then(|item| item.attachment_device_index)
                .or(iface_ref.device_index);
            match device_index {
                Some(0) if mgmt_ip.is_none() => mgmt_ip = Some(ip),
                Some(1) if dataplane_ip.is_none() => dataplane_ip = Some(ip),
                _ => {}
            }
        }

        let mgmt_ip = mgmt_ip.ok_or_else(|| {
            CloudError::InvalidResponse(format!(
                "instance {} missing management NIC ip",
                instance.id
            ))
        })?;
        let dataplane_ip = dataplane_ip.ok_or_else(|| {
            CloudError::InvalidResponse(format!(
                "instance {} missing dataplane NIC ip",
                instance.id
            ))
        })?;

        let health = health_status.unwrap_or_default().to_ascii_lowercase();
        let active = instance.state.eq_ignore_ascii_case("running")
            && (health.is_empty() || health == "healthy");

        Ok(InstanceRef {
            id: instance.id.clone(),
            name: instance.name.clone(),
            zone: instance.zone.clone(),
            created_at_epoch: instance.created_at_epoch,
            mgmt_ip: IpAddr::V4(mgmt_ip),
            dataplane_ip,
            tags: instance.tags.clone(),
            active,
        })
    }

    async fn local_instance_id(&self) -> Result<String, CloudError> {
        let cached = self.local_instance_id.lock().await.clone();
        if let Some(id) = cached {
            return Ok(id);
        }

        let token = self.imds_token().await?;
        let id = self.imds_get(&token, "meta-data/instance-id").await?;
        let instance_id = id.trim().to_string();
        if instance_id.is_empty() {
            return Err(CloudError::InvalidResponse(
                "imds instance-id empty".to_string(),
            ));
        }

        *self.local_instance_id.lock().await = Some(instance_id.clone());
        Ok(instance_id)
    }

    async fn aws_credentials(&self) -> Result<AwsCredentials, CloudError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(cached) = self.credentials.lock().await.clone() {
            if cached.expiration_epoch > now + 60 {
                return Ok(cached);
            }
        }

        let token = self.imds_token().await?;
        let roles_raw = self
            .imds_get(&token, "meta-data/iam/security-credentials/")
            .await?;
        let role_name = roles_raw
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| CloudError::InvalidResponse("imds iam role name missing".to_string()))?
            .to_string();

        let raw = self
            .imds_get(
                &token,
                &format!("meta-data/iam/security-credentials/{role_name}"),
            )
            .await?;
        let parsed: ImdsRoleCredentials = serde_json::from_str(&raw)
            .map_err(|err| CloudError::InvalidResponse(format!("imds creds decode: {err}")))?;
        if !parsed.code.eq_ignore_ascii_case("success") {
            let message = parsed.message.unwrap_or_default();
            return Err(CloudError::InvalidResponse(format!(
                "imds creds unavailable: {} {message}",
                parsed.code
            )));
        }

        let expiration_epoch = OffsetDateTime::parse(&parsed.expiration, &Rfc3339)
            .map(|value| value.unix_timestamp())
            .unwrap_or(now + 300);

        let creds = AwsCredentials {
            access_key_id: parsed.access_key_id,
            secret_access_key: parsed.secret_access_key,
            session_token: parsed.token,
            expiration_epoch,
        };
        *self.credentials.lock().await = Some(creds.clone());
        Ok(creds)
    }

    async fn imds_token(&self) -> Result<String, CloudError> {
        let url = format!("{IMDS_BASE}/api/token");
        let response = self
            .client
            .put(url)
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("imds token: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "imds token failed: {status}"
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|err| CloudError::InvalidResponse(format!("imds token body: {err}")))?;
        Ok(body)
    }

    async fn imds_get(&self, token: &str, path: &str) -> Result<String, CloudError> {
        let url = format!("{IMDS_BASE}/{path}");
        let response = self
            .client
            .get(url)
            .header("X-aws-ec2-metadata-token", token)
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("imds get {path}: {err}")))?;
        let status = response.status();
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "imds get {path} failed: {status}"
            )));
        }
        response
            .text()
            .await
            .map_err(|err| CloudError::InvalidResponse(format!("imds body {path}: {err}")))
    }

    async fn autoscaling_query(
        &self,
        mut params: BTreeMap<String, String>,
    ) -> Result<String, CloudError> {
        params.insert("Version".to_string(), AUTOSCALING_API_VERSION.to_string());
        let host = format!("autoscaling.{}.amazonaws.com", self.region);
        self.signed_query("autoscaling", &host, params).await
    }

    async fn ec2_query(&self, mut params: BTreeMap<String, String>) -> Result<String, CloudError> {
        params.insert("Version".to_string(), EC2_API_VERSION.to_string());
        let host = format!("ec2.{}.amazonaws.com", self.region);
        self.signed_query("ec2", &host, params).await
    }

    async fn signed_query(
        &self,
        service: &str,
        host: &str,
        params: BTreeMap<String, String>,
    ) -> Result<String, CloudError> {
        let creds = self.aws_credentials().await?;
        let now = OffsetDateTime::now_utc();
        let date_stamp = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
        let amz_date = format!(
            "{date_stamp}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        );

        let body = form_urlencode_params(&params);
        let payload_hash = sha256_hex(body.as_bytes());

        let mut canonical_headers = format!(
            "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:{host}\nx-amz-date:{amz_date}\n"
        );
        let mut signed_headers = "content-type;host;x-amz-date".to_string();
        if !creds.session_token.is_empty() {
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", creds.session_token));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request =
            format!("POST\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");
        let credential_scope = format!("{date_stamp}/{}/{service}/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );

        let signing_key =
            derive_signing_key(&creds.secret_access_key, &date_stamp, &self.region, service)?;
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            creds.access_key_id
        );

        let mut request = self
            .client
            .post(format!("https://{host}/"))
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .header("x-amz-date", amz_date)
            .header("authorization", authorization)
            .body(body);
        if !creds.session_token.is_empty() {
            request = request.header("x-amz-security-token", creds.session_token);
        }

        let response = request
            .send()
            .await
            .map_err(|err| CloudError::RequestFailed(format!("aws {service} request: {err}")))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<unreadable-body>".to_string());
        if !status.is_success() {
            return Err(CloudError::RequestFailed(format!(
                "aws {service} request failed: {status}: {}",
                abbreviate(&body, 800)
            )));
        }
        Ok(body)
    }
}

#[async_trait]
impl CloudProvider for AwsProvider {
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

    async fn record_termination_heartbeat(
        &self,
        event: &TerminationEvent,
    ) -> Result<Option<i64>, CloudError> {
        self.record_termination_heartbeat_provider(event).await
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.capabilities_provider()
    }
}

fn parse_asg_members(xml: &str, asg_name: &str) -> Result<Vec<AsgInstanceState>, CloudError> {
    let doc = Document::parse(xml)
        .map_err(|err| CloudError::InvalidResponse(format!("autoscaling xml parse: {err}")))?;

    let groups = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "AutoScalingGroups");
    let Some(groups) = groups else {
        return Ok(Vec::new());
    };

    for group in groups
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "member")
    {
        let name = child_text(group, "AutoScalingGroupName").unwrap_or_default();
        if name != asg_name {
            continue;
        }
        let mut out = Vec::new();
        if let Some(instances) = child_node(group, "Instances") {
            for item in instances
                .children()
                .filter(|node| node.is_element() && node.tag_name().name() == "member")
            {
                let Some(instance_id) = child_text(item, "InstanceId") else {
                    continue;
                };
                out.push(AsgInstanceState {
                    instance_id,
                    lifecycle_state: child_text(item, "LifecycleState").unwrap_or_default(),
                    health_status: child_text(item, "HealthStatus").unwrap_or_default(),
                });
            }
        }
        return Ok(out);
    }

    Ok(Vec::new())
}

fn parse_autoscaling_instance_status(xml: &str, instance_id: &str) -> Option<AsgLifecycleInfo> {
    let doc = Document::parse(xml).ok()?;
    let set = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "AutoScalingInstances")?;

    for member in set
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "member")
    {
        if child_text(member, "InstanceId").as_deref() != Some(instance_id) {
            continue;
        }
        return Some(AsgLifecycleInfo {
            asg_name: child_text(member, "AutoScalingGroupName").unwrap_or_default(),
            lifecycle_state: child_text(member, "LifecycleState").unwrap_or_default(),
        });
    }
    None
}

fn parse_lifecycle_hooks(xml: &str) -> Result<Vec<LifecycleHookInfo>, CloudError> {
    let doc = Document::parse(xml)
        .map_err(|err| CloudError::InvalidResponse(format!("lifecycle hook xml parse: {err}")))?;
    let hooks = doc
        .descendants()
        .find(|node| node.is_element() && node.tag_name().name() == "LifecycleHooks");
    let Some(hooks) = hooks else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for member in hooks
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "member")
    {
        let Some(name) = child_text(member, "LifecycleHookName") else {
            continue;
        };
        let transition = child_text(member, "LifecycleTransition").unwrap_or_default();
        let heartbeat_timeout_secs = child_text(member, "HeartbeatTimeout")
            .and_then(|raw| raw.parse::<i64>().ok())
            .unwrap_or(300);
        out.push(LifecycleHookInfo {
            name,
            transition,
            heartbeat_timeout_secs,
        });
    }
    Ok(out)
}

fn is_transient_missing_nic_error(message: &str) -> bool {
    message.contains("missing management NIC ip") || message.contains("missing dataplane NIC ip")
}

fn parse_ec2_instances(xml: &str) -> Result<Vec<Ec2InstanceData>, CloudError> {
    let doc = Document::parse(xml)
        .map_err(|err| CloudError::InvalidResponse(format!("ec2 instances xml parse: {err}")))?;

    let mut instances = Vec::new();
    for item in doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "item"
            && node
                .parent()
                .is_some_and(|parent| parent.tag_name().name() == "instancesSet")
    }) {
        let Some(id) = child_text(item, "instanceId") else {
            continue;
        };
        let tags = parse_tag_map(item);
        let name = tags.get("Name").cloned().unwrap_or_else(|| id.clone());
        let zone = child_node(item, "placement")
            .and_then(|placement| child_text(placement, "availabilityZone"))
            .unwrap_or_default();
        let created_at_epoch = child_text(item, "launchTime")
            .map(|raw| parse_epoch(&raw))
            .unwrap_or(0);
        let state = child_node(item, "instanceState")
            .and_then(|state| child_text(state, "name"))
            .unwrap_or_default();

        let mut interfaces = Vec::new();
        if let Some(ifaces) = child_node(item, "networkInterfaceSet") {
            for iface in ifaces
                .children()
                .filter(|node| node.is_element() && node.tag_name().name() == "item")
            {
                let Some(interface_id) = child_text(iface, "networkInterfaceId") else {
                    continue;
                };
                let private_ip = child_text(iface, "privateIpAddress")
                    .and_then(|raw| raw.parse::<Ipv4Addr>().ok());
                let device_index = child_node(iface, "attachment")
                    .and_then(|attachment| child_text(attachment, "deviceIndex"))
                    .and_then(|raw| raw.parse::<u32>().ok());
                interfaces.push(Ec2InterfaceRef {
                    id: interface_id,
                    private_ip,
                    device_index,
                });
            }
        }

        instances.push(Ec2InstanceData {
            id,
            name,
            zone,
            created_at_epoch,
            tags,
            state,
            interfaces,
        });
    }

    Ok(instances)
}

fn parse_network_interfaces(xml: &str) -> Result<Vec<Ec2NetworkInterfaceData>, CloudError> {
    let doc = Document::parse(xml).map_err(|err| {
        CloudError::InvalidResponse(format!("network interfaces xml parse: {err}"))
    })?;

    let mut interfaces = Vec::new();
    for item in doc.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "item"
            && node
                .parent()
                .is_some_and(|parent| parent.tag_name().name() == "networkInterfaceSet")
    }) {
        let Some(id) = child_text(item, "networkInterfaceId") else {
            continue;
        };
        let private_ip =
            child_text(item, "privateIpAddress").and_then(|raw| raw.parse::<Ipv4Addr>().ok());
        let attachment_device_index = child_node(item, "attachment")
            .and_then(|attachment| child_text(attachment, "deviceIndex"))
            .and_then(|raw| raw.parse::<u32>().ok());
        let tags = parse_tag_map(item);

        interfaces.push(Ec2NetworkInterfaceData {
            id,
            private_ip,
            attachment_device_index,
            tags,
        });
    }

    Ok(interfaces)
}

fn child_node<'a, 'd>(
    node: roxmltree::Node<'a, 'd>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'd>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name)
}

fn child_text<'a, 'd>(node: roxmltree::Node<'a, 'd>, name: &str) -> Option<String> {
    child_node(node, name)
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(|text| text.to_string())
}

fn parse_tag_map<'a, 'd>(node: roxmltree::Node<'a, 'd>) -> HashMap<String, String> {
    let mut tags = HashMap::new();
    let Some(tag_set) = child_node(node, "tagSet") else {
        return tags;
    };
    for item in tag_set
        .children()
        .filter(|child| child.is_element() && child.tag_name().name() == "item")
    {
        let Some(key) = child_text(item, "key") else {
            continue;
        };
        let value = child_text(item, "value").unwrap_or_default();
        tags.insert(key, value);
    }
    tags
}

fn parse_epoch(raw: &str) -> i64 {
    OffsetDateTime::parse(raw, &Rfc3339)
        .map(|value| value.unix_timestamp())
        .unwrap_or(0)
}

fn lifecycle_event_id(hook_name: &str) -> String {
    format!("{LIFECYCLE_EVENT_PREFIX}{hook_name}")
}

fn lifecycle_event_hook(event_id: &str) -> Option<&str> {
    event_id.strip_prefix(LIFECYCLE_EVENT_PREFIX)
}

fn tag_value<'a>(tags: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    if let Some(value) = tags.get(key) {
        return Some(value.as_str());
    }
    if key.contains('/') {
        let alt = key.replace('/', ".");
        return tags.get(&alt).map(String::as_str);
    }
    None
}

fn tag_enabled(tags: &HashMap<String, String>, keys: &[&str]) -> bool {
    keys.iter()
        .filter_map(|key| tag_value(tags, key))
        .any(is_truthy)
}

fn is_truthy(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
        || value == "1"
}

fn derive_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, CloudError> {
    let k_secret = format!("AWS4{secret_access_key}");
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CloudError> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|err| CloudError::RequestFailed(format!("hmac init failed: {err}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

fn form_urlencode_params(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", aws_percent_encode(key), aws_percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
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
    fn parse_asg_members_extracts_instances() {
        let xml = r#"
<DescribeAutoScalingGroupsResponse>
  <DescribeAutoScalingGroupsResult>
    <AutoScalingGroups>
      <member>
        <AutoScalingGroupName>asg-a</AutoScalingGroupName>
        <Instances>
          <member>
            <InstanceId>i-1</InstanceId>
            <LifecycleState>InService</LifecycleState>
            <HealthStatus>Healthy</HealthStatus>
          </member>
          <member>
            <InstanceId>i-2</InstanceId>
            <LifecycleState>Terminating:Wait</LifecycleState>
            <HealthStatus>Healthy</HealthStatus>
          </member>
        </Instances>
      </member>
    </AutoScalingGroups>
  </DescribeAutoScalingGroupsResult>
</DescribeAutoScalingGroupsResponse>
"#;

        let members = parse_asg_members(xml, "asg-a").expect("parse asg members");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].instance_id, "i-1");
        assert_eq!(members[1].lifecycle_state, "Terminating:Wait");
    }

    #[test]
    fn parse_lifecycle_hooks_filters_terminating() {
        let xml = r#"
<DescribeLifecycleHooksResponse>
  <DescribeLifecycleHooksResult>
    <LifecycleHooks>
      <member>
        <LifecycleHookName>terminate-hook</LifecycleHookName>
        <LifecycleTransition>autoscaling:EC2_INSTANCE_TERMINATING</LifecycleTransition>
        <HeartbeatTimeout>120</HeartbeatTimeout>
      </member>
      <member>
        <LifecycleHookName>launch-hook</LifecycleHookName>
        <LifecycleTransition>autoscaling:EC2_INSTANCE_LAUNCHING</LifecycleTransition>
        <HeartbeatTimeout>60</HeartbeatTimeout>
      </member>
    </LifecycleHooks>
  </DescribeLifecycleHooksResult>
</DescribeLifecycleHooksResponse>
"#;

        let hooks = parse_lifecycle_hooks(xml).expect("parse hooks");
        assert_eq!(hooks.len(), 2);
        let terminating = hooks
            .into_iter()
            .find(|hook| hook.transition == LIFECYCLE_TRANSITION_TERMINATING)
            .expect("terminating hook");
        assert_eq!(terminating.name, "terminate-hook");
        assert_eq!(terminating.heartbeat_timeout_secs, 120);
    }

    #[test]
    fn instance_ref_prefers_tagged_nics() {
        let provider = AwsProvider::new(
            "eu-central-1".to_string(),
            "vpc-1".to_string(),
            "asg-a".to_string(),
        );
        let instance = Ec2InstanceData {
            id: "i-1".to_string(),
            name: "fw-1".to_string(),
            zone: "eu-central-1a".to_string(),
            created_at_epoch: 1,
            tags: HashMap::new(),
            state: "running".to_string(),
            interfaces: vec![
                Ec2InterfaceRef {
                    id: "eni-mgmt".to_string(),
                    private_ip: Some("10.0.1.4".parse().expect("mgmt ip parse")),
                    device_index: Some(0),
                },
                Ec2InterfaceRef {
                    id: "eni-data".to_string(),
                    private_ip: Some("10.0.2.4".parse().expect("data ip parse")),
                    device_index: Some(1),
                },
            ],
        };

        let mut mgmt_tags = HashMap::new();
        mgmt_tags.insert("neuwerk.io/management".to_string(), "true".to_string());
        mgmt_tags.insert("neuwerk.io/dataplane".to_string(), "false".to_string());
        let mut data_tags = HashMap::new();
        data_tags.insert("neuwerk.io/management".to_string(), "false".to_string());
        data_tags.insert("neuwerk.io/dataplane".to_string(), "true".to_string());

        let mut interfaces = HashMap::new();
        interfaces.insert(
            "eni-mgmt".to_string(),
            Ec2NetworkInterfaceData {
                id: "eni-mgmt".to_string(),
                private_ip: Some("10.0.1.4".parse().expect("mgmt detail ip parse")),
                attachment_device_index: Some(0),
                tags: mgmt_tags,
            },
        );
        interfaces.insert(
            "eni-data".to_string(),
            Ec2NetworkInterfaceData {
                id: "eni-data".to_string(),
                private_ip: Some("10.0.2.4".parse().expect("data detail ip parse")),
                attachment_device_index: Some(1),
                tags: data_tags,
            },
        );

        let instance_ref = provider
            .to_instance_ref(&instance, Some("InService"), Some("Healthy"), &interfaces)
            .expect("instance ref");
        assert_eq!(
            instance_ref.mgmt_ip,
            IpAddr::V4("10.0.1.4".parse().expect("expected mgmt ip parse"))
        );
        assert_eq!(
            instance_ref.dataplane_ip,
            "10.0.2.4"
                .parse::<Ipv4Addr>()
                .expect("expected dataplane ip parse")
        );
        assert!(instance_ref.active);
    }

    #[test]
    fn lifecycle_event_hook_roundtrip() {
        let event_id = lifecycle_event_id("terminate-hook");
        assert_eq!(lifecycle_event_hook(&event_id), Some("terminate-hook"));
    }

    #[test]
    fn aws_percent_encoding_matches_sigv4_rules() {
        assert_eq!(aws_percent_encode("a b/c"), "a%20b%2Fc");
        assert_eq!(aws_percent_encode("~._-"), "~._-");
    }

    #[test]
    fn form_urlencode_orders_keys_lexicographically() {
        let mut params = BTreeMap::new();
        params.insert("B".to_string(), "2".to_string());
        params.insert("A".to_string(), "1".to_string());
        assert_eq!(form_urlencode_params(&params), "A=1&B=2");
    }

    #[test]
    fn transient_missing_nic_errors_are_detected() {
        assert!(is_transient_missing_nic_error(
            "instance i-1 missing management NIC ip"
        ));
        assert!(is_transient_missing_nic_error(
            "instance i-2 missing dataplane NIC ip"
        ));
        assert!(!is_transient_missing_nic_error(
            "autoscaling xml parse: invalid document"
        ));
    }
}
