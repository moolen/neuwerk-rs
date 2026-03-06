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
const TAG_ROLE: &[&str] = &["neuwerk.io/role", "neuwerk.io.role"];
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
    pub fn new(
        subscription_id: String,
        resource_group: String,
        vmss_name: String,
    ) -> Result<Self, CloudError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|err| CloudError::RequestFailed(format!("azure client init failed: {err}")))?;
        Ok(Self {
            subscription_id,
            resource_group,
            vmss_name,
            client,
        })
    }

    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

include!("azure/models.rs");
include!("azure/helpers.rs");
include!("azure/provider_impl.rs");

#[cfg(test)]
mod tests;
