use std::net::SocketAddr;
use std::sync::Arc;

use firewall::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use firewall::controlplane::cloud::providers::{
    aws::AwsProvider, azure::AzureProvider, gcp::GcpProvider,
};
use firewall::controlplane::cloud::types::{DiscoveryFilter, IntegrationMode};
use firewall::controlplane::cloud::{self};

pub fn build_integration_provider(
    cfg: &crate::runtime::cli::CliConfig,
) -> Result<Option<Arc<dyn CloudProviderTrait>>, String> {
    match cfg.integration_mode {
        IntegrationMode::AzureVmss => Ok(Some(
            AzureProvider::new(
                cfg.azure_subscription_id.clone().unwrap_or_default(),
                cfg.azure_resource_group.clone().unwrap_or_default(),
                cfg.azure_vmss_name.clone().unwrap_or_default(),
            )
            .map_err(|err| format!("azure provider init failed: {err}"))?
            .shared(),
        )),
        IntegrationMode::AwsAsg => Ok(Some(
            AwsProvider::new(
                cfg.aws_region.clone().unwrap_or_default(),
                cfg.aws_vpc_id.clone().unwrap_or_default(),
                cfg.aws_asg_name.clone().unwrap_or_default(),
            )
            .shared(),
        )),
        IntegrationMode::GcpMig => Ok(Some(
            GcpProvider::new(
                cfg.gcp_project.clone().unwrap_or_default(),
                cfg.gcp_region.clone().unwrap_or_default(),
                cfg.gcp_ig_name.clone().unwrap_or_default(),
            )
            .shared(),
        )),
        IntegrationMode::None => Ok(None),
    }
}

pub fn integration_tag_filter(cfg: &crate::runtime::cli::CliConfig) -> DiscoveryFilter {
    let mut tags = std::collections::HashMap::new();
    tags.insert(
        "neuwerk.io/cluster".to_string(),
        cfg.integration_cluster_name.clone(),
    );
    tags.insert("neuwerk.io/role".to_string(), "dataplane".to_string());
    DiscoveryFilter { tags }
}

pub async fn select_integration_seed(
    provider: Arc<dyn CloudProviderTrait>,
    filter: &DiscoveryFilter,
    cluster_port: u16,
) -> Result<Option<SocketAddr>, String> {
    let instances = provider
        .discover_instances(filter)
        .await
        .map_err(|err| format!("discover instances failed: {err}"))?;
    let seed = cloud::select_seed_instance(&instances);
    let Some(seed) = seed else {
        return Ok(None);
    };
    let self_ref = provider
        .self_identity()
        .await
        .map_err(|err| format!("self identity failed: {err}"))?;
    if seed.id == self_ref.id {
        return Ok(None);
    }
    Ok(Some(SocketAddr::new(seed.mgmt_ip, cluster_port)))
}
