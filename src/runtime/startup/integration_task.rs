use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use neuwerk::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use neuwerk::controlplane::cloud::types::{IntegrationConfig, IntegrationMode};
use neuwerk::controlplane::cloud::{IntegrationManager, ReadyChecker, ReadyClient};
use neuwerk::controlplane::cluster::ClusterRuntime;
use neuwerk::dataplane::DrainControl;
use neuwerk::metrics::Metrics;
use tracing::{error, warn};

use crate::runtime::bootstrap::integration::integration_tag_filter;
use crate::runtime::cli::{load_http_ca, CliConfig};

fn build_integration_config(cfg: &CliConfig, http_advertise: SocketAddr) -> IntegrationConfig {
    IntegrationConfig {
        cluster_name: cfg.integration_cluster_name.clone(),
        route_name: cfg.integration_route_name.clone(),
        drain_timeout_secs: cfg.integration_drain_timeout_secs,
        reconcile_interval_secs: cfg.integration_reconcile_interval_secs,
        membership_auto_evict_terminating: cfg.integration_membership_auto_evict_terminating,
        membership_stale_after_secs: cfg.integration_membership_stale_after_secs,
        membership_min_voters: cfg.integration_membership_min_voters,
        tag_filter: integration_tag_filter(cfg),
        http_ready_port: http_advertise.port(),
        cluster_tls_dir: if cfg.cluster.enabled {
            Some(cfg.cluster.data_dir.join("tls"))
        } else {
            None
        },
    }
}

pub fn spawn_integration_manager_task(
    cfg: &CliConfig,
    integration_provider: Option<Arc<dyn CloudProviderTrait>>,
    cluster_runtime: Option<&ClusterRuntime>,
    http_advertise: SocketAddr,
    metrics: Metrics,
    drain_control: DrainControl,
) -> Result<Option<tokio::task::JoinHandle<()>>, String> {
    if cfg.integration_mode == IntegrationMode::None {
        return Ok(None);
    }
    let Some(provider) = integration_provider else {
        return Ok(None);
    };

    let integration_cfg = build_integration_config(cfg, http_advertise);
    let ca_pem = match load_http_ca(cfg) {
        Ok(ca_pem) => ca_pem,
        Err(err) => {
            warn!(error = %err, "integration ready client init failed");
            return Err("integration ready client init failed: missing http ca".to_string());
        }
    };
    let ready_client = match ReadyClient::new(http_advertise.port(), Some(ca_pem)) {
        Ok(client) => Arc::new(client) as Arc<dyn ReadyChecker>,
        Err(err) => {
            error!(error = %err, "integration ready client init failed");
            return Err("integration ready client init failed".to_string());
        }
    };
    let metrics_for_integration = metrics;
    let drain_for_integration = drain_control;
    let store_for_integration = cluster_runtime.map(|runtime| runtime.store.clone());
    let raft_for_integration = cluster_runtime.map(|runtime| runtime.raft.clone());
    let integration_mode = cfg.integration_mode;
    let reconcile_interval_secs = integration_cfg.reconcile_interval_secs;
    Ok(Some(tokio::spawn(async move {
        loop {
            match IntegrationManager::new(
                integration_cfg.clone(),
                provider.clone(),
                store_for_integration.clone(),
                raft_for_integration.clone(),
                metrics_for_integration.clone(),
                drain_for_integration.clone(),
                ready_client.clone(),
            )
            .await
            {
                Ok(manager) => {
                    manager.run(integration_mode).await;
                    return;
                }
                Err(err) => {
                    warn!(error = %err, "integration manager init failed");
                    let wait_secs = reconcile_interval_secs.max(5);
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                }
            }
        }
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use async_trait::async_trait;
    use neuwerk::controlplane::cloud::provider::CloudError;
    use neuwerk::controlplane::cloud::types::{
        CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, RouteChange,
        RouteRef, SubnetRef, TerminationEvent,
    };
    use neuwerk::controlplane::cluster::config::ClusterConfig;
    use neuwerk::controlplane::trafficd::TlsInterceptSettings;
    use neuwerk::dataplane::engine::EngineRuntimeConfig;
    use neuwerk::dataplane::{EncapMode, SnatMode, SoftMode};
    use tempfile::TempDir;

    use crate::runtime::cli::{CloudProviderKind, DataPlaneMode};

    #[derive(Clone)]
    struct TestProvider;

    #[async_trait]
    impl CloudProviderTrait for TestProvider {
        async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
            Ok(InstanceRef {
                id: "node-1".to_string(),
                name: "node-1".to_string(),
                zone: "test-zone".to_string(),
                created_at_epoch: 0,
                mgmt_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                dataplane_ip: Ipv4Addr::new(10, 0, 0, 1),
                tags: HashMap::new(),
                active: true,
            })
        }

        async fn discover_instances(
            &self,
            _filter: &DiscoveryFilter,
        ) -> Result<Vec<InstanceRef>, CloudError> {
            Ok(Vec::new())
        }

        async fn discover_subnets(
            &self,
            _filter: &DiscoveryFilter,
        ) -> Result<Vec<SubnetRef>, CloudError> {
            Ok(Vec::new())
        }

        async fn get_route(
            &self,
            _subnet: &SubnetRef,
            _route_name: &str,
        ) -> Result<Option<RouteRef>, CloudError> {
            Ok(None)
        }

        async fn ensure_default_route(
            &self,
            _subnet: &SubnetRef,
            _route_name: &str,
            _next_hop: Ipv4Addr,
        ) -> Result<RouteChange, CloudError> {
            Ok(RouteChange::Unchanged)
        }

        async fn set_instance_protection(
            &self,
            _instance: &InstanceRef,
            _enabled: bool,
        ) -> Result<CapabilityResult, CloudError> {
            Ok(CapabilityResult::Unsupported)
        }

        async fn poll_termination_notice(
            &self,
            _instance: &InstanceRef,
        ) -> Result<Option<TerminationEvent>, CloudError> {
            Ok(None)
        }

        async fn complete_termination_action(
            &self,
            _event: &TerminationEvent,
        ) -> Result<CapabilityResult, CloudError> {
            Ok(CapabilityResult::Unsupported)
        }

        fn capabilities(&self) -> IntegrationCapabilities {
            IntegrationCapabilities::default()
        }
    }

    fn test_cli_config(dir: &TempDir) -> CliConfig {
        CliConfig {
            management_iface: "mgmt0".to_string(),
            data_plane_iface: "data0".to_string(),
            dns_target_ips: Vec::new(),
            dns_upstreams: Vec::new(),
            data_plane_mode: DataPlaneMode::Soft(SoftMode::Tap),
            idle_timeout_secs: 60,
            dns_allowlist_idle_secs: 60,
            dns_allowlist_gc_interval_secs: 30,
            default_policy: neuwerk::dataplane::policy::DefaultPolicy::Deny,
            dhcp_timeout_secs: 5,
            dhcp_retry_max: 5,
            dhcp_lease_min_secs: 60,
            internal_cidr: None,
            snat_mode: SnatMode::None,
            encap_mode: EncapMode::None,
            encap_vni: None,
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: None,
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: 1500,
            http_external_url: None,
            http_tls_dir: dir.path().join("http-tls"),
            http_cert_path: None,
            http_key_path: None,
            http_ca_path: Some(dir.path().join("missing-ca.crt")),
            http_tls_san: Vec::new(),
            allow_public_metrics_bind: false,
            tls_intercept: TlsInterceptSettings::default(),
            engine_runtime: EngineRuntimeConfig::default(),
            runtime: crate::runtime::config::RuntimeBehaviorSettings::default(),
            dpdk: crate::runtime::config::RuntimeDpdkConfig::default(),
            cloud_provider: CloudProviderKind::Azure,
            cluster: ClusterConfig::disabled(),
            cluster_migrate_from_local: false,
            cluster_migrate_force: false,
            cluster_migrate_verify: false,
            integration_mode: IntegrationMode::AzureVmss,
            integration_route_name: "neuwerk-default".to_string(),
            integration_drain_timeout_secs: 300,
            integration_reconcile_interval_secs: 15,
            integration_cluster_name: "neuwerk".to_string(),
            integration_membership_auto_evict_terminating: true,
            integration_membership_stale_after_secs: 0,
            integration_membership_min_voters: 3,
            azure_subscription_id: None,
            azure_resource_group: None,
            azure_vmss_name: None,
            aws_region: None,
            aws_vpc_id: None,
            aws_asg_name: None,
            gcp_project: None,
            gcp_region: None,
            gcp_ig_name: None,
        }
    }

    fn test_cli_config_with_membership(dir: &TempDir) -> CliConfig {
        let mut cfg = test_cli_config(dir);
        cfg.integration_membership_auto_evict_terminating = false;
        cfg.integration_membership_stale_after_secs = 30;
        cfg.integration_membership_min_voters = 5;
        cfg
    }

    #[tokio::test]
    async fn integration_manager_fails_closed_when_http_ca_is_missing() {
        let dir = TempDir::new().unwrap();
        let cfg = test_cli_config(&dir);

        let result = spawn_integration_manager_task(
            &cfg,
            Some(Arc::new(TestProvider)),
            None,
            SocketAddr::from(([127, 0, 0, 1], 8443)),
            Metrics::new().unwrap(),
            DrainControl::new(),
        );

        match result {
            Err(err) => assert!(
                err.contains("http ca") || err.contains("ready client"),
                "unexpected error: {err}"
            ),
            Ok(Some(handle)) => {
                handle.abort();
                panic!("expected missing HTTP CA to fail closed before spawning integration task");
            }
            Ok(None) => panic!("expected missing HTTP CA to produce an error"),
        }
    }

    #[test]
    fn spawn_integration_manager_threads_membership_settings() {
        let dir = TempDir::new().unwrap();
        let cfg = test_cli_config_with_membership(&dir);
        let integration_cfg =
            build_integration_config(&cfg, SocketAddr::from(([127, 0, 0, 1], 8443)));
        assert!(!integration_cfg.membership_auto_evict_terminating);
        assert_eq!(integration_cfg.membership_stale_after_secs, 30);
        assert_eq!(integration_cfg.membership_min_voters, 5);
    }
}
