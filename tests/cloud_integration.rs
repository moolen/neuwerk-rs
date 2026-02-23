use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use firewall::controlplane::cloud::{IntegrationManager, ReadyChecker};
use firewall::controlplane::cloud::provider::{CloudError, CloudProvider};
use firewall::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, IntegrationConfig,
    RouteChange, RouteRef, SubnetRef, TerminationEvent,
};
use firewall::controlplane::metrics::Metrics;
use firewall::dataplane::DrainControl;

#[derive(Clone)]
struct MutableReady {
    readiness: Arc<Mutex<HashMap<IpAddr, bool>>>,
}

#[async_trait]
impl ReadyChecker for MutableReady {
    async fn is_ready(&self, ip: IpAddr) -> bool {
        self.readiness.lock().await.get(&ip).copied().unwrap_or(false)
    }
}

impl MutableReady {
    async fn set_ready(&self, ip: IpAddr, ready: bool) {
        self.readiness.lock().await.insert(ip, ready);
    }
}

#[derive(Clone)]
struct MockProvider {
    instances: Arc<Mutex<Vec<InstanceRef>>>,
    subnets: Arc<Mutex<Vec<SubnetRef>>>,
    routes: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    self_id: String,
}

impl MockProvider {
    fn new(instances: Vec<InstanceRef>, subnets: Vec<SubnetRef>, self_id: &str) -> Self {
        Self {
            instances: Arc::new(Mutex::new(instances)),
            subnets: Arc::new(Mutex::new(subnets)),
            routes: Arc::new(Mutex::new(HashMap::new())),
            self_id: self_id.to_string(),
        }
    }
}

#[async_trait]
impl CloudProvider for MockProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
        let instances = self.instances.lock().await;
        instances
            .iter()
            .find(|instance| instance.id == self.self_id)
            .cloned()
            .ok_or_else(|| CloudError::NotFound("self instance".to_string()))
    }

    async fn discover_instances(&self, _filter: &DiscoveryFilter) -> Result<Vec<InstanceRef>, CloudError> {
        Ok(self.instances.lock().await.clone())
    }

    async fn discover_subnets(&self, _filter: &DiscoveryFilter) -> Result<Vec<SubnetRef>, CloudError> {
        Ok(self.subnets.lock().await.clone())
    }

    async fn get_route(&self, subnet: &SubnetRef, route_name: &str) -> Result<Option<RouteRef>, CloudError> {
        let routes = self.routes.lock().await;
        let Some(next_hop) = routes.get(&format!("{}:{route_name}", subnet.id)) else {
            return Ok(None);
        };
        Ok(Some(RouteRef {
            id: format!("{}:{route_name}", subnet.id),
            name: route_name.to_string(),
            subnet_id: subnet.id.clone(),
            next_hop: *next_hop,
        }))
    }

    async fn ensure_default_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        let mut routes = self.routes.lock().await;
        routes.insert(format!("{}:{route_name}", subnet.id), next_hop);
        Ok(RouteChange::Updated)
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

fn tags() -> HashMap<String, String> {
    let mut map = HashMap::new();
    map.insert("neuwerk.io/cluster".to_string(), "demo".to_string());
    map.insert("neuwerk.io/role".to_string(), "dataplane".to_string());
    map
}

fn instance(id: &str, ip: Ipv4Addr) -> InstanceRef {
    InstanceRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: "zone-a".to_string(),
        created_at_epoch: 0,
        mgmt_ip: IpAddr::V4(ip),
        dataplane_ip: Ipv4Addr::new(10, 1, 0, ip.octets()[3]),
        tags: tags(),
        active: true,
    }
}

fn subnet(id: &str) -> SubnetRef {
    SubnetRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: "zone-a".to_string(),
        cidr: "10.0.0.0/24".to_string(),
        route_table_id: "rt".to_string(),
        tags: tags(),
    }
}

#[tokio::test]
async fn reconcile_waits_for_readiness() {
    let instance_a = instance("i-a", Ipv4Addr::new(10, 0, 0, 1));
    let instance_b = instance("i-b", Ipv4Addr::new(10, 0, 0, 2));
    let subnet = subnet("subnet-1");
    let provider = Arc::new(MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet.clone()],
        "i-a",
    ));

    let readiness = Arc::new(Mutex::new(HashMap::new()));
    readiness.lock().await.insert(instance_a.mgmt_ip, false);
    readiness.lock().await.insert(instance_b.mgmt_ip, false);
    let ready_handle = Arc::new(MutableReady { readiness });
    let ready_checker = ready_handle.clone() as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        tag_filter: DiscoveryFilter { tags: tags() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        provider.clone(),
        None,
        None,
        metrics,
        drain_control,
        ready_checker.clone(),
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();
    assert!(provider.routes.lock().await.is_empty());

    ready_handle.set_ready(instance_a.mgmt_ip, true).await;
    ready_handle.set_ready(instance_b.mgmt_ip, true).await;

    manager.reconcile_once().await.unwrap();
    let routes = provider.routes.lock().await;
    assert!(routes.contains_key("subnet-1:neuwerk-default"));
}

#[tokio::test]
async fn reconcile_sets_drain_for_unassigned_local() {
    let instance_a = instance("i-a", Ipv4Addr::new(10, 0, 0, 1));
    let instance_b = instance("i-b", Ipv4Addr::new(10, 0, 0, 2));
    let subnet = subnet("subnet-1");

    let assignments = firewall::controlplane::cloud::compute_assignments(
        &[subnet.clone()],
        &[instance_a.clone(), instance_b.clone()],
    );
    let assigned = assignments.get("subnet-1").cloned().unwrap();
    let local_id = if assigned == "i-a" { "i-b" } else { "i-a" };

    let provider = Arc::new(MockProvider::new(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet.clone()],
        local_id,
    ));

    let readiness = Arc::new(Mutex::new(HashMap::new()));
    readiness.lock().await.insert(instance_a.mgmt_ip, true);
    readiness.lock().await.insert(instance_b.mgmt_ip, true);
    let ready_handle = Arc::new(MutableReady { readiness });
    let ready_checker = ready_handle as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 1,
        reconcile_interval_secs: 1,
        tag_filter: DiscoveryFilter { tags: tags() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        provider,
        None,
        None,
        metrics,
        drain_control.clone(),
        ready_checker,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();
    assert!(drain_control.is_draining());
}
