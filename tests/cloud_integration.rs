use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use neuwerk::controlplane::cloud::provider::{CloudError, CloudProvider};
use neuwerk::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, InstanceRef, IntegrationCapabilities, IntegrationConfig,
    RouteChange, RouteRef, SubnetRef, TerminationEvent,
};
use neuwerk::controlplane::cloud::{IntegrationManager, ReadyChecker};
use neuwerk::controlplane::metrics::Metrics;
use neuwerk::dataplane::DrainControl;

#[derive(Clone)]
struct MutableReady {
    readiness: Arc<Mutex<HashMap<IpAddr, bool>>>,
}

#[async_trait]
impl ReadyChecker for MutableReady {
    async fn is_ready(&self, ip: IpAddr) -> bool {
        self.readiness
            .lock()
            .await
            .get(&ip)
            .copied()
            .unwrap_or(false)
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
    termination_event: Arc<Mutex<Option<TerminationEvent>>>,
    completed: Arc<Mutex<u32>>,
    capabilities: IntegrationCapabilities,
    self_id: String,
}

impl MockProvider {
    fn new(instances: Vec<InstanceRef>, subnets: Vec<SubnetRef>, self_id: &str) -> Self {
        Self::with_capabilities(
            instances,
            subnets,
            self_id,
            IntegrationCapabilities::default(),
        )
    }

    fn with_capabilities(
        instances: Vec<InstanceRef>,
        subnets: Vec<SubnetRef>,
        self_id: &str,
        capabilities: IntegrationCapabilities,
    ) -> Self {
        Self {
            instances: Arc::new(Mutex::new(instances)),
            subnets: Arc::new(Mutex::new(subnets)),
            routes: Arc::new(Mutex::new(HashMap::new())),
            termination_event: Arc::new(Mutex::new(None)),
            completed: Arc::new(Mutex::new(0)),
            capabilities,
            self_id: self_id.to_string(),
        }
    }

    async fn set_termination_event(&self, event: Option<TerminationEvent>) {
        *self.termination_event.lock().await = event;
    }

    async fn completed_count(&self) -> u32 {
        *self.completed.lock().await
    }
}

#[derive(Clone)]
struct FailingCompleteProvider {
    base: MockProvider,
}

impl FailingCompleteProvider {
    fn new(base: MockProvider) -> Self {
        Self { base }
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

    async fn discover_instances(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        Ok(self.instances.lock().await.clone())
    }

    async fn discover_subnets(
        &self,
        _filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        Ok(self.subnets.lock().await.clone())
    }

    async fn get_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
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
        Ok(self.termination_event.lock().await.take())
    }

    async fn complete_termination_action(
        &self,
        _event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        *self.completed.lock().await += 1;
        Ok(CapabilityResult::Applied)
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.capabilities.clone()
    }
}

#[async_trait]
impl CloudProvider for FailingCompleteProvider {
    async fn self_identity(&self) -> Result<InstanceRef, CloudError> {
        self.base.self_identity().await
    }

    async fn discover_instances(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<InstanceRef>, CloudError> {
        self.base.discover_instances(filter).await
    }

    async fn discover_subnets(
        &self,
        filter: &DiscoveryFilter,
    ) -> Result<Vec<SubnetRef>, CloudError> {
        self.base.discover_subnets(filter).await
    }

    async fn get_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
    ) -> Result<Option<RouteRef>, CloudError> {
        self.base.get_route(subnet, route_name).await
    }

    async fn ensure_default_route(
        &self,
        subnet: &SubnetRef,
        route_name: &str,
        next_hop: Ipv4Addr,
    ) -> Result<RouteChange, CloudError> {
        self.base
            .ensure_default_route(subnet, route_name, next_hop)
            .await
    }

    async fn set_instance_protection(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        self.base.set_instance_protection(instance, enabled).await
    }

    async fn poll_termination_notice(
        &self,
        instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        self.base.poll_termination_notice(instance).await
    }

    async fn complete_termination_action(
        &self,
        _event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        Err(CloudError::RequestFailed(
            "forced completion failure".to_string(),
        ))
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.base.capabilities()
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

fn metric_value(rendered: &str, metric: &str) -> f64 {
    rendered
        .lines()
        .find_map(|line| {
            if !line.starts_with(metric) {
                return None;
            }
            line.split_whitespace().last()?.parse::<f64>().ok()
        })
        .unwrap_or(0.0)
}

fn metric_value_with_labels(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> f64 {
    rendered
        .lines()
        .find_map(|line| {
            if !line.starts_with(metric) {
                return None;
            }
            let name = line.split_whitespace().next()?;
            for (key, value) in labels {
                let needle = format!(r#"{key}="{value}""#);
                if !name.contains(&needle) {
                    return None;
                }
            }
            line.split_whitespace().last()?.parse::<f64>().ok()
        })
        .unwrap_or(0.0)
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
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
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

    let assignments = neuwerk::controlplane::cloud::compute_assignments(
        std::slice::from_ref(&subnet),
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
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
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

#[tokio::test]
async fn termination_event_routes_away_drains_and_emits_metrics() {
    let instance_a = instance("i-a", Ipv4Addr::new(10, 0, 0, 1));
    let instance_b = instance("i-b", Ipv4Addr::new(10, 0, 0, 2));
    let subnet = subnet("subnet-1");
    let initial_assignments = neuwerk::controlplane::cloud::compute_assignments(
        std::slice::from_ref(&subnet),
        &[instance_a.clone(), instance_b.clone()],
    );
    let assigned_id = initial_assignments
        .get("subnet-1")
        .cloned()
        .expect("initial assignment");
    let local_id = if assigned_id == "i-a" {
        "i-b".to_string()
    } else {
        "i-a".to_string()
    };
    let expected_target = if assigned_id == "i-a" {
        instance_a.dataplane_ip
    } else {
        instance_b.dataplane_ip
    };

    let provider = Arc::new(MockProvider::with_capabilities(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet.clone()],
        &local_id,
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
    ));
    provider
        .set_termination_event(Some(TerminationEvent {
            id: "term-1".to_string(),
            instance_id: local_id.clone(),
            deadline_epoch: 123,
        }))
        .await;

    let readiness = Arc::new(Mutex::new(HashMap::new()));
    readiness.lock().await.insert(instance_a.mgmt_ip, true);
    readiness.lock().await.insert(instance_b.mgmt_ip, true);
    let ready_checker = Arc::new(MutableReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let before = metrics.render().unwrap();
    let base_events = metric_value(&before, "integration_termination_events_total");
    let base_complete = metric_value(&before, "integration_termination_complete_total");
    let base_drain_start_count =
        metric_value(&before, "integration_termination_drain_start_seconds_count");
    let base_drain_duration_count = metric_value_with_labels(
        &before,
        "integration_drain_duration_seconds_count",
        &[("result", "complete")],
    );

    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags: tags() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        provider.clone(),
        None,
        None,
        metrics.clone(),
        drain_control.clone(),
        ready_checker,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();
    assert!(drain_control.is_draining());
    let routes = provider.routes.lock().await;
    assert_eq!(
        routes.get("subnet-1:neuwerk-default").copied(),
        Some(expected_target)
    );
    drop(routes);

    manager.reconcile_once().await.unwrap();
    let completed_after_completion = provider.completed_count().await;
    assert!(
        completed_after_completion >= 1,
        "expected completion after drained state transition"
    );

    manager.reconcile_once().await.unwrap();
    assert_eq!(provider.completed_count().await, completed_after_completion);

    let after = metrics.render().unwrap();
    let events = metric_value(&after, "integration_termination_events_total");
    let complete = metric_value(&after, "integration_termination_complete_total");
    let drain_start_count =
        metric_value(&after, "integration_termination_drain_start_seconds_count");
    let drain_duration_count = metric_value_with_labels(
        &after,
        "integration_drain_duration_seconds_count",
        &[("result", "complete")],
    );
    assert!(events >= base_events + 1.0, "metrics:\n{after}");
    assert!(complete >= base_complete + 1.0, "metrics:\n{after}");
    assert!(
        drain_start_count >= base_drain_start_count + 1.0,
        "metrics:\n{after}"
    );
    assert!(
        drain_duration_count >= base_drain_duration_count + 1.0,
        "metrics:\n{after}"
    );
}

#[tokio::test]
async fn termination_completion_error_increments_error_metric() {
    let instance_a = instance("i-a", Ipv4Addr::new(10, 0, 0, 1));
    let instance_b = instance("i-b", Ipv4Addr::new(10, 0, 0, 2));
    let subnet = subnet("subnet-1");
    let initial_assignments = neuwerk::controlplane::cloud::compute_assignments(
        std::slice::from_ref(&subnet),
        &[instance_a.clone(), instance_b.clone()],
    );
    let assigned_id = initial_assignments
        .get("subnet-1")
        .cloned()
        .expect("initial assignment");
    let local_id = if assigned_id == "i-a" {
        "i-b".to_string()
    } else {
        "i-a".to_string()
    };

    let base_provider = MockProvider::with_capabilities(
        vec![instance_a.clone(), instance_b.clone()],
        vec![subnet],
        &local_id,
        IntegrationCapabilities {
            instance_protection: false,
            termination_notice: true,
            lifecycle_hook: false,
        },
    );
    base_provider
        .set_termination_event(Some(TerminationEvent {
            id: "term-error-1".to_string(),
            instance_id: local_id,
            deadline_epoch: 123,
        }))
        .await;
    let provider = Arc::new(FailingCompleteProvider::new(base_provider));

    let readiness = Arc::new(Mutex::new(HashMap::new()));
    readiness.lock().await.insert(instance_a.mgmt_ip, true);
    readiness.lock().await.insert(instance_b.mgmt_ip, true);
    let ready_checker = Arc::new(MutableReady { readiness }) as Arc<dyn ReadyChecker>;

    let metrics = Metrics::new().unwrap();
    let before = metrics.render().unwrap();
    let base_complete = metric_value(&before, "integration_termination_complete_total");
    let base_complete_errors =
        metric_value(&before, "integration_termination_complete_errors_total");

    let drain_control = DrainControl::new();
    let cfg = IntegrationConfig {
        cluster_name: "demo".to_string(),
        route_name: "neuwerk-default".to_string(),
        drain_timeout_secs: 300,
        reconcile_interval_secs: 1,
        membership_auto_evict_terminating: true,
        membership_stale_after_secs: 0,
        membership_min_voters: 3,
        tag_filter: DiscoveryFilter { tags: tags() },
        http_ready_port: 8443,
        cluster_tls_dir: None,
    };
    let mut manager = IntegrationManager::new(
        cfg,
        provider,
        None,
        None,
        metrics.clone(),
        drain_control,
        ready_checker,
    )
    .await
    .expect("manager");

    manager.reconcile_once().await.unwrap();
    manager.reconcile_once().await.unwrap();

    let after = metrics.render().unwrap();
    let complete = metric_value(&after, "integration_termination_complete_total");
    let complete_errors = metric_value(&after, "integration_termination_complete_errors_total");
    assert_eq!(complete, base_complete, "metrics:\n{after}");
    assert!(
        complete_errors >= base_complete_errors + 1.0,
        "metrics:\n{after}"
    );
}
