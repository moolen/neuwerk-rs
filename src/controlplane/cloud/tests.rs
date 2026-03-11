use super::*;
use async_trait::async_trait;
use proptest::prelude::*;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::Mutex;

use crate::controlplane::cloud::provider::{CloudError, CloudProvider};
use crate::controlplane::cloud::types::{
    CapabilityResult, DiscoveryFilter, IntegrationCapabilities, RouteRef,
};
use crate::controlplane::metrics::Metrics;
use crate::dataplane::DrainControl;

fn instance(id: &str, zone: &str) -> InstanceRef {
    InstanceRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: zone.to_string(),
        created_at_epoch: 0,
        mgmt_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        dataplane_ip: Ipv4Addr::new(10, 1, 0, 1),
        tags: HashMap::new(),
        active: true,
    }
}

fn tagged(tags: &[(&str, &str)]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in tags {
        map.insert((*key).to_string(), (*value).to_string());
    }
    map
}

fn tagged_instance(
    id: &str,
    zone: &str,
    mgmt_ip: Ipv4Addr,
    dataplane_ip: Ipv4Addr,
    tags: HashMap<String, String>,
) -> InstanceRef {
    InstanceRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: zone.to_string(),
        created_at_epoch: 0,
        mgmt_ip: IpAddr::V4(mgmt_ip),
        dataplane_ip,
        tags,
        active: true,
    }
}

fn tagged_subnet(id: &str, zone: &str, tags: HashMap<String, String>) -> SubnetRef {
    SubnetRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: zone.to_string(),
        cidr: "10.0.0.0/24".to_string(),
        route_table_id: "rt".to_string(),
        tags,
    }
}

#[derive(Clone)]
struct MockReady {
    readiness: HashMap<IpAddr, bool>,
}

#[async_trait]
impl ReadyChecker for MockReady {
    async fn is_ready(&self, ip: IpAddr) -> bool {
        self.readiness.get(&ip).copied().unwrap_or(false)
    }
}

#[derive(Clone)]
struct MockProvider {
    instances: Arc<Mutex<Vec<InstanceRef>>>,
    subnets: Arc<Mutex<Vec<SubnetRef>>>,
    routes: Arc<Mutex<HashMap<String, Ipv4Addr>>>,
    protections: Arc<Mutex<Vec<(String, bool)>>>,
    termination_event: Arc<Mutex<Option<TerminationEvent>>>,
    heartbeat_deadline: Arc<Mutex<Option<i64>>>,
    heartbeat_calls: Arc<Mutex<u32>>,
    completed: Arc<Mutex<u32>>,
    caps: IntegrationCapabilities,
    self_id: String,
}

impl MockProvider {
    fn new(
        instances: Vec<InstanceRef>,
        subnets: Vec<SubnetRef>,
        caps: IntegrationCapabilities,
        self_id: &str,
    ) -> Self {
        Self {
            instances: Arc::new(Mutex::new(instances)),
            subnets: Arc::new(Mutex::new(subnets)),
            routes: Arc::new(Mutex::new(HashMap::new())),
            protections: Arc::new(Mutex::new(Vec::new())),
            termination_event: Arc::new(Mutex::new(None)),
            heartbeat_deadline: Arc::new(Mutex::new(None)),
            heartbeat_calls: Arc::new(Mutex::new(0)),
            completed: Arc::new(Mutex::new(0)),
            caps,
            self_id: self_id.to_string(),
        }
    }
}

#[derive(Clone)]
struct RepeatTerminationProvider {
    base: MockProvider,
    remaining: Arc<Mutex<u8>>,
    event: TerminationEvent,
}

impl RepeatTerminationProvider {
    fn new(
        instances: Vec<InstanceRef>,
        subnets: Vec<SubnetRef>,
        caps: IntegrationCapabilities,
        self_id: &str,
        repeats: u8,
        event: TerminationEvent,
    ) -> Self {
        Self {
            base: MockProvider::new(instances, subnets, caps, self_id),
            remaining: Arc::new(Mutex::new(repeats)),
            event,
        }
    }

    async fn completed_count(&self) -> u32 {
        *self.base.completed.lock().await
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
        let key = format!("{}:{route_name}", subnet.id);
        let change = match routes.get(&key) {
            Some(existing) if *existing == next_hop => RouteChange::Unchanged,
            Some(_) => RouteChange::Updated,
            None => RouteChange::Created,
        };
        routes.insert(key, next_hop);
        Ok(change)
    }

    async fn set_instance_protection(
        &self,
        instance: &InstanceRef,
        enabled: bool,
    ) -> Result<CapabilityResult, CloudError> {
        self.protections
            .lock()
            .await
            .push((instance.id.clone(), enabled));
        Ok(CapabilityResult::Applied)
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
        let mut completed = self.completed.lock().await;
        *completed += 1;
        Ok(CapabilityResult::Applied)
    }

    async fn record_termination_heartbeat(
        &self,
        _event: &TerminationEvent,
    ) -> Result<Option<i64>, CloudError> {
        let mut calls = self.heartbeat_calls.lock().await;
        *calls += 1;
        Ok(*self.heartbeat_deadline.lock().await)
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.caps.clone()
    }
}

#[async_trait]
impl CloudProvider for RepeatTerminationProvider {
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
        _instance: &InstanceRef,
    ) -> Result<Option<TerminationEvent>, CloudError> {
        let mut remaining = self.remaining.lock().await;
        if *remaining == 0 {
            return Ok(None);
        }
        *remaining -= 1;
        Ok(Some(self.event.clone()))
    }

    async fn complete_termination_action(
        &self,
        event: &TerminationEvent,
    ) -> Result<CapabilityResult, CloudError> {
        self.base.complete_termination_action(event).await
    }

    async fn record_termination_heartbeat(
        &self,
        event: &TerminationEvent,
    ) -> Result<Option<i64>, CloudError> {
        self.base.record_termination_heartbeat(event).await
    }

    fn capabilities(&self) -> IntegrationCapabilities {
        self.base.capabilities()
    }
}

fn subnet(id: &str, zone: &str) -> SubnetRef {
    SubnetRef {
        id: id.to_string(),
        name: id.to_string(),
        zone: zone.to_string(),
        cidr: "10.0.0.0/24".to_string(),
        route_table_id: "rt".to_string(),
        tags: HashMap::new(),
    }
}

include!("tests/cases.rs");
