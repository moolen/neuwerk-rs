pub mod provider;
pub mod types;
pub mod providers;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::time::MissedTickBehavior;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::cluster::rpc::{IntegrationClient, RaftTlsConfig};
use crate::controlplane::metrics::Metrics;
use crate::dataplane::DrainControl;

use provider::CloudProvider;
use types::{
    DrainState, DrainStatus, InstanceObservation, InstanceRef, IntegrationConfig,
    IntegrationMode, RouteChange, SubnetRef, TerminationEvent,
};

const ASSIGNMENT_PREFIX: &[u8] = b"integration/assignments/";
const DRAIN_PREFIX: &[u8] = b"integration/drain/";
const OBSERVED_PREFIX: &[u8] = b"integration/observed/";
const TERMINATION_PREFIX: &[u8] = b"integration/termination/";

#[derive(Clone)]
pub struct ReadyClient {
    client: reqwest::Client,
    port: u16,
}

impl ReadyClient {
    pub fn new(port: u16, ca_pem: Option<Vec<u8>>) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(2));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("ready client invalid ca pem: {err}"))?;
            builder = builder.add_root_certificate(cert);
        } else {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder.build().map_err(|err| format!("ready client: {err}"))?;
        Ok(Self { client, port })
    }

    async fn is_ready(&self, ip: IpAddr) -> bool {
        let url = format!("https://{ip}:{}{}", self.port, "/ready");
        match self.client.get(url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }
}

#[async_trait]
pub trait ReadyChecker: Send + Sync {
    async fn is_ready(&self, ip: IpAddr) -> bool;
}

#[async_trait]
impl ReadyChecker for ReadyClient {
    async fn is_ready(&self, ip: IpAddr) -> bool {
        ReadyClient::is_ready(self, ip).await
    }
}

pub struct IntegrationManager {
    cfg: IntegrationConfig,
    provider: Arc<dyn CloudProvider>,
    store: Option<ClusterStore>,
    raft: Option<openraft::Raft<ClusterTypeConfig>>,
    metrics: Metrics,
    drain_control: DrainControl,
    ready_client: Arc<dyn ReadyChecker>,
    local_instance: InstanceRef,
    local_instance_id: String,
    local_termination_event: Option<TerminationEvent>,
    local_termination_detected_epoch: Option<i64>,
    local_termination_published_id: Option<String>,
    local_cache: IntegrationCache,
}

#[derive(Default)]
struct IntegrationCache {
    assignments: HashMap<String, String>,
    drains: HashMap<String, DrainState>,
    terminations: HashMap<String, TerminationEvent>,
}

impl IntegrationManager {
    pub async fn new(
        cfg: IntegrationConfig,
        provider: Arc<dyn CloudProvider>,
        store: Option<ClusterStore>,
        raft: Option<openraft::Raft<ClusterTypeConfig>>,
        metrics: Metrics,
        drain_control: DrainControl,
        ready_client: Arc<dyn ReadyChecker>,
    ) -> Result<Self, String> {
        let local = provider
            .self_identity()
            .await
            .map_err(|err| format!("integration self identity: {err}"))?;
        Ok(Self {
            cfg,
            provider,
            store,
            raft,
            metrics,
            drain_control,
            ready_client,
            local_instance_id: local.id.clone(),
            local_instance: local,
            local_termination_event: None,
            local_termination_detected_epoch: None,
            local_termination_published_id: None,
            local_cache: IntegrationCache::default(),
        })
    }

    pub async fn run(mut self, mode: IntegrationMode) {
        if mode == IntegrationMode::None {
            return;
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(self.cfg.reconcile_interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(err) = self.tick().await {
                eprintln!("integration reconcile error: {err}");
            }
        }
    }

    pub async fn reconcile_once(&mut self) -> Result<(), String> {
        self.tick().await
    }

    fn is_leader(&self) -> bool {
        match &self.raft {
            Some(raft) => {
                let metrics = raft.metrics();
                let snapshot = metrics.borrow().clone();
                snapshot.current_leader == Some(snapshot.id)
            }
            None => true,
        }
    }

    fn leader_addr(&self) -> Option<SocketAddr> {
        let raft = self.raft.as_ref()?;
        let metrics = raft.metrics();
        let snapshot = metrics.borrow().clone();
        let leader_id = snapshot.current_leader?;
        let addr = snapshot
            .membership_config
            .nodes()
            .find(|(id, _)| **id == leader_id)
            .map(|(_, node)| node.addr.clone())?;
        addr.parse().ok()
    }

    async fn poll_local_termination(&mut self, now: i64) {
        if !self.provider.capabilities().termination_notice {
            return;
        }
        let event = match self.provider.poll_termination_notice(&self.local_instance).await {
            Ok(event) => event,
            Err(err) => {
                self.metrics.inc_integration_termination_poll_error();
                eprintln!("integration termination notice error: {err}");
                return;
            }
        };
        let Some(event) = event else {
            return;
        };
        let is_new = match &self.local_termination_event {
            Some(existing) => existing.id != event.id,
            None => true,
        };
        if is_new {
            self.local_termination_event = Some(event.clone());
            self.local_termination_detected_epoch = Some(now);
            self.local_termination_published_id = None;
            self.metrics.inc_integration_termination_event();
        }
        if self.local_termination_published_id.as_deref() != Some(&event.id) {
            match self.persist_termination_event(&event).await {
                Ok(_) => self.local_termination_published_id = Some(event.id.clone()),
                Err(err) => {
                    self.metrics.inc_integration_termination_publish_error();
                    eprintln!("integration termination publish error: {err}");
                }
            }
        }
    }

    async fn process_local_termination_completion(&mut self, now: i64) {
        if !self.provider.capabilities().termination_notice {
            return;
        }
        let event = if let Some(event) = &self.local_termination_event {
            event.clone()
        } else {
            match self.load_termination_events().await {
                Ok(map) => match map.get(&self.local_instance_id) {
                    Some(event) => event.clone(),
                    None => return,
                },
                Err(_) => return,
            }
        };
        let drains = match self.load_drains().await {
            Ok(drains) => drains,
            Err(err) => {
                eprintln!("integration drain load error: {err}");
                return;
            }
        };
        if !self.is_drained_local(now, &drains) {
            return;
        }
        match self.provider.complete_termination_action(&event).await {
            Ok(_) => {
                self.metrics.inc_integration_termination_complete();
                if let Err(err) = self.clear_termination_event(&event.instance_id).await {
                    eprintln!("integration termination clear error: {err}");
                    return;
                }
                self.local_termination_event = None;
                self.local_termination_detected_epoch = None;
                self.local_termination_published_id = None;
            }
            Err(err) => {
                self.metrics.inc_integration_termination_complete_error();
                eprintln!("integration termination completion failed: {err}");
            }
        }
    }

    async fn refresh_local_drain_control(&mut self, now: i64) -> Result<(), String> {
        let prev = self.local_cache.drains.get(&self.local_instance_id).cloned();
        let drains = self.load_drains().await?;
        let next = drains.get(&self.local_instance_id).cloned();
        if let (Some(prev), Some(next)) = (prev, next.clone()) {
            if prev.state == DrainStatus::Active && next.state == DrainStatus::Draining {
                if let Some(detected) = self.local_termination_detected_epoch {
                    self.metrics
                        .observe_integration_termination_drain_start(now - detected);
                }
            }
        }
        if let Some(next) = next {
            let draining = next.state != DrainStatus::Active;
            self.drain_control.set_draining(draining);
        }
        Ok(())
    }

    async fn tick(&mut self) -> Result<(), String> {
        let now = unix_now();
        self.poll_local_termination(now).await;
        if self.is_leader() {
            self.reconcile(now).await?;
        } else {
            self.refresh_local_drain_control(now).await?;
        }
        self.process_local_termination_completion(now).await;
        Ok(())
    }

    async fn reconcile(&mut self, now: i64) -> Result<(), String> {
        let filter = self.cfg.tag_filter.clone();
        let previous_assignments = self.load_assignments().await.unwrap_or_default();

        let mut instances = self
            .provider
            .discover_instances(&filter)
            .await
            .map_err(|err| format!("discover instances: {err}"))?;
        let mut subnets = self
            .provider
            .discover_subnets(&filter)
            .await
            .map_err(|err| format!("discover subnets: {err}"))?;

        let termination_events = self.load_termination_events().await.unwrap_or_default();

        subnets.retain(|subnet| filter.matches(&subnet.tags));

        let mut ready_instances = Vec::new();
        for instance in &instances {
            if !filter.matches(&instance.tags) {
                continue;
            }
            let ready = self.ready_client.is_ready(instance.mgmt_ip).await;
            let observation = InstanceObservation {
                ready,
                last_seen_epoch: now,
            };
            self.persist_observation(instance, &observation).await;
            if ready {
                ready_instances.push(instance.clone());
            }
        }

        let drain_states = self.load_drains().await?;
        let terminating: HashSet<String> = termination_events.keys().cloned().collect();

        instances.retain(|instance| instance.active && filter.matches(&instance.tags));
        let eligible_instances: Vec<InstanceRef> = ready_instances
            .iter()
            .filter(|instance| instance.active)
            .filter(|instance| !terminating.contains(&instance.id))
            .filter(|instance| match drain_states.get(&instance.id) {
                Some(state) => state.state == DrainStatus::Active,
                None => true,
            })
            .cloned()
            .collect();
        let fallback_instances: Vec<InstanceRef> = ready_instances
            .into_iter()
            .filter(|instance| instance.active)
            .filter(|instance| match drain_states.get(&instance.id) {
                Some(state) => state.state == DrainStatus::Active,
                None => true,
            })
            .collect();

        let assignments = compute_assignments_with_fallback(&subnets, &eligible_instances, &fallback_instances);
        let assignment_changes = assignment_change_count(&previous_assignments, &assignments);
        if assignment_changes > 0 {
            self.metrics.add_integration_assignment_changes(assignment_changes as u64);
        }
        self.persist_assignments(&assignments).await?;

        let mut assigned_instances: HashSet<String> = HashSet::new();
        for instance_id in assignments.values() {
            assigned_instances.insert(instance_id.clone());
        }

        for subnet in &subnets {
            let Some(target_id) = assignments.get(&subnet.id) else {
                continue;
            };
            let Some(target) = fallback_instances
                .iter()
                .find(|instance| &instance.id == target_id)
            else {
                continue;
            };
            let route = self
                .provider
                .get_route(subnet, &self.cfg.route_name)
                .await
                .map_err(|err| format!("get route: {err}"))?;
            let needs_update = match route {
                Some(route) => route.next_hop != target.dataplane_ip,
                None => true,
            };
            if needs_update {
                let change = self
                    .provider
                    .ensure_default_route(subnet, &self.cfg.route_name, target.dataplane_ip)
                    .await
                    .map_err(|err| format!("ensure route: {err}"))?;
                match change {
                    RouteChange::Created | RouteChange::Updated => {
                        self.metrics.inc_integration_route_change();
                    }
                    RouteChange::Unchanged => {}
                }
            }
        }

        if !fallback_instances.is_empty() {
            self.update_instance_protection(&fallback_instances, &assigned_instances)
                .await;
            self.update_drains(&instances, &assigned_instances, now).await?;
        }

        Ok(())
    }

    fn is_drained_local(&self, now: i64, drains: &HashMap<String, DrainState>) -> bool {
        let Some(state) = drains.get(&self.local_instance_id) else {
            return false;
        };
        match state.state {
            DrainStatus::Drained => true,
            DrainStatus::Draining => now >= state.deadline_epoch,
            DrainStatus::Active => false,
        }
    }

    async fn update_instance_protection(
        &self,
        instances: &[InstanceRef],
        assigned: &HashSet<String>,
    ) {
        if !self.provider.capabilities().instance_protection {
            return;
        }
        for instance in instances {
            let enabled = assigned.contains(&instance.id);
            if let Err(err) = self.provider.set_instance_protection(instance, enabled).await {
                self.metrics.inc_integration_protection_error();
                eprintln!("integration protection error: {err}");
            }
        }
    }

    async fn update_drains(
        &mut self,
        instances: &[InstanceRef],
        assigned: &HashSet<String>,
        now: i64,
    ) -> Result<(), String> {
        let active_flows_local = self.metrics.snapshot().dataplane.active_flows as i64;
        let timeout = self.cfg.drain_timeout_secs as i64;
        let mut updates: Vec<(String, DrainState)> = Vec::new();

        for instance in instances {
            let should_assign = assigned.contains(&instance.id);
            let prev = self.local_cache.drains.get(&instance.id).cloned();
            let active_flows = if instance.id == self.local_instance_id {
                active_flows_local
            } else {
                -1
            };
            let next = compute_drain_state(prev.clone(), should_assign, active_flows, now, timeout);
            if prev.as_ref() != Some(&next) {
                updates.push((instance.id.clone(), next.clone()));
            }

            if instance.id == self.local_instance_id {
                let draining = next.state != DrainStatus::Active;
                self.drain_control.set_draining(draining);
                if let Some(prev) = prev {
                    if prev.state == DrainStatus::Active && next.state == DrainStatus::Draining {
                        if let Some(detected) = self.local_termination_detected_epoch {
                            self.metrics
                                .observe_integration_termination_drain_start(now - detected);
                        }
                    }
                }
            }
        }

        for (instance_id, state) in updates {
            self.persist_drain(&instance_id, &state).await?;
            if state.state == DrainStatus::Drained {
                self.metrics.observe_integration_drain(now - state.since_epoch);
            }
        }

        Ok(())
    }

    async fn persist_assignments(&mut self, assignments: &HashMap<String, String>) -> Result<(), String> {
        if let Some(raft) = &self.raft {
            for (subnet_id, instance_id) in assignments {
                let key = assignment_key(subnet_id);
                let value = serde_json::to_vec(instance_id)
                    .map_err(|err| format!("assignment encode: {err}"))?;
                let cmd = ClusterCommand::Put { key, value };
                let _ = raft.client_write(cmd).await;
            }
        } else if self.store.is_none() {
            self.local_cache.assignments = assignments.clone();
        }
        Ok(())
    }

    async fn load_assignments(&mut self) -> Result<HashMap<String, String>, String> {
        if let Some(store) = &self.store {
            let entries = store
                .scan_state_prefix(ASSIGNMENT_PREFIX)
                .map_err(|err| format!("assignment scan: {err}"))?;
            let mut map = HashMap::new();
            for (key, value) in entries {
                let subnet_id = String::from_utf8_lossy(&key[ASSIGNMENT_PREFIX.len()..]).to_string();
                let instance_id: String = serde_json::from_slice(&value)
                    .map_err(|err| format!("assignment decode: {err}"))?;
                map.insert(subnet_id, instance_id);
            }
            self.local_cache.assignments = map.clone();
            return Ok(map);
        }
        Ok(self.local_cache.assignments.clone())
    }

    async fn load_drains(&mut self) -> Result<HashMap<String, DrainState>, String> {
        if let Some(store) = &self.store {
            let entries = store
                .scan_state_prefix(DRAIN_PREFIX)
                .map_err(|err| format!("drain scan: {err}"))?;
            let mut map = HashMap::new();
            for (key, value) in entries {
                let instance_id = String::from_utf8_lossy(&key[DRAIN_PREFIX.len()..]).to_string();
                let state: DrainState = serde_json::from_slice(&value)
                    .map_err(|err| format!("drain decode: {err}"))?;
                map.insert(instance_id, state);
            }
            self.local_cache.drains = map.clone();
            return Ok(map);
        }
        Ok(self.local_cache.drains.clone())
    }

    async fn load_termination_events(&mut self) -> Result<HashMap<String, TerminationEvent>, String> {
        if let Some(store) = &self.store {
            let entries = store
                .scan_state_prefix(TERMINATION_PREFIX)
                .map_err(|err| format!("termination scan: {err}"))?;
            let mut map = HashMap::new();
            for (key, value) in entries {
                let instance_id =
                    String::from_utf8_lossy(&key[TERMINATION_PREFIX.len()..]).to_string();
                let event: TerminationEvent = serde_json::from_slice(&value)
                    .map_err(|err| format!("termination decode: {err}"))?;
                map.insert(instance_id, event);
            }
            self.local_cache.terminations = map.clone();
            return Ok(map);
        }
        Ok(self.local_cache.terminations.clone())
    }

    async fn persist_drain(&mut self, instance_id: &str, state: &DrainState) -> Result<(), String> {
        if let Some(raft) = &self.raft {
            let key = drain_key(instance_id);
            let value = serde_json::to_vec(state).map_err(|err| format!("drain encode: {err}"))?;
            let cmd = ClusterCommand::Put { key, value };
            let _ = raft.client_write(cmd).await;
        } else if self.store.is_none() {
            self.local_cache.drains.insert(instance_id.to_string(), state.clone());
        }
        Ok(())
    }

    async fn persist_termination_event(&mut self, event: &TerminationEvent) -> Result<(), String> {
        if let Some(raft) = &self.raft {
            if self.is_leader() {
                let key = termination_key(&event.instance_id);
                let value = serde_json::to_vec(event)
                    .map_err(|err| format!("termination encode: {err}"))?;
                let cmd = ClusterCommand::Put { key, value };
                raft.client_write(cmd)
                    .await
                    .map_err(|err| err.to_string())?;
                return Ok(());
            }
            let Some(addr) = self.leader_addr() else {
                return Err("leader unknown".to_string());
            };
            let tls_dir = self
                .cfg
                .cluster_tls_dir
                .clone()
                .ok_or_else(|| "cluster tls dir missing".to_string())?;
            let tls = RaftTlsConfig::load(tls_dir)?;
            let mut client = IntegrationClient::connect(addr, tls).await?;
            client.publish_termination_event(event.clone()).await?;
            return Ok(());
        }
        self.local_cache
            .terminations
            .insert(event.instance_id.clone(), event.clone());
        Ok(())
    }

    async fn clear_termination_event(&mut self, instance_id: &str) -> Result<(), String> {
        if let Some(raft) = &self.raft {
            if self.is_leader() {
                let key = termination_key(instance_id);
                let cmd = ClusterCommand::Delete { key };
                raft.client_write(cmd)
                    .await
                    .map_err(|err| err.to_string())?;
                return Ok(());
            }
            let Some(addr) = self.leader_addr() else {
                return Err("leader unknown".to_string());
            };
            let tls_dir = self
                .cfg
                .cluster_tls_dir
                .clone()
                .ok_or_else(|| "cluster tls dir missing".to_string())?;
            let tls = RaftTlsConfig::load(tls_dir)?;
            let mut client = IntegrationClient::connect(addr, tls).await?;
            client.clear_termination_event(instance_id.to_string()).await?;
            return Ok(());
        }
        self.local_cache.terminations.remove(instance_id);
        Ok(())
    }

    async fn persist_observation(
        &self,
        instance: &InstanceRef,
        observation: &InstanceObservation,
    ) {
        if let Some(raft) = &self.raft {
            let key = observed_key(&instance.id);
            let value = match serde_json::to_vec(observation) {
                Ok(value) => value,
                Err(_) => return,
            };
            let cmd = ClusterCommand::Put { key, value };
            let _ = raft.client_write(cmd).await;
        }
    }
}

pub fn compute_assignments(
    subnets: &[SubnetRef],
    instances: &[InstanceRef],
) -> HashMap<String, String> {
    let mut assignments = HashMap::new();
    for subnet in subnets {
        let mut best: Option<(&InstanceRef, u64)> = None;
        for instance in instances {
            if instance.zone != subnet.zone {
                continue;
            }
            let score = rendezvous_score(&subnet.id, &instance.id);
            match best {
                Some((_, best_score)) if best_score >= score => {}
                _ => best = Some((instance, score)),
            }
        }
        if let Some((instance, _)) = best {
            assignments.insert(subnet.id.clone(), instance.id.clone());
        }
    }
    assignments
}

pub fn compute_assignments_with_fallback(
    subnets: &[SubnetRef],
    preferred: &[InstanceRef],
    fallback: &[InstanceRef],
) -> HashMap<String, String> {
    let mut assignments = HashMap::new();
    for subnet in subnets {
        if let Some((instance, _)) = select_best_instance(subnet, preferred) {
            assignments.insert(subnet.id.clone(), instance.id.clone());
            continue;
        }
        if let Some((instance, _)) = select_best_instance(subnet, fallback) {
            assignments.insert(subnet.id.clone(), instance.id.clone());
        }
    }
    assignments
}

fn select_best_instance<'a>(
    subnet: &SubnetRef,
    instances: &'a [InstanceRef],
) -> Option<(&'a InstanceRef, u64)> {
    let mut best: Option<(&InstanceRef, u64)> = None;
    for instance in instances {
        if instance.zone != subnet.zone {
            continue;
        }
        let score = rendezvous_score(&subnet.id, &instance.id);
        match best {
            Some((_, best_score)) if best_score >= score => {}
            _ => best = Some((instance, score)),
        }
    }
    best
}

pub fn select_seed_instance(instances: &[InstanceRef]) -> Option<InstanceRef> {
    let mut candidates: Vec<&InstanceRef> = instances.iter().filter(|i| i.active).collect();
    candidates.sort_by(|a, b| {
        a.created_at_epoch
            .cmp(&b.created_at_epoch)
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.first().cloned().cloned()
}

fn assignment_change_count(
    previous: &HashMap<String, String>,
    next: &HashMap<String, String>,
) -> usize {
    let mut changes = 0;
    for (subnet, instance_id) in next {
        if previous.get(subnet) != Some(instance_id) {
            changes += 1;
        }
    }
    for subnet in previous.keys() {
        if !next.contains_key(subnet) {
            changes += 1;
        }
    }
    changes
}

fn rendezvous_score(subnet_id: &str, instance_id: &str) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(subnet_id.as_bytes());
    hasher.update(b"::");
    hasher.update(instance_id.as_bytes());
    let hash = hasher.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&hash[..8]);
    u64::from_be_bytes(buf)
}

fn compute_drain_state(
    previous: Option<DrainState>,
    assigned: bool,
    active_flows: i64,
    now: i64,
    timeout: i64,
) -> DrainState {
    if assigned {
        return DrainState {
            state: DrainStatus::Active,
            since_epoch: now,
            deadline_epoch: now,
        };
    }

    let mut state = previous.unwrap_or(DrainState {
        state: DrainStatus::Active,
        since_epoch: now,
        deadline_epoch: now + timeout,
    });

    match state.state {
        DrainStatus::Active => {
            state.state = DrainStatus::Draining;
            state.since_epoch = now;
            state.deadline_epoch = now + timeout;
        }
        DrainStatus::Draining => {
            if (active_flows >= 0 && active_flows <= 0) || now >= state.deadline_epoch {
                state.state = DrainStatus::Drained;
            }
        }
        DrainStatus::Drained => {}
    }

    state
}

fn assignment_key(subnet_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(ASSIGNMENT_PREFIX.len() + subnet_id.len());
    key.extend_from_slice(ASSIGNMENT_PREFIX);
    key.extend_from_slice(subnet_id.as_bytes());
    key
}

fn drain_key(instance_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(DRAIN_PREFIX.len() + instance_id.len());
    key.extend_from_slice(DRAIN_PREFIX);
    key.extend_from_slice(instance_id.as_bytes());
    key
}

pub(crate) fn termination_key(instance_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(TERMINATION_PREFIX.len() + instance_id.len());
    key.extend_from_slice(TERMINATION_PREFIX);
    key.extend_from_slice(instance_id.as_bytes());
    key
}

fn observed_key(instance_id: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(OBSERVED_PREFIX.len() + instance_id.len());
    key.extend_from_slice(OBSERVED_PREFIX);
    key.extend_from_slice(instance_id.as_bytes());
    key
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use async_trait::async_trait;
    use proptest::prelude::*;
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

    #[test]
    fn assignments_respect_zone_affinity() {
        let instances = vec![instance("a", "1"), instance("b", "2")];
        let subnets = vec![subnet("s1", "1"), subnet("s2", "2")];
        let assignments = compute_assignments(&subnets, &instances);
        assert_eq!(assignments.get("s1"), Some(&"a".to_string()));
        assert_eq!(assignments.get("s2"), Some(&"b".to_string()));
    }

    #[test]
    fn assignments_with_fallback_prefers_primary_set() {
        let subnet = subnet("s1", "1");
        let instance_a = instance("a", "1");
        let instance_b = instance("b", "1");
        let preferred = vec![instance_b.clone()];
        let fallback = vec![instance_a.clone(), instance_b.clone()];
        let assignments = compute_assignments_with_fallback(&[subnet.clone()], &preferred, &fallback);
        assert_eq!(assignments.get("s1"), Some(&"b".to_string()));

        let empty: Vec<InstanceRef> = Vec::new();
        let assignments = compute_assignments_with_fallback(&[subnet], &empty, &fallback);
        assert!(assignments.contains_key("s1"));
    }

    #[test]
    fn assignments_with_fallback_uses_zone_match_when_preferred_missing() {
        let subnet_a = subnet("s1", "zone-a");
        let subnet_b = subnet("s2", "zone-b");
        let preferred = vec![instance("i1", "zone-a")];
        let fallback = vec![instance("i2", "zone-b")];
        let assignments = compute_assignments_with_fallback(&[subnet_a.clone(), subnet_b.clone()], &preferred, &fallback);
        assert_eq!(assignments.get("s1"), Some(&"i1".to_string()));
        assert_eq!(assignments.get("s2"), Some(&"i2".to_string()));
    }

    #[test]
    fn drain_state_transitions() {
        let now = 100;
        let timeout = 10;
        let state = compute_drain_state(None, false, 5, now, timeout);
        assert_eq!(state.state, DrainStatus::Draining);
        let later = compute_drain_state(Some(state.clone()), false, 0, now + 5, timeout);
        assert_eq!(later.state, DrainStatus::Drained);
        let active = compute_drain_state(Some(later), true, 0, now + 6, timeout);
        assert_eq!(active.state, DrainStatus::Active);
    }

    #[test]
    fn drain_state_requires_timeout_for_remote_flow_count() {
        let now = 100;
        let timeout = 10;
        let state = compute_drain_state(None, false, -1, now, timeout);
        assert_eq!(state.state, DrainStatus::Draining);
        let still = compute_drain_state(Some(state.clone()), false, -1, now + 5, timeout);
        assert_eq!(still.state, DrainStatus::Draining);
        let drained = compute_drain_state(Some(state), false, -1, now + 11, timeout);
        assert_eq!(drained.state, DrainStatus::Drained);
    }

    #[test]
    fn seed_selection_picks_oldest_then_id() {
        let mut a = instance("a", "1");
        a.created_at_epoch = 10;
        let mut b = instance("b", "1");
        b.created_at_epoch = 5;
        let mut c = instance("c", "1");
        c.created_at_epoch = 5;
        let seed = select_seed_instance(&[a.clone(), b.clone(), c.clone()]).unwrap();
        assert_eq!(seed.id, "b");
    }

    #[tokio::test]
    async fn reconcile_updates_routes_and_protection() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance_a = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let instance_b = tagged_instance(
            "i-b",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 1, 0, 2),
            tags.clone(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());
        let expected_assignments = compute_assignments(&[subnet.clone()], &[instance_a.clone(), instance_b.clone()]);
        let local_id = expected_assignments.values().next().cloned().unwrap();

        let provider = MockProvider::new(
            vec![instance_a.clone(), instance_b.clone()],
            vec![subnet.clone()],
            IntegrationCapabilities {
                instance_protection: true,
                termination_notice: false,
                lifecycle_hook: false,
            },
            &local_id,
        );
        let mut readiness = HashMap::new();
        readiness.insert(instance_a.mgmt_ip, true);
        readiness.insert(instance_b.mgmt_ip, true);
        let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags: tags.clone() },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics.clone(),
            drain_control.clone(),
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();

        let routes = provider.routes.lock().await;
        let assigned_id = expected_assignments.get("subnet-1").unwrap();
        let assigned_ip = if assigned_id == "i-a" {
            instance_a.dataplane_ip
        } else {
            instance_b.dataplane_ip
        };
        let route_key = format!("subnet-1:neuwerk-default");
        assert_eq!(routes.get(&route_key), Some(&assigned_ip));

        let protections = provider.protections.lock().await;
        let mut latest = HashMap::new();
        for (id, enabled) in protections.iter().cloned() {
            latest.insert(id, enabled);
        }
        let expected_a = assigned_id == "i-a";
        let expected_b = assigned_id == "i-b";
        assert_eq!(latest.get("i-a"), Some(&expected_a));
        assert_eq!(latest.get("i-b"), Some(&expected_b));

        assert_eq!(drain_control.is_draining(), false);
        assert_eq!(
            manager.local_cache.assignments.get("subnet-1"),
            expected_assignments.get("subnet-1")
        );
    }

    #[tokio::test]
    async fn reconcile_uses_only_ready_instances() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance_a = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let instance_b = tagged_instance(
            "i-b",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 1, 0, 2),
            tags.clone(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

        let provider = MockProvider::new(
            vec![instance_a.clone(), instance_b.clone()],
            vec![subnet.clone()],
            IntegrationCapabilities::default(),
            "i-a",
        );
        let mut readiness = HashMap::new();
        readiness.insert(instance_a.mgmt_ip, true);
        readiness.insert(instance_b.mgmt_ip, false);
        let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags: tags.clone() },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();

        let routes = provider.routes.lock().await;
        let route_key = format!("subnet-1:neuwerk-default");
        assert_eq!(routes.get(&route_key), Some(&instance_a.dataplane_ip));
    }

    #[tokio::test]
    async fn reconcile_skips_instances_without_tags() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            HashMap::new(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

        let provider = MockProvider::new(
            vec![instance],
            vec![subnet.clone()],
            IntegrationCapabilities::default(),
            "i-a",
        );
        let mut readiness = HashMap::new();
        readiness.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), true);
        let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();

        let routes = provider.routes.lock().await;
        assert!(routes.is_empty());
    }

    #[tokio::test]
    async fn reconcile_preserves_routes_when_no_ready_instances() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

        let provider = MockProvider::new(
            vec![instance.clone()],
            vec![subnet.clone()],
            IntegrationCapabilities::default(),
            "i-a",
        );
        {
            let mut routes = provider.routes.lock().await;
            routes.insert(
                format!("{}:neuwerk-default", subnet.id),
                instance.dataplane_ip,
            );
        }

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, false)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();

        let routes = provider.routes.lock().await;
        let route_key = format!("{}:neuwerk-default", subnet.id);
        assert_eq!(routes.get(&route_key), Some(&instance.dataplane_ip));
    }

    #[tokio::test]
    async fn termination_event_completes_after_drain() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let provider = MockProvider::new(
            vec![instance.clone()],
            Vec::new(),
            IntegrationCapabilities {
                instance_protection: false,
                termination_notice: true,
                lifecycle_hook: false,
            },
            "i-a",
        );
        *provider.termination_event.lock().await = Some(TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        });

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.local_cache.drains.insert(
            "i-a".to_string(),
            DrainState {
                state: DrainStatus::Drained,
                since_epoch: 0,
                deadline_epoch: 0,
            },
        );

        manager.reconcile_once().await.unwrap();

        let completed = provider.completed.lock().await;
        assert_eq!(*completed, 1);
    }

    #[tokio::test]
    async fn termination_event_persists_and_clears_locally() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let provider = MockProvider::new(
            vec![instance.clone()],
            Vec::new(),
            IntegrationCapabilities {
                instance_protection: false,
                termination_notice: true,
                lifecycle_hook: false,
            },
            "i-a",
        );
        *provider.termination_event.lock().await = Some(TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        });

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();
        assert!(manager
            .local_cache
            .terminations
            .contains_key("i-a"));

        manager.local_cache.drains.insert(
            "i-a".to_string(),
            DrainState {
                state: DrainStatus::Drained,
                since_epoch: 0,
                deadline_epoch: 0,
            },
        );
        manager.reconcile_once().await.unwrap();

        let completed = provider.completed.lock().await;
        assert_eq!(*completed, 1);
        assert!(manager.local_cache.terminations.get("i-a").is_none());
    }

    #[tokio::test]
    async fn termination_event_completes_after_timeout_when_draining() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let provider = MockProvider::new(
            vec![instance.clone()],
            Vec::new(),
            IntegrationCapabilities {
                instance_protection: false,
                termination_notice: true,
                lifecycle_hook: false,
            },
            "i-a",
        );
        *provider.termination_event.lock().await = Some(TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        });

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, false)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.local_cache.drains.insert(
            "i-a".to_string(),
            DrainState {
                state: DrainStatus::Draining,
                since_epoch: 0,
                deadline_epoch: 0,
            },
        );

        manager.reconcile_once().await.unwrap();

        let completed = provider.completed.lock().await;
        assert_eq!(*completed, 1);
        assert!(manager.local_cache.terminations.get("i-a").is_none());
    }

    #[tokio::test]
    async fn termination_event_is_not_republished_on_duplicate_notice() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let event = TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        };
        let provider = RepeatTerminationProvider::new(
            vec![instance.clone()],
            Vec::new(),
            IntegrationCapabilities {
                instance_protection: false,
                termination_notice: true,
                lifecycle_hook: false,
            },
            "i-a",
            2,
            event.clone(),
        );

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, true)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.reconcile_once().await.unwrap();
        manager.reconcile_once().await.unwrap();

        assert_eq!(manager.local_termination_published_id.as_deref(), Some("event-1"));
        assert_eq!(manager.local_cache.terminations.len(), 1);
        assert!(manager.local_cache.terminations.get("i-a").is_some());
        assert_eq!(provider.completed_count().await, 0);
    }

    #[tokio::test]
    async fn termination_event_ack_is_safe_to_repeat() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let event = TerminationEvent {
            id: "event-1".to_string(),
            instance_id: "i-a".to_string(),
            deadline_epoch: 0,
        };
        let provider = RepeatTerminationProvider::new(
            vec![instance.clone()],
            Vec::new(),
            IntegrationCapabilities {
                instance_protection: false,
                termination_notice: true,
                lifecycle_hook: false,
            },
            "i-a",
            2,
            event,
        );

        let ready = Arc::new(MockReady {
            readiness: vec![(instance.mgmt_ip, false)].into_iter().collect(),
        }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");

        manager.local_cache.drains.insert(
            "i-a".to_string(),
            DrainState {
                state: DrainStatus::Drained,
                since_epoch: 0,
                deadline_epoch: 0,
            },
        );

        manager.reconcile_once().await.unwrap();
        manager.reconcile_once().await.unwrap();

        assert_eq!(provider.completed_count().await, 2);
    }

    #[tokio::test]
    async fn assignments_avoid_terminating_instance_when_possible() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance_a = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let instance_b = tagged_instance(
            "i-b",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 1, 0, 2),
            tags.clone(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

        let provider = MockProvider::new(
            vec![instance_a.clone(), instance_b.clone()],
            vec![subnet.clone()],
            IntegrationCapabilities::default(),
            "i-a",
        );
        let mut readiness = HashMap::new();
        readiness.insert(instance_a.mgmt_ip, true);
        readiness.insert(instance_b.mgmt_ip, true);
        let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags: tags.clone() },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");
        manager.local_cache.terminations.insert(
            "i-a".to_string(),
            TerminationEvent {
                id: "event-1".to_string(),
                instance_id: "i-a".to_string(),
                deadline_epoch: 0,
            },
        );

        manager.reconcile_once().await.unwrap();
        let routes = provider.routes.lock().await;
        let route_key = format!("subnet-1:neuwerk-default");
        assert_eq!(routes.get(&route_key), Some(&instance_b.dataplane_ip));
    }

    #[tokio::test]
    async fn assignments_fall_back_to_terminating_instance_when_needed() {
        let tags = tagged(&[
            ("neuwerk.io/cluster", "demo"),
            ("neuwerk.io/role", "dataplane"),
        ]);
        let instance_a = tagged_instance(
            "i-a",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 1, 0, 1),
            tags.clone(),
        );
        let instance_b = tagged_instance(
            "i-b",
            "zone-1",
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 1, 0, 2),
            tags.clone(),
        );
        let subnet = tagged_subnet("subnet-1", "zone-1", tags.clone());

        let provider = MockProvider::new(
            vec![instance_a.clone(), instance_b.clone()],
            vec![subnet.clone()],
            IntegrationCapabilities::default(),
            "i-a",
        );
        let mut readiness = HashMap::new();
        readiness.insert(instance_a.mgmt_ip, true);
        readiness.insert(instance_b.mgmt_ip, false);
        let ready = Arc::new(MockReady { readiness }) as Arc<dyn ReadyChecker>;

        let metrics = Metrics::new().unwrap();
        let drain_control = DrainControl::new();
        let cfg = IntegrationConfig {
            cluster_name: "demo".to_string(),
            route_name: "neuwerk-default".to_string(),
            drain_timeout_secs: 300,
            reconcile_interval_secs: 1,
            tag_filter: DiscoveryFilter { tags: tags.clone() },
            http_ready_port: 8443,
            cluster_tls_dir: None,
        };
        let mut manager = IntegrationManager::new(
            cfg,
            Arc::new(provider.clone()),
            None,
            None,
            metrics,
            drain_control,
            ready,
        )
        .await
        .expect("manager");
        manager.local_cache.terminations.insert(
            "i-a".to_string(),
            TerminationEvent {
                id: "event-1".to_string(),
                instance_id: "i-a".to_string(),
                deadline_epoch: 0,
            },
        );

        manager.reconcile_once().await.unwrap();
        let routes = provider.routes.lock().await;
        let route_key = format!("subnet-1:neuwerk-default");
        assert_eq!(routes.get(&route_key), Some(&instance_a.dataplane_ip));
    }

    #[test]
    fn assignment_change_count_detects_changes() {
        let mut prev = HashMap::new();
        prev.insert("s1".to_string(), "i1".to_string());
        let mut next = HashMap::new();
        next.insert("s1".to_string(), "i2".to_string());
        next.insert("s2".to_string(), "i3".to_string());
        let changes = assignment_change_count(&prev, &next);
        assert_eq!(changes, 2);
    }

    fn zone_strategy() -> impl Strategy<Value = String> {
        prop_oneof![Just("zone-a"), Just("zone-b"), Just("zone-c")]
            .prop_map(|value| value.to_string())
    }

    fn subnet_strategy() -> impl Strategy<Value = Vec<SubnetRef>> {
        prop::collection::hash_set(".{1,8}", 1..8).prop_flat_map(|ids| {
            let ids: Vec<String> = ids.into_iter().collect();
            let len = ids.len();
            (Just(ids), prop::collection::vec(zone_strategy(), len))
        })
        .prop_map(|(ids, zones)| {
            ids.into_iter()
                .zip(zones)
                .map(|(id, zone)| SubnetRef {
                    id: id.clone(),
                    name: id,
                    zone,
                    cidr: "10.0.0.0/24".to_string(),
                    route_table_id: "rt".to_string(),
                    tags: HashMap::new(),
                })
                .collect()
        })
    }

    proptest! {
        #[test]
        fn assignments_only_choose_matching_zone(
            instance_zones in prop::collection::vec((zone_strategy(), any::<u8>()), 1..8),
            subnets in subnet_strategy(),
        ) {
            let instances: Vec<InstanceRef> = instance_zones
                .into_iter()
                .enumerate()
                .map(|(idx, (zone, octet))| InstanceRef {
                    id: format!("i{idx}"),
                    name: format!("i{idx}"),
                    zone,
                    created_at_epoch: 0,
                    mgmt_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                    dataplane_ip: Ipv4Addr::new(10, 1, 0, octet),
                    tags: HashMap::new(),
                    active: true,
                })
                .collect();
            let assignments = compute_assignments(&subnets, &instances);
            for subnet in &subnets {
                if let Some(instance_id) = assignments.get(&subnet.id) {
                    let instance = instances
                        .iter()
                        .find(|instance| &instance.id == instance_id)
                        .expect("assigned instance exists");
                    prop_assert_eq!(&instance.zone, &subnet.zone);
                }
            }
        }
    }

    #[test]
    fn assignments_only_change_for_removed_instance() {
        let subnets = vec![
            subnet("s1", "zone-a"),
            subnet("s2", "zone-a"),
            subnet("s3", "zone-a"),
        ];
        let instances = vec![
            instance("i1", "zone-a"),
            instance("i2", "zone-a"),
            instance("i3", "zone-a"),
        ];
        let assignments_before = compute_assignments(&subnets, &instances);
        let removed = "i2".to_string();
        let remaining: Vec<_> = instances
            .into_iter()
            .filter(|instance| instance.id != removed)
            .collect();
        let assignments_after = compute_assignments(&subnets, &remaining);
        for subnet in &subnets {
            let before = assignments_before.get(&subnet.id).expect("assignment");
            let after = assignments_after.get(&subnet.id).expect("assignment");
            if before != &removed {
                assert_eq!(before, after);
            }
        }
    }
}
