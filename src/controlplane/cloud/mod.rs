pub mod provider;
pub mod providers;
pub mod types;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use crate::controlplane::cluster::rpc::{IntegrationClient, RaftTlsConfig};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::metrics::Metrics;
use crate::dataplane::DrainControl;

use provider::CloudProvider;
use types::{
    DrainState, DrainStatus, InstanceObservation, InstanceRef, IntegrationConfig, IntegrationMode,
    RouteChange, SubnetRef, TerminationEvent,
};

const ASSIGNMENT_PREFIX: &[u8] = b"integration/assignments/";
const DRAIN_PREFIX: &[u8] = b"integration/drain/";
const OBSERVED_PREFIX: &[u8] = b"integration/observed/";
const TERMINATION_PREFIX: &[u8] = b"integration/termination/";
const TERMINATION_HEARTBEAT_LEAD_SECS: i64 = 30;

#[derive(Clone)]
pub struct ReadyClient {
    client: reqwest::Client,
    port: u16,
}

impl ReadyClient {
    pub fn new(port: u16, ca_pem: Option<Vec<u8>>) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(2));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|err| format!("ready client invalid ca pem: {err}"))?;
            builder = builder.add_root_certificate(cert);
        } else {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|err| format!("ready client: {err}"))?;
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
        let mut ticker =
            tokio::time::interval(Duration::from_secs(self.cfg.reconcile_interval_secs));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            if let Err(err) = self.tick().await {
                warn!(error = %err, "integration reconcile error");
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
        let event = match self
            .provider
            .poll_termination_notice(&self.local_instance)
            .await
        {
            Ok(event) => event,
            Err(err) => {
                self.metrics.inc_integration_termination_poll_error();
                warn!(error = %err, "integration termination notice poll failed");
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
                    warn!(error = %err, "integration termination publish failed");
                }
            }
        }
    }

    async fn process_local_termination_completion(&mut self, now: i64) {
        if !self.provider.capabilities().termination_notice {
            return;
        }
        let mut event = if let Some(event) = &self.local_termination_event {
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
                warn!(error = %err, "integration drain load failed");
                return;
            }
        };
        if !self.is_drained_local(now, &drains) {
            self.refresh_local_termination_heartbeat(&mut event, now)
                .await;
            return;
        }
        match self.provider.complete_termination_action(&event).await {
            Ok(_) => {
                self.metrics.inc_integration_termination_complete();
                if let Err(err) = self.clear_termination_event(&event.instance_id).await {
                    warn!(error = %err, "integration termination event clear failed");
                    return;
                }
                self.local_termination_event = None;
                self.local_termination_detected_epoch = None;
                self.local_termination_published_id = None;
            }
            Err(err) => {
                self.metrics.inc_integration_termination_complete_error();
                error!(error = %err, "integration termination completion failed");
            }
        }
    }

    async fn refresh_local_termination_heartbeat(
        &mut self,
        event: &mut TerminationEvent,
        now: i64,
    ) {
        if !self.provider.capabilities().lifecycle_hook {
            return;
        }
        if now + TERMINATION_HEARTBEAT_LEAD_SECS < event.deadline_epoch {
            return;
        }
        let next_deadline = match self.provider.record_termination_heartbeat(event).await {
            Ok(next_deadline) => next_deadline,
            Err(err) => {
                warn!(error = %err, "integration termination heartbeat failed");
                return;
            }
        };
        let Some(next_deadline) = next_deadline else {
            return;
        };
        if next_deadline <= event.deadline_epoch {
            return;
        }
        event.deadline_epoch = next_deadline;
        if let Err(err) = self.persist_termination_event(event).await {
            warn!(error = %err, "integration termination heartbeat persist failed");
            return;
        }
        self.local_termination_event = Some(event.clone());
        self.local_termination_published_id = Some(event.id.clone());
    }

    async fn refresh_local_drain_control(&mut self, now: i64) -> Result<(), String> {
        let prev = self
            .local_cache
            .drains
            .get(&self.local_instance_id)
            .cloned();
        let drains = self.load_drains().await?;
        let next = drains.get(&self.local_instance_id).cloned();
        if let Some(next) = next.clone() {
            if transitioned_into_draining(prev.as_ref(), &next) {
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

        let lifecycle_only_mode = subnets.is_empty();
        let assignments = if lifecycle_only_mode {
            HashMap::new()
        } else {
            compute_assignments_with_fallback(&subnets, &eligible_instances, &fallback_instances)
        };
        let assignment_changes = assignment_change_count(&previous_assignments, &assignments);
        if assignment_changes > 0 {
            self.metrics
                .add_integration_assignment_changes(assignment_changes as u64);
        }
        self.persist_assignments(&assignments).await?;

        let assigned_instances: HashSet<String> = if lifecycle_only_mode {
            eligible_instances
                .iter()
                .map(|instance| instance.id.clone())
                .collect()
        } else {
            assignments.values().cloned().collect()
        };
        let protected_instances: HashSet<String> = if lifecycle_only_mode {
            HashSet::new()
        } else {
            assigned_instances.clone()
        };
        let protection_candidates: Vec<InstanceRef> = if lifecycle_only_mode {
            instances
                .iter()
                .filter(|instance| !terminating.contains(&instance.id))
                .cloned()
                .collect()
        } else {
            fallback_instances.clone()
        };

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

        if !protection_candidates.is_empty() {
            self.update_instance_protection(&protection_candidates, &protected_instances)
                .await;
        }
        if !fallback_instances.is_empty() {
            self.update_drains(&instances, &assigned_instances, now)
                .await?;
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
            if let Err(err) = self
                .provider
                .set_instance_protection(instance, enabled)
                .await
            {
                self.metrics.inc_integration_protection_error();
                warn!(error = %err, "integration protection error");
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
                if transitioned_into_draining(prev.as_ref(), &next) {
                    if let Some(detected) = self.local_termination_detected_epoch {
                        self.metrics
                            .observe_integration_termination_drain_start(now - detected);
                    }
                }
            }
        }

        for (instance_id, state) in updates {
            self.persist_drain(&instance_id, &state).await?;
            if state.state == DrainStatus::Drained {
                self.metrics
                    .observe_integration_drain(now - state.since_epoch);
            }
        }

        Ok(())
    }

    async fn persist_assignments(
        &mut self,
        assignments: &HashMap<String, String>,
    ) -> Result<(), String> {
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
                let subnet_id =
                    String::from_utf8_lossy(&key[ASSIGNMENT_PREFIX.len()..]).to_string();
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
                let state: DrainState =
                    serde_json::from_slice(&value).map_err(|err| format!("drain decode: {err}"))?;
                map.insert(instance_id, state);
            }
            self.local_cache.drains = map.clone();
            return Ok(map);
        }
        Ok(self.local_cache.drains.clone())
    }

    async fn load_termination_events(
        &mut self,
    ) -> Result<HashMap<String, TerminationEvent>, String> {
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
            self.local_cache
                .drains
                .insert(instance_id.to_string(), state.clone());
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
            client
                .clear_termination_event(instance_id.to_string())
                .await?;
            return Ok(());
        }
        self.local_cache.terminations.remove(instance_id);
        Ok(())
    }

    async fn persist_observation(&self, instance: &InstanceRef, observation: &InstanceObservation) {
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
            if active_flows == 0 || now >= state.deadline_epoch {
                state.state = DrainStatus::Drained;
            }
        }
        DrainStatus::Drained => {}
    }

    state
}

fn transitioned_into_draining(previous: Option<&DrainState>, next: &DrainState) -> bool {
    if next.state != DrainStatus::Draining {
        return false;
    }
    match previous.map(|state| &state.state) {
        None => true,
        Some(DrainStatus::Active) => true,
        Some(DrainStatus::Draining | DrainStatus::Drained) => false,
    }
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
mod tests;
