use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dataplane::audit::{AuditEmitter, AuditEvent as DataplaneAuditEvent, AuditEventType};
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::drain::DrainControl;
use crate::dataplane::flow::{
    ExpiredFlow, FlowEntry, FlowKey, FlowResizeCounters, FlowTable, SynOnlyEntry, SynOnlyTable,
    TcpHandshakePhase, DEFAULT_SOURCE_GROUP,
};
use crate::dataplane::nat::{NatTable, ReverseKey};
use crate::dataplane::overlay::{OverlayConfig, SnatMode};
use crate::dataplane::packet::Packet;
use crate::dataplane::policy::{
    new_shared_exact_source_group_index, DynamicIpSetV4, PacketMeta, PolicyDecision,
    PolicySnapshot, SharedExactSourceGroupIndex, SharedPolicySnapshot,
};
use crate::dataplane::tls::{
    TlsDirection, TlsFlowDecision, TlsFlowState, TlsObservation, TlsVerifier,
};
use crate::dataplane::wiretap::{flow_id_from_key, WiretapEmitter, WiretapEvent, WiretapEventType};
use crate::metrics::{current_dpdk_worker_id, DataplaneShardMetricHandles, Metrics};

static NAT_MISS_LOGS: AtomicUsize = AtomicUsize::new(0);
const FLOW_RATIO_UPDATE_INTERVAL: u64 = 64;
const NAT_RATIO_UPDATE_INTERVAL: u64 = 64;
const RECENT_SYN_ONLY_CLOSE_WINDOW_SECS: u64 = 30;

#[derive(Debug, Clone)]
struct RecentSynOnlyClose {
    reason: Arc<str>,
    closed_at: u64,
}

fn parse_truthy_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| parse_truthy_flag(&raw))
        .unwrap_or(false)
}

mod common;
mod icmp;
mod no_snat;

use common::*;
use icmp::{
    handle_inbound_icmp, handle_inbound_icmp_no_snat, handle_outbound_icmp,
    handle_outbound_icmp_no_snat,
};
use no_snat::{
    handle_inbound_no_snat, handle_outbound_dns_target, handle_outbound_no_snat,
    is_dns_target_outbound_flow,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Drop,
    Forward { out_port: u16 },
    ToHost,
}

#[derive(Debug)]
pub struct EngineState {
    pub flows: FlowTable,
    pub syn_only: SynOnlyTable,
    pub syn_only_enabled: bool,
    recent_syn_only_closes: HashMap<FlowKey, RecentSynOnlyClose>,
    pub nat: NatTable,
    pub policy: Arc<RwLock<PolicySnapshot>>,
    policy_snapshot: SharedPolicySnapshot,
    pub internal_net: Ipv4Addr,
    pub internal_prefix: u8,
    pub public_ip: Ipv4Addr,
    pub data_port: u16,
    pub tls_verifier: TlsVerifier,
    pub dataplane_config: DataplaneConfigStore,
    pub overlay: OverlayConfig,
    pub snat_mode: SnatMode,
    dns_target_ips: Vec<Ipv4Addr>,
    dns_allowlist_override: Option<DynamicIpSetV4>,
    wiretap: Option<WiretapEmitter>,
    audit: Option<AuditEmitter>,
    now_override_secs: Option<u64>,
    last_eviction_check_secs: Option<u64>,
    metrics: Option<Arc<Metrics>>,
    dataplane_shard_metrics: Option<DataplaneShardMetricHandles>,
    detailed_dataplane_observability: bool,
    flow_ratio_update_debt: AtomicU64,
    nat_ratio_update_debt: AtomicU64,
    flow_resize_grow_seen: AtomicU64,
    flow_resize_shrink_seen: AtomicU64,
    flow_resize_rehash_seen: AtomicU64,
    drain_control: Option<DrainControl>,
    shard_id: Option<usize>,
    policy_applied_generation: Option<Arc<AtomicU64>>,
    service_policy_applied_generation: Option<Arc<AtomicU64>>,
    intercept_to_host_steering: bool,
    exact_source_policy_index: SharedExactSourceGroupIndex,
}

impl EngineState {
    pub fn new(
        policy: Arc<RwLock<PolicySnapshot>>,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        public_ip: Ipv4Addr,
        data_port: u16,
    ) -> Self {
        Self::new_with_idle_timeout(
            policy,
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
            crate::dataplane::nat::DEFAULT_IDLE_TIMEOUT_SECS,
        )
    }

    pub fn new_with_idle_timeout(
        policy: Arc<RwLock<PolicySnapshot>>,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        public_ip: Ipv4Addr,
        data_port: u16,
        idle_timeout_secs: u64,
    ) -> Self {
        let (exact_source_policy_index, policy_snapshot) = match policy.read() {
            Ok(lock) => (
                new_shared_exact_source_group_index(&lock),
                Arc::new(arc_swap::ArcSwap::from_pointee(lock.clone())),
            ),
            Err(_) => (
                Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
                Arc::new(arc_swap::ArcSwap::from_pointee(PolicySnapshot::new(
                    crate::dataplane::policy::DefaultPolicy::Deny,
                    vec![],
                ))),
            ),
        };
        let flows = FlowTable::new_with_timeout(idle_timeout_secs);
        let syn_only =
            SynOnlyTable::new_with_timeout(flows.incomplete_tcp_syn_sent_idle_timeout_secs());
        let syn_only_enabled = env_flag_enabled("NEUWERK_DPDK_SYN_ONLY_TABLE");
        let detailed_dataplane_observability =
            env_flag_enabled("NEUWERK_DP_DETAILED_OBSERVABILITY");
        Self {
            flows,
            syn_only,
            syn_only_enabled,
            recent_syn_only_closes: HashMap::new(),
            nat: NatTable::new_with_timeout(idle_timeout_secs),
            policy,
            policy_snapshot,
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
            tls_verifier: TlsVerifier::new(),
            dataplane_config: DataplaneConfigStore::new(),
            overlay: OverlayConfig::none(),
            snat_mode: SnatMode::Auto,
            dns_target_ips: Vec::new(),
            dns_allowlist_override: None,
            wiretap: None,
            audit: None,
            now_override_secs: None,
            last_eviction_check_secs: None,
            metrics: None,
            dataplane_shard_metrics: None,
            detailed_dataplane_observability,
            flow_ratio_update_debt: AtomicU64::new(0),
            nat_ratio_update_debt: AtomicU64::new(0),
            flow_resize_grow_seen: AtomicU64::new(0),
            flow_resize_shrink_seen: AtomicU64::new(0),
            flow_resize_rehash_seen: AtomicU64::new(0),
            drain_control: None,
            shard_id: None,
            policy_applied_generation: None,
            service_policy_applied_generation: None,
            intercept_to_host_steering: false,
            exact_source_policy_index,
        }
    }

    fn cidr_contains_ip(ip: Ipv4Addr, net_ip: Ipv4Addr, prefix: u8) -> bool {
        let prefix = prefix.min(32);
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        let net = u32::from(net_ip) & mask;
        let addr = u32::from(ip) & mask;
        net == addr
    }

    fn has_explicit_internal_cidr(&self) -> bool {
        self.internal_net != Ipv4Addr::UNSPECIFIED || self.internal_prefix != 32
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        if self.policy_snapshot.load().is_internal(ip) {
            return true;
        }
        if self.has_explicit_internal_cidr() {
            return Self::cidr_contains_ip(ip, self.internal_net, self.internal_prefix);
        }
        if let Some(cfg) = self.dataplane_config.get() {
            if Self::cidr_contains_ip(ip, cfg.ip, cfg.prefix) {
                return true;
            }
        }
        Self::cidr_contains_ip(ip, self.internal_net, self.internal_prefix)
    }

    pub fn set_time_override(&mut self, now_secs: Option<u64>) {
        self.now_override_secs = now_secs;
    }

    pub fn set_dns_allowlist(&mut self, allowlist: DynamicIpSetV4) {
        self.dns_allowlist_override = Some(allowlist);
    }

    pub fn set_dns_target_ips(&mut self, targets: Vec<Ipv4Addr>) {
        self.dns_target_ips = targets;
    }

    pub fn set_dataplane_config(&mut self, config: DataplaneConfigStore) {
        self.dataplane_config = config;
    }

    pub fn set_overlay_config(&mut self, overlay: OverlayConfig) {
        self.overlay = overlay;
    }

    pub fn set_snat_mode(&mut self, mode: SnatMode) {
        self.snat_mode = mode;
    }

    pub fn set_drain_control(&mut self, control: DrainControl) {
        self.drain_control = Some(control);
    }

    pub fn set_shard_id(&mut self, shard_id: usize) {
        self.shard_id = Some(shard_id);
        self.refresh_metric_handles();
        self.update_flow_metrics();
        self.update_syn_only_metrics();
        self.update_nat_metrics();
    }

    pub fn set_service_policy_applied_generation(&mut self, tracker: Arc<AtomicU64>) {
        self.service_policy_applied_generation = Some(tracker);
    }

    pub fn set_policy_applied_generation(&mut self, tracker: Arc<AtomicU64>) {
        self.policy_applied_generation = Some(tracker);
    }

    pub fn set_intercept_to_host_steering(&mut self, enabled: bool) {
        self.intercept_to_host_steering = enabled;
    }

    pub fn set_exact_source_policy_index(&mut self, index: SharedExactSourceGroupIndex) {
        self.exact_source_policy_index = index;
    }

    pub fn set_policy_snapshot(&mut self, snapshot: SharedPolicySnapshot) {
        self.policy_snapshot = snapshot;
    }

    pub fn clone_for_shard(&self) -> Self {
        let flows = FlowTable::new_with_timeout(self.flows.idle_timeout_secs());
        let state = Self {
            syn_only: SynOnlyTable::new_with_timeout(
                self.flows.incomplete_tcp_syn_sent_idle_timeout_secs(),
            ),
            syn_only_enabled: self.syn_only_enabled,
            recent_syn_only_closes: HashMap::new(),
            flows,
            nat: NatTable::new_with_timeout(self.nat.idle_timeout_secs()),
            policy: self.policy.clone(),
            policy_snapshot: self.policy_snapshot.clone(),
            internal_net: self.internal_net,
            internal_prefix: self.internal_prefix,
            public_ip: self.public_ip,
            data_port: self.data_port,
            tls_verifier: self.tls_verifier.clone(),
            dataplane_config: self.dataplane_config.clone(),
            overlay: self.overlay.clone(),
            snat_mode: self.snat_mode,
            dns_target_ips: self.dns_target_ips.clone(),
            dns_allowlist_override: self.dns_allowlist_override.clone(),
            wiretap: self.wiretap.clone(),
            audit: self.audit.clone(),
            now_override_secs: self.now_override_secs,
            last_eviction_check_secs: None,
            metrics: self.metrics.clone(),
            dataplane_shard_metrics: None,
            detailed_dataplane_observability: self.detailed_dataplane_observability,
            flow_ratio_update_debt: AtomicU64::new(0),
            nat_ratio_update_debt: AtomicU64::new(0),
            flow_resize_grow_seen: AtomicU64::new(0),
            flow_resize_shrink_seen: AtomicU64::new(0),
            flow_resize_rehash_seen: AtomicU64::new(0),
            drain_control: self.drain_control.clone(),
            shard_id: None,
            policy_applied_generation: self.policy_applied_generation.clone(),
            service_policy_applied_generation: self.service_policy_applied_generation.clone(),
            intercept_to_host_steering: self.intercept_to_host_steering,
            exact_source_policy_index: self.exact_source_policy_index.clone(),
        };
        state.update_flow_metrics();
        state.update_syn_only_metrics();
        state.update_nat_metrics();
        state
    }

    pub fn is_draining(&self) -> bool {
        self.drain_control
            .as_ref()
            .map(|control| control.is_draining())
            .unwrap_or(false)
    }

    pub fn set_wiretap_emitter(&mut self, emitter: WiretapEmitter) {
        self.wiretap = Some(emitter);
    }

    pub fn set_audit_emitter(&mut self, emitter: AuditEmitter) {
        self.audit = Some(emitter);
    }

    pub fn set_metrics(&mut self, metrics: Metrics) {
        self.set_metrics_handle(Arc::new(metrics));
    }

    pub fn set_metrics_handle(&mut self, metrics: Arc<Metrics>) {
        self.metrics = Some(metrics);
        self.refresh_metric_handles();
        self.update_flow_metrics();
        self.update_syn_only_metrics();
        self.update_nat_metrics();
    }

    fn refresh_metric_handles(&mut self) {
        self.dataplane_shard_metrics = self.metrics.as_ref().and_then(|metrics| {
            self.shard_id
                .map(|shard_id| metrics.bind_dataplane_shard_metrics(shard_id))
        });
    }

    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_deref()
    }

    fn dpdk_worker_id(&self) -> Option<usize> {
        current_dpdk_worker_id()
    }

    fn note_tcp_handshake_event_for_target(&self, event: &str, target_host: Ipv4Addr) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        let target_host = target_host.to_string();
        metrics.inc_dp_tcp_handshake_event_by_target(worker_id, event, &target_host);
    }

    fn note_tcp_handshake_final_ack_in(&self, source_group: &str, target_host: Ipv4Addr) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        let target_host = target_host.to_string();
        metrics.inc_dp_tcp_handshake_final_ack_in(worker_id, source_group, &target_host);
    }

    fn note_tcp_handshake_synack_out_without_followup_ack(
        &self,
        source_group: &str,
        target_host: Ipv4Addr,
        reason: &str,
    ) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        let target_host = target_host.to_string();
        metrics.inc_dp_tcp_handshake_synack_out_without_followup_ack(
            worker_id,
            source_group,
            &target_host,
            reason,
        );
    }

    fn note_tcp_handshake_drop(&self, phase: &str, reason: &str) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.inc_dp_tcp_handshake_drop(worker_id, phase, reason);
    }

    fn note_tcp_handshake_stage(&self, direction: &str, stage: &str, duration: Duration) {
        if !self.detailed_dataplane_observability {
            return;
        }
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.observe_dp_handshake_stage(worker_id, direction, stage, duration);
    }

    fn note_syn_only_lookup(&self, result: &str) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.inc_dp_syn_only_lookup(worker_id, result);
    }

    fn note_syn_only_promotion(&self, reason: &str) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.inc_dp_syn_only_promotion(worker_id, reason);
    }

    fn note_syn_only_eviction(&self, reason: &str, count: u64) {
        if count == 0 {
            return;
        }
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.add_dp_syn_only_eviction(worker_id, reason, count);
    }

    fn note_table_probe(&self, table: &str, operation: &str, result: &str, steps: usize) {
        if !self.detailed_dataplane_observability {
            return;
        }
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.observe_dp_table_probe(worker_id, table, operation, result, steps);
    }

    fn note_nat_port_scan(&self, result: &str, steps: usize) {
        if !self.detailed_dataplane_observability {
            return;
        }
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.observe_dp_nat_port_scan(worker_id, result, steps);
    }

    fn note_flow_lifecycle_event(&self, event: &str, reason: &str, count: u64) {
        if count == 0 {
            return;
        }
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.add_dp_flow_lifecycle_event(worker_id, event, reason, count);
    }

    fn note_tcp_handshake_close_age(
        &self,
        proto: u8,
        reason: &str,
        first_seen: u64,
        last_seen: u64,
        handshake_phase: TcpHandshakePhase,
    ) {
        if proto != 6 {
            return;
        }
        let lifetime_secs = last_seen.saturating_sub(first_seen) as f64;
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.observe_dp_tcp_handshake_close_age(
            worker_id,
            reason,
            handshake_phase.label(),
            lifetime_secs,
        );
    }

    fn record_recent_syn_only_close(&mut self, flow: &FlowKey, reason: &str, now: u64) {
        self.recent_syn_only_closes.retain(|_, close| {
            now.saturating_sub(close.closed_at) <= RECENT_SYN_ONLY_CLOSE_WINDOW_SECS
        });
        self.recent_syn_only_closes.insert(
            *flow,
            RecentSynOnlyClose {
                reason: Arc::from(reason),
                closed_at: now,
            },
        );
    }

    fn classify_synack_flow_missing_reason(&self, flow: &FlowKey, now: u64) -> &'static str {
        let Some(close) = self.recent_syn_only_closes.get(flow) else {
            return "flow_missing";
        };
        if now.saturating_sub(close.closed_at) > RECENT_SYN_ONLY_CLOSE_WINDOW_SECS {
            return "flow_missing";
        }
        match close.reason.as_ref() {
            "idle_timeout" => "recent_syn_only_idle_timeout",
            "tcp_rst" => "recent_syn_only_tcp_rst",
            "tcp_fin" => "recent_syn_only_tcp_fin",
            "policy_deny" => "recent_syn_only_policy_deny",
            "policy_drop" => "recent_syn_only_policy_drop",
            _ => "flow_missing",
        }
    }

    pub fn inc_dp_arp_handled(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.inc_dp_arp_handled();
        }
    }

    pub fn evict_expired_now(&mut self) {
        let now = self.now_secs();
        self.last_eviction_check_secs = Some(now);
        self.evict_expired(now);
    }

    pub fn run_housekeeping(&mut self) {
        let now = self.now_secs();
        self.evict_expired_if_needed(now);
    }

    fn now_secs(&self) -> u64 {
        if let Some(now) = self.now_override_secs {
            return now;
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn evict_expired(&mut self, now: u64) {
        let expired_nat = self.nat.evict_expired(now);
        if expired_nat > 0 {
            self.note_nat_delta(-(expired_nat as i64));
        }
        let expired_syn_only = self.syn_only.evict_expired(now);
        if !expired_syn_only.is_empty() {
            self.note_syn_only_eviction("idle_timeout", expired_syn_only.len() as u64);
            self.note_flow_lifecycle_event("close", "idle_timeout", expired_syn_only.len() as u64);
            for flow in &expired_syn_only {
                self.record_recent_syn_only_close(&flow.key, "idle_timeout", now);
                let source_group = flow.source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP);
                self.note_dns_grant_flow_close(source_group, flow.key.dst_ip, flow.last_seen);
                self.observe_flow_close(
                    source_group,
                    "idle_timeout",
                    flow.first_seen,
                    flow.last_seen,
                );
                self.note_tcp_handshake_close_age(
                    flow.key.proto,
                    "idle_timeout",
                    flow.first_seen,
                    flow.last_seen,
                    TcpHandshakePhase::SynOnly,
                );
            }
            for flow in expired_syn_only {
                if self.nat.remove(&flow.key) {
                    self.note_nat_close();
                }
            }
        }
        let expired = self.flows.evict_expired(now);
        self.note_flow_expired(expired);
        self.update_flow_metrics();
        self.update_syn_only_metrics();
        self.update_nat_metrics();
    }

    fn evict_expired_if_needed(&mut self, now: u64) {
        if self.last_eviction_check_secs == Some(now) {
            return;
        }
        self.last_eviction_check_secs = Some(now);
        self.evict_expired(now);
    }

    fn note_flow_open_with_reason(
        &self,
        flow: FlowKey,
        proto: u8,
        source_group: &str,
        reason: &str,
        now: u64,
    ) {
        self.note_dns_grant_flow_open(source_group, flow.dst_ip, now);
        self.note_flow_lifecycle_event("open", reason, 1);
        if let Some(metrics) = &self.metrics {
            metrics.inc_dp_flow_open(proto_label(proto), source_group);
            if let Some(shard_metrics) = &self.dataplane_shard_metrics {
                shard_metrics.inc_active_flows();
                metrics.add_dp_active_flows(1);
            } else {
                metrics.add_dp_active_flows(1);
            }
        }
        self.maybe_update_flow_table_utilization(false);
    }

    fn note_nat_open(&self) {
        self.note_nat_delta(1);
    }

    fn note_nat_close(&self) {
        self.note_nat_delta(-1);
    }

    fn note_nat_delta(&self, delta: i64) {
        if let Some(metrics) = &self.metrics {
            if let Some(shard_metrics) = &self.dataplane_shard_metrics {
                shard_metrics.add_active_nat_entries(delta);
                metrics.add_dp_active_nat_entries(delta);
            } else {
                metrics.add_dp_active_nat_entries(delta);
            }
            let delta_weight = delta.unsigned_abs().max(1);
            let debt = self
                .nat_ratio_update_debt
                .fetch_add(delta_weight, Ordering::Relaxed)
                + delta_weight;
            if debt >= NAT_RATIO_UPDATE_INTERVAL {
                self.nat_ratio_update_debt.store(0, Ordering::Relaxed);
                self.update_nat_ratio_metrics(metrics);
            }
        }
    }

    fn service_policy_ready_for_generation(&self, generation: u64) -> bool {
        self.service_policy_applied_generation
            .as_ref()
            .map(|tracker| tracker.load(Ordering::Acquire) >= generation)
            .unwrap_or(true)
    }

    fn current_policy_generation(&self) -> u64 {
        self.policy_applied_generation
            .as_ref()
            .map(|tracker| tracker.load(Ordering::Acquire))
            .unwrap_or_else(|| self.policy_snapshot.load().generation())
    }

    fn policy_snapshot(&self) -> arc_swap::Guard<Arc<PolicySnapshot>> {
        self.policy_snapshot.load()
    }

    fn dns_grant_allowlist_for_group(&self, source_group: &str) -> Option<DynamicIpSetV4> {
        if let Some(allowlist) = &self.dns_allowlist_override {
            return Some(allowlist.clone());
        }
        if source_group == DEFAULT_SOURCE_GROUP {
            return None;
        }
        self.policy_snapshot
            .load()
            .dns_allowlist_for_group(source_group)
    }

    fn note_dns_grant_flow_open(&self, source_group: &str, dst_ip: Ipv4Addr, now: u64) {
        if let Some(allowlist) = self.dns_grant_allowlist_for_group(source_group) {
            allowlist.flow_open(dst_ip, now);
        }
    }

    fn note_dns_grant_flow_close(&self, source_group: &str, dst_ip: Ipv4Addr, last_seen: u64) {
        if let Some(allowlist) = self.dns_grant_allowlist_for_group(source_group) {
            allowlist.flow_close(dst_ip, last_seen);
        }
    }

    fn note_flow_expired(&self, expired: Vec<ExpiredFlow>) {
        self.note_flow_lifecycle_event("close", "idle_timeout", expired.len() as u64);
        for flow in &expired {
            let source_group = flow.source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP);
            self.note_dns_grant_flow_close(source_group, flow.key.dst_ip, flow.last_seen);
            self.observe_flow_close(
                source_group,
                "idle_timeout",
                flow.first_seen,
                flow.last_seen,
            );
            self.note_tcp_handshake_close_age(
                flow.key.proto,
                "idle_timeout",
                flow.first_seen,
                flow.last_seen,
                flow.handshake_phase,
            );
            if flow.handshake_phase == TcpHandshakePhase::SynAckSeen {
                self.note_tcp_handshake_synack_out_without_followup_ack(
                    source_group,
                    flow.key.dst_ip,
                    "idle_timeout",
                );
            }
        }
        if let Some(emitter) = &self.wiretap {
            for flow in expired {
                emitter.try_send(WiretapEvent {
                    event_type: WiretapEventType::FlowEnd,
                    flow_id: flow_id_from_key(&flow.key),
                    src_ip: flow.key.src_ip,
                    dst_ip: flow.key.dst_ip,
                    src_port: flow.key.src_port,
                    dst_port: flow.key.dst_port,
                    proto: flow.key.proto,
                    packets_in: flow.packets_in,
                    packets_out: flow.packets_out,
                    last_seen: flow.last_seen,
                });
            }
        }
    }

    fn note_syn_only_close(&self, flow: &FlowKey, entry: &SynOnlyEntry, reason: &str, now: u64) {
        self.note_flow_lifecycle_event("close", reason, 1);
        self.note_tcp_handshake_close_age(
            flow.proto,
            reason,
            entry.first_seen,
            now,
            TcpHandshakePhase::SynOnly,
        );
        let source_group = entry
            .source_group
            .as_deref()
            .unwrap_or(DEFAULT_SOURCE_GROUP);
        self.note_dns_grant_flow_close(source_group, flow.dst_ip, now);
        self.observe_flow_close(source_group, reason, entry.first_seen, now);
    }

    fn observe_entry_flow_close(&self, entry: &FlowEntry, reason: &str, now: u64) {
        self.observe_flow_close(entry.source_group(), reason, entry.first_seen, now);
    }

    fn note_flow_close(&self, flow: &FlowKey, entry: &FlowEntry, reason: &str, now: u64) {
        let handshake_phase = entry.handshake_phase();
        let source_group = entry.source_group();
        self.note_dns_grant_flow_close(source_group, flow.dst_ip, now);
        self.note_flow_lifecycle_event("close", reason, 1);
        self.note_tcp_handshake_close_age(
            flow.proto,
            reason,
            entry.first_seen,
            now,
            handshake_phase,
        );
        if handshake_phase == TcpHandshakePhase::SynAckSeen {
            self.note_tcp_handshake_synack_out_without_followup_ack(
                source_group,
                flow.dst_ip,
                reason,
            );
        }
        self.observe_entry_flow_close(entry, reason, now);
        if let Some(metrics) = &self.metrics {
            if let Some(shard_metrics) = &self.dataplane_shard_metrics {
                shard_metrics.dec_active_flows();
                metrics.add_dp_active_flows(-1);
            } else {
                metrics.add_dp_active_flows(-1);
            }
        }
        self.maybe_update_flow_table_utilization(false);
    }

    fn observe_flow_close(
        &self,
        source_group: &str,
        reason: &str,
        first_seen: u64,
        last_seen: u64,
    ) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        let lifetime = last_seen.saturating_sub(first_seen) as f64;
        metrics.observe_dp_flow_close(source_group, reason, lifetime);
    }

    fn update_flow_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            if let Some(shard_id) = self.shard_id {
                metrics.set_dp_active_flows_shard(shard_id, self.flows.len());
            } else {
                metrics.set_dp_active_flows(self.flows.len());
            }
            self.maybe_update_flow_table_utilization(true);
        }
    }

    fn update_syn_only_metrics(&self) {
        let (Some(metrics), Some(worker_id)) = (&self.metrics, self.dpdk_worker_id()) else {
            return;
        };
        metrics.set_dp_syn_only_active_flows(worker_id, self.syn_only.len());
    }

    fn update_nat_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            let count = self.nat.len();
            if let Some(shard_id) = self.shard_id {
                metrics.set_dp_active_nat_entries_shard(shard_id, count);
            } else {
                metrics.set_dp_active_nat_entries(count);
            }
            self.nat_ratio_update_debt.store(0, Ordering::Relaxed);
            self.update_nat_ratio_metrics(metrics);
        }
    }

    fn maybe_update_flow_table_utilization(&self, force: bool) {
        let Some(metrics) = &self.metrics else {
            return;
        };
        if !force {
            let debt = self.flow_ratio_update_debt.fetch_add(1, Ordering::Relaxed) + 1;
            if debt < FLOW_RATIO_UPDATE_INTERVAL {
                return;
            }
        }
        self.flow_ratio_update_debt.store(0, Ordering::Relaxed);
        let capacity = self.flows.capacity() as f64;
        let live = self.flows.len() as f64;
        let tombstones = self.flows.tombstones() as f64;
        let ratio = if capacity > 0.0 { live / capacity } else { 0.0 };
        let used_ratio = if capacity > 0.0 {
            (live + tombstones) / capacity
        } else {
            0.0
        };
        let tombstone_ratio = if capacity > 0.0 {
            tombstones / capacity
        } else {
            0.0
        };
        metrics.set_dp_flow_table_utilization_ratio(ratio);
        if let Some(shard_id) = self.shard_id {
            metrics.set_dp_flow_table_utilization_ratio_shard(shard_id, ratio);
        }
        if let Some(worker_id) = self.dpdk_worker_id() {
            metrics.set_dp_flow_table_capacity_worker(worker_id, self.flows.capacity());
            metrics.set_dp_flow_table_tombstones_worker(worker_id, self.flows.tombstones());
            metrics.set_dp_flow_table_used_slots_ratio_worker(worker_id, used_ratio);
            metrics.set_dp_flow_table_tombstone_ratio_worker(worker_id, tombstone_ratio);
            let FlowResizeCounters {
                grow,
                shrink,
                rehash,
            } = self.flows.resize_counters();
            let grow_prev = self.flow_resize_grow_seen.swap(grow, Ordering::Relaxed);
            let shrink_prev = self.flow_resize_shrink_seen.swap(shrink, Ordering::Relaxed);
            let rehash_prev = self.flow_resize_rehash_seen.swap(rehash, Ordering::Relaxed);
            metrics.add_dp_flow_table_resize_event(
                worker_id,
                "grow",
                grow.saturating_sub(grow_prev),
            );
            metrics.add_dp_flow_table_resize_event(
                worker_id,
                "shrink",
                shrink.saturating_sub(shrink_prev),
            );
            metrics.add_dp_flow_table_resize_event(
                worker_id,
                "rehash",
                rehash.saturating_sub(rehash_prev),
            );
        }
    }

    fn update_nat_ratio_metrics(&self, metrics: &Metrics) {
        let total_ports = NatTable::port_range_len() as f64;
        let port_ratio = if total_ports > 0.0 {
            self.nat.len() as f64 / total_ports
        } else {
            0.0
        };
        metrics.set_dp_nat_port_utilization_ratio(port_ratio);

        let capacity = self.nat.capacity() as f64;
        let table_ratio = if capacity > 0.0 {
            self.nat.len() as f64 / capacity
        } else {
            0.0
        };
        metrics.set_dp_nat_table_utilization_ratio(table_ratio);
        if let Some(shard_id) = self.shard_id {
            metrics.set_dp_nat_table_utilization_ratio_shard(shard_id, table_ratio);
        }
    }
}

include!("engine/packet_path.rs");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataplane::config::DataplaneConfig;
    use crate::dataplane::policy::DefaultPolicy;

    fn test_state(snat_mode: SnatMode, idle_timeout_secs: u64) -> EngineState {
        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Allow,
            vec![],
        )));
        let public_ip = match snat_mode {
            SnatMode::None => Ipv4Addr::UNSPECIFIED,
            _ => Ipv4Addr::new(203, 0, 113, 1),
        };
        let mut state = EngineState::new_with_idle_timeout(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            public_ip,
            0,
            idle_timeout_secs,
        );
        state.set_snat_mode(snat_mode);
        state.syn_only_enabled = false;
        state
    }

    fn build_ipv4_tcp_flags(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Packet {
        let total_len = 20 + 20;
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[8] = 64;
        buf[9] = 6;
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());

        let l4_off = 20;
        buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[l4_off + 12] = 0x50;
        buf[l4_off + 13] = flags;
        buf[l4_off + 16..l4_off + 18].copy_from_slice(&1024u16.to_be_bytes());

        let mut pkt = Packet::new(buf);
        assert!(pkt.recalc_checksums());
        pkt
    }

    #[test]
    fn explicit_internal_cidr_overrides_dataplane_subnet_classification() {
        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Allow,
            vec![],
        )));
        let state = EngineState::new(
            policy,
            Ipv4Addr::new(192, 168, 178, 83),
            32,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        state.dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(192, 168, 178, 77),
            prefix: 24,
            gateway: Ipv4Addr::new(192, 168, 178, 1),
            mac: [0x52, 0x54, 0x00, 0x08, 0x1f, 0x1b],
            lease_expiry: None,
        });

        assert!(state.is_internal(Ipv4Addr::new(192, 168, 178, 83)));
        assert!(!state.is_internal(Ipv4Addr::new(192, 168, 178, 44)));
        assert!(!state.is_internal(Ipv4Addr::new(192, 168, 178, 84)));
    }

    #[test]
    fn outbound_rst_removes_flow_and_nat_state() {
        let mut state = test_state(SnatMode::Auto, 300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut open =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x02);
        assert_eq!(
            handle_packet(&mut open, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_some());
        assert!(state.nat.get_entry(&flow).is_some());

        state.set_time_override(Some(2));
        let mut rst =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x04);
        assert_eq!(
            handle_packet(&mut rst, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_none());
        assert!(state.nat.get_entry(&flow).is_none());
    }

    #[test]
    fn outbound_non_syn_miss_without_nat_is_dropped_without_creating_state() {
        let mut state = test_state(SnatMode::Auto, 300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut fin =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x11);
        assert_eq!(handle_packet(&mut fin, &mut state), Action::Drop);
        assert!(state.flows.get_entry(&flow).is_none());
        assert!(state.nat.get_entry(&flow).is_none());
    }

    #[test]
    fn late_fin_after_flow_close_does_not_recreate_flow_or_nat_state() {
        let mut state = test_state(SnatMode::Auto, 300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut syn =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x02);
        assert_eq!(
            handle_packet(&mut syn, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_some());
        assert!(state.nat.get_entry(&flow).is_some());

        state.set_time_override(Some(2));
        let mut rst =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x04);
        assert_eq!(
            handle_packet(&mut rst, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_none());
        assert!(state.nat.get_entry(&flow).is_none());

        state.set_time_override(Some(3));
        let mut fin =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x11);
        assert_eq!(handle_packet(&mut fin, &mut state), Action::Drop);
        assert!(state.flows.get_entry(&flow).is_none());
        assert!(state.nat.get_entry(&flow).is_none());
    }

    #[test]
    fn outbound_no_snat_non_syn_miss_is_dropped_without_creating_state() {
        let mut state = test_state(SnatMode::None, 300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut fin =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x11);
        assert_eq!(handle_packet(&mut fin, &mut state), Action::Drop);
        assert!(state.flows.get_entry(&flow).is_none());
    }

    #[test]
    fn late_fin_after_no_snat_flow_close_does_not_recreate_state() {
        let mut state = test_state(SnatMode::None, 300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut syn =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x02);
        assert_eq!(
            handle_packet(&mut syn, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_some());

        state.set_time_override(Some(2));
        let mut rst =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x04);
        assert_eq!(
            handle_packet(&mut rst, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_none());

        state.set_time_override(Some(3));
        let mut fin =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x11);
        assert_eq!(handle_packet(&mut fin, &mut state), Action::Drop);
        assert!(state.flows.get_entry(&flow).is_none());
    }

    #[test]
    fn expired_state_is_removed_by_housekeeping_not_handle_packet() {
        let mut state = test_state(SnatMode::Auto, 1);
        let expired_flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut open = build_ipv4_tcp_flags(
            expired_flow.src_ip,
            expired_flow.dst_ip,
            expired_flow.src_port,
            expired_flow.dst_port,
            0x02,
        );
        assert_eq!(
            handle_packet(&mut open, &mut state),
            Action::Forward { out_port: 0 }
        );

        state.set_time_override(Some(5));
        let mut unrelated = build_ipv4_tcp_flags(
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Addr::new(198, 51, 100, 11),
            40_001,
            443,
            0x11,
        );
        assert_eq!(handle_packet(&mut unrelated, &mut state), Action::Drop);
        assert!(state.flows.get_entry(&expired_flow).is_some());
        assert!(state.nat.get_entry(&expired_flow).is_some());

        state.run_housekeeping();
        assert!(state.flows.get_entry(&expired_flow).is_none());
        assert!(state.nat.get_entry(&expired_flow).is_none());
    }

    #[test]
    fn no_snat_syn_only_promotes_on_inbound_synack() {
        let mut state = test_state(SnatMode::None, 300);
        state.syn_only_enabled = true;
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 40_000,
            dst_port: 443,
            proto: 6,
        };

        state.set_time_override(Some(1));
        let mut syn =
            build_ipv4_tcp_flags(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 0x02);
        assert_eq!(
            handle_packet(&mut syn, &mut state),
            Action::Forward { out_port: 0 }
        );
        assert!(state.flows.get_entry(&flow).is_none());
        assert_eq!(state.syn_only.len(), 1);

        state.set_time_override(Some(2));
        let mut synack =
            build_ipv4_tcp_flags(flow.dst_ip, flow.src_ip, flow.dst_port, flow.src_port, 0x12);
        assert_eq!(
            handle_packet(&mut synack, &mut state),
            Action::Forward { out_port: 0 }
        );
        let entry = state
            .flows
            .get_entry(&flow)
            .expect("flow should be promoted");
        assert!(entry.syn_outbound_seen());
        assert!(entry.synack_inbound_seen());
        assert!(state.syn_only.is_empty());
    }
}
