use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::controlplane::metrics::Metrics;
use crate::dataplane::audit::{AuditEmitter, AuditEvent as DataplaneAuditEvent, AuditEventType};
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::drain::DrainControl;
use crate::dataplane::flow::{ExpiredFlow, FlowEntry, FlowKey, FlowTable, DEFAULT_SOURCE_GROUP};
use crate::dataplane::nat::{NatTable, ReverseKey};
use crate::dataplane::overlay::{OverlayConfig, SnatMode};
use crate::dataplane::packet::Packet;
use crate::dataplane::policy::{
    new_shared_exact_source_group_index, DynamicIpSetV4, PacketMeta, PolicyDecision,
    PolicySnapshot, SharedExactSourceGroupIndex,
};
use crate::dataplane::tls::{
    TlsDirection, TlsFlowDecision, TlsFlowState, TlsObservation, TlsVerifier,
};
use crate::dataplane::wiretap::{flow_id_from_key, WiretapEmitter, WiretapEvent, WiretapEventType};

static NAT_MISS_LOGS: AtomicUsize = AtomicUsize::new(0);

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
    pub nat: NatTable,
    pub policy: Arc<RwLock<PolicySnapshot>>,
    pub internal_net: Ipv4Addr,
    pub internal_prefix: u8,
    pub public_ip: Ipv4Addr,
    pub data_port: u16,
    pub tls_verifier: TlsVerifier,
    pub dataplane_config: DataplaneConfigStore,
    pub overlay: OverlayConfig,
    pub snat_mode: SnatMode,
    dns_target_ips: Vec<Ipv4Addr>,
    dns_allowlist: Option<DynamicIpSetV4>,
    wiretap: Option<WiretapEmitter>,
    audit: Option<AuditEmitter>,
    now_override_secs: Option<u64>,
    last_eviction_check_secs: Option<u64>,
    metrics: Option<Arc<Metrics>>,
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
        let exact_source_policy_index = match policy.read() {
            Ok(lock) => new_shared_exact_source_group_index(&lock),
            Err(_) => Arc::new(arc_swap::ArcSwap::from_pointee(Default::default())),
        };
        Self {
            flows: FlowTable::new_with_timeout(idle_timeout_secs),
            nat: NatTable::new_with_timeout(idle_timeout_secs),
            policy,
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
            tls_verifier: TlsVerifier::new(),
            dataplane_config: DataplaneConfigStore::new(),
            overlay: OverlayConfig::none(),
            snat_mode: SnatMode::Auto,
            dns_target_ips: Vec::new(),
            dns_allowlist: None,
            wiretap: None,
            audit: None,
            now_override_secs: None,
            last_eviction_check_secs: None,
            metrics: None,
            drain_control: None,
            shard_id: None,
            policy_applied_generation: None,
            service_policy_applied_generation: None,
            intercept_to_host_steering: false,
            exact_source_policy_index,
        }
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        if let Some(cfg) = self.dataplane_config.get() {
            let prefix = cfg.prefix.min(32);
            if prefix == 0 {
                return true;
            }
            let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
            let net = u32::from(cfg.ip) & mask;
            let addr = u32::from(ip) & mask;
            if net == addr {
                return true;
            }
        }
        if let Ok(lock) = self.policy.read() {
            if lock.is_internal(ip) {
                return true;
            }
        }
        let prefix = self.internal_prefix.min(32);
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        let net = u32::from(self.internal_net) & mask;
        let addr = u32::from(ip) & mask;
        net == addr
    }

    pub fn set_time_override(&mut self, now_secs: Option<u64>) {
        self.now_override_secs = now_secs;
    }

    pub fn set_dns_allowlist(&mut self, allowlist: DynamicIpSetV4) {
        self.dns_allowlist = Some(allowlist);
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
        self.update_flow_metrics();
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

    pub fn clone_for_shard(&self) -> Self {
        let state = Self {
            flows: FlowTable::new_with_timeout(self.flows.idle_timeout_secs()),
            nat: NatTable::new_with_timeout(self.nat.idle_timeout_secs()),
            policy: self.policy.clone(),
            internal_net: self.internal_net,
            internal_prefix: self.internal_prefix,
            public_ip: self.public_ip,
            data_port: self.data_port,
            tls_verifier: self.tls_verifier.clone(),
            dataplane_config: self.dataplane_config.clone(),
            overlay: self.overlay.clone(),
            snat_mode: self.snat_mode,
            dns_target_ips: self.dns_target_ips.clone(),
            dns_allowlist: self.dns_allowlist.clone(),
            wiretap: self.wiretap.clone(),
            audit: self.audit.clone(),
            now_override_secs: self.now_override_secs,
            last_eviction_check_secs: None,
            metrics: self.metrics.clone(),
            drain_control: self.drain_control.clone(),
            shard_id: None,
            policy_applied_generation: self.policy_applied_generation.clone(),
            service_policy_applied_generation: self.service_policy_applied_generation.clone(),
            intercept_to_host_steering: self.intercept_to_host_steering,
            exact_source_policy_index: self.exact_source_policy_index.clone(),
        };
        state.update_flow_metrics();
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
        self.update_flow_metrics();
        self.update_nat_metrics();
    }

    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_deref()
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
        self.nat.evict_expired(now);
        let expired = self.flows.evict_expired(now);
        self.note_flow_expired(expired);
        self.update_flow_metrics();
        self.update_nat_metrics();
    }

    fn evict_expired_if_needed(&mut self, now: u64) {
        if self.last_eviction_check_secs == Some(now) {
            return;
        }
        self.last_eviction_check_secs = Some(now);
        self.evict_expired(now);
    }

    fn note_flow_open(&self, flow: FlowKey, proto: u8, source_group: &str, now: u64) {
        if let Some(allowlist) = &self.dns_allowlist {
            allowlist.flow_open(flow.dst_ip, now);
        }
        if let Some(metrics) = &self.metrics {
            metrics.inc_dp_flow_open(proto_label(proto), source_group);
            if let Some(shard_id) = self.shard_id {
                metrics.add_dp_active_flows_shard(shard_id, 1);
            } else {
                metrics.add_dp_active_flows(1);
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
            .unwrap_or_else(|| match self.policy.read() {
                Ok(lock) => lock.generation(),
                Err(_) => 0,
            })
    }

    fn note_flow_expired(&self, expired: Vec<ExpiredFlow>) {
        if let Some(allowlist) = &self.dns_allowlist {
            for flow in &expired {
                allowlist.flow_close(flow.key.dst_ip, flow.last_seen);
            }
        }
        for flow in &expired {
            let source_group = flow.source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP);
            self.observe_flow_close(
                source_group,
                "idle_timeout",
                flow.first_seen,
                flow.last_seen,
            );
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

    fn observe_entry_flow_close(&self, entry: &FlowEntry, reason: &str, now: u64) {
        self.observe_flow_close(entry.source_group(), reason, entry.first_seen, now);
    }

    fn note_flow_close(&self, flow: &FlowKey, entry: &FlowEntry, reason: &str, now: u64) {
        if let Some(allowlist) = &self.dns_allowlist {
            allowlist.flow_close(flow.dst_ip, now);
        }
        self.observe_entry_flow_close(entry, reason, now);
        if let Some(metrics) = &self.metrics {
            if let Some(shard_id) = self.shard_id {
                metrics.add_dp_active_flows_shard(shard_id, -1);
            } else {
                metrics.add_dp_active_flows(-1);
            }
        }
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
        }
    }

    fn update_nat_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            let count = self.nat.len();
            if let Some(shard_id) = self.shard_id {
                metrics.set_dp_active_nat_entries_shard(shard_id, count);
            } else {
                metrics.set_dp_active_nat_entries(count);
            }
            let total = NatTable::port_range_len() as f64;
            let ratio = if total > 0.0 {
                count as f64 / total
            } else {
                0.0
            };
            metrics.set_dp_nat_port_utilization_ratio(ratio);
        }
    }
}

include!("engine/packet_path.rs");
