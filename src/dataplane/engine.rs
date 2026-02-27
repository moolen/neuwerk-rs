use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::controlplane::metrics::Metrics;
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::drain::DrainControl;
use crate::dataplane::flow::{ExpiredFlow, FlowEntry, FlowKey, FlowTable};
use crate::dataplane::nat::{NatTable, ReverseKey};
use crate::dataplane::overlay::{OverlayConfig, SnatMode};
use crate::dataplane::packet::Packet;
use crate::dataplane::policy::{DynamicIpSetV4, PacketMeta, PolicyDecision, PolicySnapshot};
use crate::dataplane::tls::{TlsDirection, TlsFlowDecision, TlsFlowState, TlsVerifier};
use crate::dataplane::wiretap::{flow_id_from_key, WiretapEmitter, WiretapEvent, WiretapEventType};

static NAT_MISS_LOGS: AtomicUsize = AtomicUsize::new(0);

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
    dns_allowlist: Option<DynamicIpSetV4>,
    wiretap: Option<WiretapEmitter>,
    now_override_secs: Option<u64>,
    metrics: Option<Metrics>,
    drain_control: Option<DrainControl>,
    shard_id: Option<usize>,
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
            dns_allowlist: None,
            wiretap: None,
            now_override_secs: None,
            metrics: None,
            drain_control: None,
            shard_id: None,
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

    pub fn clone_for_shard(&self) -> Self {
        let mut state = Self::new_with_idle_timeout(
            self.policy.clone(),
            self.internal_net,
            self.internal_prefix,
            self.public_ip,
            self.data_port,
            self.flows.idle_timeout_secs(),
        );
        state.set_dataplane_config(self.dataplane_config.clone());
        state.set_overlay_config(self.overlay.clone());
        state.set_snat_mode(self.snat_mode);
        state.set_time_override(self.now_override_secs);
        if let Some(allowlist) = &self.dns_allowlist {
            state.set_dns_allowlist(allowlist.clone());
        }
        if let Some(emitter) = &self.wiretap {
            state.set_wiretap_emitter(emitter.clone());
        }
        if let Some(metrics) = &self.metrics {
            state.set_metrics(metrics.clone());
        }
        if let Some(control) = &self.drain_control {
            state.set_drain_control(control.clone());
        }
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

    pub fn set_metrics(&mut self, metrics: Metrics) {
        self.metrics = Some(metrics);
        self.update_flow_metrics();
        self.update_nat_metrics();
    }

    pub fn metrics(&self) -> Option<&Metrics> {
        self.metrics.as_ref()
    }

    pub fn inc_dp_arp_handled(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.inc_dp_arp_handled();
        }
    }

    pub fn evict_expired_now(&mut self) {
        let now = self.now_secs();
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

    fn note_flow_open(&self, flow: FlowKey, now: u64) {
        if let Some(allowlist) = &self.dns_allowlist {
            allowlist.flow_open(flow.dst_ip, now);
        }
    }

    fn note_flow_expired(&self, expired: Vec<ExpiredFlow>) {
        if let Some(metrics) = &self.metrics {
            if !expired.is_empty() {
                metrics.inc_dp_flow_close("idle_timeout", expired.len() as u64);
            }
        }
        if let Some(allowlist) = &self.dns_allowlist {
            for flow in &expired {
                allowlist.flow_close(flow.key.dst_ip, flow.last_seen);
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

pub fn handle_packet(pkt: &mut Packet, state: &mut EngineState) -> Action {
    let now = state.now_secs();
    state.evict_expired(now);

    let snat_disabled = matches!(state.snat_mode, SnatMode::None);
    let src_ip = match pkt.src_ip() {
        Some(ip) => ip,
        None => return Action::Drop,
    };
    let dst_ip = match pkt.dst_ip() {
        Some(ip) => ip,
        None => return Action::Drop,
    };
    if pkt.is_ipv4_fragment().unwrap_or(false) {
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_ipv4_fragment_drop();
        }
        return Action::Drop;
    }
    let proto = match pkt.protocol() {
        Some(p) => p,
        None => return Action::Drop,
    };

    if proto == 1 {
        if snat_disabled {
            if state.is_internal(src_ip) && !state.is_internal(dst_ip) {
                return handle_outbound_icmp_no_snat(pkt, state, src_ip, dst_ip, now);
            }
            if !state.is_internal(src_ip) && state.is_internal(dst_ip) {
                return handle_inbound_icmp_no_snat(pkt, state, src_ip, dst_ip, now);
            }
            return Action::Drop;
        }
        if state.is_internal(src_ip) && !state.is_internal(dst_ip) {
            return handle_outbound_icmp(pkt, state, src_ip, dst_ip, now);
        }
        if dst_ip == resolve_snat_ip(state).unwrap_or(Ipv4Addr::UNSPECIFIED) {
            return handle_inbound_icmp(pkt, state, src_ip, now);
        }
        return Action::Drop;
    }

    let (src_port, dst_port) = match pkt.ports() {
        Some(ports) => ports,
        None => return Action::Drop,
    };

    if snat_disabled && state.overlay.mode != crate::dataplane::overlay::EncapMode::None {
        let reverse = FlowKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            proto,
        };
        if state.flows.get_entry(&reverse).is_some() {
            return handle_inbound_no_snat(
                pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
            );
        }
        return handle_outbound_no_snat(pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now);
    }

    if state.is_internal(src_ip) && !state.is_internal(dst_ip) {
        let flow = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        };
        let meta = PacketMeta {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
            icmp_type: None,
            icmp_code: None,
        };

        let mut is_new = false;
        let mut source_group = "default".to_string();
        let mut current_generation = match state.policy.read() {
            Ok(lock) => lock.generation(),
            Err(_) => 0,
        };
        if state.flows.get_entry(&flow).is_none() {
            if state.is_draining() {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(proto),
                        "deny",
                        "default",
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }
            let ((decision, group), generation) = match state.policy.read() {
                Ok(lock) => (
                    lock.evaluate_with_source_group(&meta, None, Some(&state.tls_verifier)),
                    lock.generation(),
                ),
                Err(_) => ((PolicyDecision::Deny, None), 0),
            };
            current_generation = generation;
            source_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    is_new = true;
                    let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                    entry.policy_generation = current_generation;
                    state.flows.insert(flow, entry);
                }
                PolicyDecision::Deny => {
                    if let Some(metrics) = &state.metrics {
                        metrics.observe_dp_packet(
                            "outbound",
                            proto_label(proto),
                            "deny",
                            &source_group,
                            pkt.len(),
                        );
                    }
                    return Action::Drop;
                }
                PolicyDecision::PendingTls => {
                    is_new = true;
                    let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                    entry.policy_generation = current_generation;
                    entry.tls = Some(TlsFlowState::new());
                    state.flows.insert(flow, entry);
                    if let Some(metrics) = &state.metrics {
                        metrics.inc_dp_tls_decision("pending");
                    }
                }
            }
        }

        if is_new {
            state.note_flow_open(flow, now);
            if let Some(metrics) = &state.metrics {
                metrics.inc_dp_flow_open(proto_label(proto), &source_group);
            }
            state.update_flow_metrics();
        }

        let policy = &state.policy;
        let verifier = &state.tls_verifier;
        let wiretap = state.wiretap.clone();
        let metrics = state.metrics.clone();
        let mut policy_drop_group: Option<String> = None;
        let (decision_label, entry_source_group) = {
            let entry = match state.flows.get_entry_mut(&flow) {
                Some(entry) => entry,
                None => return Action::Drop,
            };
            if entry.policy_generation != current_generation {
                let (decision, group) = match state.policy.read() {
                    Ok(lock) => lock.evaluate_with_source_group(
                        &meta,
                        entry.tls.as_ref().map(|tls| &tls.observation),
                        Some(&state.tls_verifier),
                    ),
                    Err(_) => (PolicyDecision::Deny, None),
                };
                let next_group = group.unwrap_or_else(|| "default".to_string());
                match decision {
                    PolicyDecision::Allow => {
                        entry.policy_generation = current_generation;
                        entry.source_group = next_group;
                    }
                    PolicyDecision::PendingTls => {
                        entry.policy_generation = current_generation;
                        entry.source_group = next_group;
                        if let Some(tls_state) = &mut entry.tls {
                            tls_state.decision = TlsFlowDecision::Pending;
                        } else {
                            entry.tls = Some(TlsFlowState::new());
                        }
                    }
                    PolicyDecision::Deny => {
                        policy_drop_group = Some(next_group);
                    }
                }
            }
            if policy_drop_group.is_none() {
                entry.last_seen = now;
                entry.packets_out = entry.packets_out.saturating_add(1);
                maybe_emit_wiretap(&wiretap, &flow, entry, now);
                if let Some(tls_state) = &mut entry.tls {
                    if !process_tls_packet(
                        pkt,
                        TlsDirection::ClientToServer,
                        tls_state,
                        &meta,
                        policy,
                        verifier,
                        metrics.as_ref(),
                    ) {
                        if let Some(metrics) = &metrics {
                            metrics.observe_dp_packet(
                                "outbound",
                                proto_label(proto),
                                "deny",
                                entry.source_group.as_str(),
                                pkt.len(),
                            );
                        }
                        return Action::Drop;
                    }
                }
                (flow_decision_label(entry), entry.source_group.clone())
            } else {
                ("deny", entry.source_group.clone())
            }
        };

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now);
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    "deny",
                    &drop_group,
                    pkt.len(),
                );
            }
            return Action::Drop;
        }

        if let Some(action) = handle_ttl(pkt, state) {
            return action;
        }

        if snat_disabled {
            if !pkt.recalc_checksums() {
                return Action::Drop;
            }
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    decision_label,
                    entry_source_group.as_str(),
                    pkt.len(),
                );
            }
            return Action::Forward {
                out_port: state.data_port,
            };
        }

        let external_port = match state.nat.get_or_create(&flow, now) {
            Ok(port) => port,
            Err(_) => return Action::Drop,
        };

        let snat_ip = match resolve_snat_ip(state) {
            Some(ip) => ip,
            None => return Action::Drop,
        };
        if !pkt.set_src_ip(snat_ip) {
            return Action::Drop;
        }
        if !pkt.set_src_port(external_port) {
            return Action::Drop;
        }
        if !pkt.recalc_checksums() {
            return Action::Drop;
        }

        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                decision_label,
                entry_source_group.as_str(),
                pkt.len(),
            );
        }
        state.update_nat_metrics();
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    if snat_disabled {
        if !state.is_internal(src_ip) && state.is_internal(dst_ip) {
            return handle_inbound_no_snat(
                pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
            );
        }
    }

    if dst_ip == resolve_snat_ip(state).unwrap_or(Ipv4Addr::UNSPECIFIED) {
        let reverse_key = ReverseKey {
            external_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            proto,
        };
        if let Some(flow) = state.nat.reverse_lookup(&reverse_key) {
            state.nat.touch(&flow, now);
            let policy = &state.policy;
            let verifier = &state.tls_verifier;
            let wiretap = state.wiretap.clone();
            let metrics = state.metrics.clone();
            let current_generation = match state.policy.read() {
                Ok(lock) => lock.generation(),
                Err(_) => 0,
            };
            let meta = PacketMeta {
                src_ip: flow.src_ip,
                dst_ip: flow.dst_ip,
                proto: flow.proto,
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                icmp_type: None,
                icmp_code: None,
            };
            let mut policy_drop_group: Option<String> = None;
            let (decision_label, entry_source_group) = {
                let entry = match state.flows.get_entry_mut(&flow) {
                    Some(entry) => entry,
                    None => return Action::Drop,
                };
                if entry.policy_generation != current_generation {
                    let (decision, group) = match state.policy.read() {
                        Ok(lock) => lock.evaluate_with_source_group(
                            &meta,
                            entry.tls.as_ref().map(|tls| &tls.observation),
                            Some(&state.tls_verifier),
                        ),
                        Err(_) => (PolicyDecision::Deny, None),
                    };
                    let next_group = group.unwrap_or_else(|| "default".to_string());
                    match decision {
                        PolicyDecision::Allow => {
                            entry.policy_generation = current_generation;
                            entry.source_group = next_group;
                        }
                        PolicyDecision::PendingTls => {
                            entry.policy_generation = current_generation;
                            entry.source_group = next_group;
                            if let Some(tls_state) = &mut entry.tls {
                                tls_state.decision = TlsFlowDecision::Pending;
                            } else {
                                entry.tls = Some(TlsFlowState::new());
                            }
                        }
                        PolicyDecision::Deny => {
                            policy_drop_group = Some(next_group);
                        }
                    }
                }
                if policy_drop_group.is_none() {
                    entry.last_seen = now;
                    entry.packets_in = entry.packets_in.saturating_add(1);
                    maybe_emit_wiretap(&wiretap, &flow, entry, now);
                    if let Some(tls_state) = &mut entry.tls {
                        if !process_tls_packet(
                            pkt,
                            TlsDirection::ServerToClient,
                            tls_state,
                            &meta,
                            policy,
                            verifier,
                            metrics.as_ref(),
                        ) {
                            if let Some(metrics) = &metrics {
                                metrics.observe_dp_packet(
                                    "inbound",
                                    proto_label(proto),
                                    "deny",
                                    entry.source_group.as_str(),
                                    pkt.len(),
                                );
                            }
                            return Action::Drop;
                        }
                    }
                    (flow_decision_label(entry), entry.source_group.clone())
                } else {
                    ("deny", entry.source_group.clone())
                }
            };

            if let Some(drop_group) = policy_drop_group {
                remove_flow_state(state, &flow, now);
                if let Some(metrics) = &metrics {
                    metrics.observe_dp_packet(
                        "inbound",
                        proto_label(proto),
                        "deny",
                        &drop_group,
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }

            if let Some(action) = handle_ttl(pkt, state) {
                return action;
            }

            if !pkt.set_dst_ip(flow.src_ip) {
                return Action::Drop;
            }
            if !pkt.set_dst_port(flow.src_port) {
                return Action::Drop;
            }
            if !pkt.recalc_checksums() {
                return Action::Drop;
            }
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "inbound",
                    proto_label(proto),
                    decision_label,
                    entry_source_group.as_str(),
                    pkt.len(),
                );
            }
            state.update_nat_metrics();
            return Action::Forward {
                out_port: state.data_port,
            };
        }
        if NAT_MISS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dp: nat miss src={} dst={} sport={} dport={} proto={} snat_ip={}",
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                proto,
                resolve_snat_ip(state).unwrap_or(Ipv4Addr::UNSPECIFIED)
            );
        }
        if let Some(metrics) = &state.metrics {
            metrics.observe_dp_packet("inbound", proto_label(proto), "deny", "default", pkt.len());
        }
        return Action::Drop;
    }

    Action::Drop
}

fn handle_outbound_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    now: u64,
) -> Action {
    let flow = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
    };
    let meta = PacketMeta {
        src_ip,
        dst_ip,
        proto,
        src_port,
        dst_port,
        icmp_type: None,
        icmp_code: None,
    };

    let mut is_new = false;
    let mut source_group = "default".to_string();
    let mut current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };
    if state.flows.get_entry(&flow).is_none() {
        if state.is_draining() {
            if let Some(metrics) = &state.metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    "deny",
                    "default",
                    pkt.len(),
                );
            }
            return Action::Drop;
        }
        let ((decision, group), generation) = match state.policy.read() {
            Ok(lock) => (
                lock.evaluate_with_source_group(&meta, None, Some(&state.tls_verifier)),
                lock.generation(),
            ),
            Err(_) => ((PolicyDecision::Deny, None), 0),
        };
        current_generation = generation;
        source_group = group.unwrap_or_else(|| "default".to_string());
        match decision {
            PolicyDecision::Allow => {
                is_new = true;
                let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                entry.policy_generation = current_generation;
                state.flows.insert(flow, entry);
            }
            PolicyDecision::Deny => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(proto),
                        "deny",
                        &source_group,
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }
            PolicyDecision::PendingTls => {
                is_new = true;
                let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                entry.policy_generation = current_generation;
                entry.tls = Some(TlsFlowState::new());
                state.flows.insert(flow, entry);
                if let Some(metrics) = &state.metrics {
                    metrics.inc_dp_tls_decision("pending");
                }
            }
        }
    }

    if is_new {
        state.note_flow_open(flow, now);
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_flow_open(proto_label(proto), &source_group);
        }
        state.update_flow_metrics();
    }

    let policy = &state.policy;
    let verifier = &state.tls_verifier;
    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::PendingTls => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                    if let Some(tls_state) = &mut entry.tls {
                        tls_state.decision = TlsFlowDecision::Pending;
                    } else {
                        entry.tls = Some(TlsFlowState::new());
                    }
                }
                PolicyDecision::Deny => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            if let Some(tls_state) = &mut entry.tls {
                if !process_tls_packet(
                    pkt,
                    TlsDirection::ClientToServer,
                    tls_state,
                    &meta,
                    policy,
                    verifier,
                    metrics.as_ref(),
                ) {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "outbound",
                            proto_label(proto),
                            "deny",
                            entry.source_group.as_str(),
                            pkt.len(),
                        );
                    }
                    return Action::Drop;
                }
            }
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                "deny",
                &drop_group,
                pkt.len(),
            );
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if !pkt.recalc_checksums() {
        return Action::Drop;
    }
    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(proto),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

fn handle_inbound_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    now: u64,
) -> Action {
    let flow = FlowKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: dst_port,
        dst_port: src_port,
        proto,
    };
    let policy = &state.policy;
    let verifier = &state.tls_verifier;
    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };
    let meta = PacketMeta {
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        proto: flow.proto,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        icmp_type: None,
        icmp_code: None,
    };
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => {
                if let Some(metrics) = &metrics {
                    metrics.observe_dp_packet(
                        "inbound",
                        proto_label(proto),
                        "deny",
                        "default",
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::PendingTls => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                    if let Some(tls_state) = &mut entry.tls {
                        tls_state.decision = TlsFlowDecision::Pending;
                    } else {
                        entry.tls = Some(TlsFlowState::new());
                    }
                }
                PolicyDecision::Deny => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_in = entry.packets_in.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            if let Some(tls_state) = &mut entry.tls {
                if !process_tls_packet(
                    pkt,
                    TlsDirection::ServerToClient,
                    tls_state,
                    &meta,
                    policy,
                    verifier,
                    metrics.as_ref(),
                ) {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "inbound",
                            proto_label(proto),
                            "deny",
                            entry.source_group.as_str(),
                            pkt.len(),
                        );
                    }
                    return Action::Drop;
                }
            }
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "inbound",
                proto_label(proto),
                "deny",
                &drop_group,
                pkt.len(),
            );
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if !pkt.recalc_checksums() {
        return Action::Drop;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "inbound",
            proto_label(proto),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

fn handle_outbound_icmp(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    now: u64,
) -> Action {
    let (icmp_type, icmp_code) = match pkt.icmp_type_code() {
        Some(values) => values,
        None => return Action::Drop,
    };
    if icmp_is_error_type(icmp_type) {
        let inner = match pkt.icmp_inner_tuple() {
            Some(inner) => inner,
            None => return Action::Drop,
        };
        let flow = FlowKey {
            src_ip: inner.dst_ip,
            dst_ip: inner.src_ip,
            src_port: inner.dst_port,
            dst_port: inner.src_port,
            proto: inner.proto,
        };
        let external_port = match state.nat.get_entry(&flow) {
            Some(entry) => entry.external_port,
            None => return Action::Drop,
        };
        state.nat.touch(&flow, now);

        let meta = PacketMeta {
            src_ip,
            dst_ip,
            proto: 1,
            src_port: 0,
            dst_port: 0,
            icmp_type: Some(icmp_type),
            icmp_code: Some(icmp_code),
        };
        let (decision, group) = match state.policy.read() {
            Ok(lock) => lock.evaluate_with_source_group(&meta, None, Some(&state.tls_verifier)),
            Err(_) => (PolicyDecision::Deny, None),
        };
        let source_group = group.unwrap_or_else(|| "default".to_string());
        match decision {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        &source_group,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        &source_group,
                    );
                }
                return Action::Drop;
            }
        }

        if let Some(action) = handle_ttl(pkt, state) {
            return action;
        }

        let snat_ip = match resolve_snat_ip(state) {
            Some(ip) => ip,
            None => return Action::Drop,
        };
        if !pkt.set_src_ip(snat_ip) {
            return Action::Drop;
        }
        if !pkt.set_icmp_inner_dst_ip(&inner, snat_ip) {
            return Action::Drop;
        }
        match inner.proto {
            6 | 17 => {
                if !pkt.set_icmp_inner_dst_port(&inner, external_port) {
                    return Action::Drop;
                }
            }
            1 => {
                if !pkt.set_icmp_inner_src_port(&inner, external_port) {
                    return Action::Drop;
                }
            }
            _ => return Action::Drop,
        }
        if !pkt.recalc_checksums() {
            return Action::Drop;
        }

        if let Some(metrics) = &state.metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(1),
                "allow",
                &source_group,
                pkt.len(),
            );
            metrics.observe_dp_icmp_decision(
                "outbound",
                icmp_type,
                icmp_code,
                "allow",
                &source_group,
            );
        }
        return Action::Forward {
            out_port: state.data_port,
        };
    }
    let identifier = match pkt.icmp_identifier() {
        Some(value) => value,
        None => return Action::Drop,
    };

    let flow = FlowKey {
        src_ip,
        dst_ip,
        src_port: identifier,
        dst_port: 0,
        proto: 1,
    };
    let meta = PacketMeta {
        src_ip,
        dst_ip,
        proto: 1,
        src_port: identifier,
        dst_port: 0,
        icmp_type: Some(icmp_type),
        icmp_code: Some(icmp_code),
    };

    let mut is_new = false;
    let mut source_group = "default".to_string();
    let mut current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };
    if state.flows.get_entry(&flow).is_none() {
        if state.is_draining() {
            if let Some(metrics) = &state.metrics {
                metrics.observe_dp_packet("outbound", proto_label(1), "deny", "default", pkt.len());
                metrics
                    .observe_dp_icmp_decision("outbound", icmp_type, icmp_code, "deny", "default");
            }
            return Action::Drop;
        }
        let ((decision, group), generation) = match state.policy.read() {
            Ok(lock) => (
                lock.evaluate_with_source_group(&meta, None, Some(&state.tls_verifier)),
                lock.generation(),
            ),
            Err(_) => ((PolicyDecision::Deny, None), 0),
        };
        current_generation = generation;
        source_group = group.unwrap_or_else(|| "default".to_string());
        match decision {
            PolicyDecision::Allow => {
                is_new = true;
                let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                entry.policy_generation = current_generation;
                state.flows.insert(flow, entry);
            }
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        &source_group,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        &source_group,
                    );
                }
                return Action::Drop;
            }
        }
    }

    if is_new {
        state.note_flow_open(flow, now);
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_flow_open(proto_label(1), &source_group);
        }
        state.update_flow_metrics();
    }

    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("outbound", proto_label(1), "deny", &drop_group, pkt.len());
            metrics.observe_dp_icmp_decision("outbound", icmp_type, icmp_code, "deny", &drop_group);
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    let external_port = match state.nat.get_or_create(&flow, now) {
        Ok(port) => port,
        Err(_) => return Action::Drop,
    };
    let snat_ip = match resolve_snat_ip(state) {
        Some(ip) => ip,
        None => return Action::Drop,
    };
    if !pkt.set_src_ip(snat_ip) {
        return Action::Drop;
    }
    if !pkt.set_icmp_identifier(external_port) {
        return Action::Drop;
    }
    if !pkt.recalc_checksums() {
        return Action::Drop;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(1),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "outbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group.as_str(),
        );
    }
    state.update_nat_metrics();
    Action::Forward {
        out_port: state.data_port,
    }
}

fn handle_outbound_icmp_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    now: u64,
) -> Action {
    let (icmp_type, icmp_code) = match pkt.icmp_type_code() {
        Some(values) => values,
        None => return Action::Drop,
    };
    let identifier = pkt.icmp_identifier().unwrap_or(0);
    let flow = FlowKey {
        src_ip,
        dst_ip,
        src_port: identifier,
        dst_port: 0,
        proto: 1,
    };
    let meta = PacketMeta {
        src_ip,
        dst_ip,
        proto: 1,
        src_port: identifier,
        dst_port: 0,
        icmp_type: Some(icmp_type),
        icmp_code: Some(icmp_code),
    };

    let mut is_new = false;
    let mut source_group = "default".to_string();
    let mut current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };
    if state.flows.get_entry(&flow).is_none() {
        if state.is_draining() {
            if let Some(metrics) = &state.metrics {
                metrics.observe_dp_packet("outbound", proto_label(1), "deny", "default", pkt.len());
                metrics
                    .observe_dp_icmp_decision("outbound", icmp_type, icmp_code, "deny", "default");
            }
            return Action::Drop;
        }
        let ((decision, group), generation) = match state.policy.read() {
            Ok(lock) => (
                lock.evaluate_with_source_group(&meta, None, Some(&state.tls_verifier)),
                lock.generation(),
            ),
            Err(_) => ((PolicyDecision::Deny, None), 0),
        };
        current_generation = generation;
        source_group = group.unwrap_or_else(|| "default".to_string());
        match decision {
            PolicyDecision::Allow => {
                is_new = true;
                let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                entry.policy_generation = current_generation;
                state.flows.insert(flow, entry);
            }
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        &source_group,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        &source_group,
                    );
                }
                return Action::Drop;
            }
        }
    }

    if is_new {
        state.note_flow_open(flow, now);
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_flow_open(proto_label(1), &source_group);
        }
        state.update_flow_metrics();
    }

    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("outbound", proto_label(1), "deny", &drop_group, pkt.len());
            metrics.observe_dp_icmp_decision("outbound", icmp_type, icmp_code, "deny", &drop_group);
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if !pkt.recalc_checksums() {
        return Action::Drop;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(1),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "outbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group.as_str(),
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

fn handle_inbound_icmp_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    now: u64,
) -> Action {
    let (icmp_type, icmp_code) = match pkt.icmp_type_code() {
        Some(values) => values,
        None => return Action::Drop,
    };
    let metrics = state.metrics.clone();
    let current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };

    if icmp_is_error_type(icmp_type) {
        let inner = match pkt.icmp_inner_tuple() {
            Some(inner) => inner,
            None => return Action::Drop,
        };
        let flow = FlowKey {
            src_ip: inner.src_ip,
            dst_ip: inner.dst_ip,
            src_port: inner.src_port,
            dst_port: inner.dst_port,
            proto: inner.proto,
        };
        let wiretap = state.wiretap.clone();
        let mut policy_drop_group: Option<String> = None;
        let (decision_label, entry_source_group) = {
            let entry = match state.flows.get_entry_mut(&flow) {
                Some(entry) => entry,
                None => {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "inbound",
                            proto_label(1),
                            "deny",
                            "default",
                            pkt.len(),
                        );
                        metrics.observe_dp_icmp_decision(
                            "inbound", icmp_type, icmp_code, "deny", "default",
                        );
                    }
                    return Action::Drop;
                }
            };
            if entry.policy_generation != current_generation {
                let (decision, group) = match state.policy.read() {
                    Ok(lock) => lock.evaluate_with_source_group(
                        &PacketMeta {
                            src_ip: flow.src_ip,
                            dst_ip: flow.dst_ip,
                            proto: flow.proto,
                            src_port: flow.src_port,
                            dst_port: flow.dst_port,
                            icmp_type: Some(icmp_type),
                            icmp_code: Some(icmp_code),
                        },
                        None,
                        Some(&state.tls_verifier),
                    ),
                    Err(_) => (PolicyDecision::Deny, None),
                };
                let next_group = group.unwrap_or_else(|| "default".to_string());
                match decision {
                    PolicyDecision::Allow => {
                        entry.policy_generation = current_generation;
                        entry.source_group = next_group;
                    }
                    PolicyDecision::Deny | PolicyDecision::PendingTls => {
                        policy_drop_group = Some(next_group);
                    }
                }
            }
            if policy_drop_group.is_none() {
                entry.last_seen = now;
                entry.packets_in = entry.packets_in.saturating_add(1);
                maybe_emit_wiretap(&wiretap, &flow, entry, now);
                (flow_decision_label(entry), entry.source_group.clone())
            } else {
                ("deny", entry.source_group.clone())
            }
        };

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now);
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "inbound",
                    proto_label(1),
                    "deny",
                    &drop_group,
                    pkt.len(),
                );
                metrics.observe_dp_icmp_decision(
                    "inbound",
                    icmp_type,
                    icmp_code,
                    "deny",
                    &drop_group,
                );
            }
            return Action::Drop;
        }

        if let Some(action) = handle_ttl(pkt, state) {
            return action;
        }

        if !pkt.recalc_checksums() {
            return Action::Drop;
        }

        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "inbound",
                proto_label(1),
                decision_label,
                entry_source_group.as_str(),
                pkt.len(),
            );
            metrics.observe_dp_icmp_decision(
                "inbound",
                icmp_type,
                icmp_code,
                decision_label,
                entry_source_group.as_str(),
            );
        }
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    let identifier = match pkt.icmp_identifier() {
        Some(value) => value,
        None => return Action::Drop,
    };
    let flow = FlowKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: identifier,
        dst_port: 0,
        proto: 1,
    };
    let wiretap = state.wiretap.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => {
                if let Some(metrics) = &metrics {
                    metrics.observe_dp_packet(
                        "inbound",
                        proto_label(1),
                        "deny",
                        "default",
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "inbound", icmp_type, icmp_code, "deny", "default",
                    );
                }
                return Action::Drop;
            }
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &PacketMeta {
                        src_ip: flow.src_ip,
                        dst_ip: flow.dst_ip,
                        proto: flow.proto,
                        src_port: flow.src_port,
                        dst_port: flow.dst_port,
                        icmp_type: Some(icmp_type),
                        icmp_code: Some(icmp_code),
                    },
                    None,
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_in = entry.packets_in.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("inbound", proto_label(1), "deny", &drop_group, pkt.len());
            metrics.observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", &drop_group);
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if !pkt.recalc_checksums() {
        return Action::Drop;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "inbound",
            proto_label(1),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "inbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group.as_str(),
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

fn handle_inbound_icmp(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    now: u64,
) -> Action {
    let (icmp_type, icmp_code) = match pkt.icmp_type_code() {
        Some(values) => values,
        None => return Action::Drop,
    };
    let metrics = state.metrics.clone();
    let current_generation = match state.policy.read() {
        Ok(lock) => lock.generation(),
        Err(_) => 0,
    };

    if icmp_is_error_type(icmp_type) {
        let inner = match pkt.icmp_inner_tuple() {
            Some(inner) => inner,
            None => return Action::Drop,
        };
        let reverse_key = ReverseKey {
            external_port: inner.src_port,
            remote_ip: inner.dst_ip,
            remote_port: inner.dst_port,
            proto: inner.proto,
        };
        let Some(flow) = state.nat.reverse_lookup(&reverse_key) else {
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet("inbound", proto_label(1), "deny", "default", pkt.len());
                metrics
                    .observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", "default");
            }
            return Action::Drop;
        };

        state.nat.touch(&flow, now);
        let wiretap = state.wiretap.clone();
        let mut policy_drop_group: Option<String> = None;
        let (decision_label, entry_source_group) = {
            let entry = match state.flows.get_entry_mut(&flow) {
                Some(entry) => entry,
                None => return Action::Drop,
            };
            if entry.policy_generation != current_generation {
                let (decision, group) = match state.policy.read() {
                    Ok(lock) => lock.evaluate_with_source_group(
                        &PacketMeta {
                            src_ip: flow.src_ip,
                            dst_ip: flow.dst_ip,
                            proto: flow.proto,
                            src_port: flow.src_port,
                            dst_port: flow.dst_port,
                            icmp_type: Some(icmp_type),
                            icmp_code: Some(icmp_code),
                        },
                        None,
                        Some(&state.tls_verifier),
                    ),
                    Err(_) => (PolicyDecision::Deny, None),
                };
                let next_group = group.unwrap_or_else(|| "default".to_string());
                match decision {
                    PolicyDecision::Allow => {
                        entry.policy_generation = current_generation;
                        entry.source_group = next_group;
                    }
                    PolicyDecision::Deny | PolicyDecision::PendingTls => {
                        policy_drop_group = Some(next_group);
                    }
                }
            }
            if policy_drop_group.is_none() {
                entry.last_seen = now;
                entry.packets_in = entry.packets_in.saturating_add(1);
                maybe_emit_wiretap(&wiretap, &flow, entry, now);
                (flow_decision_label(entry), entry.source_group.clone())
            } else {
                ("deny", entry.source_group.clone())
            }
        };

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now);
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "inbound",
                    proto_label(1),
                    "deny",
                    &drop_group,
                    pkt.len(),
                );
                metrics.observe_dp_icmp_decision(
                    "inbound",
                    icmp_type,
                    icmp_code,
                    "deny",
                    &drop_group,
                );
            }
            return Action::Drop;
        }

        if let Some(action) = handle_ttl(pkt, state) {
            return action;
        }

        if !pkt.set_dst_ip(flow.src_ip) {
            return Action::Drop;
        }
        if !pkt.set_icmp_inner_src_ip(&inner, flow.src_ip) {
            return Action::Drop;
        }
        if !pkt.set_icmp_inner_src_port(&inner, flow.src_port) {
            return Action::Drop;
        }
        if !pkt.recalc_checksums() {
            return Action::Drop;
        }
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "inbound",
                proto_label(1),
                decision_label,
                entry_source_group.as_str(),
                pkt.len(),
            );
            metrics.observe_dp_icmp_decision(
                "inbound",
                icmp_type,
                icmp_code,
                decision_label,
                entry_source_group.as_str(),
            );
        }
        state.update_nat_metrics();
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    let identifier = match pkt.icmp_identifier() {
        Some(value) => value,
        None => return Action::Drop,
    };
    let reverse_key = ReverseKey {
        external_port: identifier,
        remote_ip: src_ip,
        remote_port: 0,
        proto: 1,
    };
    let Some(flow) = state.nat.reverse_lookup(&reverse_key) else {
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("inbound", proto_label(1), "deny", "default", pkt.len());
            metrics.observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", "default");
        }
        return Action::Drop;
    };

    state.nat.touch(&flow, now);
    let wiretap = state.wiretap.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let (decision, group) = match state.policy.read() {
                Ok(lock) => lock.evaluate_with_source_group(
                    &PacketMeta {
                        src_ip: flow.src_ip,
                        dst_ip: flow.dst_ip,
                        proto: flow.proto,
                        src_port: flow.src_port,
                        dst_port: flow.dst_port,
                        icmp_type: Some(icmp_type),
                        icmp_code: Some(icmp_code),
                    },
                    None,
                    Some(&state.tls_verifier),
                ),
                Err(_) => (PolicyDecision::Deny, None),
            };
            let next_group = group.unwrap_or_else(|| "default".to_string());
            match decision {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.source_group = next_group;
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop_group = Some(next_group);
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_in = entry.packets_in.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            (flow_decision_label(entry), entry.source_group.clone())
        } else {
            ("deny", entry.source_group.clone())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now);
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("inbound", proto_label(1), "deny", &drop_group, pkt.len());
            metrics.observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", &drop_group);
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if !pkt.set_dst_ip(flow.src_ip) {
        return Action::Drop;
    }
    if !pkt.set_icmp_identifier(flow.src_port) {
        return Action::Drop;
    }
    if !pkt.recalc_checksums() {
        return Action::Drop;
    }
    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "inbound",
            proto_label(1),
            decision_label,
            entry_source_group.as_str(),
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "inbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group.as_str(),
        );
    }
    state.update_nat_metrics();
    Action::Forward {
        out_port: state.data_port,
    }
}

fn icmp_is_error_type(icmp_type: u8) -> bool {
    matches!(icmp_type, 3 | 4 | 5 | 11 | 12)
}

fn resolve_snat_ip(state: &EngineState) -> Option<Ipv4Addr> {
    match state.snat_mode {
        SnatMode::None => None,
        SnatMode::Static(ip) => Some(ip),
        SnatMode::Auto => {
            if let Some(cfg) = state.dataplane_config.get() {
                if cfg.ip != Ipv4Addr::UNSPECIFIED {
                    return Some(cfg.ip);
                }
            }
            if state.public_ip != Ipv4Addr::UNSPECIFIED {
                return Some(state.public_ip);
            }
            None
        }
    }
}

fn maybe_emit_wiretap(
    wiretap: &Option<WiretapEmitter>,
    flow: &FlowKey,
    entry: &mut FlowEntry,
    now: u64,
) {
    let Some(emitter) = wiretap.as_ref() else {
        return;
    };
    let interval = emitter.report_interval_secs();
    if now.saturating_sub(entry.last_reported) < interval {
        return;
    }
    entry.last_reported = now;
    emitter.try_send(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: flow_id_from_key(flow),
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        proto: flow.proto,
        packets_in: entry.packets_in,
        packets_out: entry.packets_out,
        last_seen: entry.last_seen,
    });
}

fn process_tls_packet(
    pkt: &Packet,
    direction: TlsDirection,
    tls_state: &mut TlsFlowState,
    meta: &PacketMeta,
    policy: &Arc<RwLock<PolicySnapshot>>,
    verifier: &TlsVerifier,
    metrics: Option<&Metrics>,
) -> bool {
    if tls_state.decision == TlsFlowDecision::Denied {
        return false;
    }
    if tls_state.decision == TlsFlowDecision::Allowed {
        return true;
    }

    let payload = match pkt.tcp_payload() {
        Some(value) => value,
        None => return false,
    };
    let seq = match pkt.tcp_seq() {
        Some(value) => value,
        None => return false,
    };
    let flags = match pkt.tcp_flags() {
        Some(value) => value,
        None => return false,
    };
    let syn = flags & 0x02 != 0;

    let ingest = match tls_state.ingest(direction, seq, syn, payload) {
        Ok(result) => result,
        Err(_) => {
            tls_state.decision = TlsFlowDecision::Denied;
            if let Some(metrics) = metrics {
                metrics.inc_dp_tls_decision("deny");
            }
            return false;
        }
    };

    if tls_state.decision == TlsFlowDecision::Pending {
        let decision = match policy.read() {
            Ok(lock) => lock.evaluate(meta, Some(&tls_state.observation), Some(verifier)),
            Err(_) => PolicyDecision::Deny,
        };
        match decision {
            PolicyDecision::Allow => {
                tls_state.decision = TlsFlowDecision::Allowed;
                if let Some(metrics) = metrics {
                    metrics.inc_dp_tls_decision("allow");
                }
            }
            PolicyDecision::Deny => {
                tls_state.decision = TlsFlowDecision::Denied;
                if let Some(metrics) = metrics {
                    metrics.inc_dp_tls_decision("deny");
                }
            }
            PolicyDecision::PendingTls => {}
        }
    }

    if tls_state.decision == TlsFlowDecision::Pending && ingest.saw_application_data {
        tls_state.decision = TlsFlowDecision::Denied;
        if let Some(metrics) = metrics {
            metrics.inc_dp_tls_decision("deny_after_data");
        }
    }

    tls_state.decision != TlsFlowDecision::Denied
}

fn proto_label(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    }
}

fn flow_decision_label(entry: &FlowEntry) -> &'static str {
    match entry.tls.as_ref().map(|tls| tls.decision) {
        Some(TlsFlowDecision::Pending) => "pending_tls",
        Some(TlsFlowDecision::Allowed) => "allow",
        Some(TlsFlowDecision::Denied) => "deny",
        None => "allow",
    }
}

fn remove_flow_state(state: &mut EngineState, flow: &FlowKey, now: u64) -> Option<FlowEntry> {
    let entry = state.flows.remove(flow);
    if entry.is_some() {
        if let Some(allowlist) = &state.dns_allowlist {
            allowlist.flow_close(flow.dst_ip, now);
        }
    }
    state.nat.remove(flow);
    state.update_flow_metrics();
    state.update_nat_metrics();
    entry
}

fn handle_ttl(pkt: &mut Packet, state: &EngineState) -> Option<Action> {
    let ttl = pkt.ipv4_ttl()?;
    if ttl <= 1 {
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_ipv4_ttl_exceeded();
        }
        let src_ip = state
            .dataplane_config
            .get()
            .map(|cfg| cfg.ip)
            .filter(|ip| *ip != Ipv4Addr::UNSPECIFIED)
            .unwrap_or(state.public_ip);
        if src_ip == Ipv4Addr::UNSPECIFIED {
            return Some(Action::Drop);
        }
        if !pkt.rewrite_as_icmp_time_exceeded(src_ip) {
            return Some(Action::Drop);
        }
        return Some(Action::Forward {
            out_port: state.data_port,
        });
    }
    if !pkt.set_ipv4_ttl(ttl - 1) {
        return Some(Action::Drop);
    }
    None
}
