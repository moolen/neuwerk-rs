use std::time::Instant;

use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_outbound_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    now: u64,
) -> Action {
    let tcp_flags = if proto == 6 { pkt.tcp_flags() } else { None };
    let outbound_syn = tcp_flags.is_some_and(is_tcp_syn);
    let outbound_ack_only = tcp_flags.is_some_and(is_tcp_ack_only);
    if outbound_syn {
        state.note_tcp_handshake_event_for_target("syn_in", dst_ip);
    }
    let flow = FlowKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
    };
    let flow_probe_start = Instant::now();
    state.flows.prefetch_key(&flow);
    let flow_probe = state.flows.probe(&flow);
    state.note_tcp_handshake_stage("outbound", "flow_probe", flow_probe_start.elapsed());
    state.note_table_probe(
        "flow",
        "lookup",
        flow_probe.result_label(),
        flow_probe.steps(),
    );
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
    let mut pending_entry: Option<FlowEntry> = None;
    let mut syn_only_decision: Option<(&'static str, Option<Arc<str>>, bool)> = None;
    let mut source_group: Option<Arc<str>> = None;
    let current_generation;
    let audit = state.audit.clone();
    if !flow_probe.is_hit() {
        let policy_eval_start = Instant::now();
        let exact_source_policy_index = &state.exact_source_policy_index;
        let policy = state.policy_snapshot();
        let evaluation = evaluate_policy_outcome(
            exact_source_policy_index,
            &policy,
            &meta,
            None,
            &state.tls_verifier,
            state.audit.is_some(),
        );
        state.note_tcp_handshake_stage("outbound", "policy_eval_miss", policy_eval_start.elapsed());
        let generation = policy.generation();
        current_generation = generation;
        source_group = evaluation.source_group.clone();
        let source_group_label = source_group_label(source_group.as_ref());
        if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
            maybe_emit_policy_deny_audit(audit.as_ref(), &meta, source_group_label, None, now);
        }
        match evaluation.effective {
            PolicyDecision::Allow => {
                if evaluation.intercept_requires_service
                    && !state.service_policy_ready_for_generation(current_generation)
                {
                    if outbound_syn {
                        state.note_tcp_handshake_drop("syn", "service_not_ready");
                    }
                    if let Some(action) =
                        maybe_intercept_fail_closed_rst(pkt, state, source_group_label, "outbound")
                    {
                        return action;
                    }
                    if let Some(metrics) = &state.metrics {
                        metrics.observe_dp_packet(
                            "outbound",
                            proto_label(proto),
                            "deny",
                            source_group_label,
                            pkt.len(),
                        );
                    }
                    return Action::Drop;
                }
                if proto == 6 && !outbound_syn {
                    // Late TCP ACK/FIN/RST packets can arrive after the original flow state was
                    // already removed. Do not recreate flow state for those misses.
                } else {
                    if let Some(rejection) =
                        state.admission_rejection(source_group.as_ref(), true, false, false)
                    {
                        state.note_admission_rejection(rejection);
                        if outbound_syn {
                            state.note_tcp_handshake_drop(
                                "syn",
                                EngineState::admission_rejection_reason(rejection),
                            );
                        } else if outbound_ack_only {
                            state.note_tcp_handshake_drop(
                                "ack",
                                EngineState::admission_rejection_reason(rejection),
                            );
                        }
                        if let Some(metrics) = &state.metrics {
                            metrics.observe_dp_packet(
                                "outbound",
                                proto_label(proto),
                                "deny",
                                source_group_label,
                                pkt.len(),
                            );
                        }
                        return Action::Drop;
                    }
                    is_new = true;
                    if outbound_syn && state.syn_only_enabled {
                        let upsert = state.syn_only.upsert(
                            flow,
                            now,
                            source_group.clone(),
                            current_generation,
                            evaluation.intercept_requires_service,
                        );
                        state.note_syn_only_lookup(match upsert {
                            crate::dataplane::flow::SynOnlyUpsertResult::Inserted => "miss",
                            crate::dataplane::flow::SynOnlyUpsertResult::Updated => "hit",
                        });
                        if matches!(
                            upsert,
                            crate::dataplane::flow::SynOnlyUpsertResult::Inserted
                        ) {
                            state.record_new_syn_only_state(source_group.as_ref());
                        }
                        state.update_syn_only_metrics();
                        syn_only_decision = Some((
                            "allow",
                            source_group.clone(),
                            evaluation.intercept_requires_service,
                        ));
                    } else {
                        let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                        entry.policy_generation = current_generation;
                        entry.intercept_requires_service = evaluation.intercept_requires_service;
                        pending_entry = Some(entry);
                    }
                }
            }
            PolicyDecision::Deny => {
                if outbound_syn && state.syn_only_enabled {
                    let _ = remove_flow_state(state, &flow, now, "policy_deny");
                }
                if outbound_syn {
                    state.note_tcp_handshake_drop("syn", "policy_deny");
                } else if outbound_ack_only {
                    state.note_tcp_handshake_drop("ack", "policy_deny");
                }
                if evaluation.intercept_requires_service {
                    if let Some(action) =
                        maybe_intercept_fail_closed_rst(pkt, state, source_group_label, "outbound")
                    {
                        return action;
                    }
                }
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(proto),
                        "deny",
                        source_group_label,
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }
            PolicyDecision::PendingTls => {
                if proto == 6 && !outbound_syn {
                    // Do not create placeholder TLS state for late TCP packets after close.
                } else {
                    if let Some(rejection) =
                        state.admission_rejection(source_group.as_ref(), true, true, false)
                    {
                        state.note_admission_rejection(rejection);
                        if outbound_syn {
                            state.note_tcp_handshake_drop(
                                "syn",
                                EngineState::admission_rejection_reason(rejection),
                            );
                        } else if outbound_ack_only {
                            state.note_tcp_handshake_drop(
                                "ack",
                                EngineState::admission_rejection_reason(rejection),
                            );
                        }
                        if let Some(metrics) = &state.metrics {
                            metrics.observe_dp_packet(
                                "outbound",
                                proto_label(proto),
                                "deny",
                                source_group_label,
                                pkt.len(),
                            );
                        }
                        return Action::Drop;
                    }
                    is_new = true;
                    if outbound_syn && state.syn_only_enabled {
                        let upsert = state.syn_only.upsert(
                            flow,
                            now,
                            source_group.clone(),
                            current_generation,
                            false,
                        );
                        state.note_syn_only_lookup(match upsert {
                            crate::dataplane::flow::SynOnlyUpsertResult::Inserted => "miss",
                            crate::dataplane::flow::SynOnlyUpsertResult::Updated => "hit",
                        });
                        if matches!(
                            upsert,
                            crate::dataplane::flow::SynOnlyUpsertResult::Inserted
                        ) {
                            state.record_new_syn_only_state(source_group.as_ref());
                        }
                        state.update_syn_only_metrics();
                        syn_only_decision = Some(("pending_tls", source_group.clone(), false));
                    } else {
                        let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                        entry.policy_generation = current_generation;
                        entry.intercept_requires_service = false;
                        entry.tls = Some(TlsFlowState::new());
                        pending_entry = Some(entry);
                    }
                }
                if let Some(metrics) = &state.metrics {
                    metrics.inc_dp_tls_decision("pending");
                }
            }
        }
    } else {
        current_generation = state.current_policy_generation();
    }

    if is_new && syn_only_decision.is_none() {
        state.record_new_flow_state(
            flow,
            proto,
            source_group.as_ref(),
            "outbound_new",
            now,
            pending_entry.as_ref().is_some_and(FlowEntry::pending_tls),
        );
    }

    let policy_snapshot = state.policy_snapshot.clone();
    let policy = &state.policy_snapshot;
    let verifier = &state.tls_verifier;
    let wiretap = state.wiretap.clone();
    let audit = state.audit.clone();
    let metrics = state.metrics.clone();
    let service_policy_applied_generation = state.service_policy_applied_generation.clone();
    let mut service_ready_for_current_generation = None;
    let mut policy_drop = false;
    let mut policy_drop_group: Option<Arc<str>> = None;
    let mut policy_drop_intercept_requires_service = false;
    let mut source_group_membership = None;
    let mut pending_tls_membership = None;
    let mut tls_packet_denied = false;
    let mut tls_packet_drop_group: Option<Arc<str>> = None;
    let need_entry_source_group = metrics.is_some();
    let worker_id = state.dpdk_worker_id();
    let detailed_dataplane_observability = state.detailed_dataplane_observability;
    let mut fast_allow_forward = false;
    let mut mark_handshake_completed = false;
    let mut note_syn_out_first = false;
    let mut note_syn_out_repeat = false;
    let pending_tls_cap = state.admission_control.max_pending_tls_flows;
    let current_pending_tls_flow_count = state.pending_tls_flow_count;
    let mut pending_tls_cap_rejection = None;
    let (decision_label, entry_source_group, flow_intercept_requires_service) =
        if let Some((decision_label, source_group, intercept_requires_service)) =
            syn_only_decision.take()
        {
            (
                decision_label,
                if need_entry_source_group {
                    source_group
                } else {
                    None
                },
                intercept_requires_service,
            )
        } else {
            let flow_state_start = Instant::now();
            let (entry, flow_state_stage) = match pending_entry.take() {
                Some(entry) => {
                    state.note_table_probe(
                        "flow",
                        "insert",
                        flow_probe.result_label(),
                        flow_probe.steps(),
                    );
                    let entry = state
                        .flows
                        .insert_with_probe_and_get_mut(flow, entry, flow_probe);
                    (entry, "flow_insert")
                }
                None => match state.flows.get_entry_mut_with_probe(&flow, flow_probe) {
                    Some(entry) => (entry, "flow_lookup_hit"),
                    None => {
                        if detailed_dataplane_observability {
                            if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                                metrics.observe_dp_handshake_stage(
                                    worker_id,
                                    "outbound",
                                    "flow_lookup_miss",
                                    flow_state_start.elapsed(),
                                );
                            }
                        }
                        if outbound_ack_only {
                            state.note_tcp_handshake_drop("ack", "flow_missing");
                        }
                        return Action::Drop;
                    }
                },
            };
            if detailed_dataplane_observability {
                if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                    metrics.observe_dp_handshake_stage(
                        worker_id,
                        "outbound",
                        flow_state_stage,
                        flow_state_start.elapsed(),
                    );
                }
            }
            let source_group_before = entry.source_group_arc();
            let pending_tls_before = entry.pending_tls();
            if entry.policy_generation != current_generation {
                let policy_eval_start = Instant::now();
                let exact_source_policy_index = &state.exact_source_policy_index;
                let policy = policy_snapshot.load();
                let evaluation = evaluate_policy_outcome(
                    exact_source_policy_index,
                    &policy,
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    &state.tls_verifier,
                    state.audit.is_some(),
                );
                if detailed_dataplane_observability {
                    if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                        metrics.observe_dp_handshake_stage(
                            worker_id,
                            "outbound",
                            "policy_eval_hit",
                            policy_eval_start.elapsed(),
                        );
                    }
                }
                let next_group = evaluation.source_group.clone();
                if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                    let sni = entry
                        .tls
                        .as_ref()
                        .and_then(|tls| tls.observation.sni.clone());
                    maybe_emit_policy_deny_audit(
                        audit.as_ref(),
                        &meta,
                        source_group_label(next_group.as_ref()),
                        sni,
                        now,
                    );
                }
                match evaluation.effective {
                    PolicyDecision::Allow => {
                        let service_ready = if evaluation.intercept_requires_service {
                            *service_ready_for_current_generation.get_or_insert_with(|| {
                                service_policy_applied_generation
                                    .as_ref()
                                    .map(|tracker| {
                                        tracker.load(Ordering::Acquire) >= current_generation
                                    })
                                    .unwrap_or(true)
                            })
                        } else {
                            true
                        };
                        if evaluation.intercept_requires_service && !service_ready {
                            policy_drop = true;
                            policy_drop_group = next_group;
                            policy_drop_intercept_requires_service = true;
                        } else {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_arc(next_group);
                            entry.intercept_requires_service =
                                evaluation.intercept_requires_service;
                        }
                    }
                    PolicyDecision::PendingTls => {
                        if !pending_tls_before {
                            if pending_tls_cap
                                .is_some_and(|max| current_pending_tls_flow_count >= max)
                            {
                                pending_tls_cap_rejection = Some(AdmissionRejection::PendingTlsCap);
                                policy_drop = true;
                                policy_drop_group = next_group;
                            } else {
                                entry.policy_generation = current_generation;
                                entry.set_source_group_arc(next_group);
                                entry.intercept_requires_service = false;
                                if let Some(tls_state) = &mut entry.tls {
                                    tls_state.decision = TlsFlowDecision::Pending;
                                } else {
                                    entry.tls = Some(TlsFlowState::new());
                                }
                            }
                        } else {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_arc(next_group);
                            entry.intercept_requires_service = false;
                            if let Some(tls_state) = &mut entry.tls {
                                tls_state.decision = TlsFlowDecision::Pending;
                            } else {
                                entry.tls = Some(TlsFlowState::new());
                            }
                        }
                    }
                    PolicyDecision::Deny => {
                        policy_drop = true;
                        policy_drop_group = next_group;
                        policy_drop_intercept_requires_service =
                            evaluation.intercept_requires_service;
                        entry.intercept_requires_service = false;
                    }
                }
            }
            if !policy_drop {
                entry.last_seen = now;
                entry.packets_out = entry.packets_out.saturating_add(1);
                if outbound_syn {
                    let syn_seen_before = entry.syn_outbound_seen();
                    entry.note_syn_outbound();
                    if syn_seen_before {
                        note_syn_out_repeat = true;
                    } else {
                        note_syn_out_first = true;
                    }
                }
                mark_handshake_completed = outbound_ack_only
                    && entry.syn_outbound_seen()
                    && entry.synack_inbound_seen()
                    && !entry.handshake_completed();
                fast_allow_forward = wiretap.is_none()
                    && metrics.is_none()
                    && entry.tls.is_none()
                    && !(state.intercept_to_host_steering && entry.intercept_requires_service);
                if fast_allow_forward {
                    ("allow", None, false)
                } else {
                    maybe_emit_wiretap(&wiretap, &flow, entry, now);
                    let tls_source_group = if entry.tls.is_some() {
                        entry.source_group_arc()
                    } else {
                        None
                    };
                    if let Some(tls_state) = &mut entry.tls {
                        let source_group_name = source_group_label(tls_source_group.as_ref());
                        if !process_tls_packet(
                            pkt,
                            TlsDirection::ClientToServer,
                            tls_state,
                            &meta,
                            policy,
                            verifier,
                            audit.as_ref(),
                            source_group_name,
                            now,
                            metrics.as_deref(),
                        ) {
                            if let Some(metrics) = &metrics {
                                metrics.observe_dp_packet(
                                    "outbound",
                                    proto_label(proto),
                                    "deny",
                                    source_group_name,
                                    pkt.len(),
                                );
                            }
                            tls_packet_denied = true;
                            tls_packet_drop_group = tls_source_group.clone();
                        }
                    }
                    source_group_membership = Some((source_group_before, entry.source_group_arc()));
                    pending_tls_membership = Some((pending_tls_before, entry.pending_tls()));
                    (
                        flow_decision_label(entry),
                        if need_entry_source_group {
                            entry.source_group_arc()
                        } else {
                            None
                        },
                        entry.intercept_requires_service,
                    )
                }
            } else {
                ("deny", None, false)
            }
        };
    if let Some((previous, next)) = source_group_membership {
        state.reconcile_source_group_membership(previous, next);
    }
    if let Some((was_pending, is_pending)) = pending_tls_membership {
        state.reconcile_pending_tls_membership(was_pending, is_pending);
    }
    if let Some(rejection) = pending_tls_cap_rejection {
        state.note_admission_rejection(rejection);
    }
    if tls_packet_denied {
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                "deny",
                source_group_label(tls_packet_drop_group.as_ref()),
                pkt.len(),
            );
        }
        return Action::Drop;
    }
    let entry_source_group_name = source_group_label(entry_source_group.as_ref());

    if policy_drop {
        let _ = remove_flow_state_timed(
            state,
            &flow,
            now,
            "policy_drop",
            "outbound",
            "flow_close_policy_drop",
        );
        if outbound_syn {
            state.note_tcp_handshake_drop("syn", "policy_deny");
        } else if mark_handshake_completed {
            state.note_tcp_handshake_drop("ack", "policy_deny");
        }
        if policy_drop_intercept_requires_service {
            if let Some(action) = maybe_intercept_fail_closed_rst(
                pkt,
                state,
                source_group_label(policy_drop_group.as_ref()),
                "outbound",
            ) {
                return action;
            }
        }
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                "deny",
                source_group_label(policy_drop_group.as_ref()),
                pkt.len(),
            );
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if fast_allow_forward {
        if outbound_syn {
            state.note_tcp_handshake_event_for_target("syn_out", flow.dst_ip);
            if note_syn_out_first {
                state.note_tcp_handshake_event_for_target("syn_out_first", flow.dst_ip);
            }
            if note_syn_out_repeat {
                state.note_tcp_handshake_event_for_target("syn_out_repeat", flow.dst_ip);
            }
        }
        if mark_handshake_completed {
            let mut final_ack_source_group: Option<String> = None;
            if let Some(entry) = state.flows.get_entry_mut(&flow) {
                if entry.syn_outbound_seen()
                    && entry.synack_inbound_seen()
                    && !entry.handshake_completed()
                {
                    final_ack_source_group = Some(entry.source_group().to_string());
                    entry.note_handshake_completed();
                }
            }
            if let Some(source_group) = final_ack_source_group.as_deref() {
                state.note_tcp_handshake_final_ack_in(source_group, flow.dst_ip);
                state.note_tcp_handshake_event_for_target("completed", flow.dst_ip);
            }
        }
        maybe_close_tcp_flow_timed(state, &flow, pkt, now, "outbound");
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    if state.intercept_to_host_steering && flow_intercept_requires_service {
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                decision_label,
                entry_source_group_name,
                pkt.len(),
            );
        }
        return Action::ToHost;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(proto),
            decision_label,
            entry_source_group_name,
            pkt.len(),
        );
    }
    if outbound_syn {
        state.note_tcp_handshake_event_for_target("syn_out", flow.dst_ip);
        if note_syn_out_first {
            state.note_tcp_handshake_event_for_target("syn_out_first", flow.dst_ip);
        }
        if note_syn_out_repeat {
            state.note_tcp_handshake_event_for_target("syn_out_repeat", flow.dst_ip);
        }
    }
    if mark_handshake_completed {
        let mut final_ack_source_group: Option<String> = None;
        if let Some(entry) = state.flows.get_entry_mut(&flow) {
            if entry.syn_outbound_seen()
                && entry.synack_inbound_seen()
                && !entry.handshake_completed()
            {
                final_ack_source_group = Some(entry.source_group().to_string());
                entry.note_handshake_completed();
            }
        }
        if let Some(source_group) = final_ack_source_group.as_deref() {
            state.note_tcp_handshake_final_ack_in(source_group, flow.dst_ip);
            state.note_tcp_handshake_event_for_target("completed", flow.dst_ip);
        }
    }
    maybe_close_tcp_flow(state, &flow, pkt, now);
    Action::Forward {
        out_port: state.data_port,
    }
}

pub(super) fn is_dns_target_outbound_flow(
    state: &EngineState,
    dst_ip: Ipv4Addr,
    proto: u8,
    dst_port: u16,
    src_internal: bool,
    dst_internal: bool,
) -> bool {
    if dst_port != 53 {
        return false;
    }
    if proto != 6 && proto != 17 {
        return false;
    }
    if !src_internal || dst_internal {
        return false;
    }
    state.dns_target_ips.contains(&dst_ip)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_outbound_dns_target(
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
    state.flows.prefetch_key(&flow);
    let source_group = Arc::<str>::from("dns-intercept");
    if state.flows.get_entry(&flow).is_none() {
        let snat_disabled = matches!(state.snat_mode, SnatMode::None);
        if let Some(rejection) =
            state.admission_rejection(Some(&source_group), true, false, !snat_disabled)
        {
            state.note_admission_rejection(rejection);
            if let Some(metrics) = &state.metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    "deny",
                    source_group.as_ref(),
                    pkt.len(),
                );
            }
            return Action::Drop;
        }
        let mut entry = FlowEntry::with_source_group(now, source_group.to_string());
        entry.policy_generation = state.current_policy_generation();
        state.flows.insert(flow, entry);
        state.record_new_flow_state(
            flow,
            proto,
            Some(&source_group),
            "dns_intercept_new",
            now,
            false,
        );
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    let snat_disabled = matches!(state.snat_mode, SnatMode::None);
    if !snat_disabled {
        state.nat.prefetch_flow_key(&flow);
        if state.nat.get_entry(&flow).is_none() {
            if let Some(rejection) =
                state.admission_rejection(Some(&source_group), false, false, true)
            {
                state.note_admission_rejection(rejection);
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(proto),
                        "deny",
                        source_group.as_ref(),
                        pkt.len(),
                    );
                }
                return Action::Drop;
            }
        }
        let (external_port, nat_created) = match state.nat.get_or_create_with_status(&flow, now) {
            Ok(result) => result,
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
        if nat_created {
            state.note_nat_open();
        }
    }
    if let Some(metrics) = &state.metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(proto),
            "allow",
            source_group.as_ref(),
            pkt.len(),
        );
    }
    maybe_close_tcp_flow(state, &flow, pkt, now);
    Action::Forward {
        out_port: state.data_port,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_inbound_no_snat(
    pkt: &mut Packet,
    state: &mut EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    proto: u8,
    now: u64,
) -> Action {
    let tcp_flags = if proto == 6 { pkt.tcp_flags() } else { None };
    let inbound_synack = tcp_flags.is_some_and(is_tcp_synack);
    let flow = FlowKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: dst_port,
        dst_port: src_port,
        proto,
    };
    let flow_probe_start = Instant::now();
    state.flows.prefetch_key(&flow);
    let flow_probe = state.flows.probe(&flow);
    state.note_tcp_handshake_stage("inbound", "flow_probe", flow_probe_start.elapsed());
    state.note_table_probe(
        "flow",
        "lookup",
        flow_probe.result_label(),
        flow_probe.steps(),
    );
    if state.syn_only_enabled && inbound_synack && !flow_probe.is_hit() {
        if let Some(promoted) = state.syn_only.promote(&flow, now) {
            state.note_syn_only_lookup("promoted");
            state.note_syn_only_promotion("inbound_synack");
            let promoted_source_group = promoted.source_group.clone();
            let mut promoted_entry =
                FlowEntry::with_source_group_arc(promoted.last_seen, promoted.source_group);
            promoted_entry.first_seen = promoted.first_seen;
            promoted_entry.last_seen = promoted.last_seen;
            promoted_entry.packets_out = promoted.packets_out;
            promoted_entry.policy_generation = promoted.policy_generation;
            promoted_entry.intercept_requires_service = promoted.intercept_requires_service;
            promoted_entry.note_syn_outbound();
            state.note_table_probe(
                "flow",
                "insert",
                flow_probe.result_label(),
                flow_probe.steps(),
            );
            state
                .flows
                .insert_with_probe_and_get_mut(flow, promoted_entry, flow_probe);
            state.record_syn_only_promotion(promoted_source_group.as_ref());
            state.record_new_flow_state(
                flow,
                proto,
                promoted_source_group.as_ref(),
                "inbound_synack_promote",
                now,
                false,
            );
            state.update_syn_only_metrics();
        } else {
            state.note_syn_only_lookup("miss");
        }
    }
    let policy = &state.policy_snapshot;
    let verifier = &state.tls_verifier;
    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let policy_snapshot = state.policy_snapshot.clone();
    let current_generation = state.current_policy_generation();
    let audit = state.audit.clone();
    let meta = PacketMeta {
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        proto: flow.proto,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        icmp_type: None,
        icmp_code: None,
    };
    let mut policy_drop = false;
    let mut policy_drop_group: Option<Arc<str>> = None;
    let mut source_group_membership = None;
    let mut pending_tls_membership = None;
    let mut tls_packet_denied = false;
    let mut tls_packet_drop_group: Option<Arc<str>> = None;
    let need_entry_source_group = metrics.is_some();
    let worker_id = state.dpdk_worker_id();
    let detailed_dataplane_observability = state.detailed_dataplane_observability;
    let mut note_synack_in = false;
    let mut note_synack_in_first = false;
    let mut note_synack_in_repeat = false;
    let pending_tls_cap = state.admission_control.max_pending_tls_flows;
    let current_pending_tls_flow_count = state.pending_tls_flow_count;
    let mut pending_tls_cap_rejection = None;
    let (decision_label, entry_source_group) = {
        let flow_state_start = Instant::now();
        let entry = match state.flows.get_entry_mut_with_probe(&flow, flow_probe) {
            Some(entry) => entry,
            None => {
                if detailed_dataplane_observability {
                    if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                        metrics.observe_dp_handshake_stage(
                            worker_id,
                            "inbound",
                            "flow_lookup_miss",
                            flow_state_start.elapsed(),
                        );
                    }
                }
                if inbound_synack {
                    state.note_tcp_handshake_drop(
                        "synack",
                        state.classify_synack_flow_missing_reason(&flow, now),
                    );
                }
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
        if detailed_dataplane_observability {
            if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                metrics.observe_dp_handshake_stage(
                    worker_id,
                    "inbound",
                    "flow_lookup_hit",
                    flow_state_start.elapsed(),
                );
            }
        }
        let source_group_before = entry.source_group_arc();
        let pending_tls_before = entry.pending_tls();
        if entry.policy_generation != current_generation {
            let policy_eval_start = Instant::now();
            let exact_source_policy_index = &state.exact_source_policy_index;
            let policy = policy_snapshot.load();
            let evaluation = evaluate_policy_outcome(
                exact_source_policy_index,
                &policy,
                &meta,
                entry.tls.as_ref().map(|tls| &tls.observation),
                &state.tls_verifier,
                state.audit.is_some(),
            );
            if detailed_dataplane_observability {
                if let (Some(metrics), Some(worker_id)) = (&metrics, worker_id) {
                    metrics.observe_dp_handshake_stage(
                        worker_id,
                        "inbound",
                        "policy_eval",
                        policy_eval_start.elapsed(),
                    );
                }
            }
            let next_group = evaluation.source_group.clone();
            if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                let sni = entry
                    .tls
                    .as_ref()
                    .and_then(|tls| tls.observation.sni.clone());
                maybe_emit_policy_deny_audit(
                    audit.as_ref(),
                    &meta,
                    source_group_label(next_group.as_ref()),
                    sni,
                    now,
                );
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.set_source_group_arc(next_group);
                }
                PolicyDecision::PendingTls => {
                    if !pending_tls_before {
                        if pending_tls_cap.is_some_and(|max| current_pending_tls_flow_count >= max)
                        {
                            pending_tls_cap_rejection = Some(AdmissionRejection::PendingTlsCap);
                            policy_drop = true;
                            policy_drop_group = next_group;
                        } else {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_arc(next_group);
                            if let Some(tls_state) = &mut entry.tls {
                                tls_state.decision = TlsFlowDecision::Pending;
                            } else {
                                entry.tls = Some(TlsFlowState::new());
                            }
                        }
                    } else {
                        entry.policy_generation = current_generation;
                        entry.set_source_group_arc(next_group);
                        if let Some(tls_state) = &mut entry.tls {
                            tls_state.decision = TlsFlowDecision::Pending;
                        } else {
                            entry.tls = Some(TlsFlowState::new());
                        }
                    }
                }
                PolicyDecision::Deny => {
                    policy_drop = true;
                    policy_drop_group = next_group;
                }
            }
        }
        if !policy_drop {
            entry.last_seen = now;
            entry.packets_in = entry.packets_in.saturating_add(1);
            if inbound_synack {
                let synack_seen_before = entry.synack_inbound_seen();
                entry.note_synack_inbound();
                note_synack_in = true;
                if synack_seen_before {
                    note_synack_in_repeat = true;
                } else {
                    note_synack_in_first = true;
                }
            }
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            let tls_source_group = if entry.tls.is_some() {
                entry.source_group_arc()
            } else {
                None
            };
            if let Some(tls_state) = &mut entry.tls {
                let source_group_name = source_group_label(tls_source_group.as_ref());
                if !process_tls_packet(
                    pkt,
                    TlsDirection::ServerToClient,
                    tls_state,
                    &meta,
                    policy,
                    verifier,
                    audit.as_ref(),
                    source_group_name,
                    now,
                    metrics.as_deref(),
                ) {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "inbound",
                            proto_label(proto),
                            "deny",
                            source_group_name,
                            pkt.len(),
                        );
                    }
                    tls_packet_denied = true;
                    tls_packet_drop_group = tls_source_group.clone();
                }
            }
            source_group_membership = Some((source_group_before, entry.source_group_arc()));
            pending_tls_membership = Some((pending_tls_before, entry.pending_tls()));
            (
                flow_decision_label(entry),
                if need_entry_source_group {
                    entry.source_group_arc()
                } else {
                    None
                },
            )
        } else {
            ("deny", None)
        }
    };
    if let Some((previous, next)) = source_group_membership {
        state.reconcile_source_group_membership(previous, next);
    }
    if let Some((was_pending, is_pending)) = pending_tls_membership {
        state.reconcile_pending_tls_membership(was_pending, is_pending);
    }
    if let Some(rejection) = pending_tls_cap_rejection {
        state.note_admission_rejection(rejection);
    }
    if tls_packet_denied {
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "inbound",
                proto_label(proto),
                "deny",
                source_group_label(tls_packet_drop_group.as_ref()),
                pkt.len(),
            );
        }
        return Action::Drop;
    }
    let entry_source_group_name = source_group_label(entry_source_group.as_ref());
    if note_synack_in {
        state.note_tcp_handshake_event_for_target("synack_in", flow.dst_ip);
        if note_synack_in_first {
            state.note_tcp_handshake_event_for_target("synack_in_first", flow.dst_ip);
        }
        if note_synack_in_repeat {
            state.note_tcp_handshake_event_for_target("synack_in_repeat", flow.dst_ip);
        }
    }

    if policy_drop {
        let _ = remove_flow_state_timed(
            state,
            &flow,
            now,
            "policy_drop",
            "inbound",
            "flow_close_policy_drop",
        );
        if inbound_synack {
            state.note_tcp_handshake_drop("synack", "policy_deny");
        }
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "inbound",
                proto_label(proto),
                "deny",
                source_group_label(policy_drop_group.as_ref()),
                pkt.len(),
            );
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    if let Some(metrics) = &metrics {
        metrics.observe_dp_packet(
            "inbound",
            proto_label(proto),
            decision_label,
            entry_source_group_name,
            pkt.len(),
        );
    }
    if inbound_synack {
        state.note_tcp_handshake_event_for_target("synack_out", flow.dst_ip);
        if note_synack_in_first {
            state.note_tcp_handshake_event_for_target("synack_out_first", flow.dst_ip);
        }
        if note_synack_in_repeat {
            state.note_tcp_handshake_event_for_target("synack_out_repeat", flow.dst_ip);
        }
    }
    maybe_close_tcp_flow_timed(state, &flow, pkt, now, "inbound");
    Action::Forward {
        out_port: state.data_port,
    }
}
