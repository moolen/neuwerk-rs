use std::time::Instant;

pub fn handle_packet(pkt: &mut Packet, state: &mut EngineState) -> Action {
    let now = state.now_secs();

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
    let src_internal = state.is_internal(src_ip);
    let dst_internal = state.is_internal(dst_ip);

    if proto == 1 {
        if snat_disabled {
            if src_internal && !dst_internal {
                return handle_outbound_icmp_no_snat(pkt, state, src_ip, dst_ip, now);
            }
            if !src_internal && dst_internal {
                return handle_inbound_icmp_no_snat(pkt, state, src_ip, dst_ip, now);
            }
            return Action::Drop;
        }
        if src_internal && !dst_internal {
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
    let tcp_flags = if proto == 6 { pkt.tcp_flags() } else { None };
    if is_dns_target_outbound_flow(state, dst_ip, proto, dst_port, src_internal, dst_internal) {
        return handle_outbound_dns_target(
            pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
        );
    }

    if snat_disabled {
        if src_internal && !dst_internal {
            return handle_outbound_no_snat(
                pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
            );
        }
        if !src_internal && dst_internal {
            return handle_inbound_no_snat(
                pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
            );
        }
        return Action::Drop;
    }

    if src_internal && !dst_internal {
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
        let mut allow_without_flow_state = false;
        let mut pending_entry: Option<FlowEntry> = None;
        let mut source_group: Option<Arc<str>> = None;
        let mut syn_only_decision: Option<(&'static str, Option<Arc<str>>, bool)> = None;
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
            state.note_tcp_handshake_stage(
                "outbound",
                "policy_eval_miss",
                policy_eval_start.elapsed(),
            );
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
                        if let Some(action) = maybe_intercept_fail_closed_rst(
                            pkt,
                            state,
                            source_group_label,
                            "outbound",
                        ) {
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
                        allow_without_flow_state = true;
                    } else {
                        is_new = true;
                    }
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
                        state.update_syn_only_metrics();
                        syn_only_decision = Some((
                            "allow",
                            source_group.clone(),
                            evaluation.intercept_requires_service,
                        ));
                    } else if allow_without_flow_state {
                        // Do not resurrect closed TCP flows or allocate fresh NAT state for
                        // non-SYN misses. These packets may be late FIN/ACK traffic arriving
                        // after the real flow was already removed.
                    } else {
                        let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                        entry.policy_generation = current_generation;
                        entry.intercept_requires_service = evaluation.intercept_requires_service;
                        pending_entry = Some(entry);
                    }
                }
                PolicyDecision::Deny => {
                    if outbound_syn && state.syn_only_enabled {
                        let _ = remove_flow_state(state, &flow, now, "policy_deny");
                    }
                    if outbound_syn {
                        state.note_tcp_handshake_drop("syn", "policy_deny");
                    }
                    if evaluation.intercept_requires_service {
                        if let Some(action) = maybe_intercept_fail_closed_rst(
                            pkt,
                            state,
                            source_group_label,
                            "outbound",
                        ) {
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
                        state.update_syn_only_metrics();
                        syn_only_decision = Some(("pending_tls", source_group.clone(), false));
                    } else {
                        let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                        entry.policy_generation = current_generation;
                        entry.intercept_requires_service = false;
                        entry.tls = Some(TlsFlowState::new());
                        pending_entry = Some(entry);
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
            state.note_flow_open_with_reason(
                flow,
                proto,
                source_group_label(source_group.as_ref()),
                "outbound_miss",
                now,
            );
        }

        let policy = &state.policy_snapshot;
        let verifier = &state.tls_verifier;
        let wiretap = state.wiretap.clone();
        let metrics = state.metrics.clone();
        let mut policy_drop = false;
        let mut policy_drop_group: Option<Arc<str>> = None;
        let mut policy_drop_intercept_requires_service = false;
        let mut mark_handshake_completed = false;
        let mut note_syn_out_first = false;
        let mut note_syn_out_repeat = false;
        let need_entry_source_group = metrics.is_some();
        let worker_id = state.dpdk_worker_id();
        let detailed_dataplane_observability = state.detailed_dataplane_observability;
        let (decision_label, entry_source_group, flow_intercept_requires_service) =
            if allow_without_flow_state {
                (
                    "allow",
                    if need_entry_source_group {
                        source_group.clone()
                    } else {
                        None
                    },
                    false,
                )
            } else if let Some((decision_label, source_group, intercept_requires_service)) =
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
                if entry.policy_generation != current_generation {
                    let policy_eval_start = Instant::now();
                    let exact_source_policy_index = &state.exact_source_policy_index;
                    let policy = state.policy_snapshot.load();
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
                                state
                                    .service_policy_applied_generation
                                    .as_ref()
                                    .map(|tracker| {
                                        tracker.load(Ordering::Acquire) >= current_generation
                                    })
                                    .unwrap_or(true)
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
                            entry.policy_generation = current_generation;
                            entry.set_source_group_arc(next_group);
                            entry.intercept_requires_service = false;
                            if let Some(tls_state) = &mut entry.tls {
                                tls_state.decision = TlsFlowDecision::Pending;
                            } else {
                                entry.tls = Some(TlsFlowState::new());
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
                    let fast_allow_path = wiretap.is_none()
                        && metrics.is_none()
                        && entry.tls.is_none()
                        && !(state.intercept_to_host_steering && entry.intercept_requires_service);
                    if fast_allow_path {
                        ("allow", None, false)
                    } else {
                        maybe_emit_wiretap(&wiretap, &flow, entry, now);
                        let tls_source_group = if entry.tls.is_some() {
                            entry.source_group_arc()
                        } else {
                            None
                        };
                        if let Some(tls_state) = &mut entry.tls {
                            let source_group_label = source_group_label(tls_source_group.as_ref());
                            if !process_tls_packet(
                                pkt,
                                TlsDirection::ClientToServer,
                                tls_state,
                                &meta,
                                policy,
                                verifier,
                                audit.as_ref(),
                                source_group_label,
                                now,
                                metrics.as_deref(),
                            ) {
                                if let Some(metrics) = &metrics {
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
                        }
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
        let entry_source_group_label = entry_source_group
            .as_deref()
            .unwrap_or(DEFAULT_SOURCE_GROUP);

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

        if state.intercept_to_host_steering && flow_intercept_requires_service {
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    decision_label,
                    entry_source_group_label,
                    pkt.len(),
                );
            }
            return Action::ToHost;
        }

        if snat_disabled {
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    decision_label,
                    entry_source_group_label,
                    pkt.len(),
                );
            }
            return Action::Forward {
                out_port: state.data_port,
            };
        }

        state.nat.prefetch_flow_key(&flow);
        let nat_start = Instant::now();
        let (external_port, nat_created) = if allow_without_flow_state {
            let existing_port = state.nat.get_entry(&flow).map(|entry| entry.external_port);
            state.note_tcp_handshake_stage("outbound", "nat_forward", nat_start.elapsed());
            match existing_port {
                Some(port) => {
                    state.nat.touch(&flow, now);
                    (port, false)
                }
                None => {
                    if outbound_ack_only {
                        state.note_tcp_handshake_drop("ack", "flow_missing");
                    }
                    return Action::Drop;
                }
            }
        } else {
            let nat_obs = match state.nat.get_or_create_with_observation(&flow, now) {
                Ok(result) => result,
                Err(_) => {
                    state.note_tcp_handshake_stage("outbound", "nat_forward", nat_start.elapsed());
                    state.note_nat_port_scan(
                        "port_exhausted",
                        crate::dataplane::nat::NatTable::port_range_len() as usize,
                    );
                    if outbound_syn {
                        state.note_tcp_handshake_drop("syn", "nat_alloc_failed");
                    } else if mark_handshake_completed {
                        state.note_tcp_handshake_drop("ack", "nat_alloc_failed");
                    }
                    return Action::Drop;
                }
            };
            state.note_tcp_handshake_stage("outbound", "nat_forward", nat_start.elapsed());
            state.note_table_probe(
                "nat_forward",
                "lookup",
                nat_obs.map_probe_result,
                nat_obs.map_probe_steps,
            );
            if nat_obs.created {
                state.note_table_probe(
                    "nat_reverse",
                    "insert",
                    nat_obs.reverse_probe_result,
                    nat_obs.reverse_probe_steps,
                );
                state.note_nat_port_scan("allocated", nat_obs.port_scan_steps);
            } else {
                state.note_nat_port_scan("reused", 0);
            }
            (nat_obs.external_port, nat_obs.created)
        };

        let rewrite_start = Instant::now();
        let snat_ip = match resolve_snat_ip(state) {
            Some(ip) => ip,
            None => {
                state.note_tcp_handshake_stage("outbound", "rewrite", rewrite_start.elapsed());
                if outbound_syn {
                    state.note_tcp_handshake_drop("syn", "snat_ip_missing");
                } else if mark_handshake_completed {
                    state.note_tcp_handshake_drop("ack", "snat_ip_missing");
                }
                return Action::Drop;
            }
        };
        if !pkt.set_src_ip(snat_ip) {
            state.note_tcp_handshake_stage("outbound", "rewrite", rewrite_start.elapsed());
            if outbound_syn {
                state.note_tcp_handshake_drop("syn", "rewrite_src_ip_failed");
            } else if mark_handshake_completed {
                state.note_tcp_handshake_drop("ack", "rewrite_src_ip_failed");
            }
            return Action::Drop;
        }
        if !pkt.set_src_port(external_port) {
            state.note_tcp_handshake_stage("outbound", "rewrite", rewrite_start.elapsed());
            if outbound_syn {
                state.note_tcp_handshake_drop("syn", "rewrite_src_port_failed");
            } else if mark_handshake_completed {
                state.note_tcp_handshake_drop("ack", "rewrite_src_port_failed");
            }
            return Action::Drop;
        }
        state.note_tcp_handshake_stage("outbound", "rewrite", rewrite_start.elapsed());

        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(proto),
                decision_label,
                entry_source_group_label,
                pkt.len(),
            );
        }
        if nat_created {
            state.note_nat_open();
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
        if !allow_without_flow_state {
            maybe_close_tcp_flow_timed(state, &flow, pkt, now, "outbound");
        }
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    if snat_disabled && !src_internal && dst_internal {
        return handle_inbound_no_snat(pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now);
    }

    if dst_ip == resolve_snat_ip(state).unwrap_or(Ipv4Addr::UNSPECIFIED) {
        let inbound_synack = tcp_flags.is_some_and(is_tcp_synack);
        let reverse_key = ReverseKey {
            external_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            proto,
        };
        let nat_reverse_start = Instant::now();
        state.nat.prefetch_reverse_key(&reverse_key);
        let reverse_obs = state.nat.reverse_lookup_with_observation(&reverse_key);
        state.note_tcp_handshake_stage("inbound", "nat_reverse", nat_reverse_start.elapsed());
        state.note_table_probe(
            "nat_reverse",
            "lookup",
            reverse_obs.probe_result,
            reverse_obs.probe_steps,
        );
        if let Some(flow) = reverse_obs.flow {
            state.nat.touch(&flow, now);
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
                    state.note_flow_open_with_reason(
                        flow,
                        proto,
                        source_group_label(promoted_source_group.as_ref()),
                        "inbound_synack_promote",
                        now,
                    );
                    state.update_syn_only_metrics();
                } else {
                    state.note_syn_only_lookup("miss");
                }
            }
            let policy = &state.policy_snapshot;
            let verifier = &state.tls_verifier;
            let wiretap = state.wiretap.clone();
            let audit = state.audit.clone();
            let metrics = state.metrics.clone();
            let current_generation = state.current_policy_generation();
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
            let mut note_synack_in = false;
            let mut note_synack_in_first = false;
            let mut note_synack_in_repeat = false;
            let need_entry_source_group = metrics.is_some();
            let worker_id = state.dpdk_worker_id();
            let detailed_dataplane_observability = state.detailed_dataplane_observability;
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
                if entry.policy_generation != current_generation {
                    let policy_eval_start = Instant::now();
                    let exact_source_policy_index = &state.exact_source_policy_index;
                    let policy = state.policy_snapshot.load();
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
                            entry.policy_generation = current_generation;
                            entry.set_source_group_arc(next_group);
                            if let Some(tls_state) = &mut entry.tls {
                                tls_state.decision = TlsFlowDecision::Pending;
                            } else {
                                entry.tls = Some(TlsFlowState::new());
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
                        let source_group_label = source_group_label(tls_source_group.as_ref());
                        if !process_tls_packet(
                            pkt,
                            TlsDirection::ServerToClient,
                            tls_state,
                            &meta,
                            policy,
                            verifier,
                            audit.as_ref(),
                            source_group_label,
                            now,
                            metrics.as_deref(),
                        ) {
                            if let Some(metrics) = &metrics {
                                metrics.observe_dp_packet(
                                    "inbound",
                                    proto_label(proto),
                                    "deny",
                                    source_group_label,
                                    pkt.len(),
                                );
                            }
                            return Action::Drop;
                        }
                    }
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
            let entry_source_group_label = entry_source_group
                .as_deref()
                .unwrap_or(DEFAULT_SOURCE_GROUP);
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

            let rewrite_start = Instant::now();
            if !pkt.set_dst_ip(flow.src_ip) {
                state.note_tcp_handshake_stage("inbound", "rewrite", rewrite_start.elapsed());
                if inbound_synack {
                    state.note_tcp_handshake_drop("synack", "rewrite_dst_ip_failed");
                }
                return Action::Drop;
            }
            if !pkt.set_dst_port(flow.src_port) {
                state.note_tcp_handshake_stage("inbound", "rewrite", rewrite_start.elapsed());
                if inbound_synack {
                    state.note_tcp_handshake_drop("synack", "rewrite_dst_port_failed");
                }
                return Action::Drop;
            }
            state.note_tcp_handshake_stage("inbound", "rewrite", rewrite_start.elapsed());
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "inbound",
                    proto_label(proto),
                    decision_label,
                    entry_source_group_label,
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
            return Action::Forward {
                out_port: state.data_port,
            };
        }
        if NAT_MISS_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            tracing::debug!(
                src_ip = %src_ip,
                dst_ip = %dst_ip,
                src_port,
                dst_port,
                proto,
                snat_ip = %resolve_snat_ip(state).unwrap_or(Ipv4Addr::UNSPECIFIED),
                "dataplane nat miss"
            );
        }
        if inbound_synack {
            state.note_tcp_handshake_drop("synack", "nat_reverse_miss");
        }
        if let Some(metrics) = &state.metrics {
            metrics.observe_dp_packet("inbound", proto_label(proto), "deny", "default", pkt.len());
        }
        return Action::Drop;
    }

    Action::Drop
}

struct PolicyEvalOutcome {
    effective: PolicyDecision,
    raw: PolicyDecision,
    source_group: Option<Arc<str>>,
    intercept_requires_service: bool,
    audit_rule_denied: bool,
}

fn deny_policy_eval_outcome() -> PolicyEvalOutcome {
    PolicyEvalOutcome {
        effective: PolicyDecision::Deny,
        raw: PolicyDecision::Deny,
        source_group: None,
        intercept_requires_service: false,
        audit_rule_denied: false,
    }
}

fn evaluate_policy_outcome(
    exact_source_policy_index: &SharedExactSourceGroupIndex,
    snapshot: &PolicySnapshot,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: &TlsVerifier,
    audit_enabled: bool,
) -> PolicyEvalOutcome {
    let exact_verifier = Some(verifier);
    let exact_source_group_index = exact_source_policy_index.load();
    let use_exact_source_index = exact_source_group_index.matches_generation(snapshot.generation())
        && exact_source_group_index.has_candidates();
    let exact_group_indices = if use_exact_source_index {
        exact_source_group_index.group_indices(meta.src_ip)
    } else {
        None
    };
    let fallback_group_indices = if use_exact_source_index {
        exact_source_group_index.fallback_group_indices()
    } else {
        None
    };
    let (effective, raw, group_idx, intercept_requires_service) = if use_exact_source_index {
        snapshot.evaluate_with_source_group_effective_and_raw_index_for_group_indices_borrowed(
            exact_group_indices,
            fallback_group_indices,
            meta,
            tls,
            exact_verifier,
        )
    } else {
        snapshot.evaluate_with_source_group_effective_and_raw_index_borrowed(
            meta,
            tls,
            exact_verifier,
        )
    };
    let (audit_rule_denied, audit_group_idx) = if audit_enabled && snapshot.has_audit_rules() {
        let (audit_decision, audit_group_idx, audit_matched) = if use_exact_source_index {
            snapshot.evaluate_audit_rules_with_source_group_index_for_group_indices_borrowed(
                exact_group_indices,
                fallback_group_indices,
                meta,
                tls,
                exact_verifier,
            )
        } else {
            snapshot.evaluate_audit_rules_with_source_group_index_borrowed(
                meta,
                tls,
                exact_verifier,
            )
        };
        (
            audit_matched && audit_decision == PolicyDecision::Deny,
            audit_group_idx,
        )
    } else {
        (false, None)
    };
    let source_group = group_idx
        .or(audit_group_idx)
        .and_then(|group_idx| snapshot.group_id_arc(group_idx));
    PolicyEvalOutcome {
        effective,
        raw,
        source_group,
        intercept_requires_service,
        audit_rule_denied,
    }
}
