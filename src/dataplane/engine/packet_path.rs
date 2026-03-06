pub fn handle_packet(pkt: &mut Packet, state: &mut EngineState) -> Action {
    let now = state.now_secs();
    state.evict_expired_if_needed(now);

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
    if is_dns_target_outbound_flow(state, src_ip, dst_ip, proto, dst_port) {
        return handle_outbound_dns_target(
            pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
        );
    }

    if snat_disabled {
        // In no-SNAT mode, reverse traffic must be matched against the
        // forward flow regardless of overlay mode.
        let reverse = FlowKey {
            src_ip: dst_ip,
            dst_ip: src_ip,
            src_port: dst_port,
            dst_port: src_port,
            proto,
        };
        state.flows.prefetch_key(&reverse);
        if state.flows.get_entry(&reverse).is_some() {
            return handle_inbound_no_snat(
                pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now,
            );
        }

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
        let flow = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        };
        state.flows.prefetch_key(&flow);
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
        let mut current_generation = state.current_policy_generation();
        let audit = state.audit.clone();
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
            let (evaluation, generation) = match state.policy.read() {
                Ok(lock) => (
                    evaluate_policy_outcome(&lock, &meta, None, &state.tls_verifier),
                    lock.generation(),
                ),
                Err(_) => (
                    PolicyEvalOutcome {
                        effective: PolicyDecision::Deny,
                        raw: PolicyDecision::Deny,
                        source_group: "default".to_string(),
                        intercept_requires_service: false,
                        audit_rule_denied: false,
                    },
                    0,
                ),
            };
            current_generation = generation;
            source_group = evaluation.source_group.clone();
            if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &source_group, None, now);
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    if evaluation.intercept_requires_service
                        && !state.service_policy_ready_for_generation(current_generation)
                    {
                        if let Some(action) =
                            maybe_intercept_fail_closed_rst(pkt, state, &source_group, "outbound")
                        {
                            return action;
                        }
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
                    is_new = true;
                    let mut entry = FlowEntry::with_source_group(now, source_group.clone());
                    entry.policy_generation = current_generation;
                    entry.intercept_requires_service = evaluation.intercept_requires_service;
                    state.flows.insert(flow, entry);
                }
                PolicyDecision::Deny => {
                    if evaluation.intercept_requires_service {
                        if let Some(action) =
                            maybe_intercept_fail_closed_rst(pkt, state, &source_group, "outbound")
                        {
                            return action;
                        }
                    }
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
                    entry.intercept_requires_service = false;
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
        let service_ready_for_current_generation =
            state.service_policy_ready_for_generation(current_generation);
        let mut policy_drop_group: Option<String> = None;
        let mut policy_drop_intercept_requires_service = false;
        let (decision_label, entry_source_group, flow_intercept_requires_service) = {
            let entry = match state.flows.get_entry_mut(&flow) {
                Some(entry) => entry,
                None => return Action::Drop,
            };
            if entry.policy_generation != current_generation {
                let evaluation = match state.policy.read() {
                    Ok(lock) => evaluate_policy_outcome(
                        &lock,
                        &meta,
                        entry.tls.as_ref().map(|tls| &tls.observation),
                        &state.tls_verifier,
                    ),
                    Err(_) => PolicyEvalOutcome {
                        effective: PolicyDecision::Deny,
                        raw: PolicyDecision::Deny,
                        source_group: "default".to_string(),
                        intercept_requires_service: false,
                        audit_rule_denied: false,
                    },
                };
                let next_group = evaluation.source_group.clone();
                if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                    let sni = entry
                        .tls
                        .as_ref()
                        .and_then(|tls| tls.observation.sni.clone());
                    maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, sni, now);
                }
                match evaluation.effective {
                    PolicyDecision::Allow => {
                        if evaluation.intercept_requires_service
                            && !service_ready_for_current_generation
                        {
                            policy_drop_group = Some(next_group);
                            policy_drop_intercept_requires_service = true;
                        } else {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_owned(next_group);
                            entry.intercept_requires_service =
                                evaluation.intercept_requires_service;
                        }
                    }
                    PolicyDecision::PendingTls => {
                        entry.policy_generation = current_generation;
                        entry.set_source_group_owned(next_group);
                        entry.intercept_requires_service = false;
                        if let Some(tls_state) = &mut entry.tls {
                            tls_state.decision = TlsFlowDecision::Pending;
                        } else {
                            entry.tls = Some(TlsFlowState::new());
                        }
                    }
                    PolicyDecision::Deny => {
                        policy_drop_group = Some(next_group);
                        policy_drop_intercept_requires_service =
                            evaluation.intercept_requires_service;
                        entry.intercept_requires_service = false;
                    }
                }
            }
            if policy_drop_group.is_none() {
                entry.last_seen = now;
                entry.packets_out = entry.packets_out.saturating_add(1);
                maybe_emit_wiretap(&wiretap, &flow, entry, now);
                let source_group = entry.source_group_arc();
                let source_group_label = source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP);
                if let Some(tls_state) = &mut entry.tls {
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
                    source_group,
                    entry.intercept_requires_service,
                )
            } else {
                ("deny", entry.source_group_arc(), false)
            }
        };
        let entry_source_group_label = entry_source_group
            .as_deref()
            .unwrap_or(DEFAULT_SOURCE_GROUP);

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now);
            if policy_drop_intercept_requires_service {
                if let Some(action) =
                    maybe_intercept_fail_closed_rst(pkt, state, &drop_group, "outbound")
                {
                    return action;
                }
            }
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
            state.update_nat_metrics();
        }
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    if snat_disabled {
        if !src_internal && dst_internal {
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
        state.nat.prefetch_reverse_key(&reverse_key);
        if let Some(flow) = state.nat.reverse_lookup(&reverse_key) {
            state.nat.touch(&flow, now);
            state.flows.prefetch_key(&flow);
            let policy = &state.policy;
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
            let mut policy_drop_group: Option<String> = None;
            let (decision_label, entry_source_group) = {
                let entry = match state.flows.get_entry_mut(&flow) {
                    Some(entry) => entry,
                    None => return Action::Drop,
                };
                if entry.policy_generation != current_generation {
                    let evaluation = match state.policy.read() {
                        Ok(lock) => evaluate_policy_outcome(
                            &lock,
                            &meta,
                            entry.tls.as_ref().map(|tls| &tls.observation),
                            &state.tls_verifier,
                        ),
                        Err(_) => PolicyEvalOutcome {
                            effective: PolicyDecision::Deny,
                            raw: PolicyDecision::Deny,
                            source_group: "default".to_string(),
                            intercept_requires_service: false,
                            audit_rule_denied: false,
                        },
                    };
                    let next_group = evaluation.source_group.clone();
                    if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                        let sni = entry
                            .tls
                            .as_ref()
                            .and_then(|tls| tls.observation.sni.clone());
                        maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, sni, now);
                    }
                    match evaluation.effective {
                        PolicyDecision::Allow => {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_owned(next_group);
                        }
                        PolicyDecision::PendingTls => {
                            entry.policy_generation = current_generation;
                            entry.set_source_group_owned(next_group);
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
                    let source_group = entry.source_group_arc();
                    let source_group_label =
                        source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP);
                    if let Some(tls_state) = &mut entry.tls {
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
                    (flow_decision_label(entry), source_group)
                } else {
                    ("deny", entry.source_group_arc())
                }
            };
            let entry_source_group_label = entry_source_group
                .as_deref()
                .unwrap_or(DEFAULT_SOURCE_GROUP);

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
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "inbound",
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

struct PolicyEvalOutcome {
    effective: PolicyDecision,
    raw: PolicyDecision,
    source_group: String,
    intercept_requires_service: bool,
    audit_rule_denied: bool,
}

fn evaluate_policy_outcome(
    snapshot: &PolicySnapshot,
    meta: &PacketMeta,
    tls: Option<&TlsObservation>,
    verifier: &TlsVerifier,
) -> PolicyEvalOutcome {
    let (effective, group, intercept_requires_service) =
        snapshot.evaluate_with_source_group_detailed(meta, tls, Some(verifier));
    let (raw, raw_group, _) =
        snapshot.evaluate_with_source_group_detailed_raw(meta, tls, Some(verifier));
    let (audit_decision, audit_group, audit_matched) =
        snapshot.evaluate_audit_rules_with_source_group(meta, tls, Some(verifier));
    let source_group = group
        .or(raw_group)
        .or(audit_group)
        .unwrap_or_else(|| "default".to_string());
    let audit_rule_denied = audit_matched && audit_decision == PolicyDecision::Deny;
    PolicyEvalOutcome {
        effective,
        raw,
        source_group,
        intercept_requires_service,
        audit_rule_denied,
    }
}
