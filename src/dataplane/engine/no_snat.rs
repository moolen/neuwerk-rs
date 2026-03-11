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
    let audit = state.audit.clone();
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
                        entry.intercept_requires_service = evaluation.intercept_requires_service;
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
                    policy_drop_intercept_requires_service = evaluation.intercept_requires_service;
                    entry.intercept_requires_service = false;
                }
            }
        }
        if policy_drop_group.is_none() {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            let source_group = entry.source_group().to_string();
            if let Some(tls_state) = &mut entry.tls {
                if !process_tls_packet(
                    pkt,
                    TlsDirection::ClientToServer,
                    tls_state,
                    &meta,
                    policy,
                    verifier,
                    audit.as_ref(),
                    source_group.as_str(),
                    now,
                    metrics.as_deref(),
                ) {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "outbound",
                            proto_label(proto),
                            "deny",
                            source_group.as_str(),
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
            ("deny", entry.source_group().to_string(), false)
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now, "policy_drop");
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
                entry_source_group.as_str(),
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
            entry_source_group.as_str(),
            pkt.len(),
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

pub(super) fn is_dns_target_outbound_flow(
    state: &EngineState,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto: u8,
    dst_port: u16,
) -> bool {
    if dst_port != 53 {
        return false;
    }
    if proto != 6 && proto != 17 {
        return false;
    }
    if !state.is_internal(src_ip) || state.is_internal(dst_ip) {
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
    let source_group = "dns-intercept";
    if state.flows.get_entry(&flow).is_none() {
        let mut entry = FlowEntry::with_source_group(now, source_group.to_string());
        entry.policy_generation = state.current_policy_generation();
        state.flows.insert(flow, entry);
        state.note_flow_open(flow, now);
        if let Some(metrics) = &state.metrics {
            metrics.inc_dp_flow_open(proto_label(proto), source_group);
        }
        state.update_flow_metrics();
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    let snat_disabled = matches!(state.snat_mode, SnatMode::None);
    if !snat_disabled {
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
        if nat_created {
            state.update_nat_metrics();
        }
    }
    if let Some(metrics) = &state.metrics {
        metrics.observe_dp_packet(
            "outbound",
            proto_label(proto),
            "allow",
            source_group,
            pkt.len(),
        );
    }
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
    let flow = FlowKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: dst_port,
        dst_port: src_port,
        proto,
    };
    state.flows.prefetch_key(&flow);
    let policy = &state.policy;
    let verifier = &state.tls_verifier;
    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
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
            let source_group = entry.source_group().to_string();
            if let Some(tls_state) = &mut entry.tls {
                if !process_tls_packet(
                    pkt,
                    TlsDirection::ServerToClient,
                    tls_state,
                    &meta,
                    policy,
                    verifier,
                    audit.as_ref(),
                    source_group.as_str(),
                    now,
                    metrics.as_deref(),
                ) {
                    if let Some(metrics) = &metrics {
                        metrics.observe_dp_packet(
                            "inbound",
                            proto_label(proto),
                            "deny",
                            source_group.as_str(),
                            pkt.len(),
                        );
                    }
                    return Action::Drop;
                }
            }
            (flow_decision_label(entry), source_group)
        } else {
            ("deny", entry.source_group().to_string())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now, "policy_drop");
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
