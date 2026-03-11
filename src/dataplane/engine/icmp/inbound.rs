pub(super) fn handle_inbound_icmp_no_snat(
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
    let audit = state.audit.clone();
    let current_generation = state.current_policy_generation();

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
        state.flows.prefetch_key(&flow);
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
                let meta = PacketMeta {
                    src_ip: flow.src_ip,
                    dst_ip: flow.dst_ip,
                    proto: flow.proto,
                    src_port: flow.src_port,
                    dst_port: flow.dst_port,
                    icmp_type: Some(icmp_type),
                    icmp_code: Some(icmp_code),
                };
                let evaluation = match state.policy.read() {
                    Ok(lock) => evaluate_policy_outcome(&lock, &meta, None, &state.tls_verifier),
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
                    maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, None, now);
                }
                match evaluation.effective {
                    PolicyDecision::Allow => {
                        entry.policy_generation = current_generation;
                        entry.set_source_group_owned(next_group);
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
                (flow_decision_label(entry), entry.source_group().to_string())
            } else {
                ("deny", entry.source_group().to_string())
            }
        };

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now, "policy_drop");
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
    state.flows.prefetch_key(&flow);
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
            let meta = PacketMeta {
                src_ip: flow.src_ip,
                dst_ip: flow.dst_ip,
                proto: flow.proto,
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                icmp_type: Some(icmp_type),
                icmp_code: Some(icmp_code),
            };
            let evaluation = match state.policy.read() {
                Ok(lock) => evaluate_policy_outcome(&lock, &meta, None, &state.tls_verifier),
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
                maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, None, now);
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.set_source_group_owned(next_group);
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
            (flow_decision_label(entry), entry.source_group().to_string())
        } else {
            ("deny", entry.source_group().to_string())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now, "policy_drop");
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

pub(super) fn handle_inbound_icmp(
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
    let audit = state.audit.clone();
    let current_generation = state.current_policy_generation();

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
        state.nat.prefetch_reverse_key(&reverse_key);
        let Some(flow) = state.nat.reverse_lookup(&reverse_key) else {
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet("inbound", proto_label(1), "deny", "default", pkt.len());
                metrics
                    .observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", "default");
            }
            return Action::Drop;
        };

        state.nat.touch(&flow, now);
        state.flows.prefetch_key(&flow);
        let wiretap = state.wiretap.clone();
        let mut policy_drop_group: Option<String> = None;
        let (decision_label, entry_source_group) = {
            let entry = match state.flows.get_entry_mut(&flow) {
                Some(entry) => entry,
                None => return Action::Drop,
            };
            if entry.policy_generation != current_generation {
                let meta = PacketMeta {
                    src_ip: flow.src_ip,
                    dst_ip: flow.dst_ip,
                    proto: flow.proto,
                    src_port: flow.src_port,
                    dst_port: flow.dst_port,
                    icmp_type: Some(icmp_type),
                    icmp_code: Some(icmp_code),
                };
                let evaluation = match state.policy.read() {
                    Ok(lock) => evaluate_policy_outcome(&lock, &meta, None, &state.tls_verifier),
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
                    maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, None, now);
                }
                match evaluation.effective {
                    PolicyDecision::Allow => {
                        entry.policy_generation = current_generation;
                        entry.set_source_group_owned(next_group);
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
                (flow_decision_label(entry), entry.source_group().to_string())
            } else {
                ("deny", entry.source_group().to_string())
            }
        };

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now, "policy_drop");
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
    state.nat.prefetch_reverse_key(&reverse_key);
    let Some(flow) = state.nat.reverse_lookup(&reverse_key) else {
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet("inbound", proto_label(1), "deny", "default", pkt.len());
            metrics.observe_dp_icmp_decision("inbound", icmp_type, icmp_code, "deny", "default");
        }
        return Action::Drop;
    };

    state.nat.touch(&flow, now);
    state.flows.prefetch_key(&flow);
    let wiretap = state.wiretap.clone();
    let mut policy_drop_group: Option<String> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let meta = PacketMeta {
                src_ip: flow.src_ip,
                dst_ip: flow.dst_ip,
                proto: flow.proto,
                src_port: flow.src_port,
                dst_port: flow.dst_port,
                icmp_type: Some(icmp_type),
                icmp_code: Some(icmp_code),
            };
            let evaluation = match state.policy.read() {
                Ok(lock) => evaluate_policy_outcome(&lock, &meta, None, &state.tls_verifier),
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
                maybe_emit_policy_deny_audit(audit.as_ref(), &meta, &next_group, None, now);
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.set_source_group_owned(next_group);
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
            (flow_decision_label(entry), entry.source_group().to_string())
        } else {
            ("deny", entry.source_group().to_string())
        }
    };

    if let Some(drop_group) = policy_drop_group {
        remove_flow_state(state, &flow, now, "policy_drop");
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
    Action::Forward {
        out_port: state.data_port,
    }
}
