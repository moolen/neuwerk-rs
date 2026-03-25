pub(super) fn handle_outbound_icmp(
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
        state.nat.prefetch_flow_key(&flow);
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
        let audit = state.audit.clone();
        let exact_source_policy_index = &state.exact_source_policy_index;
        let evaluation = match state.policy.read() {
            Ok(lock) => evaluate_policy_outcome(
                exact_source_policy_index,
                &lock,
                &meta,
                None,
                &state.tls_verifier,
                state.audit.is_some(),
            ),
            Err(_) => deny_policy_eval_outcome(),
        };
        let source_group = source_group_label(evaluation.source_group.as_ref());
        if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
            maybe_emit_policy_deny_audit(audit.as_ref(), &meta, source_group, None, now);
        }
        match evaluation.effective {
            PolicyDecision::Allow => {}
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        source_group,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        source_group,
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
            metrics.observe_dp_packet("outbound", proto_label(1), "allow", source_group, pkt.len());
            metrics.observe_dp_icmp_decision(
                "outbound",
                icmp_type,
                icmp_code,
                "allow",
                source_group,
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
    state.flows.prefetch_key(&flow);
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
    let mut source_group: Option<Arc<str>> = None;
    let mut current_generation = state.current_policy_generation();
    let audit = state.audit.clone();
    if state.flows.get_entry(&flow).is_none() {
        let exact_source_policy_index = &state.exact_source_policy_index;
        let (evaluation, generation) = match state.policy.read() {
            Ok(lock) => (
                evaluate_policy_outcome(
                    exact_source_policy_index,
                    &lock,
                    &meta,
                    None,
                    &state.tls_verifier,
                    state.audit.is_some(),
                ),
                lock.generation(),
            ),
            Err(_) => (deny_policy_eval_outcome(), 0),
        };
        current_generation = generation;
        source_group = evaluation.source_group.clone();
        let source_group_name = source_group_label(source_group.as_ref());
        if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
            maybe_emit_policy_deny_audit(audit.as_ref(), &meta, source_group_name, None, now);
        }
        match evaluation.effective {
            PolicyDecision::Allow => {
                if let Some(rejection) =
                    state.admission_rejection(source_group.as_ref(), true, false, true)
                {
                    state.note_admission_rejection(rejection);
                    if let Some(metrics) = &state.metrics {
                        metrics.observe_dp_packet(
                            "outbound",
                            proto_label(1),
                            "deny",
                            source_group_name,
                            pkt.len(),
                        );
                        metrics.observe_dp_icmp_decision(
                            "outbound",
                            icmp_type,
                            icmp_code,
                            "deny",
                            source_group_name,
                        );
                    }
                    return Action::Drop;
                }
                is_new = true;
                let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                entry.policy_generation = current_generation;
                state.flows.insert(flow, entry);
            }
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        source_group_name,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        source_group_name,
                    );
                }
                return Action::Drop;
            }
        }
    }

    if is_new {
        state.record_new_flow_state(
            flow,
            1,
            source_group.as_ref(),
            "outbound_new",
            now,
            false,
        );
    }

    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let mut policy_drop = false;
    let mut policy_drop_group: Option<Arc<str>> = None;
    let mut source_group_membership = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        let source_group_before = entry.source_group_arc();
        if entry.policy_generation != current_generation {
            let exact_source_policy_index = &state.exact_source_policy_index;
            let evaluation = match state.policy.read() {
                Ok(lock) => evaluate_policy_outcome(
                    exact_source_policy_index,
                    &lock,
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    &state.tls_verifier,
                    state.audit.is_some(),
                ),
                Err(_) => deny_policy_eval_outcome(),
            };
            let next_group = evaluation.source_group.clone();
            if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                maybe_emit_policy_deny_audit(
                    audit.as_ref(),
                    &meta,
                    source_group_label(next_group.as_ref()),
                    None,
                    now,
                );
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.set_source_group_arc(next_group);
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop = true;
                    policy_drop_group = next_group;
                }
            }
        }
        if !policy_drop {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            source_group_membership = Some((source_group_before, entry.source_group_arc()));
            (flow_decision_label(entry), entry.source_group_arc())
        } else {
            ("deny", entry.source_group_arc())
        }
    };
    if let Some((previous, next)) = source_group_membership {
        state.reconcile_source_group_membership(previous, next);
    }
    let entry_source_group_name = source_group_label(entry_source_group.as_ref());

    if policy_drop {
        remove_flow_state(state, &flow, now, "policy_drop");
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(1),
                "deny",
                source_group_label(policy_drop_group.as_ref()),
                pkt.len(),
            );
            metrics.observe_dp_icmp_decision(
                "outbound",
                icmp_type,
                icmp_code,
                "deny",
                source_group_label(policy_drop_group.as_ref()),
            );
        }
        return Action::Drop;
    }

    if let Some(action) = handle_ttl(pkt, state) {
        return action;
    }

    state.nat.prefetch_flow_key(&flow);
    if state.nat.get_entry(&flow).is_none() {
        if let Some(rejection) =
            state.admission_rejection(entry_source_group.as_ref(), false, false, true)
        {
            state.note_admission_rejection(rejection);
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(1),
                    "deny",
                    entry_source_group_name,
                    pkt.len(),
                );
                metrics.observe_dp_icmp_decision(
                    "outbound",
                    icmp_type,
                    icmp_code,
                    "deny",
                    entry_source_group_name,
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
            entry_source_group_name,
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "outbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group_name,
        );
    }
    if nat_created {
        state.update_nat_metrics();
    }
    Action::Forward {
        out_port: state.data_port,
    }
}

pub(super) fn handle_outbound_icmp_no_snat(
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
    state.flows.prefetch_key(&flow);
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
    let mut source_group: Option<Arc<str>> = None;
    let mut current_generation = state.current_policy_generation();
    let audit = state.audit.clone();
    if state.flows.get_entry(&flow).is_none() {
        let exact_source_policy_index = &state.exact_source_policy_index;
        let (evaluation, generation) = match state.policy.read() {
            Ok(lock) => (
                evaluate_policy_outcome(
                    exact_source_policy_index,
                    &lock,
                    &meta,
                    None,
                    &state.tls_verifier,
                    state.audit.is_some(),
                ),
                lock.generation(),
            ),
            Err(_) => (deny_policy_eval_outcome(), 0),
        };
        current_generation = generation;
        source_group = evaluation.source_group.clone();
        let source_group_name = source_group_label(source_group.as_ref());
        if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
            maybe_emit_policy_deny_audit(audit.as_ref(), &meta, source_group_name, None, now);
        }
        match evaluation.effective {
            PolicyDecision::Allow => {
                is_new = true;
                let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                entry.policy_generation = current_generation;
                state.flows.insert(flow, entry);
            }
            PolicyDecision::Deny | PolicyDecision::PendingTls => {
                if let Some(metrics) = &state.metrics {
                    metrics.observe_dp_packet(
                        "outbound",
                        proto_label(1),
                        "deny",
                        source_group_name,
                        pkt.len(),
                    );
                    metrics.observe_dp_icmp_decision(
                        "outbound",
                        icmp_type,
                        icmp_code,
                        "deny",
                        source_group_name,
                    );
                }
                return Action::Drop;
            }
        }
    }

    if is_new {
        state.note_flow_open_with_reason(
            flow,
            1,
            source_group_label(source_group.as_ref()),
            "outbound_new",
            now,
        );
    }

    let wiretap = state.wiretap.clone();
    let metrics = state.metrics.clone();
    let mut policy_drop = false;
    let mut policy_drop_group: Option<Arc<str>> = None;
    let (decision_label, entry_source_group) = {
        let entry = match state.flows.get_entry_mut(&flow) {
            Some(entry) => entry,
            None => return Action::Drop,
        };
        if entry.policy_generation != current_generation {
            let exact_source_policy_index = &state.exact_source_policy_index;
            let evaluation = match state.policy.read() {
                Ok(lock) => evaluate_policy_outcome(
                    exact_source_policy_index,
                    &lock,
                    &meta,
                    entry.tls.as_ref().map(|tls| &tls.observation),
                    &state.tls_verifier,
                    state.audit.is_some(),
                ),
                Err(_) => deny_policy_eval_outcome(),
            };
            let next_group = evaluation.source_group.clone();
            if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                maybe_emit_policy_deny_audit(
                    audit.as_ref(),
                    &meta,
                    source_group_label(next_group.as_ref()),
                    None,
                    now,
                );
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    entry.policy_generation = current_generation;
                    entry.set_source_group_arc(next_group);
                }
                PolicyDecision::Deny | PolicyDecision::PendingTls => {
                    policy_drop = true;
                    policy_drop_group = next_group;
                }
            }
        }
        if !policy_drop {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            maybe_emit_wiretap(&wiretap, &flow, entry, now);
            (flow_decision_label(entry), entry.source_group_arc())
        } else {
            ("deny", entry.source_group_arc())
        }
    };
    let entry_source_group_name = source_group_label(entry_source_group.as_ref());

    if policy_drop {
        remove_flow_state(state, &flow, now, "policy_drop");
        if let Some(metrics) = &metrics {
            metrics.observe_dp_packet(
                "outbound",
                proto_label(1),
                "deny",
                source_group_label(policy_drop_group.as_ref()),
                pkt.len(),
            );
            metrics.observe_dp_icmp_decision(
                "outbound",
                icmp_type,
                icmp_code,
                "deny",
                source_group_label(policy_drop_group.as_ref()),
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
            proto_label(1),
            decision_label,
            entry_source_group_name,
            pkt.len(),
        );
        metrics.observe_dp_icmp_decision(
            "outbound",
            icmp_type,
            icmp_code,
            decision_label,
            entry_source_group_name,
        );
    }
    Action::Forward {
        out_port: state.data_port,
    }
}
