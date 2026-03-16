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
        let flow = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        };
        state.flows.prefetch_key(&flow);
        let flow_probe = state.flows.probe(&flow);
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
        let mut source_group: Option<Arc<str>> = None;
        let current_generation;
        let audit = state.audit.clone();
        if !flow_probe.is_hit() {
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
            let source_group_label = source_group_label(source_group.as_ref());
            if evaluation.raw == PolicyDecision::Deny || evaluation.audit_rule_denied {
                maybe_emit_policy_deny_audit(
                    audit.as_ref(),
                    &meta,
                    source_group_label,
                    None,
                    now,
                );
            }
            match evaluation.effective {
                PolicyDecision::Allow => {
                    if evaluation.intercept_requires_service
                        && !state.service_policy_ready_for_generation(current_generation)
                    {
                        if let Some(action) =
                            maybe_intercept_fail_closed_rst(
                                pkt,
                                state,
                                source_group_label,
                                "outbound",
                            )
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
                    is_new = true;
                    let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                    entry.policy_generation = current_generation;
                    entry.intercept_requires_service = evaluation.intercept_requires_service;
                    pending_entry = Some(entry);
                }
                PolicyDecision::Deny => {
                    if evaluation.intercept_requires_service {
                        if let Some(action) =
                            maybe_intercept_fail_closed_rst(
                                pkt,
                                state,
                                source_group_label,
                                "outbound",
                            )
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
                    is_new = true;
                    let mut entry = FlowEntry::with_source_group_arc(now, source_group.clone());
                    entry.policy_generation = current_generation;
                    entry.intercept_requires_service = false;
                    entry.tls = Some(TlsFlowState::new());
                    pending_entry = Some(entry);
                    if let Some(metrics) = &state.metrics {
                        metrics.inc_dp_tls_decision("pending");
                    }
                }
            }
        } else {
            current_generation = state.current_policy_generation();
        }

        if is_new {
            state.note_flow_open(flow, proto, source_group_label(source_group.as_ref()), now);
        }

        let policy = &state.policy;
        let verifier = &state.tls_verifier;
        let wiretap = state.wiretap.clone();
        let metrics = state.metrics.clone();
        let service_policy_applied_generation = state.service_policy_applied_generation.clone();
        let mut service_ready_for_current_generation = None;
        let mut policy_drop_group: Option<Arc<str>> = None;
        let mut policy_drop_intercept_requires_service = false;
        let need_entry_source_group = metrics.is_some();
        let (decision_label, entry_source_group, flow_intercept_requires_service) = {
            let entry = match pending_entry.take() {
                Some(entry) => state.flows.insert_with_probe_and_get_mut(flow, entry, flow_probe),
                None => match state.flows.get_entry_mut_with_probe(&flow, flow_probe) {
                    Some(entry) => entry,
                    None => return Action::Drop,
                },
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
                        if evaluation.intercept_requires_service
                            && !service_ready
                        {
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
                        policy_drop_group = next_group;
                        policy_drop_intercept_requires_service =
                            evaluation.intercept_requires_service;
                        entry.intercept_requires_service = false;
                    }
                }
            }
            if policy_drop_group.is_none() {
                entry.last_seen = now;
                entry.packets_out = entry.packets_out.saturating_add(1);
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

        if let Some(drop_group) = policy_drop_group {
            remove_flow_state(state, &flow, now, "policy_drop");
            if policy_drop_intercept_requires_service {
                if let Some(action) =
                    maybe_intercept_fail_closed_rst(
                        pkt,
                        state,
                        source_group_label(Some(&drop_group)),
                        "outbound",
                    )
                {
                    return action;
                }
            }
            if let Some(metrics) = &metrics {
                metrics.observe_dp_packet(
                    "outbound",
                    proto_label(proto),
                    "deny",
                    source_group_label(Some(&drop_group)),
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

    if snat_disabled && !src_internal && dst_internal {
        return handle_inbound_no_snat(pkt, state, src_ip, dst_ip, src_port, dst_port, proto, now);
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
            let mut policy_drop_group: Option<Arc<str>> = None;
            let need_entry_source_group = metrics.is_some();
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
                            policy_drop_group = next_group;
                        }
                    }
                }
                if policy_drop_group.is_none() {
                    entry.last_seen = now;
                    entry.packets_in = entry.packets_in.saturating_add(1);
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

            if let Some(drop_group) = policy_drop_group {
                remove_flow_state(state, &flow, now, "policy_drop");
                if let Some(metrics) = &metrics {
                    metrics.observe_dp_packet(
                        "inbound",
                        proto_label(proto),
                        "deny",
                        source_group_label(Some(&drop_group)),
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
