use super::*;

pub(super) fn resolve_snat_ip(state: &EngineState) -> Option<Ipv4Addr> {
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

pub(super) fn maybe_emit_wiretap(
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

#[allow(clippy::too_many_arguments)]
pub(super) fn process_tls_packet(
    pkt: &Packet,
    direction: TlsDirection,
    tls_state: &mut TlsFlowState,
    meta: &PacketMeta,
    policy: &Arc<RwLock<PolicySnapshot>>,
    verifier: &TlsVerifier,
    audit: Option<&AuditEmitter>,
    source_group: &str,
    now: u64,
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
            maybe_emit_tls_policy_deny_audit(
                audit,
                meta,
                source_group,
                tls_state.observation.sni.clone(),
                now,
            );
            if let Some(metrics) = metrics {
                metrics.inc_dp_tls_decision("deny");
            }
            return false;
        }
    };

    if tls_state.decision == TlsFlowDecision::Pending {
        let (decision, raw_denied) = match policy.read() {
            Ok(lock) => {
                let (effective, _, _) = lock.evaluate_with_source_group_detailed(
                    meta,
                    Some(&tls_state.observation),
                    Some(verifier),
                );
                let (raw, _, _) = lock.evaluate_with_source_group_detailed_raw(
                    meta,
                    Some(&tls_state.observation),
                    Some(verifier),
                );
                (effective, raw == PolicyDecision::Deny)
            }
            Err(_) => (PolicyDecision::Deny, true),
        };
        if raw_denied {
            maybe_emit_tls_policy_deny_audit(
                audit,
                meta,
                source_group,
                tls_state.observation.sni.clone(),
                now,
            );
        }
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
        maybe_emit_tls_policy_deny_audit(
            audit,
            meta,
            source_group,
            tls_state.observation.sni.clone(),
            now,
        );
        if let Some(metrics) = metrics {
            metrics.inc_dp_tls_decision("deny_after_data");
        }
    }

    tls_state.decision != TlsFlowDecision::Denied
}

pub(super) fn proto_label(proto: u8) -> &'static str {
    match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    }
}

pub(super) fn maybe_emit_policy_deny_audit(
    emitter: Option<&AuditEmitter>,
    meta: &PacketMeta,
    source_group: &str,
    sni: Option<String>,
    now: u64,
) {
    let Some(emitter) = emitter else {
        return;
    };
    let event_type = if meta.proto == 1 {
        AuditEventType::IcmpDeny
    } else if sni.is_some() {
        AuditEventType::TlsDeny
    } else {
        AuditEventType::L4Deny
    };
    emitter.try_send(DataplaneAuditEvent {
        event_type,
        src_ip: meta.src_ip,
        dst_ip: meta.dst_ip,
        src_port: meta.src_port,
        dst_port: meta.dst_port,
        proto: meta.proto,
        source_group: source_group.to_string(),
        sni,
        icmp_type: meta.icmp_type,
        icmp_code: meta.icmp_code,
        observed_at: now,
    });
}

pub(super) fn maybe_emit_tls_policy_deny_audit(
    emitter: Option<&AuditEmitter>,
    meta: &PacketMeta,
    source_group: &str,
    sni: Option<String>,
    now: u64,
) {
    let Some(emitter) = emitter else {
        return;
    };
    emitter.try_send(DataplaneAuditEvent {
        event_type: AuditEventType::TlsDeny,
        src_ip: meta.src_ip,
        dst_ip: meta.dst_ip,
        src_port: meta.src_port,
        dst_port: meta.dst_port,
        proto: meta.proto,
        source_group: source_group.to_string(),
        sni,
        icmp_type: meta.icmp_type,
        icmp_code: meta.icmp_code,
        observed_at: now,
    });
}

pub(super) fn flow_decision_label(entry: &FlowEntry) -> &'static str {
    match entry.tls.as_ref().map(|tls| tls.decision) {
        Some(TlsFlowDecision::Pending) => "pending_tls",
        Some(TlsFlowDecision::Allowed) => "allow",
        Some(TlsFlowDecision::Denied) => "deny",
        None => "allow",
    }
}

pub(super) fn maybe_intercept_fail_closed_rst(
    pkt: &mut Packet,
    state: &EngineState,
    source_group: &str,
    direction: &str,
) -> Option<Action> {
    if pkt.protocol() != Some(6) {
        return None;
    }
    if !pkt.rewrite_as_tcp_rst_reply() {
        return None;
    }
    if let Some(metrics) = &state.metrics {
        metrics.observe_dp_packet(direction, "tcp", "deny", source_group, pkt.len());
    }
    Some(Action::Forward {
        out_port: state.data_port,
    })
}

pub(super) fn remove_flow_state(
    state: &mut EngineState,
    flow: &FlowKey,
    now: u64,
    reason: &str,
) -> Option<FlowEntry> {
    let entry = state.flows.remove(flow);
    if entry.is_some() {
        if let Some(allowlist) = &state.dns_allowlist {
            allowlist.flow_close(flow.dst_ip, now);
        }
        if let Some(entry_ref) = entry.as_ref() {
            state.observe_entry_flow_close(entry_ref, reason, now);
        }
    }
    state.nat.remove(flow);
    state.update_flow_metrics();
    state.update_nat_metrics();
    entry
}

pub(super) fn handle_ttl(pkt: &mut Packet, state: &EngineState) -> Option<Action> {
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
