use neuwerk::controlplane::audit::{
    AuditEvent as ControlplaneAuditEvent, AuditFindingType, AuditStore,
};
use neuwerk::controlplane::policy_telemetry::PolicyTelemetryStore;
use neuwerk::controlplane::threat_intel::runtime::{ThreatObservation, ThreatRuntimeSlot};
use neuwerk::controlplane::wiretap::{DnsMap, WiretapHub};
use neuwerk::controlplane::PolicyStore;
use neuwerk::dataplane::{
    AuditEvent, AuditEventType, PolicyTelemetryEvent, WiretapEvent as DataplaneWiretapEvent,
};
use tokio::sync::mpsc;
use tracing::warn;

pub fn spawn_event_bridges(
    mut wiretap_rx: mpsc::Receiver<DataplaneWiretapEvent>,
    mut audit_rx: mpsc::Receiver<AuditEvent>,
    mut policy_telemetry_rx: mpsc::Receiver<PolicyTelemetryEvent>,
    wiretap_hub: WiretapHub,
    dns_map: DnsMap,
    audit_store: AuditStore,
    policy_telemetry_store: PolicyTelemetryStore,
    policy_store: PolicyStore,
    threat_runtime: Option<ThreatRuntimeSlot>,
    node_id: String,
) -> Result<(), String> {
    let hub_for_wiretap = wiretap_hub.clone();
    let dns_map_for_wiretap = dns_map.clone();
    let dns_map_for_audit = dns_map;
    let audit_store_for_events = audit_store;
    let policy_telemetry_store_for_audit = policy_telemetry_store.clone();
    let policy_telemetry_store_for_allowed = policy_telemetry_store;
    let policy_store_for_audit = policy_store;
    let policy_store_for_allowed = policy_store_for_audit.clone();
    let threat_runtime_for_audit = threat_runtime;
    let node_id_for_wiretap = node_id.clone();
    let node_id_for_audit = node_id;

    std::thread::Builder::new()
        .name("wiretap-bridge".to_string())
        .spawn(move || {
            while let Some(event) = wiretap_rx.blocking_recv() {
                let hostname = dns_map_for_wiretap.lookup(event.dst_ip);
                let enriched = neuwerk::controlplane::wiretap::WiretapEvent::from_dataplane(
                    event,
                    hostname,
                    &node_id_for_wiretap,
                );
                hub_for_wiretap.publish(enriched);
            }
            warn!("wiretap bridge stopped because all senders dropped");
        })
        .map_err(|err| format!("wiretap bridge thread failed to start: {err}"))?;

    std::thread::Builder::new()
        .name("audit-bridge".to_string())
        .spawn(move || {
            while let Some(event) = audit_rx.blocking_recv() {
                let fqdn = dns_map_for_audit.lookup(event.dst_ip);
                let policy_id = policy_store_for_audit.active_policy_id();
                let finding_type = match event.event_type {
                    AuditEventType::L4Deny => AuditFindingType::L4Deny,
                    AuditEventType::TlsDeny => AuditFindingType::TlsDeny,
                    AuditEventType::IcmpDeny => AuditFindingType::IcmpDeny,
                };
                let enriched = ControlplaneAuditEvent {
                    finding_type,
                    source_group: event.source_group.clone(),
                    hostname: None,
                    dst_ip: Some(event.dst_ip),
                    dst_port: Some(event.dst_port),
                    proto: Some(event.proto),
                    fqdn: fqdn.clone(),
                    sni: event.sni.clone(),
                    icmp_type: event.icmp_type,
                    icmp_code: event.icmp_code,
                    query_type: None,
                    observed_at: event.observed_at,
                };
                audit_store_for_events.ingest(enriched, policy_id, &node_id_for_audit);
                record_policy_hit(
                    &policy_telemetry_store_for_audit,
                    policy_id,
                    &event.source_group,
                    event.observed_at,
                );
                if let Some(threat_runtime) = threat_runtime_for_audit.as_ref() {
                    for observation in ThreatObservation::from_audit_event(
                        &event,
                        fqdn,
                        &node_id_for_audit,
                        policy_id,
                    ) {
                        let _ = threat_runtime.try_observe(observation);
                    }
                }
            }
            warn!("audit bridge stopped because all senders dropped");
        })
        .map_err(|err| format!("audit bridge thread failed to start: {err}"))?;

    std::thread::Builder::new()
        .name("policy-telemetry-bridge".to_string())
        .spawn(move || {
            while let Some(event) = policy_telemetry_rx.blocking_recv() {
                let policy_id = policy_store_for_allowed.active_policy_id();
                record_policy_hit(
                    &policy_telemetry_store_for_allowed,
                    policy_id,
                    &event.source_group,
                    event.observed_at,
                );
            }
            warn!("policy telemetry bridge stopped because all senders dropped");
        })
        .map_err(|err| format!("policy telemetry bridge thread failed to start: {err}"))?;

    Ok(())
}

fn record_policy_hit(
    store: &PolicyTelemetryStore,
    policy_id: Option<uuid::Uuid>,
    source_group: &str,
    observed_at: u64,
) {
    let Some(policy_id) = policy_id else {
        return;
    };
    store.record_hit(policy_id, source_group, observed_at);
}

#[cfg(test)]
mod tests {
    use super::*;
    use neuwerk::controlplane::policy_telemetry::PolicyTelemetryStore;
    use neuwerk::dataplane::{PolicyTelemetryEvent, WiretapEventType};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn wait_for_hits(store: &PolicyTelemetryStore, policy_id: Uuid, now: u64, expected: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let summaries = store.policy_24h_summary(policy_id, now).expect("summary");
            let hits = summaries
                .iter()
                .find(|summary| summary.source_group_id == "apps")
                .map(|summary| summary.current_24h_hits)
                .unwrap_or(0);
            if hits == expected {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {expected} hits, got {hits}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn spawn_event_bridges_records_deny_hits_in_policy_telemetry_store() {
        let dir = TempDir::new().expect("tempdir");
        let audit_store = AuditStore::new(dir.path().join("audit"), 1024 * 1024);
        let telemetry_store = PolicyTelemetryStore::new(dir.path().join("telemetry"));
        let policy_store = PolicyStore::new(
            neuwerk::dataplane::policy::DefaultPolicy::Deny,
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        );
        let policy_id = Uuid::new_v4();
        let observed_at = 1_744_086_400u64;
        policy_store.set_active_policy_id(Some(policy_id));

        let (wiretap_tx, wiretap_rx) = mpsc::channel(4);
        let (audit_tx, audit_rx) = mpsc::channel(4);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(4);
        spawn_event_bridges(
            wiretap_rx,
            audit_rx,
            telemetry_rx,
            WiretapHub::new(16),
            DnsMap::new(),
            audit_store,
            telemetry_store.clone(),
            policy_store,
            None,
            "node-a".to_string(),
        )
        .expect("spawn bridges");

        audit_tx
            .try_send(AuditEvent {
                event_type: AuditEventType::L4Deny,
                src_ip: std::net::Ipv4Addr::new(192, 0, 2, 10),
                dst_ip: std::net::Ipv4Addr::new(203, 0, 113, 7),
                src_port: 12345,
                dst_port: 443,
                proto: 6,
                source_group: "apps".to_string(),
                sni: None,
                icmp_type: None,
                icmp_code: None,
                observed_at,
            })
            .expect("send audit event");
        drop(audit_tx);
        drop(telemetry_tx);
        drop(wiretap_tx);

        wait_for_hits(&telemetry_store, policy_id, observed_at, 1);
    }

    #[test]
    fn spawn_event_bridges_records_allowed_flow_hits_in_policy_telemetry_store() {
        let dir = TempDir::new().expect("tempdir");
        let audit_store = AuditStore::new(dir.path().join("audit"), 1024 * 1024);
        let telemetry_store = PolicyTelemetryStore::new(dir.path().join("telemetry"));
        let policy_store = PolicyStore::new(
            neuwerk::dataplane::policy::DefaultPolicy::Deny,
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        );
        let policy_id = Uuid::new_v4();
        let observed_at = 1_744_086_400u64;
        policy_store.set_active_policy_id(Some(policy_id));

        let (wiretap_tx, wiretap_rx) = mpsc::channel(4);
        let (audit_tx, audit_rx) = mpsc::channel(4);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(4);
        spawn_event_bridges(
            wiretap_rx,
            audit_rx,
            telemetry_rx,
            WiretapHub::new(16),
            DnsMap::new(),
            audit_store,
            telemetry_store.clone(),
            policy_store,
            None,
            "node-a".to_string(),
        )
        .expect("spawn bridges");

        telemetry_tx
            .try_send(PolicyTelemetryEvent {
                source_group: "apps".to_string(),
                observed_at,
            })
            .expect("send telemetry event");
        drop(telemetry_tx);
        drop(audit_tx);
        wiretap_tx
            .try_send(DataplaneWiretapEvent {
                event_type: WiretapEventType::Flow,
                flow_id: "ignored".to_string(),
                src_ip: std::net::Ipv4Addr::new(192, 0, 2, 10),
                dst_ip: std::net::Ipv4Addr::new(203, 0, 113, 7),
                src_port: 12345,
                dst_port: 443,
                proto: 6,
                packets_in: 1,
                packets_out: 1,
                last_seen: observed_at,
            })
            .expect("send wiretap event");
        drop(wiretap_tx);

        wait_for_hits(&telemetry_store, policy_id, observed_at, 1);
    }
}
