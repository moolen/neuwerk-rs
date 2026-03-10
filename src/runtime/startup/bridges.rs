use firewall::controlplane::audit::{
    AuditEvent as ControlplaneAuditEvent, AuditFindingType, AuditStore,
};
use firewall::controlplane::wiretap::{DnsMap, WiretapHub};
use firewall::controlplane::PolicyStore;
use firewall::dataplane::{AuditEvent, AuditEventType, WiretapEvent as DataplaneWiretapEvent};
use tokio::sync::mpsc;

pub fn spawn_event_bridges(
    mut wiretap_rx: mpsc::Receiver<DataplaneWiretapEvent>,
    mut audit_rx: mpsc::Receiver<AuditEvent>,
    wiretap_hub: WiretapHub,
    dns_map: DnsMap,
    audit_store: AuditStore,
    policy_store: PolicyStore,
    node_id: String,
) -> Result<(), String> {
    let hub_for_wiretap = wiretap_hub.clone();
    let dns_map_for_wiretap = dns_map.clone();
    let dns_map_for_audit = dns_map;
    let audit_store_for_events = audit_store;
    let policy_store_for_audit = policy_store;
    let node_id_for_wiretap = node_id.clone();
    let node_id_for_audit = node_id;

    std::thread::Builder::new()
        .name("wiretap-bridge".to_string())
        .spawn(move || {
            while let Some(event) = wiretap_rx.blocking_recv() {
                let hostname = dns_map_for_wiretap.lookup(event.dst_ip);
                let enriched = firewall::controlplane::wiretap::WiretapEvent::from_dataplane(
                    event,
                    hostname,
                    &node_id_for_wiretap,
                );
                hub_for_wiretap.publish(enriched);
            }
            tracing::warn!("wiretap bridge stopped because all senders dropped");
        })
        .map_err(|err| format!("wiretap bridge thread failed to start: {err}"))?;

    std::thread::Builder::new()
        .name("audit-bridge".to_string())
        .spawn(move || {
            while let Some(event) = audit_rx.blocking_recv() {
                let fqdn = dns_map_for_audit.lookup(event.dst_ip);
                let finding_type = match event.event_type {
                    AuditEventType::L4Deny => AuditFindingType::L4Deny,
                    AuditEventType::TlsDeny => AuditFindingType::TlsDeny,
                    AuditEventType::IcmpDeny => AuditFindingType::IcmpDeny,
                };
                let enriched = ControlplaneAuditEvent {
                    finding_type,
                    source_group: event.source_group,
                    hostname: None,
                    dst_ip: Some(event.dst_ip),
                    dst_port: Some(event.dst_port),
                    proto: Some(event.proto),
                    fqdn,
                    sni: event.sni,
                    icmp_type: event.icmp_type,
                    icmp_code: event.icmp_code,
                    query_type: None,
                    observed_at: event.observed_at,
                };
                audit_store_for_events.ingest(
                    enriched,
                    policy_store_for_audit.active_policy_id(),
                    &node_id_for_audit,
                );
            }
            tracing::warn!("audit bridge stopped because all senders dropped");
        })
        .map_err(|err| format!("audit bridge thread failed to start: {err}"))?;

    Ok(())
}
