use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

use crate::controlplane::audit::finding_key_for_dataplane_event;
use crate::controlplane::metrics::Metrics;
use crate::dataplane::{AuditEvent, AuditEventType};

use super::feeds::{ThreatIndicatorSnapshotItem, ThreatSnapshot};
use super::matcher::{ThreatMatch, ThreatMatcher};
use super::store::{
    ThreatEnrichmentStatus, ThreatFeedHit, ThreatFinding, ThreatMatchSource, ThreatStore,
};
use super::types::{ThreatIndicatorType, ThreatObservationLayer, ThreatSeverity};

static THREAT_OBSERVATION_DROPS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub struct ThreatRuntimeConfig {
    pub snapshot: ThreatSnapshot,
    pub store: ThreatStore,
    pub metrics: Metrics,
    pub queue_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatObservation {
    pub indicator: String,
    pub indicator_type: ThreatIndicatorType,
    pub observation_layer: ThreatObservationLayer,
    pub source_group: String,
    pub node_id: String,
    pub observed_at: u64,
    pub dst_ip: Option<Ipv4Addr>,
    pub audit_finding_key: Option<String>,
}

impl ThreatObservation {
    pub fn dns(
        hostname: &str,
        source_group: &str,
        node_id: &str,
        observed_at: u64,
    ) -> Option<Self> {
        Self::dns_with_audit_link(hostname, source_group, node_id, observed_at, None)
    }

    pub fn dns_with_audit_link(
        hostname: &str,
        source_group: &str,
        node_id: &str,
        observed_at: u64,
        audit_finding_key: Option<String>,
    ) -> Option<Self> {
        let indicator = normalize_hostname(hostname);
        if indicator.is_empty() {
            return None;
        }
        Some(Self {
            indicator,
            indicator_type: ThreatIndicatorType::Hostname,
            observation_layer: ThreatObservationLayer::Dns,
            source_group: source_group.trim().to_string(),
            node_id: node_id.to_string(),
            observed_at,
            dst_ip: None,
            audit_finding_key,
        })
    }

    pub fn from_audit_event(
        event: &AuditEvent,
        fqdn: Option<String>,
        node_id: &str,
        policy_id: Option<Uuid>,
    ) -> Vec<Self> {
        let mut observations = Vec::new();
        let source_group = event.source_group.trim().to_string();
        let node_id = node_id.to_string();
        let audit_finding_key = finding_key_for_dataplane_event(event, policy_id, fqdn.as_deref());

        match event.event_type {
            AuditEventType::L4Deny | AuditEventType::IcmpDeny => {
                observations.push(Self {
                    indicator: event.dst_ip.to_string(),
                    indicator_type: ThreatIndicatorType::Ip,
                    observation_layer: ThreatObservationLayer::L4,
                    source_group: source_group.clone(),
                    node_id: node_id.clone(),
                    observed_at: event.observed_at,
                    dst_ip: Some(event.dst_ip),
                    audit_finding_key: Some(audit_finding_key.clone()),
                });
                if let Some(hostname) = fqdn.as_deref().map(normalize_hostname) {
                    if !hostname.is_empty() {
                        observations.push(Self {
                            indicator: hostname,
                            indicator_type: ThreatIndicatorType::Hostname,
                            observation_layer: ThreatObservationLayer::L4,
                            source_group,
                            node_id,
                            observed_at: event.observed_at,
                            dst_ip: Some(event.dst_ip),
                            audit_finding_key: Some(audit_finding_key),
                        });
                    }
                }
            }
            AuditEventType::TlsDeny => {
                observations.push(Self {
                    indicator: event.dst_ip.to_string(),
                    indicator_type: ThreatIndicatorType::Ip,
                    observation_layer: ThreatObservationLayer::Tls,
                    source_group: source_group.clone(),
                    node_id: node_id.clone(),
                    observed_at: event.observed_at,
                    dst_ip: Some(event.dst_ip),
                    audit_finding_key: Some(audit_finding_key.clone()),
                });
                if let Some(hostname) = event.sni.as_deref().map(normalize_hostname) {
                    if !hostname.is_empty() {
                        observations.push(Self {
                            indicator: hostname,
                            indicator_type: ThreatIndicatorType::Hostname,
                            observation_layer: ThreatObservationLayer::Tls,
                            source_group,
                            node_id,
                            observed_at: event.observed_at,
                            dst_ip: Some(event.dst_ip),
                            audit_finding_key: Some(audit_finding_key),
                        });
                    }
                }
            }
        }

        observations
    }
}

#[derive(Clone)]
pub struct ThreatRuntimeHandle {
    sender: mpsc::Sender<ThreatObservation>,
    matcher: Arc<RwLock<ThreatMatcher>>,
    metrics: Metrics,
}

#[derive(Clone, Default)]
pub struct ThreatRuntimeSlot {
    inner: Arc<RwLock<Option<ThreatRuntimeHandle>>>,
    metrics: Option<Metrics>,
}

impl ThreatRuntimeHandle {
    pub fn spawn(config: ThreatRuntimeConfig) -> Self {
        let ThreatRuntimeConfig {
            snapshot,
            store,
            metrics,
            queue_capacity,
        } = config;
        let matcher = Arc::new(RwLock::new(ThreatMatcher::from_snapshot(&snapshot)));
        metrics.set_threat_cluster_snapshot_version(snapshot.version);
        let (sender, mut receiver) = mpsc::channel(queue_capacity.max(1));
        let matcher_for_worker = matcher.clone();
        let store_for_worker = store.clone();
        let metrics_for_worker = metrics.clone();
        tokio::spawn(async move {
            while let Some(observation) = receiver.recv().await {
                process_observation(
                    &matcher_for_worker,
                    &store_for_worker,
                    &metrics_for_worker,
                    observation,
                );
            }
        });

        let handle = Self {
            sender,
            matcher,
            metrics,
        };
        let _ = handle.refresh_active_metrics(&store);
        handle
    }

    pub fn try_observe(&self, observation: ThreatObservation) -> bool {
        match self.sender.try_send(observation) {
            Ok(()) => true,
            Err(err) => {
                self.metrics.inc_threat_observation_enqueue_failure();
                if THREAT_OBSERVATION_DROPS.fetch_add(1, Ordering::Relaxed) < 20 {
                    warn!(error = %err, "threat observation enqueue failed");
                }
                false
            }
        }
    }

    pub fn replace_snapshot(&self, snapshot: ThreatSnapshot) -> Result<(), String> {
        let mut lock = self
            .matcher
            .write()
            .map_err(|_| "threat runtime matcher lock poisoned".to_string())?;
        *lock = ThreatMatcher::from_snapshot(&snapshot);
        self.metrics
            .set_threat_cluster_snapshot_version(snapshot.version);
        Ok(())
    }

    pub fn refresh_active_metrics(&self, store: &ThreatStore) -> Result<(), String> {
        refresh_active_metrics(&self.metrics, store)
    }
}

impl ThreatRuntimeSlot {
    pub fn new(initial: Option<ThreatRuntimeHandle>, metrics: Option<Metrics>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
            metrics,
        }
    }

    pub fn replace(&self, handle: Option<ThreatRuntimeHandle>) -> Result<(), String> {
        let mut lock = self
            .inner
            .write()
            .map_err(|_| "threat runtime slot lock poisoned".to_string())?;
        *lock = handle;
        Ok(())
    }

    pub fn try_observe(&self, observation: ThreatObservation) -> bool {
        match self.inner.read() {
            Ok(lock) => match lock.as_ref() {
                Some(handle) => handle.try_observe(observation),
                None => false,
            },
            Err(_) => {
                if let Some(metrics) = self.metrics.as_ref() {
                    metrics.inc_threat_observation_enqueue_failure();
                }
                false
            }
        }
    }
}

fn process_observation(
    matcher: &Arc<RwLock<ThreatMatcher>>,
    store: &ThreatStore,
    metrics: &Metrics,
    observation: ThreatObservation,
) {
    let Some(threat_match) = match_observation(matcher, &observation) else {
        return;
    };

    let finding = build_finding(observation, threat_match);
    let finding = match store.upsert_finding(finding) {
        Ok(finding) => finding,
        Err(err) => {
            warn!(error = %err, "threat finding write failed");
            return;
        }
    };
    record_match_metrics(metrics, &finding);
    if let Err(err) = refresh_active_metrics(metrics, store) {
        warn!(error = %err, "threat finding active metric refresh failed");
    }
}

fn match_observation(
    matcher: &Arc<RwLock<ThreatMatcher>>,
    observation: &ThreatObservation,
) -> Option<ThreatMatch> {
    let lock = matcher.read().ok()?;
    match observation.indicator_type {
        ThreatIndicatorType::Hostname => lock.match_hostname(&observation.indicator),
        ThreatIndicatorType::Ip => observation
            .indicator
            .parse::<Ipv4Addr>()
            .ok()
            .and_then(|ip| lock.match_ip(ip)),
    }
}

fn build_finding(observation: ThreatObservation, threat_match: ThreatMatch) -> ThreatFinding {
    ThreatFinding {
        indicator: threat_match.indicator,
        indicator_type: threat_match.indicator_type,
        observation_layer: observation.observation_layer,
        match_source: ThreatMatchSource::Stream,
        source_group: observation.source_group,
        severity: threat_match.severity,
        confidence: threat_match.confidence,
        feed_hits: threat_match
            .feed_hits
            .into_iter()
            .map(feed_hit_from_snapshot)
            .collect(),
        first_seen: observation.observed_at,
        last_seen: observation.observed_at,
        count: 1,
        sample_node_ids: vec![observation.node_id],
        alertable: false,
        audit_links: observation.audit_finding_key.into_iter().collect(),
        enrichment_status: ThreatEnrichmentStatus::NotRequested,
    }
}

fn feed_hit_from_snapshot(item: ThreatIndicatorSnapshotItem) -> ThreatFeedHit {
    ThreatFeedHit {
        feed: item.feed,
        severity: item.severity,
        confidence: item.confidence,
        reference_url: item.reference_url,
        tags: item.tags,
    }
}

fn record_match_metrics(metrics: &Metrics, finding: &ThreatFinding) {
    for (feed, severity) in metric_feeds_for_finding(finding) {
        metrics.inc_threat_match(
            indicator_type_label(finding.indicator_type),
            layer_label(finding.observation_layer),
            severity_label(severity),
            &feed,
            finding.match_source.as_str(),
        );
        if finding.alertable {
            metrics.inc_threat_alertable_match(
                indicator_type_label(finding.indicator_type),
                layer_label(finding.observation_layer),
                severity_label(finding.severity),
                &feed,
            );
        }
    }
}

fn metric_feeds_for_finding(finding: &ThreatFinding) -> Vec<(String, ThreatSeverity)> {
    let mut feeds: HashMap<String, ThreatSeverity> = HashMap::new();
    for hit in &finding.feed_hits {
        feeds
            .entry(hit.feed.clone())
            .and_modify(|existing| {
                if severity_rank(hit.severity) > severity_rank(*existing) {
                    *existing = hit.severity;
                }
            })
            .or_insert(hit.severity);
    }
    let mut items: Vec<_> = feeds.into_iter().collect();
    items.sort_by(|left, right| left.0.cmp(&right.0));
    items
}

fn refresh_active_metrics(metrics: &Metrics, store: &ThreatStore) -> Result<(), String> {
    let counts = store.active_counts_by_severity()?;
    for severity in [
        ThreatSeverity::Low,
        ThreatSeverity::Medium,
        ThreatSeverity::High,
        ThreatSeverity::Critical,
    ] {
        metrics.set_threat_findings_active(
            severity_label(severity),
            counts.get(&severity).copied().unwrap_or(0),
        );
    }
    Ok(())
}

fn indicator_type_label(indicator_type: ThreatIndicatorType) -> &'static str {
    match indicator_type {
        ThreatIndicatorType::Hostname => "hostname",
        ThreatIndicatorType::Ip => "ip",
    }
}

fn layer_label(layer: ThreatObservationLayer) -> &'static str {
    match layer {
        ThreatObservationLayer::Dns => "dns",
        ThreatObservationLayer::Tls => "tls",
        ThreatObservationLayer::L4 => "l4",
    }
}

fn severity_label(severity: ThreatSeverity) -> &'static str {
    match severity {
        ThreatSeverity::Low => "low",
        ThreatSeverity::Medium => "medium",
        ThreatSeverity::High => "high",
        ThreatSeverity::Critical => "critical",
    }
}

fn severity_rank(severity: ThreatSeverity) -> u8 {
    match severity {
        ThreatSeverity::Low => 0,
        ThreatSeverity::Medium => 1,
        ThreatSeverity::High => 2,
        ThreatSeverity::Critical => 3,
    }
}

fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::{ThreatObservation, ThreatRuntimeConfig, ThreatRuntimeHandle, ThreatRuntimeSlot};
    use crate::controlplane::threat_intel::feeds::{
        snapshot_with_cidr, snapshot_with_hostname, ThreatIndicatorSnapshotItem, ThreatSnapshot,
    };
    use crate::controlplane::threat_intel::store::{
        ThreatFinding, ThreatFindingQuery, ThreatStore,
    };
    use crate::controlplane::threat_intel::types::{
        ThreatIndicatorType, ThreatObservationLayer, ThreatSeverity,
    };
    use crate::dataplane::{AuditEvent, AuditEventType};
    use crate::metrics::Metrics;
    use uuid::Uuid;

    #[tokio::test]
    async fn runtime_creates_alertable_hostname_finding_on_stream_match() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
            snapshot: snapshot_with_hostname("Bad.Example.com.", ThreatSeverity::High, "threatfox"),
            store: store.clone(),
            metrics: metrics.clone(),
            queue_capacity: 16,
        });

        assert!(handle.try_observe(
            ThreatObservation::dns("bad.example.com.", "apps", "node-a", 100).expect("observation")
        ));

        let items = wait_for_findings(&store, 1).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].indicator, "bad.example.com");
        assert_eq!(items[0].indicator_type, ThreatIndicatorType::Hostname);
        assert_eq!(items[0].observation_layer, ThreatObservationLayer::Dns);
        assert!(items[0].alertable);
        assert_eq!(items[0].confidence, Some(80));
        assert_eq!(items[0].sample_node_ids, vec!["node-a".to_string()]);
        assert_eq!(items[0].feed_hits[0].feed, "threatfox");

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_matches_total",
                &[
                    ("indicator_type", "hostname"),
                    ("observation_layer", "dns"),
                    ("severity", "high"),
                    ("feed", "threatfox"),
                    ("match_source", "stream"),
                ]
            ),
            1.0
        );
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_alertable_matches_total",
                &[
                    ("indicator_type", "hostname"),
                    ("observation_layer", "dns"),
                    ("severity", "high"),
                    ("feed", "threatfox"),
                ]
            ),
            1.0
        );
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_findings_active",
                &[("severity", "high")]
            ),
            1.0
        );
    }

    #[tokio::test]
    async fn runtime_creates_l4_ip_finding_from_audit_observation() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
            snapshot: snapshot_with_cidr(
                "203.0.113.0/24",
                ThreatSeverity::Critical,
                "spamhaus_drop",
            ),
            store: store.clone(),
            metrics: metrics.clone(),
            queue_capacity: 16,
        });
        let event = AuditEvent {
            event_type: AuditEventType::L4Deny,
            src_ip: Ipv4Addr::new(192, 0, 2, 10),
            dst_ip: Ipv4Addr::new(203, 0, 113, 42),
            src_port: 54000,
            dst_port: 443,
            proto: 6,
            source_group: "payments".to_string(),
            sni: None,
            icmp_type: None,
            icmp_code: None,
            observed_at: 200,
        };

        for observation in ThreatObservation::from_audit_event(
            &event,
            Some("Bad.Example.com".to_string()),
            "node-b",
            None,
        ) {
            assert!(handle.try_observe(observation));
        }

        let items = wait_for_findings(&store, 1).await;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].indicator, "203.0.113.42");
        assert_eq!(items[0].indicator_type, ThreatIndicatorType::Ip);
        assert_eq!(items[0].observation_layer, ThreatObservationLayer::L4);
        assert_eq!(items[0].source_group, "payments");
        assert!(items[0].alertable);
        assert_eq!(
            items[0].audit_links,
            vec!["l4:none:payments:203.0.113.42:443:6:bad.example.com".to_string()]
        );
        assert_eq!(items[0].sample_node_ids, vec!["node-b".to_string()]);

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_matches_total",
                &[
                    ("indicator_type", "ip"),
                    ("observation_layer", "l4"),
                    ("severity", "critical"),
                    ("feed", "spamhaus_drop"),
                    ("match_source", "stream"),
                ]
            ),
            1.0
        );
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_alertable_matches_total",
                &[
                    ("indicator_type", "ip"),
                    ("observation_layer", "l4"),
                    ("severity", "critical"),
                    ("feed", "spamhaus_drop"),
                ]
            ),
            1.0
        );
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_findings_active",
                &[("severity", "critical")]
            ),
            1.0
        );
    }

    #[tokio::test]
    async fn runtime_uses_effective_severity_for_alertable_metrics() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
            snapshot: ThreatSnapshot::new(
                7,
                300,
                vec![
                    ThreatIndicatorSnapshotItem {
                        indicator: "bad.example.com".to_string(),
                        indicator_type: ThreatIndicatorType::Hostname,
                        feed: "threatfox".to_string(),
                        severity: ThreatSeverity::Critical,
                        confidence: Some(95),
                        tags: Vec::new(),
                        reference_url: None,
                        feed_first_seen: Some(1),
                        feed_last_seen: Some(2),
                        expires_at: None,
                    },
                    ThreatIndicatorSnapshotItem {
                        indicator: "bad.example.com".to_string(),
                        indicator_type: ThreatIndicatorType::Hostname,
                        feed: "urlhaus".to_string(),
                        severity: ThreatSeverity::Low,
                        confidence: Some(40),
                        tags: Vec::new(),
                        reference_url: None,
                        feed_first_seen: Some(1),
                        feed_last_seen: Some(2),
                        expires_at: None,
                    },
                ],
            ),
            store,
            metrics: metrics.clone(),
            queue_capacity: 16,
        });

        assert!(handle.try_observe(
            ThreatObservation::dns("bad.example.com", "apps", "node-a", 300).expect("observation")
        ));

        wait_for_alertable_metric(
            &metrics,
            &[
                ("indicator_type", "hostname"),
                ("observation_layer", "dns"),
                ("severity", "critical"),
                ("feed", "urlhaus"),
            ],
        )
        .await;

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_alertable_matches_total",
                &[
                    ("indicator_type", "hostname"),
                    ("observation_layer", "dns"),
                    ("severity", "low"),
                    ("feed", "urlhaus"),
                ]
            ),
            0.0
        );
    }

    #[tokio::test]
    async fn runtime_uses_store_threshold_for_alertable_metrics() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        store
            .reconcile_alertable_threshold(ThreatSeverity::Critical)
            .expect("set threshold");
        let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
            snapshot: snapshot_with_hostname("bad.example.com", ThreatSeverity::High, "threatfox"),
            store: store.clone(),
            metrics: metrics.clone(),
            queue_capacity: 16,
        });

        assert!(handle.try_observe(
            ThreatObservation::dns("bad.example.com", "apps", "node-a", 350).expect("observation")
        ));

        let items = wait_for_findings(&store, 1).await;
        assert_eq!(items.len(), 1);
        assert!(!items[0].alertable);

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_alertable_matches_total",
                &[
                    ("indicator_type", "hostname"),
                    ("observation_layer", "dns"),
                    ("severity", "high"),
                    ("feed", "threatfox"),
                ]
            ),
            0.0
        );
    }

    #[tokio::test]
    async fn runtime_preserves_dns_audit_link_when_provided() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
            snapshot: snapshot_with_hostname("bad.example.com", ThreatSeverity::High, "threatfox"),
            store: store.clone(),
            metrics,
            queue_capacity: 16,
        });

        assert!(handle.try_observe(
            ThreatObservation::dns_with_audit_link(
                "bad.example.com",
                "apps",
                "node-a",
                400,
                Some("dns:none:apps:bad.example.com".to_string()),
            )
            .expect("observation")
        ));

        let items = wait_for_findings(&store, 1).await;
        assert_eq!(
            items[0].audit_links,
            vec!["dns:none:apps:bad.example.com".to_string()]
        );
    }

    #[test]
    fn runtime_emits_ip_and_hostname_observations_for_tls_audit_events() {
        let event = AuditEvent {
            event_type: AuditEventType::TlsDeny,
            src_ip: Ipv4Addr::new(192, 0, 2, 10),
            dst_ip: Ipv4Addr::new(203, 0, 113, 42),
            src_port: 54000,
            dst_port: 443,
            proto: 6,
            source_group: "payments".to_string(),
            sni: Some("Bad.Example.com".to_string()),
            icmp_type: None,
            icmp_code: None,
            observed_at: 500,
        };

        let observations = ThreatObservation::from_audit_event(&event, None, "node-c", None);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].indicator, "203.0.113.42");
        assert_eq!(observations[0].indicator_type, ThreatIndicatorType::Ip);
        assert_eq!(
            observations[0].observation_layer,
            ThreatObservationLayer::Tls
        );
        assert_eq!(observations[1].indicator, "bad.example.com");
        assert_eq!(
            observations[1].indicator_type,
            ThreatIndicatorType::Hostname
        );
        assert_eq!(
            observations[1].observation_layer,
            ThreatObservationLayer::Tls
        );
    }

    #[test]
    fn runtime_slot_noops_when_runtime_unavailable() {
        let slot = ThreatRuntimeSlot::default();
        let observed = slot.try_observe(
            ThreatObservation::dns("bad.example.com", "apps", "node-a", 1).expect("observation"),
        );
        assert!(!observed);
    }

    #[test]
    fn runtime_slot_does_not_record_enqueue_failure_metric_when_inactive() {
        let metrics = Metrics::new().expect("metrics");
        let slot = ThreatRuntimeSlot::new(None, Some(metrics.clone()));

        let observed = slot.try_observe(
            ThreatObservation::dns("bad.example.com", "apps", "node-a", 1).expect("observation"),
        );

        assert!(!observed);
        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_observation_enqueue_failures_total",
                &[],
            ),
            0.0
        );
    }

    async fn wait_for_findings(store: &ThreatStore, expected: usize) -> Vec<ThreatFinding> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let items = store.query(&ThreatFindingQuery::default()).expect("query");
                if items.len() >= expected {
                    return items;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("findings timeout")
    }

    async fn wait_for_alertable_metric(metrics: &Metrics, labels: &[(&str, &str)]) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let rendered = metrics.render().expect("render metrics");
                if metric_value_with_labels(
                    &rendered,
                    "neuwerk_threat_alertable_matches_total",
                    labels,
                ) >= 1.0
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("metric timeout");
    }

    fn temp_store_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("threat-runtime-{}", Uuid::new_v4()))
    }

    fn metric_value_with_labels(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> f64 {
        rendered
            .lines()
            .find_map(|line| {
                if !line.starts_with(metric) {
                    return None;
                }
                let name = line.split_whitespace().next()?;
                for (key, value) in labels {
                    let needle = format!(r#"{key}="{value}""#);
                    if !name.contains(&needle) {
                        return None;
                    }
                }
                line.split_whitespace().last()?.parse::<f64>().ok()
            })
            .unwrap_or(0.0)
    }
}
