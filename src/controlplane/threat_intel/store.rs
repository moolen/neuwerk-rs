use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::types::{ThreatIndicatorType, ThreatObservationLayer, ThreatSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreatMatchSource {
    Stream,
    Backfill,
}

impl ThreatMatchSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Backfill => "backfill",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreatEnrichmentStatus {
    NotRequested,
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreatFeedHit {
    pub feed: String,
    pub severity: ThreatSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreatFinding {
    pub indicator: String,
    pub indicator_type: ThreatIndicatorType,
    pub observation_layer: ThreatObservationLayer,
    pub match_source: ThreatMatchSource,
    pub source_group: String,
    pub severity: ThreatSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    pub feed_hits: Vec<ThreatFeedHit>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u64,
    pub sample_node_ids: Vec<String>,
    pub alertable: bool,
    pub audit_links: Vec<String>,
    pub enrichment_status: ThreatEnrichmentStatus,
}

impl ThreatFinding {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.indicator_type_label(),
            normalized_key_indicator(self.indicator_type, &self.indicator),
            self.observation_layer_label(),
            self.match_source.as_str(),
            self.source_group.trim().to_ascii_lowercase(),
        )
    }

    fn merge_from(&mut self, other: &ThreatFinding) {
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.count = self.count.saturating_add(other.count);
        self.severity = max_severity(self.severity, other.severity);
        self.confidence = match (self.confidence, other.confidence) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        self.alertable |= other.alertable;
        self.enrichment_status =
            merge_enrichment_status(self.enrichment_status, other.enrichment_status);
        merge_string_set(&mut self.sample_node_ids, &other.sample_node_ids);
        merge_string_set(&mut self.audit_links, &other.audit_links);
        merge_feed_hits(&mut self.feed_hits, &other.feed_hits);
    }

    fn indicator_type_label(&self) -> &'static str {
        match self.indicator_type {
            ThreatIndicatorType::Hostname => "hostname",
            ThreatIndicatorType::Ip => "ip",
        }
    }

    fn observation_layer_label(&self) -> &'static str {
        match self.observation_layer {
            ThreatObservationLayer::Dns => "dns",
            ThreatObservationLayer::Tls => "tls",
            ThreatObservationLayer::L4 => "l4",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ThreatFindingSnapshot {
    findings: Vec<ThreatFinding>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub struct ThreatFindingQuery {
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub indicator_type: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub severity: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub source_group: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub observation_layer: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub feed: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub match_source: Vec<String>,
    #[serde(default, alias = "alertable")]
    pub alertable_only: Option<bool>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ThreatNodeQueryError {
    pub node_id: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ThreatFindingQueryResponse {
    pub items: Vec<ThreatFinding>,
    pub partial: bool,
    pub node_errors: Vec<ThreatNodeQueryError>,
    pub nodes_queried: usize,
    pub nodes_responded: usize,
}

#[derive(Debug, Clone)]
pub struct ThreatStore {
    base_dir: PathBuf,
    max_bytes: usize,
    inner: Arc<RwLock<ThreatStoreState>>,
}

#[derive(Debug, Clone)]
struct ThreatStoreState {
    alert_threshold: ThreatSeverity,
    findings: HashMap<String, ThreatFinding>,
}

impl ThreatStore {
    pub fn new(base_dir: PathBuf, max_bytes: usize) -> Result<Self, String> {
        let max_bytes = max_bytes.max(1024);
        let store = Self {
            base_dir,
            max_bytes,
            inner: Arc::new(RwLock::new(ThreatStoreState {
                alert_threshold: ThreatSeverity::High,
                findings: HashMap::new(),
            })),
        };
        store.load_snapshot()?;
        Ok(store)
    }

    pub fn upsert_finding(&self, finding: ThreatFinding) -> Result<ThreatFinding, String> {
        let mut lock = self
            .inner
            .write()
            .map_err(|_| "threat store lock poisoned".to_string())?;
        let threshold = lock.alert_threshold;
        let finding = normalize_finding(finding, threshold);
        let key = finding.key();
        let persisted = if let Some(existing) = lock.findings.get_mut(&key) {
            existing.merge_from(&finding);
            existing.alertable = is_alertable(existing.severity, threshold);
            existing.clone()
        } else {
            lock.findings.insert(key, finding.clone());
            finding
        };
        self.persist_snapshot_locked(&mut lock)?;
        Ok(persisted)
    }

    pub fn query(&self, query: &ThreatFindingQuery) -> Result<Vec<ThreatFinding>, String> {
        let indicator_types = parse_indicator_types(&query.indicator_type)?;
        let severities = parse_severities(&query.severity)?;
        let layers = parse_observation_layers(&query.observation_layer)?;
        let match_sources = parse_match_sources(&query.match_source)?;
        let source_groups = normalize_values(&query.source_group);
        let feeds = normalize_values(&query.feed);
        let since = query.since.unwrap_or(0);
        let until = query.until.unwrap_or(u64::MAX);
        let limit = query.limit.unwrap_or(500).clamp(1, 10_000);

        let mut items = Vec::new();
        let lock = self
            .inner
            .read()
            .map_err(|_| "threat store lock poisoned".to_string())?;
        for finding in lock.findings.values() {
            if !indicator_types.is_empty() && !indicator_types.contains(&finding.indicator_type) {
                continue;
            }
            if !severities.is_empty() && !severities.contains(&finding.severity) {
                continue;
            }
            if !layers.is_empty() && !layers.contains(&finding.observation_layer) {
                continue;
            }
            if !match_sources.is_empty() && !match_sources.contains(&finding.match_source) {
                continue;
            }
            if !source_groups.is_empty()
                && !source_groups.contains(&finding.source_group.to_ascii_lowercase())
            {
                continue;
            }
            if query.alertable_only == Some(true) && !finding.alertable {
                continue;
            }
            if finding.last_seen < since || finding.first_seen > until {
                continue;
            }
            if !feeds.is_empty()
                && !finding
                    .feed_hits
                    .iter()
                    .any(|hit| feeds.contains(&hit.feed.to_ascii_lowercase()))
            {
                continue;
            }
            items.push(finding.clone());
        }
        items.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.indicator.cmp(&b.indicator))
        });
        items.truncate(limit);
        Ok(items)
    }

    pub fn merge_findings(sources: Vec<Vec<ThreatFinding>>) -> Vec<ThreatFinding> {
        let mut merged: HashMap<String, ThreatFinding> = HashMap::new();
        for findings in sources {
            for finding in findings {
                let key = finding.key();
                if let Some(existing) = merged.get_mut(&key) {
                    existing.merge_from(&finding);
                } else {
                    merged.insert(key, finding);
                }
            }
        }
        let mut items: Vec<ThreatFinding> = merged.into_values().collect();
        items.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.count.cmp(&a.count))
                .then_with(|| a.indicator.cmp(&b.indicator))
        });
        items
    }

    pub fn active_counts_by_severity(&self) -> Result<HashMap<ThreatSeverity, usize>, String> {
        let mut counts = HashMap::new();
        let lock = self
            .inner
            .read()
            .map_err(|_| "threat store lock poisoned".to_string())?;
        for finding in lock.findings.values() {
            *counts.entry(finding.severity).or_insert(0) += 1;
        }
        Ok(counts)
    }

    pub fn reconcile_alertable_threshold(&self, threshold: ThreatSeverity) -> Result<(), String> {
        let mut lock = self
            .inner
            .write()
            .map_err(|_| "threat store lock poisoned".to_string())?;
        lock.alert_threshold = threshold;
        for finding in lock.findings.values_mut() {
            finding.alertable = is_alertable(finding.severity, threshold);
        }
        self.persist_snapshot_locked(&mut lock)?;
        Ok(())
    }

    fn ensure_dirs(&self) -> Result<(), String> {
        fs::create_dir_all(&self.base_dir).map_err(|err| err.to_string())
    }

    fn snapshot_path(&self) -> PathBuf {
        self.base_dir.join("snapshot.json")
    }

    fn load_snapshot(&self) -> Result<(), String> {
        self.ensure_dirs()?;
        let path = self.snapshot_path();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.to_string()),
        };
        let snapshot: ThreatFindingSnapshot =
            serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
        let mut lock = self
            .inner
            .write()
            .map_err(|_| "threat store lock poisoned".to_string())?;
        let threshold = lock.alert_threshold;
        lock.findings.clear();
        for finding in snapshot.findings {
            let finding = normalize_finding(finding, threshold);
            lock.findings.insert(finding.key(), finding);
        }
        Ok(())
    }

    fn persist_snapshot_locked(&self, state: &mut ThreatStoreState) -> Result<(), String> {
        self.ensure_dirs()?;
        loop {
            let snapshot = ThreatFindingSnapshot {
                findings: state.findings.values().cloned().collect(),
            };
            let payload = serde_json::to_vec_pretty(&snapshot).map_err(|err| err.to_string())?;
            if payload.len() <= self.max_bytes || state.findings.is_empty() {
                return atomic_write(&self.snapshot_path(), &payload);
            }

            let oldest_key = state
                .findings
                .iter()
                .min_by_key(|(_, finding)| finding.last_seen)
                .map(|(key, _)| key.clone());
            match oldest_key {
                Some(key) => {
                    state.findings.remove(&key);
                }
                None => return atomic_write(&self.snapshot_path(), &payload),
            }
        }
    }
}

fn parse_indicator_types(values: &[String]) -> Result<HashSet<ThreatIndicatorType>, String> {
    let mut out = HashSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        let parsed = match value.as_str() {
            "hostname" => ThreatIndicatorType::Hostname,
            "ip" => ThreatIndicatorType::Ip,
            _ => return Err(format!("invalid indicator_type value: {value}")),
        };
        out.insert(parsed);
    }
    Ok(out)
}

fn parse_severities(values: &[String]) -> Result<HashSet<ThreatSeverity>, String> {
    let mut out = HashSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        let parsed = match value.as_str() {
            "low" => ThreatSeverity::Low,
            "medium" => ThreatSeverity::Medium,
            "high" => ThreatSeverity::High,
            "critical" => ThreatSeverity::Critical,
            _ => return Err(format!("invalid severity value: {value}")),
        };
        out.insert(parsed);
    }
    Ok(out)
}

fn parse_observation_layers(values: &[String]) -> Result<HashSet<ThreatObservationLayer>, String> {
    let mut out = HashSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        let parsed = match value.as_str() {
            "dns" => ThreatObservationLayer::Dns,
            "tls" => ThreatObservationLayer::Tls,
            "l4" => ThreatObservationLayer::L4,
            _ => return Err(format!("invalid observation_layer value: {value}")),
        };
        out.insert(parsed);
    }
    Ok(out)
}

fn parse_match_sources(values: &[String]) -> Result<HashSet<ThreatMatchSource>, String> {
    let mut out = HashSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        let parsed = match value.as_str() {
            "stream" => ThreatMatchSource::Stream,
            "backfill" => ThreatMatchSource::Backfill,
            _ => return Err(format!("invalid match_source value: {value}")),
        };
        out.insert(parsed);
    }
    Ok(out)
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }

    match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => Ok(vec![value]),
        OneOrMany::Many(values) => Ok(values),
    }
}

fn normalize_values(values: &[String]) -> HashSet<String> {
    values
        .iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_finding(mut finding: ThreatFinding, alert_threshold: ThreatSeverity) -> ThreatFinding {
    finding.indicator = normalized_key_indicator(finding.indicator_type, &finding.indicator);
    finding.source_group = finding.source_group.trim().to_string();
    finding.alertable = is_alertable(finding.severity, alert_threshold);
    finding
}

fn normalized_key_indicator(indicator_type: ThreatIndicatorType, indicator: &str) -> String {
    match indicator_type {
        ThreatIndicatorType::Hostname => {
            indicator.trim().trim_end_matches('.').to_ascii_lowercase()
        }
        ThreatIndicatorType::Ip => indicator.trim().to_string(),
    }
}

fn merge_enrichment_status(
    left: ThreatEnrichmentStatus,
    right: ThreatEnrichmentStatus,
) -> ThreatEnrichmentStatus {
    if enrichment_rank(right) > enrichment_rank(left) {
        right
    } else {
        left
    }
}

fn enrichment_rank(status: ThreatEnrichmentStatus) -> u8 {
    match status {
        ThreatEnrichmentStatus::NotRequested => 0,
        ThreatEnrichmentStatus::Queued => 1,
        ThreatEnrichmentStatus::Running => 2,
        ThreatEnrichmentStatus::Completed => 3,
        ThreatEnrichmentStatus::Failed => 4,
    }
}

fn max_severity(left: ThreatSeverity, right: ThreatSeverity) -> ThreatSeverity {
    if severity_rank(right) > severity_rank(left) {
        right
    } else {
        left
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

fn is_alertable(severity: ThreatSeverity, threshold: ThreatSeverity) -> bool {
    severity_rank(severity) >= severity_rank(threshold)
}

fn merge_feed_hits(target: &mut Vec<ThreatFeedHit>, incoming: &[ThreatFeedHit]) {
    let mut merged: HashMap<String, ThreatFeedHit> = target
        .iter()
        .cloned()
        .map(|hit| (hit.feed.clone(), hit))
        .collect();
    for hit in incoming {
        merged
            .entry(hit.feed.clone())
            .and_modify(|existing| {
                existing.severity = max_severity(existing.severity, hit.severity);
                existing.confidence = match (existing.confidence, hit.confidence) {
                    (Some(left), Some(right)) => Some(left.max(right)),
                    (None, value) | (value, None) => value,
                };
                if existing.reference_url.is_none() {
                    existing.reference_url = hit.reference_url.clone();
                }
                merge_string_set(&mut existing.tags, &hit.tags);
            })
            .or_insert_with(|| hit.clone());
    }
    let mut values: Vec<_> = merged.into_values().collect();
    values.sort_by(|a, b| a.feed.cmp(&b.feed));
    *target = values;
}

fn merge_string_set(target: &mut Vec<String>, incoming: &[String]) {
    let mut values: HashSet<String> = target.iter().cloned().collect();
    for value in incoming {
        if !value.is_empty() {
            values.insert(value.clone());
        }
    }
    let mut out: Vec<_> = values.into_iter().collect();
    out.sort();
    *target = out;
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&tmp, contents).map_err(|err| err.to_string())?;
    fs::rename(&tmp, path).map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding(indicator: &str, alertable: bool) -> ThreatFinding {
        ThreatFinding {
            indicator: indicator.to_string(),
            indicator_type: ThreatIndicatorType::Hostname,
            observation_layer: ThreatObservationLayer::Dns,
            match_source: ThreatMatchSource::Stream,
            source_group: "apps".to_string(),
            severity: ThreatSeverity::High,
            confidence: Some(90),
            feed_hits: vec![ThreatFeedHit {
                feed: "threatfox".to_string(),
                severity: ThreatSeverity::High,
                confidence: Some(90),
                reference_url: None,
                tags: Vec::new(),
            }],
            first_seen: 10,
            last_seen: 10,
            count: 1,
            sample_node_ids: vec!["node-a".to_string()],
            alertable,
            audit_links: Vec::new(),
            enrichment_status: ThreatEnrichmentStatus::NotRequested,
        }
    }

    #[test]
    fn alertable_only_false_does_not_filter_out_alertable_findings() {
        let dir = std::env::temp_dir().join(format!("threat-store-{}", Uuid::new_v4()));
        let store = ThreatStore::new(dir, 1024 * 1024).unwrap();
        store
            .upsert_finding(sample_finding("alertable.example.com", true))
            .unwrap();
        store
            .upsert_finding(sample_finding("info.example.com", false))
            .unwrap();

        let items = store
            .query(&ThreatFindingQuery {
                alertable_only: Some(false),
                ..ThreatFindingQuery::default()
            })
            .unwrap();

        assert_eq!(items.len(), 2);
    }

    #[test]
    fn hostname_dedup_key_is_case_insensitive_and_trims_trailing_dot() {
        let dir = std::env::temp_dir().join(format!("threat-store-{}", Uuid::new_v4()));
        let store = ThreatStore::new(dir, 1024 * 1024).unwrap();
        store
            .upsert_finding(sample_finding("Bad.Example.com.", true))
            .unwrap();
        store
            .upsert_finding(sample_finding("bad.example.com", true))
            .unwrap();

        let items = store.query(&ThreatFindingQuery::default()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].count, 2);
        assert_eq!(items[0].indicator, "bad.example.com");
    }

    #[test]
    fn new_returns_error_for_corrupt_snapshot() {
        let dir = std::env::temp_dir().join(format!("threat-store-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("snapshot.json"), b"{not-json").unwrap();

        let err = ThreatStore::new(dir, 1024 * 1024).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn reconcile_alertable_threshold_updates_existing_findings() {
        let dir = std::env::temp_dir().join(format!("threat-store-{}", Uuid::new_v4()));
        let store = ThreatStore::new(dir, 1024 * 1024).unwrap();
        let mut finding = sample_finding("bad.example.com", true);
        finding.severity = ThreatSeverity::High;
        store.upsert_finding(finding).unwrap();

        store
            .reconcile_alertable_threshold(ThreatSeverity::Critical)
            .unwrap();

        let items = store.query(&ThreatFindingQuery::default()).unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].alertable);
    }

    #[test]
    fn upsert_finding_uses_current_alertable_threshold() {
        let dir = std::env::temp_dir().join(format!("threat-store-{}", Uuid::new_v4()));
        let store = ThreatStore::new(dir, 1024 * 1024).unwrap();
        store
            .reconcile_alertable_threshold(ThreatSeverity::Critical)
            .unwrap();

        let mut finding = sample_finding("bad.example.com", true);
        finding.severity = ThreatSeverity::High;
        store.upsert_finding(finding).unwrap();

        let items = store.query(&ThreatFindingQuery::default()).unwrap();
        assert_eq!(items.len(), 1);
        assert!(!items[0].alertable);
    }
}
