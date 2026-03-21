use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::warn;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::threat_intel::feeds::{
    SpamhausDropAdapter, ThreatFeedAdapter, ThreatFoxAdapter, ThreatIndicatorSnapshotItem,
    ThreatSnapshot, UrlhausAdapter,
};
use crate::controlplane::threat_intel::settings::{load_settings, ThreatIntelSettings};
use crate::controlplane::threat_intel::types::ThreatIndicatorType;
use crate::metrics::Metrics;

pub const THREAT_INTEL_SNAPSHOT_KEY: &[u8] = b"threat_intel/snapshot";
pub const THREAT_INTEL_FEED_STATUS_KEY: &[u8] = b"threat_intel/feed_status";

const THREATFOX_RECENT_URL: &str = "https://threatfox.abuse.ch/export/json/urls/recent/";
const URLHAUS_TEXT_URL: &str = "https://urlhaus.abuse.ch/downloads/text/";
const SPAMHAUS_DROP_V4_URL: &str = "https://www.spamhaus.org/drop/drop_v4.json";
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 30;
const FAILED_REFRESH_RETRY_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreatRefreshOutcome {
    Success,
    Failed,
    Skipped,
}

impl ThreatRefreshOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
pub struct ThreatFeedIndicatorCounts {
    #[serde(default)]
    pub hostname: usize,
    #[serde(default)]
    pub ip: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
pub struct ThreatFeedStatusItem {
    pub feed: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_completed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_successful_refresh_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_outcome: Option<ThreatRefreshOutcome>,
    #[serde(default)]
    pub indicator_counts: ThreatFeedIndicatorCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
pub struct ThreatFeedRefreshState {
    #[serde(default)]
    pub snapshot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_generated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_completed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_successful_refresh_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh_outcome: Option<ThreatRefreshOutcome>,
    #[serde(default)]
    pub feeds: Vec<ThreatFeedStatusItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ThreatLocalRuntimeState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backfill_snapshot_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backfill_started_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backfill_completed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_backfill_outcome: Option<ThreatRefreshOutcome>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatFeedPayloads {
    pub threatfox: Option<String>,
    pub urlhaus: Option<String>,
    pub spamhaus_drop: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ThreatRefreshResult {
    pub snapshot: ThreatSnapshot,
    pub state: ThreatFeedRefreshState,
}

#[derive(Clone)]
pub struct ThreatManagerCluster {
    pub raft: openraft::Raft<ClusterTypeConfig>,
    pub store: ClusterStore,
}

#[derive(Clone)]
pub struct ThreatManagerConfig {
    pub local_data_root: PathBuf,
    pub cluster: Option<ThreatManagerCluster>,
    pub metrics: Metrics,
    pub poll_interval: Duration,
    pub http_timeout: Duration,
}

impl ThreatManagerConfig {
    pub fn new(
        local_data_root: PathBuf,
        cluster: Option<ThreatManagerCluster>,
        metrics: Metrics,
    ) -> Self {
        Self {
            local_data_root,
            cluster,
            metrics,
            poll_interval: Duration::from_secs(5),
            http_timeout: Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS),
        }
    }
}

pub fn local_snapshot_path(local_data_root: &Path) -> PathBuf {
    local_data_root.join("threat-intel").join("snapshot.json")
}

fn local_feed_status_path(local_data_root: &Path) -> PathBuf {
    local_data_root
        .join("threat-intel")
        .join("feed-status.json")
}

fn local_runtime_state_path(local_data_root: &Path) -> PathBuf {
    local_data_root.join("threat-intel").join("node-state.json")
}

pub fn load_local_snapshot(local_data_root: &Path) -> Result<Option<ThreatSnapshot>, String> {
    let path = local_snapshot_path(local_data_root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read threat snapshot: {err}")),
    };
    let snapshot =
        serde_json::from_slice(&bytes).map_err(|err| format!("parse threat snapshot: {err}"))?;
    Ok(Some(snapshot))
}

pub fn persist_local_snapshot(
    local_data_root: &Path,
    snapshot: &ThreatSnapshot,
) -> Result<(), String> {
    let payload = serde_json::to_vec_pretty(snapshot)
        .map_err(|err| format!("serialize threat snapshot: {err}"))?;
    atomic_write(&local_snapshot_path(local_data_root), &payload)
}

pub fn load_local_feed_status(
    local_data_root: &Path,
) -> Result<Option<ThreatFeedRefreshState>, String> {
    read_json_file(
        local_feed_status_path(local_data_root),
        "threat feed status",
    )
}

pub fn persist_local_feed_status(
    local_data_root: &Path,
    state: &ThreatFeedRefreshState,
) -> Result<(), String> {
    write_json_file(
        local_feed_status_path(local_data_root),
        state,
        "threat feed status",
    )
}

pub fn load_local_runtime_state(
    local_data_root: &Path,
) -> Result<Option<ThreatLocalRuntimeState>, String> {
    read_json_file(
        local_runtime_state_path(local_data_root),
        "threat local runtime state",
    )
}

pub fn persist_local_runtime_state(
    local_data_root: &Path,
    state: &ThreatLocalRuntimeState,
) -> Result<(), String> {
    write_json_file(
        local_runtime_state_path(local_data_root),
        state,
        "threat local runtime state",
    )
}

pub fn load_cluster_snapshot(
    cluster_store: &ClusterStore,
) -> Result<Option<ThreatSnapshot>, String> {
    let Some(raw) = cluster_store.get_state_value(THREAT_INTEL_SNAPSHOT_KEY)? else {
        return Ok(None);
    };
    let snapshot = serde_json::from_slice(&raw)
        .map_err(|err| format!("parse replicated threat snapshot: {err}"))?;
    Ok(Some(snapshot))
}

pub fn load_cluster_feed_status(
    cluster_store: &ClusterStore,
) -> Result<Option<ThreatFeedRefreshState>, String> {
    let Some(raw) = cluster_store.get_state_value(THREAT_INTEL_FEED_STATUS_KEY)? else {
        return Ok(None);
    };
    let state = serde_json::from_slice(&raw)
        .map_err(|err| format!("parse replicated threat feed status: {err}"))?;
    Ok(Some(state))
}

pub fn load_effective_snapshot(
    cluster_store: Option<&ClusterStore>,
    local_data_root: &Path,
) -> Result<Option<ThreatSnapshot>, String> {
    if let Some(store) = cluster_store {
        if let Some(snapshot) = load_cluster_snapshot(store)? {
            persist_local_snapshot(local_data_root, &snapshot)?;
            return Ok(Some(snapshot));
        }
    }
    load_local_snapshot(local_data_root)
}

pub fn load_effective_feed_status(
    cluster_store: Option<&ClusterStore>,
    local_data_root: &Path,
    settings: &ThreatIntelSettings,
) -> Result<Option<ThreatFeedRefreshState>, String> {
    let cluster_state = if let Some(store) = cluster_store {
        load_cluster_feed_status(store)?
    } else {
        None
    };
    if let Some(state) = cluster_state.as_ref() {
        persist_local_feed_status(local_data_root, state)?;
    }
    let local_state = match cluster_state {
        Some(state) => Some(state),
        None => load_local_feed_status(local_data_root)?,
    };
    let snapshot = load_effective_snapshot(cluster_store, local_data_root)?;
    let effective = reconcile_feed_status_with_snapshot(local_state.clone(), snapshot, settings);
    if let Some(state) = effective.as_ref() {
        if local_state.as_ref() != Some(state) {
            persist_local_feed_status(local_data_root, state)?;
        }
    }
    Ok(effective)
}

fn reconcile_feed_status_with_snapshot(
    state: Option<ThreatFeedRefreshState>,
    snapshot: Option<ThreatSnapshot>,
    settings: &ThreatIntelSettings,
) -> Option<ThreatFeedRefreshState> {
    let now = unix_now();
    match (state, snapshot) {
        (Some(state), Some(snapshot)) if state.snapshot_version == snapshot.version => {
            Some(state_with_current_ages(&state, now))
        }
        (state, Some(snapshot)) if snapshot.version > 0 => Some(snapshot_only_feed_status(
            settings,
            &snapshot,
            now,
            state.as_ref(),
        )),
        (Some(state), Some(_)) => Some(state_with_current_ages(&state, now)),
        (Some(state), None) => Some(state_with_current_ages(&state, now)),
        (None, None) => None,
        (None, Some(_)) => None,
    }
}

fn snapshot_only_feed_status(
    settings: &ThreatIntelSettings,
    snapshot: &ThreatSnapshot,
    now: u64,
    previous_state: Option<&ThreatFeedRefreshState>,
) -> ThreatFeedRefreshState {
    ThreatFeedRefreshState {
        snapshot_version: snapshot.version,
        snapshot_generated_at: (snapshot.generated_at > 0).then_some(snapshot.generated_at),
        last_refresh_started_at: None,
        last_refresh_completed_at: None,
        last_successful_refresh_at: previous_state
            .filter(|state| state.snapshot_version == snapshot.version)
            .and_then(|state| state.last_successful_refresh_at),
        last_refresh_outcome: None,
        feeds: compute_snapshot_status(settings, snapshot, now),
    }
}

pub async fn publish_cluster_state(
    cluster: &ThreatManagerCluster,
    snapshot: Option<&ThreatSnapshot>,
    state: &ThreatFeedRefreshState,
) -> Result<(), String> {
    if let Some(snapshot) = snapshot {
        let payload = serde_json::to_vec(snapshot)
            .map_err(|err| format!("serialize threat snapshot: {err}"))?;
        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: THREAT_INTEL_SNAPSHOT_KEY.to_vec(),
                value: payload,
            })
            .await
            .map_err(|err| err.to_string())?;
    }

    let payload =
        serde_json::to_vec(state).map_err(|err| format!("serialize threat feed status: {err}"))?;
    cluster
        .raft
        .client_write(ClusterCommand::Put {
            key: THREAT_INTEL_FEED_STATUS_KEY.to_vec(),
            value: payload,
        })
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

pub fn compute_snapshot_status(
    settings: &ThreatIntelSettings,
    snapshot: &ThreatSnapshot,
    now: u64,
) -> Vec<ThreatFeedStatusItem> {
    [
        ("threatfox", settings.baseline_feeds.threatfox.enabled),
        ("urlhaus", settings.baseline_feeds.urlhaus.enabled),
        (
            "spamhaus_drop",
            settings.baseline_feeds.spamhaus_drop.enabled,
        ),
    ]
    .into_iter()
    .map(|(feed, enabled)| {
        let mut counts = ThreatFeedIndicatorCounts::default();
        for item in snapshot.items.iter().filter(|item| item.feed == feed) {
            match item.indicator_type {
                ThreatIndicatorType::Hostname => counts.hostname += 1,
                ThreatIndicatorType::Ip => counts.ip += 1,
            }
        }
        ThreatFeedStatusItem {
            feed: feed.to_string(),
            enabled,
            snapshot_age_seconds: enabled
                .then_some(now.saturating_sub(snapshot.generated_at))
                .filter(|_| snapshot.generated_at > 0),
            last_refresh_started_at: None,
            last_refresh_completed_at: None,
            last_successful_refresh_at: None,
            last_refresh_outcome: None,
            indicator_counts: counts,
        }
    })
    .collect()
}

pub fn refresh_from_payloads(
    settings: &ThreatIntelSettings,
    now: u64,
    previous_snapshot: Option<&ThreatSnapshot>,
    previous_state: Option<&ThreatFeedRefreshState>,
    payloads: ThreatFeedPayloads,
) -> Result<ThreatRefreshResult, String> {
    let started_at = Some(now);
    let completed_at = Some(now);

    let mut merged_items = Vec::<ThreatIndicatorSnapshotItem>::new();
    let mut refresh_error = None::<String>;

    if settings.baseline_feeds.threatfox.enabled {
        match payloads.threatfox {
            Some(payload) => match ThreatFoxAdapter.snapshot_from_payload(&payload, 0, now) {
                Ok(snapshot) => merged_items.extend(snapshot.items),
                Err(err) => refresh_error = Some(err),
            },
            None => refresh_error = Some("missing threatfox payload".to_string()),
        }
    }
    if refresh_error.is_none() && settings.baseline_feeds.urlhaus.enabled {
        match payloads.urlhaus {
            Some(payload) => match UrlhausAdapter.snapshot_from_payload(&payload, 0, now) {
                Ok(snapshot) => merged_items.extend(snapshot.items),
                Err(err) => refresh_error = Some(err),
            },
            None => refresh_error = Some("missing urlhaus payload".to_string()),
        }
    }
    if refresh_error.is_none() && settings.baseline_feeds.spamhaus_drop.enabled {
        match payloads.spamhaus_drop {
            Some(payload) => match SpamhausDropAdapter.snapshot_from_payload(&payload, 0, now) {
                Ok(snapshot) => merged_items.extend(snapshot.items),
                Err(err) => refresh_error = Some(err),
            },
            None => refresh_error = Some("missing spamhaus_drop payload".to_string()),
        }
    }

    if let Some(err) = refresh_error {
        warn!(error = %err, "threat-intel refresh failed while parsing or normalizing feeds");
        let snapshot = previous_snapshot
            .cloned()
            .unwrap_or_else(|| ThreatSnapshot::new(0, 0, Vec::new()));
        let state = build_refresh_state(
            settings,
            &snapshot,
            now,
            started_at,
            completed_at,
            previous_state.and_then(|state| state.last_successful_refresh_at),
            Some(ThreatRefreshOutcome::Failed),
        );
        return Ok(ThreatRefreshResult { snapshot, state });
    }

    let candidate_snapshot = ThreatSnapshot::new(0, now, merged_items);
    let snapshot = match previous_snapshot {
        Some(previous) if previous.items == candidate_snapshot.items => {
            ThreatSnapshot::new(previous.version, now, candidate_snapshot.items.clone())
        }
        Some(previous) => ThreatSnapshot::new(
            previous.version.saturating_add(1),
            now,
            candidate_snapshot.items.clone(),
        ),
        None => ThreatSnapshot::new(1, now, candidate_snapshot.items),
    };

    let state = build_refresh_state(
        settings,
        &snapshot,
        now,
        started_at,
        completed_at,
        completed_at,
        Some(ThreatRefreshOutcome::Success),
    );

    Ok(ThreatRefreshResult { snapshot, state })
}

pub fn set_snapshot_metrics(metrics: &Metrics, state: &ThreatFeedRefreshState) {
    metrics.set_threat_cluster_snapshot_version(state.snapshot_version);
    for feed in &state.feeds {
        metrics.set_threat_feed_snapshot_age_seconds(
            &feed.feed,
            feed.snapshot_age_seconds.unwrap_or(0),
        );
        metrics.set_threat_feed_indicators(&feed.feed, "hostname", feed.indicator_counts.hostname);
        metrics.set_threat_feed_indicators(&feed.feed, "ip", feed.indicator_counts.ip);
    }
}

pub fn record_refresh_metrics(metrics: &Metrics, state: &ThreatFeedRefreshState) {
    for feed in &state.feeds {
        if let Some(outcome) = feed.last_refresh_outcome {
            metrics.observe_threat_feed_refresh(&feed.feed, outcome.as_str());
        }
    }
}

pub fn spawn_refresh_loop(config: ThreatManagerConfig) {
    tokio::spawn(async move {
        let client = match Client::builder().timeout(config.http_timeout).build() {
            Ok(client) => client,
            Err(err) => {
                warn!(error = %err, "failed to build threat-intel http client");
                return;
            }
        };
        let mut interval = tokio::time::interval(config.poll_interval);
        loop {
            interval.tick().await;
            if let Err(err) = refresh_once(&config, &client).await {
                warn!(error = %err, "threat-intel refresh tick failed");
            }
        }
    });
}

async fn refresh_once(config: &ThreatManagerConfig, client: &Client) -> Result<(), String> {
    let cluster_store = config.cluster.as_ref().map(|cluster| &cluster.store);
    let (settings, _) = load_settings(cluster_store, &config.local_data_root)?;
    let Some(cluster) = config.cluster.as_ref() else {
        return refresh_local_once(config, client, &settings, None).await;
    };
    if !is_cluster_leader(cluster) {
        if let Some(state) =
            load_effective_feed_status(Some(&cluster.store), &config.local_data_root, &settings)?
        {
            set_snapshot_metrics(&config.metrics, &state);
        }
        return Ok(());
    }

    let previous_snapshot = load_effective_snapshot(Some(&cluster.store), &config.local_data_root)?;
    refresh_local_once(config, client, &settings, previous_snapshot.as_ref()).await
}

async fn refresh_local_once(
    config: &ThreatManagerConfig,
    client: &Client,
    settings: &ThreatIntelSettings,
    previous_snapshot: Option<&ThreatSnapshot>,
) -> Result<(), String> {
    if !settings.enabled {
        return Ok(());
    }
    let now = unix_now();
    let previous_state = load_local_feed_status(&config.local_data_root)?;
    if !refresh_due(settings, previous_state.as_ref(), now) {
        if let Some(state) = previous_state.as_ref() {
            let current = state_with_current_ages(state, now);
            set_snapshot_metrics(&config.metrics, &current);
        }
        return Ok(());
    }

    let result = match fetch_enabled_payloads(client, settings).await {
        Ok(payloads) => refresh_from_payloads(
            settings,
            now,
            previous_snapshot,
            previous_state.as_ref(),
            payloads,
        )?,
        Err(err) => {
            warn!(error = %err, "threat-intel refresh failed while fetching feeds");
            failure_refresh_result(settings, now, previous_snapshot, previous_state.as_ref())
        }
    };

    persist_local_snapshot(&config.local_data_root, &result.snapshot)?;
    persist_local_feed_status(&config.local_data_root, &result.state)?;
    if let Some(cluster) = config.cluster.as_ref() {
        let snapshot = (result.snapshot.version > 0).then_some(&result.snapshot);
        publish_cluster_state(cluster, snapshot, &result.state).await?;
    }
    record_refresh_metrics(&config.metrics, &result.state);
    set_snapshot_metrics(&config.metrics, &result.state);
    Ok(())
}

fn refresh_due(
    settings: &ThreatIntelSettings,
    state: Option<&ThreatFeedRefreshState>,
    now: u64,
) -> bool {
    let mut min_interval = u64::MAX;
    if settings.baseline_feeds.threatfox.enabled {
        min_interval = min_interval.min(settings.baseline_feeds.threatfox.refresh_interval_secs);
    }
    if settings.baseline_feeds.urlhaus.enabled {
        min_interval = min_interval.min(settings.baseline_feeds.urlhaus.refresh_interval_secs);
    }
    if settings.baseline_feeds.spamhaus_drop.enabled {
        min_interval =
            min_interval.min(settings.baseline_feeds.spamhaus_drop.refresh_interval_secs);
    }
    if min_interval == u64::MAX {
        return false;
    }
    if state.and_then(|state| state.last_refresh_outcome) == Some(ThreatRefreshOutcome::Failed) {
        let last_completed_at = state
            .and_then(|state| state.last_refresh_completed_at)
            .unwrap_or(0);
        return now.saturating_sub(last_completed_at)
            >= FAILED_REFRESH_RETRY_SECS.min(min_interval);
    }
    let last_successful_at = state
        .and_then(|state| state.last_successful_refresh_at)
        .or_else(|| state.and_then(|state| state.last_refresh_completed_at))
        .unwrap_or(0);
    now.saturating_sub(last_successful_at) >= min_interval
}

fn state_with_current_ages(state: &ThreatFeedRefreshState, now: u64) -> ThreatFeedRefreshState {
    let mut current = state.clone();
    if let Some(generated_at) = state.snapshot_generated_at {
        for feed in &mut current.feeds {
            if feed.enabled {
                feed.snapshot_age_seconds = Some(now.saturating_sub(generated_at));
            }
        }
    }
    current
}

async fn fetch_enabled_payloads(
    client: &Client,
    settings: &ThreatIntelSettings,
) -> Result<ThreatFeedPayloads, String> {
    let mut payloads = ThreatFeedPayloads::default();
    if settings.baseline_feeds.threatfox.enabled {
        payloads.threatfox = Some(fetch_feed(client, THREATFOX_RECENT_URL).await?);
    }
    if settings.baseline_feeds.urlhaus.enabled {
        payloads.urlhaus = Some(fetch_feed(client, URLHAUS_TEXT_URL).await?);
    }
    if settings.baseline_feeds.spamhaus_drop.enabled {
        payloads.spamhaus_drop = Some(fetch_feed(client, SPAMHAUS_DROP_V4_URL).await?);
    }
    Ok(payloads)
}

async fn fetch_feed(client: &Client, url: &str) -> Result<String, String> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("fetch {url}: {err}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("fetch {url}: http {status}"));
    }
    response
        .text()
        .await
        .map_err(|err| format!("read {url}: {err}"))
}

fn build_refresh_state(
    settings: &ThreatIntelSettings,
    snapshot: &ThreatSnapshot,
    now: u64,
    last_refresh_started_at: Option<u64>,
    last_refresh_completed_at: Option<u64>,
    last_successful_refresh_at: Option<u64>,
    last_refresh_outcome: Option<ThreatRefreshOutcome>,
) -> ThreatFeedRefreshState {
    let mut feeds = compute_snapshot_status(settings, snapshot, now);
    for feed in &mut feeds {
        feed.last_refresh_started_at = last_refresh_started_at;
        feed.last_refresh_completed_at = last_refresh_completed_at;
        feed.last_successful_refresh_at = last_successful_refresh_at;
        feed.last_refresh_outcome = last_refresh_outcome;
    }
    ThreatFeedRefreshState {
        snapshot_version: snapshot.version,
        snapshot_generated_at: (snapshot.generated_at > 0).then_some(snapshot.generated_at),
        last_refresh_started_at,
        last_refresh_completed_at,
        last_successful_refresh_at,
        last_refresh_outcome,
        feeds,
    }
}

fn failure_refresh_result(
    settings: &ThreatIntelSettings,
    now: u64,
    previous_snapshot: Option<&ThreatSnapshot>,
    previous_state: Option<&ThreatFeedRefreshState>,
) -> ThreatRefreshResult {
    let snapshot = previous_snapshot
        .cloned()
        .unwrap_or_else(|| ThreatSnapshot::new(0, 0, Vec::new()));
    let state = build_refresh_state(
        settings,
        &snapshot,
        now,
        Some(now),
        Some(now),
        previous_state.and_then(|state| state.last_successful_refresh_at),
        Some(ThreatRefreshOutcome::Failed),
    );
    ThreatRefreshResult { snapshot, state }
}

fn is_cluster_leader(cluster: &ThreatManagerCluster) -> bool {
    let metrics = cluster.raft.metrics();
    let snapshot = metrics.borrow().clone();
    snapshot.current_leader == Some(snapshot.id)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
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

fn write_json_file<T: Serialize>(path: PathBuf, value: &T, label: &str) -> Result<(), String> {
    let payload =
        serde_json::to_vec_pretty(value).map_err(|err| format!("serialize {label}: {err}"))?;
    atomic_write(&path, &payload)
}

fn read_json_file<T: for<'de> Deserialize<'de>>(
    path: PathBuf,
    label: &str,
) -> Result<Option<T>, String> {
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read {label}: {err}")),
    };
    let value = serde_json::from_slice(&bytes).map_err(|err| format!("parse {label}: {err}"))?;
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::controlplane::threat_intel::feeds::{snapshot_with_cidr, snapshot_with_hostname};
    use crate::controlplane::threat_intel::settings::ThreatIntelSettings;
    use crate::controlplane::threat_intel::types::ThreatSeverity;
    use uuid::Uuid;

    use super::{
        compute_snapshot_status, load_local_feed_status, persist_local_feed_status,
        persist_local_snapshot, refresh_from_payloads, ThreatFeedPayloads, ThreatFeedRefreshState,
        ThreatRefreshOutcome,
    };

    #[test]
    fn threat_feed_state_persists_snapshot_and_status() {
        let root = temp_root();
        let snapshot = snapshot_with_hostname("bad.example.com", ThreatSeverity::High, "threatfox");
        let state = ThreatFeedRefreshState {
            snapshot_version: snapshot.version,
            snapshot_generated_at: Some(snapshot.generated_at),
            last_refresh_started_at: Some(100),
            last_refresh_completed_at: Some(110),
            last_successful_refresh_at: Some(110),
            last_refresh_outcome: Some(ThreatRefreshOutcome::Success),
            feeds: compute_snapshot_status(&ThreatIntelSettings::default(), &snapshot, 120),
        };

        persist_local_snapshot(&root, &snapshot).expect("persist snapshot");
        persist_local_feed_status(&root, &state).expect("persist state");

        let loaded = load_local_feed_status(&root)
            .expect("load state")
            .expect("persisted state");

        assert_eq!(loaded.snapshot_version, snapshot.version);
        assert_eq!(
            loaded.last_refresh_outcome,
            Some(ThreatRefreshOutcome::Success)
        );
        assert!(loaded
            .feeds
            .iter()
            .any(|feed| feed.feed == "threatfox" && feed.indicator_counts.hostname == 1));
    }

    #[test]
    fn refresh_from_payloads_merges_feeds_and_tracks_indicator_counts() {
        let settings = ThreatIntelSettings::default();
        let result = refresh_from_payloads(
            &settings,
            200,
            None,
            None,
            ThreatFeedPayloads {
                threatfox: Some(
                    r#"{
                        "data": [
                            {
                                "ioc": "bad.example.com",
                                "ioc_type": "domain",
                                "threat_type": "botnet_cc",
                                "confidence_level": 85,
                                "first_seen": "2025-03-13 10:20:00 UTC"
                            }
                        ]
                    }"#
                    .to_string(),
                ),
                urlhaus: Some("https://drop.bad.example.net/payload\n".to_string()),
                spamhaus_drop: Some(
                    "{\"cidr\":\"203.0.113.0/24\",\"sblid\":\"SBL12345\",\"rir\":\"arin\"}\n"
                        .to_string(),
                ),
            },
        )
        .expect("refresh result");

        assert_eq!(result.snapshot.version, 1);
        assert_eq!(result.snapshot.items.len(), 3);
        assert!(result
            .state
            .feeds
            .iter()
            .any(|feed| feed.feed == "threatfox" && feed.indicator_counts.hostname == 1));
        assert!(result
            .state
            .feeds
            .iter()
            .any(|feed| feed.feed == "spamhaus_drop" && feed.indicator_counts.ip == 1));
    }

    #[test]
    fn refresh_from_payloads_keeps_last_good_snapshot_on_failure() {
        let settings = ThreatIntelSettings::default();
        let previous =
            snapshot_with_cidr("203.0.113.0/24", ThreatSeverity::Critical, "spamhaus_drop");

        let result = refresh_from_payloads(
            &settings,
            300,
            Some(&previous),
            None,
            ThreatFeedPayloads {
                threatfox: Some("{not-json".to_string()),
                urlhaus: Some("https://drop.bad.example.net/payload\n".to_string()),
                spamhaus_drop: Some(
                    "{\"cidr\":\"198.51.100.0/24\",\"sblid\":\"SBL54321\",\"rir\":\"arin\"}\n"
                        .to_string(),
                ),
            },
        )
        .expect("refresh result");

        assert_eq!(result.snapshot, previous);
        assert_eq!(result.state.snapshot_version, previous.version);
        assert_eq!(
            result.state.last_refresh_outcome,
            Some(ThreatRefreshOutcome::Failed)
        );
    }

    #[test]
    fn failed_refreshes_retry_before_full_feed_interval() {
        let settings = ThreatIntelSettings::default();
        let state = ThreatFeedRefreshState {
            snapshot_version: 0,
            snapshot_generated_at: None,
            last_refresh_started_at: Some(100),
            last_refresh_completed_at: Some(100),
            last_successful_refresh_at: None,
            last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
            feeds: Vec::new(),
        };

        assert!(!super::refresh_due(&settings, Some(&state), 150));
        assert!(super::refresh_due(&settings, Some(&state), 161));
    }

    #[test]
    fn load_effective_feed_status_repairs_stale_local_status_from_newer_snapshot() {
        let root = temp_root();
        let snapshot = snapshot_with_hostname("bad.example.com", ThreatSeverity::High, "threatfox");
        persist_local_snapshot(&root, &snapshot).expect("persist snapshot");
        persist_local_feed_status(
            &root,
            &ThreatFeedRefreshState {
                snapshot_version: 0,
                snapshot_generated_at: None,
                last_refresh_started_at: Some(100),
                last_refresh_completed_at: Some(100),
                last_successful_refresh_at: None,
                last_refresh_outcome: Some(ThreatRefreshOutcome::Failed),
                feeds: Vec::new(),
            },
        )
        .expect("persist stale state");

        let loaded =
            super::load_effective_feed_status(None, &root, &ThreatIntelSettings::default())
                .expect("load state")
                .expect("effective state");

        assert_eq!(loaded.snapshot_version, snapshot.version);
        assert_eq!(loaded.snapshot_generated_at, Some(snapshot.generated_at));
        assert!(loaded
            .feeds
            .iter()
            .any(|feed| feed.feed == "threatfox" && feed.indicator_counts.hostname == 1));
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("threat-manager-{}", Uuid::new_v4()))
    }
}
