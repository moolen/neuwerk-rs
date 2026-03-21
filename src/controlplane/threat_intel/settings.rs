use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub use super::types::ThreatSeverity;

pub const THREAT_INTEL_SETTINGS_KEY: &[u8] = b"settings/threat_intel/config";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ThreatIntelSettings {
    pub enabled: bool,
    pub alert_threshold: ThreatSeverity,
    pub baseline_feeds: ThreatBaselineFeeds,
    pub remote_enrichment: ThreatRemoteEnrichmentSettings,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(default)]
pub struct ThreatBaselineFeeds {
    pub threatfox: ThreatFeedToggle,
    pub urlhaus: ThreatFeedToggle,
    pub spamhaus_drop: ThreatFeedToggle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ThreatFeedToggle {
    pub enabled: bool,
    pub refresh_interval_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(default)]
pub struct ThreatRemoteEnrichmentSettings {
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSettingsSource {
    Cluster,
    Local,
}

impl ThreatSettingsSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cluster => "cluster",
            Self::Local => "local",
        }
    }
}

impl Default for ThreatIntelSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_threshold: ThreatSeverity::High,
            baseline_feeds: ThreatBaselineFeeds::default(),
            remote_enrichment: ThreatRemoteEnrichmentSettings::default(),
        }
    }
}

impl Default for ThreatFeedToggle {
    fn default() -> Self {
        Self {
            enabled: true,
            refresh_interval_secs: 3600,
        }
    }
}

impl ThreatIntelSettings {
    pub fn validate_refresh_interval_secs(refresh_interval_secs: u64) -> Result<(), String> {
        if refresh_interval_secs < 1 {
            return Err("refresh_interval_secs must be >= 1".to_string());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        Self::validate_refresh_interval_secs(self.baseline_feeds.threatfox.refresh_interval_secs)?;
        Self::validate_refresh_interval_secs(self.baseline_feeds.urlhaus.refresh_interval_secs)?;
        Self::validate_refresh_interval_secs(
            self.baseline_feeds.spamhaus_drop.refresh_interval_secs,
        )?;
        Ok(())
    }
}

pub fn load_settings(
    cluster_store: Option<&ClusterStore>,
    local_data_root: &Path,
) -> Result<(ThreatIntelSettings, Option<ThreatSettingsSource>), String> {
    if let Some(store) = cluster_store {
        let value = store.get_state_value(THREAT_INTEL_SETTINGS_KEY)?;
        let Some(value) = value else {
            return Ok((ThreatIntelSettings::default(), None));
        };
        let settings = parse_settings_value(&value)?;
        return Ok((settings, Some(ThreatSettingsSource::Cluster)));
    }

    let path = local_settings_path(local_data_root);
    if !path.exists() {
        return Ok((ThreatIntelSettings::default(), None));
    }
    let bytes = fs::read(path).map_err(|err| format!("read threat intel settings: {err}"))?;
    let settings = parse_settings_value(&bytes)?;
    Ok((settings, Some(ThreatSettingsSource::Local)))
}

pub async fn persist_settings_cluster(
    raft: &openraft::Raft<ClusterTypeConfig>,
    settings: &ThreatIntelSettings,
) -> Result<(), String> {
    settings.validate()?;
    let value = encode_settings_value(settings)?;
    raft.client_write(ClusterCommand::Put {
        key: THREAT_INTEL_SETTINGS_KEY.to_vec(),
        value,
    })
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

pub fn persist_settings_local(
    local_data_root: &Path,
    settings: &ThreatIntelSettings,
) -> Result<(), String> {
    settings.validate()?;
    let path = local_settings_path(local_data_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("prepare threat intel settings directory: {err}"))?;
    }
    let value = encode_settings_value(settings)?;
    fs::write(path, value).map_err(|err| format!("write threat intel settings: {err}"))?;
    Ok(())
}

fn local_settings_path(local_data_root: &Path) -> PathBuf {
    local_data_root.join("settings").join("threat-intel.json")
}

fn encode_settings_value(settings: &ThreatIntelSettings) -> Result<Vec<u8>, String> {
    serde_json::to_vec(settings).map_err(|err| format!("serialize threat intel settings: {err}"))
}

fn parse_settings_value(raw: &[u8]) -> Result<ThreatIntelSettings, String> {
    serde_json::from_slice(raw).map_err(|err| format!("invalid threat intel settings value: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{parse_settings_value, ThreatIntelSettings, ThreatSeverity};

    #[test]
    fn threat_settings_default_matches_spec() {
        let settings = ThreatIntelSettings::default();
        assert!(settings.enabled);
        assert_eq!(settings.alert_threshold, ThreatSeverity::High);
        assert!(settings.baseline_feeds.threatfox.enabled);
        assert!(settings.baseline_feeds.urlhaus.enabled);
        assert!(settings.baseline_feeds.spamhaus_drop.enabled);
        assert!(!settings.remote_enrichment.enabled);
    }

    #[test]
    fn threat_settings_reject_empty_refresh_interval() {
        let err = ThreatIntelSettings::validate_refresh_interval_secs(0).unwrap_err();
        assert!(err.contains(">= 1"));
    }

    #[test]
    fn parse_settings_value_accepts_partial_payload_with_defaults() {
        let settings = parse_settings_value(br#"{"enabled":false}"#).unwrap();
        assert!(!settings.enabled);
        assert_eq!(settings.alert_threshold, ThreatSeverity::High);
        assert!(settings.baseline_feeds.threatfox.enabled);
        assert!(settings.baseline_feeds.urlhaus.enabled);
        assert!(settings.baseline_feeds.spamhaus_drop.enabled);
        assert!(!settings.remote_enrichment.enabled);
    }
}
