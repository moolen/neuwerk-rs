use std::collections::HashSet;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

use super::types::ThreatIndicatorType;

pub const THREAT_INTEL_SILENCES_KEY: &[u8] = b"settings/threat_intel/silences";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSilenceSource {
    Cluster,
    Local,
}

impl ThreatSilenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cluster => "cluster",
            Self::Local => "local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSilenceKind {
    Exact,
    HostnameRegex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreatSilenceEntry {
    pub id: String,
    pub kind: ThreatSilenceKind,
    pub indicator_type: Option<ThreatIndicatorType>,
    pub value: String,
    pub reason: Option<String>,
    pub created_at: u64,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(default)]
pub struct ThreatSilenceList {
    pub items: Vec<ThreatSilenceEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreatSilenceMatcher {
    exact_hostnames: HashSet<String>,
    exact_ips: HashSet<String>,
    hostname_regexes: Vec<Regex>,
}

impl ThreatSilenceEntry {
    pub fn exact(
        indicator_type: ThreatIndicatorType,
        value: String,
        reason: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: ThreatSilenceKind::Exact,
            indicator_type: Some(indicator_type),
            value,
            reason,
            created_at: 0,
            created_by: None,
        }
    }

    pub fn hostname_regex(value: String, reason: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            kind: ThreatSilenceKind::HostnameRegex,
            indicator_type: None,
            value,
            reason,
            created_at: 0,
            created_by: None,
        }
    }

    pub fn normalized(mut self) -> Result<Self, String> {
        self.value = match self.kind {
            ThreatSilenceKind::Exact => {
                let indicator_type = self.indicator_type.ok_or_else(|| {
                    "exact threat silence requires indicator_type".to_string()
                })?;
                normalize_exact_value(indicator_type, &self.value)?
            }
            ThreatSilenceKind::HostnameRegex => {
                if self.indicator_type == Some(ThreatIndicatorType::Ip) {
                    return Err(
                        "hostname_regex threat silence cannot target ip indicators".to_string(),
                    );
                }
                self.indicator_type = None;
                compile_hostname_regex(&self.value)?.as_str().to_string()
            }
        };
        self.reason = self
            .reason
            .take()
            .map(|reason| reason.trim().to_string())
            .filter(|reason| !reason.is_empty());
        Ok(self)
    }
}

impl ThreatSilenceList {
    pub fn validate(&self) -> Result<(), String> {
        ThreatSilenceMatcher::compile(self).map(|_| ())
    }
}

impl ThreatSilenceMatcher {
    pub fn compile(list: &ThreatSilenceList) -> Result<Self, String> {
        let mut matcher = Self::default();
        for entry in &list.items {
            match entry.kind {
                ThreatSilenceKind::Exact => {
                    let indicator_type = entry.indicator_type.ok_or_else(|| {
                        "exact threat silence requires indicator_type".to_string()
                    })?;
                    let value = normalize_exact_value(indicator_type, &entry.value)?;
                    match indicator_type {
                        ThreatIndicatorType::Hostname => {
                            matcher.exact_hostnames.insert(value);
                        }
                        ThreatIndicatorType::Ip => {
                            matcher.exact_ips.insert(value);
                        }
                    }
                }
                ThreatSilenceKind::HostnameRegex => {
                    if entry.indicator_type.is_some_and(|kind| kind != ThreatIndicatorType::Hostname)
                    {
                        return Err(
                            "hostname_regex threat silence cannot target ip indicators"
                                .to_string(),
                        );
                    }
                    matcher
                        .hostname_regexes
                        .push(compile_hostname_regex(&entry.value)?);
                }
            }
        }
        Ok(matcher)
    }

    pub fn matches(&self, indicator_type: ThreatIndicatorType, indicator: &str) -> bool {
        match indicator_type {
            ThreatIndicatorType::Hostname => {
                let normalized = normalize_hostname(indicator);
                if normalized.is_empty() {
                    return false;
                }
                self.exact_hostnames.contains(&normalized)
                    || self
                        .hostname_regexes
                        .iter()
                        .any(|pattern| pattern.is_match(&normalized))
            }
            ThreatIndicatorType::Ip => normalize_ip(indicator)
                .ok()
                .is_some_and(|value| self.exact_ips.contains(&value)),
        }
    }
}

pub fn load_silences(
    cluster_store: Option<&ClusterStore>,
    local_data_root: &Path,
) -> Result<(ThreatSilenceList, Option<ThreatSilenceSource>), String> {
    if let Some(store) = cluster_store {
        let value = store.get_state_value(THREAT_INTEL_SILENCES_KEY)?;
        let Some(value) = value else {
            return Ok((ThreatSilenceList::default(), None));
        };
        let silences = parse_silences_value(&value)?;
        silences.validate()?;
        return Ok((silences, Some(ThreatSilenceSource::Cluster)));
    }

    let path = local_silences_path(local_data_root);
    if !path.exists() {
        return Ok((ThreatSilenceList::default(), None));
    }
    let bytes = fs::read(path).map_err(|err| format!("read threat silences: {err}"))?;
    let silences = parse_silences_value(&bytes)?;
    silences.validate()?;
    Ok((silences, Some(ThreatSilenceSource::Local)))
}

pub async fn persist_silences_cluster(
    raft: &openraft::Raft<ClusterTypeConfig>,
    silences: &ThreatSilenceList,
) -> Result<(), String> {
    silences.validate()?;
    let value = encode_silences_value(silences)?;
    raft.client_write(ClusterCommand::Put {
        key: THREAT_INTEL_SILENCES_KEY.to_vec(),
        value,
    })
    .await
    .map_err(|err| err.to_string())?;
    Ok(())
}

pub fn persist_silences_local(
    local_data_root: &Path,
    silences: &ThreatSilenceList,
) -> Result<(), String> {
    silences.validate()?;
    let path = local_silences_path(local_data_root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("prepare threat silences directory: {err}"))?;
    }
    let value = encode_silences_value(silences)?;
    fs::write(path, value).map_err(|err| format!("write threat silences: {err}"))?;
    Ok(())
}

fn local_silences_path(local_data_root: &Path) -> PathBuf {
    local_data_root.join("settings").join("threat-intel-silences.json")
}

fn encode_silences_value(silences: &ThreatSilenceList) -> Result<Vec<u8>, String> {
    serde_json::to_vec(silences).map_err(|err| format!("serialize threat silences: {err}"))
}

fn parse_silences_value(raw: &[u8]) -> Result<ThreatSilenceList, String> {
    serde_json::from_slice(raw).map_err(|err| format!("invalid threat silences value: {err}"))
}

fn normalize_exact_value(indicator_type: ThreatIndicatorType, value: &str) -> Result<String, String> {
    match indicator_type {
        ThreatIndicatorType::Hostname => {
            let normalized = normalize_hostname(value);
            if normalized.is_empty() {
                return Err("hostname silence value cannot be empty".to_string());
            }
            Ok(normalized)
        }
        ThreatIndicatorType::Ip => normalize_ip(value),
    }
}

fn compile_hostname_regex(value: &str) -> Result<Regex, String> {
    let pattern = value.trim();
    if pattern.is_empty() {
        return Err("hostname regex silence value cannot be empty".to_string());
    }
    Regex::new(pattern).map_err(|err| format!("invalid hostname regex silence: {err}"))
}

fn normalize_hostname(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_ip(value: &str) -> Result<String, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map(|addr| addr.to_string())
        .map_err(|err| format!("invalid ipv4 silence value: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ThreatSilenceEntry, ThreatSilenceKind, ThreatSilenceList, ThreatSilenceMatcher,
    };
    use crate::controlplane::threat_intel::types::ThreatIndicatorType;

    #[test]
    fn threat_silence_exact_hostname_matches_normalized_hostnames() {
        let silences = ThreatSilenceList {
            items: vec![ThreatSilenceEntry::exact(
                ThreatIndicatorType::Hostname,
                "Bad.Example.com.".to_string(),
                None,
            )],
        };

        let matcher = ThreatSilenceMatcher::compile(&silences).expect("compile");

        assert!(matcher.matches(ThreatIndicatorType::Hostname, "bad.example.com"));
    }

    #[test]
    fn threat_silence_exact_ip_matches_canonical_ip_indicators() {
        let silences = ThreatSilenceList {
            items: vec![ThreatSilenceEntry::exact(
                ThreatIndicatorType::Ip,
                " 203.0.113.10 ".to_string(),
                None,
            )],
        };

        let matcher = ThreatSilenceMatcher::compile(&silences).expect("compile");

        assert!(matcher.matches(ThreatIndicatorType::Ip, "203.0.113.10"));
    }

    #[test]
    fn threat_silence_hostname_regex_matches_normalized_hostname_only() {
        let silences = ThreatSilenceList {
            items: vec![ThreatSilenceEntry::hostname_regex(
                "^.*\\.example\\.com$".to_string(),
                None,
            )],
        };

        let matcher = ThreatSilenceMatcher::compile(&silences).expect("compile");

        assert!(matcher.matches(ThreatIndicatorType::Hostname, "bad.example.com"));
        assert!(!matcher.matches(ThreatIndicatorType::Ip, "203.0.113.10"));
    }

    #[test]
    fn threat_silence_rejects_invalid_hostname_regex_patterns() {
        let silences = ThreatSilenceList {
            items: vec![ThreatSilenceEntry {
                id: "test".to_string(),
                kind: ThreatSilenceKind::HostnameRegex,
                indicator_type: None,
                value: "[unclosed".to_string(),
                reason: None,
                created_at: 1,
                created_by: None,
            }],
        };

        let err = ThreatSilenceMatcher::compile(&silences).unwrap_err();
        assert!(err.contains("regex"));
    }
}
