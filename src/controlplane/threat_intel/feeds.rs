use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{format_description, OffsetDateTime, PrimitiveDateTime};

use super::types::{ThreatIndicatorType, ThreatSeverity};

pub const THREATFOX_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
const URLHAUS_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
const FIXTURE_SNAPSHOT_VERSION: u64 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIndicatorSnapshotItem {
    pub indicator: String,
    pub indicator_type: ThreatIndicatorType,
    pub feed: String,
    pub severity: ThreatSeverity,
    pub confidence: Option<u8>,
    pub tags: Vec<String>,
    pub reference_url: Option<String>,
    pub feed_first_seen: Option<u64>,
    pub feed_last_seen: Option<u64>,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatSnapshot {
    pub version: u64,
    pub generated_at: u64,
    pub items: Vec<ThreatIndicatorSnapshotItem>,
}

impl ThreatSnapshot {
    pub fn new(version: u64, generated_at: u64, items: Vec<ThreatIndicatorSnapshotItem>) -> Self {
        let mut normalized = items
            .into_iter()
            .filter_map(normalize_snapshot_item)
            .collect::<Vec<_>>();
        normalized.sort_unstable_by(|left, right| {
            left.feed
                .cmp(&right.feed)
                .then_with(|| left.indicator.cmp(&right.indicator))
                .then_with(|| {
                    indicator_type_rank(left.indicator_type)
                        .cmp(&indicator_type_rank(right.indicator_type))
                })
        });
        normalized.dedup();
        Self {
            version,
            generated_at: if generated_at == 0 {
                derive_generated_at(&normalized)
            } else {
                generated_at
            },
            items: normalized,
        }
    }
}

pub trait ThreatFeedAdapter {
    fn feed_name(&self) -> &'static str;

    fn snapshot_from_payload(
        &self,
        payload: &str,
        version: u64,
        generated_at: u64,
    ) -> Result<ThreatSnapshot, String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ThreatFoxAdapter;

#[derive(Debug, Clone, Copy, Default)]
pub struct UrlhausAdapter;

#[derive(Debug, Clone, Copy, Default)]
pub struct SpamhausDropAdapter;

pub fn parse_threatfox_fixture(payload: &str) -> Result<ThreatSnapshot, String> {
    ThreatFoxAdapter.snapshot_from_payload(payload, FIXTURE_SNAPSHOT_VERSION, 0)
}

pub fn parse_urlhaus_fixture(payload: &str) -> Result<ThreatSnapshot, String> {
    UrlhausAdapter.snapshot_from_payload(payload, FIXTURE_SNAPSHOT_VERSION, 0)
}

pub fn parse_spamhaus_drop_fixture(payload: &str) -> Result<ThreatSnapshot, String> {
    SpamhausDropAdapter.snapshot_from_payload(payload, FIXTURE_SNAPSHOT_VERSION, 0)
}

#[cfg(test)]
pub(crate) fn snapshot_with_hostname(
    hostname: &str,
    severity: ThreatSeverity,
    feed: &str,
) -> ThreatSnapshot {
    ThreatSnapshot::new(
        FIXTURE_SNAPSHOT_VERSION,
        1,
        vec![ThreatIndicatorSnapshotItem {
            indicator: hostname.to_string(),
            indicator_type: ThreatIndicatorType::Hostname,
            feed: feed.to_string(),
            severity,
            confidence: Some(80),
            tags: Vec::new(),
            reference_url: None,
            feed_first_seen: Some(1),
            feed_last_seen: Some(1),
            expires_at: None,
        }],
    )
}

#[cfg(test)]
pub(crate) fn snapshot_with_cidr(
    cidr: &str,
    severity: ThreatSeverity,
    feed: &str,
) -> ThreatSnapshot {
    ThreatSnapshot::new(
        FIXTURE_SNAPSHOT_VERSION,
        1,
        vec![ThreatIndicatorSnapshotItem {
            indicator: cidr.to_string(),
            indicator_type: ThreatIndicatorType::Ip,
            feed: feed.to_string(),
            severity,
            confidence: Some(100),
            tags: Vec::new(),
            reference_url: None,
            feed_first_seen: Some(1),
            feed_last_seen: Some(1),
            expires_at: None,
        }],
    )
}

impl ThreatFeedAdapter for ThreatFoxAdapter {
    fn feed_name(&self) -> &'static str {
        "threatfox"
    }

    fn snapshot_from_payload(
        &self,
        payload: &str,
        version: u64,
        generated_at: u64,
    ) -> Result<ThreatSnapshot, String> {
        let response: ThreatFoxResponse = serde_json::from_str(payload)
            .map_err(|err| format!("parse threatfox payload: {err}"))?;
        let mut items = Vec::new();
        for entry in response.data {
            if let Some(item) = threatfox_entry_to_item(entry, self.feed_name())? {
                items.push(item);
            }
        }
        Ok(ThreatSnapshot::new(version, generated_at, items))
    }
}

impl ThreatFeedAdapter for UrlhausAdapter {
    fn feed_name(&self) -> &'static str {
        "urlhaus"
    }

    fn snapshot_from_payload(
        &self,
        payload: &str,
        version: u64,
        generated_at: u64,
    ) -> Result<ThreatSnapshot, String> {
        let items =
            if payload.trim_start().starts_with('{') || payload.trim_start().starts_with('[') {
                parse_urlhaus_json_items(payload, self.feed_name())?
            } else {
                parse_urlhaus_csv_items(payload, self.feed_name())?
            };
        Ok(ThreatSnapshot::new(version, generated_at, items))
    }
}

impl ThreatFeedAdapter for SpamhausDropAdapter {
    fn feed_name(&self) -> &'static str {
        "spamhaus_drop"
    }

    fn snapshot_from_payload(
        &self,
        payload: &str,
        version: u64,
        generated_at: u64,
    ) -> Result<ThreatSnapshot, String> {
        let mut items = Vec::new();
        let seen_at = timestamp_if_nonzero(generated_at);
        for line in payload.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with(';') || trimmed.starts_with('#') {
                continue;
            }
            let indicator = trimmed
                .split(';')
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "invalid spamhaus drop line".to_string())?;
            let description = trimmed
                .split_once(';')
                .map(|(_, value)| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty());
            items.push(ThreatIndicatorSnapshotItem {
                indicator: indicator.to_string(),
                indicator_type: ThreatIndicatorType::Ip,
                feed: self.feed_name().to_string(),
                severity: ThreatSeverity::Critical,
                confidence: Some(100),
                tags: description.into_iter().collect(),
                reference_url: None,
                feed_first_seen: seen_at,
                feed_last_seen: seen_at,
                expires_at: None,
            });
        }
        Ok(ThreatSnapshot::new(version, generated_at, items))
    }
}

fn derive_generated_at(items: &[ThreatIndicatorSnapshotItem]) -> u64 {
    items
        .iter()
        .filter_map(|item| item.feed_last_seen.or(item.feed_first_seen))
        .max()
        .unwrap_or(0)
}

fn normalize_snapshot_item(
    mut item: ThreatIndicatorSnapshotItem,
) -> Option<ThreatIndicatorSnapshotItem> {
    item.feed = item.feed.trim().to_ascii_lowercase();
    if item.feed.is_empty() {
        return None;
    }
    item.indicator = normalize_indicator(item.indicator_type, &item.indicator).ok()?;
    item.confidence = item.confidence.map(|value| value.min(100));
    item.reference_url = item.reference_url.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    });
    item.tags = normalized_tags(item.tags);
    Some(item)
}

fn normalize_indicator(
    indicator_type: ThreatIndicatorType,
    indicator: &str,
) -> Result<String, String> {
    match indicator_type {
        ThreatIndicatorType::Hostname => normalize_hostname(indicator),
        ThreatIndicatorType::Ip => normalize_ip_indicator(indicator),
    }
}

fn normalize_hostname(raw: &str) -> Result<String, String> {
    let normalized = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("hostname indicator cannot be empty".to_string());
    }
    Ok(normalized)
}

fn normalize_ip_indicator(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if let Some((addr_raw, prefix_raw)) = trimmed.split_once('/') {
        let addr = addr_raw
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|err| format!("invalid cidr ip address: {err}"))?;
        let prefix = prefix_raw
            .trim()
            .parse::<u8>()
            .map_err(|err| format!("invalid cidr prefix: {err}"))?;
        if prefix > 32 {
            return Err("invalid cidr prefix: must be <= 32".to_string());
        }
        return Ok(format!("{addr}/{prefix}"));
    }
    let addr = trimmed
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("invalid ipv4 indicator: {err}"))?;
    Ok(addr.to_string())
}

fn normalized_tags(tags: Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for tag in tags {
        let normalized = tag.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            out.insert(normalized);
        }
    }
    out.into_iter().collect()
}

fn indicator_type_rank(indicator_type: ThreatIndicatorType) -> u8 {
    match indicator_type {
        ThreatIndicatorType::Hostname => 0,
        ThreatIndicatorType::Ip => 1,
    }
}

fn severity_from_confidence(confidence: Option<u8>) -> ThreatSeverity {
    match confidence.unwrap_or(50) {
        0..=39 => ThreatSeverity::Low,
        40..=69 => ThreatSeverity::Medium,
        70..=89 => ThreatSeverity::High,
        _ => ThreatSeverity::Critical,
    }
}

fn parse_timestamp(raw: &str) -> Result<u64, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("timestamp cannot be empty".to_string());
    }
    if let Ok(timestamp) = OffsetDateTime::parse(trimmed, &Rfc3339) {
        return Ok(timestamp.unix_timestamp().max(0) as u64);
    }
    let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC")
        .map_err(|err| format!("invalid timestamp format description: {err}"))?;
    let timestamp = PrimitiveDateTime::parse(trimmed, &format)
        .map_err(|err| format!("parse timestamp {trimmed:?}: {err}"))?;
    Ok(timestamp.assume_utc().unix_timestamp().max(0) as u64)
}

fn parse_optional_timestamp(raw: Option<&str>) -> Option<u64> {
    raw.filter(|value| !value.trim().is_empty())
        .and_then(|value| parse_timestamp(value).ok())
}

fn timestamp_if_nonzero(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

fn extract_url_host_indicator(url: &str) -> Option<(ThreatIndicatorType, String)> {
    let parsed = Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    if host.contains(':') {
        return None;
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some((ThreatIndicatorType::Ip, ip.to_string()));
    };
    Some((ThreatIndicatorType::Hostname, host.to_string()))
}

fn parse_confidence(value: Option<FlexibleU8>) -> Option<u8> {
    value.and_then(|value| match value {
        FlexibleU8::Number(value) => u8::try_from(value).ok(),
        FlexibleU8::String(value) => value.trim().parse::<u8>().ok(),
    })
}

fn parse_tags(tags: FlexibleTags) -> Vec<String> {
    match tags {
        FlexibleTags::Missing => Vec::new(),
        FlexibleTags::One(value) => value
            .split(',')
            .map(|entry| entry.trim().to_string())
            .collect(),
        FlexibleTags::Many(values) => values,
    }
}

fn threatfox_entry_to_item(
    entry: ThreatFoxEntry,
    feed_name: &str,
) -> Result<Option<ThreatIndicatorSnapshotItem>, String> {
    let Some((indicator_type, indicator)) = threatfox_indicator(&entry.ioc_type, &entry.ioc) else {
        return Ok(None);
    };
    let confidence = parse_confidence(entry.confidence_level);
    let feed_first_seen = parse_optional_timestamp(entry.first_seen.as_deref());
    let feed_last_seen = parse_optional_timestamp(entry.last_seen.as_deref());
    let expires_at = feed_last_seen
        .or(feed_first_seen)
        .map(|timestamp| timestamp.saturating_add(THREATFOX_EXPIRY_SECS));

    let mut tags = parse_tags(entry.tags);
    if !entry.threat_type.trim().is_empty() {
        tags.push(entry.threat_type);
    }
    if !entry.malware_printable.trim().is_empty() {
        tags.push(entry.malware_printable);
    }

    Ok(Some(ThreatIndicatorSnapshotItem {
        indicator,
        indicator_type,
        feed: feed_name.to_string(),
        severity: severity_from_confidence(confidence),
        confidence,
        tags,
        reference_url: entry.reference,
        feed_first_seen,
        feed_last_seen,
        expires_at,
    }))
}

fn threatfox_indicator(ioc_type: &str, ioc: &str) -> Option<(ThreatIndicatorType, String)> {
    let ioc_type = ioc_type.trim().to_ascii_lowercase();
    match ioc_type.as_str() {
        "domain" | "hostname" | "fqdn" => Some((ThreatIndicatorType::Hostname, ioc.to_string())),
        "ip" | "netblock" | "cidr" => Some((ThreatIndicatorType::Ip, ioc.to_string())),
        "ip:port" => ioc
            .split_once(':')
            .map(|(ip, _)| (ThreatIndicatorType::Ip, ip.to_string())),
        _ => {
            if ioc.parse::<Ipv4Addr>().is_ok() || ioc.contains('/') {
                Some((ThreatIndicatorType::Ip, ioc.to_string()))
            } else if ioc.contains('.') {
                Some((ThreatIndicatorType::Hostname, ioc.to_string()))
            } else {
                None
            }
        }
    }
}

fn parse_urlhaus_json_items(
    payload: &str,
    feed_name: &str,
) -> Result<Vec<ThreatIndicatorSnapshotItem>, String> {
    let value: Value =
        serde_json::from_str(payload).map_err(|err| format!("parse urlhaus payload: {err}"))?;
    let items = match value {
        Value::Array(items) => items,
        Value::Object(mut object) => {
            match object.remove("data").or_else(|| object.remove("urls")) {
                Some(Value::Array(items)) => items,
                _ => Vec::new(),
            }
        }
        _ => Vec::new(),
    };

    let mut normalized = Vec::new();
    for item in items {
        let Value::Object(object) = item else {
            continue;
        };
        let url = object
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some((indicator_type, indicator)) = extract_url_host_indicator(&url) else {
            continue;
        };
        let last_seen = parse_optional_timestamp(
            object
                .get("date_added")
                .or_else(|| object.get("dateadded"))
                .and_then(Value::as_str),
        );
        let threat = object
            .get("threat")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let reference_url = object
            .get("urlhaus_reference")
            .or_else(|| object.get("reference"))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        normalized.push(ThreatIndicatorSnapshotItem {
            indicator,
            indicator_type,
            feed: feed_name.to_string(),
            severity: ThreatSeverity::High,
            confidence: Some(80),
            tags: if threat.is_empty() {
                Vec::new()
            } else {
                vec![threat]
            },
            reference_url,
            feed_first_seen: last_seen,
            feed_last_seen: last_seen,
            expires_at: last_seen.map(|timestamp| timestamp.saturating_add(URLHAUS_EXPIRY_SECS)),
        });
    }
    Ok(normalized)
}

fn parse_urlhaus_csv_items(
    payload: &str,
    feed_name: &str,
) -> Result<Vec<ThreatIndicatorSnapshotItem>, String> {
    let mut items = Vec::new();
    let mut header = None::<Vec<String>>;
    for line in payload.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let fields = match parse_csv_record(trimmed) {
            Ok(fields) => fields,
            Err(_) => continue,
        };
        if header.is_none() && fields.iter().any(|field| field.eq_ignore_ascii_case("url")) {
            header = Some(
                fields
                    .iter()
                    .map(|field| field.to_ascii_lowercase())
                    .collect(),
            );
            continue;
        }

        let Some(url) =
            csv_field(&fields, header.as_deref(), "url", 0).filter(|value| !value.is_empty())
        else {
            continue;
        };
        let Some((indicator_type, indicator)) = extract_url_host_indicator(url) else {
            continue;
        };
        let last_seen = parse_optional_timestamp(
            csv_field(&fields, header.as_deref(), "dateadded", 1)
                .or_else(|| csv_field(&fields, header.as_deref(), "date_added", 1)),
        );
        let threat = csv_field(&fields, header.as_deref(), "threat", 2)
            .map(ToString::to_string)
            .unwrap_or_default();
        let reference_url = csv_field(&fields, header.as_deref(), "urlhaus_reference", 3)
            .or_else(|| csv_field(&fields, header.as_deref(), "reference", 3))
            .map(ToString::to_string);
        items.push(ThreatIndicatorSnapshotItem {
            indicator,
            indicator_type,
            feed: feed_name.to_string(),
            severity: ThreatSeverity::High,
            confidence: Some(80),
            tags: if threat.is_empty() {
                Vec::new()
            } else {
                vec![threat]
            },
            reference_url,
            feed_first_seen: last_seen,
            feed_last_seen: last_seen,
            expires_at: last_seen.map(|timestamp| timestamp.saturating_add(URLHAUS_EXPIRY_SECS)),
        });
    }
    Ok(items)
}

fn parse_csv_record(line: &str) -> Result<Vec<String>, String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if in_quotes {
        return Err("unterminated csv quote".to_string());
    }

    fields.push(current.trim().to_string());
    Ok(fields)
}

fn csv_field<'a>(
    fields: &'a [String],
    header: Option<&[String]>,
    column: &str,
    fallback_index: usize,
) -> Option<&'a str> {
    if let Some(header) = header {
        if let Some(index) = header.iter().position(|name| name == column) {
            return fields.get(index).map(String::as_str);
        }
    }
    fields.get(fallback_index).map(String::as_str)
}

#[derive(Debug, Deserialize)]
struct ThreatFoxResponse {
    #[serde(default)]
    data: Vec<ThreatFoxEntry>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxEntry {
    ioc: String,
    #[serde(default)]
    ioc_type: String,
    #[serde(default)]
    threat_type: String,
    #[serde(default)]
    malware_printable: String,
    #[serde(default)]
    confidence_level: Option<FlexibleU8>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    first_seen: Option<String>,
    #[serde(default)]
    last_seen: Option<String>,
    #[serde(default)]
    tags: FlexibleTags,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FlexibleU8 {
    Number(u64),
    String(String),
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum FlexibleTags {
    #[default]
    Missing,
    One(String),
    Many(Vec<String>),
}

#[cfg(test)]
mod tests {
    use super::{
        parse_spamhaus_drop_fixture, parse_threatfox_fixture, parse_urlhaus_fixture,
        THREATFOX_EXPIRY_SECS,
    };
    use crate::controlplane::threat_intel::types::{ThreatIndicatorType, ThreatSeverity};

    #[test]
    fn threatfox_adapter_normalizes_expiry_and_severity() {
        let payload = include_str!("fixtures/threatfox_recent.json");
        let snapshot = parse_threatfox_fixture(payload).expect("snapshot");
        let hostname_item = snapshot
            .items
            .iter()
            .find(|item| item.indicator_type == ThreatIndicatorType::Hostname)
            .expect("hostname item");
        assert_eq!(hostname_item.indicator, "bad.example.com");
        assert_eq!(hostname_item.severity, ThreatSeverity::High);
        assert_eq!(hostname_item.feed_last_seen, Some(1_741_861_200));
        assert_eq!(
            hostname_item.expires_at,
            Some(1_741_861_200 + THREATFOX_EXPIRY_SECS)
        );
    }

    #[test]
    fn urlhaus_adapter_extracts_hostname_from_json_payload() {
        let payload = r#"{
            "urls": [
                {
                    "url": "https://Bad.Example.com/dropper",
                    "date_added": "2025-03-13 10:20:00 UTC",
                    "threat": "malware_download",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/"
                }
            ]
        }"#;
        let snapshot = parse_urlhaus_fixture(payload).expect("snapshot");
        let item = snapshot.items.first().expect("item");
        assert_eq!(item.indicator_type, ThreatIndicatorType::Hostname);
        assert_eq!(item.indicator, "bad.example.com");
        assert_eq!(
            item.reference_url.as_deref(),
            Some("https://urlhaus.abuse.ch/url/123/")
        );
    }

    #[test]
    fn urlhaus_adapter_skips_ipv6_literals_in_phase_one() {
        let payload = r#"{
            "urls": [
                {
                    "url": "https://[2001:db8::1]/dropper",
                    "date_added": "2025-03-13 10:20:00 UTC",
                    "threat": "malware_download"
                }
            ]
        }"#;
        let snapshot = parse_urlhaus_fixture(payload).expect("snapshot");
        assert!(snapshot.items.is_empty());
    }

    #[test]
    fn urlhaus_csv_parser_handles_quoted_commas() {
        let payload = concat!(
            "url,dateadded,threat,urlhaus_reference\n",
            "\"https://bad.example.com/payload?tag=a,b\",2025-03-13 10:20:00 UTC,malware_download,https://urlhaus.abuse.ch/url/123/\n"
        );
        let snapshot = parse_urlhaus_fixture(payload).expect("snapshot");
        let item = snapshot.items.first().expect("item");
        assert_eq!(item.indicator, "bad.example.com");
        assert_eq!(
            item.reference_url.as_deref(),
            Some("https://urlhaus.abuse.ch/url/123/")
        );
    }

    #[test]
    fn urlhaus_csv_parser_skips_malformed_rows_without_dropping_snapshot() {
        let payload = concat!(
            "url,dateadded,threat,urlhaus_reference\n",
            "\"https://broken.example.com,2025-03-13 10:20:00 UTC,malware_download,https://urlhaus.abuse.ch/url/bad/\n",
            "https://good.example.com/payload,2025-03-13 10:20:00 UTC,malware_download,https://urlhaus.abuse.ch/url/456/\n"
        );
        let snapshot = parse_urlhaus_fixture(payload).expect("snapshot");
        assert_eq!(snapshot.items.len(), 1);
        assert_eq!(snapshot.items[0].indicator, "good.example.com");
    }

    #[test]
    fn threatfox_parser_tolerates_invalid_timestamps() {
        let payload = r#"{
            "query_status": "ok",
            "data": [
                {
                    "ioc": "bad.example.com",
                    "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "confidence_level": "85",
                    "first_seen": "not-a-time",
                    "last_seen": "also-bad"
                }
            ]
        }"#;
        let snapshot = parse_threatfox_fixture(payload).expect("snapshot");
        assert_eq!(snapshot.items.len(), 1);
        let item = snapshot.items.first().expect("item");
        assert_eq!(item.indicator, "bad.example.com");
        assert_eq!(item.feed_first_seen, None);
        assert_eq!(item.feed_last_seen, None);
    }

    #[test]
    fn spamhaus_drop_parser_skips_comments_and_collects_description_tags() {
        let payload = concat!(
            "; comment\n",
            "# another comment\n",
            "203.0.113.0/24 ; botnet c2\n"
        );
        let snapshot = parse_spamhaus_drop_fixture(payload).expect("snapshot");
        let item = snapshot.items.first().expect("item");
        assert_eq!(item.indicator_type, ThreatIndicatorType::Ip);
        assert_eq!(item.indicator, "203.0.113.0/24");
        assert_eq!(item.severity, ThreatSeverity::Critical);
        assert!(item.tags.iter().any(|tag| tag == "botnet c2"));
    }
}
