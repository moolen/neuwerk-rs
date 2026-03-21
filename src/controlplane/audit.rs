use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

pub const DEFAULT_AUDIT_STORE_MAX_BYTES: usize = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFindingType {
    DnsDeny,
    L4Deny,
    TlsDeny,
    IcmpDeny,
    AuthSso,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub finding_type: AuditFindingType,
    pub source_group: String,
    pub hostname: Option<String>,
    pub dst_ip: Option<Ipv4Addr>,
    pub dst_port: Option<u16>,
    pub proto: Option<u8>,
    pub fqdn: Option<String>,
    pub sni: Option<String>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub query_type: Option<u16>,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub finding_type: AuditFindingType,
    pub policy_id: Option<Uuid>,
    pub source_group: String,
    pub hostname: Option<String>,
    pub dst_ip: Option<Ipv4Addr>,
    pub dst_port: Option<u16>,
    pub proto: Option<u8>,
    pub fqdn: Option<String>,
    pub sni: Option<String>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub query_type: Option<u16>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: u64,
    pub node_ids: Vec<String>,
}

impl AuditFinding {
    fn from_event(event: AuditEvent, policy_id: Option<Uuid>, node_id: &str) -> Self {
        Self {
            finding_type: event.finding_type,
            policy_id,
            source_group: event.source_group,
            hostname: normalize_opt(event.hostname),
            dst_ip: event.dst_ip,
            dst_port: event.dst_port,
            proto: event.proto,
            fqdn: normalize_opt(event.fqdn),
            sni: normalize_opt(event.sni),
            icmp_type: event.icmp_type,
            icmp_code: event.icmp_code,
            query_type: event.query_type,
            first_seen: event.observed_at,
            last_seen: event.observed_at,
            count: 1,
            node_ids: vec![node_id.to_string()],
        }
    }

    pub fn key(&self) -> String {
        key_for_fields(
            self.finding_type,
            self.policy_id,
            &self.source_group,
            self.hostname.as_deref(),
            self.dst_ip,
            self.dst_port,
            self.proto,
            self.fqdn.as_deref(),
            self.sni.as_deref(),
            self.icmp_type,
            self.icmp_code,
        )
    }

    fn merge_from(&mut self, other: &AuditFinding) {
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.count = self.count.saturating_add(other.count);
        let mut node_set: HashSet<String> = self.node_ids.iter().cloned().collect();
        for node in &other.node_ids {
            node_set.insert(node.clone());
        }
        let mut node_ids: Vec<String> = node_set.into_iter().collect();
        node_ids.sort();
        self.node_ids = node_ids;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct AuditSnapshot {
    findings: Vec<AuditFinding>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub finding_type: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub source_group: Vec<String>,
    #[serde(default)]
    pub since: Option<u64>,
    #[serde(default)]
    pub until: Option<u64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditQueryResponse {
    pub items: Vec<AuditFinding>,
    pub partial: bool,
    pub node_errors: Vec<NodeQueryError>,
    pub nodes_queried: usize,
    pub nodes_responded: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeQueryError {
    pub node_id: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct AuditStore {
    base_dir: PathBuf,
    max_bytes: usize,
    inner: Arc<RwLock<HashMap<String, AuditFinding>>>,
}

impl AuditStore {
    pub fn new(base_dir: PathBuf, max_bytes: usize) -> Self {
        let max_bytes = max_bytes.max(1024);
        let store = Self {
            base_dir,
            max_bytes,
            inner: Arc::new(RwLock::new(HashMap::new())),
        };
        let _ = store.load_snapshot();
        store
    }

    pub fn ingest(&self, event: AuditEvent, policy_id: Option<Uuid>, node_id: &str) {
        let finding = AuditFinding::from_event(event, policy_id, node_id);
        if let Ok(mut lock) = self.inner.write() {
            let key = finding.key();
            if let Some(existing) = lock.get_mut(&key) {
                existing.first_seen = existing.first_seen.min(finding.first_seen);
                existing.last_seen = existing.last_seen.max(finding.last_seen);
                existing.count = existing.count.saturating_add(1);
                if !existing.node_ids.iter().any(|n| n == node_id) {
                    existing.node_ids.push(node_id.to_string());
                    existing.node_ids.sort();
                }
            } else {
                lock.insert(key, finding);
            }
            let _ = self.persist_snapshot_locked(&mut lock);
        }
    }

    pub fn query(&self, query: &AuditQuery) -> Result<Vec<AuditFinding>, String> {
        let policy_id = match &query.policy_id {
            Some(value) => Some(parse_uuid(value, "policy_id")?),
            None => None,
        };
        let finding_types = parse_finding_types(&query.finding_type)?;
        let source_groups = normalize_values(&query.source_group);
        let since = query.since.unwrap_or(0);
        let until = query.until.unwrap_or(u64::MAX);
        let limit = query.limit.unwrap_or(500).clamp(1, 10_000);

        let mut items = Vec::new();
        if let Ok(lock) = self.inner.read() {
            for finding in lock.values() {
                if let Some(expected) = policy_id {
                    if finding.policy_id != Some(expected) {
                        continue;
                    }
                }
                if !finding_types.is_empty() && !finding_types.contains(&finding.finding_type) {
                    continue;
                }
                if !source_groups.is_empty()
                    && !source_groups.contains(&finding.source_group.to_ascii_lowercase())
                {
                    continue;
                }
                if finding.last_seen < since || finding.first_seen > until {
                    continue;
                }
                items.push(finding.clone());
            }
        }
        items.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.count.cmp(&a.count))
        });
        items.truncate(limit);
        Ok(items)
    }

    pub fn merge_findings(sources: Vec<Vec<AuditFinding>>) -> Vec<AuditFinding> {
        let mut merged: HashMap<String, AuditFinding> = HashMap::new();
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
        let mut items: Vec<AuditFinding> = merged.into_values().collect();
        items.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.count.cmp(&a.count))
        });
        items
    }

    pub fn all_findings(&self) -> Result<Vec<AuditFinding>, String> {
        let mut items = self
            .inner
            .read()
            .map_err(|_| "audit store lock poisoned".to_string())?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        items.sort_by(|a, b| {
            b.last_seen
                .cmp(&a.last_seen)
                .then_with(|| b.count.cmp(&a.count))
        });
        Ok(items)
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
        let snapshot: AuditSnapshot =
            serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
        if let Ok(mut lock) = self.inner.write() {
            lock.clear();
            for finding in snapshot.findings {
                lock.insert(finding.key(), finding);
            }
        }
        Ok(())
    }

    fn persist_snapshot_locked(
        &self,
        findings_map: &mut HashMap<String, AuditFinding>,
    ) -> Result<(), String> {
        self.ensure_dirs()?;
        loop {
            let snapshot = AuditSnapshot {
                findings: findings_map.values().cloned().collect(),
            };
            let payload = serde_json::to_vec_pretty(&snapshot).map_err(|err| err.to_string())?;
            if payload.len() <= self.max_bytes || findings_map.is_empty() {
                return atomic_write(&self.snapshot_path(), &payload);
            }

            let oldest_key = findings_map
                .iter()
                .min_by_key(|(_, finding)| finding.last_seen)
                .map(|(key, _)| key.clone());
            match oldest_key {
                Some(key) => {
                    findings_map.remove(&key);
                }
                None => return atomic_write(&self.snapshot_path(), &payload),
            }
        }
    }
}

pub(crate) fn finding_key_for_dataplane_event(
    event: &crate::dataplane::AuditEvent,
    policy_id: Option<Uuid>,
    fqdn: Option<&str>,
) -> String {
    match event.event_type {
        crate::dataplane::AuditEventType::L4Deny => key_for_fields(
            AuditFindingType::L4Deny,
            policy_id,
            event.source_group.trim(),
            None,
            Some(event.dst_ip),
            Some(event.dst_port),
            Some(event.proto),
            normalize_opt(fqdn.map(str::to_string)).as_deref(),
            None,
            None,
            None,
        ),
        crate::dataplane::AuditEventType::TlsDeny => key_for_fields(
            AuditFindingType::TlsDeny,
            policy_id,
            event.source_group.trim(),
            None,
            Some(event.dst_ip),
            Some(event.dst_port),
            None,
            None,
            normalize_opt(event.sni.clone()).as_deref(),
            None,
            None,
        ),
        crate::dataplane::AuditEventType::IcmpDeny => key_for_fields(
            AuditFindingType::IcmpDeny,
            policy_id,
            event.source_group.trim(),
            None,
            Some(event.dst_ip),
            None,
            None,
            None,
            None,
            event.icmp_type,
            event.icmp_code,
        ),
    }
}

pub(crate) fn finding_key_for_dns_deny(
    policy_id: Option<Uuid>,
    source_group: &str,
    hostname: &str,
) -> String {
    key_for_fields(
        AuditFindingType::DnsDeny,
        policy_id,
        source_group.trim(),
        normalize_opt(Some(hostname.to_string())).as_deref(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn parse_finding_types(values: &[String]) -> Result<HashSet<AuditFindingType>, String> {
    let mut out = HashSet::new();
    for value in values {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            continue;
        }
        let parsed = match value.as_str() {
            "dns_deny" => AuditFindingType::DnsDeny,
            "l4_deny" => AuditFindingType::L4Deny,
            "tls_deny" => AuditFindingType::TlsDeny,
            "icmp_deny" => AuditFindingType::IcmpDeny,
            "auth_sso" => AuditFindingType::AuthSso,
            _ => return Err(format!("invalid finding_type value: {value}")),
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

fn normalize_opt(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().trim_end_matches('.').to_ascii_lowercase())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, String> {
    Uuid::parse_str(value).map_err(|err| format!("invalid {field}: {err}"))
}

#[allow(clippy::too_many_arguments)]
fn key_for_fields(
    finding_type: AuditFindingType,
    policy_id: Option<Uuid>,
    source_group: &str,
    hostname: Option<&str>,
    dst_ip: Option<Ipv4Addr>,
    dst_port: Option<u16>,
    proto: Option<u8>,
    fqdn: Option<&str>,
    sni: Option<&str>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
) -> String {
    match finding_type {
        AuditFindingType::DnsDeny => format!(
            "dns:{}:{}:{}",
            policy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string()),
            source_group,
            hostname.unwrap_or("")
        ),
        AuditFindingType::L4Deny => format!(
            "l4:{}:{}:{}:{}:{}:{}",
            policy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string()),
            source_group,
            dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            dst_port.unwrap_or(0),
            proto.unwrap_or(0),
            fqdn.unwrap_or(""),
        ),
        AuditFindingType::TlsDeny => format!(
            "tls:{}:{}:{}:{}:{}",
            policy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string()),
            source_group,
            sni.unwrap_or(""),
            dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            dst_port.unwrap_or(0),
        ),
        AuditFindingType::IcmpDeny => format!(
            "icmp:{}:{}:{}:{}:{}",
            policy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string()),
            source_group,
            dst_ip
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "0.0.0.0".to_string()),
            icmp_type.unwrap_or(255),
            icmp_code.unwrap_or(255),
        ),
        AuditFindingType::AuthSso => format!(
            "auth_sso:{}:{}:{}:{}",
            policy_id
                .map(|id| id.to_string())
                .unwrap_or_else(|| "none".to_string()),
            source_group,
            hostname.unwrap_or(""),
            fqdn.unwrap_or(""),
        ),
    }
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    #[test]
    fn store_dedups_and_counts() {
        let dir = std::env::temp_dir().join(format!("audit-store-{}", Uuid::new_v4()));
        let store = AuditStore::new(dir, 1024 * 1024);
        let ts = now();
        let event = AuditEvent {
            finding_type: AuditFindingType::L4Deny,
            source_group: "apps".to_string(),
            hostname: None,
            dst_ip: Some(Ipv4Addr::new(203, 0, 113, 10)),
            dst_port: Some(443),
            proto: Some(6),
            fqdn: Some("api.example.com".to_string()),
            sni: None,
            icmp_type: None,
            icmp_code: None,
            query_type: None,
            observed_at: ts,
        };
        store.ingest(event.clone(), None, "node-a");
        store.ingest(event, None, "node-a");
        let items = store.query(&AuditQuery::default()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].count, 2);
    }

    #[test]
    fn merge_findings_unions_nodes() {
        let mut a = AuditFinding {
            finding_type: AuditFindingType::DnsDeny,
            policy_id: None,
            source_group: "apps".to_string(),
            hostname: Some("foo.example.com".to_string()),
            dst_ip: None,
            dst_port: None,
            proto: None,
            fqdn: None,
            sni: None,
            icmp_type: None,
            icmp_code: None,
            query_type: Some(1),
            first_seen: 10,
            last_seen: 20,
            count: 3,
            node_ids: vec!["node-a".to_string()],
        };
        let mut b = a.clone();
        b.last_seen = 30;
        b.count = 2;
        b.node_ids = vec!["node-b".to_string()];
        let merged = AuditStore::merge_findings(vec![vec![a.clone()], vec![b.clone()]]);
        assert_eq!(merged.len(), 1);
        let finding = &merged[0];
        assert_eq!(finding.count, 5);
        assert_eq!(finding.last_seen, 30);
        a.node_ids.push("node-b".to_string());
        a.node_ids.sort();
        assert_eq!(finding.node_ids, a.node_ids);
    }

    #[test]
    fn ingest_evicts_oldest_findings_when_snapshot_exceeds_limit() {
        let dir = std::env::temp_dir().join(format!("audit-store-{}", Uuid::new_v4()));
        let store = AuditStore::new(dir.clone(), 1024);

        for idx in 0..32u8 {
            store.ingest(
                AuditEvent {
                    finding_type: AuditFindingType::L4Deny,
                    source_group: format!("apps-{idx:02}"),
                    hostname: None,
                    dst_ip: Some(Ipv4Addr::new(203, 0, 113, idx)),
                    dst_port: Some(4000 + idx as u16),
                    proto: Some(6),
                    fqdn: Some(format!(
                        "very-long-persisted-name-{idx:02}.example.internal.example.com"
                    )),
                    sni: None,
                    icmp_type: None,
                    icmp_code: None,
                    query_type: None,
                    observed_at: idx as u64,
                },
                None,
                "node-a",
            );
        }

        let snapshot_path = dir.join("snapshot.json");
        let snapshot_size = fs::metadata(&snapshot_path).unwrap().len() as usize;
        assert!(
            snapshot_size <= 1024,
            "snapshot should honor max_bytes, got {snapshot_size}"
        );

        let items = store.query(&AuditQuery {
            limit: Some(1000),
            ..AuditQuery::default()
        });
        let items = items.unwrap();
        assert!(
            items.len() < 32,
            "expected eviction when snapshot grows too large"
        );
        assert!(
            items.iter().all(|item| item.source_group != "apps-00"),
            "oldest finding should be evicted first"
        );
        assert!(
            items.iter().any(|item| item.source_group == "apps-31"),
            "newest finding should remain after eviction"
        );
    }

    #[test]
    fn load_snapshot_restores_evicted_retained_findings_after_restart() {
        let dir = std::env::temp_dir().join(format!("audit-store-{}", Uuid::new_v4()));
        {
            let store = AuditStore::new(dir.clone(), 1024);
            for idx in 0..32u8 {
                store.ingest(
                    AuditEvent {
                        finding_type: AuditFindingType::L4Deny,
                        source_group: format!("persist-{idx:02}"),
                        hostname: None,
                        dst_ip: Some(Ipv4Addr::new(198, 51, 100, idx)),
                        dst_port: Some(5000 + idx as u16),
                        proto: Some(6),
                        fqdn: Some(format!(
                            "persisted-retention-test-{idx:02}.example.internal.example.com"
                        )),
                        sni: None,
                        icmp_type: None,
                        icmp_code: None,
                        query_type: None,
                        observed_at: idx as u64,
                    },
                    None,
                    "node-a",
                );
            }
        }

        let restored = AuditStore::new(dir, 1024);
        let items = restored
            .query(&AuditQuery {
                limit: Some(1000),
                ..AuditQuery::default()
            })
            .unwrap();
        assert!(
            !items.is_empty(),
            "expected retained findings after restart"
        );
        assert!(
            items.iter().all(|item| item.source_group != "persist-00"),
            "evicted oldest finding should stay gone after reload"
        );
        assert!(
            items.iter().any(|item| item.source_group == "persist-31"),
            "latest retained finding should reload from snapshot"
        );
    }
}
