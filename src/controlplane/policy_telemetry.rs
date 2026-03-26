use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::controlplane::audit::NodeQueryError;

const SECONDS_PER_HOUR: u64 = 3_600;
const CURRENT_WINDOW_HOURS: u64 = 24;
const PREVIOUS_WINDOW_HOURS: u64 = 24;
const RETENTION_HOURS: u64 = CURRENT_WINDOW_HOURS + PREVIOUS_WINDOW_HOURS + 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTelemetrySummary {
    pub source_group_id: String,
    pub current_24h_hits: u64,
    pub previous_24h_hits: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTelemetryResponse {
    pub items: Vec<PolicyTelemetrySummary>,
    pub partial: bool,
    pub node_errors: Vec<NodeQueryError>,
    pub nodes_queried: usize,
    pub nodes_responded: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct PolicyTelemetryBucketKey {
    policy_id: Uuid,
    source_group_id: String,
    hour_bucket: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolicyTelemetryBucketRecord {
    policy_id: Uuid,
    source_group_id: String,
    hour_bucket: u64,
    hits: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PolicyTelemetrySnapshot {
    buckets: Vec<PolicyTelemetryBucketRecord>,
}

#[derive(Debug, Clone)]
pub struct PolicyTelemetryStore {
    base_dir: PathBuf,
    inner: Arc<RwLock<HashMap<PolicyTelemetryBucketKey, u64>>>,
}

impl PolicyTelemetryStore {
    pub fn new(base_dir: PathBuf) -> Self {
        let store = Self {
            base_dir,
            inner: Arc::new(RwLock::new(HashMap::new())),
        };
        let _ = store.load_snapshot();
        store
    }

    pub fn record_hit(&self, policy_id: Uuid, source_group_id: &str, observed_at: u64) {
        let source_group_id = source_group_id.trim();
        if source_group_id.is_empty() {
            return;
        }

        let hour_bucket = hour_bucket_for(observed_at);
        if let Ok(mut lock) = self.inner.write() {
            let key = PolicyTelemetryBucketKey {
                policy_id,
                source_group_id: source_group_id.to_string(),
                hour_bucket,
            };
            *lock.entry(key).or_insert(0) = lock
                .get(&PolicyTelemetryBucketKey {
                    policy_id,
                    source_group_id: source_group_id.to_string(),
                    hour_bucket,
                })
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            prune_locked(&mut lock, hour_bucket);
            let _ = self.persist_snapshot_locked(&lock);
        }
    }

    pub fn policy_24h_summary(
        &self,
        policy_id: Uuid,
        now: u64,
    ) -> Result<Vec<PolicyTelemetrySummary>, String> {
        let current_hour = hour_bucket_for(now);
        let current_start = current_hour.saturating_sub(CURRENT_WINDOW_HOURS - 1);
        let previous_end = current_start.saturating_sub(1);
        let previous_start = previous_end.saturating_sub(PREVIOUS_WINDOW_HOURS - 1);

        let lock = self
            .inner
            .read()
            .map_err(|_| "policy telemetry store lock poisoned".to_string())?;

        let mut by_source_group: HashMap<String, PolicyTelemetrySummary> = HashMap::new();
        for (key, hits) in lock.iter() {
            if key.policy_id != policy_id {
                continue;
            }

            let entry = by_source_group
                .entry(key.source_group_id.clone())
                .or_insert_with(|| PolicyTelemetrySummary {
                    source_group_id: key.source_group_id.clone(),
                    current_24h_hits: 0,
                    previous_24h_hits: 0,
                });

            if (current_start..=current_hour).contains(&key.hour_bucket) {
                entry.current_24h_hits = entry.current_24h_hits.saturating_add(*hits);
            } else if previous_start <= previous_end
                && (previous_start..=previous_end).contains(&key.hour_bucket)
            {
                entry.previous_24h_hits = entry.previous_24h_hits.saturating_add(*hits);
            }
        }

        let mut summaries: Vec<_> = by_source_group.into_values().collect();
        summaries.sort_by(|a, b| {
            b.current_24h_hits
                .cmp(&a.current_24h_hits)
                .then_with(|| b.previous_24h_hits.cmp(&a.previous_24h_hits))
                .then_with(|| a.source_group_id.cmp(&b.source_group_id))
        });
        Ok(summaries)
    }

    pub fn merge_summaries(sources: Vec<Vec<PolicyTelemetrySummary>>) -> Vec<PolicyTelemetrySummary> {
        let mut merged: HashMap<String, PolicyTelemetrySummary> = HashMap::new();
        for summaries in sources {
            for summary in summaries {
                let entry = merged
                    .entry(summary.source_group_id.clone())
                    .or_insert_with(|| PolicyTelemetrySummary {
                        source_group_id: summary.source_group_id.clone(),
                        current_24h_hits: 0,
                        previous_24h_hits: 0,
                    });
                entry.current_24h_hits =
                    entry.current_24h_hits.saturating_add(summary.current_24h_hits);
                entry.previous_24h_hits = entry
                    .previous_24h_hits
                    .saturating_add(summary.previous_24h_hits);
            }
        }

        let mut out: Vec<_> = merged.into_values().collect();
        out.sort_by(|a, b| {
            b.current_24h_hits
                .cmp(&a.current_24h_hits)
                .then_with(|| b.previous_24h_hits.cmp(&a.previous_24h_hits))
                .then_with(|| a.source_group_id.cmp(&b.source_group_id))
        });
        out
    }

    fn ensure_dirs(&self) -> Result<(), String> {
        fs::create_dir_all(&self.base_dir).map_err(|err| err.to_string())
    }

    fn snapshot_path(&self) -> PathBuf {
        self.base_dir.join("snapshot.json")
    }

    fn load_snapshot(&self) -> Result<(), String> {
        self.ensure_dirs()?;
        let bytes = match fs::read(self.snapshot_path()) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.to_string()),
        };
        let snapshot: PolicyTelemetrySnapshot =
            serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;

        let mut lock = self
            .inner
            .write()
            .map_err(|_| "policy telemetry store lock poisoned".to_string())?;
        lock.clear();
        for record in snapshot.buckets {
            lock.insert(
                PolicyTelemetryBucketKey {
                    policy_id: record.policy_id,
                    source_group_id: record.source_group_id,
                    hour_bucket: record.hour_bucket,
                },
                record.hits,
            );
        }
        Ok(())
    }

    fn persist_snapshot_locked(
        &self,
        buckets: &HashMap<PolicyTelemetryBucketKey, u64>,
    ) -> Result<(), String> {
        self.ensure_dirs()?;
        let snapshot = PolicyTelemetrySnapshot {
            buckets: buckets
                .iter()
                .map(|(key, hits)| PolicyTelemetryBucketRecord {
                    policy_id: key.policy_id,
                    source_group_id: key.source_group_id.clone(),
                    hour_bucket: key.hour_bucket,
                    hits: *hits,
                })
                .collect(),
        };
        let payload = serde_json::to_vec_pretty(&snapshot).map_err(|err| err.to_string())?;
        atomic_write(&self.snapshot_path(), &payload)
    }
}

fn hour_bucket_for(timestamp: u64) -> u64 {
    timestamp / SECONDS_PER_HOUR
}

fn prune_locked(buckets: &mut HashMap<PolicyTelemetryBucketKey, u64>, current_hour: u64) {
    let min_hour = current_hour.saturating_sub(RETENTION_HOURS - 1);
    buckets.retain(|key, _| key.hour_bucket >= min_hour);
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

    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn policy_telemetry_records_hourly_hits_and_rolls_up_current_window() {
        let dir = TempDir::new().expect("tempdir");
        let store = PolicyTelemetryStore::new(dir.path().join("policy-telemetry-store"));
        let policy_id = Uuid::new_v4();
        let hour = 1_744_000_000u64;

        store.record_hit(policy_id, "apps", hour);
        store.record_hit(policy_id, "apps", hour + 120);

        let summaries = store
            .policy_24h_summary(policy_id, hour + 180)
            .expect("summary");

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].source_group_id, "apps");
        assert_eq!(summaries[0].current_24h_hits, 2);
        assert_eq!(summaries[0].previous_24h_hits, 0);
    }

    #[test]
    fn policy_telemetry_tracks_previous_window_for_trend() {
        let dir = TempDir::new().expect("tempdir");
        let store = PolicyTelemetryStore::new(dir.path().join("policy-telemetry-store"));
        let policy_id = Uuid::new_v4();
        let now = 1_744_086_400u64;

        store.record_hit(policy_id, "apps", now - (2 * SECONDS_PER_HOUR));
        store.record_hit(policy_id, "apps", now - (26 * SECONDS_PER_HOUR));
        store.record_hit(policy_id, "db", now - (27 * SECONDS_PER_HOUR));

        let summaries = store.policy_24h_summary(policy_id, now).expect("summary");

        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[0].source_group_id, "apps");
        assert_eq!(summaries[0].current_24h_hits, 1);
        assert_eq!(summaries[0].previous_24h_hits, 1);
        assert_eq!(summaries[1].source_group_id, "db");
        assert_eq!(summaries[1].current_24h_hits, 0);
        assert_eq!(summaries[1].previous_24h_hits, 1);
    }

    #[test]
    fn policy_telemetry_persists_and_prunes_old_buckets() {
        let dir = TempDir::new().expect("tempdir");
        let base_dir = dir.path().join("policy-telemetry-store");
        let policy_id = Uuid::new_v4();
        let now = 1_744_086_400u64;
        let stale = now - (RETENTION_HOURS * SECONDS_PER_HOUR) - SECONDS_PER_HOUR;

        let store = PolicyTelemetryStore::new(base_dir.clone());
        store.record_hit(policy_id, "apps", stale);
        store.record_hit(policy_id, "apps", now);

        let reloaded = PolicyTelemetryStore::new(base_dir);
        let summaries = reloaded.policy_24h_summary(policy_id, now).expect("summary");

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].current_24h_hits, 1);
        assert_eq!(summaries[0].previous_24h_hits, 0);
    }

    #[test]
    fn policy_telemetry_merge_summaries_sums_by_source_group() {
        let merged = PolicyTelemetryStore::merge_summaries(vec![
            vec![
                PolicyTelemetrySummary {
                    source_group_id: "apps".to_string(),
                    current_24h_hits: 2,
                    previous_24h_hits: 1,
                },
                PolicyTelemetrySummary {
                    source_group_id: "db".to_string(),
                    current_24h_hits: 1,
                    previous_24h_hits: 0,
                },
            ],
            vec![PolicyTelemetrySummary {
                source_group_id: "apps".to_string(),
                current_24h_hits: 3,
                previous_24h_hits: 4,
            }],
        ]);

        assert_eq!(
            merged,
            vec![
                PolicyTelemetrySummary {
                    source_group_id: "apps".to_string(),
                    current_24h_hits: 5,
                    previous_24h_hits: 5,
                },
                PolicyTelemetrySummary {
                    source_group_id: "db".to_string(),
                    current_24h_hits: 1,
                    previous_24h_hits: 0,
                },
            ]
        );
    }
}
