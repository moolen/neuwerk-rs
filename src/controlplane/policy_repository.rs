use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};

pub const POLICY_INDEX_KEY: &[u8] = b"policies/index";
pub const POLICY_ACTIVE_KEY: &[u8] = b"policies/active";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub id: Uuid,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub mode: PolicyMode,
    pub policy: PolicyConfig,
}

impl PolicyRecord {
    pub fn new(
        mode: PolicyMode,
        policy: PolicyConfig,
        name: Option<String>,
    ) -> Result<Self, String> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format created_at: {err}"))?;
        Ok(Self {
            id: Uuid::new_v4(),
            created_at,
            name: sanitize_policy_name(name),
            mode,
            policy,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMeta {
    pub id: Uuid,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub mode: PolicyMode,
}

impl From<&PolicyRecord> for PolicyMeta {
    fn from(record: &PolicyRecord) -> Self {
        Self {
            id: record.id,
            created_at: record.created_at.clone(),
            name: record.name.clone(),
            mode: record.mode,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyIndex {
    pub policies: Vec<PolicyMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyActive {
    pub id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCreateRequest {
    pub mode: PolicyMode,
    pub policy: PolicyConfig,
}

#[derive(Clone)]
pub struct PolicyDiskStore {
    base_dir: PathBuf,
}

impl PolicyDiskStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(self.base_dir.join("policies"))
    }

    pub fn write_record(&self, record: &PolicyRecord) -> io::Result<()> {
        self.ensure()?;
        let policy_path = self.policy_path(record.id);
        let payload = serde_json::to_vec_pretty(record).map_err(to_io_err)?;
        atomic_write(&policy_path, &payload)?;

        let mut index = self.read_index()?;
        let meta = PolicyMeta::from(record);
        if let Some(existing) = index.policies.iter_mut().find(|item| item.id == meta.id) {
            *existing = meta;
        } else {
            index.policies.push(meta);
        }
        index.policies.sort_by(|a, b| {
            let ts = a.created_at.cmp(&b.created_at);
            if ts == std::cmp::Ordering::Equal {
                a.id.as_bytes().cmp(b.id.as_bytes())
            } else {
                ts
            }
        });
        self.write_index(&index)?;
        Ok(())
    }

    pub fn list_records(&self) -> io::Result<Vec<PolicyRecord>> {
        let index = self.read_index()?;
        let mut records = Vec::with_capacity(index.policies.len());
        for meta in index.policies {
            let record = self
                .read_record(meta.id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing policy record"))?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn delete_record(&self, id: Uuid) -> io::Result<()> {
        let path = self.policy_path(id);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let mut index = self.read_index()?;
        index.policies.retain(|meta| meta.id != id);
        self.write_index(&index)?;
        Ok(())
    }

    pub fn read_record(&self, id: Uuid) -> io::Result<Option<PolicyRecord>> {
        let path = self.policy_path(id);
        read_json(&path)
    }

    pub fn set_active(&self, id: Option<Uuid>) -> io::Result<()> {
        let path = self.active_path();
        match id {
            Some(id) => {
                let payload = serde_json::to_vec_pretty(&PolicyActive { id }).map_err(to_io_err)?;
                atomic_write(&path, &payload)
            }
            None => match fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(err) => Err(err),
            },
        }
    }

    pub fn active_id(&self) -> io::Result<Option<Uuid>> {
        let path = self.active_path();
        let active: Option<PolicyActive> = read_json(&path)?;
        Ok(active.map(|entry| entry.id))
    }

    pub fn read_index(&self) -> io::Result<PolicyIndex> {
        let path = self.index_path();
        Ok(read_json(&path)?.unwrap_or_default())
    }

    fn write_index(&self, index: &PolicyIndex) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(index).map_err(to_io_err)?;
        atomic_write(&self.index_path(), &payload)
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.json")
    }

    fn active_path(&self) -> PathBuf {
        self.base_dir.join("active.json")
    }

    fn policy_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join("policies").join(format!("{id}.json"))
    }
}

pub fn policy_item_key(id: Uuid) -> Vec<u8> {
    format!("policies/item/{id}").into_bytes()
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> io::Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => {
            let value = serde_json::from_slice(&bytes).map_err(to_io_err)?;
            Ok(Some(value))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

fn to_io_err(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

pub fn sanitize_policy_name(name: Option<String>) -> Option<String> {
    name.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn sample_policy() -> PolicyConfig {
        serde_yaml::from_str(
            r#"
default_policy: deny
"#,
        )
        .unwrap()
    }

    fn sample_record() -> PolicyRecord {
        PolicyRecord::new(
            PolicyMode::Enforce,
            sample_policy(),
            Some("test-policy".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn read_index_rejects_invalid_json() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        fs::write(store.index_path(), b"{not-json").unwrap();

        let err = store.read_index().expect_err("expected invalid index json");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn list_records_errors_when_index_references_missing_record() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        store.ensure().unwrap();

        let record = sample_record();
        let index = PolicyIndex {
            policies: vec![PolicyMeta::from(&record)],
        };
        fs::write(
            store.index_path(),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();

        let err = store
            .list_records()
            .expect_err("expected missing referenced record");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string().contains("missing policy record"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn set_active_none_ignores_missing_file() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());

        store.set_active(None).unwrap();
        assert_eq!(store.active_id().unwrap(), None);
    }

    #[test]
    fn write_record_replaces_existing_record_contents() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());

        let mut record = sample_record();
        store.write_record(&record).unwrap();

        let path = store.policy_path(record.id);
        let first = fs::read_to_string(&path).unwrap();
        assert!(first.contains("test-policy"));

        record.name = Some("updated-policy".to_string());
        record.mode = PolicyMode::Audit;
        store.write_record(&record).unwrap();

        let updated = store.read_record(record.id).unwrap().unwrap();
        assert_eq!(updated.name.as_deref(), Some("updated-policy"));
        assert_eq!(updated.mode, PolicyMode::Audit);

        let second = fs::read_to_string(&path).unwrap();
        assert!(second.contains("updated-policy"));
        assert!(!second.contains("test-policy"));

        let tmp_files = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(tmp_files, 0, "atomic write leaked temporary files");
    }

    #[test]
    fn write_record_returns_io_error_when_policies_path_is_blocked() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        fs::write(dir.path().join("policies"), b"not-a-directory").unwrap();

        let err = store
            .write_record(&sample_record())
            .expect_err("expected policies path collision to fail");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));
    }

    #[test]
    fn disk_store_reads_legacy_record_and_index_with_schema_compatibility() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        store.ensure().unwrap();

        let id = Uuid::new_v4();
        let policy_value = serde_json::to_value(sample_policy()).unwrap();
        fs::write(
            store.index_path(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "policies": [{
                    "id": id,
                    "created_at": "2026-03-09T12:00:00Z",
                    "mode": "enforce",
                    "ignored_meta_field": "compat"
                }],
                "ignored_index_field": true
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            store.policy_path(id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "mode": "enforce",
                "policy": policy_value,
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let records = store.list_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, id);
        assert_eq!(records[0].name, None);
        assert_eq!(records[0].mode, PolicyMode::Enforce);
        assert!(matches!(
            records[0].policy.default_policy,
            Some(crate::controlplane::policy_config::PolicyValue::String(ref value))
                if value == "deny"
        ));
    }
}
