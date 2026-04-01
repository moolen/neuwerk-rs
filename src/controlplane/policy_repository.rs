use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::policy_config::{PolicyConfig, PolicyMode, PolicyValue};

pub const POLICY_STATE_KEY: &[u8] = b"policy/state";
pub const POLICY_INDEX_KEY: &[u8] = b"policies/index";
pub const POLICY_ACTIVE_KEY: &[u8] = b"policies/active";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPolicyCompat {
    #[serde(default = "singleton_policy_id")]
    id: Uuid,
    #[serde(default = "default_created_at")]
    created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default)]
    mode: PolicyMode,
    #[serde(default = "default_active")]
    active: bool,
}

impl Default for StoredPolicyCompat {
    fn default() -> Self {
        Self {
            id: singleton_policy_id(),
            created_at: default_created_at(),
            name: None,
            mode: PolicyMode::Enforce,
            active: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPolicy {
    pub policy: PolicyConfig,
    #[serde(default)]
    compat: StoredPolicyCompat,
}

impl Default for StoredPolicy {
    fn default() -> Self {
        Self {
            policy: PolicyConfig {
                default_policy: Some(PolicyValue::String("deny".to_string())),
                source_groups: Vec::new(),
            },
            compat: StoredPolicyCompat::default(),
        }
    }
}

impl StoredPolicy {
    pub fn from_policy(policy: PolicyConfig) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn from_record(record: &PolicyRecord) -> Self {
        stored_policy_from_record(record)
    }

    pub fn record(&self) -> PolicyRecord {
        compat_record(self.clone())
    }

    pub fn active_id(&self) -> Option<Uuid> {
        self.compat.active.then_some(self.compat.id)
    }
}

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
        fs::create_dir_all(&self.base_dir)
    }

    pub fn read_state(&self) -> io::Result<Option<StoredPolicy>> {
        read_json(&self.state_path())
    }

    pub fn write_state(&self, state: &StoredPolicy) -> io::Result<()> {
        self.ensure()?;
        let payload = serde_json::to_vec_pretty(state).map_err(to_io_err)?;
        atomic_write(&self.state_path(), &payload)
    }

    pub fn load_or_bootstrap_singleton(&self) -> io::Result<StoredPolicy> {
        if let Some(state) = self.read_state()? {
            return Ok(state);
        }

        let state = self
            .read_legacy_active_state()?
            .unwrap_or_else(StoredPolicy::default);
        self.write_state(&state)?;
        Ok(state)
    }

    pub fn write_record(&self, record: &PolicyRecord) -> io::Result<()> {
        self.ensure()?;
        let mut state = self.read_state()?.unwrap_or_default();
        state.policy = record.policy.clone();
        state.compat = StoredPolicyCompat {
            id: record.id,
            created_at: record.created_at.clone(),
            name: sanitize_policy_name(record.name.clone()),
            mode: record.mode,
            active: record.mode.is_active(),
        };
        self.write_state(&state)
    }

    pub fn list_records(&self) -> io::Result<Vec<PolicyRecord>> {
        self.read_state()?
            .map(|state| vec![compat_record(state)])
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "singleton policy missing"))
            .or_else(|err| {
                if err.kind() == io::ErrorKind::NotFound {
                    Ok(vec![compat_record(self.load_or_bootstrap_singleton()?)])
                } else {
                    Err(err)
                }
            })
    }

    pub fn delete_record(&self, id: Uuid) -> io::Result<()> {
        let Some(state) = self.read_state()? else {
            return Ok(());
        };
        if state.compat.id != id {
            return Ok(());
        }
        match fs::remove_file(self.state_path()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub fn read_record(&self, id: Uuid) -> io::Result<Option<PolicyRecord>> {
        let Some(state) = self.read_state()? else {
            return Ok(None);
        };
        if id != state.compat.id {
            return Ok(None);
        }
        Ok(Some(compat_record(state)))
    }

    pub fn read_record_by_name(&self, name: &str) -> io::Result<Option<PolicyRecord>> {
        let Some(state) = self.read_state()? else {
            return Ok(None);
        };
        if state
            .compat
            .name
            .as_deref()
            .is_some_and(|candidate| policy_names_equal(candidate, name))
        {
            return Ok(Some(compat_record(state)));
        }
        Ok(None)
    }

    pub fn name_in_use_by_other_record(
        &self,
        name: &str,
        exclude_id: Option<Uuid>,
    ) -> io::Result<bool> {
        let Some(state) = self.read_state()? else {
            return Ok(false);
        };
        Ok(exclude_id.map(|id| id != state.compat.id).unwrap_or(true)
            && state
                .compat
                .name
                .as_deref()
                .is_some_and(|candidate| policy_names_equal(candidate, name)))
    }

    pub fn set_active(&self, id: Option<Uuid>) -> io::Result<()> {
        let mut state = self.load_or_bootstrap_singleton()?;
        match id {
            Some(id) => {
                if state.compat.id == id {
                    state.compat.active = true;
                }
            }
            None => state.compat.active = false,
        };
        self.write_state(&state)
    }

    pub fn active_id(&self) -> io::Result<Option<Uuid>> {
        if let Some(state) = self.read_state()? {
            return Ok(state.compat.active.then_some(state.compat.id));
        }
        if let Some(state) = self.read_legacy_active_state()? {
            return Ok(state.compat.active.then_some(state.compat.id));
        }
        Ok(None)
    }

    pub fn read_index(&self) -> io::Result<PolicyIndex> {
        let Some(state) = self.read_state()? else {
            return Ok(PolicyIndex::default());
        };
        Ok(PolicyIndex {
            policies: vec![PolicyMeta::from(&compat_record(state))],
        })
    }

    #[allow(dead_code)]
    fn write_index(&self, _index: &PolicyIndex) -> io::Result<()> {
        self.load_or_bootstrap_singleton().map(|_| ())
    }

    fn active_path(&self) -> PathBuf {
        self.base_dir.join("active.json")
    }

    fn policy_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join("policies").join(format!("{id}.json"))
    }

    fn state_path(&self) -> PathBuf {
        self.base_dir.join("policy.json")
    }

    fn read_legacy_active_state(&self) -> io::Result<Option<StoredPolicy>> {
        let active: Option<PolicyActive> = read_json(&self.active_path())?;
        let Some(active) = active else {
            return Ok(None);
        };
        let record: Option<PolicyRecord> = read_json(&self.policy_path(active.id))?;
        match record {
            Some(record) if record.mode.is_active() => Ok(Some(stored_policy_from_record(&record))),
            _ => Ok(None),
        }
    }
}

pub fn policy_item_key(id: Uuid) -> Vec<u8> {
    format!("policies/item/{id}").into_bytes()
}

pub fn singleton_policy_id() -> Uuid {
    Uuid::nil()
}

fn compat_record(state: StoredPolicy) -> PolicyRecord {
    PolicyRecord {
        id: state.compat.id,
        created_at: state.compat.created_at,
        name: state.compat.name,
        mode: state.compat.mode,
        policy: state.policy,
    }
}

fn stored_policy_from_record(record: &PolicyRecord) -> StoredPolicy {
    StoredPolicy {
        policy: record.policy.clone(),
        compat: StoredPolicyCompat {
            id: record.id,
            created_at: record.created_at.clone(),
            name: sanitize_policy_name(record.name.clone()),
            mode: record.mode,
            active: record.mode.is_active(),
        },
    }
}

fn default_created_at() -> String {
    "1970-01-01T00:00:00Z".to_string()
}

fn default_active() -> bool {
    true
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

pub fn policy_names_equal(lhs: &str, rhs: &str) -> bool {
    lhs.trim().eq_ignore_ascii_case(rhs.trim())
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

    fn write_legacy_record(store: &PolicyDiskStore, record: &PolicyRecord) {
        store.ensure().unwrap();
        fs::create_dir_all(store.policy_path(record.id).parent().unwrap()).unwrap();
        fs::write(
            store.policy_path(record.id),
            serde_json::to_vec_pretty(record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn read_state_rejects_invalid_json() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        fs::write(store.state_path(), b"{not-json").unwrap();

        let err = store
            .read_state()
            .expect_err("expected invalid singleton json");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn list_records_bootstraps_singleton_when_missing() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());

        let records = store.list_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, singleton_policy_id());
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

        let path = store.state_path();
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
    fn read_record_by_name_matches_case_insensitively() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        let record = sample_record();
        store.write_record(&record).unwrap();

        let fetched = store
            .read_record_by_name("  TEST-policy ")
            .unwrap()
            .unwrap();
        assert_eq!(fetched.id, record.id);
    }

    #[test]
    fn read_record_by_name_reuses_latest_singleton_name() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        let first = sample_record();
        let second = PolicyRecord::new(
            PolicyMode::Audit,
            sample_policy(),
            Some("TEST-policy".to_string()),
        )
        .unwrap();
        store.write_record(&first).unwrap();
        store.write_record(&second).unwrap();

        let fetched = store.read_record_by_name("test-policy").unwrap().unwrap();
        assert_eq!(fetched.id, second.id);
        assert_eq!(fetched.mode, PolicyMode::Audit);
    }

    #[test]
    fn name_in_use_by_other_record_matches_singleton_name() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        let first = sample_record();
        store.write_record(&first).unwrap();

        assert!(!store
            .name_in_use_by_other_record("TEST-policy", Some(first.id))
            .unwrap());
        assert!(store
            .name_in_use_by_other_record("test-policy", None)
            .unwrap());
    }

    #[test]
    fn write_record_returns_io_error_when_base_path_is_blocked() {
        let dir = TempDir::new().unwrap();
        let blocked = dir.path().join("blocked");
        fs::write(&blocked, b"not-a-directory").unwrap();
        let store = PolicyDiskStore::new(blocked);

        let err = store
            .write_record(&sample_record())
            .expect_err("expected base path collision to fail");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));
    }

    #[test]
    fn disk_store_reads_legacy_active_record_with_schema_compatibility() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        store.ensure().unwrap();

        let id = Uuid::new_v4();
        fs::write(
            store.active_path(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "ignored_active_field": true
            }))
            .unwrap(),
        )
        .unwrap();
        fs::create_dir_all(store.policy_path(id).parent().unwrap()).unwrap();
        fs::write(
            store.policy_path(id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "mode": "enforce",
                "policy": serde_json::to_value(sample_policy()).unwrap(),
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = store.load_or_bootstrap_singleton().unwrap();
        assert!(matches!(
            state.policy.default_policy,
            Some(crate::controlplane::policy_config::PolicyValue::String(ref value))
                if value == "deny"
        ));
    }

    #[test]
    fn migrate_active_legacy_policy_to_singleton() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        let record = sample_record();
        write_legacy_record(&store, &record);
        fs::write(
            store.active_path(),
            serde_json::to_vec_pretty(&PolicyActive { id: record.id }).unwrap(),
        )
        .unwrap();

        let state = store.load_or_bootstrap_singleton().unwrap();

        assert_eq!(
            serde_json::to_value(&state.policy).unwrap(),
            serde_json::to_value(&record.policy).unwrap()
        );
        let persisted = store.read_state().unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&persisted.policy).unwrap(),
            serde_json::to_value(&record.policy).unwrap()
        );
    }

    #[test]
    fn inactive_legacy_records_are_ignored_when_bootstrapping_singleton() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());
        let record = PolicyRecord::new(
            PolicyMode::Disabled,
            serde_yaml::from_str(
                r#"
default_policy: allow
source_groups:
  - id: inactive-legacy
    mode: enforce
    sources:
      ips: ["192.0.2.10"]
    rules: []
"#,
            )
            .unwrap(),
            None,
        )
        .unwrap();
        write_legacy_record(&store, &record);
        fs::write(
            store.active_path(),
            serde_json::to_vec_pretty(&PolicyActive { id: record.id }).unwrap(),
        )
        .unwrap();

        let state = store.load_or_bootstrap_singleton().unwrap();

        assert_ne!(
            serde_json::to_value(&state.policy).unwrap(),
            serde_json::to_value(&record.policy).unwrap()
        );
        assert!(matches!(
            state.policy.default_policy,
            Some(crate::controlplane::policy_config::PolicyValue::String(ref value))
                if value == "deny"
        ));
        assert!(state.policy.source_groups.is_empty());
    }

    #[test]
    fn bootstrap_singleton_policy_when_missing() {
        let dir = TempDir::new().unwrap();
        let store = PolicyDiskStore::new(dir.path().to_path_buf());

        let state = store.load_or_bootstrap_singleton().unwrap();

        assert!(matches!(
            state.policy.default_policy,
            Some(crate::controlplane::policy_config::PolicyValue::String(ref value))
                if value == "deny"
        ));
        assert!(state.policy.source_groups.is_empty());
        assert!(store.read_state().unwrap().is_some());
    }
}
