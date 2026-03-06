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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIndex {
    pub policies: Vec<PolicyMeta>,
}

impl Default for PolicyIndex {
    fn default() -> Self {
        Self {
            policies: Vec::new(),
        }
    }
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
