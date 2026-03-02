use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub(crate) const INTEGRATIONS_INDEX_KEY: &[u8] = b"integrations/index";

pub(crate) fn integration_item_key(id: Uuid) -> Vec<u8> {
    format!("integrations/item/{id}").into_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrationKind {
    Kubernetes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationRecord {
    pub id: Uuid,
    pub created_at: String,
    pub name: String,
    pub kind: IntegrationKind,
    pub api_server_url: String,
    pub ca_cert_pem: String,
    pub service_account_token: String,
}

impl IntegrationRecord {
    pub fn new_kubernetes(
        name: String,
        api_server_url: String,
        ca_cert_pem: String,
        service_account_token: String,
    ) -> Result<Self, String> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format created_at: {err}"))?;
        Ok(Self {
            id: Uuid::new_v4(),
            created_at,
            name,
            kind: IntegrationKind::Kubernetes,
            api_server_url,
            ca_cert_pem,
            service_account_token,
        })
    }

    pub fn update_kubernetes(
        &mut self,
        api_server_url: String,
        ca_cert_pem: String,
        service_account_token: String,
    ) {
        self.api_server_url = api_server_url;
        self.ca_cert_pem = ca_cert_pem;
        self.service_account_token = service_account_token;
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IntegrationView {
    pub id: Uuid,
    pub created_at: String,
    pub name: String,
    pub kind: IntegrationKind,
    pub api_server_url: String,
    pub ca_cert_pem: String,
    pub auth_type: String,
    pub token_configured: bool,
}

impl From<&IntegrationRecord> for IntegrationView {
    fn from(value: &IntegrationRecord) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at.clone(),
            name: value.name.clone(),
            kind: value.kind,
            api_server_url: value.api_server_url.clone(),
            ca_cert_pem: value.ca_cert_pem.clone(),
            auth_type: "service_account_token".to_string(),
            token_configured: !value.service_account_token.trim().is_empty(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntegrationMeta {
    id: Uuid,
    created_at: String,
    name: String,
    kind: IntegrationKind,
}

impl From<&IntegrationRecord> for IntegrationMeta {
    fn from(value: &IntegrationRecord) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at.clone(),
            name: value.name.clone(),
            kind: value.kind,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct IntegrationIndex {
    integrations: Vec<IntegrationMeta>,
}

#[derive(Clone)]
pub struct IntegrationDiskStore {
    base_dir: PathBuf,
}

impl IntegrationDiskStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(self.base_dir.join("integrations"))
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.json")
    }

    fn item_path(&self, id: Uuid) -> PathBuf {
        self.base_dir
            .join("integrations")
            .join(format!("{id}.json"))
    }

    fn read_index(&self) -> io::Result<IntegrationIndex> {
        let path = self.index_path();
        Ok(read_json(&path)?.unwrap_or_default())
    }

    fn write_index(&self, index: &IntegrationIndex) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(index).map_err(to_io_err)?;
        atomic_write(&self.index_path(), &payload)
    }

    pub fn write_record(&self, record: &IntegrationRecord) -> io::Result<()> {
        self.ensure()?;
        let payload = serde_json::to_vec_pretty(record).map_err(to_io_err)?;
        atomic_write(&self.item_path(record.id), &payload)?;

        let mut index = self.read_index()?;
        let meta = IntegrationMeta::from(record);
        if let Some(existing) = index
            .integrations
            .iter_mut()
            .find(|entry| entry.id == meta.id)
        {
            *existing = meta;
        } else {
            index.integrations.push(meta);
        }
        index.integrations.sort_by(|a, b| {
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

    pub fn list_records(&self) -> io::Result<Vec<IntegrationRecord>> {
        let index = self.read_index()?;
        let mut out = Vec::with_capacity(index.integrations.len());
        for meta in index.integrations {
            let rec = self
                .read_record(meta.id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing integration"))?;
            out.push(rec);
        }
        Ok(out)
    }

    pub fn read_record(&self, id: Uuid) -> io::Result<Option<IntegrationRecord>> {
        read_json(&self.item_path(id))
    }

    pub fn delete_record(&self, id: Uuid) -> io::Result<()> {
        match fs::remove_file(self.item_path(id)) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let mut index = self.read_index()?;
        index.integrations.retain(|entry| entry.id != id);
        self.write_index(&index)
    }
}

#[derive(Clone)]
pub struct IntegrationClusterStore {
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
}

impl IntegrationClusterStore {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>, store: ClusterStore) -> Self {
        Self { raft, store }
    }

    fn read_index(&self) -> Result<IntegrationIndex, String> {
        let raw = self.store.get_state_value(INTEGRATIONS_INDEX_KEY)?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
            None => Ok(IntegrationIndex::default()),
        }
    }

    async fn write_index(&self, index: &IntegrationIndex) -> Result<(), String> {
        let payload = serde_json::to_vec(index).map_err(|err| err.to_string())?;
        self.put_state(INTEGRATIONS_INDEX_KEY.to_vec(), payload)
            .await
    }

    async fn put_state(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        let cmd = ClusterCommand::Put { key, value };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn read_record(&self, id: Uuid) -> Result<Option<IntegrationRecord>, String> {
        let raw = self.store.get_state_value(&integration_item_key(id))?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|err| err.to_string()),
            None => Ok(None),
        }
    }

    pub fn list_records(&self) -> Result<Vec<IntegrationRecord>, String> {
        let index = self.read_index()?;
        let mut out = Vec::with_capacity(index.integrations.len());
        for meta in index.integrations {
            let rec = self
                .read_record(meta.id)?
                .ok_or_else(|| "missing integration".to_string())?;
            out.push(rec);
        }
        Ok(out)
    }

    pub async fn write_record(&self, record: &IntegrationRecord) -> Result<(), String> {
        let payload = serde_json::to_vec(record).map_err(|err| err.to_string())?;
        self.put_state(integration_item_key(record.id), payload)
            .await?;

        let mut index = self.read_index()?;
        let meta = IntegrationMeta::from(record);
        if let Some(existing) = index
            .integrations
            .iter_mut()
            .find(|entry| entry.id == meta.id)
        {
            *existing = meta;
        } else {
            index.integrations.push(meta);
        }
        index.integrations.sort_by(|a, b| {
            let ts = a.created_at.cmp(&b.created_at);
            if ts == std::cmp::Ordering::Equal {
                a.id.as_bytes().cmp(b.id.as_bytes())
            } else {
                ts
            }
        });
        self.write_index(&index).await
    }

    pub async fn delete_record(&self, id: Uuid) -> Result<(), String> {
        let cmd = ClusterCommand::Delete {
            key: integration_item_key(id),
        };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;

        let mut index = self.read_index()?;
        index.integrations.retain(|entry| entry.id != id);
        self.write_index(&index).await
    }
}

#[derive(Clone)]
pub enum IntegrationStore {
    Cluster(IntegrationClusterStore),
    Local(IntegrationDiskStore),
}

impl IntegrationStore {
    pub fn cluster(raft: openraft::Raft<ClusterTypeConfig>, store: ClusterStore) -> Self {
        Self::Cluster(IntegrationClusterStore::new(raft, store))
    }

    pub fn local(base_dir: PathBuf) -> Self {
        Self::Local(IntegrationDiskStore::new(base_dir))
    }

    pub async fn list_records(&self) -> Result<Vec<IntegrationRecord>, String> {
        match self {
            IntegrationStore::Cluster(store) => store.list_records(),
            IntegrationStore::Local(store) => store.list_records().map_err(|err| err.to_string()),
        }
    }

    pub async fn get_by_name_kind(
        &self,
        name: &str,
        kind: IntegrationKind,
    ) -> Result<Option<IntegrationRecord>, String> {
        let name = name.trim();
        if name.is_empty() {
            return Ok(None);
        }
        let records = self.list_records().await?;
        Ok(records
            .into_iter()
            .find(|rec| rec.kind == kind && rec.name.eq_ignore_ascii_case(name)))
    }

    pub async fn create_kubernetes(
        &self,
        name: String,
        api_server_url: String,
        ca_cert_pem: String,
        service_account_token: String,
    ) -> Result<IntegrationRecord, String> {
        validate_create_inputs(&name, &api_server_url, &ca_cert_pem, &service_account_token)?;
        if self
            .get_by_name_kind(&name, IntegrationKind::Kubernetes)
            .await?
            .is_some()
        {
            return Err("integration already exists".to_string());
        }
        let record = IntegrationRecord::new_kubernetes(
            name.trim().to_string(),
            api_server_url.trim().to_string(),
            ca_cert_pem.trim().to_string(),
            service_account_token.trim().to_string(),
        )?;
        match self {
            IntegrationStore::Cluster(store) => store.write_record(&record).await?,
            IntegrationStore::Local(store) => {
                store.write_record(&record).map_err(|err| err.to_string())?;
            }
        }
        Ok(record)
    }

    pub async fn update_kubernetes(
        &self,
        name: &str,
        api_server_url: String,
        ca_cert_pem: String,
        service_account_token: String,
    ) -> Result<IntegrationRecord, String> {
        validate_create_inputs(name, &api_server_url, &ca_cert_pem, &service_account_token)?;
        let Some(mut record) = self
            .get_by_name_kind(name, IntegrationKind::Kubernetes)
            .await?
        else {
            return Err("integration not found".to_string());
        };
        record.update_kubernetes(
            api_server_url.trim().to_string(),
            ca_cert_pem.trim().to_string(),
            service_account_token.trim().to_string(),
        );
        match self {
            IntegrationStore::Cluster(store) => store.write_record(&record).await?,
            IntegrationStore::Local(store) => {
                store.write_record(&record).map_err(|err| err.to_string())?;
            }
        }
        Ok(record)
    }

    pub async fn delete_by_name_kind(
        &self,
        name: &str,
        kind: IntegrationKind,
    ) -> Result<bool, String> {
        let Some(record) = self.get_by_name_kind(name, kind).await? else {
            return Ok(false);
        };
        match self {
            IntegrationStore::Cluster(store) => store.delete_record(record.id).await?,
            IntegrationStore::Local(store) => {
                store
                    .delete_record(record.id)
                    .map_err(|err| err.to_string())?;
            }
        }
        Ok(true)
    }
}

fn validate_create_inputs(
    name: &str,
    api_server_url: &str,
    ca_cert_pem: &str,
    service_account_token: &str,
) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("name is required".to_string());
    }
    if api_server_url.trim().is_empty() {
        return Err("api_server_url is required".to_string());
    }
    if ca_cert_pem.trim().is_empty() {
        return Err("ca_cert_pem is required".to_string());
    }
    if service_account_token.trim().is_empty() {
        return Err("service_account_token is required".to_string());
    }
    Ok(())
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

fn to_io_err<E: std::fmt::Display>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn disk_store_round_trip_and_uniqueness() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationStore::local(dir.path().join("integrations"));

        let created = store
            .create_kubernetes(
                "prod".to_string(),
                "https://127.0.0.1:6443".to_string(),
                "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".to_string(),
                "token-1".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(created.kind, IntegrationKind::Kubernetes);

        let dup = store
            .create_kubernetes(
                "PROD".to_string(),
                "https://127.0.0.1:6443".to_string(),
                "ca".to_string(),
                "token-2".to_string(),
            )
            .await;
        assert!(dup.is_err());

        let listed = store.list_records().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "prod");

        let updated = store
            .update_kubernetes(
                "prod",
                "https://10.0.0.1:6443".to_string(),
                "ca2".to_string(),
                "token-3".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(updated.api_server_url, "https://10.0.0.1:6443");

        let found = store
            .get_by_name_kind("prod", IntegrationKind::Kubernetes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.service_account_token, "token-3");

        let deleted = store
            .delete_by_name_kind("prod", IntegrationKind::Kubernetes)
            .await
            .unwrap();
        assert!(deleted);
        assert!(store.list_records().await.unwrap().is_empty());
    }
}
