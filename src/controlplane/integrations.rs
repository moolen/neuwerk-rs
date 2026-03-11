use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::cluster::bootstrap::ca::{decrypt_ca_key, encrypt_ca_key, CaEnvelope};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIntegrationRecord {
    pub id: Uuid,
    pub created_at: String,
    pub name: String,
    pub kind: IntegrationKind,
    pub api_server_url: String,
    pub ca_cert_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_token_envelope: Option<CaEnvelope>,
}

#[derive(Clone)]
enum IntegrationSecretSealer {
    Local { key_path: PathBuf },
    Token { token_path: PathBuf },
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

impl StoredIntegrationRecord {
    fn from_record(
        record: &IntegrationRecord,
        sealer: &IntegrationSecretSealer,
    ) -> Result<Self, String> {
        Ok(Self {
            id: record.id,
            created_at: record.created_at.clone(),
            name: record.name.clone(),
            kind: record.kind,
            api_server_url: record.api_server_url.clone(),
            ca_cert_pem: record.ca_cert_pem.clone(),
            service_account_token: None,
            service_account_token_envelope: Some(
                sealer.seal(record.service_account_token.as_bytes())?,
            ),
        })
    }

    fn into_record(self, sealer: &IntegrationSecretSealer) -> Result<IntegrationRecord, String> {
        let token = match (
            self.service_account_token_envelope,
            self.service_account_token,
        ) {
            (Some(envelope), _) => {
                let plain = sealer.open(&envelope)?;
                String::from_utf8(plain)
                    .map_err(|err| format!("integration token utf8 decode failed: {err}"))?
            }
            (None, Some(legacy)) => legacy,
            (None, None) => return Err("integration token missing".to_string()),
        };
        Ok(IntegrationRecord {
            id: self.id,
            created_at: self.created_at,
            name: self.name,
            kind: self.kind,
            api_server_url: self.api_server_url,
            ca_cert_pem: self.ca_cert_pem,
            service_account_token: token,
        })
    }
}

impl IntegrationSecretSealer {
    fn local(base_dir: &Path) -> Self {
        Self::Local {
            key_path: base_dir.join("secret.key"),
        }
    }

    fn token(token_path: PathBuf) -> Self {
        Self::Token { token_path }
    }

    fn seal(&self, plaintext: &[u8]) -> Result<CaEnvelope, String> {
        match self {
            IntegrationSecretSealer::Local { key_path } => {
                let key = load_or_create_local_key(key_path)?;
                encrypt_ca_key("local-v1", &key, plaintext).map_err(|err| err.to_string())
            }
            IntegrationSecretSealer::Token { token_path } => {
                let tokens = TokenStore::load(token_path).map_err(|err| err.to_string())?;
                let active = tokens
                    .current(OffsetDateTime::now_utc())
                    .map_err(|err| err.to_string())?;
                encrypt_ca_key(&active.kid, &active.token, plaintext).map_err(|err| err.to_string())
            }
        }
    }

    fn open(&self, envelope: &CaEnvelope) -> Result<Vec<u8>, String> {
        match self {
            IntegrationSecretSealer::Local { key_path } => {
                let key = load_or_create_local_key(key_path)?;
                decrypt_ca_key(envelope, &key).map_err(|err| err.to_string())
            }
            IntegrationSecretSealer::Token { token_path } => {
                let tokens = TokenStore::load(token_path).map_err(|err| err.to_string())?;
                let token = tokens
                    .get(&envelope.kid)
                    .ok_or_else(|| "missing token for integration secret envelope".to_string())?;
                decrypt_ca_key(envelope, &token.token).map_err(|err| err.to_string())
            }
        }
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
    secret_sealer: IntegrationSecretSealer,
}

impl IntegrationDiskStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            secret_sealer: IntegrationSecretSealer::local(&base_dir),
            base_dir,
        }
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
        atomic_write(&self.index_path(), &payload, 0o600)
    }

    pub fn write_record(&self, record: &IntegrationRecord) -> io::Result<()> {
        self.ensure()?;
        let stored =
            StoredIntegrationRecord::from_record(record, &self.secret_sealer).map_err(to_io_err)?;
        let payload = serde_json::to_vec_pretty(&stored).map_err(to_io_err)?;
        atomic_write(&self.item_path(record.id), &payload, 0o600)?;

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
        let stored: Option<StoredIntegrationRecord> = read_json(&self.item_path(id))?;
        stored
            .map(|record| record.into_record(&self.secret_sealer).map_err(to_io_err))
            .transpose()
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
    secret_sealer: IntegrationSecretSealer,
}

impl IntegrationClusterStore {
    pub fn new(
        raft: openraft::Raft<ClusterTypeConfig>,
        store: ClusterStore,
        token_path: PathBuf,
    ) -> Self {
        Self {
            raft,
            store,
            secret_sealer: IntegrationSecretSealer::token(token_path),
        }
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
            Some(raw) => {
                let stored: StoredIntegrationRecord =
                    serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
                let record = stored.into_record(&self.secret_sealer)?;
                Ok(Some(record))
            }
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
        let stored = StoredIntegrationRecord::from_record(record, &self.secret_sealer)?;
        let payload = serde_json::to_vec(&stored).map_err(|err| err.to_string())?;
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
    pub fn cluster(
        raft: openraft::Raft<ClusterTypeConfig>,
        store: ClusterStore,
        token_path: PathBuf,
    ) -> Self {
        Self::Cluster(IntegrationClusterStore::new(raft, store, token_path))
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
    validate_api_server_url(api_server_url)?;
    if ca_cert_pem.trim().is_empty() {
        return Err("ca_cert_pem is required".to_string());
    }
    if service_account_token.trim().is_empty() {
        return Err("service_account_token is required".to_string());
    }
    Ok(())
}

fn validate_api_server_url(raw: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(raw.trim())
        .map_err(|_| "api_server_url must be a valid absolute URL".to_string())?;
    if url.host_str().is_none() {
        return Err("api_server_url must include a host".to_string());
    }
    let scheme = url.scheme();
    if scheme.eq_ignore_ascii_case("https") {
        return Ok(());
    }
    if scheme.eq_ignore_ascii_case("http") && api_server_url_is_loopback(&url) {
        return Ok(());
    }
    Err(
        "api_server_url must use https (http is allowed only for loopback test endpoints)"
            .to_string(),
    )
}

fn api_server_url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    write_with_mode(&tmp, contents, mode)?;
    fs::rename(&tmp, path)?;
    ensure_permissions(path, mode)?;
    Ok(())
}

fn load_or_create_local_key(path: &Path) -> Result<Vec<u8>, String> {
    if path.exists() {
        let key = fs::read(path).map_err(|err| err.to_string())?;
        if key.len() == 32 {
            ensure_permissions(path, 0o600).map_err(|err| err.to_string())?;
            return Ok(key);
        }
        return Err("integration secret key must be 32 bytes".to_string());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let mut key = vec![0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| "integration secret key generation failed".to_string())?;
    write_with_mode(path, &key, 0o600).map_err(|err| err.to_string())?;
    Ok(key)
}

fn write_with_mode(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    ensure_permissions(path, mode)?;
    Ok(())
}

fn ensure_permissions(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms)?;
    }
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
    io::Error::other(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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

    #[tokio::test]
    async fn rejects_non_https_non_loopback_api_server_url() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationStore::local(dir.path().join("integrations"));
        let err = store
            .create_kubernetes(
                "prod".to_string(),
                "http://10.0.0.10:6443".to_string(),
                "ca".to_string(),
                "token".to_string(),
            )
            .await
            .unwrap_err();
        assert!(err.contains("must use https"));
    }

    #[tokio::test]
    async fn rejects_malformed_api_server_url() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationStore::local(dir.path().join("integrations"));
        let err = store
            .create_kubernetes(
                "prod".to_string(),
                "not-a-url".to_string(),
                "ca".to_string(),
                "token".to_string(),
            )
            .await
            .unwrap_err();
        assert!(err.contains("valid absolute URL"));
    }

    #[tokio::test]
    async fn allows_http_loopback_api_server_url_for_local_tests() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationStore::local(dir.path().join("integrations"));
        let created = store
            .create_kubernetes(
                "prod".to_string(),
                "http://127.0.0.1:6443".to_string(),
                "ca".to_string(),
                "token".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(created.api_server_url, "http://127.0.0.1:6443");
    }

    #[test]
    fn disk_store_encrypts_service_account_token_at_rest() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationDiskStore::new(dir.path().join("integrations"));
        let record = IntegrationRecord::new_kubernetes(
            "prod".to_string(),
            "https://127.0.0.1:6443".to_string(),
            "ca".to_string(),
            "secret-token".to_string(),
        )
        .unwrap();

        store.write_record(&record).unwrap();
        let raw = fs::read_to_string(store.item_path(record.id)).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(parsed.get("service_account_token").is_none());
        let envelope = parsed
            .get("service_account_token_envelope")
            .and_then(|v| v.as_object())
            .expect("missing service_account_token_envelope");
        assert!(envelope.get("ciphertext").is_some());
        assert!(!raw.contains("secret-token"));

        let loaded = store.read_record(record.id).unwrap().unwrap();
        assert_eq!(loaded.service_account_token, "secret-token");
    }

    #[cfg(unix)]
    #[test]
    fn disk_store_secret_files_use_600_permissions() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationDiskStore::new(dir.path().join("integrations"));
        let record = IntegrationRecord::new_kubernetes(
            "prod".to_string(),
            "https://127.0.0.1:6443".to_string(),
            "ca".to_string(),
            "secret-token".to_string(),
        )
        .unwrap();

        store.write_record(&record).unwrap();
        let item_mode = fs::metadata(store.item_path(record.id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let index_mode = fs::metadata(store.index_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = fs::metadata(store.base_dir().join("secret.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(item_mode, 0o600);
        assert_eq!(index_mode, 0o600);
        assert_eq!(key_mode, 0o600);
    }

    #[tokio::test]
    async fn disk_store_persists_across_restart_and_recovers_token_envelope() {
        let dir = TempDir::new().unwrap();
        let base_dir = dir.path().join("integrations");

        let store = IntegrationStore::local(base_dir.clone());
        let created = store
            .create_kubernetes(
                "prod".to_string(),
                "https://127.0.0.1:6443".to_string(),
                "ca-1".to_string(),
                "token-1".to_string(),
            )
            .await
            .unwrap();

        let restarted = IntegrationStore::local(base_dir.clone());
        let recovered = restarted
            .get_by_name_kind("prod", IntegrationKind::Kubernetes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.id, created.id);
        assert_eq!(recovered.api_server_url, "https://127.0.0.1:6443");
        assert_eq!(recovered.ca_cert_pem, "ca-1");
        assert_eq!(recovered.service_account_token, "token-1");

        let updated = restarted
            .update_kubernetes(
                "prod",
                "https://10.0.0.20:6443".to_string(),
                "ca-2".to_string(),
                "token-2".to_string(),
            )
            .await
            .unwrap();
        assert_eq!(updated.id, created.id);

        let restarted_again = IntegrationStore::local(base_dir.clone());
        let final_record = restarted_again
            .get_by_name_kind("prod", IntegrationKind::Kubernetes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(final_record.id, created.id);
        assert_eq!(final_record.api_server_url, "https://10.0.0.20:6443");
        assert_eq!(final_record.ca_cert_pem, "ca-2");
        assert_eq!(final_record.service_account_token, "token-2");

        let records = restarted_again.list_records().await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, created.id);
    }

    #[test]
    fn disk_store_write_record_returns_io_error_when_integrations_path_is_blocked() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationDiskStore::new(dir.path().join("integrations"));
        fs::create_dir_all(store.base_dir()).unwrap();
        fs::write(store.base_dir().join("integrations"), b"not-a-directory").unwrap();
        let record = IntegrationRecord::new_kubernetes(
            "prod".to_string(),
            "https://127.0.0.1:6443".to_string(),
            "ca".to_string(),
            "secret-token".to_string(),
        )
        .unwrap();

        let err = store
            .write_record(&record)
            .expect_err("expected blocked integrations path to fail");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));
    }

    #[test]
    fn disk_store_reads_legacy_plaintext_record_and_ignores_unknown_fields() {
        let dir = TempDir::new().unwrap();
        let store = IntegrationDiskStore::new(dir.path().join("integrations"));
        store.ensure().unwrap();

        let id = Uuid::new_v4();
        let record_path = store.item_path(id);
        let index = serde_json::json!({
            "integrations": [{
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "name": "prod",
                "kind": "kubernetes",
                "ignored_meta": true
            }],
            "ignored_index_field": "compat"
        });
        fs::write(
            store.index_path(),
            serde_json::to_vec_pretty(&index).unwrap(),
        )
        .unwrap();
        fs::write(
            &record_path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "name": "prod",
                "kind": "kubernetes",
                "api_server_url": "https://127.0.0.1:6443",
                "ca_cert_pem": "legacy-ca",
                "service_account_token": "legacy-token",
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let records = store.list_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, id);
        assert_eq!(records[0].name, "prod");
        assert_eq!(records[0].ca_cert_pem, "legacy-ca");
        assert_eq!(records[0].service_account_token, "legacy-token");
    }

    #[test]
    fn stored_record_reads_legacy_plaintext_without_creating_secret_key() {
        let dir = TempDir::new().unwrap();
        let sealer = IntegrationSecretSealer::local(dir.path());
        let stored: StoredIntegrationRecord = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "created_at": "2026-03-09T12:00:00Z",
            "name": "prod",
            "kind": "kubernetes",
            "api_server_url": "https://127.0.0.1:6443",
            "ca_cert_pem": "legacy-ca",
            "service_account_token": "legacy-token"
        }))
        .unwrap();

        let loaded = stored.into_record(&sealer).unwrap();
        assert_eq!(loaded.service_account_token, "legacy-token");
        assert!(!dir.path().join("secret.key").exists());
    }

    #[test]
    fn stored_record_prefers_envelope_over_legacy_plaintext_during_mixed_version_upgrade() {
        let dir = TempDir::new().unwrap();
        let sealer = IntegrationSecretSealer::local(dir.path());
        let record = IntegrationRecord::new_kubernetes(
            "prod".to_string(),
            "https://127.0.0.1:6443".to_string(),
            "ca".to_string(),
            "sealed-token".to_string(),
        )
        .unwrap();

        let mut stored = StoredIntegrationRecord::from_record(&record, &sealer).unwrap();
        stored.service_account_token = Some("stale-legacy-token".to_string());

        let loaded = stored.into_record(&sealer).unwrap();
        assert_eq!(loaded.service_account_token, "sealed-token");
    }
}
