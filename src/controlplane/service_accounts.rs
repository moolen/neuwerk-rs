use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

const SERVICE_ACCOUNTS_INDEX_KEY: &[u8] = b"auth/service-accounts/index";

fn account_item_key(id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/item/{id}").into_bytes()
}

fn token_index_key(account_id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/tokens/index/{account_id}").into_bytes()
}

fn token_item_key(token_id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/tokens/item/{token_id}").into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAccountStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub status: ServiceAccountStatus,
}

impl ServiceAccount {
    pub fn new(name: String, description: Option<String>, created_by: String) -> Result<Self, String> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format created_at: {err}"))?;
        Ok(Self {
            id: Uuid::new_v4(),
            name,
            description,
            created_at,
            created_by,
            status: ServiceAccountStatus::Active,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TokenStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMeta {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub name: Option<String>,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub last_used_at: Option<String>,
    pub kid: String,
    pub status: TokenStatus,
}

impl TokenMeta {
    pub fn new(
        service_account_id: Uuid,
        name: Option<String>,
        created_by: String,
        kid: String,
        expires_at: Option<String>,
        token_id: Uuid,
    ) -> Result<Self, String> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format created_at: {err}"))?;
        Ok(Self {
            id: token_id,
            service_account_id,
            name,
            created_at,
            created_by,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            kid,
            status: TokenStatus::Active,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ServiceAccountIndex {
    accounts: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenIndex {
    tokens: Vec<Uuid>,
}

#[derive(Clone)]
pub struct ServiceAccountDiskStore {
    base_dir: PathBuf,
}

impl ServiceAccountDiskStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(self.base_dir.join("accounts"))?;
        fs::create_dir_all(self.base_dir.join("tokens").join("index"))?;
        Ok(())
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.json")
    }

    fn account_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join("accounts").join(format!("{id}.json"))
    }

    fn token_index_path(&self, account_id: Uuid) -> PathBuf {
        self.base_dir
            .join("tokens")
            .join("index")
            .join(format!("{account_id}.json"))
    }

    fn token_path(&self, token_id: Uuid) -> PathBuf {
        self.base_dir.join("tokens").join(format!("{token_id}.json"))
    }

    fn read_index(&self) -> io::Result<ServiceAccountIndex> {
        let path = self.index_path();
        Ok(read_json(&path)?.unwrap_or_default())
    }

    fn write_index(&self, index: &ServiceAccountIndex) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(index).map_err(to_io_err)?;
        atomic_write(&self.index_path(), &payload)
    }

    fn read_token_index(&self, account_id: Uuid) -> io::Result<TokenIndex> {
        let path = self.token_index_path(account_id);
        Ok(read_json(&path)?.unwrap_or_default())
    }

    fn write_token_index(&self, account_id: Uuid, index: &TokenIndex) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(index).map_err(to_io_err)?;
        atomic_write(&self.token_index_path(account_id), &payload)
    }

    pub fn write_account(&self, account: &ServiceAccount) -> io::Result<()> {
        self.ensure()?;
        let payload = serde_json::to_vec_pretty(account).map_err(to_io_err)?;
        atomic_write(&self.account_path(account.id), &payload)?;
        let mut index = self.read_index()?;
        if !index.accounts.contains(&account.id) {
            index.accounts.push(account.id);
        }
        self.write_index(&index)?;
        Ok(())
    }

    pub fn read_account(&self, id: Uuid) -> io::Result<Option<ServiceAccount>> {
        read_json(&self.account_path(id))
    }

    pub fn list_accounts(&self) -> io::Result<Vec<ServiceAccount>> {
        let index = self.read_index()?;
        let mut accounts = Vec::with_capacity(index.accounts.len());
        for id in index.accounts {
            let account = self
                .read_account(id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing account record"))?;
            accounts.push(account);
        }
        Ok(accounts)
    }

    pub fn write_token(&self, token: &TokenMeta) -> io::Result<()> {
        self.ensure()?;
        let payload = serde_json::to_vec_pretty(token).map_err(to_io_err)?;
        atomic_write(&self.token_path(token.id), &payload)?;
        let mut index = self.read_token_index(token.service_account_id)?;
        if !index.tokens.contains(&token.id) {
            index.tokens.push(token.id);
        }
        self.write_token_index(token.service_account_id, &index)?;
        Ok(())
    }

    pub fn read_token(&self, token_id: Uuid) -> io::Result<Option<TokenMeta>> {
        read_json(&self.token_path(token_id))
    }

    pub fn list_tokens(&self, account_id: Uuid) -> io::Result<Vec<TokenMeta>> {
        let index = self.read_token_index(account_id)?;
        let mut tokens = Vec::with_capacity(index.tokens.len());
        for token_id in index.tokens {
            let token = self
                .read_token(token_id)?
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing token record"))?;
            tokens.push(token);
        }
        Ok(tokens)
    }
}

#[derive(Clone)]
pub struct ServiceAccountClusterStore {
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
}

impl ServiceAccountClusterStore {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>, store: ClusterStore) -> Self {
        Self { raft, store }
    }

    fn read_index(&self) -> Result<ServiceAccountIndex, String> {
        let raw = self.store.get_state_value(SERVICE_ACCOUNTS_INDEX_KEY)?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
            None => Ok(ServiceAccountIndex::default()),
        }
    }

    async fn write_index(&self, index: &ServiceAccountIndex) -> Result<(), String> {
        let payload = serde_json::to_vec(index).map_err(|err| err.to_string())?;
        self.put_state(SERVICE_ACCOUNTS_INDEX_KEY.to_vec(), payload)
            .await
    }

    fn read_token_index(&self, account_id: Uuid) -> Result<TokenIndex, String> {
        let raw = self.store.get_state_value(&token_index_key(account_id))?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
            None => Ok(TokenIndex::default()),
        }
    }

    async fn write_token_index(&self, account_id: Uuid, index: &TokenIndex) -> Result<(), String> {
        let payload = serde_json::to_vec(index).map_err(|err| err.to_string())?;
        self.put_state(token_index_key(account_id), payload).await
    }

    async fn put_state(&self, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        let cmd = ClusterCommand::Put { key, value };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    pub fn read_account(&self, id: Uuid) -> Result<Option<ServiceAccount>, String> {
        let raw = self.store.get_state_value(&account_item_key(id))?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map(Some).map_err(|err| err.to_string()),
            None => Ok(None),
        }
    }

    pub fn list_accounts(&self) -> Result<Vec<ServiceAccount>, String> {
        let index = self.read_index()?;
        let mut accounts = Vec::with_capacity(index.accounts.len());
        for id in index.accounts {
            let account = self
                .read_account(id)?
                .ok_or_else(|| "missing account record".to_string())?;
            accounts.push(account);
        }
        Ok(accounts)
    }

    pub async fn write_account(&self, account: &ServiceAccount) -> Result<(), String> {
        let payload = serde_json::to_vec(account).map_err(|err| err.to_string())?;
        self.put_state(account_item_key(account.id), payload).await?;
        let mut index = self.read_index()?;
        if !index.accounts.contains(&account.id) {
            index.accounts.push(account.id);
        }
        self.write_index(&index).await?;
        Ok(())
    }

    pub fn read_token(&self, token_id: Uuid) -> Result<Option<TokenMeta>, String> {
        let raw = self.store.get_state_value(&token_item_key(token_id))?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map(Some).map_err(|err| err.to_string()),
            None => Ok(None),
        }
    }

    pub fn list_tokens(&self, account_id: Uuid) -> Result<Vec<TokenMeta>, String> {
        let index = self.read_token_index(account_id)?;
        let mut tokens = Vec::with_capacity(index.tokens.len());
        for token_id in index.tokens {
            let token = self
                .read_token(token_id)?
                .ok_or_else(|| "missing token record".to_string())?;
            tokens.push(token);
        }
        Ok(tokens)
    }

    pub async fn write_token(&self, token: &TokenMeta) -> Result<(), String> {
        let payload = serde_json::to_vec(token).map_err(|err| err.to_string())?;
        self.put_state(token_item_key(token.id), payload).await?;
        let mut index = self.read_token_index(token.service_account_id)?;
        if !index.tokens.contains(&token.id) {
            index.tokens.push(token.id);
        }
        self.write_token_index(token.service_account_id, &index).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub enum ServiceAccountStore {
    Cluster(ServiceAccountClusterStore),
    Local(ServiceAccountDiskStore),
}

impl ServiceAccountStore {
    pub fn cluster(raft: openraft::Raft<ClusterTypeConfig>, store: ClusterStore) -> Self {
        Self::Cluster(ServiceAccountClusterStore::new(raft, store))
    }

    pub fn local(base_dir: PathBuf) -> Self {
        Self::Local(ServiceAccountDiskStore::new(base_dir))
    }

    pub async fn create_account(
        &self,
        name: String,
        description: Option<String>,
        created_by: String,
    ) -> Result<ServiceAccount, String> {
        let account = ServiceAccount::new(name, description, created_by)?;
        match self {
            ServiceAccountStore::Cluster(store) => {
                store.write_account(&account).await?;
            }
            ServiceAccountStore::Local(store) => {
                store
                    .write_account(&account)
                    .map_err(|err| err.to_string())?;
            }
        }
        Ok(account)
    }

    pub async fn list_accounts(&self) -> Result<Vec<ServiceAccount>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.list_accounts(),
            ServiceAccountStore::Local(store) => store.list_accounts().map_err(|err| err.to_string()),
        }
    }

    pub async fn get_account(&self, id: Uuid) -> Result<Option<ServiceAccount>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.read_account(id),
            ServiceAccountStore::Local(store) => store.read_account(id).map_err(|err| err.to_string()),
        }
    }

    pub async fn update_account(&self, account: &ServiceAccount) -> Result<(), String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.write_account(account).await,
            ServiceAccountStore::Local(store) => store
                .write_account(account)
                .map_err(|err| err.to_string()),
        }
    }

    pub async fn list_tokens(&self, account_id: Uuid) -> Result<Vec<TokenMeta>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.list_tokens(account_id),
            ServiceAccountStore::Local(store) => store.list_tokens(account_id).map_err(|err| err.to_string()),
        }
    }

    pub async fn get_token(&self, token_id: Uuid) -> Result<Option<TokenMeta>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.read_token(token_id),
            ServiceAccountStore::Local(store) => store.read_token(token_id).map_err(|err| err.to_string()),
        }
    }

    pub async fn write_token(&self, token: &TokenMeta) -> Result<(), String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.write_token(token).await,
            ServiceAccountStore::Local(store) => store
                .write_token(token)
                .map_err(|err| err.to_string()),
        }
    }
}

pub fn parse_ttl_secs(value: &str) -> Result<i64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("ttl value is empty".to_string());
    }
    let (num, unit) = value.split_at(value.len() - 1);
    let (num, multiplier) = if num.chars().all(|c| c.is_ascii_digit()) {
        let multiplier = match unit {
            "s" | "S" => 1,
            "m" | "M" => 60,
            "h" | "H" => 60 * 60,
            "d" | "D" => 24 * 60 * 60,
            _ => {
                return value
                    .parse::<i64>()
                    .map_err(|_| format!("invalid ttl duration: {value}"));
            }
        };
        (num, multiplier)
    } else {
        (value, 1)
    };
    let parsed = num
        .parse::<i64>()
        .map_err(|_| format!("invalid ttl duration: {value}"))?;
    if parsed <= 0 {
        return Err("ttl must be positive".to_string());
    }
    parsed
        .checked_mul(multiplier)
        .ok_or_else(|| "ttl duration overflow".to_string())
}

pub fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|err| format!("invalid timestamp: {err}"))
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

    #[test]
    fn disk_store_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));

        let account = ServiceAccount::new(
            "svc".to_string(),
            Some("desc".to_string()),
            "creator".to_string(),
        )
        .unwrap();
        store.write_account(&account).unwrap();
        let loaded = store.read_account(account.id).unwrap().unwrap();
        assert_eq!(loaded.name, "svc");

        let token = TokenMeta::new(
            account.id,
            Some("tok".to_string()),
            "creator".to_string(),
            "kid".to_string(),
            None,
            Uuid::new_v4(),
        )
        .unwrap();
        store.write_token(&token).unwrap();
        let tokens = store.list_tokens(account.id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kid, "kid");
    }
}
