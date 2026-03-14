use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub(crate) const SERVICE_ACCOUNTS_INDEX_KEY: &[u8] = b"auth/service-accounts/index";

pub(crate) fn account_item_key(id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/item/{id}").into_bytes()
}

pub(crate) fn token_index_key(account_id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/tokens/index/{account_id}").into_bytes()
}

pub(crate) fn token_item_key(token_id: Uuid) -> Vec<u8> {
    format!("auth/service-accounts/tokens/item/{token_id}").into_bytes()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAccountStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAccountRole {
    #[default]
    Readonly,
    Admin,
}

impl ServiceAccountRole {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceAccountRole::Readonly => "readonly",
            ServiceAccountRole::Admin => "admin",
        }
    }

    pub fn allows(self, requested: ServiceAccountRole) -> bool {
        self.rank() >= requested.rank()
    }

    fn rank(self) -> u8 {
        match self {
            ServiceAccountRole::Readonly => 0,
            ServiceAccountRole::Admin => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
    pub created_by: String,
    #[serde(default)]
    pub role: ServiceAccountRole,
    pub status: ServiceAccountStatus,
}

impl ServiceAccount {
    pub fn new(
        name: String,
        description: Option<String>,
        created_by: String,
    ) -> Result<Self, String> {
        Self::new_with_role(name, description, created_by, ServiceAccountRole::Readonly)
    }

    pub fn new_with_role(
        name: String,
        description: Option<String>,
        created_by: String,
        role: ServiceAccountRole,
    ) -> Result<Self, String> {
        let created_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format created_at: {err}"))?;
        Ok(Self {
            id: Uuid::new_v4(),
            name,
            description,
            created_at,
            created_by,
            role,
            status: ServiceAccountStatus::Active,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum TokenStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
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
    #[serde(default)]
    pub role: ServiceAccountRole,
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
        Self::new_with_role(
            service_account_id,
            name,
            created_by,
            kid,
            expires_at,
            token_id,
            ServiceAccountRole::Readonly,
        )
    }

    pub fn new_with_role(
        service_account_id: Uuid,
        name: Option<String>,
        created_by: String,
        kid: String,
        expires_at: Option<String>,
        token_id: Uuid,
        role: ServiceAccountRole,
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
            role,
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
        self.base_dir
            .join("tokens")
            .join(format!("{token_id}.json"))
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
            Some(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|err| err.to_string()),
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
        self.put_state(account_item_key(account.id), payload)
            .await?;
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
            Some(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|err| err.to_string()),
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
        self.write_token_index(token.service_account_id, &index)
            .await?;
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
        self.create_account_with_role(name, description, created_by, ServiceAccountRole::Readonly)
            .await
    }

    pub async fn create_account_with_role(
        &self,
        name: String,
        description: Option<String>,
        created_by: String,
        role: ServiceAccountRole,
    ) -> Result<ServiceAccount, String> {
        let account = ServiceAccount::new_with_role(name, description, created_by, role)?;
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
            ServiceAccountStore::Local(store) => {
                store.list_accounts().map_err(|err| err.to_string())
            }
        }
    }

    pub async fn get_account(&self, id: Uuid) -> Result<Option<ServiceAccount>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.read_account(id),
            ServiceAccountStore::Local(store) => {
                store.read_account(id).map_err(|err| err.to_string())
            }
        }
    }

    pub async fn update_account(&self, account: &ServiceAccount) -> Result<(), String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.write_account(account).await,
            ServiceAccountStore::Local(store) => {
                store.write_account(account).map_err(|err| err.to_string())
            }
        }
    }

    pub async fn list_tokens(&self, account_id: Uuid) -> Result<Vec<TokenMeta>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.list_tokens(account_id),
            ServiceAccountStore::Local(store) => {
                store.list_tokens(account_id).map_err(|err| err.to_string())
            }
        }
    }

    pub async fn get_token(&self, token_id: Uuid) -> Result<Option<TokenMeta>, String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.read_token(token_id),
            ServiceAccountStore::Local(store) => {
                store.read_token(token_id).map_err(|err| err.to_string())
            }
        }
    }

    pub async fn write_token(&self, token: &TokenMeta) -> Result<(), String> {
        match self {
            ServiceAccountStore::Cluster(store) => store.write_token(token).await,
            ServiceAccountStore::Local(store) => {
                store.write_token(token).map_err(|err| err.to_string())
            }
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
    write_with_mode(&tmp, contents, 0o600)?;
    fs::rename(&tmp, path)?;
    ensure_permissions(path, 0o600)?;
    Ok(())
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

    #[test]
    fn disk_store_round_trip() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));

        let account = ServiceAccount::new_with_role(
            "svc".to_string(),
            Some("desc".to_string()),
            "creator".to_string(),
            ServiceAccountRole::Admin,
        )
        .unwrap();
        store.write_account(&account).unwrap();
        let loaded = store.read_account(account.id).unwrap().unwrap();
        assert_eq!(loaded.name, "svc");
        assert_eq!(loaded.role, ServiceAccountRole::Admin);

        let token = TokenMeta::new_with_role(
            account.id,
            Some("tok".to_string()),
            "creator".to_string(),
            "kid".to_string(),
            None,
            Uuid::new_v4(),
            ServiceAccountRole::Admin,
        )
        .unwrap();
        store.write_token(&token).unwrap();
        let tokens = store.list_tokens(account.id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].kid, "kid");
        assert_eq!(tokens[0].role, ServiceAccountRole::Admin);
    }

    #[cfg(unix)]
    #[test]
    fn disk_store_files_use_600_permissions() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));

        let account = ServiceAccount::new("svc".to_string(), None, "creator".to_string()).unwrap();
        store.write_account(&account).unwrap();
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

        let paths = [
            store.index_path(),
            store.account_path(account.id),
            store.token_index_path(account.id),
            store.token_path(token.id),
        ];
        for path in paths {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn disk_store_persists_accounts_and_revoked_tokens_across_restart() {
        let dir = TempDir::new().unwrap();
        let base_dir = dir.path().join("sa");

        let store = ServiceAccountStore::local(base_dir.clone());
        let account = store
            .create_account(
                "svc".to_string(),
                Some("desc".to_string()),
                "creator".to_string(),
            )
            .await
            .unwrap();
        let token_id = Uuid::new_v4();
        let token = TokenMeta::new(
            account.id,
            Some("tok".to_string()),
            "creator".to_string(),
            "kid".to_string(),
            None,
            token_id,
        )
        .unwrap();
        store.write_token(&token).await.unwrap();

        let restarted = ServiceAccountStore::local(base_dir.clone());
        let accounts = restarted.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, account.id);
        assert_eq!(accounts[0].name, "svc");
        assert_eq!(accounts[0].role, ServiceAccountRole::Readonly);

        let mut persisted_token = restarted
            .get_token(token_id)
            .await
            .unwrap()
            .expect("token after restart");
        assert_eq!(persisted_token.status, TokenStatus::Active);
        assert_eq!(persisted_token.role, ServiceAccountRole::Readonly);
        persisted_token.status = TokenStatus::Revoked;
        persisted_token.revoked_at = Some("2026-03-09T12:00:00Z".to_string());
        restarted.write_token(&persisted_token).await.unwrap();

        let restarted_again = ServiceAccountStore::local(base_dir);
        let tokens = restarted_again.list_tokens(account.id).await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, token_id);
        assert_eq!(tokens[0].status, TokenStatus::Revoked);
        assert_eq!(
            tokens[0].revoked_at.as_deref(),
            Some("2026-03-09T12:00:00Z")
        );
    }

    #[test]
    fn write_account_returns_io_error_when_accounts_path_is_blocked() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));
        fs::create_dir_all(store.base_dir()).unwrap();
        fs::write(store.base_dir().join("accounts"), b"not-a-directory").unwrap();

        let account = ServiceAccount::new("svc".to_string(), None, "creator".to_string()).unwrap();
        let err = store
            .write_account(&account)
            .expect_err("expected blocked accounts path to fail");
        assert!(matches!(
            err.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));
    }

    #[test]
    fn disk_store_reads_account_index_and_record_with_schema_compatibility() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));
        store.ensure().unwrap();

        let account_id = Uuid::new_v4();
        fs::write(
            store.index_path(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "accounts": [account_id],
                "ignored_index_field": "compat"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            store.account_path(account_id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": account_id,
                "name": "svc",
                "created_at": "2026-03-09T12:00:00Z",
                "created_by": "bootstrap",
                "status": "active",
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let accounts = store.list_accounts().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, account_id);
        assert_eq!(accounts[0].name, "svc");
        assert_eq!(accounts[0].description, None);
        assert_eq!(accounts[0].role, ServiceAccountRole::Readonly);
        assert_eq!(accounts[0].status, ServiceAccountStatus::Active);
    }

    #[test]
    fn disk_store_reads_token_index_and_record_with_schema_compatibility() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountDiskStore::new(dir.path().join("sa"));
        store.ensure().unwrap();

        let account_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        fs::write(
            store.token_index_path(account_id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "tokens": [token_id],
                "ignored_index_field": "compat"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            store.token_path(token_id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": token_id,
                "service_account_id": account_id,
                "name": "token-a",
                "created_at": "2026-03-09T12:00:00Z",
                "created_by": "bootstrap",
                "kid": "kid-1",
                "status": "active",
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let tokens = store.list_tokens(account_id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, token_id);
        assert_eq!(tokens[0].name.as_deref(), Some("token-a"));
        assert_eq!(tokens[0].expires_at, None);
        assert_eq!(tokens[0].revoked_at, None);
        assert_eq!(tokens[0].last_used_at, None);
        assert_eq!(tokens[0].role, ServiceAccountRole::Readonly);
        assert_eq!(tokens[0].status, TokenStatus::Active);
    }

    #[test]
    fn service_account_role_allows_narrower_roles_only() {
        assert!(ServiceAccountRole::Admin.allows(ServiceAccountRole::Readonly));
        assert!(ServiceAccountRole::Admin.allows(ServiceAccountRole::Admin));
        assert!(ServiceAccountRole::Readonly.allows(ServiceAccountRole::Readonly));
        assert!(!ServiceAccountRole::Readonly.allows(ServiceAccountRole::Admin));
    }
}
