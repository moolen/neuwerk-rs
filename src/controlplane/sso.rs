use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::controlplane::cluster::bootstrap::ca::{decrypt_ca_key, encrypt_ca_key, CaEnvelope};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub(crate) const SSO_PROVIDERS_INDEX_KEY: &[u8] = b"auth/sso/providers/index";
pub(crate) const SSO_STATE_KEY_KEY: &[u8] = b"auth/sso/state_key";

pub(crate) fn sso_provider_item_key(id: Uuid) -> Vec<u8> {
    format!("auth/sso/providers/item/{id}").into_bytes()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SsoProviderKind {
    Google,
    Github,
    GenericOidc,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SsoRole {
    Admin,
    Readonly,
}

impl SsoRole {
    pub fn as_str(self) -> &'static str {
        match self {
            SsoRole::Admin => "admin",
            SsoRole::Readonly => "readonly",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoProvider {
    pub id: Uuid,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    pub kind: SsoProviderKind,
    pub enabled: bool,
    pub display_order: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub pkce_required: bool,
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_role: Option<SsoRole>,
    #[serde(default)]
    pub admin_subjects: Vec<String>,
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub admin_email_domains: Vec<String>,
    #[serde(default)]
    pub readonly_subjects: Vec<String>,
    #[serde(default)]
    pub readonly_groups: Vec<String>,
    #[serde(default)]
    pub readonly_email_domains: Vec<String>,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsoProviderView {
    pub id: Uuid,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    pub kind: SsoProviderKind,
    pub enabled: bool,
    pub display_order: i32,
    pub issuer_url: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub client_id: String,
    pub client_secret_configured: bool,
    pub scopes: Vec<String>,
    pub pkce_required: bool,
    pub subject_claim: String,
    pub email_claim: Option<String>,
    pub groups_claim: Option<String>,
    pub default_role: Option<SsoRole>,
    pub admin_subjects: Vec<String>,
    pub admin_groups: Vec<String>,
    pub admin_email_domains: Vec<String>,
    pub readonly_subjects: Vec<String>,
    pub readonly_groups: Vec<String>,
    pub readonly_email_domains: Vec<String>,
    pub allowed_email_domains: Vec<String>,
    pub session_ttl_secs: u64,
}

impl From<&SsoProvider> for SsoProviderView {
    fn from(value: &SsoProvider) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at.clone(),
            updated_at: value.updated_at.clone(),
            name: value.name.clone(),
            kind: value.kind,
            enabled: value.enabled,
            display_order: value.display_order,
            issuer_url: value.issuer_url.clone(),
            authorization_url: value.authorization_url.clone(),
            token_url: value.token_url.clone(),
            userinfo_url: value.userinfo_url.clone(),
            client_id: value.client_id.clone(),
            client_secret_configured: !value.client_secret.trim().is_empty(),
            scopes: value.scopes.clone(),
            pkce_required: value.pkce_required,
            subject_claim: value.subject_claim.clone(),
            email_claim: value.email_claim.clone(),
            groups_claim: value.groups_claim.clone(),
            default_role: value.default_role,
            admin_subjects: value.admin_subjects.clone(),
            admin_groups: value.admin_groups.clone(),
            admin_email_domains: value.admin_email_domains.clone(),
            readonly_subjects: value.readonly_subjects.clone(),
            readonly_groups: value.readonly_groups.clone(),
            readonly_email_domains: value.readonly_email_domains.clone(),
            allowed_email_domains: value.allowed_email_domains.clone(),
            session_ttl_secs: value.session_ttl_secs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SsoEndpoints {
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

impl SsoProvider {
    pub fn new(
        name: String,
        kind: SsoProviderKind,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, String> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format timestamp: {err}"))?;
        Ok(Self {
            id: Uuid::new_v4(),
            created_at: now.clone(),
            updated_at: now,
            name,
            kind,
            enabled: true,
            display_order: 0,
            issuer_url: None,
            authorization_url: None,
            token_url: None,
            userinfo_url: None,
            client_id,
            client_secret,
            scopes: Vec::new(),
            pkce_required: true,
            subject_claim: default_subject_claim(),
            email_claim: Some("email".to_string()),
            groups_claim: None,
            default_role: Some(SsoRole::Readonly),
            admin_subjects: Vec::new(),
            admin_groups: Vec::new(),
            admin_email_domains: Vec::new(),
            readonly_subjects: Vec::new(),
            readonly_groups: Vec::new(),
            readonly_email_domains: Vec::new(),
            allowed_email_domains: Vec::new(),
            session_ttl_secs: default_session_ttl_secs(),
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("provider name is required".to_string());
        }
        if self.client_id.trim().is_empty() {
            return Err("client_id is required".to_string());
        }
        if self.client_secret.trim().is_empty() {
            return Err("client_secret is required".to_string());
        }
        if self.subject_claim.trim().is_empty() {
            return Err("subject_claim is required".to_string());
        }
        if self.session_ttl_secs == 0 {
            return Err("session_ttl_secs must be >= 1".to_string());
        }
        if self.session_ttl_secs > 60 * 60 * 24 * 30 {
            return Err("session_ttl_secs must be <= 2592000".to_string());
        }
        if let Some(url) = &self.issuer_url {
            validate_url("issuer_url", url)?;
        }
        if let Some(url) = &self.authorization_url {
            validate_url("authorization_url", url)?;
        }
        if let Some(url) = &self.token_url {
            validate_url("token_url", url)?;
        }
        if let Some(url) = &self.userinfo_url {
            validate_url("userinfo_url", url)?;
        }
        for scope in &self.scopes {
            if scope.trim().is_empty() {
                return Err("scopes must not contain empty values".to_string());
            }
        }
        Ok(())
    }

    pub fn scopes_or_default(&self) -> Vec<String> {
        if !self.scopes.is_empty() {
            return self
                .scopes
                .iter()
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty())
                .collect();
        }
        match self.kind {
            SsoProviderKind::Google | SsoProviderKind::GenericOidc => {
                vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ]
            }
            SsoProviderKind::Github => vec!["read:user".to_string(), "user:email".to_string()],
        }
    }

    pub fn endpoints_or_default(&self) -> Result<SsoEndpoints, String> {
        let (default_auth, default_token, default_userinfo) = match self.kind {
            SsoProviderKind::Google => (
                "https://accounts.google.com/o/oauth2/v2/auth",
                "https://oauth2.googleapis.com/token",
                "https://openidconnect.googleapis.com/v1/userinfo",
            ),
            SsoProviderKind::Github => (
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
            ),
            SsoProviderKind::GenericOidc => ("", "", ""),
        };

        let authorization_url = self
            .authorization_url
            .clone()
            .unwrap_or_else(|| default_auth.to_string());
        let token_url = self
            .token_url
            .clone()
            .unwrap_or_else(|| default_token.to_string());
        let userinfo_url = self
            .userinfo_url
            .clone()
            .unwrap_or_else(|| default_userinfo.to_string());

        if authorization_url.trim().is_empty() {
            return Err("authorization_url is required".to_string());
        }
        if token_url.trim().is_empty() {
            return Err("token_url is required".to_string());
        }
        if userinfo_url.trim().is_empty() {
            return Err("userinfo_url is required".to_string());
        }

        validate_url("authorization_url", &authorization_url)?;
        validate_url("token_url", &token_url)?;
        validate_url("userinfo_url", &userinfo_url)?;

        Ok(SsoEndpoints {
            authorization_url,
            token_url,
            userinfo_url,
        })
    }

    pub fn touch_updated_at(&mut self) -> Result<(), String> {
        self.updated_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|err| format!("failed to format timestamp: {err}"))?;
        Ok(())
    }

    pub fn resolve_role(
        &self,
        external_subject: &str,
        email: Option<&str>,
        groups: &[String],
    ) -> Option<SsoRole> {
        let subject = external_subject.trim();
        if subject.is_empty() {
            return None;
        }

        if self
            .admin_subjects
            .iter()
            .any(|entry| entry.trim() == subject)
        {
            return Some(SsoRole::Admin);
        }
        if self
            .readonly_subjects
            .iter()
            .any(|entry| entry.trim() == subject)
        {
            return Some(SsoRole::Readonly);
        }

        let groups_lc: HashSet<String> = groups
            .iter()
            .map(|group| group.trim().to_ascii_lowercase())
            .filter(|group| !group.is_empty())
            .collect();

        if self
            .admin_groups
            .iter()
            .any(|entry| groups_lc.contains(&entry.trim().to_ascii_lowercase()))
        {
            return Some(SsoRole::Admin);
        }
        if self
            .readonly_groups
            .iter()
            .any(|entry| groups_lc.contains(&entry.trim().to_ascii_lowercase()))
        {
            return Some(SsoRole::Readonly);
        }

        if let Some(domain) = email.and_then(email_domain) {
            if self
                .admin_email_domains
                .iter()
                .any(|entry| entry.trim().eq_ignore_ascii_case(domain))
            {
                return Some(SsoRole::Admin);
            }
            if self
                .readonly_email_domains
                .iter()
                .any(|entry| entry.trim().eq_ignore_ascii_case(domain))
            {
                return Some(SsoRole::Readonly);
            }
        }

        self.default_role
    }

    pub fn email_allowed(&self, email: Option<&str>) -> bool {
        if self.allowed_email_domains.is_empty() {
            return true;
        }
        let Some(domain) = email.and_then(email_domain) else {
            return false;
        };
        self.allowed_email_domains
            .iter()
            .any(|entry| entry.trim().eq_ignore_ascii_case(domain))
    }
}

fn email_domain(email: &str) -> Option<&str> {
    let mut parts = email.rsplit('@');
    let domain = parts.next()?.trim();
    let local = parts.next()?.trim();
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some(domain)
}

fn validate_url(field: &str, value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value)
        .map_err(|err| format!("{field} must be an absolute url: {err}"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url.host_str()) => Ok(()),
        _ => Err(format!("{field} must use https (or loopback http)")),
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST);
    }
    false
}

fn default_true() -> bool {
    true
}

fn default_subject_claim() -> String {
    "sub".to_string()
}

fn default_session_ttl_secs() -> u64 {
    8 * 60 * 60
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SsoProviderIndex {
    providers: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSsoProvider {
    pub id: Uuid,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    pub kind: SsoProviderKind,
    pub enabled: bool,
    pub display_order: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userinfo_url: Option<String>,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_envelope: Option<CaEnvelope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_true")]
    pub pkce_required: bool,
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups_claim: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_role: Option<SsoRole>,
    #[serde(default)]
    pub admin_subjects: Vec<String>,
    #[serde(default)]
    pub admin_groups: Vec<String>,
    #[serde(default)]
    pub admin_email_domains: Vec<String>,
    #[serde(default)]
    pub readonly_subjects: Vec<String>,
    #[serde(default)]
    pub readonly_groups: Vec<String>,
    #[serde(default)]
    pub readonly_email_domains: Vec<String>,
    #[serde(default)]
    pub allowed_email_domains: Vec<String>,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
}

#[derive(Clone)]
enum SsoSecretSealer {
    Local { key_path: PathBuf },
    Token { token_path: PathBuf },
}

impl SsoSecretSealer {
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
            SsoSecretSealer::Local { key_path } => {
                let key = load_or_create_local_key(key_path)?;
                encrypt_ca_key("local-v1", &key, plaintext).map_err(|err| err.to_string())
            }
            SsoSecretSealer::Token { token_path } => {
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
            SsoSecretSealer::Local { key_path } => {
                let key = load_or_create_local_key(key_path)?;
                decrypt_ca_key(envelope, &key).map_err(|err| err.to_string())
            }
            SsoSecretSealer::Token { token_path } => {
                let tokens = TokenStore::load(token_path).map_err(|err| err.to_string())?;
                let token = tokens
                    .get(&envelope.kid)
                    .ok_or_else(|| "missing token for sso client secret envelope".to_string())?;
                decrypt_ca_key(envelope, &token.token).map_err(|err| err.to_string())
            }
        }
    }
}

impl StoredSsoProvider {
    fn from_provider(provider: &SsoProvider, sealer: &SsoSecretSealer) -> Result<Self, String> {
        Ok(Self {
            id: provider.id,
            created_at: provider.created_at.clone(),
            updated_at: provider.updated_at.clone(),
            name: provider.name.clone(),
            kind: provider.kind,
            enabled: provider.enabled,
            display_order: provider.display_order,
            issuer_url: provider.issuer_url.clone(),
            authorization_url: provider.authorization_url.clone(),
            token_url: provider.token_url.clone(),
            userinfo_url: provider.userinfo_url.clone(),
            client_id: provider.client_id.clone(),
            client_secret_envelope: Some(sealer.seal(provider.client_secret.as_bytes())?),
            client_secret: None,
            scopes: provider.scopes.clone(),
            pkce_required: provider.pkce_required,
            subject_claim: provider.subject_claim.clone(),
            email_claim: provider.email_claim.clone(),
            groups_claim: provider.groups_claim.clone(),
            default_role: provider.default_role,
            admin_subjects: provider.admin_subjects.clone(),
            admin_groups: provider.admin_groups.clone(),
            admin_email_domains: provider.admin_email_domains.clone(),
            readonly_subjects: provider.readonly_subjects.clone(),
            readonly_groups: provider.readonly_groups.clone(),
            readonly_email_domains: provider.readonly_email_domains.clone(),
            allowed_email_domains: provider.allowed_email_domains.clone(),
            session_ttl_secs: provider.session_ttl_secs,
        })
    }

    fn into_provider(self, sealer: &SsoSecretSealer) -> Result<SsoProvider, String> {
        let client_secret = match (self.client_secret_envelope, self.client_secret) {
            (Some(envelope), _) => {
                let bytes = sealer.open(&envelope)?;
                String::from_utf8(bytes)
                    .map_err(|err| format!("sso client_secret utf8 decode failed: {err}"))?
            }
            (None, Some(secret)) => secret,
            (None, None) => return Err("missing sso client_secret material".to_string()),
        };
        Ok(SsoProvider {
            id: self.id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            name: self.name,
            kind: self.kind,
            enabled: self.enabled,
            display_order: self.display_order,
            issuer_url: self.issuer_url,
            authorization_url: self.authorization_url,
            token_url: self.token_url,
            userinfo_url: self.userinfo_url,
            client_id: self.client_id,
            client_secret,
            scopes: self.scopes,
            pkce_required: self.pkce_required,
            subject_claim: self.subject_claim,
            email_claim: self.email_claim,
            groups_claim: self.groups_claim,
            default_role: self.default_role,
            admin_subjects: self.admin_subjects,
            admin_groups: self.admin_groups,
            admin_email_domains: self.admin_email_domains,
            readonly_subjects: self.readonly_subjects,
            readonly_groups: self.readonly_groups,
            readonly_email_domains: self.readonly_email_domains,
            allowed_email_domains: self.allowed_email_domains,
            session_ttl_secs: self.session_ttl_secs,
        })
    }
}

#[derive(Clone)]
pub struct SsoDiskStore {
    base_dir: PathBuf,
    secret_sealer: SsoSecretSealer,
    io_lock: Arc<Mutex<()>>,
}

impl SsoDiskStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            secret_sealer: SsoSecretSealer::local(&base_dir),
            base_dir,
            io_lock: Arc::new(Mutex::new(())),
        }
    }

    fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(self.base_dir.join("providers"))
    }

    fn index_path(&self) -> PathBuf {
        self.base_dir.join("index.json")
    }

    fn item_path(&self, id: Uuid) -> PathBuf {
        self.base_dir.join("providers").join(format!("{id}.json"))
    }

    fn state_key_path(&self) -> PathBuf {
        self.base_dir.join("state-key.bin")
    }

    fn read_index(&self) -> io::Result<SsoProviderIndex> {
        let path = self.index_path();
        Ok(read_json(&path)?.unwrap_or_default())
    }

    fn write_index(&self, index: &SsoProviderIndex) -> io::Result<()> {
        let payload = serde_json::to_vec_pretty(index).map_err(to_io_err)?;
        atomic_write(&self.index_path(), &payload)
    }

    pub fn read_provider(&self, id: Uuid) -> io::Result<Option<SsoProvider>> {
        let _guard = self.lock_io()?;
        self.read_provider_unlocked(id)
    }

    pub fn list_providers(&self) -> io::Result<Vec<SsoProvider>> {
        let _guard = self.lock_io()?;
        let mut index = self.read_index()?;
        let mut out = Vec::with_capacity(index.providers.len());
        let mut seen = Vec::with_capacity(index.providers.len());
        for id in index.providers.iter().copied() {
            let Some(provider) = self.read_provider_unlocked(id)? else {
                continue;
            };
            seen.push(id);
            out.push(provider);
        }
        if seen.len() != index.providers.len() {
            index.providers = seen;
            self.write_index(&index)?;
        }
        out.sort_by(|left, right| {
            left.display_order
                .cmp(&right.display_order)
                .then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                })
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(out)
    }

    pub fn write_provider(&self, provider: &SsoProvider) -> io::Result<()> {
        let _guard = self.lock_io()?;
        self.ensure()?;
        let stored =
            StoredSsoProvider::from_provider(provider, &self.secret_sealer).map_err(to_io_err)?;
        let payload = serde_json::to_vec_pretty(&stored).map_err(to_io_err)?;
        atomic_write(&self.item_path(provider.id), &payload)?;
        let mut index = self.read_index()?;
        if !index.providers.contains(&provider.id) {
            index.providers.push(provider.id);
        }
        self.write_index(&index)
    }

    pub fn delete_provider(&self, id: Uuid) -> io::Result<()> {
        let _guard = self.lock_io()?;
        self.ensure()?;
        if let Err(err) = fs::remove_file(self.item_path(id)) {
            if err.kind() != io::ErrorKind::NotFound {
                return Err(err);
            }
        }
        let mut index = self.read_index()?;
        index.providers.retain(|entry| *entry != id);
        self.write_index(&index)
    }

    fn read_provider_unlocked(&self, id: Uuid) -> io::Result<Option<SsoProvider>> {
        let raw: Option<StoredSsoProvider> = read_json(&self.item_path(id))?;
        match raw {
            Some(raw) => raw
                .into_provider(&self.secret_sealer)
                .map(Some)
                .map_err(to_io_err),
            None => Ok(None),
        }
    }

    fn lock_io(&self) -> io::Result<std::sync::MutexGuard<'_, ()>> {
        self.io_lock
            .lock()
            .map_err(|_| io::Error::other("sso disk store lock poisoned"))
    }

    pub fn ensure_state_key(&self) -> io::Result<Vec<u8>> {
        self.ensure()?;
        let path = self.state_key_path();
        match fs::read(&path) {
            Ok(bytes) => {
                if bytes.len() != 32 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid sso state key length",
                    ));
                }
                ensure_permissions(&path, 0o600)?;
                Ok(bytes)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let mut bytes = vec![0u8; 32];
                SystemRandom::new()
                    .fill(&mut bytes)
                    .map_err(|_| io::Error::other("state key generation failed"))?;
                write_with_mode(&path, &bytes, 0o600)?;
                Ok(bytes)
            }
            Err(err) => Err(err),
        }
    }
}

#[derive(Clone)]
pub struct SsoClusterStore {
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
    secret_sealer: SsoSecretSealer,
}

impl SsoClusterStore {
    pub fn new(
        raft: openraft::Raft<ClusterTypeConfig>,
        store: ClusterStore,
        token_path: PathBuf,
    ) -> Self {
        Self {
            raft,
            store,
            secret_sealer: SsoSecretSealer::token(token_path),
        }
    }

    fn read_index(&self) -> Result<SsoProviderIndex, String> {
        let raw = self.store.get_state_value(SSO_PROVIDERS_INDEX_KEY)?;
        match raw {
            Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
            None => Ok(SsoProviderIndex::default()),
        }
    }

    async fn write_index(&self, index: &SsoProviderIndex) -> Result<(), String> {
        let payload = serde_json::to_vec(index).map_err(|err| err.to_string())?;
        self.put_state(SSO_PROVIDERS_INDEX_KEY.to_vec(), payload)
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

    pub fn read_provider(&self, id: Uuid) -> Result<Option<SsoProvider>, String> {
        let raw = self.store.get_state_value(&sso_provider_item_key(id))?;
        match raw {
            Some(raw) => {
                let stored: StoredSsoProvider =
                    serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
                stored
                    .into_provider(&self.secret_sealer)
                    .map(Some)
                    .map_err(|err| err.to_string())
            }
            None => Ok(None),
        }
    }

    pub fn list_providers(&self) -> Result<Vec<SsoProvider>, String> {
        let index = self.read_index()?;
        let mut out = Vec::with_capacity(index.providers.len());
        for id in index.providers {
            let provider = self
                .read_provider(id)?
                .ok_or_else(|| "missing sso provider record".to_string())?;
            out.push(provider);
        }
        out.sort_by(|left, right| {
            left.display_order
                .cmp(&right.display_order)
                .then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                })
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(out)
    }

    pub async fn write_provider(&self, provider: &SsoProvider) -> Result<(), String> {
        let stored = StoredSsoProvider::from_provider(provider, &self.secret_sealer)?;
        let payload = serde_json::to_vec(&stored).map_err(|err| err.to_string())?;
        self.put_state(sso_provider_item_key(provider.id), payload)
            .await?;
        let mut index = self.read_index()?;
        if !index.providers.contains(&provider.id) {
            index.providers.push(provider.id);
        }
        self.write_index(&index).await
    }

    pub async fn delete_provider(&self, id: Uuid) -> Result<(), String> {
        let cmd = ClusterCommand::Delete {
            key: sso_provider_item_key(id),
        };
        self.raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        let mut index = self.read_index()?;
        index.providers.retain(|entry| *entry != id);
        self.write_index(&index).await
    }

    pub async fn ensure_state_key(&self) -> Result<Vec<u8>, String> {
        if let Some(raw) = self.store.get_state_value(SSO_STATE_KEY_KEY)? {
            if raw.len() != 32 {
                return Err("invalid sso state key length".to_string());
            }
            return Ok(raw);
        }
        let mut bytes = vec![0u8; 32];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| "state key generation failed".to_string())?;
        self.put_state(SSO_STATE_KEY_KEY.to_vec(), bytes.clone())
            .await?;
        Ok(bytes)
    }
}

#[derive(Clone)]
pub enum SsoStore {
    Cluster(SsoClusterStore),
    Local(SsoDiskStore),
}

impl SsoStore {
    pub fn cluster(
        raft: openraft::Raft<ClusterTypeConfig>,
        store: ClusterStore,
        token_path: PathBuf,
    ) -> Self {
        Self::Cluster(SsoClusterStore::new(raft, store, token_path))
    }

    pub fn local(base_dir: PathBuf) -> Self {
        Self::Local(SsoDiskStore::new(base_dir))
    }

    pub async fn list_providers(&self) -> Result<Vec<SsoProvider>, String> {
        match self {
            SsoStore::Cluster(store) => store.list_providers(),
            SsoStore::Local(store) => store.list_providers().map_err(|err| err.to_string()),
        }
    }

    pub async fn list_enabled_provider_views(&self) -> Result<Vec<SsoProviderView>, String> {
        let mut views: Vec<SsoProviderView> = self
            .list_providers()
            .await?
            .into_iter()
            .filter(|provider| provider.enabled)
            .map(|provider| SsoProviderView::from(&provider))
            .collect();
        views.sort_by(|left, right| {
            left.display_order
                .cmp(&right.display_order)
                .then_with(|| {
                    left.name
                        .to_ascii_lowercase()
                        .cmp(&right.name.to_ascii_lowercase())
                })
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(views)
    }

    pub async fn get_provider(&self, id: Uuid) -> Result<Option<SsoProvider>, String> {
        match self {
            SsoStore::Cluster(store) => store.read_provider(id),
            SsoStore::Local(store) => store.read_provider(id).map_err(|err| err.to_string()),
        }
    }

    pub async fn write_provider(&self, provider: &SsoProvider) -> Result<(), String> {
        match self {
            SsoStore::Cluster(store) => store.write_provider(provider).await,
            SsoStore::Local(store) => store
                .write_provider(provider)
                .map_err(|err| err.to_string()),
        }
    }

    pub async fn delete_provider(&self, id: Uuid) -> Result<(), String> {
        match self {
            SsoStore::Cluster(store) => store.delete_provider(id).await,
            SsoStore::Local(store) => store.delete_provider(id).map_err(|err| err.to_string()),
        }
    }

    pub async fn ensure_state_key(&self) -> Result<Vec<u8>, String> {
        match self {
            SsoStore::Cluster(store) => store.ensure_state_key().await,
            SsoStore::Local(store) => store.ensure_state_key().map_err(|err| err.to_string()),
        }
    }
}

fn load_or_create_local_key(path: &Path) -> Result<Vec<u8>, String> {
    match fs::read(path) {
        Ok(key) => {
            if key.len() != 32 {
                return Err("invalid local sso secret key length".to_string());
            }
            ensure_permissions(path, 0o600).map_err(|err| err.to_string())?;
            Ok(key)
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
            let mut key = vec![0u8; 32];
            SystemRandom::new()
                .fill(&mut key)
                .map_err(|_| "failed to generate local sso secret key".to_string())?;
            write_with_mode(path, &key, 0o600).map_err(|err| err.to_string())?;
            Ok(key)
        }
        Err(err) => Err(err.to_string()),
    }
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
    fn provider_role_mapping_precedence() {
        let mut provider = SsoProvider::new(
            "test".to_string(),
            SsoProviderKind::GenericOidc,
            "cid".to_string(),
            "secret".to_string(),
        )
        .unwrap();
        provider.default_role = Some(SsoRole::Readonly);
        provider.admin_subjects = vec!["subject-1".to_string()];
        provider.readonly_subjects = vec!["subject-2".to_string()];
        provider.admin_groups = vec!["ops".to_string()];
        provider.readonly_groups = vec!["viewer".to_string()];

        assert_eq!(
            provider.resolve_role("subject-1", None, &[]),
            Some(SsoRole::Admin)
        );
        assert_eq!(
            provider.resolve_role("subject-2", None, &[]),
            Some(SsoRole::Readonly)
        );
        assert_eq!(
            provider.resolve_role("subject-3", None, &["ops".to_string()]),
            Some(SsoRole::Admin)
        );
        assert_eq!(
            provider.resolve_role("subject-3", None, &["viewer".to_string()]),
            Some(SsoRole::Readonly)
        );
        assert_eq!(
            provider.resolve_role("subject-3", None, &[]),
            Some(SsoRole::Readonly)
        );
    }

    #[test]
    fn disk_store_round_trip_and_no_plain_secret() {
        let dir = TempDir::new().unwrap();
        let store = SsoDiskStore::new(dir.path().join("sso"));

        let mut provider = SsoProvider::new(
            "google".to_string(),
            SsoProviderKind::Google,
            "client".to_string(),
            "secret-value".to_string(),
        )
        .unwrap();
        provider.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
        provider.token_url = Some("http://127.0.0.1:5556/token".to_string());
        provider.userinfo_url = Some("http://127.0.0.1:5556/userinfo".to_string());
        store.write_provider(&provider).unwrap();

        let loaded = store.read_provider(provider.id).unwrap().unwrap();
        assert_eq!(loaded.client_secret, "secret-value");

        let raw = fs::read_to_string(store.item_path(provider.id)).unwrap();
        assert!(!raw.contains("secret-value"));
        assert!(raw.contains("client_secret_envelope"));
    }

    #[cfg(unix)]
    #[test]
    fn disk_store_files_use_600_permissions() {
        let dir = TempDir::new().unwrap();
        let store = SsoDiskStore::new(dir.path().join("sso"));

        let provider = SsoProvider::new(
            "google".to_string(),
            SsoProviderKind::Google,
            "client".to_string(),
            "secret-value".to_string(),
        )
        .unwrap();
        store.write_provider(&provider).unwrap();
        let _ = store.ensure_state_key().unwrap();

        let paths = [
            store.index_path(),
            store.item_path(provider.id),
            store.state_key_path(),
            dir.path().join("sso").join("secret.key"),
        ];

        for path in paths {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn disk_store_reads_legacy_plaintext_provider_and_ignores_unknown_fields() {
        let dir = TempDir::new().unwrap();
        let store = SsoDiskStore::new(dir.path().join("sso"));
        store.ensure().unwrap();

        let id = Uuid::new_v4();
        fs::write(
            store.index_path(),
            serde_json::to_vec_pretty(&serde_json::json!({
                "providers": [id],
                "ignored_index_field": "compat"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            store.item_path(id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "updated_at": "2026-03-09T12:30:00Z",
                "name": "google",
                "kind": "google",
                "enabled": true,
                "display_order": 2,
                "client_id": "legacy-client",
                "client_secret": "legacy-secret",
                "authorization_url": "http://127.0.0.1:5556/auth",
                "token_url": "http://127.0.0.1:5556/token",
                "userinfo_url": "http://127.0.0.1:5556/userinfo",
                "ignored_record_field": { "future": true }
            }))
            .unwrap(),
        )
        .unwrap();

        let providers = store.list_providers().unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, id);
        assert_eq!(providers[0].client_id, "legacy-client");
        assert_eq!(providers[0].client_secret, "legacy-secret");
        assert_eq!(providers[0].display_order, 2);
    }

    #[test]
    fn disk_store_reads_minimal_provider_json_with_defaults() {
        let dir = TempDir::new().unwrap();
        let store = SsoDiskStore::new(dir.path().join("sso"));
        store.ensure().unwrap();

        let id = Uuid::new_v4();
        fs::write(
            store.item_path(id),
            serde_json::to_vec_pretty(&serde_json::json!({
                "id": id,
                "created_at": "2026-03-09T12:00:00Z",
                "updated_at": "2026-03-09T12:30:00Z",
                "name": "oidc",
                "kind": "generic-oidc",
                "enabled": false,
                "display_order": 7,
                "client_id": "client",
                "client_secret": "secret"
            }))
            .unwrap(),
        )
        .unwrap();

        let provider = store.read_provider(id).unwrap().unwrap();
        assert_eq!(provider.name, "oidc");
        assert_eq!(provider.kind, SsoProviderKind::GenericOidc);
        assert!(!provider.enabled);
        assert_eq!(provider.display_order, 7);
        assert_eq!(provider.client_secret, "secret");
        assert!(provider.scopes.is_empty());
        assert!(provider.pkce_required);
        assert_eq!(provider.subject_claim, "sub");
        assert_eq!(provider.email_claim, None);
        assert_eq!(provider.groups_claim, None);
        assert_eq!(provider.default_role, None);
        assert!(provider.admin_subjects.is_empty());
        assert!(provider.allowed_email_domains.is_empty());
        assert_eq!(provider.session_ttl_secs, default_session_ttl_secs());
    }

    #[test]
    fn stored_provider_reads_legacy_plaintext_without_creating_secret_key() {
        let dir = TempDir::new().unwrap();
        let sealer = SsoSecretSealer::local(dir.path());
        let stored: StoredSsoProvider = serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4(),
            "created_at": "2026-03-09T12:00:00Z",
            "updated_at": "2026-03-09T12:30:00Z",
            "name": "oidc",
            "kind": "generic-oidc",
            "enabled": true,
            "display_order": 1,
            "client_id": "client",
            "client_secret": "legacy-secret"
        }))
        .unwrap();

        let loaded = stored.into_provider(&sealer).unwrap();
        assert_eq!(loaded.client_secret, "legacy-secret");
        assert!(!dir.path().join("secret.key").exists());
    }

    #[test]
    fn stored_provider_prefers_envelope_over_legacy_plaintext_during_mixed_version_upgrade() {
        let dir = TempDir::new().unwrap();
        let sealer = SsoSecretSealer::local(dir.path());
        let provider = SsoProvider::new(
            "oidc".to_string(),
            SsoProviderKind::GenericOidc,
            "client".to_string(),
            "sealed-secret".to_string(),
        )
        .unwrap();

        let mut stored = StoredSsoProvider::from_provider(&provider, &sealer).unwrap();
        stored.client_secret = Some("stale-legacy-secret".to_string());

        let loaded = stored.into_provider(&sealer).unwrap();
        assert_eq!(loaded.client_secret, "sealed-secret");
    }
}
