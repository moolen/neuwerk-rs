use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::api_auth::{self, ApiKeySet, API_KEYS_KEY};
use crate::controlplane::cluster::bootstrap::ca::encrypt_ca_key;
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::http_tls::{HTTP_CA_CERT_KEY, HTTP_CA_ENVELOPE_KEY};
use crate::controlplane::intercept_tls::{
    load_local_intercept_ca_pair, INTERCEPT_CA_CERT_KEY, INTERCEPT_CA_ENVELOPE_KEY,
};
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyDiskStore, PolicyIndex, StoredPolicy, POLICY_ACTIVE_KEY,
    POLICY_INDEX_KEY, POLICY_STATE_KEY,
};
use crate::controlplane::service_accounts::{
    account_item_key, token_index_key, token_item_key, ServiceAccount, ServiceAccountClusterStore,
    ServiceAccountDiskStore, TokenMeta, SERVICE_ACCOUNTS_INDEX_KEY,
};

const MARKER_DIR: &str = "migrations";
const MARKER_FILE: &str = "local-seed-v1.json";

#[derive(Clone)]
pub struct MigrationConfig {
    pub enabled: bool,
    pub force: bool,
    pub verify: bool,
    pub http_tls_dir: PathBuf,
    pub local_policy_store: PolicyDiskStore,
    pub local_service_accounts_dir: PathBuf,
    pub cluster_data_dir: PathBuf,
    pub token_path: PathBuf,
    pub node_id: Uuid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MigrationReport {
    pub migrated: bool,
    pub skipped_reason: Option<String>,
    pub policies_seeded: usize,
    pub service_accounts_seeded: usize,
    pub tokens_seeded: usize,
    pub api_keyset_source: Option<String>,
    pub http_ca_seeded: bool,
    pub intercept_ca_seeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MigrationMarker {
    version: String,
    timestamp: String,
    node_id: String,
    report: MigrationReport,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ServiceAccountIndexRaw {
    accounts: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenIndexRaw {
    tokens: Vec<Uuid>,
}

pub async fn run(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: MigrationConfig,
) -> Result<MigrationReport, String> {
    if !cfg.enabled && !cfg.verify {
        return Ok(MigrationReport {
            migrated: false,
            skipped_reason: Some("migration disabled".to_string()),
            ..Default::default()
        });
    }

    let marker_path = marker_path(&cfg.cluster_data_dir);
    if !cfg.enabled && cfg.verify {
        verify_state(store, &cfg)?;
        return Ok(MigrationReport {
            migrated: false,
            skipped_reason: Some("verify-only".to_string()),
            ..Default::default()
        });
    }

    if marker_path.exists() && !cfg.force {
        if cfg.verify {
            verify_state(store, &cfg)?;
        }
        return Ok(MigrationReport {
            migrated: false,
            skipped_reason: Some("migration marker present".to_string()),
            ..Default::default()
        });
    }

    if !cfg.force {
        ensure_empty_state(store)?;
    }

    let token_store = TokenStore::load(&cfg.token_path).map_err(|err| err.to_string())?;
    let now = OffsetDateTime::now_utc();
    let current_token = token_store.current(now).map_err(|err| err.to_string())?;

    let mut report = MigrationReport::default();

    seed_api_keyset(raft, store, &cfg, &mut report).await?;
    seed_policies(raft, store, &cfg, &mut report).await?;
    seed_service_accounts(raft, store, &cfg, &mut report).await?;
    seed_http_ca(
        raft,
        store,
        &cfg,
        current_token.kid.as_str(),
        &current_token.token,
        &mut report,
    )
    .await?;
    seed_intercept_ca(
        raft,
        store,
        &cfg,
        current_token.kid.as_str(),
        &current_token.token,
        &mut report,
    )
    .await?;

    if cfg.verify {
        verify_state(store, &cfg)?;
    }
    write_marker(&marker_path, &cfg.node_id, &report)?;
    Ok(MigrationReport {
        migrated: true,
        ..report
    })
}

fn marker_path(cluster_data_dir: &Path) -> PathBuf {
    cluster_data_dir.join(MARKER_DIR).join(MARKER_FILE)
}

fn ensure_empty_state(store: &ClusterStore) -> Result<(), String> {
    if store.get_state_value(POLICY_STATE_KEY)?.is_some()
        || store.get_state_value(POLICY_INDEX_KEY)?.is_some()
    {
        return Err(
            "cluster already contains policies; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }
    if store.get_state_value(SERVICE_ACCOUNTS_INDEX_KEY)?.is_some() {
        return Err(
            "cluster already contains service accounts; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }
    if store.get_state_value(HTTP_CA_CERT_KEY)?.is_some() {
        return Err(
            "cluster already contains HTTP CA material; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }
    if store.get_state_value(INTERCEPT_CA_CERT_KEY)?.is_some()
        || store.get_state_value(INTERCEPT_CA_ENVELOPE_KEY)?.is_some()
    {
        return Err(
            "cluster already contains TLS intercept CA material; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }
    Ok(())
}

async fn seed_api_keyset(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: &MigrationConfig,
    report: &mut MigrationReport,
) -> Result<(), String> {
    let local_keyset_path = api_auth::local_keyset_path(&cfg.http_tls_dir);
    if let Some(local_keyset) = api_auth::load_keyset_from_file(&local_keyset_path)? {
        api_auth::persist_keyset_via_raft(raft, &local_keyset).await?;
        report.api_keyset_source = Some("local".to_string());
        return Ok(());
    }

    if store.get_state_value(API_KEYS_KEY)?.is_none() {
        api_auth::ensure_cluster_keyset(raft, store).await?;
        report.api_keyset_source = Some("generated".to_string());
    } else {
        report.api_keyset_source = Some("cluster-existing".to_string());
    }

    Ok(())
}

async fn seed_policies(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: &MigrationConfig,
    report: &mut MigrationReport,
) -> Result<(), String> {
    let state = cfg
        .local_policy_store
        .load_or_bootstrap_singleton()
        .map_err(|err| format!("read local policy failed: {err}"))?;
    let state_bytes = serde_json::to_vec(&state).map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::Put {
        key: POLICY_STATE_KEY.to_vec(),
        value: state_bytes,
    })
    .await
    .map_err(|err| err.to_string())?;

    report.policies_seeded = 1;
    if cfg.force {
        cleanup_policy_extras(raft, store).await?;
    }
    Ok(())
}

async fn cleanup_policy_extras(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
) -> Result<(), String> {
    let raw = store.get_state_value(POLICY_INDEX_KEY)?;
    let existing: Option<PolicyIndex> = raw
        .map(|raw| serde_json::from_slice(&raw).map_err(|err| err.to_string()))
        .transpose()?;

    raft.client_write(ClusterCommand::Delete {
        key: POLICY_INDEX_KEY.to_vec(),
    })
    .await
    .map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::Delete {
        key: POLICY_ACTIVE_KEY.to_vec(),
    })
    .await
    .map_err(|err| err.to_string())?;
    for meta in existing.unwrap_or_default().policies {
        raft.client_write(ClusterCommand::Delete {
            key: policy_item_key(meta.id),
        })
        .await
        .map_err(|err| err.to_string())?;
    }
    Ok(())
}

async fn seed_service_accounts(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: &MigrationConfig,
    report: &mut MigrationReport,
) -> Result<(), String> {
    let local_store = ServiceAccountDiskStore::new(cfg.local_service_accounts_dir.clone());
    let cluster_store = ServiceAccountClusterStore::new(raft.clone(), store.clone());
    let accounts = local_store
        .list_accounts()
        .map_err(|err| format!("read local service accounts failed: {err}"))?;
    let mut token_count = 0usize;
    for account in &accounts {
        cluster_store
            .write_account(account)
            .await
            .map_err(|err| format!("seed service account failed: {err}"))?;
        let tokens = local_store
            .list_tokens(account.id)
            .map_err(|err| format!("read local tokens failed: {err}"))?;
        for token in tokens {
            cluster_store
                .write_token(&token)
                .await
                .map_err(|err| format!("seed token failed: {err}"))?;
            token_count += 1;
        }
    }
    report.service_accounts_seeded = accounts.len();
    report.tokens_seeded = token_count;
    Ok(())
}

async fn seed_http_ca(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: &MigrationConfig,
    kid: &str,
    token: &[u8],
    report: &mut MigrationReport,
) -> Result<(), String> {
    if store.get_state_value(HTTP_CA_CERT_KEY)?.is_some() && !cfg.force {
        return Err(
            "cluster already contains HTTP CA material; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }

    let ca_cert_path = cfg.http_tls_dir.join("ca.crt");
    let ca_key_path = cfg.http_tls_dir.join("ca.key");
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        return Err(
            "missing http-tls/ca.key; restart in local mode to generate a CA key before migration"
                .to_string(),
        );
    }
    let ca_cert = fs::read(&ca_cert_path).map_err(|err| err.to_string())?;
    let ca_key = fs::read(&ca_key_path).map_err(|err| err.to_string())?;
    let envelope = encrypt_ca_key(kid, token, &ca_key).map_err(|err| err.to_string())?;
    let envelope_bytes = bincode::serialize(&envelope).map_err(|err| err.to_string())?;

    raft.client_write(ClusterCommand::Put {
        key: HTTP_CA_CERT_KEY.to_vec(),
        value: ca_cert,
    })
    .await
    .map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::Put {
        key: HTTP_CA_ENVELOPE_KEY.to_vec(),
        value: envelope_bytes,
    })
    .await
    .map_err(|err| err.to_string())?;

    report.http_ca_seeded = true;
    Ok(())
}

async fn seed_intercept_ca(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    cfg: &MigrationConfig,
    kid: &str,
    token: &[u8],
    report: &mut MigrationReport,
) -> Result<(), String> {
    let Some((ca_cert, ca_key)) = load_local_intercept_ca_pair(&cfg.http_tls_dir)? else {
        return Ok(());
    };

    if store.get_state_value(INTERCEPT_CA_CERT_KEY)?.is_some() && !cfg.force {
        return Err(
            "cluster already contains TLS intercept CA material; abort migration or use --cluster-migrate-force"
                .to_string(),
        );
    }

    let envelope = encrypt_ca_key(kid, token, &ca_key).map_err(|err| err.to_string())?;
    let envelope_bytes = bincode::serialize(&envelope).map_err(|err| err.to_string())?;

    raft.client_write(ClusterCommand::Put {
        key: INTERCEPT_CA_CERT_KEY.to_vec(),
        value: ca_cert,
    })
    .await
    .map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::Put {
        key: INTERCEPT_CA_ENVELOPE_KEY.to_vec(),
        value: envelope_bytes,
    })
    .await
    .map_err(|err| err.to_string())?;

    report.intercept_ca_seeded = true;
    Ok(())
}

fn write_marker(path: &Path, node_id: &Uuid, report: &MigrationReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let marker = MigrationMarker {
        version: MARKER_FILE.to_string(),
        timestamp: OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string()),
        node_id: node_id.to_string(),
        report: report.clone(),
    };
    let payload = serde_json::to_vec_pretty(&marker).map_err(|err| err.to_string())?;
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    fs::write(&tmp, payload).map_err(|err| err.to_string())?;
    fs::rename(&tmp, path).map_err(|err| err.to_string())?;
    Ok(())
}

fn verify_state(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    verify_api_keyset(store, cfg)?;
    verify_policies(store, cfg)?;
    verify_service_accounts(store, cfg)?;
    verify_http_ca(store, cfg)?;
    verify_intercept_ca(store, cfg)?;
    Ok(())
}

fn verify_api_keyset(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    let local_keyset_path = api_auth::local_keyset_path(&cfg.http_tls_dir);
    let Some(local_keyset) = api_auth::load_keyset_from_file(&local_keyset_path)? else {
        return Ok(());
    };
    let Some(cluster_keyset) = api_auth::load_keyset_from_store(store)? else {
        return Err("cluster api keyset missing".to_string());
    };
    if !keyset_equivalent(&local_keyset, &cluster_keyset) {
        return Err("api keyset mismatch between local and cluster".to_string());
    }
    Ok(())
}

fn keyset_equivalent(left: &ApiKeySet, right: &ApiKeySet) -> bool {
    if left.active_kid != right.active_kid {
        return false;
    }
    if left.keys.len() != right.keys.len() {
        return false;
    }
    for (l, r) in left.keys.iter().zip(right.keys.iter()) {
        if l.kid != r.kid
            || l.public_key != r.public_key
            || l.private_key != r.private_key
            || l.created_at != r.created_at
            || l.status != r.status
        {
            return false;
        }
    }
    true
}

fn verify_policies(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    let local_state = cfg
        .local_policy_store
        .read_state()
        .map_err(|err| format!("read local policy failed: {err}"))?;
    let cluster_state_raw = store
        .get_state_value(POLICY_STATE_KEY)?
        .ok_or_else(|| "cluster singleton policy missing".to_string())?;
    let cluster_state: StoredPolicy =
        serde_json::from_slice(&cluster_state_raw).map_err(|err| err.to_string())?;
    let local_id = local_state.as_ref().map(|state| state.record().id);
    let cluster_id = cluster_state.record().id;
    if local_id != Some(cluster_id) {
        return Err("policy index mismatch between local and cluster".to_string());
    }
    if local_state.as_ref().and_then(StoredPolicy::active_id).map(|id| id.to_string())
        != cluster_state.active_id().map(|id| id.to_string())
    {
        return Err("active policy mismatch between local and cluster".to_string());
    }
    let Some(local_state) = local_state else {
        return Err("policy index mismatch between local and cluster".to_string());
    };
    if serde_json::to_value(&local_state.policy).map_err(|err| err.to_string())?
        != serde_json::to_value(&cluster_state.policy).map_err(|err| err.to_string())?
    {
        return Err("singleton policy mismatch between local and cluster".to_string());
    }
    Ok(())
}

fn verify_service_accounts(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    let local_store = ServiceAccountDiskStore::new(cfg.local_service_accounts_dir.clone());
    let local_accounts = local_store
        .list_accounts()
        .map_err(|err| format!("read local service accounts failed: {err}"))?;
    let cluster_index = read_sa_index(store)?;
    let mut local_ids: Vec<Uuid> = local_accounts.iter().map(|a| a.id).collect();
    let mut cluster_ids: Vec<Uuid> = cluster_index.accounts;
    local_ids.sort();
    cluster_ids.sort();
    if local_ids != cluster_ids {
        return Err("service account list mismatch between local and cluster".to_string());
    }
    for account in local_accounts {
        let cluster_account = read_cluster_account(store, account.id)?
            .ok_or_else(|| "cluster service account missing".to_string())?;
        if !account_equivalent(&account, &cluster_account) {
            return Err("service account mismatch between local and cluster".to_string());
        }
        let local_tokens = local_store
            .list_tokens(account.id)
            .map_err(|err| format!("read local tokens failed: {err}"))?;
        let cluster_tokens = read_cluster_tokens(store, account.id)?;
        if !tokens_equivalent(&local_tokens, &cluster_tokens) {
            return Err("service account token mismatch between local and cluster".to_string());
        }
    }
    Ok(())
}

fn read_sa_index(store: &ClusterStore) -> Result<ServiceAccountIndexRaw, String> {
    let raw = store.get_state_value(SERVICE_ACCOUNTS_INDEX_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
        None => Ok(ServiceAccountIndexRaw::default()),
    }
}

fn read_cluster_account(store: &ClusterStore, id: Uuid) -> Result<Option<ServiceAccount>, String> {
    let raw = store.get_state_value(&account_item_key(id))?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

fn read_cluster_tokens(store: &ClusterStore, account_id: Uuid) -> Result<Vec<TokenMeta>, String> {
    let raw = store.get_state_value(&token_index_key(account_id))?;
    let index: TokenIndexRaw = match raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string())?,
        None => TokenIndexRaw::default(),
    };
    let mut tokens = Vec::with_capacity(index.tokens.len());
    for token_id in index.tokens {
        let raw = store
            .get_state_value(&token_item_key(token_id))?
            .ok_or_else(|| "cluster token missing".to_string())?;
        let token: TokenMeta = serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
        tokens.push(token);
    }
    Ok(tokens)
}

fn account_equivalent(left: &ServiceAccount, right: &ServiceAccount) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.description == right.description
        && left.created_at == right.created_at
        && left.created_by == right.created_by
        && left.status == right.status
}

fn tokens_equivalent(left: &[TokenMeta], right: &[TokenMeta]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_by_key(|t| t.id);
    right.sort_by_key(|t| t.id);
    left.iter().zip(right.iter()).all(|(l, r)| {
        l.id == r.id
            && l.service_account_id == r.service_account_id
            && l.name == r.name
            && l.created_at == r.created_at
            && l.created_by == r.created_by
            && l.expires_at == r.expires_at
            && l.revoked_at == r.revoked_at
            && l.last_used_at == r.last_used_at
            && l.kid == r.kid
            && l.status == r.status
    })
}

fn verify_http_ca(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    let ca_cert_path = cfg.http_tls_dir.join("ca.crt");
    if !ca_cert_path.exists() {
        return Ok(());
    }
    let local_cert = fs::read(&ca_cert_path).map_err(|err| err.to_string())?;
    let cluster_cert = store
        .get_state_value(HTTP_CA_CERT_KEY)?
        .ok_or_else(|| "cluster http ca missing".to_string())?;
    if local_cert != cluster_cert {
        return Err("http ca cert mismatch between local and cluster".to_string());
    }
    Ok(())
}

fn verify_intercept_ca(store: &ClusterStore, cfg: &MigrationConfig) -> Result<(), String> {
    let Some((local_cert, _local_key)) = load_local_intercept_ca_pair(&cfg.http_tls_dir)? else {
        return Ok(());
    };

    let cluster_cert = store
        .get_state_value(INTERCEPT_CA_CERT_KEY)?
        .ok_or_else(|| "cluster tls intercept ca cert missing".to_string())?;
    if local_cert != cluster_cert {
        return Err("tls intercept ca cert mismatch between local and cluster".to_string());
    }
    if store.get_state_value(INTERCEPT_CA_ENVELOPE_KEY)?.is_none() {
        return Err("cluster tls intercept ca key envelope missing".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use openraft::entry::EntryPayload;
    use openraft::storage::RaftStateMachine;
    use openraft::{CommittedLeaderId, Entry, LogId};
    use tempfile::TempDir;

    use crate::controlplane::policy_config::PolicyConfig;

    fn sample_policy() -> PolicyConfig {
        serde_yaml::from_str(
            r#"
default_policy: deny
source_groups:
  - id: branch
    mode: enforce
    sources:
      ips: ["10.0.0.5"]
    rules:
      - id: allow-dns
        action: allow
        match:
          dns_hostname: example.com
"#,
        )
        .unwrap()
    }

    fn migration_config(dir: &TempDir) -> MigrationConfig {
        MigrationConfig {
            enabled: true,
            force: false,
            verify: true,
            http_tls_dir: dir.path().join("http-tls"),
            local_policy_store: PolicyDiskStore::new(dir.path().join("local-policy-store")),
            local_service_accounts_dir: dir.path().join("service-accounts"),
            cluster_data_dir: dir.path().join("cluster-data"),
            token_path: dir.path().join("token.json"),
            node_id: Uuid::new_v4(),
        }
    }

    fn test_entry(index: u64, cmd: ClusterCommand) -> Entry<ClusterTypeConfig> {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, 1), index),
            payload: EntryPayload::Normal(cmd),
        }
    }

    #[tokio::test]
    async fn verify_state_accepts_schema_compatible_cluster_payloads() {
        let dir = TempDir::new().unwrap();
        let cfg = migration_config(&dir);
        let mut store = ClusterStore::open(dir.path().join("cluster-store")).unwrap();

        let keyset = api_auth::ensure_local_keyset(&cfg.http_tls_dir).unwrap();

        cfg.local_policy_store
            .write_state(&StoredPolicy::from_policy(sample_policy()))
            .unwrap();

        let local_service_accounts =
            ServiceAccountDiskStore::new(cfg.local_service_accounts_dir.clone());
        let account =
            ServiceAccount::new("svc-compat".to_string(), None, "creator".to_string()).unwrap();
        local_service_accounts.write_account(&account).unwrap();
        let token = TokenMeta::new(
            account.id,
            None,
            "creator".to_string(),
            keyset.active_kid.clone(),
            None,
            Uuid::new_v4(),
        )
        .unwrap();
        local_service_accounts.write_token(&token).unwrap();

        let mut cluster_keyset = serde_json::to_value(&keyset).unwrap();
        cluster_keyset
            .as_object_mut()
            .unwrap()
            .insert("future_keyset_field".to_string(), serde_json::json!(true));
        cluster_keyset["keys"][0].as_object_mut().unwrap().insert(
            "future_key_field".to_string(),
            serde_json::json!("ignored-by-current-reader"),
        );

        let commands = vec![
            ClusterCommand::Put {
                key: API_KEYS_KEY.to_vec(),
                value: serde_json::to_vec(&cluster_keyset).unwrap(),
            },
            ClusterCommand::Put {
                key: POLICY_STATE_KEY.to_vec(),
                value: serde_json::to_vec(&serde_json::json!({
                    "policy": serde_json::to_value(sample_policy()).unwrap(),
                    "future_state_field": true
                }))
                .unwrap(),
            },
            ClusterCommand::Put {
                key: SERVICE_ACCOUNTS_INDEX_KEY.to_vec(),
                value: serde_json::to_vec(&serde_json::json!({
                    "accounts": [account.id],
                    "future_index_field": "ignored"
                }))
                .unwrap(),
            },
            ClusterCommand::Put {
                key: account_item_key(account.id),
                value: serde_json::to_vec(&serde_json::json!({
                    "id": account.id,
                    "name": account.name,
                    "created_at": account.created_at,
                    "created_by": account.created_by,
                    "status": "active",
                    "future_account_field": "ignored"
                }))
                .unwrap(),
            },
            ClusterCommand::Put {
                key: token_index_key(account.id),
                value: serde_json::to_vec(&serde_json::json!({
                    "tokens": [token.id],
                    "future_index_field": "ignored"
                }))
                .unwrap(),
            },
            ClusterCommand::Put {
                key: token_item_key(token.id),
                value: serde_json::to_vec(&serde_json::json!({
                    "id": token.id,
                    "service_account_id": account.id,
                    "created_at": token.created_at,
                    "created_by": token.created_by,
                    "kid": token.kid,
                    "status": "active",
                    "future_token_field": "ignored"
                }))
                .unwrap(),
            },
        ];

        store
            .apply(
                commands
                    .into_iter()
                    .enumerate()
                    .map(|(index, cmd)| test_entry(index as u64 + 1, cmd))
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();

        verify_state(&store, &cfg).unwrap();
    }

    #[tokio::test]
    async fn verify_policies_reports_missing_local_singleton_without_bootstrapping() {
        let dir = TempDir::new().unwrap();
        let cfg = migration_config(&dir);
        let mut store = ClusterStore::open(dir.path().join("cluster-store")).unwrap();
        let state = StoredPolicy::from_policy(sample_policy());

        cfg.local_policy_store.write_state(&state).unwrap();
        cfg.local_policy_store
            .delete_record(state.record().id)
            .unwrap();

        store
            .apply(vec![test_entry(
                1,
                ClusterCommand::Put {
                    key: POLICY_STATE_KEY.to_vec(),
                    value: serde_json::to_vec(&state).unwrap(),
                },
            )])
            .await
            .unwrap();

        let err = verify_policies(&store, &cfg).unwrap_err();
        assert!(err.contains("policy index mismatch"), "unexpected error: {err}");
        assert!(cfg.local_policy_store.read_state().unwrap().is_none());
    }
}
