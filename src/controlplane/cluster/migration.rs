use std::collections::HashSet;
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
    policy_item_key, PolicyActive, PolicyDiskStore, PolicyIndex, PolicyMeta, PolicyRecord,
    POLICY_ACTIVE_KEY, POLICY_INDEX_KEY,
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
    if store.get_state_value(POLICY_INDEX_KEY)?.is_some() {
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
    let records = cfg
        .local_policy_store
        .list_records()
        .map_err(|err| format!("read local policies failed: {err}"))?;
    let mut index = PolicyIndex::default();
    for record in &records {
        let record_bytes = serde_json::to_vec(record).map_err(|err| err.to_string())?;
        let cmd = ClusterCommand::Put {
            key: policy_item_key(record.id),
            value: record_bytes,
        };
        raft.client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
        index.policies.push(PolicyMeta::from(record));
    }
    index.policies.sort_by(|a, b| {
        let ts = a.created_at.cmp(&b.created_at);
        if ts == std::cmp::Ordering::Equal {
            a.id.as_bytes().cmp(b.id.as_bytes())
        } else {
            ts
        }
    });
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    raft.client_write(ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    })
    .await
    .map_err(|err| err.to_string())?;

    let active_id = cfg
        .local_policy_store
        .active_id()
        .map_err(|err| format!("read local active policy failed: {err}"))?;
    let active_id = match active_id {
        Some(id) => match cfg
            .local_policy_store
            .read_record(id)
            .map_err(|err| format!("read local policy failed: {err}"))?
        {
            Some(record) if record.mode.is_active() => Some(id),
            _ => None,
        },
        None => None,
    };
    if let Some(active_id) = active_id {
        let active = PolicyActive { id: active_id };
        let active_bytes = serde_json::to_vec(&active).map_err(|err| err.to_string())?;
        raft.client_write(ClusterCommand::Put {
            key: POLICY_ACTIVE_KEY.to_vec(),
            value: active_bytes,
        })
        .await
        .map_err(|err| err.to_string())?;
    } else {
        raft.client_write(ClusterCommand::Delete {
            key: POLICY_ACTIVE_KEY.to_vec(),
        })
        .await
        .map_err(|err| err.to_string())?;
    }

    report.policies_seeded = records.len();
    if cfg.force {
        cleanup_policy_extras(raft, store, &records).await?;
    }
    Ok(())
}

async fn cleanup_policy_extras(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    local_records: &[PolicyRecord],
) -> Result<(), String> {
    let raw = store.get_state_value(POLICY_INDEX_KEY)?;
    let Some(raw) = raw else {
        return Ok(());
    };
    let existing: PolicyIndex = serde_json::from_slice(&raw).map_err(|err| err.to_string())?;
    let local_ids: HashSet<Uuid> = local_records.iter().map(|r| r.id).collect();
    for meta in existing.policies {
        if !local_ids.contains(&meta.id) {
            raft.client_write(ClusterCommand::Delete {
                key: policy_item_key(meta.id),
            })
            .await
            .map_err(|err| err.to_string())?;
        }
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
    let local_records = cfg
        .local_policy_store
        .list_records()
        .map_err(|err| format!("read local policies failed: {err}"))?;
    let mut local_ids: Vec<Uuid> = local_records.iter().map(|r| r.id).collect();
    let cluster_index_raw = store.get_state_value(POLICY_INDEX_KEY)?;
    let cluster_index: PolicyIndex = match cluster_index_raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string())?,
        None => PolicyIndex::default(),
    };
    let mut cluster_ids: Vec<Uuid> = cluster_index.policies.iter().map(|m| m.id).collect();
    local_ids.sort();
    cluster_ids.sort();
    if local_ids != cluster_ids {
        return Err("policy index mismatch between local and cluster".to_string());
    }
    let expected_active = cfg
        .local_policy_store
        .active_id()
        .map_err(|err| format!("read local active policy failed: {err}"))?
        .and_then(|id| {
            cfg.local_policy_store
                .read_record(id)
                .ok()
                .flatten()
                .filter(|record| record.mode.is_active())
                .map(|_| id)
        });
    let cluster_active_raw = store.get_state_value(POLICY_ACTIVE_KEY)?;
    let cluster_active: Option<PolicyActive> = match cluster_active_raw {
        Some(raw) => Some(serde_json::from_slice(&raw).map_err(|err| err.to_string())?),
        None => None,
    };
    if expected_active.map(|id| id.to_string())
        != cluster_active.map(|active| active.id.to_string())
    {
        return Err("active policy mismatch between local and cluster".to_string());
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
