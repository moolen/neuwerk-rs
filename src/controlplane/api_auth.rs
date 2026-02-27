use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub const API_KEYS_KEY: &[u8] = b"auth/api_keys";
pub const DEFAULT_ISSUER: &str = "neuwerk-api";
pub const DEFAULT_AUDIENCE: &str = "neuwerk-api";
pub const DEFAULT_TTL_SECS: i64 = 90 * 24 * 60 * 60;
pub const CLOCK_SKEW_SECS: i64 = 60;
const LOCAL_KEYSET_FILENAME: &str = "api-auth.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeySet {
    pub active_kid: String,
    pub keys: Vec<ApiKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub kid: String,
    pub public_key: String,
    pub private_key: Option<String>,
    pub created_at: String,
    pub status: ApiKeyStatus,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ApiKeyStatus {
    Active,
    Retired,
}

#[derive(Debug, Clone)]
pub struct MintedToken {
    pub token: String,
    pub kid: String,
    pub exp: i64,
}

#[derive(Debug, Clone)]
pub struct MintedServiceToken {
    pub token: String,
    pub kid: String,
    pub exp: Option<i64>,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    pub iat: i64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sa_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ApiKeySummary {
    pub kid: String,
    pub status: ApiKeyStatus,
    pub created_at: String,
    pub signing: bool,
}

pub fn local_keyset_path(tls_dir: &Path) -> PathBuf {
    tls_dir.join(LOCAL_KEYSET_FILENAME)
}

pub fn load_keyset_from_store(store: &ClusterStore) -> Result<Option<ApiKeySet>, String> {
    let raw = store.get_state_value(API_KEYS_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

pub fn load_keyset_from_file(path: &Path) -> Result<Option<ApiKeySet>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(path).map_err(|err| err.to_string())?;
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|err| err.to_string())
}

pub async fn persist_keyset_via_raft(
    raft: &openraft::Raft<ClusterTypeConfig>,
    keyset: &ApiKeySet,
) -> Result<(), String> {
    let encoded = serde_json::to_vec(keyset).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: API_KEYS_KEY.to_vec(),
        value: encoded,
    };
    raft.client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;
    Ok(())
}

pub fn persist_keyset_to_file(path: &Path, keyset: &ApiKeySet) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let encoded = serde_json::to_vec_pretty(keyset).map_err(|err| err.to_string())?;
    write_secure_file(path, &encoded, 0o600)?;
    Ok(())
}

pub async fn ensure_cluster_keyset(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
) -> Result<ApiKeySet, String> {
    if let Some(existing) = load_keyset_from_store(store)? {
        return Ok(existing);
    }
    let keyset = new_keyset()?;
    persist_keyset_via_raft(raft, &keyset).await?;
    Ok(keyset)
}

pub fn ensure_local_keyset(tls_dir: &Path) -> Result<ApiKeySet, String> {
    let path = local_keyset_path(tls_dir);
    if let Some(existing) = load_keyset_from_file(&path)? {
        ensure_permissions(&path, 0o600)?;
        return Ok(existing);
    }
    let keyset = new_keyset()?;
    persist_keyset_to_file(&path, &keyset)?;
    Ok(keyset)
}

fn write_secure_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|err| err.to_string())?;
    file.write_all(contents).map_err(|err| err.to_string())?;
    file.sync_all().map_err(|err| err.to_string())?;
    ensure_permissions(path, mode)?;
    Ok(())
}

fn ensure_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(path)
            .map_err(|err| err.to_string())?
            .permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms).map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub fn list_summaries(keyset: &ApiKeySet) -> Vec<ApiKeySummary> {
    keyset
        .keys
        .iter()
        .map(|key| ApiKeySummary {
            kid: key.kid.clone(),
            status: key.status,
            created_at: key.created_at.clone(),
            signing: key.kid == keyset.active_kid,
        })
        .collect()
}

pub fn rotate_key(keyset: &mut ApiKeySet) -> Result<ApiKey, String> {
    let kid = uuid::Uuid::new_v4().to_string();
    let key = generate_key(&kid)?;
    keyset.active_kid = kid;
    keyset.keys.push(key.clone());
    Ok(key)
}

pub fn retire_key(keyset: &mut ApiKeySet, kid: &str) -> Result<(), String> {
    if keyset.active_kid == kid {
        return Err("cannot retire active signing key".to_string());
    }
    let key = keyset
        .keys
        .iter_mut()
        .find(|key| key.kid == kid)
        .ok_or_else(|| format!("unknown kid {kid}"))?;
    key.status = ApiKeyStatus::Retired;
    Ok(())
}

pub fn mint_token(
    keyset: &ApiKeySet,
    sub: &str,
    ttl_secs: Option<i64>,
    kid: Option<&str>,
) -> Result<MintedToken, String> {
    mint_token_at(keyset, sub, ttl_secs, kid, OffsetDateTime::now_utc())
}

pub fn mint_token_at(
    keyset: &ApiKeySet,
    sub: &str,
    ttl_secs: Option<i64>,
    kid: Option<&str>,
    now: OffsetDateTime,
) -> Result<MintedToken, String> {
    if sub.trim().is_empty() {
        return Err("sub is required".to_string());
    }
    let key = match kid {
        Some(kid) => keyset.keys.iter().find(|key| key.kid == kid),
        None => keyset.keys.iter().find(|key| key.kid == keyset.active_kid),
    }
    .ok_or_else(|| "signing key not found".to_string())?;
    if key.status != ApiKeyStatus::Active {
        return Err("signing key is retired".to_string());
    }
    let private_key = key
        .private_key
        .as_ref()
        .ok_or_else(|| "signing key missing private material".to_string())?;
    let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
    if ttl <= 0 {
        return Err("ttl must be positive".to_string());
    }
    let iat = now.unix_timestamp();
    let exp = iat + ttl;
    let claims = JwtClaims {
        iss: DEFAULT_ISSUER.to_string(),
        aud: DEFAULT_AUDIENCE.to_string(),
        sub: sub.to_string(),
        exp: Some(exp),
        iat,
        jti: uuid::Uuid::new_v4().to_string(),
        sa_id: None,
        scope: None,
        roles: None,
    };
    let token = sign_jwt(&key.kid, private_key, &claims)?;
    Ok(MintedToken {
        token,
        kid: key.kid.clone(),
        exp,
    })
}

pub fn validate_token(token: &str, keyset: &ApiKeySet) -> Result<JwtClaims, String> {
    validate_token_at(token, keyset, OffsetDateTime::now_utc())
}

pub fn validate_token_at(
    token: &str,
    keyset: &ApiKeySet,
    now: OffsetDateTime,
) -> Result<JwtClaims, String> {
    let (header, claims, signing_input, signature) = parse_jwt(token)?;
    if header.alg != "EdDSA" {
        return Err("unsupported jwt alg".to_string());
    }
    let key = keyset
        .keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or_else(|| "unknown jwt kid".to_string())?;
    if key.status != ApiKeyStatus::Active {
        return Err("jwt key retired".to_string());
    }
    verify_signature(&key.public_key, &signing_input, &signature)?;
    validate_claims(&claims, now, false)?;
    Ok(claims)
}

pub fn validate_token_allow_missing_exp(
    token: &str,
    keyset: &ApiKeySet,
    now: OffsetDateTime,
) -> Result<JwtClaims, String> {
    let (header, claims, signing_input, signature) = parse_jwt(token)?;
    if header.alg != "EdDSA" {
        return Err("unsupported jwt alg".to_string());
    }
    let key = keyset
        .keys
        .iter()
        .find(|key| key.kid == header.kid)
        .ok_or_else(|| "unknown jwt kid".to_string())?;
    if key.status != ApiKeyStatus::Active {
        return Err("jwt key retired".to_string());
    }
    verify_signature(&key.public_key, &signing_input, &signature)?;
    validate_claims(&claims, now, true)?;
    Ok(claims)
}

pub fn mint_service_account_token(
    keyset: &ApiKeySet,
    service_account_id: &str,
    ttl_secs: Option<i64>,
    eternal: bool,
    kid: Option<&str>,
    now: OffsetDateTime,
) -> Result<MintedServiceToken, String> {
    if service_account_id.trim().is_empty() {
        return Err("service account id is required".to_string());
    }
    let key = match kid {
        Some(kid) => keyset.keys.iter().find(|key| key.kid == kid),
        None => keyset.keys.iter().find(|key| key.kid == keyset.active_kid),
    }
    .ok_or_else(|| "signing key not found".to_string())?;
    if key.status != ApiKeyStatus::Active {
        return Err("signing key is retired".to_string());
    }
    let private_key = key
        .private_key
        .as_ref()
        .ok_or_else(|| "signing key missing private material".to_string())?;
    let exp = if eternal {
        None
    } else {
        let ttl = ttl_secs.unwrap_or(DEFAULT_TTL_SECS);
        if ttl <= 0 {
            return Err("ttl must be positive".to_string());
        }
        Some(now.unix_timestamp() + ttl)
    };
    let claims = JwtClaims {
        iss: DEFAULT_ISSUER.to_string(),
        aud: DEFAULT_AUDIENCE.to_string(),
        sub: service_account_id.to_string(),
        exp,
        iat: now.unix_timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        sa_id: Some(service_account_id.to_string()),
        scope: None,
        roles: None,
    };
    let token = sign_jwt(&key.kid, private_key, &claims)?;
    Ok(MintedServiceToken {
        token,
        kid: key.kid.clone(),
        exp,
        jti: claims.jti.clone(),
    })
}

fn new_keyset() -> Result<ApiKeySet, String> {
    let kid = uuid::Uuid::new_v4().to_string();
    let key = generate_key(&kid)?;
    Ok(ApiKeySet {
        active_kid: kid,
        keys: vec![key],
    })
}

fn generate_key(kid: &str) -> Result<ApiKey, String> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "failed to generate keypair".to_string())?;
    let keypair =
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "invalid keypair".to_string())?;
    let public_key = STANDARD.encode(keypair.public_key().as_ref());
    let private_key = STANDARD.encode(pkcs8.as_ref());
    let created_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| err.to_string())?;
    Ok(ApiKey {
        kid: kid.to_string(),
        public_key,
        private_key: Some(private_key),
        created_at,
        status: ApiKeyStatus::Active,
    })
}

fn sign_jwt(kid: &str, private_key_b64: &str, claims: &JwtClaims) -> Result<String, String> {
    let header = JwtHeader {
        alg: "EdDSA".to_string(),
        kid: kid.to_string(),
        typ: Some("JWT".to_string()),
    };
    let header_json = serde_json::to_vec(&header).map_err(|err| err.to_string())?;
    let claims_json = serde_json::to_vec(claims).map_err(|err| err.to_string())?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims_json);
    let signing_input = format!("{header_b64}.{claims_b64}");
    let key_bytes = STANDARD
        .decode(private_key_b64)
        .map_err(|_| "invalid private key encoding".to_string())?;
    let keypair =
        Ed25519KeyPair::from_pkcs8(&key_bytes).map_err(|_| "invalid private key".to_string())?;
    let signature = keypair.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());
    Ok(format!("{signing_input}.{signature_b64}"))
}

fn parse_jwt(token: &str) -> Result<(JwtHeader, JwtClaims, String, Vec<u8>), String> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| "jwt missing header".to_string())?;
    let claims_b64 = parts
        .next()
        .ok_or_else(|| "jwt missing claims".to_string())?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| "jwt missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("jwt has too many segments".to_string());
    }
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| "invalid jwt header".to_string())?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| "invalid jwt claims".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| "invalid jwt signature encoding".to_string())?;
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| "invalid jwt header".to_string())?;
    let claims: JwtClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| "invalid jwt claims".to_string())?;
    Ok((
        header,
        claims,
        format!("{header_b64}.{claims_b64}"),
        signature,
    ))
}

fn verify_signature(
    public_key_b64: &str,
    signing_input: &str,
    signature: &[u8],
) -> Result<(), String> {
    let public_key = STANDARD
        .decode(public_key_b64)
        .map_err(|_| "invalid public key encoding".to_string())?;
    let verifier = UnparsedPublicKey::new(&ED25519, public_key);
    verifier
        .verify(signing_input.as_bytes(), signature)
        .map_err(|_| "invalid jwt signature".to_string())
}

fn validate_claims(
    claims: &JwtClaims,
    now: OffsetDateTime,
    allow_missing_exp: bool,
) -> Result<(), String> {
    if claims.iss != DEFAULT_ISSUER {
        return Err("invalid jwt issuer".to_string());
    }
    if claims.aud != DEFAULT_AUDIENCE {
        return Err("invalid jwt audience".to_string());
    }
    if claims.sub.trim().is_empty() {
        return Err("missing jwt sub".to_string());
    }
    if claims.jti.trim().is_empty() {
        return Err("missing jwt jti".to_string());
    }
    let now_ts = now.unix_timestamp();
    if let Some(exp) = claims.exp {
        if exp + CLOCK_SKEW_SECS < now_ts {
            return Err("jwt expired".to_string());
        }
    } else if !allow_missing_exp {
        return Err("missing jwt exp".to_string());
    }
    if claims.iat - CLOCK_SKEW_SECS > now_ts {
        return Err("jwt issued in the future".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn jwt_mints_and_validates() {
        let mut keyset = new_keyset().unwrap();
        let now = OffsetDateTime::now_utc();
        let token = mint_token_at(&keyset, "tester", Some(60), None, now).unwrap();
        let claims = validate_token_at(&token.token, &keyset, now).unwrap();
        assert_eq!(claims.sub, "tester");

        keyset.keys[0].status = ApiKeyStatus::Retired;
        assert!(validate_token_at(&token.token, &keyset, now).is_err());
    }

    #[test]
    fn jwt_expiration_enforced() {
        let keyset = new_keyset().unwrap();
        let now = OffsetDateTime::now_utc();
        let token = mint_token_at(&keyset, "tester", Some(1), None, now).unwrap();
        let later = now + Duration::seconds(120);
        assert!(validate_token_at(&token.token, &keyset, later).is_err());
    }

    #[test]
    fn jwt_claims_validated() {
        let keyset = new_keyset().unwrap();
        let now = OffsetDateTime::now_utc();
        let mut token = mint_token_at(&keyset, "tester", Some(60), None, now).unwrap();
        let mut claims = parse_jwt(&token.token).unwrap().1;
        claims.iss = "bad-issuer".to_string();
        token.token = sign_jwt(
            &keyset.active_kid,
            keyset.keys[0].private_key.as_ref().unwrap(),
            &claims,
        )
        .unwrap();
        assert!(validate_token_at(&token.token, &keyset, now).is_err());
    }

    #[test]
    fn jwt_allows_missing_exp_for_service_accounts() {
        let keyset = new_keyset().unwrap();
        let now = OffsetDateTime::now_utc();
        let minted =
            mint_service_account_token(&keyset, "service-account", None, true, None, now).unwrap();
        assert!(validate_token_allow_missing_exp(&minted.token, &keyset, now).is_ok());
        assert!(validate_token_at(&minted.token, &keyset, now).is_err());
    }
}
