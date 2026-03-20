use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use super::*;

use axum::http::header::{LOCATION, SET_COOKIE};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature;
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::controlplane::audit::{AuditEvent, AuditFindingType};
use crate::controlplane::sso::{SsoEndpoints, SsoProvider, SsoProviderKind};

type HmacSha256 = Hmac<Sha256>;

const OIDC_CLOCK_SKEW_SECS: i64 = 60;
const OIDC_CACHE_TTL_SECS: i64 = 600;
const GOOGLE_DEFAULT_ISSUER: &str = "https://accounts.google.com";
const GOOGLE_DEFAULT_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

#[derive(Debug, Serialize, ToSchema)]
struct SsoSupportedProvider {
    id: Uuid,
    name: String,
    kind: crate::controlplane::sso::SsoProviderKind,
}

#[derive(Debug, Deserialize)]
pub(super) struct SsoStartQuery {
    #[serde(default)]
    next: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SsoCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SsoFlowCookie {
    provider_id: String,
    state: String,
    nonce: String,
    pkce_verifier: String,
    next_path: String,
    issued_at: i64,
    expires_at: i64,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Debug, Clone)]
struct ExternalIdentity {
    subject: String,
    email: Option<String>,
    groups: Vec<String>,
}

#[derive(Debug, Clone)]
struct ResolvedProviderMetadata {
    endpoints: SsoEndpoints,
    issuer: Option<String>,
    jwks_uri: Option<String>,
}

#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at_epoch: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    #[serde(default)]
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

static OIDC_DISCOVERY_CACHE: OnceLock<Mutex<HashMap<String, CacheEntry<OidcDiscoveryDocument>>>> =
    OnceLock::new();
static OIDC_JWKS_CACHE: OnceLock<Mutex<HashMap<String, CacheEntry<JwkSet>>>> = OnceLock::new();
static SSO_CALLBACK_REPLAY_GUARD: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

#[utoipa::path(
    get,
    path = "/api/v1/auth/sso/providers",
    tag = "Auth",
    responses(
        (status = 200, description = "Enabled SSO providers", body = [SsoSupportedProvider]),
        (status = 500, description = "Provider store error", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn auth_sso_supported_providers(State(state): State<ApiState>) -> Response {
    match state.sso.list_enabled_provider_views().await {
        Ok(providers) => {
            let out: Vec<SsoSupportedProvider> = providers
                .into_iter()
                .map(|provider| SsoSupportedProvider {
                    id: provider.id,
                    name: provider.name,
                    kind: provider.kind,
                })
                .collect();
            Json(out).into_response()
        }
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn auth_sso_start(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<SsoStartQuery>,
) -> Response {
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let provider_lookup_started = Instant::now();
    let provider = match state.sso.get_provider(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            observe_sso(&state, "deny", "provider_not_found", "none");
            return error_response(StatusCode::NOT_FOUND, "sso provider not found".to_string());
        }
        Err(err) => {
            observe_sso(&state, "deny", "provider_store_error", "none");
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "provider_lookup",
        provider_lookup_started,
    );
    if !provider.enabled {
        observe_sso(&state, "deny", "provider_disabled", provider.kind_name());
        return error_response(
            StatusCode::BAD_REQUEST,
            "sso provider is disabled".to_string(),
        );
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            observe_sso(&state, "deny", "http_client_error", provider.kind_name());
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    };

    let metadata_started = Instant::now();
    let metadata = match resolve_provider_metadata(&http, &provider).await {
        Ok(metadata) => metadata,
        Err(err) => {
            observe_sso(
                &state,
                "deny",
                "provider_config_invalid",
                provider.kind_name(),
            );
            return error_response(StatusCode::BAD_REQUEST, err);
        }
    };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "provider_metadata",
        metadata_started,
    );

    let state_key_started = Instant::now();
    let state_key = match state.sso.ensure_state_key().await {
        Ok(state_key) => state_key,
        Err(err) => {
            observe_sso(&state, "deny", "state_key_error", provider.kind_name());
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    observe_sso_latency(&state, provider.kind_name(), "state_key", state_key_started);

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let state_token = random_urlsafe(24);
    let nonce = random_urlsafe(24);
    let pkce_verifier = random_urlsafe(48);
    let pkce_challenge = pkce_challenge(&pkce_verifier);
    let next_path = sanitize_next_path(query.next.as_deref());
    let flow = SsoFlowCookie {
        provider_id: provider.id.to_string(),
        state: state_token.clone(),
        nonce: nonce.clone(),
        pkce_verifier,
        next_path,
        issued_at: now,
        expires_at: now + AUTH_SSO_STATE_TTL_SECS,
    };

    let flow_cookie = match encode_flow_cookie(&flow, &state_key) {
        Ok(value) => value,
        Err(err) => {
            observe_sso(
                &state,
                "deny",
                "state_cookie_encode_error",
                provider.kind_name(),
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };

    let redirect_uri = format!(
        "{}/api/v1/auth/sso/{}/callback",
        state.external_url, provider.id
    );

    let mut auth_url = match reqwest::Url::parse(&metadata.endpoints.authorization_url) {
        Ok(url) => url,
        Err(err) => {
            observe_sso(
                &state,
                "deny",
                "authorization_url_invalid",
                provider.kind_name(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid authorization url: {err}"),
            );
        }
    };
    {
        let scopes = provider.scopes_or_default().join(" ");
        let mut pairs = auth_url.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", &provider.client_id);
        pairs.append_pair("redirect_uri", &redirect_uri);
        pairs.append_pair("scope", &scopes);
        pairs.append_pair("state", &state_token);
        pairs.append_pair("nonce", &nonce);
        if provider.pkce_required {
            pairs.append_pair("code_challenge", &pkce_challenge);
            pairs.append_pair("code_challenge_method", "S256");
        }
    }

    let set_cookie = match build_sso_cookie(&flow_cookie) {
        Ok(value) => value,
        Err(err) => {
            observe_sso(&state, "deny", "state_cookie_invalid", provider.kind_name());
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };

    observe_sso(&state, "allow", "start", provider.kind_name());
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        LOCATION,
        axum::http::HeaderValue::from_str(auth_url.as_str())
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/")),
    );
    response.headers_mut().append(SET_COOKIE, set_cookie);
    response
}

pub(super) async fn auth_sso_callback(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<SsoCallbackQuery>,
    request: Request,
) -> Response {
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    if let Some(error) = query.error {
        observe_sso(&state, "deny", "provider_error", "none");
        let detail = query.error_description.unwrap_or_default();
        let message = format!("sso provider denied login: {error} {detail}")
            .trim()
            .to_string();
        return callback_error(StatusCode::UNAUTHORIZED, message);
    }

    let code = match query.code.and_then(trimmed_opt) {
        Some(code) => code,
        None => {
            observe_sso(&state, "deny", "missing_code", "none");
            return callback_error(StatusCode::BAD_REQUEST, "missing code".to_string());
        }
    };
    let returned_state = match query.state.and_then(trimmed_opt) {
        Some(state_value) => state_value,
        None => {
            observe_sso(&state, "deny", "missing_state", "none");
            return callback_error(StatusCode::BAD_REQUEST, "missing state".to_string());
        }
    };

    let encoded_cookie = match extract_named_cookie(request.headers(), AUTH_SSO_COOKIE_NAME) {
        Some(cookie) => cookie,
        None => {
            observe_sso(&state, "deny", "missing_state_cookie", "none");
            return callback_error(
                StatusCode::UNAUTHORIZED,
                "missing sso state cookie".to_string(),
            );
        }
    };

    let state_key_started = Instant::now();
    let state_key = match state.sso.ensure_state_key().await {
        Ok(state_key) => state_key,
        Err(err) => {
            observe_sso(&state, "deny", "state_key_error", "none");
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };

    let flow = match decode_flow_cookie(&encoded_cookie, &state_key) {
        Ok(flow) => flow,
        Err(err) => {
            observe_sso(&state, "deny", "state_cookie_invalid", "none");
            return callback_error(StatusCode::UNAUTHORIZED, err);
        }
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if flow.provider_id != provider_id.to_string() {
        observe_sso(&state, "deny", "provider_mismatch", "none");
        return callback_error(
            StatusCode::UNAUTHORIZED,
            "sso provider mismatch".to_string(),
        );
    }
    if flow.state != returned_state {
        observe_sso(&state, "deny", "state_mismatch", "none");
        return callback_error(StatusCode::UNAUTHORIZED, "invalid sso state".to_string());
    }
    if now > flow.expires_at {
        observe_sso(&state, "deny", "state_expired", "none");
        return callback_error(StatusCode::UNAUTHORIZED, "expired sso state".to_string());
    }
    if !mark_sso_state_consumed(&flow, now) {
        observe_sso(&state, "deny", "state_replayed", "none");
        return callback_error(
            StatusCode::UNAUTHORIZED,
            "sso state already used".to_string(),
        );
    }

    let provider_lookup_started = Instant::now();
    let provider = match state.sso.get_provider(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            observe_sso(&state, "deny", "provider_not_found", "none");
            return callback_error(StatusCode::NOT_FOUND, "sso provider not found".to_string());
        }
        Err(err) => {
            observe_sso(&state, "deny", "provider_store_error", "none");
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "provider_lookup",
        provider_lookup_started,
    );
    observe_sso_latency(&state, provider.kind_name(), "state_key", state_key_started);

    if !provider.enabled {
        observe_sso(&state, "deny", "provider_disabled", provider.kind_name());
        return callback_error(
            StatusCode::UNAUTHORIZED,
            "sso provider disabled".to_string(),
        );
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            observe_sso(&state, "deny", "http_client_error", provider.kind_name());
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    };

    let metadata_started = Instant::now();
    let metadata = match resolve_provider_metadata(&http, &provider).await {
        Ok(metadata) => metadata,
        Err(err) => {
            observe_sso(
                &state,
                "deny",
                "provider_config_invalid",
                provider.kind_name(),
            );
            return callback_error(StatusCode::BAD_REQUEST, err);
        }
    };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "provider_metadata",
        metadata_started,
    );

    let redirect_uri = format!(
        "{}/api/v1/auth/sso/{}/callback",
        state.external_url, provider.id
    );

    let token_exchange_started = Instant::now();
    let token = match exchange_code(
        &http,
        &provider,
        &metadata.endpoints.token_url,
        &code,
        &redirect_uri,
        &flow.pkce_verifier,
    )
    .await
    {
        Ok(token) => token,
        Err(err) => {
            observe_sso(
                &state,
                "deny",
                "token_exchange_failed",
                provider.kind_name(),
            );
            return callback_error(StatusCode::UNAUTHORIZED, err);
        }
    };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "token_exchange",
        token_exchange_started,
    );

    let identity_started = Instant::now();
    let identity =
        match load_external_identity(&http, &provider, &metadata, &token, &flow.nonce).await {
            Ok(identity) => identity,
            Err(err) => {
                observe_sso(
                    &state,
                    "deny",
                    "identity_resolution_failed",
                    provider.kind_name(),
                );
                return callback_error(StatusCode::UNAUTHORIZED, err);
            }
        };
    observe_sso_latency(
        &state,
        provider.kind_name(),
        "identity_resolution",
        identity_started,
    );

    if !provider.email_allowed(identity.email.as_deref()) {
        observe_sso(&state, "deny", "email_domain_denied", provider.kind_name());
        return callback_error(
            StatusCode::FORBIDDEN,
            "email domain not allowed".to_string(),
        );
    }

    let role = match provider.resolve_role(
        &identity.subject,
        identity.email.as_deref(),
        &identity.groups,
    ) {
        Some(role) => role,
        None => {
            observe_sso(&state, "deny", "role_unmapped", provider.kind_name());
            return callback_error(
                StatusCode::FORBIDDEN,
                "no matching role mapping for identity".to_string(),
            );
        }
    };

    let keyset_started = Instant::now();
    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => {
            observe_sso(&state, "deny", "keyset_error", provider.kind_name());
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    observe_sso_latency(&state, provider.kind_name(), "keyset_load", keyset_started);

    let mint_started = Instant::now();
    let sub = format!("sso:{}:{}", provider.id, identity.subject);
    let ttl_secs = i64::try_from(provider.session_ttl_secs).unwrap_or(8 * 60 * 60);
    let token = match api_auth::mint_token_with_roles(
        &keyset,
        &sub,
        Some(ttl_secs.max(1)),
        None,
        Some(vec![role.as_str().to_string()]),
    ) {
        Ok(token) => token,
        Err(err) => {
            observe_sso(&state, "deny", "token_mint_error", provider.kind_name());
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    observe_sso_latency(&state, provider.kind_name(), "token_mint", mint_started);

    let auth_cookie = match build_auth_cookie(&token.token) {
        Ok(cookie) => cookie,
        Err(err) => {
            observe_sso(&state, "deny", "cookie_build_error", provider.kind_name());
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };
    let clear_sso = match clear_sso_cookie() {
        Ok(cookie) => cookie,
        Err(err) => {
            observe_sso(&state, "deny", "cookie_build_error", provider.kind_name());
            return callback_error(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    };

    observe_sso(&state, "allow", "callback", provider.kind_name());
    let mut response = StatusCode::FOUND.into_response();
    let next_path = sanitize_next_path(Some(&flow.next_path));
    response.headers_mut().insert(
        LOCATION,
        axum::http::HeaderValue::from_str(&next_path)
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("/")),
    );
    response.headers_mut().append(SET_COOKIE, auth_cookie);
    response.headers_mut().append(SET_COOKIE, clear_sso);
    response
}

fn callback_error(status: StatusCode, message: String) -> Response {
    let mut response = error_response(status, message);
    if let Ok(cookie) = clear_sso_cookie() {
        response.headers_mut().append(SET_COOKIE, cookie);
    }
    response
}

async fn resolve_provider_metadata(
    http: &reqwest::Client,
    provider: &SsoProvider,
) -> Result<ResolvedProviderMetadata, String> {
    let (issuer, discovery) = match provider.kind {
        SsoProviderKind::Google => {
            let issuer = provider
                .issuer_url
                .clone()
                .unwrap_or_else(|| GOOGLE_DEFAULT_ISSUER.to_string());
            let discovery = load_oidc_discovery(http, &issuer).await?;
            (Some(issuer), Some(discovery))
        }
        SsoProviderKind::GenericOidc => {
            let issuer = provider
                .issuer_url
                .clone()
                .ok_or_else(|| "issuer_url is required for generic_oidc".to_string())?;
            let discovery = load_oidc_discovery(http, &issuer).await?;
            (Some(issuer), Some(discovery))
        }
        SsoProviderKind::Github => (None, None),
    };

    let default_endpoints = provider.endpoints_or_default().ok();
    let authorization_url = provider
        .authorization_url
        .clone()
        .or_else(|| {
            discovery
                .as_ref()
                .map(|value| value.authorization_endpoint.clone())
        })
        .or_else(|| {
            default_endpoints
                .as_ref()
                .map(|value| value.authorization_url.clone())
        })
        .ok_or_else(|| "authorization_url is required".to_string())?;
    let token_url = provider
        .token_url
        .clone()
        .or_else(|| discovery.as_ref().map(|value| value.token_endpoint.clone()))
        .or_else(|| {
            default_endpoints
                .as_ref()
                .map(|value| value.token_url.clone())
        })
        .ok_or_else(|| "token_url is required".to_string())?;
    let userinfo_url = provider
        .userinfo_url
        .clone()
        .or_else(|| {
            discovery
                .as_ref()
                .and_then(|value| value.userinfo_endpoint.clone())
        })
        .or_else(|| {
            default_endpoints
                .as_ref()
                .map(|value| value.userinfo_url.clone())
        })
        .ok_or_else(|| "userinfo_url is required".to_string())?;

    validate_url_for_runtime("authorization_url", &authorization_url)?;
    validate_url_for_runtime("token_url", &token_url)?;
    validate_url_for_runtime("userinfo_url", &userinfo_url)?;

    let issuer = discovery
        .as_ref()
        .map(|value| value.issuer.clone())
        .or(issuer);
    let jwks_uri = match provider.kind {
        SsoProviderKind::Github => None,
        SsoProviderKind::Google => Some(
            discovery
                .as_ref()
                .map(|value| value.jwks_uri.clone())
                .unwrap_or_else(|| GOOGLE_DEFAULT_JWKS_URI.to_string()),
        ),
        SsoProviderKind::GenericOidc => Some(
            discovery
                .as_ref()
                .map(|value| value.jwks_uri.clone())
                .ok_or_else(|| "oidc discovery missing jwks_uri".to_string())?,
        ),
    };

    if let Some(uri) = &jwks_uri {
        validate_url_for_runtime("jwks_uri", uri)?;
    }

    Ok(ResolvedProviderMetadata {
        endpoints: SsoEndpoints {
            authorization_url,
            token_url,
            userinfo_url,
        },
        issuer,
        jwks_uri,
    })
}

async fn load_oidc_discovery(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<OidcDiscoveryDocument, String> {
    let cache_key = issuer.trim().to_string();
    let now_epoch = OffsetDateTime::now_utc().unix_timestamp();
    let cache = OIDC_DISCOVERY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(lock) = cache.lock() {
        if let Some(entry) = lock.get(&cache_key) {
            if entry.expires_at_epoch > now_epoch {
                return Ok(entry.value.clone());
            }
        }
    }

    let base = issuer.trim().trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let response = http
        .get(&url)
        .send()
        .await
        .map_err(|err| format!("oidc discovery request failed: {err}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "oidc discovery endpoint returned {}: {}",
            status, body
        ));
    }

    let payload = response
        .json::<OidcDiscoveryDocument>()
        .await
        .map_err(|err| format!("oidc discovery decode failed: {err}"))?;

    validate_url_for_runtime(
        "oidc authorization_endpoint",
        &payload.authorization_endpoint,
    )?;
    validate_url_for_runtime("oidc token_endpoint", &payload.token_endpoint)?;
    validate_url_for_runtime("oidc jwks_uri", &payload.jwks_uri)?;
    if let Some(endpoint) = &payload.userinfo_endpoint {
        validate_url_for_runtime("oidc userinfo_endpoint", endpoint)?;
    }

    if let Ok(mut lock) = cache.lock() {
        lock.insert(
            cache_key,
            CacheEntry {
                value: payload.clone(),
                expires_at_epoch: now_epoch + OIDC_CACHE_TTL_SECS,
            },
        );
    }

    Ok(payload)
}

async fn exchange_code(
    http: &reqwest::Client,
    provider: &SsoProvider,
    token_url: &str,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<OAuthTokenResponse, String> {
    let request = match provider.kind {
        SsoProviderKind::Github => http
            .post(token_url)
            .header("accept", "application/json")
            .header("user-agent", "neuwerk")
            .form(&[
                ("client_id", provider.client_id.as_str()),
                ("client_secret", provider.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
            ]),
        _ => {
            let mut params = vec![
                ("grant_type", "authorization_code"),
                ("client_id", provider.client_id.as_str()),
                ("client_secret", provider.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", redirect_uri),
            ];
            if provider.pkce_required {
                params.push(("code_verifier", pkce_verifier));
            }
            http.post(token_url).form(&params)
        }
    };

    let response = request
        .send()
        .await
        .map_err(|err| format!("token request failed: {err}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("token endpoint returned {}: {}", status, body));
    }

    response
        .json::<OAuthTokenResponse>()
        .await
        .map_err(|err| format!("token response decode failed: {err}"))
}

async fn load_external_identity(
    http: &reqwest::Client,
    provider: &SsoProvider,
    metadata: &ResolvedProviderMetadata,
    token: &OAuthTokenResponse,
    expected_nonce: &str,
) -> Result<ExternalIdentity, String> {
    match provider.kind {
        SsoProviderKind::Github => load_github_identity(http, &token.access_token).await,
        _ => load_oidc_identity(http, provider, metadata, token, expected_nonce).await,
    }
}

async fn load_oidc_identity(
    http: &reqwest::Client,
    provider: &SsoProvider,
    metadata: &ResolvedProviderMetadata,
    token: &OAuthTokenResponse,
    expected_nonce: &str,
) -> Result<ExternalIdentity, String> {
    let id_token = token
        .id_token
        .as_deref()
        .ok_or_else(|| "oidc token response missing id_token".to_string())?;
    let issuer = metadata
        .issuer
        .as_deref()
        .ok_or_else(|| "oidc provider issuer is missing".to_string())?;
    let jwks_uri = metadata
        .jwks_uri
        .as_deref()
        .ok_or_else(|| "oidc provider jwks_uri is missing".to_string())?;

    let claims =
        verify_id_token(http, provider, issuer, jwks_uri, id_token, expected_nonce).await?;

    let subject_claim = provider.subject_claim.trim();
    let mut subject = claims.get(subject_claim).and_then(value_to_string);
    let mut email = provider
        .email_claim
        .as_deref()
        .and_then(|claim| claims.get(claim))
        .and_then(value_to_string);
    let mut groups = provider
        .groups_claim
        .as_deref()
        .and_then(|claim| claims.get(claim))
        .map(value_to_string_vec)
        .unwrap_or_default();

    if subject.is_none() || email.is_none() || groups.is_empty() {
        let userinfo =
            load_userinfo_payload(http, &metadata.endpoints.userinfo_url, &token.access_token)
                .await?;
        if subject.is_none() {
            subject = userinfo.get(subject_claim).and_then(value_to_string);
        }
        if email.is_none() {
            email = provider
                .email_claim
                .as_deref()
                .and_then(|claim| userinfo.get(claim))
                .and_then(value_to_string);
        }
        if groups.is_empty() {
            groups = provider
                .groups_claim
                .as_deref()
                .and_then(|claim| userinfo.get(claim))
                .map(value_to_string_vec)
                .unwrap_or_default();
        }
    }

    let subject = subject.ok_or_else(|| format!("missing subject claim: {subject_claim}"))?;

    Ok(ExternalIdentity {
        subject,
        email,
        groups,
    })
}

async fn verify_id_token(
    http: &reqwest::Client,
    provider: &SsoProvider,
    issuer: &str,
    jwks_uri: &str,
    id_token: &str,
    expected_nonce: &str,
) -> Result<Value, String> {
    let (signing_input, header, claims, signature) = parse_jwt(id_token)?;

    verify_jwt_signature(http, jwks_uri, &signing_input, &header, &signature).await?;

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token_issuer = claims
        .get("iss")
        .and_then(value_to_string)
        .ok_or_else(|| "id_token missing iss claim".to_string())?;
    if !issuer_matches(provider.kind, issuer, &token_issuer) {
        return Err("id_token issuer mismatch".to_string());
    }

    if !audience_matches(&claims, &provider.client_id) {
        return Err("id_token audience mismatch".to_string());
    }

    let nonce = claims
        .get("nonce")
        .and_then(value_to_string)
        .ok_or_else(|| "id_token missing nonce claim".to_string())?;
    if nonce != expected_nonce {
        return Err("id_token nonce mismatch".to_string());
    }

    let exp = value_to_i64(claims.get("exp")).ok_or_else(|| "id_token missing exp".to_string())?;
    if now > exp.saturating_add(OIDC_CLOCK_SKEW_SECS) {
        return Err("id_token expired".to_string());
    }

    if let Some(nbf) = value_to_i64(claims.get("nbf")) {
        if now.saturating_add(OIDC_CLOCK_SKEW_SECS) < nbf {
            return Err("id_token not yet valid".to_string());
        }
    }

    if let Some(iat) = value_to_i64(claims.get("iat")) {
        if iat > now.saturating_add(OIDC_CLOCK_SKEW_SECS) {
            return Err("id_token issued_at is in the future".to_string());
        }
    }

    Ok(claims)
}

fn parse_jwt(token: &str) -> Result<(String, JwtHeader, Value, Vec<u8>), String> {
    let mut segments = token.split('.');
    let header_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token format".to_string())?;
    let payload_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token format".to_string())?;
    let signature_segment = segments
        .next()
        .ok_or_else(|| "invalid id_token format".to_string())?;
    if segments.next().is_some() {
        return Err("invalid id_token format".to_string());
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| "invalid id_token header".to_string())?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| "invalid id_token payload".to_string())?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_segment)
        .map_err(|_| "invalid id_token signature".to_string())?;

    let header = serde_json::from_slice::<JwtHeader>(&header_bytes)
        .map_err(|_| "invalid id_token header".to_string())?;
    let claims = serde_json::from_slice::<Value>(&payload_bytes)
        .map_err(|_| "invalid id_token payload".to_string())?;

    if header.alg.trim().is_empty() {
        return Err("id_token header missing alg".to_string());
    }

    Ok((
        format!("{header_segment}.{payload_segment}"),
        header,
        claims,
        signature,
    ))
}

async fn verify_jwt_signature(
    http: &reqwest::Client,
    jwks_uri: &str,
    signing_input: &str,
    header: &JwtHeader,
    signature: &[u8],
) -> Result<(), String> {
    let jwks = load_jwks(http, jwks_uri).await?;
    let mut keys = jwks.keys;

    if let Some(kid) = header.kid.as_deref() {
        keys.retain(|key| key.kid.as_deref() == Some(kid));
        if keys.is_empty() {
            return Err("id_token signing key not found".to_string());
        }
    }

    let verify_alg = jwt_verify_algorithm(&header.alg)?;
    let mut seen_rsa_key = false;
    for key in keys {
        if !key.kty.eq_ignore_ascii_case("rsa") {
            continue;
        }
        let Some(n) = key.n.as_deref() else {
            continue;
        };
        let Some(e) = key.e.as_deref() else {
            continue;
        };
        seen_rsa_key = true;
        let n_bytes = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|_| "invalid jwk modulus".to_string())?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|_| "invalid jwk exponent".to_string())?;

        let components = signature::RsaPublicKeyComponents {
            n: &n_bytes,
            e: &e_bytes,
        };
        if components
            .verify(verify_alg, signing_input.as_bytes(), signature)
            .is_ok()
        {
            return Ok(());
        }
    }

    if !seen_rsa_key {
        return Err("jwks does not contain rsa signing keys".to_string());
    }

    Err("id_token signature verification failed".to_string())
}

fn jwt_verify_algorithm(alg: &str) -> Result<&'static signature::RsaParameters, String> {
    match alg {
        "RS256" => Ok(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => Ok(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => Ok(&signature::RSA_PKCS1_2048_8192_SHA512),
        _ => Err(format!("unsupported id_token algorithm: {alg}")),
    }
}

async fn load_jwks(http: &reqwest::Client, uri: &str) -> Result<JwkSet, String> {
    let cache_key = uri.to_string();
    let now_epoch = OffsetDateTime::now_utc().unix_timestamp();
    let cache = OIDC_JWKS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(lock) = cache.lock() {
        if let Some(entry) = lock.get(&cache_key) {
            if entry.expires_at_epoch > now_epoch {
                return Ok(entry.value.clone());
            }
        }
    }

    let response = http
        .get(uri)
        .send()
        .await
        .map_err(|err| format!("jwks request failed: {err}"))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("jwks endpoint returned {}: {}", status, body));
    }

    let payload = response
        .json::<JwkSet>()
        .await
        .map_err(|err| format!("jwks decode failed: {err}"))?;

    if let Ok(mut lock) = cache.lock() {
        lock.insert(
            cache_key,
            CacheEntry {
                value: payload.clone(),
                expires_at_epoch: now_epoch + OIDC_CACHE_TTL_SECS,
            },
        );
    }

    Ok(payload)
}

fn issuer_matches(kind: SsoProviderKind, expected: &str, actual: &str) -> bool {
    if actual == expected {
        return true;
    }
    if kind == SsoProviderKind::Google
        && expected.eq_ignore_ascii_case(GOOGLE_DEFAULT_ISSUER)
        && actual == "accounts.google.com"
    {
        return true;
    }
    false
}

fn audience_matches(claims: &Value, client_id: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(value)) => value == client_id,
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(value_to_string)
            .any(|entry| entry == client_id),
        _ => false,
    }
}

fn value_to_i64(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(value)) => value.as_i64(),
        Some(Value::String(value)) => value.parse::<i64>().ok(),
        _ => None,
    }
}

fn mark_sso_state_consumed(flow: &SsoFlowCookie, now_epoch: i64) -> bool {
    let key = format!("{}:{}", flow.provider_id, flow.state);
    let guard = SSO_CALLBACK_REPLAY_GUARD.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut lock) = guard.lock() else {
        return false;
    };

    lock.retain(|_, expires_at| expires_at.saturating_add(30) >= now_epoch);
    if lock.contains_key(&key) {
        return false;
    }

    lock.insert(key, flow.expires_at);
    true
}

async fn load_userinfo_payload(
    http: &reqwest::Client,
    userinfo_url: &str,
    access_token: &str,
) -> Result<Value, String> {
    let response = http
        .get(userinfo_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| format!("userinfo request failed: {err}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("userinfo endpoint returned {}: {}", status, body));
    }

    response
        .json::<Value>()
        .await
        .map_err(|err| format!("userinfo decode failed: {err}"))
}

async fn load_github_identity(
    http: &reqwest::Client,
    access_token: &str,
) -> Result<ExternalIdentity, String> {
    let user = http
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("accept", "application/json")
        .header("user-agent", "neuwerk")
        .send()
        .await
        .map_err(|err| format!("github user request failed: {err}"))?;

    if !user.status().is_success() {
        let status = user.status();
        let body = user.text().await.unwrap_or_default();
        return Err(format!(
            "github user endpoint returned {}: {}",
            status, body
        ));
    }

    let payload = user
        .json::<Value>()
        .await
        .map_err(|err| format!("github user decode failed: {err}"))?;
    let subject = payload
        .get("id")
        .and_then(value_to_string)
        .ok_or_else(|| "github user id missing".to_string())?;
    let mut email = payload.get("email").and_then(value_to_string);

    if email.is_none() {
        let emails = http
            .get("https://api.github.com/user/emails")
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .header("user-agent", "neuwerk")
            .send()
            .await
            .map_err(|err| format!("github emails request failed: {err}"))?;
        if emails.status().is_success() {
            let values = emails
                .json::<Value>()
                .await
                .map_err(|err| format!("github emails decode failed: {err}"))?;
            if let Some(list) = values.as_array() {
                for entry in list {
                    let verified = entry
                        .get("verified")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    if !verified {
                        continue;
                    }
                    if let Some(addr) = entry.get("email").and_then(Value::as_str) {
                        email = Some(addr.to_string());
                        break;
                    }
                }
            }
        }
    }

    Ok(ExternalIdentity {
        subject,
        email,
        groups: Vec::new(),
    })
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => {
            let value = value.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_to_string_vec(value: &Value) -> Vec<String> {
    match value {
        Value::Array(entries) => entries.iter().filter_map(value_to_string).collect(),
        Value::String(value) => value
            .split(',')
            .map(|entry| entry.trim().to_string())
            .filter(|entry| !entry.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn sanitize_next_path(input: Option<&str>) -> String {
    let Some(input) = input else {
        return "/".to_string();
    };
    let trimmed = input.trim();
    if !trimmed.starts_with('/') {
        return "/".to_string();
    }
    if trimmed.starts_with("//") {
        return "/".to_string();
    }
    trimmed.to_string()
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut bytes = vec![0u8; bytes_len.max(16)];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Uuid::new_v4().to_string().replace('-', "");
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn encode_flow_cookie(flow: &SsoFlowCookie, key: &[u8]) -> Result<String, String> {
    let payload = serde_json::to_vec(flow).map_err(|err| err.to_string())?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "invalid hmac key".to_string())?;
    mac.update(payload_b64.as_bytes());
    let sig = mac.finalize().into_bytes();
    Ok(format!("{}.{}", payload_b64, URL_SAFE_NO_PAD.encode(sig)))
}

fn decode_flow_cookie(raw: &str, key: &[u8]) -> Result<SsoFlowCookie, String> {
    let mut parts = raw.split('.');
    let payload_b64 = parts
        .next()
        .ok_or_else(|| "invalid sso state cookie".to_string())?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| "invalid sso state cookie".to_string())?;
    if parts.next().is_some() {
        return Err("invalid sso state cookie".to_string());
    }

    let signature = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "invalid sso cookie signature".to_string())?;

    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| "invalid hmac key".to_string())?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| "invalid sso state signature".to_string())?;

    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "invalid sso state payload".to_string())?;
    serde_json::from_slice::<SsoFlowCookie>(&payload)
        .map_err(|_| "invalid sso state payload".to_string())
}

fn extract_named_cookie(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let header = headers.get(COOKIE)?.to_str().ok()?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{cookie_name}=")) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn build_sso_cookie(value: &str) -> Result<axum::http::HeaderValue, String> {
    let cookie = format!(
        "{AUTH_SSO_COOKIE_NAME}={value}; Max-Age={AUTH_SSO_STATE_TTL_SECS}; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/sso/"
    );
    axum::http::HeaderValue::from_str(&cookie).map_err(|_| "invalid sso cookie".to_string())
}

fn clear_sso_cookie() -> Result<axum::http::HeaderValue, String> {
    let cookie = format!(
        "{AUTH_SSO_COOKIE_NAME}=; Max-Age=0; HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/sso/"
    );
    axum::http::HeaderValue::from_str(&cookie).map_err(|_| "invalid sso cookie".to_string())
}

fn build_auth_cookie(token: &str) -> Result<axum::http::HeaderValue, String> {
    let cookie = format!("{AUTH_COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Strict; Path=/");
    axum::http::HeaderValue::from_str(&cookie).map_err(|_| "invalid auth cookie".to_string())
}

fn validate_url_for_runtime(field: &str, value: &str) -> Result<(), String> {
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

fn trimmed_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn observe_sso(state: &ApiState, outcome: &str, reason: &str, provider: &str) {
    state
        .metrics
        .observe_http_auth_sso(outcome, reason, provider);
    if let Some(audit_store) = &state.audit_store {
        let observed_at = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
        audit_store.ingest(
            AuditEvent {
                finding_type: AuditFindingType::AuthSso,
                source_group: format!("sso:{provider}"),
                hostname: Some(reason.to_string()),
                dst_ip: None,
                dst_port: None,
                proto: None,
                fqdn: Some(outcome.to_string()),
                sni: None,
                icmp_type: None,
                icmp_code: None,
                query_type: None,
                observed_at,
            },
            None,
            "controlplane-auth",
        );
    }
}

fn observe_sso_latency(state: &ApiState, provider: &str, stage: &str, started: Instant) {
    state
        .metrics
        .observe_http_auth_sso_latency(provider, stage, started.elapsed());
}

trait ProviderKindName {
    fn kind_name(&self) -> &'static str;
}

impl ProviderKindName for SsoProvider {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            SsoProviderKind::Google => "google",
            SsoProviderKind::Github => "github",
            SsoProviderKind::GenericOidc => "generic_oidc",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_path_sanitization_blocks_open_redirects() {
        assert_eq!(sanitize_next_path(Some("/")), "/");
        assert_eq!(sanitize_next_path(Some("/ui")), "/ui");
        assert_eq!(sanitize_next_path(Some("https://evil")), "/");
        assert_eq!(sanitize_next_path(Some("//evil")), "/");
    }

    #[test]
    fn flow_cookie_round_trip_and_tamper_rejected() {
        let key = vec![7u8; 32];
        let flow = SsoFlowCookie {
            provider_id: Uuid::new_v4().to_string(),
            state: "state".to_string(),
            nonce: "nonce".to_string(),
            pkce_verifier: "verifier".to_string(),
            next_path: "/".to_string(),
            issued_at: 1,
            expires_at: 2,
        };

        let encoded = encode_flow_cookie(&flow, &key).expect("encode");
        let decoded = decode_flow_cookie(&encoded, &key).expect("decode");
        assert_eq!(decoded.state, "state");

        let tampered = format!("{}x", encoded);
        assert!(decode_flow_cookie(&tampered, &key).is_err());
    }

    #[test]
    fn callback_replay_guard_rejects_second_use() {
        let flow = SsoFlowCookie {
            provider_id: "p1".to_string(),
            state: "s1".to_string(),
            nonce: "n1".to_string(),
            pkce_verifier: "v1".to_string(),
            next_path: "/".to_string(),
            issued_at: 10,
            expires_at: 20,
        };

        assert!(mark_sso_state_consumed(&flow, 11));
        assert!(!mark_sso_state_consumed(&flow, 11));
    }

    #[test]
    fn audience_match_supports_string_and_array() {
        let claims = serde_json::json!({ "aud": "abc" });
        assert!(audience_matches(&claims, "abc"));

        let claims = serde_json::json!({ "aud": ["x", "y", "abc"] });
        assert!(audience_matches(&claims, "abc"));

        let claims = serde_json::json!({ "aud": ["x", "y"] });
        assert!(!audience_matches(&claims, "abc"));
    }
}
