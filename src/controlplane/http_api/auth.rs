use std::collections::HashMap;
use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::HeaderMap;
use axum::http::Method;
use axum::response::Response;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::api_auth;
use crate::controlplane::service_accounts::{
    parse_rfc3339, ServiceAccountRole, ServiceAccountStatus, TokenMeta, TokenStatus,
};

use super::{error_response, ApiState, AuthContext, AUTH_COOKIE_NAME};
use super::{AUTH_LOGIN_BLOCK, AUTH_LOGIN_MAX_BUCKETS, AUTH_LOGIN_MAX_FAILURES, AUTH_LOGIN_WINDOW};

#[derive(Debug, Clone)]
struct LoginBucket {
    failures: Vec<Instant>,
    blocked_until: Option<Instant>,
    last_seen: Instant,
}

impl LoginBucket {
    fn new(now: Instant) -> Self {
        Self {
            failures: Vec::new(),
            blocked_until: None,
            last_seen: now,
        }
    }

    fn allow_attempt(&mut self, now: Instant) -> bool {
        self.last_seen = now;
        self.prune(now);
        if let Some(until) = self.blocked_until {
            if now < until {
                return false;
            }
            self.blocked_until = None;
        }
        true
    }

    fn record_failure(&mut self, now: Instant) {
        self.last_seen = now;
        self.prune(now);
        self.failures.push(now);
        if self.failures.len() >= AUTH_LOGIN_MAX_FAILURES {
            self.blocked_until = Some(now + AUTH_LOGIN_BLOCK);
            self.failures.clear();
        }
    }

    fn record_success(&mut self, now: Instant) {
        self.last_seen = now;
        self.failures.clear();
        self.blocked_until = None;
    }

    fn prune(&mut self, now: Instant) {
        self.failures
            .retain(|attempt| now.duration_since(*attempt) <= AUTH_LOGIN_WINDOW);
    }

    fn is_stale(&self, now: Instant) -> bool {
        self.failures.is_empty()
            && self.blocked_until.map(|until| now >= until).unwrap_or(true)
            && now.duration_since(self.last_seen)
                > AUTH_LOGIN_WINDOW.saturating_add(AUTH_LOGIN_BLOCK)
    }
}

#[derive(Debug, Default)]
pub(super) struct AuthLoginLimiter {
    buckets: HashMap<String, LoginBucket>,
}

impl AuthLoginLimiter {
    pub(super) fn allow_attempt(&mut self, key: &str, now: Instant) -> bool {
        self.prune(now);
        self.bucket_mut(key, now).allow_attempt(now)
    }

    pub(super) fn record_failure(&mut self, key: &str, now: Instant) {
        self.prune(now);
        self.bucket_mut(key, now).record_failure(now);
    }

    pub(super) fn record_success(&mut self, key: &str, now: Instant) {
        self.prune(now);
        self.bucket_mut(key, now).record_success(now);
    }

    fn prune(&mut self, now: Instant) {
        for bucket in self.buckets.values_mut() {
            bucket.prune(now);
        }
        self.buckets.retain(|_, bucket| !bucket.is_stale(now));
    }

    fn bucket_mut(&mut self, key: &str, now: Instant) -> &mut LoginBucket {
        if !self.buckets.contains_key(key) {
            self.evict_if_needed();
            self.buckets.insert(key.to_string(), LoginBucket::new(now));
        }
        self.buckets
            .get_mut(key)
            .unwrap_or_else(|| unreachable!("bucket inserted or already present"))
    }

    fn evict_if_needed(&mut self) {
        if self.buckets.len() < AUTH_LOGIN_MAX_BUCKETS {
            return;
        }
        if let Some((oldest_key, _)) = self
            .buckets
            .iter()
            .min_by_key(|(_, bucket)| bucket.last_seen)
            .map(|(key, bucket)| (key.clone(), bucket.last_seen))
        {
            self.buckets.remove(&oldest_key);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum AuthFailureReason {
    MissingToken,
    InvalidScheme,
    InvalidToken,
    KeysetError,
    InsufficientRole,
    ValidToken,
}

impl AuthFailureReason {
    fn as_label(self) -> &'static str {
        match self {
            AuthFailureReason::MissingToken => "missing_token",
            AuthFailureReason::InvalidScheme => "invalid_scheme",
            AuthFailureReason::InvalidToken => "invalid_token",
            AuthFailureReason::KeysetError => "keyset_error",
            AuthFailureReason::InsufficientRole => "insufficient_role",
            AuthFailureReason::ValidToken => "valid_token",
        }
    }

    fn message(self) -> String {
        match self {
            AuthFailureReason::MissingToken => "missing bearer token".to_string(),
            AuthFailureReason::InvalidScheme => "invalid authorization scheme".to_string(),
            AuthFailureReason::InvalidToken => "invalid bearer token".to_string(),
            AuthFailureReason::KeysetError => "missing api auth keyset".to_string(),
            AuthFailureReason::InsufficientRole => "insufficient role".to_string(),
            AuthFailureReason::ValidToken => "ok".to_string(),
        }
    }
}

pub(super) async fn auth_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    if path == "/health" || path == "/metrics" {
        return next.run(request).await;
    }

    let token = match extract_bearer_token(request.headers().get(AUTHORIZATION)) {
        Ok(token) => token,
        Err(reason) => {
            if let Some(token) = extract_cookie_token(request.headers()) {
                token
            } else {
                state.metrics.observe_http_auth("deny", reason.as_label());
                return error_response(axum::http::StatusCode::UNAUTHORIZED, reason.message());
            }
        }
    };

    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => {
            state
                .metrics
                .observe_http_auth("deny", AuthFailureReason::KeysetError.as_label());
            return error_response(axum::http::StatusCode::UNAUTHORIZED, err);
        }
    };

    let now = OffsetDateTime::now_utc();
    let mut claims = match api_auth::validate_token_allow_missing_exp(&token, &keyset, now) {
        Ok(claims) => claims,
        Err(err) => {
            state
                .metrics
                .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
            return error_response(axum::http::StatusCode::UNAUTHORIZED, err);
        }
    };

    if claims.sa_id.is_none() && claims.exp.is_none() {
        state
            .metrics
            .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
        return error_response(
            axum::http::StatusCode::UNAUTHORIZED,
            "missing jwt exp".to_string(),
        );
    }

    if let Some(sa_id) = &claims.sa_id {
        match validate_service_account_claims(&state, &claims, sa_id, now).await {
            Ok(role) => {
                claims.roles = Some(vec![role.as_str().to_string()]);
            }
            Err(err) => {
                state
                    .metrics
                    .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
                return error_response(axum::http::StatusCode::UNAUTHORIZED, err);
            }
        }
    }

    if requires_admin_role(request.method(), path) && !has_admin_role(&claims) {
        state
            .metrics
            .observe_http_auth("deny", AuthFailureReason::InsufficientRole.as_label());
        return error_response(
            axum::http::StatusCode::FORBIDDEN,
            "admin role required".to_string(),
        );
    }

    let mut request = request;
    request.extensions_mut().insert(AuthContext {
        claims: claims.clone(),
    });

    state
        .metrics
        .observe_http_auth("allow", AuthFailureReason::ValidToken.as_label());
    next.run(request).await
}

fn requires_admin_role(method: &Method, _path: &str) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn has_admin_role(claims: &api_auth::JwtClaims) -> bool {
    claims
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|role| role.eq_ignore_ascii_case("admin")))
        .unwrap_or(false)
}

pub(super) async fn validate_service_account_claims(
    state: &ApiState,
    claims: &api_auth::JwtClaims,
    sa_id: &str,
    now: OffsetDateTime,
) -> Result<ServiceAccountRole, String> {
    let account_id =
        Uuid::parse_str(sa_id).map_err(|_| "invalid service account id".to_string())?;
    if claims.sub != sa_id {
        return Err("jwt sub does not match service account".to_string());
    }
    let token_id = Uuid::parse_str(&claims.jti).map_err(|_| "invalid token id".to_string())?;
    let mut token = state
        .service_accounts
        .get_token(token_id)
        .await?
        .ok_or_else(|| "token not found".to_string())?;
    if token.service_account_id != account_id {
        return Err("token does not belong to service account".to_string());
    }
    if token.status != TokenStatus::Active || token.revoked_at.is_some() {
        return Err("token revoked".to_string());
    }
    let account = state
        .service_accounts
        .get_account(account_id)
        .await?
        .ok_or_else(|| "service account not found".to_string())?;
    if account.status != ServiceAccountStatus::Active {
        return Err("service account disabled".to_string());
    }
    if !account.role.allows(token.role) {
        return Err("token role exceeds current account role".to_string());
    }
    validate_service_account_claimed_roles(claims.roles.as_ref(), token.role)?;
    if let Some(expires_at) = &token.expires_at {
        if claims.exp.is_none() {
            return Err("missing jwt exp".to_string());
        }
        let expiry = parse_rfc3339(expires_at)?;
        if expiry.unix_timestamp() + api_auth::CLOCK_SKEW_SECS < now.unix_timestamp() {
            return Err("token expired".to_string());
        }
    }
    if should_update_last_used(&token, now) {
        if let Ok(updated_at) = now.format(&Rfc3339) {
            token.last_used_at = Some(updated_at);
            let _ = state.service_accounts.write_token(&token).await;
        }
    }
    Ok(token.role)
}

fn validate_service_account_claimed_roles(
    claims_roles: Option<&Vec<String>>,
    effective_role: ServiceAccountRole,
) -> Result<(), String> {
    let Some(claims_roles) = claims_roles else {
        return Ok(());
    };
    for role in claims_roles {
        let claimed = match role.trim().to_ascii_lowercase().as_str() {
            "readonly" => ServiceAccountRole::Readonly,
            "admin" => ServiceAccountRole::Admin,
            _ => return Err("invalid service account role claim".to_string()),
        };
        if !effective_role.allows(claimed) {
            return Err("jwt role exceeds stored token role".to_string());
        }
    }
    Ok(())
}

fn should_update_last_used(token: &TokenMeta, now: OffsetDateTime) -> bool {
    let Some(last_used) = &token.last_used_at else {
        return true;
    };
    let Ok(parsed) = parse_rfc3339(last_used) else {
        return true;
    };
    now.unix_timestamp().saturating_sub(parsed.unix_timestamp()) >= 60
}

fn extract_bearer_token(
    value: Option<&axum::http::HeaderValue>,
) -> Result<String, AuthFailureReason> {
    let value = match value {
        Some(value) => value,
        None => return Err(AuthFailureReason::MissingToken),
    };
    let value = value
        .to_str()
        .map_err(|_| AuthFailureReason::InvalidScheme)?;
    let mut parts = value.split_whitespace();
    let scheme = parts.next().ok_or(AuthFailureReason::InvalidScheme)?;
    let token = parts.next().ok_or(AuthFailureReason::MissingToken)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(AuthFailureReason::InvalidScheme);
    }
    Ok(token.to_string())
}

fn extract_cookie_token(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(COOKIE)?.to_str().ok()?;
    for part in header.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{AUTH_COOKIE_NAME}=")) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::http_api::ApiAuthSource;
    use crate::controlplane::integrations::IntegrationStore;
    use crate::controlplane::metrics::Metrics;
    use crate::controlplane::policy_repository::PolicyDiskStore;
    use crate::controlplane::service_accounts::{
        ServiceAccountRole, ServiceAccountStore, TokenMeta,
    };
    use crate::controlplane::sso::SsoStore;
    use crate::controlplane::PolicyStore;
    use crate::dataplane::policy::DefaultPolicy;
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn test_api_state(dir: &TempDir, service_accounts: ServiceAccountStore) -> ApiState {
        ApiState {
            policy_store: PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24),
            local_store: PolicyDiskStore::new(dir.path().join("policies")),
            service_accounts,
            sso: SsoStore::local(dir.path().join("sso")),
            integrations: IntegrationStore::local(dir.path().join("integrations")),
            audit_store: None,
            threat_store: None,
            cluster: None,
            metrics: Metrics::new().unwrap(),
            proxy_client: None,
            http_port: 8443,
            auth_source: ApiAuthSource::Local(dir.path().join("auth.json")),
            auth_login_limiter: Arc::new(Mutex::new(AuthLoginLimiter::default())),
            wiretap_hub: None,
            cluster_tls_dir: None,
            tls_dir: dir.path().join("http-tls"),
            token_path: dir.path().join("bootstrap-token"),
            external_url: "https://localhost".to_string(),
            tls_intercept_ca_ready: None,
            tls_intercept_ca_generation: None,
            leader_local_policy_apply_count: None,
            dns_map: None,
            readiness: None,
        }
    }

    #[tokio::test]
    async fn validate_service_account_claims_rejects_revoked_token_after_restart() {
        let dir = TempDir::new().unwrap();
        let sa_dir = dir.path().join("service-accounts");
        let store = ServiceAccountStore::local(sa_dir.clone());
        let account = store
            .create_account("svc".to_string(), None, "creator".to_string())
            .await
            .unwrap();
        let token_id = Uuid::new_v4();
        let mut token = TokenMeta::new(
            account.id,
            Some("token".to_string()),
            "creator".to_string(),
            "kid".to_string(),
            None,
            token_id,
        )
        .unwrap();
        token.status = TokenStatus::Revoked;
        token.revoked_at = Some("2026-03-09T12:00:00Z".to_string());
        store.write_token(&token).await.unwrap();

        let restarted_store = ServiceAccountStore::local(sa_dir);
        let state = test_api_state(&dir, restarted_store);
        let now = OffsetDateTime::now_utc();
        let claims = api_auth::JwtClaims {
            iss: "neuwerk".to_string(),
            aud: "neuwerk-api".to_string(),
            sub: account.id.to_string(),
            exp: None,
            iat: now.unix_timestamp(),
            jti: token_id.to_string(),
            sa_id: Some(account.id.to_string()),
            scope: None,
            roles: None,
        };

        let err = validate_service_account_claims(&state, &claims, &account.id.to_string(), now)
            .await
            .unwrap_err();
        assert_eq!(err, "token revoked");
    }

    #[tokio::test]
    async fn validate_service_account_claims_rejects_broader_token_than_account() {
        let dir = TempDir::new().unwrap();
        let store = ServiceAccountStore::local(dir.path().join("service-accounts"));
        let mut account = store
            .create_account_with_role(
                "svc".to_string(),
                None,
                "creator".to_string(),
                ServiceAccountRole::Admin,
            )
            .await
            .unwrap();
        let token_id = Uuid::new_v4();
        let token = TokenMeta::new_with_role(
            account.id,
            Some("token".to_string()),
            "creator".to_string(),
            "kid".to_string(),
            None,
            token_id,
            ServiceAccountRole::Admin,
        )
        .unwrap();
        store.write_token(&token).await.unwrap();
        account.role = ServiceAccountRole::Readonly;
        store.update_account(&account).await.unwrap();

        let state = test_api_state(&dir, store);
        let now = OffsetDateTime::now_utc();
        let claims = api_auth::JwtClaims {
            iss: "neuwerk".to_string(),
            aud: "neuwerk-api".to_string(),
            sub: account.id.to_string(),
            exp: None,
            iat: now.unix_timestamp(),
            jti: token_id.to_string(),
            sa_id: Some(account.id.to_string()),
            scope: None,
            roles: Some(vec!["admin".to_string()]),
        };

        let err = validate_service_account_claims(&state, &claims, &account.id.to_string(), now)
            .await
            .unwrap_err();
        assert_eq!(err, "token role exceeds current account role");
    }
}
