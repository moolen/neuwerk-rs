use axum::extract::{ConnectInfo, Extension, Request, State};
use axum::http::header::SET_COOKIE;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::controlplane::api_auth;

use super::{
    error_response, read_body_limited, ApiState, AuthContext, AUTH_COOKIE_NAME,
    AUTH_LOGIN_MAX_TOKEN_LEN,
};

#[derive(Debug, Serialize)]
struct AuthUser {
    sub: String,
    sa_id: Option<String>,
    exp: Option<i64>,
    roles: Vec<String>,
}

impl AuthUser {
    fn from_claims(claims: &api_auth::JwtClaims) -> Self {
        Self {
            sub: claims.sub.clone(),
            sa_id: claims.sa_id.clone(),
            exp: claims.exp,
            roles: claims.roles.clone().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct TokenLoginRequest {
    token: String,
}

pub(super) async fn auth_token_login(State(state): State<ApiState>, request: Request) -> Response {
    let client_hint = auth_login_client_hint(&request);
    let malformed_bucket = format!("{client_hint}:malformed");

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => {
            record_auth_login_failure(&state, &malformed_bucket);
            return resp;
        }
    };
    let login: TokenLoginRequest = match serde_json::from_slice(&body) {
        Ok(login) => login,
        Err(err) => {
            record_auth_login_failure(&state, &malformed_bucket);
            return error_response(
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid json: {err}"),
            );
        }
    };
    let token = normalize_login_token(&login.token);
    if token.is_empty() {
        record_auth_login_failure(&state, &malformed_bucket);
        return error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "token is required".to_string(),
        );
    }
    if token.len() > AUTH_LOGIN_MAX_TOKEN_LEN {
        record_auth_login_failure(&state, &malformed_bucket);
        return error_response(
            axum::http::StatusCode::BAD_REQUEST,
            "token too large".to_string(),
        );
    }
    let login_bucket = auth_login_bucket_key(&client_hint, token);
    if let Ok(mut limiter) = state.auth_login_limiter.lock() {
        if !limiter.allow_attempt(&login_bucket, std::time::Instant::now()) {
            return error_response(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "too many login attempts".to_string(),
            );
        }
    }
    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => return error_response(axum::http::StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let now = OffsetDateTime::now_utc();
    let claims = match api_auth::validate_token_allow_missing_exp(token, &keyset, now) {
        Ok(claims) => claims,
        Err(err) => {
            record_auth_login_failure(&state, &login_bucket);
            return error_response(axum::http::StatusCode::UNAUTHORIZED, err);
        }
    };
    if claims.sa_id.is_none() && claims.exp.is_none() {
        record_auth_login_failure(&state, &login_bucket);
        return error_response(
            axum::http::StatusCode::UNAUTHORIZED,
            "missing jwt exp".to_string(),
        );
    }
    if let Some(sa_id) = &claims.sa_id {
        if let Err(err) =
            super::auth::validate_service_account_claims(&state, &claims, sa_id, now).await
        {
            record_auth_login_failure(&state, &login_bucket);
            return error_response(axum::http::StatusCode::UNAUTHORIZED, err);
        }
    }
    if let Ok(mut limiter) = state.auth_login_limiter.lock() {
        limiter.record_success(&login_bucket, std::time::Instant::now());
    }
    let mut resp = Json(AuthUser::from_claims(&claims)).into_response();
    if let Ok(header) = build_auth_cookie(token) {
        resp.headers_mut().insert(SET_COOKIE, header);
    }
    resp
}

pub(super) async fn auth_whoami(Extension(auth): Extension<AuthContext>) -> Response {
    Json(AuthUser::from_claims(&auth.claims)).into_response()
}

pub(super) async fn auth_logout() -> Response {
    let mut resp = axum::http::StatusCode::NO_CONTENT.into_response();
    if let Ok(header) = clear_auth_cookie() {
        resp.headers_mut().insert(SET_COOKIE, header);
    }
    resp
}

fn record_auth_login_failure(state: &ApiState, bucket: &str) {
    if let Ok(mut limiter) = state.auth_login_limiter.lock() {
        limiter.record_failure(bucket, std::time::Instant::now());
    }
}

fn auth_login_bucket_key(client_hint: &str, token: &str) -> String {
    let digest = super::sha256_hex(token.as_bytes());
    let short = &digest[..16];
    format!("{client_hint}:token:{short}")
}

fn auth_login_client_hint(request: &Request) -> String {
    if let Some(peer) = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
    {
        return peer.0.ip().to_string();
    }
    let headers = request.headers();
    for name in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers.get(name) {
            if let Ok(raw) = value.to_str() {
                if let Some(first) = raw.split(',').next() {
                    let trimmed = first.trim();
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
    }
    "unknown".to_string()
}

fn build_auth_cookie(token: &str) -> Result<axum::http::HeaderValue, String> {
    let cookie = format!("{AUTH_COOKIE_NAME}={token}; HttpOnly; Secure; SameSite=Strict; Path=/");
    axum::http::HeaderValue::from_str(&cookie).map_err(|_| "invalid auth cookie".to_string())
}

fn clear_auth_cookie() -> Result<axum::http::HeaderValue, String> {
    let cookie =
        format!("{AUTH_COOKIE_NAME}=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/");
    axum::http::HeaderValue::from_str(&cookie).map_err(|_| "invalid auth cookie".to_string())
}

fn normalize_login_token(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed
        .strip_prefix("Bearer ")
        .or_else(|| trimmed.strip_prefix("bearer "))
    {
        return stripped.trim();
    }
    trimmed
}
