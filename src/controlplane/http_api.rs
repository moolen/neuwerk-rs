use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::extract::{Extension, OriginalUri, Path, Query, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE};
use axum::http::HeaderMap;
use axum::http::{Method, StatusCode};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_server::Server;
use futures::stream::SelectAll;
use futures::StreamExt;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use include_dir::{include_dir, Dir};
use mime_guess::MimeGuess;

use crate::controlplane::api_auth::{self, ApiKeySet};
use crate::controlplane::cluster::rpc::{RaftTlsConfig, WiretapClient};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::http_tls::{ensure_http_tls, HttpTlsConfig};
use crate::controlplane::metrics::{Metrics, StatsSnapshot};
use crate::controlplane::policy_config::PolicyMode;
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyActive, PolicyCreateRequest, PolicyDiskStore, PolicyIndex, PolicyMeta,
    PolicyRecord, POLICY_ACTIVE_KEY, POLICY_INDEX_KEY,
};
use crate::controlplane::ready::ReadinessState;
use crate::controlplane::service_accounts::{
    parse_rfc3339, parse_ttl_secs, ServiceAccountStatus, ServiceAccountStore, TokenMeta,
    TokenStatus,
};
use crate::controlplane::wiretap::{
    DnsCacheEntry, DnsMap, WiretapFilter, WiretapHub, WiretapQuery,
};
use crate::controlplane::PolicyStore;
static UI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/ui/dist");
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const AUTH_COOKIE_NAME: &str = "neuwerk_auth";
const POLICY_ACTIVATION_TIMEOUT: Duration = Duration::from_secs(2);
const POLICY_ACTIVATION_POLL: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub struct HttpApiCluster {
    pub raft: openraft::Raft<ClusterTypeConfig>,
    pub store: ClusterStore,
}

#[derive(Debug, Clone)]
pub struct HttpApiConfig {
    pub bind_addr: SocketAddr,
    pub advertise_addr: SocketAddr,
    pub metrics_bind: SocketAddr,
    pub tls_dir: PathBuf,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    pub san_entries: Vec<String>,
    pub management_ip: IpAddr,
    pub token_path: PathBuf,
    pub cluster_tls_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct ApiState {
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    service_accounts: ServiceAccountStore,
    cluster: Option<HttpApiCluster>,
    metrics: Metrics,
    proxy_client: Option<reqwest::Client>,
    http_port: u16,
    auth_source: ApiAuthSource,
    wiretap_hub: Option<WiretapHub>,
    cluster_tls_dir: Option<PathBuf>,
    dns_map: Option<DnsMap>,
    readiness: Option<ReadinessState>,
}

#[derive(Clone)]
struct AuthContext {
    claims: api_auth::JwtClaims,
}

#[derive(Clone)]
enum ApiAuthSource {
    Cluster(ClusterStore),
    Local(std::path::PathBuf),
}

impl ApiAuthSource {
    fn load_keyset(&self) -> Result<ApiKeySet, String> {
        match self {
            ApiAuthSource::Cluster(store) => api_auth::load_keyset_from_store(store)?
                .ok_or_else(|| "missing api auth keyset".to_string()),
            ApiAuthSource::Local(path) => api_auth::load_keyset_from_file(path)?
                .ok_or_else(|| "missing api auth keyset".to_string()),
        }
    }
}

async fn wait_for_policy_activation(
    policy_store: &PolicyStore,
    readiness: Option<&ReadinessState>,
    generation: u64,
) -> Result<(), String> {
    if readiness.is_none() {
        return Ok(());
    }
    if let Some(state) = readiness {
        if !state.dataplane_running() {
            return Ok(());
        }
    }
    if policy_store.policy_applied_generation() >= generation {
        return Ok(());
    }
    let deadline = Instant::now() + POLICY_ACTIVATION_TIMEOUT;
    loop {
        if policy_store.policy_applied_generation() >= generation {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "policy activation timed out waiting for generation {generation}"
            ));
        }
        tokio::time::sleep(POLICY_ACTIVATION_POLL).await;
    }
}

pub async fn run_http_api(
    cfg: HttpApiConfig,
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    cluster: Option<HttpApiCluster>,
    wiretap_hub: Option<WiretapHub>,
    dns_map: Option<DnsMap>,
    readiness: Option<ReadinessState>,
    metrics: Metrics,
) -> Result<(), String> {
    eprintln!(
        "http api: starting (bind={}, metrics={}, tls_dir={})",
        cfg.bind_addr,
        cfg.metrics_bind,
        cfg.tls_dir.display()
    );
    let tls = ensure_http_tls(HttpTlsConfig {
        tls_dir: cfg.tls_dir.clone(),
        cert_path: cfg.cert_path.clone(),
        key_path: cfg.key_path.clone(),
        ca_path: cfg.ca_path.clone(),
        ca_key_path: None,
        san_entries: cfg.san_entries.clone(),
        advertise_addr: cfg.advertise_addr,
        management_ip: cfg.management_ip,
        token_path: cfg.token_path.clone(),
        raft: cluster.as_ref().map(|c| c.raft.clone()),
        store: cluster.as_ref().map(|c| c.store.clone()),
    })
    .await?;

    let proxy_client = if cluster.is_some() {
        let mut builder = reqwest::Client::builder();
        if !tls.ca_pem.is_empty() {
            let ca = reqwest::Certificate::from_pem(&tls.ca_pem)
                .map_err(|err| format!("invalid http ca pem: {err}"))?;
            builder = builder.add_root_certificate(ca);
        }
        Some(
            builder
                .build()
                .map_err(|err| format!("http proxy client: {err}"))?,
        )
    } else {
        None
    };

    let auth_source = build_auth_source(&cfg, &cluster)?;
    let service_accounts = match &cluster {
        Some(cluster) => ServiceAccountStore::cluster(cluster.raft.clone(), cluster.store.clone()),
        None => ServiceAccountStore::local(PathBuf::from("/var/lib/neuwerk/service-accounts")),
    };
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        cluster,
        metrics: metrics.clone(),
        proxy_client,
        http_port: cfg.bind_addr.port(),
        auth_source,
        wiretap_hub,
        cluster_tls_dir: cfg.cluster_tls_dir.clone(),
        dns_map,
        readiness,
    };

    if let Some(cluster) = &state.cluster {
        spawn_raft_metrics_sampler(metrics.clone(), cluster.raft.clone());
        spawn_rocksdb_metrics_sampler(metrics.clone(), cluster.store.clone());
    }

    let api_public = Router::new()
        .route("/auth/token-login", post(auth_token_login))
        .route("/auth/logout", post(auth_logout))
        .with_state(state.clone());

    let api_protected = Router::new()
        .route("/auth/whoami", get(auth_whoami))
        .route("/policies", get(list_policies).post(create_policy))
        .route(
            "/policies/:id",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route(
            "/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route("/service-accounts/:id", delete(delete_service_account))
        .route(
            "/service-accounts/:id/tokens",
            get(list_service_account_tokens).post(create_service_account_token),
        )
        .route(
            "/service-accounts/:id/tokens/:token_id",
            delete(revoke_service_account_token),
        )
        .route("/wiretap/stream", get(wiretap_stream))
        .route("/dns-cache", get(list_dns_cache))
        .route("/stats", get(stats_handler))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let api = api_public.merge(api_protected);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .nest("/api/v1", api)
        .fallback(ui_handler)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            track_metrics,
        ));

    let metrics_app = Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(metrics.clone());

    let metrics_bind = cfg.metrics_bind;
    tokio::spawn(async move {
        match Server::bind(metrics_bind)
            .serve(metrics_app.into_make_service())
            .await
        {
            Ok(()) => {
                eprintln!("metrics server exited on {metrics_bind}");
            }
            Err(err) => {
                eprintln!("metrics server failed on {metrics_bind}: {err}");
            }
        }
    });

    let tls_config =
        axum_server::tls_rustls::RustlsConfig::from_pem_file(tls.cert_path, tls.key_path)
            .await
            .map_err(|err| format!("http tls config: {err}"))?;

    eprintln!("http api: serving https on {}", cfg.bind_addr);
    match axum_server::bind_rustls(cfg.bind_addr, tls_config)
        .serve(app.into_make_service())
        .await
    {
        Ok(()) => {
            eprintln!("http api: server exited on {}", cfg.bind_addr);
            Ok(())
        }
        Err(err) => Err(format!("http api serve: {err}")),
    }
}

fn build_auth_source(
    cfg: &HttpApiConfig,
    cluster: &Option<HttpApiCluster>,
) -> Result<ApiAuthSource, String> {
    if let Some(cluster) = cluster {
        return Ok(ApiAuthSource::Cluster(cluster.store.clone()));
    }
    api_auth::ensure_local_keyset(&cfg.tls_dir)?;
    let path = api_auth::local_keyset_path(&cfg.tls_dir);
    Ok(ApiAuthSource::Local(path))
}

async fn list_policies(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    match state.local_store.list_records() {
        Ok(records) => Json(records).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFormatQuery {
    format: Option<String>,
}

async fn get_policy(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(query): Query<PolicyFormatQuery>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let policy_id = match parse_uuid(&id, "policy id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let record = match state.local_store.read_record(policy_id) {
        Ok(Some(record)) => record,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "policy not found".to_string()),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let wants_yaml = query
        .format
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("yaml"))
        .unwrap_or(false);
    if wants_yaml {
        let yaml = match serde_yaml::to_string(&record) {
            Ok(yaml) => yaml,
            Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };
        let mut resp = Response::new(Body::from(yaml));
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/yaml"),
        );
        return resp;
    }
    Json(record).into_response()
}

async fn health_handler() -> Response {
    Json(json!({ "status": "ok" })).into_response()
}

async fn ready_handler(State(state): State<ApiState>) -> Response {
    let Some(readiness) = state.readiness.clone() else {
        return Json(json!({ "ready": true })).into_response();
    };
    let status = readiness.snapshot();
    let code = if status.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    match serde_json::to_value(&status) {
        Ok(body) => (code, Json(body)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn ui_handler(method: Method, OriginalUri(uri): OriginalUri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let raw_path = uri.path().trim_start_matches('/');
    let requested = if raw_path.is_empty() {
        "index.html"
    } else {
        raw_path
    };

    if let Some(file) = UI_DIR.get_file(requested) {
        return embedded_file_response(requested, file);
    }

    if let Some(index) = UI_DIR.get_file("index.html") {
        return embedded_file_response("index.html", index);
    }

    StatusCode::NOT_FOUND.into_response()
}

fn embedded_file_response(path: &str, file: &include_dir::File<'_>) -> Response {
    let mut resp = Response::new(Body::from(file.contents().to_vec()));
    let mime = MimeGuess::from_path(path).first_or_octet_stream();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_str(mime.as_ref())
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream")),
    );
    resp
}

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

#[derive(Debug, Deserialize, Default)]
struct WiretapStreamAuthQuery {
    #[serde(default)]
    access_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountCreateRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceAccountTokenCreateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    eternal: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ServiceAccountTokenResponse {
    token: String,
    token_meta: TokenMeta,
}

async fn create_policy(State(state): State<ApiState>, mut request: Request) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let create: PolicyCreateRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    let compiled = match create.policy.clone().compile() {
        Ok(compiled) => compiled,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    let record = match PolicyRecord::new(create.mode, create.policy) {
        Ok(record) => record,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    if let Err(err) = state.local_store.write_record(&record) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    if record.mode == PolicyMode::Enforce {
        let generation = match state.policy_store.rebuild(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
        ) {
            Ok(generation) => generation,
            Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
        };
        state.policy_store.set_active_policy_id(Some(record.id));
        if let Err(err) = state.local_store.set_active(Some(record.id)) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
        if let Err(err) =
            wait_for_policy_activation(&state.policy_store, state.readiness.as_ref(), generation)
                .await
        {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, err);
        }
    }

    if let Some(cluster) = &state.cluster {
        if let Err(err) = persist_cluster_policy(cluster, &record).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
        if record.mode != PolicyMode::Enforce {
            if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
                if active.id == record.id {
                    let cmd = ClusterCommand::Delete {
                        key: POLICY_ACTIVE_KEY.to_vec(),
                    };
                    if let Err(err) = cluster.raft.client_write(cmd).await {
                        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
                    }
                }
            }
        }
    }

    Json(record).into_response()
}

async fn update_policy(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let policy_id = match parse_uuid(&id, "policy id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let mut record = match state.local_store.read_record(policy_id) {
        Ok(Some(record)) => record,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "policy not found".to_string()),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let update: PolicyCreateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let compiled = match update.policy.clone().compile() {
        Ok(compiled) => compiled,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    record.mode = update.mode;
    record.policy = update.policy;

    if let Err(err) = state.local_store.write_record(&record) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    if record.mode == PolicyMode::Enforce {
        let generation = match state.policy_store.rebuild(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
        ) {
            Ok(generation) => generation,
            Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
        };
        state.policy_store.set_active_policy_id(Some(record.id));
        if let Err(err) = state.local_store.set_active(Some(record.id)) {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
        if let Err(err) =
            wait_for_policy_activation(&state.policy_store, state.readiness.as_ref(), generation)
                .await
        {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, err);
        }
    } else if let Ok(active_id) = state.local_store.active_id() {
        if active_id == Some(record.id) {
            if let Err(err) = state.local_store.set_active(None) {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
            let generation = match state.policy_store.rebuild(
                Vec::new(),
                crate::controlplane::policy_config::DnsPolicy::new(Vec::new()),
                None,
            ) {
                Ok(generation) => generation,
                Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
            };
            state.policy_store.set_active_policy_id(None);
            if let Err(err) = wait_for_policy_activation(
                &state.policy_store,
                state.readiness.as_ref(),
                generation,
            )
            .await
            {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, err);
            }
        }
    }

    if let Some(cluster) = &state.cluster {
        if let Err(err) = persist_cluster_policy(cluster, &record).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    }

    Json(record).into_response()
}

async fn delete_policy(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let policy_id = match parse_uuid(&id, "policy id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let record = match state.local_store.read_record(policy_id) {
        Ok(Some(record)) => record,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "policy not found".to_string()),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    if let Ok(active_id) = state.local_store.active_id() {
        if active_id == Some(record.id) {
            let _ = state.local_store.set_active(None);
            let generation = match state.policy_store.rebuild(
                Vec::new(),
                crate::controlplane::policy_config::DnsPolicy::new(Vec::new()),
                None,
            ) {
                Ok(generation) => generation,
                Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
            };
            state.policy_store.set_active_policy_id(None);
            if let Err(err) = wait_for_policy_activation(
                &state.policy_store,
                state.readiness.as_ref(),
                generation,
            )
            .await
            {
                return error_response(StatusCode::SERVICE_UNAVAILABLE, err);
            }
        }
    }
    if let Err(err) = state.local_store.delete_record(record.id) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    if let Some(cluster) = &state.cluster {
        if let Err(err) = delete_cluster_policy(cluster, record.id).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn list_dns_cache(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(dns_map) = &state.dns_map else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "dns cache unavailable".to_string(),
        );
    };
    let entries: Vec<DnsCacheEntry> = dns_map.snapshot_grouped();
    Json(json!({ "entries": entries })).into_response()
}

async fn stats_handler(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let snapshot: StatsSnapshot = state.metrics.snapshot();
    Json(snapshot).into_response()
}

async fn auth_token_login(State(state): State<ApiState>, request: Request) -> Response {
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let login: TokenLoginRequest = match serde_json::from_slice(&body) {
        Ok(login) => login,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let token = login.token.trim();
    if token.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "token is required".to_string());
    }
    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let now = OffsetDateTime::now_utc();
    let claims = match api_auth::validate_token_allow_missing_exp(token, &keyset, now) {
        Ok(claims) => claims,
        Err(err) => return error_response(StatusCode::UNAUTHORIZED, err),
    };
    if claims.sa_id.is_none() && claims.exp.is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "missing jwt exp".to_string());
    }
    if let Some(sa_id) = &claims.sa_id {
        if let Err(err) = validate_service_account_claims(&state, &claims, sa_id, now).await {
            return error_response(StatusCode::UNAUTHORIZED, err);
        }
    }
    let mut resp = Json(AuthUser::from_claims(&claims)).into_response();
    if let Ok(header) = build_auth_cookie(token) {
        resp.headers_mut().insert(SET_COOKIE, header);
    }
    resp
}

async fn auth_whoami(Extension(auth): Extension<AuthContext>) -> Response {
    Json(AuthUser::from_claims(&auth.claims)).into_response()
}

async fn auth_logout() -> Response {
    let mut resp = StatusCode::NO_CONTENT.into_response();
    if let Ok(header) = clear_auth_cookie() {
        resp.headers_mut().insert(SET_COOKIE, header);
    }
    resp
}
async fn list_service_accounts(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state.service_accounts.list_accounts().await {
        Ok(accounts) => Json(accounts).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn create_service_account(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let create: ServiceAccountCreateRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let name = create.name.trim();
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "name is required".to_string());
    }
    let description = create.description.and_then(|desc| {
        let trimmed = desc.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let created_by = auth.claims.sub.clone();
    match state
        .service_accounts
        .create_account(name.to_string(), description, created_by)
        .await
    {
        Ok(account) => Json(account).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn delete_service_account(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let account_id = match parse_uuid(&id, "service account id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let mut account = match state.service_accounts.get_account(account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "service account not found".to_string(),
            )
        }
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if account.status != ServiceAccountStatus::Disabled {
        account.status = ServiceAccountStatus::Disabled;
        if let Err(err) = state.service_accounts.update_account(&account).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    }
    let now = OffsetDateTime::now_utc();
    let now_str = now
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string());
    let tokens = match state.service_accounts.list_tokens(account_id).await {
        Ok(tokens) => tokens,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    for mut token in tokens {
        if token.status == TokenStatus::Revoked {
            continue;
        }
        token.status = TokenStatus::Revoked;
        token.revoked_at = Some(now_str.clone());
        if let Err(err) = state.service_accounts.write_token(&token).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn list_service_account_tokens(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let account_id = match parse_uuid(&id, "service account id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.service_accounts.list_tokens(account_id).await {
        Ok(tokens) => Json(tokens).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn create_service_account_token(
    State(state): State<ApiState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let account_id = match parse_uuid(&id, "service account id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let account = match state.service_accounts.get_account(account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "service account not found".to_string(),
            )
        }
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if account.status != ServiceAccountStatus::Active {
        return error_response(
            StatusCode::BAD_REQUEST,
            "service account disabled".to_string(),
        );
    }
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let create: ServiceAccountTokenCreateRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let eternal = create.eternal.unwrap_or(false);
    let ttl_secs = match create.ttl {
        Some(ttl) if !ttl.trim().is_empty() => match parse_ttl_secs(&ttl) {
            Ok(value) => Some(value),
            Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
        },
        _ => None,
    };
    if eternal && ttl_secs.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ttl and eternal are mutually exclusive".to_string(),
        );
    }
    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let now = OffsetDateTime::now_utc();
    let minted = match api_auth::mint_service_account_token(
        &keyset,
        &account_id.to_string(),
        ttl_secs,
        eternal,
        None,
        now,
    ) {
        Ok(minted) => minted,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    let token_id = match Uuid::parse_str(&minted.jti) {
        Ok(id) => id,
        Err(_) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid token id".to_string(),
            )
        }
    };
    let expires_at = match minted.exp {
        Some(exp) => match OffsetDateTime::from_unix_timestamp(exp) {
            Ok(dt) => Some(dt.format(&Rfc3339).unwrap_or_else(|_| exp.to_string())),
            Err(_) => None,
        },
        None => None,
    };
    let token_meta = match TokenMeta::new(
        account_id,
        create.name.and_then(|name| {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }),
        auth.claims.sub.clone(),
        minted.kid.clone(),
        expires_at,
        token_id,
    ) {
        Ok(meta) => meta,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if let Err(err) = state.service_accounts.write_token(&token_meta).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
    }
    Json(ServiceAccountTokenResponse {
        token: minted.token,
        token_meta,
    })
    .into_response()
}

async fn revoke_service_account_token(
    State(state): State<ApiState>,
    Path((id, token_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let account_id = match parse_uuid(&id, "service account id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let token_id = match parse_uuid(&token_id, "token id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let mut token = match state.service_accounts.get_token(token_id).await {
        Ok(Some(token)) => token,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "token not found".to_string()),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if token.service_account_id != account_id {
        return error_response(
            StatusCode::BAD_REQUEST,
            "token does not belong to account".to_string(),
        );
    }
    if token.status != TokenStatus::Revoked {
        let now = OffsetDateTime::now_utc();
        let now_str = now
            .format(&Rfc3339)
            .unwrap_or_else(|_| now.unix_timestamp().to_string());
        token.status = TokenStatus::Revoked;
        token.revoked_at = Some(now_str);
        if let Err(err) = state.service_accounts.write_token(&token).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn wiretap_stream(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let raw_query = request.uri().query().unwrap_or("");
    let query: WiretapQuery = match serde_urlencoded::from_str(raw_query) {
        Ok(query) => query,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };
    let filter = match WiretapFilter::from_query(query.clone()) {
        Ok(filter) => filter,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    if let Some(cluster) = &state.cluster {
        match leader_state(cluster, state.http_port).await {
            LeaderState::Leader => return wiretap_leader_stream(&state, query).await,
            LeaderState::Unknown => {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "leader unknown".to_string(),
                )
            }
            LeaderState::Follower(addr) => {
                let path = if raw_query.is_empty() {
                    "/api/v1/wiretap/stream".to_string()
                } else {
                    format!("/api/v1/wiretap/stream?{raw_query}")
                };
                return match proxy_stream_request(&state, addr, &headers, &path).await {
                    Ok(response) => response,
                    Err(err) => error_response(StatusCode::BAD_GATEWAY, err),
                };
            }
        }
    }

    wiretap_local_stream(&state, filter)
}

fn wiretap_local_stream(state: &ApiState, filter: WiretapFilter) -> Response {
    let Some(hub) = &state.wiretap_hub else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "wiretap unavailable".to_string(),
        );
    };

    let subscriber = hub.subscribe(filter);
    let stream = subscriber.into_stream().map(|event| {
        let event_name = match event.event_type {
            crate::dataplane::wiretap::WiretapEventType::Flow => "flow",
            crate::dataplane::wiretap::WiretapEventType::FlowEnd => "flow_end",
        };
        let payload = event.payload();
        let data = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
        Ok::<Event, Infallible>(Event::default().event(event_name).data(data))
    });

    Sse::new(stream).into_response()
}

async fn wiretap_leader_stream(state: &ApiState, query: WiretapQuery) -> Response {
    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster unavailable".to_string(),
        );
    };
    let Some(tls_dir) = &state.cluster_tls_dir else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "cluster tls dir missing".to_string(),
        );
    };
    let tls = match RaftTlsConfig::load(tls_dir.clone()) {
        Ok(tls) => tls,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let request = crate::controlplane::cluster::rpc::proto::WiretapSubscribeRequest {
        src_cidr: query.src_cidr.clone(),
        dst_cidr: query.dst_cidr.clone(),
        hostname: query.hostname.clone(),
        proto: query.proto.clone(),
        src_port: query.src_port.clone(),
        dst_port: query.dst_port.clone(),
    };

    let metrics = cluster.raft.metrics().borrow().clone();
    let mut streams: SelectAll<
        Pin<
            Box<
                dyn futures::Stream<Item = crate::controlplane::cluster::rpc::proto::WiretapEvent>
                    + Send,
            >,
        >,
    > = SelectAll::new();
    let mut stream_count = 0usize;
    for (_, node) in metrics.membership_config.membership().nodes() {
        let Ok(addr) = node.addr.parse::<SocketAddr>() else {
            continue;
        };
        let mut client = match WiretapClient::connect(addr, tls.clone()).await {
            Ok(client) => client,
            Err(_) => continue,
        };
        let stream = match client.subscribe(request.clone()).await {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let stream = stream.filter_map(|event| async move { event.ok() });
        streams.push(Box::pin(stream));
        stream_count += 1;
    }

    if stream_count == 0 {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "no wiretap subscribers available".to_string(),
        );
    }

    let stream = streams.map(|event| Ok::<Event, Infallible>(wiretap_event_from_proto(event)));
    Sse::new(stream).into_response()
}

fn wiretap_event_from_proto(
    event: crate::controlplane::cluster::rpc::proto::WiretapEvent,
) -> Event {
    let crate::controlplane::cluster::rpc::proto::WiretapEvent {
        event_type,
        flow_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto,
        packets_in,
        packets_out,
        last_seen,
        hostname,
        node_id,
    } = event;
    let event_name = if event_type == "flow_end" {
        "flow_end"
    } else {
        "flow"
    };
    let hostname = if hostname.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(hostname)
    };
    let payload = json!({
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "packets_in": packets_in,
        "packets_out": packets_out,
        "last_seen": last_seen,
        "hostname": hostname,
        "node_id": node_id,
    });
    Event::default().event(event_name).data(payload.to_string())
}

async fn maybe_proxy(state: &ApiState, request: Request) -> Result<Request, Response> {
    let Some(cluster) = &state.cluster else {
        return Ok(request);
    };
    match leader_state(cluster, state.http_port).await {
        LeaderState::Leader => Ok(request),
        LeaderState::Unknown => Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "leader unknown".to_string(),
        )),
        LeaderState::Follower(addr) => Err(match proxy_request(state, addr, request).await {
            Ok(response) => response,
            Err(ProxyFailure::Response(resp)) => resp,
            Err(ProxyFailure::Upstream(err)) => error_response(StatusCode::BAD_GATEWAY, err),
        }),
    }
}

async fn auth_middleware(
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
            } else if let Some(token) = extract_wiretap_query_token(&request) {
                token
            } else {
                state.metrics.observe_http_auth("deny", reason.as_label());
                return error_response(StatusCode::UNAUTHORIZED, reason.message());
            }
        }
    };

    let keyset = match state.auth_source.load_keyset() {
        Ok(keyset) => keyset,
        Err(err) => {
            state
                .metrics
                .observe_http_auth("deny", AuthFailureReason::KeysetError.as_label());
            return error_response(StatusCode::UNAUTHORIZED, err);
        }
    };

    let now = OffsetDateTime::now_utc();
    let claims = match api_auth::validate_token_allow_missing_exp(&token, &keyset, now) {
        Ok(claims) => claims,
        Err(err) => {
            state
                .metrics
                .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
            return error_response(StatusCode::UNAUTHORIZED, err);
        }
    };

    if claims.sa_id.is_none() && claims.exp.is_none() {
        state
            .metrics
            .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
        return error_response(StatusCode::UNAUTHORIZED, "missing jwt exp".to_string());
    }

    if let Some(sa_id) = &claims.sa_id {
        if let Err(err) = validate_service_account_claims(&state, &claims, sa_id, now).await {
            state
                .metrics
                .observe_http_auth("deny", AuthFailureReason::InvalidToken.as_label());
            return error_response(StatusCode::UNAUTHORIZED, err);
        }
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

fn extract_wiretap_query_token(request: &Request) -> Option<String> {
    let path = request.uri().path();
    if path != "/wiretap/stream" && path != "/api/v1/wiretap/stream" {
        return None;
    }
    let query = request.uri().query()?;
    let parsed: WiretapStreamAuthQuery = serde_urlencoded::from_str(query).ok()?;
    let token = parsed.access_token?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

async fn validate_service_account_claims(
    state: &ApiState,
    claims: &api_auth::JwtClaims,
    sa_id: &str,
    now: OffsetDateTime,
) -> Result<(), String> {
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

#[derive(Debug, Clone, Copy)]
enum AuthFailureReason {
    MissingToken,
    InvalidScheme,
    InvalidToken,
    KeysetError,
    ValidToken,
}

impl AuthFailureReason {
    fn as_label(self) -> &'static str {
        match self {
            AuthFailureReason::MissingToken => "missing_token",
            AuthFailureReason::InvalidScheme => "invalid_scheme",
            AuthFailureReason::InvalidToken => "invalid_token",
            AuthFailureReason::KeysetError => "keyset_error",
            AuthFailureReason::ValidToken => "valid_token",
        }
    }

    fn message(self) -> String {
        match self {
            AuthFailureReason::MissingToken => "missing bearer token".to_string(),
            AuthFailureReason::InvalidScheme => "invalid authorization scheme".to_string(),
            AuthFailureReason::InvalidToken => "invalid bearer token".to_string(),
            AuthFailureReason::KeysetError => "missing api auth keyset".to_string(),
            AuthFailureReason::ValidToken => "ok".to_string(),
        }
    }
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

enum LeaderState {
    Leader,
    Follower(SocketAddr),
    Unknown,
}

enum ProxyFailure {
    Upstream(String),
    Response(Response),
}

async fn leader_state(cluster: &HttpApiCluster, http_port: u16) -> LeaderState {
    let metrics = cluster.raft.metrics().borrow().clone();
    let Some(leader) = metrics.current_leader else {
        return LeaderState::Unknown;
    };
    if leader == metrics.id {
        return LeaderState::Leader;
    }
    let node = metrics
        .membership_config
        .membership()
        .nodes()
        .find_map(|(id, node)| {
            if *id == leader {
                Some(node.clone())
            } else {
                None
            }
        });
    let Some(node) = node else {
        return LeaderState::Unknown;
    };
    let Ok(raft_addr) = node.addr.parse::<SocketAddr>() else {
        return LeaderState::Unknown;
    };
    LeaderState::Follower(SocketAddr::new(raft_addr.ip(), http_port))
}

async fn proxy_request(
    state: &ApiState,
    leader_addr: SocketAddr,
    request: Request,
) -> Result<Response, ProxyFailure> {
    let client = state
        .proxy_client
        .as_ref()
        .ok_or_else(|| ProxyFailure::Upstream("proxy client missing".to_string()))?;

    let path = if let Some(original) = request.extensions().get::<OriginalUri>() {
        original
            .0
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(original.0.path())
    } else {
        request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(request.uri().path())
    };
    let url = format!("https://{leader_addr}{path}");

    let mut builder = client.request(request.method().clone(), url);
    for (name, value) in request.headers().iter() {
        if should_proxy_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return Err(ProxyFailure::Response(resp)),
    };
    let resp = builder
        .body(body)
        .send()
        .await
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .bytes()
        .await
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))?;

    let mut response = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if should_proxy_header(key.as_str()) {
            response = response.header(key, value);
        }
    }

    response
        .body(Body::from(bytes))
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))
}

async fn proxy_stream_request(
    state: &ApiState,
    leader_addr: SocketAddr,
    headers: &HeaderMap,
    path: &str,
) -> Result<Response, String> {
    let client = state
        .proxy_client
        .as_ref()
        .ok_or_else(|| "proxy client missing".to_string())?;
    let url = format!("https://{leader_addr}{path}");

    let mut builder = client.get(url);
    for (name, value) in headers.iter() {
        if should_proxy_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let resp = builder.send().await.map_err(|err| err.to_string())?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let stream = resp.bytes_stream().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("proxy stream error: {err}"),
        )
    });

    let mut response = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if should_proxy_header(key.as_str()) {
            response = response.header(key, value);
        }
    }

    response
        .body(Body::from_stream(stream))
        .map_err(|err| err.to_string())
}

fn should_proxy_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "connection"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;
    use std::net::TcpListener;
    use std::time::Duration;

    use crate::dataplane::policy::DefaultPolicy;
    use axum::http::{header::AUTHORIZATION, HeaderValue};
    use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
    use tempfile::TempDir;
    use tower::ServiceExt;

    #[tokio::test]
    async fn proxy_stream_forwards_auth_header() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = TempDir::new().unwrap();
        let cert_path = dir.path().join("node.crt");
        let key_path = dir.path().join("node.key");

        let mut ca_params = CertificateParams::new(Vec::new());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = Certificate::from_params(ca_params).unwrap();
        let ca_pem = ca_cert.serialize_pem().unwrap();

        let mut leaf_params = CertificateParams::new(Vec::new());
        leaf_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let leaf_cert = Certificate::from_params(leaf_params).unwrap();
        let leaf_pem = leaf_cert.serialize_pem_with_signer(&ca_cert).unwrap();
        let leaf_key = leaf_cert.serialize_private_key_pem();

        std::fs::write(&cert_path, leaf_pem).unwrap();
        std::fs::write(&key_path, leaf_key).unwrap();

        let listener =
            TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let app = Router::new().route(
            "/api/v1/wiretap/stream",
            get(|headers: HeaderMap| async move {
                match headers.get(AUTHORIZATION) {
                    Some(value) if value == "Bearer testtoken" => Response::builder()
                        .status(StatusCode::OK)
                        .body(Body::from("ok"))
                        .unwrap(),
                    _ => Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from("unauthorized"))
                        .unwrap(),
                }
            }),
        );

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .ok();
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(ca)
            .build()
            .unwrap();

        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let local_store = PolicyDiskStore::new(dir.path().join("policies"));
        let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
        let metrics = Metrics::new().unwrap();
        let state = ApiState {
            policy_store,
            local_store,
            service_accounts,
            cluster: None,
            metrics,
            proxy_client: Some(client),
            http_port: addr.port(),
            auth_source: ApiAuthSource::Local(dir.path().join("auth.json")),
            wiretap_hub: None,
            cluster_tls_dir: None,
            dns_map: None,
            readiness: None,
        };

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer testtoken"));
        let response = proxy_stream_request(&state, addr, &headers, "/api/v1/wiretap/stream")
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(body, "ok");

        server.abort();
    }

    #[tokio::test]
    async fn auth_metrics_record_failures() {
        let dir = TempDir::new().unwrap();
        let tls_dir = dir.path().join("http-tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        api_auth::ensure_local_keyset(&tls_dir).unwrap();
        let keyset_path = api_auth::local_keyset_path(&tls_dir);
        let keyset = api_auth::load_keyset_from_file(&keyset_path)
            .unwrap()
            .expect("missing keyset");
        let token = api_auth::mint_token(&keyset, "auth-test", None, None).unwrap();

        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let local_store = PolicyDiskStore::new(dir.path().join("policies"));
        let service_accounts = ServiceAccountStore::local(dir.path().join("service-accounts"));
        let metrics = Metrics::new().unwrap();
        let state = ApiState {
            policy_store,
            local_store,
            service_accounts,
            cluster: None,
            metrics: metrics.clone(),
            proxy_client: None,
            http_port: 0,
            auth_source: ApiAuthSource::Local(keyset_path.clone()),
            wiretap_hub: None,
            cluster_tls_dir: None,
            dns_map: None,
            readiness: None,
        };

        let app = Router::new()
            .route("/api/v1/policies", get(|| async { StatusCode::OK }))
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            ));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies")
                    .header(AUTHORIZATION, "Basic test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies")
                    .header(AUTHORIZATION, "Bearer invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies")
                    .header(AUTHORIZATION, format!("Bearer {}", token.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let missing_keyset_state = ApiState {
            auth_source: ApiAuthSource::Local(dir.path().join("missing.json")),
            ..state
        };
        let missing_app = Router::new()
            .route("/api/v1/policies", get(|| async { StatusCode::OK }))
            .with_state(missing_keyset_state.clone())
            .layer(axum::middleware::from_fn_with_state(
                missing_keyset_state,
                auth_middleware,
            ));
        let resp = missing_app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/policies")
                    .header(AUTHORIZATION, "Bearer test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"missing_token\"}"));
        assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"invalid_scheme\"}"));
        assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"invalid_token\"}"));
        assert!(rendered.contains("http_auth_total{outcome=\"deny\",reason=\"keyset_error\"}"));
        assert!(rendered.contains("http_auth_total{outcome=\"allow\",reason=\"valid_token\"}"));
    }
}

async fn track_metrics(
    State(state): State<ApiState>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    state
        .metrics
        .observe_http(&path, &method, status, start.elapsed());
    response
}

async fn metrics_handler(State(metrics): State<Metrics>) -> Response {
    match metrics.render() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Body::from(body))
            .unwrap(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

fn spawn_raft_metrics_sampler(metrics: Metrics, raft: openraft::Raft<ClusterTypeConfig>) {
    tokio::spawn(async move {
        let mut watch = raft.metrics();
        let mut initialized = false;
        let mut last_leader = None;
        loop {
            let snapshot = watch.borrow().clone();
            let is_leader = snapshot.current_leader == Some(snapshot.id);
            metrics.set_raft_is_leader(is_leader);
            metrics.set_raft_current_term(snapshot.current_term);
            metrics.set_raft_last_log_index(snapshot.last_log_index);
            metrics.set_raft_last_applied(snapshot.last_applied.as_ref().map(|id| id.index));

            if initialized {
                if last_leader != snapshot.current_leader {
                    metrics.inc_raft_leader_changes();
                    last_leader = snapshot.current_leader;
                }
            } else {
                last_leader = snapshot.current_leader;
                initialized = true;
            }

            if watch.changed().await.is_err() {
                break;
            }
        }
    });
}

fn spawn_rocksdb_metrics_sampler(metrics: Metrics, store: ClusterStore) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            if let Some(value) = store.property_int_value("rocksdb.estimate-num-keys") {
                metrics.set_rocksdb_estimated_num_keys(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.live-sst-files-size") {
                metrics.set_rocksdb_live_sst_files_size_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.total-sst-files-size") {
                metrics.set_rocksdb_total_sst_files_size_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.cur-size-all-mem-tables") {
                metrics.set_rocksdb_memtable_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.num-running-compactions") {
                metrics.set_rocksdb_num_running_compactions(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.num-immutable-mem-table") {
                metrics.set_rocksdb_num_immutable_memtables(value);
            }
        }
    });
}

async fn persist_cluster_policy(
    cluster: &HttpApiCluster,
    record: &PolicyRecord,
) -> Result<(), String> {
    let record_bytes = serde_json::to_vec(record).map_err(|err| err.to_string())?;
    let item_key = policy_item_key(record.id);
    let cmd = ClusterCommand::Put {
        key: item_key,
        value: record_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let mut index = read_cluster_index(&cluster.store)?;
    let meta = PolicyMeta::from(record);
    if let Some(existing) = index.policies.iter_mut().find(|item| item.id == meta.id) {
        *existing = meta;
    } else {
        index.policies.push(meta);
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
    let cmd = ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    if record.mode == PolicyMode::Enforce {
        let active = PolicyActive { id: record.id };
        let active_bytes = serde_json::to_vec(&active).map_err(|err| err.to_string())?;
        let cmd = ClusterCommand::Put {
            key: POLICY_ACTIVE_KEY.to_vec(),
            value: active_bytes,
        };
        cluster
            .raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
    }

    Ok(())
}

async fn delete_cluster_policy(cluster: &HttpApiCluster, id: Uuid) -> Result<(), String> {
    let cmd = ClusterCommand::Delete {
        key: policy_item_key(id),
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let mut index = read_cluster_index(&cluster.store)?;
    index.policies.retain(|meta| meta.id != id);
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
        if active.id == id {
            let cmd = ClusterCommand::Delete {
                key: POLICY_ACTIVE_KEY.to_vec(),
            };
            cluster
                .raft
                .client_write(cmd)
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    Ok(())
}

fn read_cluster_index(store: &ClusterStore) -> Result<PolicyIndex, String> {
    let raw = store.get_state_value(POLICY_INDEX_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
        None => Ok(PolicyIndex::default()),
    }
}

fn read_cluster_active(store: &ClusterStore) -> Result<Option<PolicyActive>, String> {
    let raw = store.get_state_value(POLICY_ACTIVE_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(value)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, format!("invalid {field}")))
}

fn error_response(status: StatusCode, message: String) -> Response {
    let body = Json(json!({ "error": message }));
    (status, body).into_response()
}

async fn read_body_limited(body: Body) -> Result<Bytes, Response> {
    match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body too large: {err}"),
        )),
    }
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
