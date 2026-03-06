use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, Request, State};
#[cfg(test)]
use axum::http::header::CONTENT_TYPE;
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::HeaderMap;
#[cfg(test)]
use axum::http::Method;
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use axum_server::Server;
use futures::stream::SelectAll;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::controlplane::api_auth::{self, ApiKeySet};
use crate::controlplane::audit::{AuditFinding, AuditQuery, AuditQueryResponse, AuditStore};
use crate::controlplane::cluster::rpc::{RaftTlsConfig, WiretapClient};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use crate::controlplane::http_tls::{ensure_http_tls, HttpTlsConfig};
use crate::controlplane::integrations::{IntegrationKind, IntegrationStore, IntegrationView};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyActive, PolicyDiskStore, PolicyIndex, PolicyMeta,
    PolicyRecord, POLICY_ACTIVE_KEY, POLICY_INDEX_KEY,
};
use crate::controlplane::ready::ReadinessState;
use crate::controlplane::service_accounts::{
    parse_ttl_secs, ServiceAccountStatus, ServiceAccountStore, TokenMeta, TokenStatus,
};
use crate::controlplane::wiretap::{DnsMap, WiretapFilter, WiretapHub, WiretapQuery};
use crate::controlplane::PolicyStore;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const ALLOW_PUBLIC_METRICS_BIND_ENV: &str = "NEUWERK_ALLOW_PUBLIC_METRICS_BIND";
const AUTH_COOKIE_NAME: &str = "neuwerk_auth";
const AUTH_LOGIN_WINDOW: Duration = Duration::from_secs(60);
const AUTH_LOGIN_BLOCK: Duration = Duration::from_secs(120);
const AUTH_LOGIN_MAX_FAILURES: usize = 20;
const AUTH_LOGIN_MAX_BUCKETS: usize = 4096;
const AUTH_LOGIN_MAX_TOKEN_LEN: usize = 8192;

mod app_routes;
mod audit;
mod auth;
mod auth_routes;
mod cluster_persistence;
mod extractors;
mod integrations;
mod metrics;
mod policy;
mod policy_activation;
mod proxy;
mod security;
mod service_accounts_api;
mod tls_intercept;
mod wiretap;

use app_routes::{health_handler, list_dns_cache, ready_handler, stats_handler, ui_handler};
use audit::{audit_findings, audit_findings_local};
use auth_routes::{auth_logout, auth_token_login, auth_whoami};
use cluster_persistence::{delete_cluster_policy, persist_cluster_policy, read_cluster_active};
use extractors::{error_response, parse_uuid, read_body_limited};
use integrations::{
    create_integration, delete_integration, get_integration, list_integrations, update_integration,
};
use policy::{create_policy, delete_policy, get_policy, list_policies, update_policy};
use policy_activation::{enforcement_mode_for_policy_mode, wait_for_policy_activation};
use service_accounts_api::{
    create_service_account, create_service_account_token, delete_service_account,
    list_service_account_tokens, list_service_accounts, revoke_service_account_token,
};
use wiretap::wiretap_stream;

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
    pub tls_intercept_ca_ready: Option<Arc<AtomicBool>>,
    pub tls_intercept_ca_generation: Option<Arc<AtomicU64>>,
}

#[derive(Clone)]
struct ApiState {
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    service_accounts: ServiceAccountStore,
    integrations: IntegrationStore,
    audit_store: Option<AuditStore>,
    cluster: Option<HttpApiCluster>,
    metrics: Metrics,
    proxy_client: Option<reqwest::Client>,
    http_port: u16,
    auth_source: ApiAuthSource,
    auth_login_limiter: Arc<Mutex<auth::AuthLoginLimiter>>,
    wiretap_hub: Option<WiretapHub>,
    cluster_tls_dir: Option<PathBuf>,
    tls_dir: PathBuf,
    token_path: PathBuf,
    tls_intercept_ca_ready: Option<Arc<AtomicBool>>,
    tls_intercept_ca_generation: Option<Arc<AtomicU64>>,
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

pub async fn run_http_api(
    cfg: HttpApiConfig,
    policy_store: PolicyStore,
    local_store: PolicyDiskStore,
    cluster: Option<HttpApiCluster>,
    audit_store: Option<AuditStore>,
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
    if metrics_bind_requires_guardrail(cfg.metrics_bind) && !allow_public_metrics_bind_override() {
        return Err(format!(
            "metrics bind {} appears public; set {}=1 to override",
            cfg.metrics_bind, ALLOW_PUBLIC_METRICS_BIND_ENV
        ));
    }
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
        let mut builder = reqwest::Client::builder().pool_max_idle_per_host(0);
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
    let local_data_root = local_controlplane_data_root(&local_store);
    let service_accounts = match &cluster {
        Some(cluster) => ServiceAccountStore::cluster(cluster.raft.clone(), cluster.store.clone()),
        None => ServiceAccountStore::local(local_data_root.join("service-accounts")),
    };
    let integrations = match &cluster {
        Some(cluster) => IntegrationStore::cluster(
            cluster.raft.clone(),
            cluster.store.clone(),
            cfg.token_path.clone(),
        ),
        None => IntegrationStore::local(local_data_root.join("integrations")),
    };
    let state = ApiState {
        policy_store,
        local_store,
        service_accounts,
        integrations,
        audit_store,
        cluster,
        metrics: metrics.clone(),
        proxy_client,
        http_port: cfg.bind_addr.port(),
        auth_source,
        auth_login_limiter: Arc::new(Mutex::new(auth::AuthLoginLimiter::default())),
        wiretap_hub,
        cluster_tls_dir: cfg.cluster_tls_dir.clone(),
        tls_dir: cfg.tls_dir.clone(),
        token_path: cfg.token_path.clone(),
        tls_intercept_ca_ready: cfg.tls_intercept_ca_ready.clone(),
        tls_intercept_ca_generation: cfg.tls_intercept_ca_generation.clone(),
        dns_map,
        readiness,
    };

    if let Some(cluster) = &state.cluster {
        metrics::spawn_raft_metrics_sampler(metrics.clone(), cluster.raft.clone());
        metrics::spawn_rocksdb_metrics_sampler(metrics.clone(), cluster.store.clone());
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
            "/integrations",
            get(list_integrations).post(create_integration),
        )
        .route(
            "/integrations/:name",
            get(get_integration)
                .put(update_integration)
                .delete(delete_integration),
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
        .route("/audit/findings", get(audit_findings))
        .route("/audit/findings/local", get(audit_findings_local))
        .route("/wiretap/stream", get(wiretap_stream))
        .route("/dns-cache", get(list_dns_cache))
        .route(
            "/settings/tls-intercept-ca",
            get(tls_intercept::get_tls_intercept_ca)
                .put(tls_intercept::put_tls_intercept_ca)
                .delete(tls_intercept::delete_tls_intercept_ca),
        )
        .route(
            "/settings/tls-intercept-ca/cert",
            get(tls_intercept::get_tls_intercept_ca_cert),
        )
        .route(
            "/settings/tls-intercept-ca/generate",
            post(tls_intercept::generate_tls_intercept_ca),
        )
        .route("/stats", get(stats_handler))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
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
            metrics::track_metrics,
        ))
        .layer(axum::middleware::from_fn(
            security::security_headers_middleware,
        ));

    let metrics_app = Router::new()
        .route("/metrics", get(metrics::metrics_handler))
        .with_state(metrics.clone());

    let metrics_bind = cfg.metrics_bind;
    tokio::spawn(async move {
        match Server::bind(metrics_bind)
            .serve(metrics_app.into_make_service_with_connect_info::<SocketAddr>())
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
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
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

fn local_controlplane_data_root(local_store: &PolicyDiskStore) -> PathBuf {
    let base_dir = local_store.base_dir();
    match base_dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => base_dir.to_path_buf(),
    }
}

fn metrics_bind_requires_guardrail(bind: SocketAddr) -> bool {
    match bind.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified())
        }
    }
}

fn allow_public_metrics_bind_override() -> bool {
    std::env::var(ALLOW_PUBLIC_METRICS_BIND_ENV)
        .map(|value| parse_truthy_env(&value))
        .unwrap_or(false)
}

fn parse_truthy_env(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn maybe_proxy(state: &ApiState, request: Request) -> Result<Request, Response> {
    proxy::maybe_proxy(state, request).await
}

#[cfg(test)]
mod tests;

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
