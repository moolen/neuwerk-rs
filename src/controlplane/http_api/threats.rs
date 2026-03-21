use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::controlplane::threat_intel::manager::{
    load_effective_feed_status, ThreatFeedIndicatorCounts, ThreatFeedRefreshState,
    ThreatFeedStatusItem,
};
use crate::controlplane::threat_intel::silences::{
    load_silences, persist_silences_cluster, persist_silences_local, ThreatSilenceEntry,
    ThreatSilenceKind, ThreatSilenceList,
};
use crate::controlplane::threat_intel::settings::{
    load_settings, persist_settings_cluster, persist_settings_local, ThreatIntelSettings,
};
use crate::controlplane::threat_intel::store::{
    ThreatFindingQuery, ThreatFindingQueryResponse, ThreatNodeQueryError, ThreatStore,
};
use crate::controlplane::threat_intel::types::ThreatSeverity;

use super::{
    error_response, local_controlplane_data_root, maybe_proxy, read_body_limited, ApiState,
};

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(super) struct ThreatIntelSettingsStatus {
    #[serde(flatten)]
    pub settings: ThreatIntelSettings,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ThreatIntelSettingsUpdateRequest {
    pub enabled: Option<bool>,
    pub alert_threshold: Option<ThreatSeverity>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ThreatSilenceCreateRequest {
    pub kind: ThreatSilenceKind,
    pub indicator_type: Option<crate::controlplane::threat_intel::types::ThreatIndicatorType>,
    pub value: String,
    pub reason: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/settings/threat-intel",
    tag = "Settings",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Threat intel settings", body = ThreatIntelSettingsStatus),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn get_threat_settings(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match load_threat_settings_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/settings/threat-intel",
    tag = "Settings",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = ThreatIntelSettingsUpdateRequest,
    responses(
        (status = 200, description = "Updated threat intel settings", body = ThreatIntelSettingsStatus),
        (status = 400, description = "Invalid request", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn put_threat_settings(
    State(state): State<ApiState>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let update: ThreatIntelSettingsUpdateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    let (mut settings, _) = match load_settings(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
    ) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    if let Some(enabled) = update.enabled {
        settings.enabled = enabled;
    }
    if let Some(alert_threshold) = update.alert_threshold {
        settings.alert_threshold = alert_threshold;
    }
    if let Err(err) = settings.validate() {
        return error_response(StatusCode::BAD_REQUEST, err);
    }

    match persist_threat_settings(&state, &settings).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/threats/silences",
    tag = "Threats",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Threat silences", body = ThreatSilenceList),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn list_threat_silences(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match load_threat_silences(&state) {
        Ok(silences) => Json(silences).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/threats/silences",
    tag = "Threats",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = ThreatSilenceCreateRequest,
    responses(
        (status = 200, description = "Created threat silence", body = ThreatSilenceEntry),
        (status = 400, description = "Invalid request", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn post_threat_silences(
    State(state): State<ApiState>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let create: ThreatSilenceCreateRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    let mut silences = match load_threat_silences(&state) {
        Ok(silences) => silences,
        Err(response) => return response,
    };
    let entry = ThreatSilenceEntry {
        id: Uuid::new_v4().to_string(),
        kind: create.kind,
        indicator_type: create.indicator_type,
        value: create.value,
        reason: create.reason,
        created_at: unix_now(),
        created_by: None,
    };
    let entry = match entry.normalized() {
        Ok(entry) => entry,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    silences.items.push(entry.clone());

    match persist_threat_silences(&state, &silences).await {
        Ok(()) => Json(entry).into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/threats/silences/{id}",
    tag = "Threats",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Threat silence identifier")
    ),
    responses(
        (status = 204, description = "Threat silence removed"),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 404, description = "Threat silence not found", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn delete_threat_silence(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let mut silences = match load_threat_silences(&state) {
        Ok(silences) => silences,
        Err(response) => return response,
    };
    let before = silences.items.len();
    silences.items.retain(|entry| entry.id != id);
    if silences.items.len() == before {
        return error_response(StatusCode::NOT_FOUND, "threat silence not found".to_string());
    }

    match persist_threat_silences(&state, &silences).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(response) => response,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/threats/findings",
    tag = "Threats",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(ThreatFindingQuery),
    responses(
        (status = 200, description = "Threat findings", body = ThreatFindingQueryResponse),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn threat_findings(
    State(state): State<ApiState>,
    Query(query): Query<ThreatFindingQuery>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let settings = match load_effective_threat_settings(&state) {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    if !settings.enabled {
        return Json(disabled_threat_findings_response()).into_response();
    }
    if state.cluster.is_none() {
        return threat_findings_local_response(&state, &query);
    }
    threat_findings_leader_response(&state, query, &headers).await
}

pub(super) async fn threat_findings_local(
    State(state): State<ApiState>,
    Query(query): Query<ThreatFindingQuery>,
    _request: Request,
) -> Response {
    let settings = match load_effective_threat_settings(&state) {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    if !settings.enabled {
        return Json(disabled_threat_findings_response()).into_response();
    }
    threat_findings_local_response(&state, &query)
}

#[utoipa::path(
    get,
    path = "/api/v1/threats/feeds/status",
    tag = "Threats",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Threat feed status", body = ThreatFeedRefreshState),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn threat_feed_status(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let (settings, _) = match load_settings(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
    ) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let status = match load_effective_feed_status(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
        &settings,
    ) {
        Ok(Some(status)) => status,
        Ok(None) => empty_feed_status(&settings),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let mut status = status;
    status.disabled = !settings.enabled;
    Json(status).into_response()
}

#[allow(clippy::result_large_err)]
fn load_threat_settings_status(state: &ApiState) -> Result<ThreatIntelSettingsStatus, Response> {
    let (settings, source) = load_settings_and_source(state)?;
    Ok(ThreatIntelSettingsStatus {
        settings,
        source: source.map(|source| source.as_str().to_string()),
    })
}

#[allow(clippy::result_large_err)]
fn load_effective_threat_settings(state: &ApiState) -> Result<ThreatIntelSettings, Response> {
    load_settings_and_source(state).map(|(settings, _)| settings)
}

#[allow(clippy::result_large_err)]
fn load_settings_and_source(
    state: &ApiState,
) -> Result<
    (
        ThreatIntelSettings,
        Option<crate::controlplane::threat_intel::settings::ThreatSettingsSource>,
    ),
    Response,
> {
    load_settings(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
    )
    .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))
}

#[allow(clippy::result_large_err)]
fn load_threat_silences(state: &ApiState) -> Result<ThreatSilenceList, Response> {
    load_silences(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
    )
    .map(|(silences, _)| silences)
    .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))
}

async fn persist_threat_settings(
    state: &ApiState,
    settings: &ThreatIntelSettings,
) -> Result<ThreatIntelSettingsStatus, Response> {
    if let Some(cluster) = &state.cluster {
        persist_settings_cluster(&cluster.raft, settings)
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        return Ok(ThreatIntelSettingsStatus {
            settings: settings.clone(),
            source: Some("cluster".to_string()),
        });
    }

    persist_settings_local(&local_controlplane_data_root(&state.local_store), settings)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(ThreatIntelSettingsStatus {
        settings: settings.clone(),
        source: Some("local".to_string()),
    })
}

async fn persist_threat_silences(
    state: &ApiState,
    silences: &ThreatSilenceList,
) -> Result<(), Response> {
    if let Some(cluster) = &state.cluster {
        persist_silences_cluster(&cluster.raft, silences)
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        return Ok(());
    }

    persist_silences_local(&local_controlplane_data_root(&state.local_store), silences)
        .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(())
}

fn threat_findings_local_response(state: &ApiState, query: &ThreatFindingQuery) -> Response {
    let Some(threat_store) = &state.threat_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "threat store unavailable".to_string(),
        );
    };
    let items = match threat_store.query(query) {
        Ok(items) => items,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    Json(ThreatFindingQueryResponse {
        items,
        partial: false,
        node_errors: Vec::new(),
        nodes_queried: 1,
        nodes_responded: 1,
        disabled: false,
    })
    .into_response()
}

fn empty_feed_status(settings: &ThreatIntelSettings) -> ThreatFeedRefreshState {
    ThreatFeedRefreshState {
        snapshot_version: 0,
        snapshot_generated_at: None,
        last_refresh_started_at: None,
        last_refresh_completed_at: None,
        last_successful_refresh_at: None,
        last_refresh_outcome: None,
        feeds: vec![
            ThreatFeedStatusItem {
                feed: "threatfox".to_string(),
                enabled: settings.baseline_feeds.threatfox.enabled,
                snapshot_age_seconds: None,
                last_refresh_started_at: None,
                last_refresh_completed_at: None,
                last_successful_refresh_at: None,
                last_refresh_outcome: None,
                indicator_counts: ThreatFeedIndicatorCounts::default(),
            },
            ThreatFeedStatusItem {
                feed: "urlhaus".to_string(),
                enabled: settings.baseline_feeds.urlhaus.enabled,
                snapshot_age_seconds: None,
                last_refresh_started_at: None,
                last_refresh_completed_at: None,
                last_successful_refresh_at: None,
                last_refresh_outcome: None,
                indicator_counts: ThreatFeedIndicatorCounts::default(),
            },
            ThreatFeedStatusItem {
                feed: "spamhaus_drop".to_string(),
                enabled: settings.baseline_feeds.spamhaus_drop.enabled,
                snapshot_age_seconds: None,
                last_refresh_started_at: None,
                last_refresh_completed_at: None,
                last_successful_refresh_at: None,
                last_refresh_outcome: None,
                indicator_counts: ThreatFeedIndicatorCounts::default(),
            },
        ],
        disabled: false,
    }
}

async fn threat_findings_leader_response(
    state: &ApiState,
    query: ThreatFindingQuery,
    headers: &HeaderMap,
) -> Response {
    let local_items = match &state.threat_store {
        Some(store) => match store.query(&query) {
            Ok(items) => items,
            Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
        },
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "threat store unavailable".to_string(),
            );
        }
    };

    let Some(cluster) = &state.cluster else {
        return Json(ThreatFindingQueryResponse {
            items: local_items,
            partial: false,
            node_errors: Vec::new(),
            nodes_queried: 1,
            nodes_responded: 1,
            disabled: false,
        })
        .into_response();
    };

    let client = match &state.proxy_client {
        Some(client) => client,
        None => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "proxy client missing".to_string(),
            );
        }
    };

    let metrics = cluster.raft.metrics().borrow().clone();
    let query_string = match encode_threat_query(&query) {
        Ok(value) => value,
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("threat query encode failed: {err}"),
            );
        }
    };

    let mut sources = vec![local_items];
    let mut node_errors = Vec::new();
    let mut nodes_queried = 1usize;
    let mut nodes_responded = 1usize;
    for (node_id, node) in metrics.membership_config.membership().nodes() {
        if *node_id == metrics.id {
            continue;
        }
        nodes_queried = nodes_queried.saturating_add(1);
        let addr = match node.addr.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(err) => {
                node_errors.push(ThreatNodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid cluster node addr: {err}"),
                });
                continue;
            }
        };
        let peer_http_addr = SocketAddr::new(addr.ip(), state.http_port);
        let path = if query_string.is_empty() {
            format!("https://{peer_http_addr}/api/v1/threats/findings/local")
        } else {
            format!("https://{peer_http_addr}/api/v1/threats/findings/local?{query_string}")
        };
        let mut req = client.get(path);
        if let Some(value) = headers.get(AUTHORIZATION) {
            req = req.header(AUTHORIZATION, value);
        }
        if let Some(value) = headers.get(COOKIE) {
            req = req.header(COOKIE, value);
        }

        let response = match req.send().await {
            Ok(response) => response,
            Err(err) => {
                node_errors.push(ThreatNodeQueryError {
                    node_id: node_id.to_string(),
                    error: err.to_string(),
                });
                continue;
            }
        };
        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read error body".to_string());
            node_errors.push(ThreatNodeQueryError {
                node_id: node_id.to_string(),
                error: format!("status {status}: {body}"),
            });
            continue;
        }
        let payload: ThreatFindingQueryResponse = match response.json().await {
            Ok(payload) => payload,
            Err(err) => {
                node_errors.push(ThreatNodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid response payload: {err}"),
                });
                continue;
            }
        };
        sources.push(payload.items);
        nodes_responded = nodes_responded.saturating_add(1);
    }

    let mut items = ThreatStore::merge_findings(sources);
    let limit = query.limit.unwrap_or(500).clamp(1, 10_000);
    items.truncate(limit);

    Json(ThreatFindingQueryResponse {
        items,
        partial: !node_errors.is_empty(),
        node_errors,
        nodes_queried,
        nodes_responded,
        disabled: false,
    })
    .into_response()
}

fn disabled_threat_findings_response() -> ThreatFindingQueryResponse {
    ThreatFindingQueryResponse {
        items: Vec::new(),
        partial: false,
        node_errors: Vec::new(),
        nodes_queried: 0,
        nodes_responded: 0,
        disabled: true,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn encode_threat_query(query: &ThreatFindingQuery) -> Result<String, String> {
    let mut params: Vec<(String, String)> = Vec::new();
    for indicator_type in &query.indicator_type {
        params.push(("indicator_type".to_string(), indicator_type.clone()));
    }
    for severity in &query.severity {
        params.push(("severity".to_string(), severity.clone()));
    }
    for source_group in &query.source_group {
        params.push(("source_group".to_string(), source_group.clone()));
    }
    for layer in &query.observation_layer {
        params.push(("observation_layer".to_string(), layer.clone()));
    }
    for feed in &query.feed {
        params.push(("feed".to_string(), feed.clone()));
    }
    for match_source in &query.match_source {
        params.push(("match_source".to_string(), match_source.clone()));
    }
    if let Some(alertable) = query.alertable_only {
        params.push(("alertable_only".to_string(), alertable.to_string()));
    }
    if let Some(since) = query.since {
        params.push(("since".to_string(), since.to_string()));
    }
    if let Some(until) = query.until {
        params.push(("until".to_string(), until.to_string()));
    }
    if let Some(limit) = query.limit {
        params.push(("limit".to_string(), limit.to_string()));
    }
    serde_urlencoded::to_string(params).map_err(|err| err.to_string())
}
