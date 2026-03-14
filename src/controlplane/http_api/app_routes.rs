use axum::body::Body;
use axum::extract::{OriginalUri, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use include_dir::{include_dir, Dir};
use mime_guess::MimeGuess;
use serde_json::json;
use utoipa::ToSchema;

use crate::controlplane::metrics::{ClusterNodeCatchup, StatsSnapshot};
use crate::controlplane::wiretap::DnsCacheEntry;

use super::{error_response, maybe_proxy, ApiState, HttpApiCluster};

static UI_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/ui/dist");

#[derive(Debug, serde::Serialize, ToSchema)]
struct DnsCacheResponse {
    entries: Vec<DnsCacheEntry>,
}

pub(super) async fn health_handler() -> Response {
    Json(json!({ "status": "ok" })).into_response()
}

pub(super) async fn ready_handler(State(state): State<ApiState>) -> Response {
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

pub(super) async fn ui_handler(method: Method, OriginalUri(uri): OriginalUri) -> Response {
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
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_str(mime.as_ref())
            .unwrap_or_else(|_| axum::http::HeaderValue::from_static("application/octet-stream")),
    );
    resp
}

#[utoipa::path(
    get,
    path = "/api/v1/dns-cache",
    tag = "Diagnostics",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Grouped DNS cache entries", body = DnsCacheResponse),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 503, description = "DNS cache unavailable", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn list_dns_cache(State(state): State<ApiState>, request: Request) -> Response {
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
    Json(DnsCacheResponse { entries }).into_response()
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "Diagnostics",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Runtime statistics snapshot", body = StatsSnapshot),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn stats_handler(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let mut snapshot: StatsSnapshot = state.metrics.snapshot();
    if let Some(cluster) = &state.cluster {
        enrich_cluster_stats(&mut snapshot, cluster);
    }
    Json(snapshot).into_response()
}

fn enrich_cluster_stats(snapshot: &mut StatsSnapshot, cluster: &HttpApiCluster) {
    let raft_metrics = cluster.raft.metrics().borrow().clone();
    let leader_last_log_index = raft_metrics.last_log_index.unwrap_or(0);
    let replication = raft_metrics.replication.clone();
    let mut follower_count = 0u64;
    let mut followers_caught_up = 0u64;
    let mut nodes = Vec::new();

    for (node_id, node) in raft_metrics.membership_config.membership().nodes() {
        let is_leader = *node_id == raft_metrics.id;
        let (matched_index, lag_entries, caught_up) = if is_leader {
            (Some(leader_last_log_index), Some(0), true)
        } else {
            follower_count += 1;
            let matched = replication
                .as_ref()
                .and_then(|states| states.get(node_id))
                .and_then(|log_id| log_id.as_ref().map(|log_id| log_id.index));
            let lag = matched.map(|idx| leader_last_log_index.saturating_sub(idx));
            let is_caught_up = lag == Some(0);
            if is_caught_up {
                followers_caught_up += 1;
            }
            (matched, lag, is_caught_up)
        };

        nodes.push(ClusterNodeCatchup {
            node_id: node_id.to_string(),
            addr: node.addr.clone(),
            role: if is_leader {
                "leader".to_string()
            } else {
                "follower".to_string()
            },
            matched_index,
            lag_entries,
            caught_up,
        });
    }

    nodes.sort_by(|a, b| {
        (a.role != "leader", a.node_id.as_str()).cmp(&(b.role != "leader", b.node_id.as_str()))
    });

    snapshot.cluster.node_count = nodes.len() as u64;
    snapshot.cluster.follower_count = follower_count;
    snapshot.cluster.followers_caught_up = followers_caught_up;
    snapshot.cluster.nodes = nodes;
}
