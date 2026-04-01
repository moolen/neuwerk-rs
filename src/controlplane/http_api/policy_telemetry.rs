use super::*;
use crate::controlplane::audit::NodeQueryError;
use crate::controlplane::policy_telemetry::PolicyTelemetryResponse;

pub(super) async fn policy_telemetry(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if state.cluster.is_none() {
        return policy_telemetry_local_response(&state);
    }
    policy_telemetry_leader_response(&state, &headers).await
}

pub(super) async fn policy_telemetry_local(
    State(state): State<ApiState>,
    _request: Request,
) -> Response {
    policy_telemetry_local_response(&state)
}

fn policy_telemetry_local_response(state: &ApiState) -> Response {
    let Some(store) = &state.policy_telemetry_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy telemetry unavailable".to_string(),
        );
    };

    let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
    let items = match store.singleton_24h_summary(now) {
        Ok(items) => items,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    Json(PolicyTelemetryResponse {
        items,
        partial: false,
        node_errors: Vec::new(),
        nodes_queried: 1,
        nodes_responded: 1,
    })
    .into_response()
}

async fn policy_telemetry_leader_response(state: &ApiState, headers: &HeaderMap) -> Response {
    let local_items = match &state.policy_telemetry_store {
        Some(store) => {
            let now = OffsetDateTime::now_utc().unix_timestamp().max(0) as u64;
            match store.singleton_24h_summary(now) {
                Ok(items) => items,
                Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
            }
        }
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "policy telemetry unavailable".to_string(),
            );
        }
    };

    let Some(cluster) = &state.cluster else {
        return Json(PolicyTelemetryResponse {
            items: local_items,
            partial: false,
            node_errors: Vec::new(),
            nodes_queried: 1,
            nodes_responded: 1,
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
                node_errors.push(NodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid cluster node addr: {err}"),
                });
                continue;
            }
        };
        let peer_http_addr = SocketAddr::new(addr.ip(), state.http_port);
        let path = format!("https://{peer_http_addr}/api/v1/policy/telemetry/local");

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
                node_errors.push(NodeQueryError {
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
            node_errors.push(NodeQueryError {
                node_id: node_id.to_string(),
                error: format!("status {status}: {body}"),
            });
            continue;
        }

        let payload: PolicyTelemetryResponse = match response.json().await {
            Ok(payload) => payload,
            Err(err) => {
                node_errors.push(NodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid response payload: {err}"),
                });
                continue;
            }
        };

        sources.push(payload.items);
        nodes_responded = nodes_responded.saturating_add(1);
    }

    Json(PolicyTelemetryResponse {
        items: crate::controlplane::policy_telemetry::PolicyTelemetryStore::merge_summaries(
            sources,
        ),
        partial: !node_errors.is_empty(),
        node_errors,
        nodes_queried,
        nodes_responded,
    })
    .into_response()
}
