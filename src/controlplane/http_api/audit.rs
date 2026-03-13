use super::*;

pub(super) async fn audit_findings(
    State(state): State<ApiState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let perf_enabled = match super::performance_mode::performance_mode_enabled(&state) {
        Ok(enabled) => enabled,
        Err(response) => return response,
    };
    if !perf_enabled {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "performance mode is disabled; audit is unavailable".to_string(),
        );
    }
    if state.cluster.is_none() {
        return audit_findings_local_response(&state, &query);
    }
    audit_findings_leader_response(&state, query, &headers).await
}

pub(super) async fn audit_findings_local(
    State(state): State<ApiState>,
    Query(query): Query<AuditQuery>,
    _request: Request,
) -> Response {
    let perf_enabled = match super::performance_mode::performance_mode_enabled(&state) {
        Ok(enabled) => enabled,
        Err(response) => return response,
    };
    if !perf_enabled {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "performance mode is disabled; audit is unavailable".to_string(),
        );
    }
    // Intentionally bypass leader proxying so cluster leaders can fan out to
    // every node and aggregate local audit stores.
    audit_findings_local_response(&state, &query)
}

fn audit_findings_local_response(state: &ApiState, query: &AuditQuery) -> Response {
    let Some(audit_store) = &state.audit_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "audit store unavailable".to_string(),
        );
    };
    let items = match audit_store.query(query) {
        Ok(items) => items,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    Json(AuditQueryResponse {
        items,
        partial: false,
        node_errors: Vec::new(),
        nodes_queried: 1,
        nodes_responded: 1,
    })
    .into_response()
}

async fn audit_findings_leader_response(
    state: &ApiState,
    query: AuditQuery,
    headers: &HeaderMap,
) -> Response {
    let local_items = match &state.audit_store {
        Some(store) => match store.query(&query) {
            Ok(items) => items,
            Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
        },
        None => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "audit store unavailable".to_string(),
            );
        }
    };

    let Some(cluster) = &state.cluster else {
        return Json(AuditQueryResponse {
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
    let query_string = match encode_audit_query(&query) {
        Ok(value) => value,
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("audit query encode failed: {err}"),
            );
        }
    };

    let mut sources: Vec<Vec<AuditFinding>> = vec![local_items];
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
                node_errors.push(crate::controlplane::audit::NodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid cluster node addr: {err}"),
                });
                continue;
            }
        };
        let peer_http_addr = SocketAddr::new(addr.ip(), state.http_port);
        let path = if query_string.is_empty() {
            format!("https://{peer_http_addr}/api/v1/audit/findings/local")
        } else {
            format!("https://{peer_http_addr}/api/v1/audit/findings/local?{query_string}")
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
                node_errors.push(crate::controlplane::audit::NodeQueryError {
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
            node_errors.push(crate::controlplane::audit::NodeQueryError {
                node_id: node_id.to_string(),
                error: format!("status {status}: {body}"),
            });
            continue;
        }
        let payload: AuditQueryResponse = match response.json().await {
            Ok(payload) => payload,
            Err(err) => {
                node_errors.push(crate::controlplane::audit::NodeQueryError {
                    node_id: node_id.to_string(),
                    error: format!("invalid response payload: {err}"),
                });
                continue;
            }
        };
        sources.push(payload.items);
        nodes_responded = nodes_responded.saturating_add(1);
    }

    let mut items = AuditStore::merge_findings(sources);
    let limit = query.limit.unwrap_or(500).clamp(1, 10_000);
    items.truncate(limit);

    Json(AuditQueryResponse {
        items,
        partial: !node_errors.is_empty(),
        node_errors,
        nodes_queried,
        nodes_responded,
    })
    .into_response()
}

fn encode_audit_query(query: &AuditQuery) -> Result<String, String> {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(policy_id) = &query.policy_id {
        if !policy_id.trim().is_empty() {
            params.push(("policy_id".to_string(), policy_id.clone()));
        }
    }
    for finding_type in &query.finding_type {
        params.push(("finding_type".to_string(), finding_type.clone()));
    }
    for source_group in &query.source_group {
        params.push(("source_group".to_string(), source_group.clone()));
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
