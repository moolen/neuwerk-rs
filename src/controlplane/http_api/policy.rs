use std::collections::BTreeSet;

use super::*;
use crate::controlplane::policy_repository::sanitize_policy_name;
use crate::dataplane::policy::EnforcementMode;

#[derive(Debug, Deserialize)]
struct PolicyUpsertRequest {
    mode: crate::controlplane::policy_config::PolicyMode,
    policy: crate::controlplane::policy_config::PolicyConfig,
    #[serde(default)]
    name: Option<String>,
}

pub(super) async fn list_policies(State(state): State<ApiState>, request: Request) -> Response {
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
pub(super) struct PolicyFormatQuery {
    format: Option<String>,
}

pub(super) async fn get_policy(
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

pub(super) async fn create_policy(State(state): State<ApiState>, mut request: Request) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let create: PolicyUpsertRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    if let Err(err) = validate_policy_integration_refs(&create.policy, &state.integrations).await {
        return error_response(StatusCode::BAD_REQUEST, err);
    }

    let compiled = match create.policy.clone().compile() {
        Ok(compiled) => compiled,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    let record = match PolicyRecord::new(create.mode, create.policy, create.name) {
        Ok(record) => record,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    if let Err(err) = state.local_store.write_record(&record) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    if record.mode.is_active() {
        let generation = match state.policy_store.rebuild_with_kubernetes_bindings(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode_for_policy_mode(record.mode),
            compiled.kubernetes_bindings,
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
        if !record.mode.is_active() {
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

async fn validate_policy_integration_refs(
    policy: &crate::controlplane::policy_config::PolicyConfig,
    integrations: &IntegrationStore,
) -> Result<(), String> {
    let mut references = BTreeSet::new();
    for group in &policy.source_groups {
        for source in &group.sources.kubernetes {
            let name = source.integration.trim();
            if !name.is_empty() {
                references.insert(name.to_string());
            }
        }
    }
    for name in references {
        let exists = integrations
            .get_by_name_kind(&name, IntegrationKind::Kubernetes)
            .await?
            .is_some();
        if !exists {
            return Err(format!("unknown kubernetes integration: {name}"));
        }
    }
    Ok(())
}

pub(super) async fn update_policy(
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
    let update: PolicyUpsertRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    if let Err(err) = validate_policy_integration_refs(&update.policy, &state.integrations).await {
        return error_response(StatusCode::BAD_REQUEST, err);
    }
    let compiled = match update.policy.clone().compile() {
        Ok(compiled) => compiled,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    record.mode = update.mode;
    record.name = sanitize_policy_name(update.name);
    record.policy = update.policy;

    if let Err(err) = state.local_store.write_record(&record) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }

    if record.mode.is_active() {
        let generation = match state.policy_store.rebuild_with_kubernetes_bindings(
            compiled.groups,
            compiled.dns_policy,
            compiled.default_policy,
            enforcement_mode_for_policy_mode(record.mode),
            compiled.kubernetes_bindings,
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
                EnforcementMode::Enforce,
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

pub(super) async fn delete_policy(
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
                EnforcementMode::Enforce,
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
