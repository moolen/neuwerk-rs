use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::*;
use crate::controlplane::policy_config::{CompiledPolicy, PolicyConfig, PolicyMode};
use crate::dataplane::policy::EnforcementMode;

struct LeaderLocalPolicyApplyGuard(Option<Arc<AtomicU64>>);

impl LeaderLocalPolicyApplyGuard {
    fn begin(counter: Option<&Arc<AtomicU64>>) -> Self {
        if let Some(counter) = counter {
            counter.fetch_add(1, Ordering::AcqRel);
            return Self(Some(counter.clone()));
        }
        Self(None)
    }
}

impl Drop for LeaderLocalPolicyApplyGuard {
    fn drop(&mut self) {
        if let Some(counter) = &self.0 {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PolicyFormatQuery {
    format: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/policy",
    tag = "Policies",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("format" = Option<String>, Query, description = "Use `yaml` to return application/yaml")
    ),
    responses(
        (status = 200, description = "Policy document", body = crate::controlplane::policy_config::PolicyConfig),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn get_policy_singleton(
    State(state): State<ApiState>,
    Query(query): Query<PolicyFormatQuery>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    match state.local_store.load_or_bootstrap_singleton() {
        Ok(state) => policy_response(state.policy, query),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/policy",
    tag = "Policies",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = crate::controlplane::policy_config::PolicyConfig,
    responses(
        (status = 200, description = "Updated policy document", body = crate::controlplane::policy_config::PolicyConfig),
        (status = 400, description = "Invalid request or policy compile failure", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 503, description = "Activation wait failed or leader unknown", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn put_policy_singleton(
    State(state): State<ApiState>,
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
    let (policy, compiled) = match parse_policy_request(&state, &body).await {
        Ok(payload) => payload,
        Err(resp) => return resp,
    };
    let mut record = match state.local_store.load_or_bootstrap_singleton() {
        Ok(state) => state.record(),
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    record.mode = PolicyMode::Enforce;
    record.name = None;
    record.policy = policy.clone();

    if let Err(resp) = write_policy_and_apply(&state, &record, compiled).await {
        return resp;
    }

    Json(policy).into_response()
}

pub(super) async fn legacy_policy_route_gone() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

fn policy_response(policy: PolicyConfig, query: PolicyFormatQuery) -> Response {
    let wants_yaml = query
        .format
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("yaml"))
        .unwrap_or(false);
    if wants_yaml {
        let yaml = match serde_yaml::to_string(&policy) {
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
    Json(policy).into_response()
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

async fn parse_policy_request(
    state: &ApiState,
    body: &[u8],
) -> Result<(PolicyConfig, CompiledPolicy), Response> {
    let policy: PolicyConfig = serde_json::from_slice(body)
        .map_err(|err| error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")))?;
    validate_policy_integration_refs(&policy, &state.integrations)
        .await
        .map_err(|err| error_response(StatusCode::BAD_REQUEST, err))?;
    let compiled = policy
        .clone()
        .compile()
        .map_err(|err| error_response(StatusCode::BAD_REQUEST, err))?;
    Ok((policy, compiled))
}

async fn write_policy_and_apply(
    state: &ApiState,
    record: &PolicyRecord,
    compiled: CompiledPolicy,
) -> Result<(), Response> {
    let _leader_local_policy_apply_guard =
        LeaderLocalPolicyApplyGuard::begin(state.leader_local_policy_apply_count.as_ref());
    if let Err(err) = state.local_store.write_record(record) {
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            err.to_string(),
        ));
    }

    if record.mode.is_active() {
        let generation = state
            .policy_store
            .rebuild_with_kubernetes_bindings(
                compiled.groups,
                compiled.dns_policy,
                compiled.default_policy,
                enforcement_mode_for_policy_mode(record.mode),
                compiled.kubernetes_bindings,
            )
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        state.policy_store.set_active_policy_id(Some(record.id));
        if let Err(err) = state.local_store.set_active(Some(record.id)) {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            ));
        }
        wait_for_policy_activation(&state.policy_store, state.readiness.as_ref(), generation)
            .await
            .map_err(|err| error_response(StatusCode::SERVICE_UNAVAILABLE, err))?;
    } else {
        if let Err(err) = state.local_store.set_active(None) {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                err.to_string(),
            ));
        }
        let generation = state
            .policy_store
            .rebuild(
                Vec::new(),
                crate::controlplane::policy_config::DnsPolicy::new(Vec::new()),
                None,
                EnforcementMode::Enforce,
            )
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        state.policy_store.set_active_policy_id(None);
        wait_for_policy_activation(&state.policy_store, state.readiness.as_ref(), generation)
            .await
            .map_err(|err| error_response(StatusCode::SERVICE_UNAVAILABLE, err))?;
    }

    if let Some(cluster) = &state.cluster {
        persist_cluster_policy(cluster, record)
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    }

    Ok(())
}
