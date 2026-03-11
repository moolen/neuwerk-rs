use super::*;

use crate::controlplane::sso::{SsoProvider, SsoProviderKind, SsoProviderView, SsoRole};

#[derive(Debug, Deserialize)]
struct SsoProviderUpsertRequest {
    name: String,
    kind: SsoProviderKind,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    display_order: Option<i32>,
    #[serde(default)]
    issuer_url: Option<String>,
    #[serde(default)]
    authorization_url: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    userinfo_url: Option<String>,
    client_id: String,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    pkce_required: Option<bool>,
    #[serde(default)]
    subject_claim: Option<String>,
    #[serde(default)]
    email_claim: Option<String>,
    #[serde(default)]
    groups_claim: Option<String>,
    #[serde(default)]
    default_role: Option<SsoRole>,
    #[serde(default)]
    admin_subjects: Option<Vec<String>>,
    #[serde(default)]
    admin_groups: Option<Vec<String>>,
    #[serde(default)]
    admin_email_domains: Option<Vec<String>>,
    #[serde(default)]
    readonly_subjects: Option<Vec<String>>,
    #[serde(default)]
    readonly_groups: Option<Vec<String>>,
    #[serde(default)]
    readonly_email_domains: Option<Vec<String>>,
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
    #[serde(default)]
    session_ttl_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SsoProviderPatchRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    display_order: Option<i32>,
    #[serde(default)]
    issuer_url: Option<String>,
    #[serde(default)]
    authorization_url: Option<String>,
    #[serde(default)]
    token_url: Option<String>,
    #[serde(default)]
    userinfo_url: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    pkce_required: Option<bool>,
    #[serde(default)]
    subject_claim: Option<String>,
    #[serde(default)]
    email_claim: Option<String>,
    #[serde(default)]
    groups_claim: Option<String>,
    #[serde(default)]
    default_role: Option<SsoRole>,
    #[serde(default)]
    admin_subjects: Option<Vec<String>>,
    #[serde(default)]
    admin_groups: Option<Vec<String>>,
    #[serde(default)]
    admin_email_domains: Option<Vec<String>>,
    #[serde(default)]
    readonly_subjects: Option<Vec<String>>,
    #[serde(default)]
    readonly_groups: Option<Vec<String>>,
    #[serde(default)]
    readonly_email_domains: Option<Vec<String>>,
    #[serde(default)]
    allowed_email_domains: Option<Vec<String>>,
    #[serde(default)]
    session_ttl_secs: Option<u64>,
}

pub(super) async fn list_sso_providers(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state.sso.list_providers().await {
        Ok(providers) => {
            let views: Vec<SsoProviderView> = providers.iter().map(SsoProviderView::from).collect();
            Json(views).into_response()
        }
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn get_sso_provider(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.sso.get_provider(provider_id).await {
        Ok(Some(provider)) => Json(SsoProviderView::from(&provider)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "sso provider not found".to_string()),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn create_sso_provider(
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
    let create: SsoProviderUpsertRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    let secret = match create.client_secret.clone().and_then(trimmed_opt) {
        Some(secret) => secret,
        None => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "client_secret is required".to_string(),
            )
        }
    };

    let mut provider = match SsoProvider::new(
        create.name.trim().to_string(),
        create.kind,
        create.client_id.trim().to_string(),
        secret,
    ) {
        Ok(provider) => provider,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    apply_upsert_fields(&mut provider, create);

    if let Err(err) = provider.validate() {
        return error_response(StatusCode::BAD_REQUEST, err);
    }

    match state.sso.write_provider(&provider).await {
        Ok(()) => Json(SsoProviderView::from(&provider)).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn update_sso_provider(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let mut provider = match state.sso.get_provider(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "sso provider not found".to_string())
        }
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let patch: SsoProviderPatchRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    apply_patch_fields(&mut provider, patch);

    if let Err(err) = provider.touch_updated_at() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
    }

    if let Err(err) = provider.validate() {
        return error_response(StatusCode::BAD_REQUEST, err);
    }

    match state.sso.write_provider(&provider).await {
        Ok(()) => Json(SsoProviderView::from(&provider)).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn delete_sso_provider(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    match state.sso.delete_provider(provider_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

#[derive(Debug, Serialize)]
struct SsoProviderTestResult {
    ok: bool,
    details: String,
}

pub(super) async fn test_sso_provider(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let provider_id = match parse_uuid(&id, "provider id") {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let provider = match state.sso.get_provider(provider_id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return error_response(StatusCode::NOT_FOUND, "sso provider not found".to_string())
        }
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let endpoints = match provider.endpoints_or_default() {
        Ok(endpoints) => endpoints,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| err.to_string());
    let client = match client {
        Ok(client) => client,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let resp = client.get(&endpoints.authorization_url).send().await;
    match resp {
        Ok(resp) if resp.status().is_success() || resp.status().is_redirection() => {
            Json(SsoProviderTestResult {
                ok: true,
                details: "provider authorization endpoint reachable".to_string(),
            })
            .into_response()
        }
        Ok(resp) => Json(SsoProviderTestResult {
            ok: false,
            details: format!("authorization endpoint returned {}", resp.status()),
        })
        .into_response(),
        Err(err) => Json(SsoProviderTestResult {
            ok: false,
            details: format!("provider request failed: {err}"),
        })
        .into_response(),
    }
}

fn apply_upsert_fields(provider: &mut SsoProvider, req: SsoProviderUpsertRequest) {
    provider.enabled = req.enabled.unwrap_or(provider.enabled);
    provider.display_order = req.display_order.unwrap_or(provider.display_order);
    provider.issuer_url = req.issuer_url.and_then(trimmed_opt);
    provider.authorization_url = req.authorization_url.and_then(trimmed_opt);
    provider.token_url = req.token_url.and_then(trimmed_opt);
    provider.userinfo_url = req.userinfo_url.and_then(trimmed_opt);
    provider.scopes = normalize_list(req.scopes.unwrap_or_else(|| provider.scopes.clone()));
    provider.pkce_required = req.pkce_required.unwrap_or(provider.pkce_required);
    provider.subject_claim = req
        .subject_claim
        .and_then(trimmed_opt)
        .unwrap_or_else(|| provider.subject_claim.clone());
    provider.email_claim = req.email_claim.and_then(trimmed_opt);
    provider.groups_claim = req.groups_claim.and_then(trimmed_opt);
    provider.default_role = req.default_role.or(provider.default_role);
    provider.admin_subjects = normalize_list(
        req.admin_subjects
            .unwrap_or_else(|| provider.admin_subjects.clone()),
    );
    provider.admin_groups = normalize_list(
        req.admin_groups
            .unwrap_or_else(|| provider.admin_groups.clone()),
    );
    provider.admin_email_domains = normalize_list(
        req.admin_email_domains
            .unwrap_or_else(|| provider.admin_email_domains.clone()),
    );
    provider.readonly_subjects = normalize_list(
        req.readonly_subjects
            .unwrap_or_else(|| provider.readonly_subjects.clone()),
    );
    provider.readonly_groups = normalize_list(
        req.readonly_groups
            .unwrap_or_else(|| provider.readonly_groups.clone()),
    );
    provider.readonly_email_domains = normalize_list(
        req.readonly_email_domains
            .unwrap_or_else(|| provider.readonly_email_domains.clone()),
    );
    provider.allowed_email_domains = normalize_list(
        req.allowed_email_domains
            .unwrap_or_else(|| provider.allowed_email_domains.clone()),
    );
    provider.session_ttl_secs = req.session_ttl_secs.unwrap_or(provider.session_ttl_secs);
}

fn apply_patch_fields(provider: &mut SsoProvider, patch: SsoProviderPatchRequest) {
    if let Some(name) = patch.name.and_then(trimmed_opt) {
        provider.name = name;
    }
    if let Some(enabled) = patch.enabled {
        provider.enabled = enabled;
    }
    if let Some(order) = patch.display_order {
        provider.display_order = order;
    }
    if let Some(issuer_url) = patch.issuer_url {
        provider.issuer_url = trimmed_opt(issuer_url);
    }
    if let Some(authorization_url) = patch.authorization_url {
        provider.authorization_url = trimmed_opt(authorization_url);
    }
    if let Some(token_url) = patch.token_url {
        provider.token_url = trimmed_opt(token_url);
    }
    if let Some(userinfo_url) = patch.userinfo_url {
        provider.userinfo_url = trimmed_opt(userinfo_url);
    }
    if let Some(client_id) = patch.client_id.and_then(trimmed_opt) {
        provider.client_id = client_id;
    }
    if let Some(client_secret) = patch.client_secret.and_then(trimmed_opt) {
        provider.client_secret = client_secret;
    }
    if let Some(scopes) = patch.scopes {
        provider.scopes = normalize_list(scopes);
    }
    if let Some(pkce_required) = patch.pkce_required {
        provider.pkce_required = pkce_required;
    }
    if let Some(subject_claim) = patch.subject_claim.and_then(trimmed_opt) {
        provider.subject_claim = subject_claim;
    }
    if let Some(email_claim) = patch.email_claim {
        provider.email_claim = trimmed_opt(email_claim);
    }
    if let Some(groups_claim) = patch.groups_claim {
        provider.groups_claim = trimmed_opt(groups_claim);
    }
    if let Some(default_role) = patch.default_role {
        provider.default_role = Some(default_role);
    }
    if let Some(values) = patch.admin_subjects {
        provider.admin_subjects = normalize_list(values);
    }
    if let Some(values) = patch.admin_groups {
        provider.admin_groups = normalize_list(values);
    }
    if let Some(values) = patch.admin_email_domains {
        provider.admin_email_domains = normalize_list(values);
    }
    if let Some(values) = patch.readonly_subjects {
        provider.readonly_subjects = normalize_list(values);
    }
    if let Some(values) = patch.readonly_groups {
        provider.readonly_groups = normalize_list(values);
    }
    if let Some(values) = patch.readonly_email_domains {
        provider.readonly_email_domains = normalize_list(values);
    }
    if let Some(values) = patch.allowed_email_domains {
        provider.allowed_email_domains = normalize_list(values);
    }
    if let Some(ttl) = patch.session_ttl_secs {
        provider.session_ttl_secs = ttl;
    }
}

fn normalize_list(values: Vec<String>) -> Vec<String> {
    values.into_iter().filter_map(trimmed_opt).collect()
}

fn trimmed_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
