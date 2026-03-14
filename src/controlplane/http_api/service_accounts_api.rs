use super::*;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
struct ServiceAccountCreateRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
    role: ServiceAccountRole,
}

#[derive(Debug, Deserialize, ToSchema)]
struct ServiceAccountUpdateRequest {
    name: String,
    #[serde(default)]
    description: Option<String>,
    role: ServiceAccountRole,
}

#[derive(Debug, Deserialize, ToSchema)]
struct ServiceAccountTokenCreateRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ttl: Option<String>,
    #[serde(default)]
    eternal: Option<bool>,
    #[serde(default)]
    role: Option<ServiceAccountRole>,
}

#[derive(Debug, Serialize, ToSchema)]
struct ServiceAccountTokenResponse {
    token: String,
    token_meta: TokenMeta,
}

#[utoipa::path(
    get,
    path = "/api/v1/service-accounts",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Service accounts", body = [crate::controlplane::service_accounts::ServiceAccount]),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn list_service_accounts(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state.service_accounts.list_accounts().await {
        Ok(accounts) => Json(accounts).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/service-accounts",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = ServiceAccountCreateRequest,
    responses(
        (status = 200, description = "Created service account", body = crate::controlplane::service_accounts::ServiceAccount),
        (status = 400, description = "Invalid request", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn create_service_account(
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
    let description = create
        .description
        .and_then(|desc| sanitize_optional_field(desc));
    let created_by = auth.claims.sub.clone();
    match state
        .service_accounts
        .create_account_with_role(name.to_string(), description, created_by, create.role)
        .await
    {
        Ok(account) => Json(account).into_response(),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/service-accounts/{id}",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Service account UUID")
    ),
    request_body = ServiceAccountUpdateRequest,
    responses(
        (status = 200, description = "Updated service account", body = crate::controlplane::service_accounts::ServiceAccount),
        (status = 400, description = "Invalid request", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 404, description = "Service account not found", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn update_service_account(
    State(state): State<ApiState>,
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
    let mut account = match state.service_accounts.get_account(account_id).await {
        Ok(Some(account)) => account,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "service account not found".to_string(),
            );
        }
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let update: ServiceAccountUpdateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let name = update.name.trim();
    if name.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "name is required".to_string());
    }
    account.name = name.to_string();
    account.description = update.description.and_then(sanitize_optional_field);
    account.role = update.role;
    if let Err(err) = state.service_accounts.update_account(&account).await {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, err);
    }
    Json(account).into_response()
}

#[utoipa::path(
    delete,
    path = "/api/v1/service-accounts/{id}",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Service account UUID")
    ),
    responses(
        (status = 204, description = "Disabled service account and revoked tokens"),
        (status = 400, description = "Invalid service account id", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 404, description = "Service account not found", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn delete_service_account(
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
            );
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

#[utoipa::path(
    get,
    path = "/api/v1/service-accounts/{id}/tokens",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Service account UUID")
    ),
    responses(
        (status = 200, description = "Service account token metadata", body = [crate::controlplane::service_accounts::TokenMeta]),
        (status = 400, description = "Invalid service account id", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn list_service_account_tokens(
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

#[utoipa::path(
    post,
    path = "/api/v1/service-accounts/{id}/tokens",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Service account UUID")
    ),
    request_body = ServiceAccountTokenCreateRequest,
    responses(
        (status = 200, description = "Minted service account token", body = ServiceAccountTokenResponse),
        (status = 400, description = "Invalid token request", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 404, description = "Service account not found", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn create_service_account_token(
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
            );
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
    let requested_role = create.role.unwrap_or(account.role);
    if !account.role.allows(requested_role) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "token role exceeds account role".to_string(),
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
        Some(vec![requested_role.as_str().to_string()]),
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
            );
        }
    };
    let expires_at = match minted.exp {
        Some(exp) => match OffsetDateTime::from_unix_timestamp(exp) {
            Ok(dt) => Some(dt.format(&Rfc3339).unwrap_or_else(|_| exp.to_string())),
            Err(_) => None,
        },
        None => None,
    };
    let token_meta = match TokenMeta::new_with_role(
        account_id,
        create.name.and_then(sanitize_optional_field),
        auth.claims.sub.clone(),
        minted.kid.clone(),
        expires_at,
        token_id,
        requested_role,
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

#[utoipa::path(
    delete,
    path = "/api/v1/service-accounts/{id}/tokens/{token_id}",
    tag = "Service Accounts",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    params(
        ("id" = String, Path, description = "Service account UUID"),
        ("token_id" = String, Path, description = "Token UUID")
    ),
    responses(
        (status = 204, description = "Revoked token"),
        (status = 400, description = "Invalid account or token id", body = super::openapi::ErrorBody),
        (status = 401, description = "Missing or invalid token", body = super::openapi::ErrorBody),
        (status = 403, description = "Admin role required", body = super::openapi::ErrorBody),
        (status = 404, description = "Token not found", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn revoke_service_account_token(
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

fn sanitize_optional_field(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
