use super::*;

#[derive(Debug, Deserialize)]
struct IntegrationCreateRequest {
    name: String,
    kind: String,
    api_server_url: String,
    ca_cert_pem: String,
    service_account_token: String,
}

#[derive(Debug, Deserialize)]
struct IntegrationUpdateRequest {
    api_server_url: String,
    ca_cert_pem: String,
    service_account_token: String,
}

pub(super) async fn list_integrations(State(state): State<ApiState>, request: Request) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state.integrations.list_records().await {
        Ok(records) => {
            let views = records
                .iter()
                .map(IntegrationView::from)
                .collect::<Vec<_>>();
            Json(views).into_response()
        }
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn get_integration(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state
        .integrations
        .get_by_name_kind(&name, IntegrationKind::Kubernetes)
        .await
    {
        Ok(Some(record)) => Json(IntegrationView::from(&record)).into_response(),
        Ok(None) => error_response(StatusCode::NOT_FOUND, "integration not found".to_string()),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) async fn create_integration(
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
    let create: IntegrationCreateRequest = match serde_json::from_slice(&body) {
        Ok(create) => create,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    if !create.kind.eq_ignore_ascii_case("kubernetes") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "kind must be kubernetes".to_string(),
        );
    }
    match state
        .integrations
        .create_kubernetes(
            create.name,
            create.api_server_url,
            create.ca_cert_pem,
            create.service_account_token,
        )
        .await
    {
        Ok(record) => Json(IntegrationView::from(&record)).into_response(),
        Err(err) if err.contains("exists") => error_response(StatusCode::CONFLICT, err),
        Err(err) => error_response(StatusCode::BAD_REQUEST, err),
    }
}

pub(super) async fn update_integration(
    State(state): State<ApiState>,
    Path(name): Path<String>,
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
    let update: IntegrationUpdateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    match state
        .integrations
        .update_kubernetes(
            &name,
            update.api_server_url,
            update.ca_cert_pem,
            update.service_account_token,
        )
        .await
    {
        Ok(record) => Json(IntegrationView::from(&record)).into_response(),
        Err(err) if err.contains("not found") => error_response(StatusCode::NOT_FOUND, err),
        Err(err) => error_response(StatusCode::BAD_REQUEST, err),
    }
}

pub(super) async fn delete_integration(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match state
        .integrations
        .delete_by_name_kind(&name, IntegrationKind::Kubernetes)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "integration not found".to_string()),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}
