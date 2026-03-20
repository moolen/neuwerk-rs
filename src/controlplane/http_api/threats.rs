use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::controlplane::threat_intel::settings::{
    load_settings, persist_settings_cluster, persist_settings_local, ThreatIntelSettings,
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

#[allow(clippy::result_large_err)]
fn load_threat_settings_status(state: &ApiState) -> Result<ThreatIntelSettingsStatus, Response> {
    let (settings, source) = load_settings(
        state.cluster.as_ref().map(|cluster| &cluster.store),
        &local_controlplane_data_root(&state.local_store),
    )
    .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
    Ok(ThreatIntelSettingsStatus {
        settings,
        source: source.map(|source| source.as_str().to_string()),
    })
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
