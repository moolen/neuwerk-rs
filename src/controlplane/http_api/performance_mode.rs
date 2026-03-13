use std::fs;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::controlplane::cluster::types::ClusterCommand;

use super::{
    error_response, local_controlplane_data_root, maybe_proxy, read_body_limited, ApiState,
};

const PERFORMANCE_MODE_ENABLED_KEY: &[u8] = b"settings/performance_mode/enabled";
const PERFORMANCE_MODE_DEFAULT_ENABLED: bool = true;

#[derive(Debug, Serialize)]
pub(super) struct PerformanceModeStatus {
    pub enabled: bool,
    pub source: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PerformanceModeUpdateRequest {
    enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct PerformanceModeDisk {
    enabled: bool,
}

pub(super) async fn get_performance_mode(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    match load_performance_mode_status(&state) {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(super) async fn put_performance_mode(
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
    let update: PerformanceModeUpdateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    match persist_performance_mode_status(&state, update.enabled).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(super) fn performance_mode_enabled(state: &ApiState) -> Result<bool, Response> {
    Ok(load_performance_mode_status(state)?.enabled)
}

fn local_performance_mode_path(state: &ApiState) -> std::path::PathBuf {
    local_controlplane_data_root(&state.local_store)
        .join("settings")
        .join("performance-mode.json")
}

fn load_performance_mode_status(state: &ApiState) -> Result<PerformanceModeStatus, Response> {
    if let Some(cluster) = &state.cluster {
        let value = cluster
            .store
            .get_state_value(PERFORMANCE_MODE_ENABLED_KEY)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        let Some(value) = value else {
            return Ok(PerformanceModeStatus {
                enabled: PERFORMANCE_MODE_DEFAULT_ENABLED,
                source: None,
            });
        };
        let enabled = parse_enabled_value(&value).map_err(|err| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid performance mode value in cluster store: {err}"),
            )
        })?;
        return Ok(PerformanceModeStatus {
            enabled,
            source: Some("cluster".to_string()),
        });
    }

    let path = local_performance_mode_path(state);
    if !path.exists() {
        return Ok(PerformanceModeStatus {
            enabled: PERFORMANCE_MODE_DEFAULT_ENABLED,
            source: None,
        });
    }
    let bytes = fs::read(&path).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read performance mode: {err}"),
        )
    })?;
    let enabled = parse_enabled_value(&bytes).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("invalid performance mode value in local store: {err}"),
        )
    })?;
    Ok(PerformanceModeStatus {
        enabled,
        source: Some("local".to_string()),
    })
}

async fn persist_performance_mode_status(
    state: &ApiState,
    enabled: bool,
) -> Result<PerformanceModeStatus, Response> {
    if let Some(cluster) = &state.cluster {
        cluster
            .raft
            .client_write(ClusterCommand::Put {
                key: PERFORMANCE_MODE_ENABLED_KEY.to_vec(),
                value: encode_enabled_value(enabled),
            })
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        return Ok(PerformanceModeStatus {
            enabled,
            source: Some("cluster".to_string()),
        });
    }

    let path = local_performance_mode_path(state);
    let payload = serde_json::to_vec(&PerformanceModeDisk { enabled }).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialize performance mode: {err}"),
        )
    })?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("prepare performance mode directory: {err}"),
            )
        })?;
    }
    fs::write(&path, payload).map_err(|err| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("write performance mode: {err}"),
        )
    })?;
    Ok(PerformanceModeStatus {
        enabled,
        source: Some("local".to_string()),
    })
}

fn encode_enabled_value(enabled: bool) -> Vec<u8> {
    if enabled {
        b"1".to_vec()
    } else {
        b"0".to_vec()
    }
}

fn parse_enabled_value(raw: &[u8]) -> Result<bool, String> {
    if raw == b"1" {
        return Ok(true);
    }
    if raw == b"0" {
        return Ok(false);
    }

    let text = std::str::from_utf8(raw)
        .map_err(|err| format!("value is not utf-8: {err}"))?
        .trim();
    if text.eq_ignore_ascii_case("true") {
        return Ok(true);
    }
    if text.eq_ignore_ascii_case("false") {
        return Ok(false);
    }
    if let Ok(enabled) = serde_json::from_str::<bool>(text) {
        return Ok(enabled);
    }
    if let Ok(disk) = serde_json::from_str::<PerformanceModeDisk>(text) {
        return Ok(disk.enabled);
    }
    Err("expected one of: 1, 0, true, false, or {\"enabled\": <bool>}".to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_enabled_value;

    #[test]
    fn parse_enabled_value_accepts_bool_forms() {
        assert_eq!(parse_enabled_value(b"1").unwrap(), true);
        assert_eq!(parse_enabled_value(b"0").unwrap(), false);
        assert_eq!(parse_enabled_value(b"true").unwrap(), true);
        assert_eq!(parse_enabled_value(b"false").unwrap(), false);
        assert_eq!(parse_enabled_value(br#"{"enabled":true}"#).unwrap(), true);
        assert_eq!(parse_enabled_value(br#"{"enabled":false}"#).unwrap(), false);
    }

    #[test]
    fn parse_enabled_value_rejects_unknown_value() {
        assert!(parse_enabled_value(b"maybe").is_err());
    }
}
