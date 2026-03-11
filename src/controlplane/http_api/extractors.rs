use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use uuid::Uuid;

use super::MAX_BODY_BYTES;

#[allow(clippy::result_large_err)]
pub(super) fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Response> {
    Uuid::parse_str(value)
        .map_err(|_| error_response(StatusCode::BAD_REQUEST, format!("invalid {field}")))
}

pub(super) fn error_response(status: StatusCode, message: String) -> Response {
    let body = Json(json!({ "error": message }));
    (status, body).into_response()
}

pub(super) async fn read_body_limited(body: Body) -> Result<Bytes, Response> {
    match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => Ok(bytes),
        Err(err) => Err(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("request body too large: {err}"),
        )),
    }
}
