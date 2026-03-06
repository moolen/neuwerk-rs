use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::Ordering;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::controlplane::cluster::bootstrap::ca::{encrypt_ca_key, CaSigner};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::types::ClusterCommand;
use crate::controlplane::intercept_tls::{
    load_local_intercept_ca_pair, local_intercept_ca_paths, INTERCEPT_CA_CERT_KEY,
    INTERCEPT_CA_ENVELOPE_KEY,
};

use super::{error_response, maybe_proxy, read_body_limited, sha256_hex, ApiState};

#[derive(Debug, Serialize)]
struct TlsInterceptCaStatus {
    configured: bool,
    source: Option<String>,
    fingerprint_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TlsInterceptCaUpdateRequest {
    ca_cert_pem: String,
    #[serde(default)]
    ca_key_pem: Option<String>,
    #[serde(default)]
    ca_key_der_b64: Option<String>,
}

pub(super) async fn get_tls_intercept_ca(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let (source, cert) = match load_tls_intercept_ca_cert_material(&state) {
        Ok(material) => material,
        Err(response) => return response,
    };

    let fingerprint_sha256 = cert.map(|cert| sha256_hex(&cert));
    Json(TlsInterceptCaStatus {
        configured: fingerprint_sha256.is_some(),
        source,
        fingerprint_sha256,
    })
    .into_response()
}

pub(super) async fn get_tls_intercept_ca_cert(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let (_source, cert) = match load_tls_intercept_ca_cert_material(&state) {
        Ok(material) => material,
        Err(response) => return response,
    };
    let Some(cert) = cert else {
        return error_response(
            StatusCode::NOT_FOUND,
            "tls intercept ca is not configured".to_string(),
        );
    };

    let mut response = Response::new(Body::from(cert));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-pem-file"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"neuwerk-dpi-root-ca.crt\""),
    );
    response
}

pub(super) async fn put_tls_intercept_ca(
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
    let update: TlsInterceptCaUpdateRequest = match serde_json::from_slice(&body) {
        Ok(update) => update,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let cert_pem = update.ca_cert_pem.trim().as_bytes().to_vec();
    if cert_pem.is_empty() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ca_cert_pem is required".to_string(),
        );
    }
    let key_der = match parse_tls_intercept_ca_key_der(&update) {
        Ok(key) => key,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err),
    };
    if let Err(err) = CaSigner::from_cert_and_key(&cert_pem, &key_der) {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid tls intercept ca cert/key pair: {err}"),
        );
    }

    match persist_tls_intercept_ca_material(&state, cert_pem, key_der).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(super) async fn generate_tls_intercept_ca(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let (cert_pem, key_der) = match generate_tls_intercept_ca_material() {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    match persist_tls_intercept_ca_material(&state, cert_pem, key_der).await {
        Ok(status) => Json(status).into_response(),
        Err(response) => response,
    }
}

pub(super) async fn delete_tls_intercept_ca(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    if let Some(cluster) = &state.cluster {
        let cmd = ClusterCommand::Delete {
            key: INTERCEPT_CA_CERT_KEY.to_vec(),
        };
        if let Err(err) = cluster.raft.client_write(cmd).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
        let cmd = ClusterCommand::Delete {
            key: INTERCEPT_CA_ENVELOPE_KEY.to_vec(),
        };
        if let Err(err) = cluster.raft.client_write(cmd).await {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    } else {
        let (cert_path, key_path) = local_intercept_ca_paths(&state.tls_dir);
        if let Err(err) = fs::remove_file(&cert_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
        if let Err(err) = fs::remove_file(&key_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
            }
        }
    }

    if let Some(ready) = &state.tls_intercept_ca_ready {
        ready.store(false, Ordering::Release);
    }
    if let Some(generation) = &state.tls_intercept_ca_generation {
        generation.fetch_add(1, Ordering::AcqRel);
    }

    Json(TlsInterceptCaStatus {
        configured: false,
        source: None,
        fingerprint_sha256: None,
    })
    .into_response()
}

fn parse_tls_intercept_ca_key_der(update: &TlsInterceptCaUpdateRequest) -> Result<Vec<u8>, String> {
    match (
        update.ca_key_pem.as_deref(),
        update.ca_key_der_b64.as_deref(),
    ) {
        (Some(_), Some(_)) => {
            Err("provide either ca_key_pem or ca_key_der_b64, not both".to_string())
        }
        (Some(key_pem), None) => {
            let mut reader = std::io::BufReader::new(key_pem.as_bytes());
            let key = rustls_pemfile::private_key(&mut reader)
                .map_err(|err| format!("parse ca_key_pem failed: {err}"))?
                .ok_or_else(|| "ca_key_pem does not contain a private key".to_string())?;
            Ok(key.secret_der().to_vec())
        }
        (None, Some(key_der_b64)) => BASE64_STANDARD
            .decode(key_der_b64)
            .map_err(|err| format!("invalid ca_key_der_b64: {err}")),
        (None, None) => Err("ca_key_pem or ca_key_der_b64 is required".to_string()),
    }
}

fn generate_tls_intercept_ca_material() -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Neuwerk DPI Root CA");
    let cert = Certificate::from_params(params).map_err(|err| err.to_string())?;
    let signer = CaSigner::new(cert).map_err(|err| err.to_string())?;
    Ok((signer.cert_pem().to_vec(), signer.key_der().to_vec()))
}

fn load_tls_intercept_ca_cert_material(
    state: &ApiState,
) -> Result<(Option<String>, Option<Vec<u8>>), Response> {
    if let Some(cluster) = &state.cluster {
        let cert = cluster
            .store
            .get_state_value(INTERCEPT_CA_CERT_KEY)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        let envelope = cluster
            .store
            .get_state_value(INTERCEPT_CA_ENVELOPE_KEY)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err))?;
        return match (cert, envelope) {
            (None, None) => Ok((None, None)),
            (Some(cert), Some(_)) => Ok((Some("cluster".to_string()), Some(cert))),
            _ => Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tls intercept ca material is incomplete".to_string(),
            )),
        };
    }

    match load_local_intercept_ca_pair(&state.tls_dir) {
        Ok(Some((cert, _key))) => Ok((Some("local".to_string()), Some(cert))),
        Ok(None) => Ok((None, None)),
        Err(err) => Err(error_response(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

async fn persist_tls_intercept_ca_material(
    state: &ApiState,
    cert_pem: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<TlsInterceptCaStatus, Response> {
    if let Some(cluster) = &state.cluster {
        let token_store = TokenStore::load(&state.token_path)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let token = token_store
            .current(OffsetDateTime::now_utc())
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let envelope = encrypt_ca_key(&token.kid, &token.token, &key_der)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let encoded = bincode::serialize(&envelope)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let cert_cmd = ClusterCommand::Put {
            key: INTERCEPT_CA_CERT_KEY.to_vec(),
            value: cert_pem.clone(),
        };
        cluster
            .raft
            .client_write(cert_cmd)
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        let envelope_cmd = ClusterCommand::Put {
            key: INTERCEPT_CA_ENVELOPE_KEY.to_vec(),
            value: encoded,
        };
        cluster
            .raft
            .client_write(envelope_cmd)
            .await
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    } else {
        let (cert_path, key_path) = local_intercept_ca_paths(&state.tls_dir);
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            })?;
        }
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            })?;
        }
        fs::write(&cert_path, &cert_pem)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        fs::write(&key_path, &key_der)
            .map_err(|err| error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644));
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }
    }

    if let Some(ready) = &state.tls_intercept_ca_ready {
        ready.store(true, Ordering::Release);
    }
    if let Some(generation) = &state.tls_intercept_ca_generation {
        generation.fetch_add(1, Ordering::AcqRel);
    }

    Ok(TlsInterceptCaStatus {
        configured: true,
        source: if state.cluster.is_some() {
            Some("cluster".to_string())
        } else {
            Some("local".to_string())
        },
        fingerprint_sha256: Some(sha256_hex(&cert_pem)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_tls_intercept_ca_material_builds_valid_ca_pair() {
        let (cert_pem, key_der) = generate_tls_intercept_ca_material().unwrap();
        assert!(!cert_pem.is_empty());
        assert!(!key_der.is_empty());
        let cert_text = std::str::from_utf8(&cert_pem).unwrap();
        assert!(cert_text.contains("BEGIN CERTIFICATE"));
        let signer = CaSigner::from_cert_and_key(&cert_pem, &key_der).unwrap();
        assert!(!signer.cert_pem().is_empty());
    }
}
