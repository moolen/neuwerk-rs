use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::Response;
use futures::TryStreamExt;

use super::{error_response, read_body_limited, ApiState, HttpApiCluster};

pub(super) enum LeaderState {
    Leader,
    Follower(SocketAddr),
    Unknown,
}

enum ProxyFailure {
    Upstream(String),
    Response(Response),
}

pub(super) async fn maybe_proxy(state: &ApiState, request: Request) -> Result<Request, Response> {
    let Some(cluster) = &state.cluster else {
        return Ok(request);
    };
    match leader_state(cluster, state.http_port).await {
        LeaderState::Leader => Ok(request),
        LeaderState::Unknown => Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "leader unknown".to_string(),
        )),
        LeaderState::Follower(addr) => Err(match proxy_request(state, addr, request).await {
            Ok(response) => response,
            Err(ProxyFailure::Response(resp)) => resp,
            Err(ProxyFailure::Upstream(err)) => error_response(StatusCode::BAD_GATEWAY, err),
        }),
    }
}

pub(super) async fn leader_state(cluster: &HttpApiCluster, http_port: u16) -> LeaderState {
    let metrics = cluster.raft.metrics().borrow().clone();
    let Some(leader) = metrics.current_leader else {
        return LeaderState::Unknown;
    };
    if leader == metrics.id {
        return LeaderState::Leader;
    }
    let node = metrics
        .membership_config
        .membership()
        .nodes()
        .find_map(|(id, node)| {
            if *id == leader {
                Some(node.clone())
            } else {
                None
            }
        });
    let Some(node) = node else {
        return LeaderState::Unknown;
    };
    let Ok(raft_addr) = node.addr.parse::<SocketAddr>() else {
        return LeaderState::Unknown;
    };
    LeaderState::Follower(SocketAddr::new(raft_addr.ip(), http_port))
}

async fn proxy_request(
    state: &ApiState,
    leader_addr: SocketAddr,
    request: Request,
) -> Result<Response, ProxyFailure> {
    let client = state
        .proxy_client
        .as_ref()
        .ok_or_else(|| ProxyFailure::Upstream("proxy client missing".to_string()))?;

    let path = if let Some(original) = request.extensions().get::<OriginalUri>() {
        original
            .0
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(original.0.path())
    } else {
        request
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or(request.uri().path())
    };
    let url = format!("https://{leader_addr}{path}");

    let mut builder = client.request(request.method().clone(), url);
    for (name, value) in request.headers() {
        if should_proxy_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return Err(ProxyFailure::Response(resp)),
    };
    let resp = builder
        .body(body)
        .send()
        .await
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp
        .bytes()
        .await
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))?;

    let mut response = Response::builder().status(status);
    for (key, value) in &headers {
        if should_proxy_header(key.as_str()) {
            response = response.header(key, value);
        }
    }

    response
        .body(Body::from(bytes))
        .map_err(|err| ProxyFailure::Upstream(err.to_string()))
}

pub(super) async fn proxy_stream_request(
    state: &ApiState,
    leader_addr: SocketAddr,
    headers: &HeaderMap,
    path: &str,
) -> Result<Response, String> {
    let client = state
        .proxy_client
        .as_ref()
        .ok_or_else(|| "proxy client missing".to_string())?;
    let url = format!("https://{leader_addr}{path}");

    let mut builder = client.get(url);
    for (name, value) in headers {
        if should_proxy_header(name.as_str()) {
            builder = builder.header(name, value);
        }
    }

    let resp = builder.send().await.map_err(|err| err.to_string())?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let stream = resp
        .bytes_stream()
        .map_err(|err| std::io::Error::other(format!("proxy stream error: {err}")));

    let mut response = Response::builder().status(status);
    for (key, value) in &headers {
        if should_proxy_header(key.as_str()) {
            response = response.header(key, value);
        }
    }

    response
        .body(Body::from_stream(stream))
        .map_err(|err| err.to_string())
}

pub(super) fn should_proxy_header(name: &str) -> bool {
    !matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
