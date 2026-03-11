use std::io::{Cursor, Read, Write};
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tar::{Archive, Builder, Header};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{error_response, maybe_proxy, ApiState, AUTHORIZATION, COOKIE};

const CLUSTER_SYSDUMP_FANOUT_HEADER: &str = "x-neuwerk-cluster-sysdump-fanout";

#[derive(Debug, Serialize)]
struct ClusterSysdumpOverview {
    generated_at: String,
    partial: bool,
    leader_node_id: String,
    node_count: usize,
    nodes_succeeded: usize,
    nodes_failed: usize,
    nodes: Vec<ClusterSysdumpNodeOverview>,
}

#[derive(Debug, Serialize)]
struct ClusterSysdumpNodeOverview {
    node_id: String,
    addr: String,
    role: String,
    status: String,
    error: Option<String>,
    state: Option<NodeStateSummary>,
}

#[derive(Debug, Serialize)]
struct ClusterSysdumpFailures {
    failures: Vec<ClusterSysdumpFailure>,
}

#[derive(Debug, Serialize)]
struct ClusterSysdumpFailure {
    node_id: String,
    addr: String,
    error: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct NodeStateSummary {
    generated_at: String,
    mode_guess: String,
    node_id: Option<String>,
    local_policy_count: usize,
    local_active_policy_id: Option<String>,
    cluster_policy_count: Option<usize>,
    cluster_active_policy_id: Option<String>,
    local_service_account_count: usize,
    local_token_count: usize,
    cluster_service_account_count: Option<usize>,
    cluster_token_count: Option<usize>,
    local_integration_count: usize,
    cluster_integration_count: Option<usize>,
    audit_finding_count: usize,
    cluster_present: bool,
    metrics_success_count: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct NodeClusterSummary {
    current_term: Option<u64>,
    voted_for: Option<String>,
    vote_committed: Option<bool>,
    last_log_index: Option<u64>,
    last_purged_index: Option<u64>,
    last_applied_index: Option<u64>,
    membership_log_index: Option<u64>,
    joint_configs: Vec<Vec<String>>,
    voter_count: usize,
    node_count: usize,
    nodes: Vec<NodeClusterMemberSummary>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct NodeClusterMemberSummary {
    node_id: String,
    addr: String,
    role: String,
    matched_index: Option<u64>,
    lag_entries: Option<u64>,
    caught_up: bool,
}

struct NodeSysdumpBundle {
    node_id: String,
    addr: String,
    role: String,
    archive: Vec<u8>,
    state: Option<NodeStateSummary>,
    cluster: Option<NodeClusterSummary>,
}

pub(super) async fn cluster_sysdump(
    State(state): State<ApiState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster sysdump requires cluster mode".to_string(),
        );
    };
    let Some(client) = &state.proxy_client else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "proxy client missing".to_string(),
        );
    };

    let metrics = cluster.raft.metrics().borrow().clone();
    let leader_node_id = metrics.id.to_string();
    let voter_ids = metrics
        .membership_config
        .membership()
        .voter_ids()
        .collect::<std::collections::BTreeSet<_>>();
    let now = OffsetDateTime::now_utc();

    let mut nodes = Vec::new();
    let mut failures = Vec::new();
    let mut leader_cluster_summary = None;

    for (node_id, node) in metrics.membership_config.membership().nodes() {
        let node_id_string = node_id.to_string();
        let role = if *node_id == metrics.id {
            "leader".to_string()
        } else if voter_ids.contains(node_id) {
            "follower".to_string()
        } else {
            "learner".to_string()
        };

        let bundle = if *node_id == metrics.id {
            match crate::support::sysdump::build_local_sysdump_archive().await {
                Ok(archive) => {
                    let state =
                        extract_sysdump_json::<NodeStateSummary>(&archive, "summary/state.json");
                    let cluster_summary = extract_sysdump_json::<NodeClusterSummary>(
                        &archive,
                        "summary/cluster.json",
                    );
                    Some(NodeSysdumpBundle {
                        node_id: node_id_string.clone(),
                        addr: node.addr.clone(),
                        role: role.clone(),
                        archive,
                        state,
                        cluster: cluster_summary,
                    })
                }
                Err(err) => {
                    failures.push(ClusterSysdumpFailure {
                        node_id: node_id_string.clone(),
                        addr: node.addr.clone(),
                        error: err,
                    });
                    None
                }
            }
        } else {
            match fetch_peer_sysdump(client, &headers, *node_id, &node.addr, state.http_port).await
            {
                Ok(bundle) => Some(NodeSysdumpBundle {
                    role: role.clone(),
                    ..bundle
                }),
                Err(err) => {
                    failures.push(ClusterSysdumpFailure {
                        node_id: node_id_string.clone(),
                        addr: node.addr.clone(),
                        error: err,
                    });
                    None
                }
            }
        };

        if let Some(bundle) = bundle {
            if bundle.role == "leader" {
                leader_cluster_summary = bundle.cluster.clone();
            }
            nodes.push(bundle);
        }
    }

    if nodes.is_empty() {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "cluster sysdump failed on every node".to_string(),
        );
    }

    let overview = ClusterSysdumpOverview {
        generated_at: match now.format(&Rfc3339) {
            Ok(value) => value,
            Err(err) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("time format error: {err}"),
                );
            }
        },
        partial: !failures.is_empty(),
        leader_node_id,
        node_count: nodes.len() + failures.len(),
        nodes_succeeded: nodes.len(),
        nodes_failed: failures.len(),
        nodes: build_node_overview(&nodes, &failures),
    };
    let failure_payload = ClusterSysdumpFailures { failures };

    let archive = match build_cluster_archive(
        &overview,
        &failure_payload,
        leader_cluster_summary,
        &nodes,
        now,
    ) {
        Ok(bytes) => bytes,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let filename = format!(
        "neuwerk-cluster-sysdump-{:04}{:02}{:02}T{:02}{:02}{:02}Z.tar.gz",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );

    let mut response = Response::new(Body::from(archive));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    let disposition = format!("attachment; filename=\"{filename}\"");
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, value);
    }
    response
}

pub(super) async fn node_sysdump(
    State(_state): State<ApiState>,
    headers: HeaderMap,
    _request: Request,
) -> Response {
    // Intentionally bypass leader proxying so the cluster leader can fetch
    // each node's local sysdump directly.
    let allowed = headers
        .get(CLUSTER_SYSDUMP_FANOUT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value == "1")
        .unwrap_or(false);
    if !allowed {
        return error_response(
            StatusCode::FORBIDDEN,
            "cluster sysdump fanout header required".to_string(),
        );
    }

    match crate::support::sysdump::build_local_sysdump_archive().await {
        Ok(bytes) => {
            let mut response = Response::new(Body::from(bytes));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/gzip"),
            );
            response
        }
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

async fn fetch_peer_sysdump(
    client: &reqwest::Client,
    headers: &HeaderMap,
    node_id: u128,
    raft_addr: &str,
    http_port: u16,
) -> Result<NodeSysdumpBundle, String> {
    let addr = raft_addr
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid cluster node addr: {err}"))?;
    let peer_http_addr = SocketAddr::new(addr.ip(), http_port);
    let mut req = client.post(format!(
        "https://{peer_http_addr}/api/v1/support/sysdump/node"
    ));
    if let Some(value) = headers.get(AUTHORIZATION) {
        req = req.header(AUTHORIZATION, value);
    }
    if let Some(value) = headers.get(COOKIE) {
        req = req.header(COOKIE, value);
    }
    req = req.header(CLUSTER_SYSDUMP_FANOUT_HEADER, "1");

    let response = req.send().await.map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "failed to read error body".to_string());
        return Err(format!("status {status}: {body}"));
    }
    let archive = response
        .bytes()
        .await
        .map_err(|err| err.to_string())?
        .to_vec();
    let state = extract_sysdump_json::<NodeStateSummary>(&archive, "summary/state.json");
    let cluster = extract_sysdump_json::<NodeClusterSummary>(&archive, "summary/cluster.json");
    Ok(NodeSysdumpBundle {
        node_id: node_id.to_string(),
        addr: raft_addr.to_string(),
        role: "follower".to_string(),
        archive,
        state,
        cluster,
    })
}

fn build_node_overview(
    bundles: &[NodeSysdumpBundle],
    failures: &[ClusterSysdumpFailure],
) -> Vec<ClusterSysdumpNodeOverview> {
    let mut nodes = bundles
        .iter()
        .map(|bundle| ClusterSysdumpNodeOverview {
            node_id: bundle.node_id.clone(),
            addr: bundle.addr.clone(),
            role: bundle.role.clone(),
            status: "ok".to_string(),
            error: None,
            state: bundle.state.clone(),
        })
        .collect::<Vec<_>>();
    nodes.extend(failures.iter().map(|failure| ClusterSysdumpNodeOverview {
        node_id: failure.node_id.clone(),
        addr: failure.addr.clone(),
        role: "unknown".to_string(),
        status: "failed".to_string(),
        error: Some(failure.error.clone()),
        state: None,
    }));
    nodes.sort_by(|a, b| {
        (a.role != "leader", a.node_id.as_str()).cmp(&(b.role != "leader", b.node_id.as_str()))
    });
    nodes
}

fn build_cluster_archive(
    overview: &ClusterSysdumpOverview,
    failures: &ClusterSysdumpFailures,
    leader_cluster_summary: Option<NodeClusterSummary>,
    nodes: &[NodeSysdumpBundle],
    now: OffsetDateTime,
) -> Result<Vec<u8>, String> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);

    append_json(
        &mut builder,
        "manifest.json",
        &json!({
            "generated_at": overview.generated_at,
            "partial": overview.partial,
            "nodes_succeeded": overview.nodes_succeeded,
            "nodes_failed": overview.nodes_failed,
        }),
        now,
    )?;
    append_json(&mut builder, "cluster/overview.json", overview, now)?;
    append_json(&mut builder, "cluster/failures.json", failures, now)?;
    if let Some(cluster) = leader_cluster_summary {
        append_json(&mut builder, "cluster/membership.json", &cluster, now)?;
    }

    for node in nodes {
        append_json(
            &mut builder,
            &format!("nodes/{}/meta.json", node.node_id),
            &json!({
                "node_id": node.node_id,
                "addr": node.addr,
                "role": node.role,
                "state": node.state,
            }),
            now,
        )?;
        append_bytes(
            &mut builder,
            &format!("nodes/{}/sysdump.tar.gz", node.node_id),
            &node.archive,
            now,
        )?;
    }

    builder.finish().map_err(|err| err.to_string())?;
    let encoder = builder.into_inner().map_err(|err| err.to_string())?;
    encoder.finish().map_err(|err| err.to_string())
}

fn append_json<W: Write, T: Serialize>(
    builder: &mut Builder<W>,
    archive_path: &str,
    value: &T,
    now: OffsetDateTime,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| err.to_string())?;
    append_bytes(builder, archive_path, &bytes, now)
}

fn append_bytes<W: Write>(
    builder: &mut Builder<W>,
    archive_path: &str,
    bytes: &[u8],
    now: OffsetDateTime,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(now.unix_timestamp().max(0) as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, archive_path, Cursor::new(bytes))
        .map_err(|err| err.to_string())
}

fn extract_sysdump_json<T: for<'de> Deserialize<'de>>(
    archive_bytes: &[u8],
    path: &str,
) -> Option<T> {
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = Archive::new(decoder);
    let entries = archive.entries().ok()?;
    for entry in entries {
        let mut entry = entry.ok()?;
        let entry_path = entry.path().ok()?.to_string_lossy().to_string();
        if entry_path != path {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).ok()?;
        return serde_json::from_slice(&bytes).ok();
    }
    None
}
