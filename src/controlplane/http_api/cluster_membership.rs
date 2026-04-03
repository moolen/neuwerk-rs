use std::collections::{BTreeSet, HashMap};

use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::controlplane::cloud::types::MissingMemberState;
use crate::controlplane::cluster::membership_admin::MembershipAdmin;
use crate::controlplane::cluster::types::NodeId;

use super::{error_response, maybe_proxy, read_body_limited, ApiState};

const MISSING_MEMBER_PREFIX: &[u8] = b"integration/membership/missing/";

#[derive(Debug, Serialize, ToSchema)]
pub struct ClusterMembersResponse {
    pub members: Vec<ClusterMemberView>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClusterMemberView {
    pub node_id: String,
    pub addr: String,
    pub role: String,
    pub is_voter: bool,
    pub cloud_status: String,
    pub drain_state: Option<String>,
    pub termination_event_id: Option<String>,
    pub auto_evict_reason: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RemoveClusterMemberRequest {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReplaceClusterVotersRequest {
    pub ids: Vec<String>,
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ClusterVotersResponse {
    pub voters: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/cluster/members",
    tag = "Diagnostics",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    responses(
        (status = 200, description = "Cluster membership", body = ClusterMembersResponse),
        (status = 503, description = "Cluster mode required or leader unavailable", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn list_cluster_members(
    State(state): State<ApiState>,
    request: Request,
) -> Response {
    let _request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster membership requires cluster mode".to_string(),
        );
    };

    let metrics = cluster.raft.metrics().borrow().clone();
    let missing = match load_missing_members(&cluster.store) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };
    let voters: BTreeSet<NodeId> = metrics
        .membership_config
        .membership()
        .voter_ids()
        .collect();

    let payload = ClusterMembersResponse {
        members: metrics
            .membership_config
            .membership()
            .nodes()
            .map(|member| {
                let (node_id, node) = member;
                let missing_state = missing.get(node_id);

                ClusterMemberView {
                    node_id: node_id.to_string(),
                    addr: node.addr.clone(),
                    role: member_role(*node_id, metrics.current_leader, voters.contains(node_id)),
                    is_voter: voters.contains(node_id),
                    cloud_status: cloud_status(missing_state),
                    drain_state: None,
                    termination_event_id: None,
                    auto_evict_reason: missing_state.map(auto_evict_reason),
                }
            })
            .collect(),
    };
    axum::Json(payload).into_response()
}

#[utoipa::path(
    post,
    path = "/api/v1/cluster/members/{node_id}/remove",
    tag = "Diagnostics",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = RemoveClusterMemberRequest,
    responses(
        (status = 200, description = "Member removed", body = ClusterVotersResponse),
        (status = 400, description = "Validation error", body = super::openapi::ErrorBody),
        (status = 503, description = "Cluster mode required or leader unavailable", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn remove_cluster_member(
    State(state): State<ApiState>,
    Path(node_id): Path<String>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster membership requires cluster mode".to_string(),
        );
    };
    let node_id = match node_id.parse::<NodeId>() {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid node id: {err}")),
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let payload: RemoveClusterMemberRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };

    let admin = MembershipAdmin::new(cluster.raft.clone());
    if let Err(err) = admin
        .remove_member(node_id, payload.force, state.cluster_membership_min_voters)
        .await
    {
        return membership_error_response(err);
    }

    axum::Json(ClusterVotersResponse {
        voters: admin
            .list_voters()
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    })
    .into_response()
}

#[utoipa::path(
    put,
    path = "/api/v1/cluster/members/voters",
    tag = "Diagnostics",
    security(
        ("bearerAuth" = []),
        ("sessionCookie" = [])
    ),
    request_body = ReplaceClusterVotersRequest,
    responses(
        (status = 200, description = "Voter set updated", body = ClusterVotersResponse),
        (status = 400, description = "Validation error", body = super::openapi::ErrorBody),
        (status = 503, description = "Cluster mode required or leader unavailable", body = super::openapi::ErrorBody)
    )
)]
pub(super) async fn replace_cluster_voters(
    State(state): State<ApiState>,
    mut request: Request,
) -> Response {
    request = match maybe_proxy(&state, request).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    let Some(cluster) = &state.cluster else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster membership requires cluster mode".to_string(),
        );
    };
    let body = match read_body_limited(request.into_body()).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    let payload: ReplaceClusterVotersRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, format!("invalid json: {err}")),
    };
    let mut voters = BTreeSet::new();
    for id in payload.ids {
        let node_id = match id.parse::<NodeId>() {
            Ok(value) => value,
            Err(err) => {
                return error_response(StatusCode::BAD_REQUEST, format!("invalid voter id: {err}"))
            }
        };
        voters.insert(node_id);
    }

    let admin = MembershipAdmin::new(cluster.raft.clone());
    if let Err(err) = admin
        .replace_voters(voters, payload.force, state.cluster_membership_min_voters)
        .await
    {
        return membership_error_response(err);
    }

    axum::Json(ClusterVotersResponse {
        voters: admin
            .list_voters()
            .into_iter()
            .map(|id| id.to_string())
            .collect(),
    })
    .into_response()
}

fn membership_error_response(err: String) -> Response {
    let status = if err.contains("forward")
        || err.contains("ForwardToLeader")
        || err.contains("leader unknown")
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    error_response(status, err)
}

fn member_role(node_id: NodeId, leader_id: Option<NodeId>, is_voter: bool) -> String {
    if leader_id == Some(node_id) {
        "leader".to_string()
    } else if is_voter {
        "follower".to_string()
    } else {
        "learner".to_string()
    }
}

fn cloud_status(missing_state: Option<&MissingMemberState>) -> String {
    if missing_state.is_some() {
        "missing_from_discovery".to_string()
    } else {
        "unknown".to_string()
    }
}

fn auto_evict_reason(state: &MissingMemberState) -> String {
    format!("missing_from_discovery:{}", state.first_missing_epoch)
}

fn load_missing_members(
    store: &crate::controlplane::cluster::store::ClusterStore,
) -> Result<HashMap<NodeId, MissingMemberState>, String> {
    let entries = store
        .scan_state_prefix(MISSING_MEMBER_PREFIX)
        .map_err(|err| format!("missing member scan: {err}"))?;
    let mut map = HashMap::new();
    for (key, value) in entries {
        let node_id = String::from_utf8_lossy(&key[MISSING_MEMBER_PREFIX.len()..])
            .parse::<NodeId>()
            .map_err(|err| format!("missing member node id: {err}"))?;
        let state: MissingMemberState = serde_json::from_slice(&value)
            .map_err(|err| format!("missing member decode: {err}"))?;
        map.insert(node_id, state);
    }
    Ok(map)
}
