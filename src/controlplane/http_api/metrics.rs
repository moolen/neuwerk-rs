use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::metrics::Metrics;

use super::{error_response, ApiState};

pub(super) async fn track_metrics(
    State(state): State<ApiState>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    state
        .metrics
        .observe_http(&path, &method, status, start.elapsed());
    response
}

pub(super) async fn metrics_handler(State(metrics): State<Metrics>) -> Response {
    match metrics.render() {
        Ok(body) => match Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4")
            .body(Body::from(body))
        {
            Ok(resp) => resp,
            Err(err) => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("metrics response build failed: {err}"),
            ),
        },
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    }
}

pub(super) fn spawn_raft_metrics_sampler(
    metrics: Metrics,
    raft: openraft::Raft<ClusterTypeConfig>,
) {
    tokio::spawn(async move {
        let mut watch = raft.metrics();
        let mut initialized = false;
        let mut last_leader = None;
        loop {
            let snapshot = watch.borrow().clone();
            let is_leader = snapshot.current_leader == Some(snapshot.id);
            metrics.set_raft_is_leader(is_leader);
            metrics.set_raft_current_term(snapshot.current_term);
            metrics.set_raft_last_log_index(snapshot.last_log_index);
            metrics.set_raft_last_applied(snapshot.last_applied.as_ref().map(|id| id.index));

            if initialized {
                if last_leader != snapshot.current_leader {
                    metrics.inc_raft_leader_changes();
                    last_leader = snapshot.current_leader;
                }
            } else {
                last_leader = snapshot.current_leader;
                initialized = true;
            }

            if watch.changed().await.is_err() {
                break;
            }
        }
    });
}

pub(super) fn spawn_rocksdb_metrics_sampler(metrics: Metrics, store: ClusterStore) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            if let Some(value) = store.property_int_value("rocksdb.estimate-num-keys") {
                metrics.set_rocksdb_estimated_num_keys(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.live-sst-files-size") {
                metrics.set_rocksdb_live_sst_files_size_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.total-sst-files-size") {
                metrics.set_rocksdb_total_sst_files_size_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.cur-size-all-mem-tables") {
                metrics.set_rocksdb_memtable_bytes(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.num-running-compactions") {
                metrics.set_rocksdb_num_running_compactions(value);
            }
            if let Some(value) = store.property_int_value("rocksdb.num-immutable-mem-table") {
                metrics.set_rocksdb_num_immutable_memtables(value);
            }
        }
    });
}
