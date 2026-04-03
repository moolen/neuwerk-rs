mod support;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use futures::StreamExt;
use neuwerk::controlplane::api_auth;
use neuwerk::controlplane::audit::{AuditEvent, AuditFindingType, AuditQueryResponse, AuditStore};
use neuwerk::controlplane::cluster::config::ClusterConfig;
use neuwerk::controlplane::cluster::types::NodeId;
use neuwerk::controlplane::http_api::{HttpApiCluster, HttpApiConfig};
use neuwerk::controlplane::intercept_tls::local_intercept_ca_paths;
use neuwerk::controlplane::metrics::Metrics;
use neuwerk::controlplane::policy_config::PolicyMode;
use neuwerk::controlplane::policy_repository::{PolicyDiskStore, PolicyRecord, POLICY_STATE_KEY};
use neuwerk::controlplane::policy_telemetry::PolicyTelemetryStore;
use neuwerk::controlplane::ready::ReadinessState;
use neuwerk::controlplane::wiretap::{WiretapEvent, WiretapHub};
use neuwerk::controlplane::{http_api, policy_replication, PolicyStore};
use neuwerk::dataplane::config::{DataplaneConfig, DataplaneConfigStore};
use neuwerk::dataplane::policy::DefaultPolicy;
use neuwerk::dataplane::WiretapEventType;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use support::cluster_fixture::{ensure_rustls_provider, next_addr, write_token_file};
use support::cluster_wait::{wait_for_leader, wait_for_stable_membership, wait_for_voter};
use tempfile::TempDir;
use time::Duration as TimeDuration;
use time::OffsetDateTime;

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for {}", path.display()))
}

async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for tcp {addr}"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_tcp_closed(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for tcp {addr} to close"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_ready_status(
    client: &reqwest::Client,
    addr: SocketAddr,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let resp = match client.get(format!("https://{addr}/ready")).send().await {
            Ok(resp) => resp,
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(format!("ready request failed: {err}"));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let status_ok = resp.status().is_success();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| format!("ready json decode failed: {err}"))?;
        let ready = body
            .get("ready")
            .and_then(|value| value.as_bool())
            .ok_or_else(|| "ready response missing boolean field".to_string())?;
        if ready == expected && status_ok == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for ready={expected} at {addr} (last status_ok={status_ok}, ready={ready})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn http_api_client(tls_dir: &Path) -> Result<reqwest::Client, String> {
    let ca = fs::read(tls_dir.join("ca.crt"))
        .map_err(|err| format!("read http ca cert failed: {err}"))?;
    let ca = reqwest::Certificate::from_pem(&ca)
        .map_err(|err| format!("invalid http ca cert: {err}"))?;
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|err| format!("http client build failed: {err}"))
}

async fn wait_for_state_value(
    store: &neuwerk::controlplane::cluster::store::ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = store.get_state_value(key)? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for cluster value".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[allow(dead_code)]
async fn wait_for_state_absent(
    store: &neuwerk::controlplane::cluster::store::ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(key)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for cluster value removal".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn api_auth_token_from_store(
    store: &neuwerk::controlplane::cluster::store::ClusterStore,
) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(keyset) = api_auth::load_keyset_from_store(store)? {
            let token = api_auth::mint_token(&keyset, "wiretap-test", None, None)?;
            return Ok(token.token);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for api auth keyset".to_string());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn cluster_http_roles(
    leader_id: NodeId,
    seed_id: NodeId,
    seed_http_addr: SocketAddr,
    join_http_addr: SocketAddr,
    seed_tls_dir: &Path,
    join_tls_dir: &Path,
) -> (SocketAddr, std::path::PathBuf, SocketAddr, &'static str) {
    if leader_id == seed_id {
        (
            seed_http_addr,
            seed_tls_dir.to_path_buf(),
            join_http_addr,
            "join",
        )
    } else {
        (
            join_http_addr,
            join_tls_dir.to_path_buf(),
            seed_http_addr,
            "seed",
        )
    }
}

async fn send_to_current_leader_until_success<F>(
    raft: &openraft::Raft<neuwerk::controlplane::cluster::types::ClusterTypeConfig>,
    seed_id: NodeId,
    seed_http_addr: SocketAddr,
    join_http_addr: SocketAddr,
    seed_tls_dir: &Path,
    join_tls_dir: &Path,
    timeout: Duration,
    mut build_request: F,
) -> Result<(NodeId, reqwest::Response), String>
where
    F: FnMut(&reqwest::Client, SocketAddr) -> reqwest::RequestBuilder,
{
    let deadline = Instant::now() + timeout;
    let mut last_error = "request not attempted".to_string();

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out waiting for successful leader request: {last_error}"
            ));
        }

        let leader_id = wait_for_leader(raft, deadline - now).await?;
        let (leader_addr, leader_tls_dir, _, _) = cluster_http_roles(
            leader_id,
            seed_id,
            seed_http_addr,
            join_http_addr,
            seed_tls_dir,
            join_tls_dir,
        );
        let client = match http_api_client(&leader_tls_dir) {
            Ok(client) => client,
            Err(err) => {
                last_error = err;
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        match build_request(&client, leader_addr).send().await {
            Ok(response) if response.status().is_success() => return Ok((leader_id, response)),
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                last_error = format!("status={status} body={body}");
                if matches!(
                    status,
                    reqwest::StatusCode::BAD_GATEWAY | reqwest::StatusCode::SERVICE_UNAVAILABLE
                ) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                return Err(last_error);
            }
            Err(err) => {
                last_error = format!("request failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[path = "http_api/cluster_policy_telemetry_cases.rs"]
mod cluster_policy_telemetry_cases;

#[path = "http_api/authz_cases.rs"]
mod authz_cases;
#[path = "http_api/cluster_audit_cases.rs"]
mod cluster_audit_cases;
#[path = "http_api/cluster_threat_cases.rs"]
mod cluster_threat_cases;
#[path = "http_api/lifecycle_cases.rs"]
mod lifecycle_cases;
#[path = "http_api/readiness_policy_cases.rs"]
mod readiness_policy_cases;
#[path = "http_api/sso_oidc_cases.rs"]
mod sso_oidc_cases;
#[path = "http_api/wiretap_auth_cases.rs"]
mod wiretap_auth_cases;
