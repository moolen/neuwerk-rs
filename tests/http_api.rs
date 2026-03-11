mod support;

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use firewall::controlplane::api_auth;
use firewall::controlplane::audit::{AuditEvent, AuditFindingType, AuditQueryResponse, AuditStore};
use firewall::controlplane::cluster::config::ClusterConfig;
use firewall::controlplane::http_api::{HttpApiCluster, HttpApiConfig};
use firewall::controlplane::intercept_tls::local_intercept_ca_paths;
use firewall::controlplane::metrics::Metrics;
use firewall::controlplane::policy_config::PolicyMode;
use firewall::controlplane::policy_repository::{
    PolicyActive, PolicyDiskStore, PolicyRecord, POLICY_ACTIVE_KEY,
};
use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::wiretap::{WiretapEvent, WiretapHub};
use firewall::controlplane::{http_api, policy_replication, PolicyStore};
use firewall::dataplane::config::{DataplaneConfig, DataplaneConfigStore};
use firewall::dataplane::policy::DefaultPolicy;
use firewall::dataplane::WiretapEventType;
use futures::StreamExt;
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
        let resp = client
            .get(format!("https://{addr}/ready"))
            .send()
            .await
            .map_err(|err| format!("ready request failed: {err}"))?;
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
    store: &firewall::controlplane::cluster::store::ClusterStore,
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

async fn wait_for_state_absent(
    store: &firewall::controlplane::cluster::store::ClusterStore,
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
    store: &firewall::controlplane::cluster::store::ClusterStore,
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

#[path = "http_api/authz_cases.rs"]
mod authz_cases;
#[path = "http_api/cluster_audit_cases.rs"]
mod cluster_audit_cases;
#[path = "http_api/lifecycle_cases.rs"]
mod lifecycle_cases;
#[path = "http_api/readiness_policy_cases.rs"]
mod readiness_policy_cases;
#[path = "http_api/sso_oidc_cases.rs"]
mod sso_oidc_cases;
#[path = "http_api/wiretap_auth_cases.rs"]
mod wiretap_auth_cases;
