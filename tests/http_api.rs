use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use firewall::controlplane::api_auth;
use firewall::controlplane::audit::{AuditEvent, AuditFindingType, AuditQueryResponse, AuditStore};
use firewall::controlplane::cluster::config::ClusterConfig;
use firewall::controlplane::cluster::types::ClusterTypeConfig;
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
use firewall::dataplane::config::DataplaneConfigStore;
use firewall::dataplane::policy::DefaultPolicy;
use firewall::dataplane::WiretapEventType;
use futures::StreamExt;
use openraft::RaftMetrics;
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};
use tempfile::TempDir;
use time::Duration as TimeDuration;
use time::OffsetDateTime;

fn next_addr(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(ip), 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_token_file(path: &Path) {
    let json = r#"{
  "tokens": [
    { "kid": "test", "token": "b64:dGVzdC1zZWNyZXQ=", "valid_until": "2027-01-01T00:00:00Z" }
  ]
}"#;
    fs::write(path, json).unwrap();
}

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

async fn wait_for_leader(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<u128, String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if let Some(leader) = m.current_leader {
            return Ok(leader);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for leader".to_string());
        }
        tokio::time::timeout(Duration::from_millis(100), metrics.changed())
            .await
            .map_err(|_| "metrics timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

#[tokio::test]
async fn http_api_local_lifecycle() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let policy_store_check = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let local_store_check = local_store.clone();
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "local-test", None, None).unwrap();
    let expired = api_auth::mint_token_at(
        &keyset,
        "local-test",
        Some(60),
        None,
        OffsetDateTime::now_utc() - TimeDuration::hours(1),
    )
    .unwrap();
    let ca_pem = fs::read(tls_dir.join("ca.crt")).unwrap();
    let ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let record: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(record.mode, PolicyMode::Enforce);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let records: Vec<PolicyRecord> = resp.json().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, record.id);
    assert_eq!(local_store_check.active_id().unwrap(), Some(record.id));

    let disabled_payload = serde_json::json!({
        "mode": "disabled",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/policies/{}", record.id))
        .bearer_auth(&token.token)
        .json(&disabled_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(updated.mode, PolicyMode::Disabled);
    assert_eq!(local_store_check.active_id().unwrap(), None);
    assert_eq!(policy_store_check.active_policy_id(), None);

    let missing = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::UNAUTHORIZED);

    let expired_resp = client
        .get(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&expired.token)
        .send()
        .await
        .unwrap();
    assert_eq!(expired_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let metrics = reqwest::Client::new()
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .await
        .unwrap();
    assert!(metrics.status().is_success());

    server.abort();
}

#[tokio::test]
async fn http_api_integrations_lifecycle_and_policy_ref_validation() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "integration-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let create_payload = serde_json::json!({
        "name": "prod-k8s",
        "kind": "kubernetes",
        "api_server_url": "https://127.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "secret-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&create_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        created.get("name").and_then(|v| v.as_str()),
        Some("prod-k8s")
    );
    assert_eq!(
        created.get("kind").and_then(|v| v.as_str()),
        Some("kubernetes")
    );
    assert_eq!(
        created.get("token_configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        created.get("auth_type").and_then(|v| v.as_str()),
        Some("service_account_token")
    );
    assert!(
        created.get("service_account_token").is_none(),
        "service_account_token must be redacted from API responses"
    );

    let duplicate_payload = serde_json::json!({
        "name": "PROD-K8S",
        "kind": "kubernetes",
        "api_server_url": "https://10.0.0.1:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        "service_account_token": "other-token",
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .json(&duplicate_payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let listed: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(listed.as_array().map(|arr| arr.len()), Some(1));

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let fetched: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        fetched.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://127.0.0.1:6443")
    );
    assert!(fetched.get("service_account_token").is_none());

    let update_payload = serde_json::json!({
        "api_server_url": "https://10.10.10.10:6443",
        "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
        "service_account_token": "updated-token",
    });
    let resp = client
        .put(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .json(&update_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        updated.get("api_server_url").and_then(|v| v.as_str()),
        Some("https://10.10.10.10:6443")
    );
    assert!(updated.get("service_account_token").is_none());

    let missing_ref_policy = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "missing",
                                "pod_selector": {
                                    "namespace": "default",
                                    "match_labels": { "app": "web" }
                                }
                            }
                        ]
                    },
                    "rules": [
                        {
                            "id": "deny-all",
                            "action": "deny",
                            "match": {}
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&missing_ref_policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let valid_policy = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "prod-k8s",
                                "pod_selector": {
                                    "namespace": "default",
                                    "match_labels": { "app": "web" }
                                }
                            }
                        ]
                    },
                    "rules": [
                        {
                            "id": "allow-https",
                            "action": "allow",
                            "match": {
                                "proto": "tcp",
                                "dst_ports": [443]
                            }
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&valid_policy)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let created_policy: PolicyRecord = resp.json().await.unwrap();

    let bad_update = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "pods",
                    "sources": {
                        "kubernetes": [
                            {
                                "integration": "missing",
                                "node_selector": {
                                    "match_labels": { "node-role.kubernetes.io/control-plane": "true" }
                                }
                            }
                        ]
                    }
                }
            ]
        }
    });
    let resp = client
        .put(format!(
            "https://{bind_addr}/api/v1/policies/{}",
            created_policy.id
        ))
        .bearer_auth(&token.token)
        .json(&bad_update)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("unknown kubernetes integration"));

    let resp = client
        .delete(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/integrations/prod-k8s"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    server.abort();
}

#[tokio::test]
async fn http_api_tls_intercept_ca_local_settings_round_trip() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "local-settings-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = Certificate::from_params(ca_params).unwrap();
    let cert_pem = ca_cert.serialize_pem().unwrap();
    let key_pem = ca_cert.serialize_private_key_pem();

    let put_resp = client
        .put(format!(
            "https://{bind_addr}/api/v1/settings/tls-intercept-ca"
        ))
        .bearer_auth(&token.token)
        .json(&serde_json::json!({
            "ca_cert_pem": cert_pem,
            "ca_key_pem": key_pem,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put_resp.status(), reqwest::StatusCode::OK);
    let put_body: serde_json::Value = put_resp.json().await.unwrap();
    assert_eq!(
        put_body.get("configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        put_body.get("source").and_then(|v| v.as_str()),
        Some("local")
    );
    assert!(put_body
        .get("fingerprint_sha256")
        .and_then(|v| v.as_str())
        .is_some());

    let get_resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/settings/tls-intercept-ca"
        ))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), reqwest::StatusCode::OK);
    let get_body: serde_json::Value = get_resp.json().await.unwrap();
    assert_eq!(
        get_body.get("configured").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        get_body.get("source").and_then(|v| v.as_str()),
        Some("local")
    );

    let (cert_path, key_path) = local_intercept_ca_paths(&tls_dir);
    assert!(cert_path.exists());
    assert!(key_path.exists());

    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_times_out_when_dataplane_ack_missing() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "activation-timeout-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.text().await.unwrap();
    assert!(body.contains("policy activation timed out"));
    assert!(
        elapsed >= Duration::from_millis(1800),
        "policy activation timeout returned too early: {elapsed:?}"
    );

    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_waits_for_dataplane_ack() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let tracker_store = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "activation-ack-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let ack_task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let generation = tracker_store.policy_generation();
            if generation > 0 {
                tracker_store
                    .policy_applied_tracker()
                    .store(generation, Ordering::Release);
                tracker_store
                    .service_policy_applied_tracker()
                    .store(generation, Ordering::Release);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();
    let status = resp.status();
    let body = resp.text().await.unwrap();

    assert!(
        status.is_success(),
        "expected success after policy ack, got {}: {}",
        status,
        body
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "policy activation ack path should complete before timeout, took {elapsed:?}"
    );

    ack_task.await.unwrap();
    server.abort();
}

#[tokio::test]
async fn http_api_policy_write_times_out_when_service_plane_ack_missing() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let tracker_store = policy_store.clone();
    let local_store = PolicyDiskStore::new(local_store_dir);
    let readiness = ReadinessState::new(
        DataplaneConfigStore::new(),
        policy_store.clone(),
        None,
        None,
    );
    readiness.set_dataplane_running(true);
    readiness.set_policy_ready(true);
    readiness.set_dns_ready(true);
    readiness.set_service_plane_ready(true);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            None,
            None,
            Some(readiness),
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token =
        api_auth::mint_token(&keyset, "activation-service-timeout-test", None, None).unwrap();
    let client = http_api_client(&tls_dir).unwrap();

    let ack_task = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let generation = tracker_store.policy_generation();
            if generation > 0 {
                // Intentionally acknowledge only dataplane generation to verify service-plane
                // activation is also required.
                tracker_store
                    .policy_applied_tracker()
                    .store(generation, Ordering::Release);
                return;
            }
            if Instant::now() >= deadline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "local",
                    "sources": { "ips": ["10.0.0.5"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let start = Instant::now();
    let resp = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    let elapsed = start.elapsed();

    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = resp.text().await.unwrap();
    assert!(body.contains("policy activation timed out"));
    assert!(
        elapsed >= Duration::from_millis(1800),
        "policy activation timeout returned too early: {elapsed:?}"
    );

    ack_task.await.unwrap();
    server.abort();
}

#[tokio::test]
async fn http_api_cluster_proxy_lifecycle() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let join_dir = TempDir::new().unwrap();
    let seed_token = seed_dir.path().join("bootstrap.json");
    let join_token = join_dir.path().join("bootstrap.json");
    write_token_file(&seed_token);
    write_token_file(&join_token);

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let join_ip = Ipv4Addr::new(127, 0, 0, 2);

    let seed_addr: SocketAddr = SocketAddr::new(IpAddr::V4(seed_ip), 9600);
    let seed_join_addr: SocketAddr = SocketAddr::new(IpAddr::V4(seed_ip), 9601);
    let join_addr: SocketAddr = SocketAddr::new(IpAddr::V4(join_ip), 9600);
    let join_join_addr: SocketAddr = SocketAddr::new(IpAddr::V4(join_ip), 9601);

    let mut seed_cfg = ClusterConfig::disabled();
    seed_cfg.enabled = true;
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.data_dir = seed_dir.path().to_path_buf();
    seed_cfg.node_id_path = seed_dir.path().join("node_id");
    seed_cfg.token_path = seed_token.clone();

    let mut join_cfg = ClusterConfig::disabled();
    join_cfg.enabled = true;
    join_cfg.bind_addr = join_addr;
    join_cfg.join_bind_addr = join_join_addr;
    join_cfg.advertise_addr = join_addr;
    join_cfg.join_seed = Some(seed_join_addr);
    join_cfg.data_dir = join_dir.path().to_path_buf();
    join_cfg.node_id_path = join_dir.path().join("node_id");
    join_cfg.token_path = join_token.clone();

    let seed_metrics = Metrics::new().unwrap();
    let join_metrics = Metrics::new().unwrap();

    let seed_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        None,
        Some(seed_metrics.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        None,
        Some(join_metrics.clone()),
    )
    .await
    .unwrap()
    .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;
    let join_id = join_runtime.raft.metrics().borrow().id;
    assert!(leader_id == seed_id || leader_id == join_id);

    let seed_http = HttpApiConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(seed_ip), 8443),
        advertise_addr: SocketAddr::new(IpAddr::V4(seed_ip), 8443),
        metrics_bind: SocketAddr::new(IpAddr::V4(seed_ip), 8080),
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: SocketAddr::new(IpAddr::V4(join_ip), 8443),
        advertise_addr: SocketAddr::new(IpAddr::V4(join_ip), 8443),
        metrics_bind: SocketAddr::new(IpAddr::V4(join_ip), 8080),
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let join_local_store_check = join_local_store.clone();

    let seed_http_task = tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy.clone(),
        seed_local_store.clone(),
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        None,
        None,
        None,
        None,
        seed_metrics,
    ));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let join_http_task = tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy.clone(),
        join_local_store.clone(),
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        None,
        None,
        None,
        None,
        join_metrics,
    ));
    wait_for_tcp(
        SocketAddr::new(IpAddr::V4(seed_ip), 8443),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_tcp(
        SocketAddr::new(IpAddr::V4(join_ip), 8443),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(
        &seed_runtime.store,
        api_auth::API_KEYS_KEY,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let keyset = api_auth::load_keyset_from_store(&seed_runtime.store)
        .unwrap()
        .expect("missing api keyset");
    let token = api_auth::mint_token(&keyset, "cluster-test", None, None).unwrap();

    let replication_task = tokio::spawn(policy_replication::run_policy_replication(
        join_runtime.store.clone(),
        join_runtime.raft.clone(),
        join_policy.clone(),
        join_local_store.clone(),
        None,
        Duration::from_millis(200),
    ));

    let ca_pem = fs::read(seed_dir.path().join("http-tls").join("ca.crt")).unwrap();
    let ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "cluster",
                    "sources": { "ips": ["10.0.0.7"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });

    let follower_ip = if leader_id == seed_id {
        join_ip
    } else {
        seed_ip
    };
    let follower_addr = SocketAddr::new(IpAddr::V4(follower_ip), 8443);
    let resp = client
        .post(format!("https://{follower_addr}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let record: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(record.mode, PolicyMode::Enforce);

    let active = seed_runtime
        .store
        .get_state_value(POLICY_ACTIVE_KEY)
        .unwrap()
        .unwrap();
    let active: PolicyActive = serde_json::from_slice(&active).unwrap();
    assert_eq!(active.id, record.id);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(join_local_store_check.active_id().unwrap(), Some(record.id));

    let disabled_payload = serde_json::json!({
        "mode": "disabled",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "cluster",
                    "sources": { "ips": ["10.0.0.7"] },
                    "rules": [
                        {
                            "id": "allow-dns",
                            "mode": "enforce",
                            "action": "allow",
                            "match": { "dns_hostname": "example.com" }
                        }
                    ]
                }
            ]
        }
    });
    let resp = client
        .put(format!(
            "https://{follower_addr}/api/v1/policies/{}",
            record.id
        ))
        .bearer_auth(&token.token)
        .json(&disabled_payload)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let updated: PolicyRecord = resp.json().await.unwrap();
    assert_eq!(updated.mode, PolicyMode::Disabled);
    wait_for_state_absent(
        &seed_runtime.store,
        POLICY_ACTIVE_KEY,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(join_local_store_check.active_id().unwrap(), None);
    assert_eq!(join_policy.active_policy_id(), None);

    seed_http_task.abort();
    join_http_task.abort();
    replication_task.abort();
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

#[tokio::test]
async fn http_api_wiretap_stream_aggregates_cluster() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let join_dir = TempDir::new().unwrap();
    let seed_token = seed_dir.path().join("bootstrap.json");
    let join_token = join_dir.path().join("bootstrap.json");
    write_token_file(&seed_token);
    write_token_file(&join_token);

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let join_ip = Ipv4Addr::new(127, 0, 0, 2);

    let seed_addr = next_addr(seed_ip);
    let seed_join_addr = next_addr(seed_ip);
    let join_addr = next_addr(join_ip);
    let join_join_addr = next_addr(join_ip);

    let mut seed_cfg = ClusterConfig::disabled();
    seed_cfg.enabled = true;
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.data_dir = seed_dir.path().to_path_buf();
    seed_cfg.node_id_path = seed_dir.path().join("node_id");
    seed_cfg.token_path = seed_token.clone();

    let mut join_cfg = ClusterConfig::disabled();
    join_cfg.enabled = true;
    join_cfg.bind_addr = join_addr;
    join_cfg.join_bind_addr = join_join_addr;
    join_cfg.advertise_addr = join_addr;
    join_cfg.join_seed = Some(seed_join_addr);
    join_cfg.data_dir = join_dir.path().to_path_buf();
    join_cfg.node_id_path = join_dir.path().join("node_id");
    join_cfg.token_path = join_token.clone();

    let seed_wiretap = WiretapHub::new(32);
    let join_wiretap = WiretapHub::new(32);
    let seed_metrics_registry = Metrics::new().unwrap();
    let join_metrics_registry = Metrics::new().unwrap();

    let seed_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        Some(seed_wiretap.clone()),
        Some(seed_metrics_registry.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        Some(join_wiretap.clone()),
        Some(join_metrics_registry.clone()),
    )
    .await
    .unwrap()
    .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;
    let _join_id = join_runtime.raft.metrics().borrow().id;

    let http_port = next_addr(seed_ip).port();
    let seed_http_addr = SocketAddr::new(IpAddr::V4(seed_ip), http_port);
    let join_http_addr = SocketAddr::new(IpAddr::V4(join_ip), http_port);
    let seed_metrics = next_addr(seed_ip);
    let join_metrics = next_addr(join_ip);

    let seed_http = HttpApiConfig {
        bind_addr: seed_http_addr,
        advertise_addr: seed_http_addr,
        metrics_bind: seed_metrics,
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics,
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let seed_http_task = tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy,
        seed_local_store,
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        None,
        Some(seed_wiretap.clone()),
        None,
        None,
        seed_metrics_registry,
    ));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let join_http_task = tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy,
        join_local_store,
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        None,
        Some(join_wiretap.clone()),
        None,
        None,
        join_metrics_registry,
    ));

    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&join_runtime.store).unwrap();

    let (leader_addr, leader_tls_dir) = if leader_id == seed_id {
        (seed_http_addr, seed_dir.path().join("http-tls"))
    } else {
        (join_http_addr, join_dir.path().join("http-tls"))
    };

    let client = http_api_client(&leader_tls_dir).unwrap();
    let resp = client
        .get(format!("https://{leader_addr}/api/v1/wiretap/stream"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mut stream = resp.bytes_stream();
    let read_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = String::new();
        let mut seen_seed = false;
        let mut seen_join = false;
        while Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    if buf.contains("seed-flow") {
                        seen_seed = true;
                    }
                    if buf.contains("join-flow") {
                        seen_join = true;
                    }
                    if seen_seed && seen_join {
                        return Ok::<(), String>(());
                    }
                }
                Ok(Some(Err(err))) => return Err(format!("stream error: {err}")),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err("wiretap stream did not include both flows".to_string())
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    seed_wiretap.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "seed-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 2),
        dst_ip: Ipv4Addr::new(198, 51, 100, 10),
        src_port: 40000,
        dst_port: 53,
        proto: 17,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: Some("foo.allowed".to_string()),
        node_id: "seed-node".to_string(),
    });
    join_wiretap.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "join-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 3),
        dst_ip: Ipv4Addr::new(198, 51, 100, 20),
        src_port: 40001,
        dst_port: 80,
        proto: 6,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: None,
        node_id: "join-node".to_string(),
    });

    match read_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(err) => panic!("wiretap stream task failed: {err}"),
    }

    seed_http_task.abort();
    join_http_task.abort();
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

#[tokio::test]
async fn http_api_audit_findings_local_returns_deduped_items() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let audit_store = AuditStore::new(dir.path().join("audit"), 1024 * 1024);
    let finding = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "apps".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 42)),
        dst_port: Some(443),
        proto: Some(6),
        fqdn: Some("api.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 10,
    };
    audit_store.ingest(finding.clone(), None, "node-a");
    audit_store.ingest(finding, None, "node-a");

    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            Some(audit_store),
            None,
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "audit-local-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let response = client
        .get(format!(
            "https://{bind_addr}/api/v1/audit/findings?finding_type=l4_deny&source_group=apps"
        ))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(payload.items.len(), 1);
    assert_eq!(payload.items[0].count, 2);
    assert_eq!(payload.items[0].source_group, "apps");
    assert!(!payload.partial);
    assert_eq!(payload.nodes_queried, 1);
    assert_eq!(payload.nodes_responded, 1);

    server.abort();
}

#[tokio::test]
async fn http_api_audit_findings_cluster_aggregates_and_returns_partial() {
    ensure_rustls_provider();
    let seed_dir = TempDir::new().unwrap();
    let join_dir = TempDir::new().unwrap();
    let seed_token = seed_dir.path().join("bootstrap.json");
    let join_token = join_dir.path().join("bootstrap.json");
    write_token_file(&seed_token);
    write_token_file(&join_token);

    let seed_ip = Ipv4Addr::new(127, 0, 0, 1);
    let join_ip = Ipv4Addr::new(127, 0, 0, 2);
    let seed_addr = next_addr(seed_ip);
    let seed_join_addr = next_addr(seed_ip);
    let join_addr = next_addr(join_ip);
    let join_join_addr = next_addr(join_ip);

    let mut seed_cfg = ClusterConfig::disabled();
    seed_cfg.enabled = true;
    seed_cfg.bind_addr = seed_addr;
    seed_cfg.join_bind_addr = seed_join_addr;
    seed_cfg.advertise_addr = seed_addr;
    seed_cfg.data_dir = seed_dir.path().to_path_buf();
    seed_cfg.node_id_path = seed_dir.path().join("node_id");
    seed_cfg.token_path = seed_token.clone();

    let mut join_cfg = ClusterConfig::disabled();
    join_cfg.enabled = true;
    join_cfg.bind_addr = join_addr;
    join_cfg.join_bind_addr = join_join_addr;
    join_cfg.advertise_addr = join_addr;
    join_cfg.join_seed = Some(seed_join_addr);
    join_cfg.data_dir = join_dir.path().to_path_buf();
    join_cfg.node_id_path = join_dir.path().join("node_id");
    join_cfg.token_path = join_token.clone();

    let seed_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        seed_cfg,
        None,
        Some(Metrics::new().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();
    let join_runtime = firewall::controlplane::cluster::run_cluster_tasks(
        join_cfg,
        None,
        Some(Metrics::new().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    let leader_id = wait_for_leader(&seed_runtime.raft, Duration::from_secs(5))
        .await
        .unwrap();
    let seed_id = seed_runtime.raft.metrics().borrow().id;

    let http_port = next_addr(seed_ip).port();
    let seed_http_addr = SocketAddr::new(IpAddr::V4(seed_ip), http_port);
    let join_http_addr = SocketAddr::new(IpAddr::V4(join_ip), http_port);
    let seed_metrics = next_addr(seed_ip);
    let join_metrics = next_addr(join_ip);

    let seed_http = HttpApiConfig {
        bind_addr: seed_http_addr,
        advertise_addr: seed_http_addr,
        metrics_bind: seed_metrics,
        tls_dir: seed_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(seed_ip),
        token_path: seed_token.clone(),
        cluster_tls_dir: Some(seed_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let join_http = HttpApiConfig {
        bind_addr: join_http_addr,
        advertise_addr: join_http_addr,
        metrics_bind: join_metrics,
        tls_dir: join_dir.path().join("http-tls"),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(join_ip),
        token_path: join_token.clone(),
        cluster_tls_dir: Some(join_dir.path().join("tls")),
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let seed_audit_store = AuditStore::new(seed_dir.path().join("audit"), 1024 * 1024);
    let join_audit_store = AuditStore::new(join_dir.path().join("audit"), 1024 * 1024);
    let common = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "apps".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 9)),
        dst_port: Some(443),
        proto: Some(6),
        fqdn: Some("api.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 1,
    };
    seed_audit_store.ingest(common.clone(), None, "seed-node");
    join_audit_store.ingest(common, None, "join-node");

    let seed_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let join_policy = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let seed_local_store = PolicyDiskStore::new(seed_dir.path().join("policies"));
    let join_local_store = PolicyDiskStore::new(join_dir.path().join("policies"));
    let mut seed_http_task = Some(tokio::spawn(http_api::run_http_api(
        seed_http,
        seed_policy,
        seed_local_store,
        Some(HttpApiCluster {
            raft: seed_runtime.raft.clone(),
            store: seed_runtime.store.clone(),
        }),
        Some(seed_audit_store),
        None,
        None,
        None,
        Metrics::new().unwrap(),
    )));

    wait_for_file(
        &seed_dir.path().join("http-tls").join("ca.crt"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    wait_for_state_value(&join_runtime.store, b"http/ca/cert", Duration::from_secs(5))
        .await
        .unwrap();

    let mut join_http_task = Some(tokio::spawn(http_api::run_http_api(
        join_http,
        join_policy,
        join_local_store,
        Some(HttpApiCluster {
            raft: join_runtime.raft.clone(),
            store: join_runtime.store.clone(),
        }),
        Some(join_audit_store),
        None,
        None,
        None,
        Metrics::new().unwrap(),
    )));

    wait_for_tcp(seed_http_addr, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(join_http_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let token = api_auth_token_from_store(&join_runtime.store).unwrap();
    let (leader_addr, leader_tls_dir, follower_addr, stop_follower) = if leader_id == seed_id {
        (
            seed_http_addr,
            seed_dir.path().join("http-tls"),
            join_http_addr,
            "join",
        )
    } else {
        (
            join_http_addr,
            join_dir.path().join("http-tls"),
            seed_http_addr,
            "seed",
        )
    };
    let client = http_api_client(&leader_tls_dir).unwrap();

    let response = client
        .get(format!(
            "https://{leader_addr}/api/v1/audit/findings?finding_type=l4_deny"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.partial);
    assert!(payload.nodes_queried >= 2);
    assert!(payload.nodes_responded >= 2);
    assert!(!payload.items.is_empty());
    assert_eq!(payload.items[0].count, 2);
    assert_eq!(payload.items[0].node_ids.len(), 2);

    if stop_follower == "join" {
        if let Some(task) = join_http_task.take() {
            task.abort();
            let _ = task.await;
        }
    } else {
        if let Some(task) = seed_http_task.take() {
            task.abort();
            let _ = task.await;
        }
    }
    wait_for_tcp_closed(follower_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let response = client
        .get(format!(
            "https://{leader_addr}/api/v1/audit/findings?finding_type=l4_deny"
        ))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(payload.partial);
    assert!(payload.nodes_queried >= 2);
    assert!(payload.nodes_responded < payload.nodes_queried);
    assert!(!payload.node_errors.is_empty());

    if let Some(task) = seed_http_task.take() {
        task.abort();
    }
    if let Some(task) = join_http_task.take() {
        task.abort();
    }
    seed_runtime.shutdown().await;
    join_runtime.shutdown().await;
}

#[tokio::test]
async fn http_api_audit_findings_persist_across_restart() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let audit_dir = dir.path().join("audit");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let token_path = dir.path().join("token.json");
    let max_bytes = 1024 * 1024;

    let event = AuditEvent {
        finding_type: AuditFindingType::L4Deny,
        source_group: "persist".to_string(),
        hostname: None,
        dst_ip: Some(Ipv4Addr::new(203, 0, 113, 100)),
        dst_port: Some(8443),
        proto: Some(6),
        fqdn: Some("persist.example.com".to_string()),
        sni: None,
        icmp_type: None,
        icmp_code: None,
        query_type: None,
        observed_at: 42,
    };

    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: token_path.clone(),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

    let base_cfg = cfg.clone();
    let start_server = || {
        let cfg = base_cfg.clone();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let local_store = PolicyDiskStore::new(local_store_dir.clone());
        let audit_store = AuditStore::new(audit_dir.clone(), max_bytes);
        let metrics = Metrics::new().unwrap();
        tokio::spawn(async move {
            http_api::run_http_api(
                cfg,
                policy_store,
                local_store,
                None,
                Some(audit_store),
                None,
                None,
                None,
                metrics,
            )
            .await
            .map_err(|err| format!("http api error: {err}"))
        })
    };

    let seed_store = AuditStore::new(audit_dir.clone(), max_bytes);
    seed_store.ingest(event, None, "node-a");
    drop(seed_store);

    let server = start_server();
    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "audit-restart-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let query = format!(
        "https://{bind_addr}/api/v1/audit/findings?finding_type=l4_deny&source_group=persist"
    );
    let first = client
        .get(&query)
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = first.status();
    let body = first.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.items.is_empty());

    server.abort();
    let _ = server.await;
    wait_for_tcp_closed(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();

    let server = start_server();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let second = client
        .get(&query)
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    let status = second.status();
    let body = second.text().await.unwrap();
    assert!(status.is_success(), "status={status} body={body}");
    let payload: AuditQueryResponse = serde_json::from_str(&body).unwrap();
    assert!(!payload.items.is_empty());
    assert!(payload
        .items
        .iter()
        .any(|item| item.source_group == "persist" && item.count >= 1));

    server.abort();
}

#[tokio::test]
async fn http_api_wiretap_stream_local_cookie_auth_emits_events() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let login_resp = client
        .post(format!("https://{bind_addr}/api/v1/auth/token-login"))
        .json(&serde_json::json!({ "token": token.token }))
        .send()
        .await
        .unwrap();
    assert!(login_resp.status().is_success());
    let set_cookie = login_resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("missing set-cookie");
    let cookie = set_cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("neuwerk_auth="));

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/wiretap/stream"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("text/event-stream"));

    let mut stream = resp.bytes_stream();
    let read_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = String::new();
        while Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    if buf.contains("event: flow") && buf.contains("local-flow") {
                        return Ok::<(), String>(());
                    }
                }
                Ok(Some(Err(err))) => return Err(format!("stream error: {err}")),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err(format!(
            "wiretap stream missing expected event payload: {buf}"
        ))
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    wiretap_hub.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "local-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 9),
        dst_ip: Ipv4Addr::new(198, 51, 100, 42),
        src_port: 45678,
        dst_port: 443,
        proto: 6,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: Some("api.example.com".to_string()),
        node_id: "node-local".to_string(),
    });

    match read_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(err) => panic!("wiretap stream task failed: {err}"),
    }

    server.abort();
}

#[tokio::test]
async fn http_api_wiretap_stream_local_query_token_emits_events() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/wiretap/stream?access_token={}",
            token.token
        ))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("text/event-stream"));

    let mut stream = resp.bytes_stream();
    let read_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = String::new();
        while Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    if buf.contains("event: flow") && buf.contains("query-flow") {
                        return Ok::<(), String>(());
                    }
                }
                Ok(Some(Err(err))) => return Err(format!("stream error: {err}")),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err(format!(
            "wiretap stream missing expected event payload: {buf}"
        ))
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    wiretap_hub.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "query-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 10),
        dst_ip: Ipv4Addr::new(198, 51, 100, 43),
        src_port: 45679,
        dst_port: 443,
        proto: 6,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: Some("api.example.com".to_string()),
        node_id: "node-local".to_string(),
    });

    match read_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(err) => panic!("wiretap stream task failed: {err}"),
    }

    server.abort();
}

#[tokio::test]
async fn http_api_query_token_auth_is_wiretap_only() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/policies?access_token={}",
            token.token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    server.abort();
}
