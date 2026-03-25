use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use neuwerk::controlplane::api_auth;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tempfile::TempDir;
use tokio::sync::Mutex;

#[path = "support/runtime_config.rs"]
mod runtime_config_support;

static RUNTIME_SIGNAL_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn next_addr(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from((ip, 0))).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
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

fn http_client(tls_dir: &Path) -> Result<reqwest::Client, String> {
    let ca_pem =
        fs::read(tls_dir.join("ca.crt")).map_err(|err| format!("read ca cert failed: {err}"))?;
    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|err| format!("parse ca cert failed: {err}"))?;
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|err| format!("build client failed: {err}"))
}

async fn wait_for_ready(
    client: &reqwest::Client,
    addr: SocketAddr,
    expected: bool,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(format!("https://{addr}/ready")).send().await {
            let status_ok = resp.status().is_success();
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                let ready = body.get("ready").and_then(|value| value.as_bool());
                if ready == Some(expected) && status_ok == expected {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for ready={expected} at {addr}"))
}

async fn wait_for_ready_false_before_exit(
    child: &mut Child,
    client: &reqwest::Client,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().map_err(|err| err.to_string())? {
            return Err(format!(
                "Neuwerk exited before readiness turned false: {status}"
            ));
        }
        if let Ok(resp) = client.get(format!("https://{addr}/ready")).send().await {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if body.get("ready").and_then(|value| value.as_bool()) == Some(false) {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("timed out waiting for readiness=false before exit".to_string())
}

async fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait().map_err(|err| err.to_string())?.is_some() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err("timed out waiting for neuwerk exit".to_string())
}

async fn wait_for_tcp_closed(addr: SocketAddr, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("timed out waiting for tcp {addr} to close"))
}

fn cleanup_interface(name: &str) {
    let _ = Command::new("ip")
        .args(["link", "delete", "dev", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn create_tun_interface(name: &str, cidr: &str) -> Result<(), String> {
    cleanup_interface(name);
    let output = Command::new("ip")
        .args(["tuntap", "add", "dev", name, "mode", "tun"])
        .output()
        .map_err(|err| format!("create tuntap {name} failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "create tuntap {name} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = Command::new("ip")
        .args(["addr", "add", cidr, "dev", name])
        .output()
        .map_err(|err| format!("assign addr {cidr} to {name} failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "assign addr {cidr} to {name} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let output = Command::new("ip")
        .args(["link", "set", "dev", name, "up"])
        .output()
        .map_err(|err| format!("set link {name} up failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "set link {name} up exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn cleanup_service_lane_state() {
    cleanup_interface("svc0");
    let _ = Command::new("ip")
        .args(["-4", "rule", "del", "pref", "10940"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("ip")
        .args(["-4", "rule", "del", "pref", "10941"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("ip")
        .args(["-4", "rule", "del", "pref", "10942"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("ip")
        .args(["-4", "route", "flush", "table", "190"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("ip")
        .args(["-4", "route", "flush", "table", "191"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

struct NetworkCleanup {
    dataplane_iface: String,
}

impl Drop for NetworkCleanup {
    fn drop(&mut self) {
        cleanup_interface(&self.dataplane_iface);
        cleanup_service_lane_state();
    }
}

fn spawn_neuwerk(
    local_root: &Path,
) -> Result<Child, String> {
    Command::new(env!("CARGO_BIN_EXE_neuwerk"))
        .env("NEUWERK_LOCAL_DATA_DIR", local_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn neuwerk failed: {err}"))
}

#[tokio::test]
async fn neuwerk_binary_sigterm_flips_readiness_false_before_exit_and_restarts() {
    let _guard = RUNTIME_SIGNAL_TEST_LOCK.lock().await;
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_root = dir.path().join("var-lib");
    let http_bind = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_bind = next_addr(Ipv4Addr::LOCALHOST);
    let dataplane_iface = format!("nwtest{}", std::process::id());
    let _cleanup = NetworkCleanup {
        dataplane_iface: dataplane_iface.clone(),
    };

    cleanup_service_lane_state();
    if let Err(err) = create_tun_interface(&dataplane_iface, "10.9.0.2/24") {
        eprintln!("skipping runtime signal case: tun interface setup unavailable: {err}");
        return;
    }

    let _runtime_config = runtime_config_support::InstalledRuntimeConfig::install_tun(
        &tls_dir,
        http_bind,
        metrics_bind,
        &dataplane_iface,
        "10.0.0.0/24",
    )
    .unwrap();
    let mut child = spawn_neuwerk(&local_root).unwrap();

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(5))
        .await
        .unwrap();
    let client = http_client(&tls_dir).unwrap();
    wait_for_ready(&client, http_bind, true, Duration::from_secs(5))
        .await
        .unwrap();

    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(5))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing api keyset");
    let token = api_auth::mint_token(&keyset, "sigterm-test", None, None).unwrap();

    let payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "sigterm",
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

    let create = client
        .post(format!("https://{http_bind}/api/v1/policies"))
        .bearer_auth(&token.token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success());

    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();

    wait_for_ready_false_before_exit(&mut child, &client, http_bind, Duration::from_secs(3))
        .await
        .unwrap();
    wait_for_child_exit(&mut child, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_tcp_closed(http_bind, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp_closed(metrics_bind, Duration::from_secs(5))
        .await
        .unwrap();

    let mut restarted = spawn_neuwerk(&local_root).unwrap();

    wait_for_ready(&client, http_bind, true, Duration::from_secs(5))
        .await
        .unwrap();

    let listed = client
        .get(format!("https://{http_bind}/api/v1/policies"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(listed.status().is_success());
    let records: Vec<serde_json::Value> = listed.json().await.unwrap();
    assert_eq!(records.len(), 1);

    kill(Pid::from_raw(restarted.id() as i32), Signal::SIGTERM).unwrap();
    wait_for_child_exit(&mut restarted, Duration::from_secs(10))
        .await
        .unwrap();
}

#[tokio::test]
async fn neuwerk_binary_policy_upsert_by_name_preserves_stable_id_across_restart() {
    let _guard = RUNTIME_SIGNAL_TEST_LOCK.lock().await;
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_root = dir.path().join("var-lib");
    let http_bind = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_bind = next_addr(Ipv4Addr::LOCALHOST);
    let dataplane_iface = format!("nwtestb{}", std::process::id());
    let _cleanup = NetworkCleanup {
        dataplane_iface: dataplane_iface.clone(),
    };

    cleanup_service_lane_state();
    if let Err(err) = create_tun_interface(&dataplane_iface, "10.9.1.2/24") {
        eprintln!("skipping runtime by-name case: tun interface setup unavailable: {err}");
        return;
    }

    let _runtime_config = runtime_config_support::InstalledRuntimeConfig::install_tun(
        &tls_dir,
        http_bind,
        metrics_bind,
        &dataplane_iface,
        "10.0.0.0/24",
    )
    .unwrap();
    let mut child = spawn_neuwerk(&local_root).unwrap();

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(5))
        .await
        .unwrap();
    let client = http_client(&tls_dir).unwrap();
    wait_for_ready(&client, http_bind, true, Duration::from_secs(5))
        .await
        .unwrap();

    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(5))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing api keyset");
    let token = api_auth::mint_token(&keyset, "by-name-test", None, None).unwrap();

    let first_payload = serde_json::json!({
        "mode": "audit",
        "name": "ignored-body-name",
        "policy": {
            "default_policy": "deny",
            "source_groups": [
                {
                    "id": "sigterm",
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
    let create = client
        .put(format!(
            "https://{http_bind}/api/v1/policies/by-name/terraform-prod"
        ))
        .bearer_auth(&token.token)
        .json(&first_payload)
        .send()
        .await
        .unwrap();
    assert!(create.status().is_success());
    let created: serde_json::Value = create.json().await.unwrap();
    let created_id = created
        .get("id")
        .and_then(|value| value.as_str())
        .expect("missing created id")
        .to_string();
    assert_eq!(
        created.get("name").and_then(|value| value.as_str()),
        Some("terraform-prod")
    );

    let fetched = client
        .get(format!(
            "https://{http_bind}/api/v1/policies/by-name/TERRAFORM-prod"
        ))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(fetched.status().is_success());
    let fetched: serde_json::Value = fetched.json().await.unwrap();
    assert_eq!(
        fetched.get("id").and_then(|value| value.as_str()),
        Some(created_id.as_str())
    );

    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
    wait_for_ready_false_before_exit(&mut child, &client, http_bind, Duration::from_secs(3))
        .await
        .unwrap();
    wait_for_child_exit(&mut child, Duration::from_secs(10))
        .await
        .unwrap();
    wait_for_tcp_closed(http_bind, Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp_closed(metrics_bind, Duration::from_secs(5))
        .await
        .unwrap();

    let mut restarted = spawn_neuwerk(&local_root).unwrap();
    wait_for_ready(&client, http_bind, true, Duration::from_secs(5))
        .await
        .unwrap();

    let second_payload = serde_json::json!({
        "mode": "enforce",
        "policy": {
            "default_policy": "allow",
            "source_groups": []
        }
    });
    let update = client
        .put(format!(
            "https://{http_bind}/api/v1/policies/by-name/terraform-prod"
        ))
        .bearer_auth(&token.token)
        .json(&second_payload)
        .send()
        .await
        .unwrap();
    assert!(update.status().is_success());
    let updated: serde_json::Value = update.json().await.unwrap();
    assert_eq!(
        updated.get("id").and_then(|value| value.as_str()),
        Some(created_id.as_str())
    );
    assert_eq!(
        updated.get("name").and_then(|value| value.as_str()),
        Some("terraform-prod")
    );

    let listed = client
        .get(format!("https://{http_bind}/api/v1/policies"))
        .bearer_auth(&token.token)
        .send()
        .await
        .unwrap();
    assert!(listed.status().is_success());
    let records: Vec<serde_json::Value> = listed.json().await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].get("id").and_then(|value| value.as_str()),
        Some(created_id.as_str())
    );

    kill(Pid::from_raw(restarted.id() as i32), Signal::SIGTERM).unwrap();
    wait_for_child_exit(&mut restarted, Duration::from_secs(10))
        .await
        .unwrap();
}
