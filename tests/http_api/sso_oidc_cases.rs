use super::*;

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use neuwerk::controlplane::sso::{SsoDiskStore, SsoProvider, SsoProviderKind, SsoRole};
use uuid::Uuid;

struct DexProcess {
    child: Child,
}

impl Drop for DexProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn http_api_sso_oidc_dex_full_flow() {
    ensure_rustls_provider();
    let Some(dex_bin) = resolve_dex_binary() else {
        if sso_require_dex() {
            panic!("dex binary not found (set DEX_BIN or add dex to PATH)");
        }
        eprintln!("skipping dex flow test: dex binary not found (set DEX_BIN or add dex to PATH)");
        return;
    };

    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let dex_addr = next_addr(Ipv4Addr::LOCALHOST);

    let provider_id = Uuid::new_v4();
    let redirect_uri = format!("https://{bind_addr}/api/v1/auth/sso/{provider_id}/callback");
    let dex_issuer = format!("http://{dex_addr}");

    let _dex = start_dex(
        &dex_bin,
        dir.path().join("dex-config.yaml"),
        dex_addr,
        &dex_issuer,
        "neuwerk-client",
        "neuwerk-secret",
        &redirect_uri,
    )
    .await
    .expect("start dex");

    let mut provider = SsoProvider::new(
        "Google via Dex".to_string(),
        SsoProviderKind::Google,
        "neuwerk-client".to_string(),
        "neuwerk-secret".to_string(),
    )
    .unwrap();
    provider.id = provider_id;
    provider.issuer_url = Some(dex_issuer.clone());
    provider.default_role = Some(SsoRole::Readonly);

    let sso_store = SsoDiskStore::new(dir.path().join("sso"));
    sso_store.write_provider(&provider).unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: Some(format!("https://{bind_addr}")),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

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
            Metrics::new().unwrap(),
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let client = http_cookie_client(&tls_dir).unwrap();

    let providers_resp = client
        .get(format!("https://{bind_addr}/api/v1/auth/sso/providers"))
        .send()
        .await
        .unwrap();
    assert_eq!(providers_resp.status(), reqwest::StatusCode::OK);

    let start_resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/auth/sso/{provider_id}/start?next=%2F"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(start_resp.status(), reqwest::StatusCode::FOUND);

    let dex_auth_url = redirect_location(start_resp.url().as_str(), &start_resp).unwrap();
    let callback_prefix = format!("https://{bind_addr}/api/v1/auth/sso/{provider_id}/callback");
    let callback_url = complete_dex_login_flow(
        &client,
        &dex_auth_url,
        &callback_prefix,
        "sso@example.com",
        "password",
    )
    .await
    .expect("dex auth flow");

    let callback_resp = client.get(callback_url).send().await.unwrap();
    assert_eq!(callback_resp.status(), reqwest::StatusCode::FOUND);
    assert_eq!(
        callback_resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok()),
        Some("/")
    );

    let whoami = client
        .get(format!("https://{bind_addr}/api/v1/auth/whoami"))
        .send()
        .await
        .unwrap();
    assert_eq!(whoami.status(), reqwest::StatusCode::OK);
    let whoami: serde_json::Value = whoami.json().await.unwrap();
    let subject = whoami
        .get("sub")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(subject.starts_with(&format!("sso:{provider_id}:")));

    let roles = whoami
        .get("roles")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(roles.iter().any(|value| value.as_str() == Some("readonly")));

    let denied_mutation = client
        .post(format!("https://{bind_addr}/api/v1/policies"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_mutation.status(), reqwest::StatusCode::FORBIDDEN);

    server.abort();
}

#[tokio::test]
async fn http_api_sso_state_tamper_is_denied() {
    ensure_rustls_provider();

    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);

    let provider_id = Uuid::new_v4();
    let mut provider = SsoProvider::new(
        "GitHub".to_string(),
        SsoProviderKind::Github,
        "client-id".to_string(),
        "client-secret".to_string(),
    )
    .unwrap();
    provider.id = provider_id;
    provider.authorization_url = Some("http://127.0.0.1:5556/auth".to_string());
    provider.token_url = Some("http://127.0.0.1:5556/token".to_string());
    provider.userinfo_url = Some("http://127.0.0.1:5556/user".to_string());

    let sso_store = SsoDiskStore::new(dir.path().join("sso"));
    sso_store.write_provider(&provider).unwrap();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        allow_public_metrics_bind: false,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: Some(format!("https://{bind_addr}")),
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };

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
            Metrics::new().unwrap(),
        )
        .await
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(5))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(5))
        .await
        .unwrap();

    let client = http_cookie_client(&tls_dir).unwrap();

    let start_resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/auth/sso/{provider_id}/start"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(start_resp.status(), reqwest::StatusCode::FOUND);

    let callback_resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/auth/sso/{provider_id}/callback?code=fake&state=tampered"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(callback_resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let set_cookie = callback_resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(set_cookie.contains("neuwerk_sso=; Max-Age=0"));

    server.abort();
}

fn resolve_dex_binary() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("DEX_BIN") {
        let pb = PathBuf::from(path);
        if pb.exists() {
            return Some(pb);
        }
    }

    let which = Command::new("sh")
        .arg("-lc")
        .arg("command -v dex")
        .output()
        .ok()?;
    if !which.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&which.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn sso_require_dex() -> bool {
    matches!(
        std::env::var("NEUWERK_SSO_REQUIRE_DEX")
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn start_dex(
    dex_bin: &PathBuf,
    config_path: PathBuf,
    bind_addr: SocketAddr,
    issuer: &str,
    client_id: &str,
    client_secret: &str,
    redirect_uri: &str,
) -> Result<DexProcess, String> {
    let config = format!(
        r#"issuer: {issuer}
storage:
  type: memory
web:
  http: {bind_addr}
oauth2:
  skipApprovalScreen: true
enablePasswordDB: true
staticPasswords:
- email: "sso@example.com"
  hash: "$2a$10$pddyt9Cul8KaquYvS3n2oewp0AlSRwEk5G4sGOehVlcQ86MLouXgG"
  username: "sso-user"
  userID: "user-1"
staticClients:
- id: "{client_id}"
  redirectURIs:
  - "{redirect_uri}"
  name: "neuwerk"
  secret: "{client_secret}"
"#
    );
    fs::write(&config_path, config).map_err(|err| format!("write dex config failed: {err}"))?;

    let log_path = config_path.with_extension("log");
    let log_file =
        std::fs::File::create(&log_path).map_err(|err| format!("create dex log failed: {err}"))?;
    let log_file_out = log_file
        .try_clone()
        .map_err(|err| format!("clone dex log failed: {err}"))?;

    let mut child = Command::new(dex_bin)
        .arg("serve")
        .arg(&config_path)
        .stdout(Stdio::from(log_file_out))
        .stderr(Stdio::from(log_file))
        .spawn()
        .map_err(|err| format!("spawn dex failed: {err}"))?;

    let startup_timeout_secs = std::env::var("DEX_STARTUP_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(30);
    let discovery = format!("{issuer}/.well-known/openid-configuration");
    let deadline = Instant::now() + Duration::from_secs(startup_timeout_secs);
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .map_err(|err| format!("build discovery client failed: {err}"))?;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("poll dex process failed: {err}"))?
        {
            let logs = fs::read_to_string(&log_path).unwrap_or_default();
            return Err(format!(
                "dex exited before discovery became ready (status {status}); logs:\n{logs}"
            ));
        }

        match client.get(&discovery).send().await {
            Ok(resp) if resp.status().is_success() => break,
            _ => {
                if Instant::now() >= deadline {
                    let logs = fs::read_to_string(&log_path).unwrap_or_default();
                    return Err(format!(
                        "timed out waiting for dex discovery endpoint after {}s; logs:\n{}",
                        startup_timeout_secs, logs
                    ));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }

    Ok(DexProcess { child })
}

fn http_cookie_client(tls_dir: &Path) -> Result<reqwest::Client, String> {
    let ca = fs::read(tls_dir.join("ca.crt"))
        .map_err(|err| format!("read http ca cert failed: {err}"))?;
    let ca = reqwest::Certificate::from_pem(&ca)
        .map_err(|err| format!("invalid http ca cert: {err}"))?;
    reqwest::Client::builder()
        .add_root_certificate(ca)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| format!("http client build failed: {err}"))
}

fn redirect_location(base: &str, response: &reqwest::Response) -> Result<String, String> {
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| "redirect missing location header".to_string())?;
    resolve_relative(base, location)
}

fn resolve_relative(base: &str, location: &str) -> Result<String, String> {
    let base = reqwest::Url::parse(base).map_err(|err| format!("invalid base url: {err}"))?;
    let location = location.replace("&amp;", "&");
    base.join(&location)
        .map(|value| value.to_string())
        .map_err(|err| format!("invalid redirect location: {err}"))
}

async fn complete_dex_login_flow(
    client: &reqwest::Client,
    auth_url: &str,
    callback_prefix: &str,
    login: &str,
    password: &str,
) -> Result<String, String> {
    let mut response = client
        .get(auth_url)
        .send()
        .await
        .map_err(|err| format!("dex authorize request failed: {err}"))?;

    for _ in 0..16 {
        if response.status().is_redirection() {
            let next = redirect_location(response.url().as_str(), &response)?;
            if next.starts_with(callback_prefix) {
                return Ok(next);
            }
            response = client
                .get(next)
                .send()
                .await
                .map_err(|err| format!("dex redirect request failed: {err}"))?;
            continue;
        }

        let page_url = response.url().to_string();
        let body = response
            .text()
            .await
            .map_err(|err| format!("dex html read failed: {err}"))?;

        if body.contains("name=\"login\"") && body.contains("name=\"password\"") {
            let action_url = match extract_form_action(&body) {
                Some(action) => resolve_relative(&page_url, &action)?,
                None => page_url.clone(),
            };
            response = client
                .post(action_url)
                .form(&[("login", login), ("password", password)])
                .send()
                .await
                .map_err(|err| format!("dex login submit failed: {err}"))?;
            continue;
        }

        if body.contains("name=\"approval\"") {
            let action_url = match extract_form_action(&body) {
                Some(action) => resolve_relative(&page_url, &action)?,
                None => page_url.clone(),
            };
            response = client
                .post(action_url)
                .form(&[("approval", "approve")])
                .send()
                .await
                .map_err(|err| format!("dex approval submit failed: {err}"))?;
            continue;
        }

        return Err(format!(
            "unexpected dex response while completing login flow at {page_url}"
        ));
    }

    Err("dex flow exceeded redirect/form step budget".to_string())
}

fn extract_form_action(html: &str) -> Option<String> {
    let markers = ["action=\"", "action='", "action="];
    for marker in markers {
        if let Some(idx) = html.find(marker) {
            let rest = &html[idx + marker.len()..];
            let value = if marker == "action=\"" {
                let end = rest.find('"')?;
                &rest[..end]
            } else if marker == "action='" {
                let end = rest.find('\'')?;
                &rest[..end]
            } else {
                let end = rest
                    .find(|c: char| c.is_whitespace() || c == '>')
                    .unwrap_or(rest.len());
                &rest[..end]
            };
            return Some(value.to_string());
        }
    }
    None
}
