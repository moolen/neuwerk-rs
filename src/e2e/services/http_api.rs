use super::*;

pub async fn http_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    http_get_path(addr, host, "/").await
}

pub async fn http_get_path(addr: SocketAddr, host: &str, path: &str) -> Result<String, String> {
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
            .await
            .map_err(|_| "http connect timed out".to_string())?
            .map_err(|e| format!("http connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("http read failed: {e}"))?;
    let text = String::from_utf8_lossy(&buf).to_string();
    Ok(text)
}

pub async fn http_api_health(addr: SocketAddr, tls_dir: &Path) -> Result<(), String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .get(format!("https://{addr}/health"))
        .send()
        .await
        .map_err(|e| format!("health request failed: {e}"))?;
    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("health status {}", resp.status()))
    }
}

pub async fn http_api_status(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client.get(format!("https://{addr}{path}"));
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("api status request failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_auth_token_login(
    addr: SocketAddr,
    tls_dir: &Path,
    token: &str,
) -> Result<AuthUser, String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .post(format!("https://{addr}/api/v1/auth/token-login"))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .map_err(|e| format!("auth token-login failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("auth token-login status {}", resp.status()));
    }
    resp.json::<AuthUser>()
        .await
        .map_err(|e| format!("auth token-login decode failed: {e}"))
}

pub async fn http_auth_whoami(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: &str,
) -> Result<AuthUser, String> {
    let client = http_api_client(tls_dir)?;
    let resp = client
        .get(format!("https://{addr}/api/v1/auth/whoami"))
        .bearer_auth(auth_token)
        .send()
        .await
        .map_err(|e| format!("auth whoami failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("auth whoami status {}", resp.status()));
    }
    resp.json::<AuthUser>()
        .await
        .map_err(|e| format!("auth whoami decode failed: {e}"))
}

pub async fn http_wait_for_health(
    addr: SocketAddr,
    tls_dir: &Path,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Ok(()) = http_api_health(addr, tls_dir).await {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for http api health".to_string());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

pub async fn http_set_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy: PolicyConfig,
    mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let req = PolicyCreateRequest { mode, policy };
    let mut builder = client
        .post(format!("https://{addr}/api/v1/policies"))
        .json(&req);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy post failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy post status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy decode failed: {e}"))
}

pub async fn http_list_policies(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Vec<PolicyRecord>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policies"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy list status {}", resp.status()));
    }
    resp.json::<Vec<PolicyRecord>>()
        .await
        .map_err(|e| format!("policy list decode failed: {e}"))
}

pub async fn http_get_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policies/{policy_id}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy get failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy get status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy get decode failed: {e}"))
}

pub async fn http_update_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    policy: PolicyConfig,
    mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<PolicyRecord, String> {
    let client = http_api_client(tls_dir)?;
    let req = PolicyCreateRequest { mode, policy };
    let mut builder = client
        .put(format!("https://{addr}/api/v1/policies/{policy_id}"))
        .json(&req);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy update failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy update status {}", resp.status()));
    }
    resp.json::<PolicyRecord>()
        .await
        .map_err(|e| format!("policy update decode failed: {e}"))
}

pub async fn http_delete_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!("https://{addr}/api/v1/policies/{policy_id}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy delete failed: {e}"))?;
    Ok(resp.status())
}

#[derive(Debug, Deserialize)]
pub struct ServiceAccountTokenResponse {
    pub token: String,
    pub token_meta: TokenMeta,
}

#[derive(Serialize)]
struct ServiceAccountCreateRequest<'a> {
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
}

#[derive(Serialize)]
struct ServiceAccountTokenCreateRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eternal: Option<bool>,
}

pub async fn http_create_service_account(
    addr: SocketAddr,
    tls_dir: &Path,
    name: &str,
    description: Option<&str>,
    auth_token: Option<&str>,
) -> Result<ServiceAccount, String> {
    let client = http_api_client(tls_dir)?;
    let payload = ServiceAccountCreateRequest { name, description };
    let mut builder = client
        .post(format!("https://{addr}/api/v1/service-accounts"))
        .json(&payload);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account create failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("service account create status {}", resp.status()));
    }
    resp.json::<ServiceAccount>()
        .await
        .map_err(|e| format!("service account decode failed: {e}"))
}

pub async fn http_list_service_accounts(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Vec<ServiceAccount>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/service-accounts"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("service account list status {}", resp.status()));
    }
    resp.json::<Vec<ServiceAccount>>()
        .await
        .map_err(|e| format!("service account list decode failed: {e}"))
}

pub async fn http_delete_service_account(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account delete failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_create_service_account_token(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    name: Option<&str>,
    ttl: Option<&str>,
    eternal: Option<bool>,
    auth_token: Option<&str>,
) -> Result<ServiceAccountTokenResponse, String> {
    let client = http_api_client(tls_dir)?;
    let payload = ServiceAccountTokenCreateRequest { name, ttl, eternal };
    let mut builder = client
        .post(format!(
            "https://{addr}/api/v1/service-accounts/{account_id}/tokens"
        ))
        .json(&payload);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token create failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "service account token create status {}",
            resp.status()
        ));
    }
    resp.json::<ServiceAccountTokenResponse>()
        .await
        .map_err(|e| format!("service account token decode failed: {e}"))
}

pub async fn http_list_service_account_tokens(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    auth_token: Option<&str>,
) -> Result<Vec<TokenMeta>, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}/tokens"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!(
            "service account token list status {}",
            resp.status()
        ));
    }
    resp.json::<Vec<TokenMeta>>()
        .await
        .map_err(|e| format!("service account token list decode failed: {e}"))
}

pub async fn http_revoke_service_account_token(
    addr: SocketAddr,
    tls_dir: &Path,
    account_id: &str,
    token_id: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!(
        "https://{addr}/api/v1/service-accounts/{account_id}/tokens/{token_id}"
    ));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("service account token revoke failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_get_dns_cache(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<DnsCacheResponse, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/dns-cache"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("dns cache request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("dns cache status {}", resp.status()));
    }
    resp.json::<DnsCacheResponse>()
        .await
        .map_err(|e| format!("dns cache decode failed: {e}"))
}

pub async fn http_get_stats(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<Value, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/stats"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("stats request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("stats status {}", resp.status()));
    }
    resp.json::<Value>()
        .await
        .map_err(|e| format!("stats decode failed: {e}"))
}

pub async fn http_get_audit_findings(
    addr: SocketAddr,
    tls_dir: &Path,
    query: Option<&str>,
    auth_token: Option<&str>,
) -> Result<AuditQueryResponse, String> {
    let client = http_api_client(tls_dir)?;
    let suffix = query
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("?{value}"))
        .unwrap_or_default();
    let mut builder = client.get(format!("https://{addr}/api/v1/audit/findings{suffix}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("audit findings request failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("audit findings status {status}: {body}"));
    }
    resp.json::<AuditQueryResponse>()
        .await
        .map_err(|e| format!("audit findings decode failed: {e}"))
}

pub async fn http_put_tls_intercept_ca_from_http_ca(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<(), String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "E2E Intercept CA");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = Certificate::from_params(params)
        .map_err(|e| format!("intercept ca certificate generation failed: {e}"))?;
    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| format!("intercept ca pem encode failed: {e}"))?;
    let key_der = cert.serialize_private_key_der();
    let payload = serde_json::json!({
        "ca_cert_pem": cert_pem,
        "ca_key_der_b64": base64::engine::general_purpose::STANDARD.encode(key_der),
    });

    let client = http_api_client(tls_dir)?;
    let mut builder = client
        .put(format!("https://{addr}/api/v1/settings/tls-intercept-ca"))
        .json(&payload);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("intercept ca put failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(format!("intercept ca put status {status}: {body}"))
}

pub async fn http_delete_tls_intercept_ca(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<(), String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.delete(format!("https://{addr}/api/v1/settings/tls-intercept-ca"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("intercept ca delete failed: {e}"))?;
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(format!("intercept ca delete status {status}: {body}"))
}

fn http_api_client(tls_dir: &Path) -> Result<Client, String> {
    let ca = std::fs::read(tls_dir.join("ca.crt"))
        .map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca =
        reqwest::Certificate::from_pem(&ca).map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

pub fn http_api_client_with_cookie(tls_dir: &Path) -> Result<Client, String> {
    let ca = std::fs::read(tls_dir.join("ca.crt"))
        .map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca =
        reqwest::Certificate::from_pem(&ca).map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

pub async fn http_api_post_raw(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    body: Vec<u8>,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client
        .post(format!("https://{addr}{path}"))
        .header("content-type", "application/json")
        .body(body);
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("api post request failed: {e}"))?;
    Ok(resp.status())
}

pub async fn http_stream(
    addr: SocketAddr,
    host: &str,
    min_duration: std::time::Duration,
    max_duration: std::time::Duration,
) -> Result<usize, String> {
    http_stream_path(addr, host, "/stream", min_duration, max_duration).await
}

pub async fn http_stream_path(
    addr: SocketAddr,
    host: &str,
    path: &str,
    min_duration: std::time::Duration,
    max_duration: std::time::Duration,
) -> Result<usize, String> {
    let mut stream = tokio::time::timeout(max_duration, TcpStream::connect(addr))
        .await
        .map_err(|_| "http stream connect timed out".to_string())?
        .map_err(|e| format!("http stream connect failed: {e}"))?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http stream write failed: {e}"))?;

    let start = std::time::Instant::now();
    let read_result = tokio::time::timeout(max_duration, async {
        let mut buf = [0u8; 512];
        let mut total = 0usize;
        loop {
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n;
        }
        Ok::<usize, String>(total)
    })
    .await;

    let total = match read_result {
        Ok(Ok(total)) => total,
        Ok(Err(err)) => return Err(format!("http stream read failed: {err}")),
        Err(_) => return Err("http stream timed out".to_string()),
    };

    if start.elapsed() < min_duration {
        return Err(format!(
            "http stream ended too early after {:?}",
            start.elapsed()
        ));
    }

    Ok(total)
}
