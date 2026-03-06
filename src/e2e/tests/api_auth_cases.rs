use super::*;

pub(super) fn api_health_ok(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async { http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await })
}

pub(super) fn api_auth_required(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let health = http_api_status(api_addr, &tls_dir, "/health", None).await?;
        if !health.is_success() {
            return Err(format!("unexpected health status: {health}"));
        }
        let policies = http_api_status(api_addr, &tls_dir, "/api/v1/policies", None).await?;
        if policies != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized, got {policies}"));
        }
        let _ = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        Ok(())
    })
}

pub(super) fn api_auth_token_login_whoami(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let login = http_auth_token_login(api_addr, &tls_dir, &token).await?;
        if login.sub != "e2e" {
            return Err(format!("unexpected token-login sub {}", login.sub));
        }
        let whoami = http_auth_whoami(api_addr, &tls_dir, &token).await?;
        if whoami.sub != "e2e" {
            return Err(format!("unexpected whoami sub {}", whoami.sub));
        }
        Ok(())
    })
}

pub(super) fn api_auth_cookie_login_whoami(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let client = http_api_client_with_cookie(&tls_dir)?;
        let resp = client
            .post(format!("https://{api_addr}/api/v1/auth/token-login"))
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| format!("auth token-login failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("auth token-login status {}", resp.status()));
        }
        let cookie = resp
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .ok_or_else(|| "missing auth cookie".to_string())?
            .to_string();
        let user = resp
            .json::<crate::e2e::services::AuthUser>()
            .await
            .map_err(|e| format!("auth token-login decode failed: {e}"))?;
        if user.sub != "e2e" {
            return Err(format!("unexpected token-login sub {}", user.sub));
        }
        let whoami = client
            .get(format!("https://{api_addr}/api/v1/auth/whoami"))
            .header(reqwest::header::COOKIE, cookie)
            .send()
            .await
            .map_err(|e| format!("auth whoami failed: {e}"))?;
        if !whoami.status().is_success() {
            return Err(format!("auth whoami status {}", whoami.status()));
        }
        let who = whoami
            .json::<crate::e2e::services::AuthUser>()
            .await
            .map_err(|e| format!("auth whoami decode failed: {e}"))?;
        if who.sub != "e2e" {
            return Err(format!("unexpected whoami sub {}", who.sub));
        }
        Ok(())
    })
}

pub(super) fn api_auth_rejects_expired(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let expired = api_auth_token_expired(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&expired)).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized, got {status}"));
        }
        Ok(())
    })
}

pub(super) fn api_auth_token_login_rate_limit_scoped(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let client = http_api_client_with_cookie(&tls_dir)?;
        for attempt in 0..20usize {
            let resp = client
                .post(format!("https://{api_addr}/api/v1/auth/token-login"))
                .json(&serde_json::json!({ "token": "invalid-token-a" }))
                .send()
                .await
                .map_err(|e| format!("token-login request failed: {e}"))?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
                return Err(format!(
                    "attempt {} expected unauthorized, got {}",
                    attempt + 1,
                    resp.status()
                ));
            }
        }

        let blocked = client
            .post(format!("https://{api_addr}/api/v1/auth/token-login"))
            .json(&serde_json::json!({ "token": "invalid-token-a" }))
            .send()
            .await
            .map_err(|e| format!("blocked token-login request failed: {e}"))?;
        if blocked.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(format!(
                "expected rate-limit status 429, got {}",
                blocked.status()
            ));
        }

        let different = client
            .post(format!("https://{api_addr}/api/v1/auth/token-login"))
            .json(&serde_json::json!({ "token": "invalid-token-b" }))
            .send()
            .await
            .map_err(|e| format!("different token-login request failed: {e}"))?;
        if different.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!(
                "expected unauthorized for different invalid token, got {}",
                different.status()
            ));
        }
        Ok(())
    })
}

pub(super) fn api_auth_rotation_keeps_old_tokens(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let mut client = auth_client(cfg).await?;
        let (active_kid, _) = client.list_keys().await?;
        let (old_token, _, _) = client
            .mint_token("e2e-rotate-old", None, Some(&active_kid), None)
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("expected ok before rotation, got {status}"));
        }

        let _ = client.rotate_key().await?;

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("old token rejected after rotation: {status}"));
        }

        let (new_token, _, _) = client
            .mint_token("e2e-rotate-new", None, None, None)
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&new_token)).await?;
        if !status.is_success() {
            return Err(format!("new token rejected after rotation: {status}"));
        }
        Ok(())
    })
}

pub(super) fn api_auth_retire_revokes_old_kid(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let mut client = auth_client(cfg).await?;

        let mut target_kid = None;
        let mut keys = client.list_keys().await?.1;
        if keys.len() < 2 {
            let _ = client.rotate_key().await?;
            keys = client.list_keys().await?.1;
        }
        for key in keys.iter() {
            if !key.signing && key.status == api_auth::ApiKeyStatus::Active {
                target_kid = Some(key.kid.clone());
                break;
            }
        }
        if target_kid.is_none() {
            let _ = client.rotate_key().await?;
            let keys = client.list_keys().await?.1;
            for key in keys.iter() {
                if !key.signing && key.status == api_auth::ApiKeyStatus::Active {
                    target_kid = Some(key.kid.clone());
                    break;
                }
            }
        }
        let target_kid =
            target_kid.ok_or_else(|| "no non-active key available to retire".to_string())?;

        let (old_token, _, _) = client
            .mint_token("e2e-retire-old", None, Some(&target_kid), None)
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("expected ok before retire, got {status}"));
        }

        client.retire_key(&target_kid).await?;

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized after retire, got {status}"));
        }

        let (new_token, _, _) = client
            .mint_token("e2e-retire-new", None, None, None)
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&new_token)).await?;
        if !status.is_success() {
            return Err(format!("new token rejected after retire: {status}"));
        }
        Ok(())
    })
}

pub(super) fn api_service_accounts_lifecycle(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let admin_token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;

        let account = http_create_service_account(
            api_addr,
            &tls_dir,
            "e2e-sa",
            Some("e2e service account"),
            Some(&admin_token),
        )
        .await?;
        if account.status != ServiceAccountStatus::Active {
            return Err(format!("expected active account, got {:?}", account.status));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let accounts =
                http_list_service_accounts(api_addr, &tls_dir, Some(&admin_token)).await?;
            if accounts.iter().any(|item| item.id == account.id) {
                break;
            }
            if Instant::now() >= deadline {
                return Err("service account not visible in list".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let token_resp = http_create_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some("primary"),
            Some("1h"),
            None,
            Some(&admin_token),
        )
        .await?;
        if token_resp.token_meta.service_account_id != account.id {
            return Err("token meta service account id mismatch".to_string());
        }
        if token_resp.token_meta.status != TokenStatus::Active {
            return Err(format!(
                "expected active token, got {:?}",
                token_resp.token_meta.status
            ));
        }
        if token_resp.token_meta.expires_at.is_none() {
            return Err("expected ttl token to include expires_at".to_string());
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&token_resp.token),
        )
        .await?;
        if !status.is_success() {
            return Err(format!("service account token rejected: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if tokens
                .iter()
                .any(|item| item.id == token_resp.token_meta.id)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("token not visible in list".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_revoke_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            &token_resp.token_meta.id.to_string(),
            Some(&admin_token),
        )
        .await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected revoke status: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if let Some(token) = tokens
                .iter()
                .find(|item| item.id == token_resp.token_meta.id)
            {
                if token.status == TokenStatus::Revoked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("token was not revoked".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&token_resp.token),
        )
        .await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized after revoke, got {status}"));
        }

        let eternal_resp = http_create_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some("eternal"),
            None,
            Some(true),
            Some(&admin_token),
        )
        .await?;
        if eternal_resp.token_meta.expires_at.is_some() {
            return Err("expected eternal token to omit expires_at".to_string());
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&eternal_resp.token),
        )
        .await?;
        if !status.is_success() {
            return Err(format!("eternal token rejected: {status}"));
        }

        let status = http_delete_service_account(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some(&admin_token),
        )
        .await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected delete status: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let accounts =
                http_list_service_accounts(api_addr, &tls_dir, Some(&admin_token)).await?;
            if let Some(item) = accounts.iter().find(|item| item.id == account.id) {
                if item.status == ServiceAccountStatus::Disabled {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("service account not marked disabled".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if let Some(token) = tokens
                .iter()
                .find(|item| item.id == eternal_resp.token_meta.id)
            {
                if token.status == TokenStatus::Revoked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("eternal token not revoked after account delete".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&eternal_resp.token),
        )
        .await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!(
                "expected unauthorized after account delete, got {status}"
            ));
        }

        Ok(())
    })
}
