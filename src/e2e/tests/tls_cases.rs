use super::*;

pub(super) fn http_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match http_get(http_addr, "foo.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "http denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

pub(super) fn udp_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match udp_echo(
            bind,
            server,
            b"denied",
            std::time::Duration::from_millis(500),
        )
        .await
        {
            Ok(_) => Err("udp unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "udp denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

pub(super) fn https_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match https_get(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "https denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

pub(super) fn tls_sni_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls12(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_sni_allows_https_tls13(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls13(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_sni_denies_https(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "bar.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls12(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded with sni mismatch".to_string()),
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn tls_cert_tls12_allows(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy(cfg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls12(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_cert_tls12_denies_san_mismatch(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy_with(cfg, "bar.allowed", "deny")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls12(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded with SAN mismatch".to_string()),
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn tls_cert_tls13_denied(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy(cfg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls13(https_addr, "foo.allowed").await {
            Ok(_) => {
                Err("https unexpectedly succeeded on tls1.3 with cert constraints".to_string())
            }
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn tls_cert_tls13_allows(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy_with(cfg, "foo.allowed", "allow")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls13(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_reassembly_client_hello(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let read = tls_client_hello_raw(https_addr, "foo.allowed", 2000).await?;
        if read == 0 {
            return Err("tls raw client hello did not receive response".to_string());
        }
        Ok(())
    })
}

pub(super) fn tls_intercept_http_allow(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let resp = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_intercept_http_deny_rst(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let deny_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match assert_https_path_denied_with_rst(
                cfg.client_dp_ip,
                cfg.up_dp_ip,
                https_addr,
                "foo.allowed",
                "/moolen",
            )
            .await
            {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if Instant::now() >= deny_deadline {
                        return Err(format!(
                            "tls intercept deny path did not fail-closed after CA rotation: {}",
                            err
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    })
}

pub(super) fn tls_intercept_response_header_deny_rst(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy_with_response_deny(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        assert_https_path_denied_with_rst(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            https_addr,
            "foo.allowed",
            "/external-secrets/forbidden-response",
        )
        .await
    })
}

pub(super) fn tls_intercept_h2_allow(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let resp = https_h2_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets?ref=main",
        )
        .await?;
        if !resp.starts_with("HTTP/2 200") {
            return Err(format!("unexpected h2 response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

pub(super) fn tls_intercept_h2_concurrency_smoke(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;

        const CONCURRENCY: usize = 8;
        const ROUNDS: usize = 3;
        for _round in 0..ROUNDS {
            let mut workers = Vec::with_capacity(CONCURRENCY);
            for _idx in 0..CONCURRENCY {
                workers.push(tokio::spawn(async move {
                    let mut last_err = String::new();
                    for _attempt in 0..5 {
                        match https_h2_get_path(
                            https_addr,
                            "foo.allowed",
                            "/external-secrets/external-secrets?ref=main",
                        )
                        .await
                        {
                            Ok(resp) => return Ok::<String, String>(resp),
                            Err(err) if looks_like_reset(&err) => {
                                last_err = err;
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Err(format!(
                        "h2 allow path retries exhausted with reset-like errors: {last_err}"
                    ))
                }));
            }
            for worker in workers {
                let resp = worker
                    .await
                    .map_err(|e| format!("h2 worker join failed: {e}"))??;
                if !resp.starts_with("HTTP/2 200") {
                    return Err(format!(
                        "unexpected h2 response during concurrency smoke: {}",
                        first_line(&resp)
                    ));
                }
            }
        }

        match https_h2_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => Err(format!(
                "intercept h2 deny expected failure after load, got response: {}",
                first_line(&resp)
            )),
            Err(err) if looks_like_reset(&err) => Ok(()),
            Err(err) => Err(format!(
                "intercept h2 deny expected reset/close after load, got different failure: {err}"
            )),
        }
    })
}

pub(super) fn tls_intercept_ca_rotation_reloads_runtime(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;

        let initial_fingerprint = https_leaf_cert_sha256(https_addr, "foo.allowed").await?;
        let baseline = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !baseline.starts_with("HTTP/1.1 200") {
            return Err(format!(
                "unexpected baseline https response: {}",
                first_line(&baseline)
            ));
        }

        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut rotated = false;
        let mut last = String::new();
        while Instant::now() < deadline {
            match https_leaf_cert_sha256(https_addr, "foo.allowed").await {
                Ok(fingerprint) => {
                    if fingerprint != initial_fingerprint {
                        rotated = true;
                        break;
                    }
                }
                Err(err) => {
                    last = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !rotated {
            return Err(format!(
                "tls intercept CA rotation did not change served leaf cert fingerprint within timeout (last error: {last})"
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut allow_ok = false;
        let mut last_allow = String::new();
        while Instant::now() < deadline {
            match https_get_path(https_addr, "foo.allowed", "/external-secrets/external-secrets")
                .await
            {
                Ok(resp) if resp.starts_with("HTTP/1.1 200") => {
                    allow_ok = true;
                    break;
                }
                Ok(resp) => {
                    last_allow = format!("unexpected response {}", first_line(&resp));
                }
                Err(err) => {
                    last_allow = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !allow_ok {
            return Err(format!(
                "tls intercept allow path failed after CA rotation: {last_allow}"
            ));
        }

        assert_https_path_denied_with_rst(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            https_addr,
            "foo.allowed",
            "/moolen",
        )
        .await
    })
}

pub(super) fn tls_intercept_h2_deny_fail_closed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        match https_h2_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => Err(format!(
                "intercept h2 deny expected failure, got response: {}",
                first_line(&resp)
            )),
            Err(err) => {
                if looks_like_reset(&err) {
                    Ok(())
                } else {
                    Err(format!(
                        "intercept h2 deny expected reset/close, got different failure: {err}"
                    ))
                }
            }
        }
    })
}

pub(super) fn tls_intercept_service_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let allow = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !allow.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected allow response: {}", first_line(&allow)));
        }
        match https_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => {
                return Err(format!(
                    "intercept deny expected reset/failure, got response: {}",
                    first_line(&resp)
                ));
            }
            Err(err) if looks_like_reset(&err) => {}
            Err(err) => {
                return Err(format!(
                    "intercept deny expected reset/refused, got different failure: {err}"
                ));
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;

        let tls_allow = metric_value_with_labels(
            &body,
            "svc_tls_intercept_flows_total",
            &[("result", "allow")],
        )
        .ok_or_else(|| "missing svc tls allow metrics".to_string())?;
        if tls_allow < 1.0 {
            return Err("svc tls allow metrics did not increment".to_string());
        }
        let tls_deny = metric_value_with_labels(
            &body,
            "svc_tls_intercept_flows_total",
            &[("result", "deny")],
        )
        .ok_or_else(|| "missing svc tls deny metrics".to_string())?;
        if tls_deny < 1.0 {
            return Err("svc tls deny metrics did not increment".to_string());
        }
        let http_allow = metric_value_with_labels(
            &body,
            "svc_http_requests_total",
            &[("proto", "http1"), ("decision", "allow")],
        )
        .ok_or_else(|| "missing svc http allow metrics".to_string())?;
        if http_allow < 1.0 {
            return Err("svc http allow metrics did not increment".to_string());
        }
        let http_deny = metric_value_with_labels(
            &body,
            "svc_http_denies_total",
            &[
                ("proto", "http1"),
                ("phase", "request"),
                ("reason", "policy"),
            ],
        )
        .ok_or_else(|| "missing svc http deny metrics".to_string())?;
        if http_deny < 1.0 {
            return Err("svc http deny metrics did not increment".to_string());
        }
        let rst = metric_value_with_labels(
            &body,
            "svc_policy_rst_total",
            &[("reason", "request_policy")],
        )
        .ok_or_else(|| "missing svc policy rst metrics".to_string())?;
        if rst < 1.0 {
            return Err("svc policy rst metrics did not increment".to_string());
        }
        let fail_closed =
            metric_value_with_labels(&body, "svc_fail_closed_total", &[("component", "tls")])
                .ok_or_else(|| "missing svc fail-closed metrics".to_string())?;
        if fail_closed < 1.0 {
            return Err("svc fail-closed metrics did not increment".to_string());
        }

        Ok(())
    })
}

async fn assert_https_path_denied_with_rst(
    client_ip: Ipv4Addr,
    upstream_ip: Ipv4Addr,
    https_addr: SocketAddr,
    host: &str,
    path: &str,
) -> Result<(), String> {
    let tcp_fd = open_tcp_raw_socket(client_ip, Duration::from_secs(2))?;
    let request = https_get_path(https_addr, host, path).await;
    let rst_capture = wait_for_tcp_rst_on_fd(
        tcp_fd,
        upstream_ip,
        client_ip,
        Some(443),
        None,
        Duration::from_secs(2),
    );
    unsafe {
        libc::close(tcp_fd);
    }
    match request {
        Ok(resp) => Err(format!(
            "intercept deny expected reset/failure, got response: {}",
            first_line(&resp)
        )),
        Err(err) => {
            if !looks_like_reset(&err) {
                return Err(format!(
                    "intercept deny expected reset/refused, got different failure: {err}"
                ));
            }
            rst_capture.map(|_| ())
        }
    }
}
