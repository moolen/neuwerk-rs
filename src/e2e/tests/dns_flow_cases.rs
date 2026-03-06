use super::*;

pub(super) fn dns_allows_http(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let dns_start = std::time::Instant::now();
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        println!("dns response in {:?}: {:?}", dns_start.elapsed(), ips);
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http_start = std::time::Instant::now();
        let http = http_get(http_addr, "foo.allowed").await?;
        println!("http request completed in {:?}", http_start.elapsed());
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        let https_start = std::time::Instant::now();
        let https = {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                match https_get(https_addr, "foo.allowed").await {
                    Ok(resp) => break resp,
                    Err(err) if looks_like_reset(&err) => {
                        if std::time::Instant::now() >= deadline {
                            return Err(format!(
                                "https retries exhausted after policy transition: {err}"
                            ));
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                    Err(err) => return Err(err),
                }
            }
        };
        println!("https request completed in {:?}", https_start.elapsed());
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }

        Ok(())
    })
}

pub(super) fn dns_allows_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let payload = b"udp-allowed";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }
        Ok(())
    })
}

pub(super) fn dns_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let https = https_get(https_addr, "foo.allowed").await?;
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }
        Ok(())
    })
}

pub(super) fn dns_tcp_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response_tcp(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;

        let https = https_get(https_addr, "foo.allowed").await?;
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }
        Ok(())
    })
}

pub(super) fn dns_tcp_blocks_nonmatch(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response_tcp(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;

        match http_get(http_addr, "bar.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded after dns tcp NXDOMAIN".to_string()),
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn dns_regex_allows_example(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "api.example.com").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn dns_regex_blocks_nonmatch(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

pub(super) fn dns_source_group_allows_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip_alt), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn dns_source_group_blocks_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip_alt), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

pub(super) fn dns_case_insensitive_match(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "FoO.AlLoWeD.").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn dns_upstream_failover_allows_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_spoof())?;

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
        tokio::time::sleep(Duration::from_millis(150)).await;

        let resp = dns_query_response(client_bind, dns_server, "spoof.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let mismatch = metric_value_with_labels(
            &body,
            "dns_upstream_mismatch_total",
            &[("reason", "txid"), ("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream mismatch metrics".to_string())?;
        if mismatch < 1.0 {
            return Err("dns upstream mismatch metrics did not increment".to_string());
        }
        let rtt_count = metric_value_with_labels(
            &body,
            "dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream rtt metrics".to_string())?;
        if rtt_count < 1.0 {
            return Err("dns upstream rtt metrics did not increment".to_string());
        }
        Ok(())
    })
}

pub(super) fn dns_upstream_mismatch_nxdomain(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_spoof())?;

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
        tokio::time::sleep(Duration::from_millis(150)).await;

        let resp = dns_query_response(client_bind, dns_server, "spoof-fail.allowed").await?;
        assert_dns_nxdomain(&resp)?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let mismatch = metric_value_with_labels(
            &body,
            "dns_upstream_mismatch_total",
            &[("reason", "txid"), ("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream mismatch metrics".to_string())?;
        if mismatch < 1.0 {
            return Err("dns upstream mismatch metrics did not increment".to_string());
        }
        Ok(())
    })
}

pub(super) fn dns_long_name_match(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let resp = dns_query_response(
            client_bind,
            dns_server,
            "very.long.subdomain.name.example.com",
        )
        .await?;
        if resp.rcode != 0 {
            let metrics = http_get_path(metrics_addr, "metrics", "/metrics")
                .await
                .unwrap_or_else(|err| format!("metrics fetch failed: {err}"));
            let policy_deny = metric_value_with_labels(
                &metrics,
                "dns_queries_total",
                &[
                    ("result", "deny"),
                    ("reason", "policy_deny"),
                    ("source_group", "client-primary"),
                ],
            )
            .unwrap_or(0.0);
            let mismatch = metric_value_with_labels(
                &metrics,
                "dns_queries_total",
                &[
                    ("result", "deny"),
                    ("reason", "upstream_mismatch"),
                    ("source_group", "client-primary"),
                ],
            )
            .unwrap_or(0.0);
            let nxdomain_policy = metric_value_with_labels(
                &metrics,
                "dns_nxdomain_total",
                &[("source", "policy")],
            )
            .unwrap_or(0.0);
            let nxdomain_upstream = metric_value_with_labels(
                &metrics,
                "dns_nxdomain_total",
                &[("source", "upstream")],
            )
            .unwrap_or(0.0);
            return Err(format!(
                "dns response unexpected rcode: {}; policy_deny={}, upstream_mismatch={}, nxdomain_policy={}, nxdomain_upstream={}",
                resp.rcode, policy_deny, mismatch, nxdomain_policy, nxdomain_upstream
            ));
        }
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn dns_wildcard_allows_allowed_suffix(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "baz.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn dns_deny_overrides_wildcard(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

pub(super) fn udp_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let payload_a = b"flow-a";
        let payload_b = b"flow-b";
        let fut_a = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_a,
            std::time::Duration::from_secs(1),
        );
        let fut_b = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_b,
            std::time::Duration::from_secs(1),
        );

        let (resp_a, resp_b) = tokio::join!(fut_a, fut_b);
        let resp_a = resp_a?;
        let resp_b = resp_b?;
        if resp_a != payload_a || resp_b != payload_b {
            return Err("udp multi-flow payload mismatch".to_string());
        }
        Ok(())
    })
}

pub(super) fn udp_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut sockets = Vec::new();
        for i in 0..8usize {
            let socket = tokio::net::UdpSocket::bind((IpAddr::V4(cfg.client_dp_ip), 0u16))
                .await
                .map_err(|e| format!("udp bind failed: {e}"))?;
            let payload = format!("flow-{i}").into_bytes();
            socket
                .send_to(&payload, udp_server)
                .await
                .map_err(|e| format!("udp send failed: {e}"))?;
            sockets.push((socket, payload));
        }

        let mut handles = Vec::new();
        for (socket, payload) in sockets {
            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let (len, _) = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    socket.recv_from(&mut buf),
                )
                .await
                .map_err(|_| "udp recv timed out".to_string())?
                .map_err(|e| format!("udp recv failed: {e}"))?;
                if buf[..len] != payload[..] {
                    return Err("udp reverse nat payload mismatch".to_string());
                }
                Ok(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("udp task failed: {err}")),
            }
        }

        Ok(())
    })
}

pub(super) fn tcp_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut handles = Vec::new();
        for i in 0..8usize {
            let path = format!("/echo/flow-{i}");
            let expected = format!("flow-{i}");
            let handle = tokio::spawn(async move {
                let resp = http_get_path(http_addr, "foo.allowed", &path).await?;
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
                if body != expected {
                    return Err(format!("tcp reverse nat mismatch for {path}: {body}"));
                }
                Ok::<(), String>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("tcp task failed: {err}")),
            }
        }

        Ok(())
    })
}

pub(super) fn https_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut handles = Vec::new();
        for i in 0..8usize {
            let path = format!("/echo/flow-{i}");
            let expected = format!("flow-{i}");
            let handle = tokio::spawn(async move {
                let resp = https_get_path(https_addr, "foo.allowed", &path).await?;
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
                if body != expected {
                    return Err(format!("https reverse nat mismatch for {path}: {body}"));
                }
                Ok::<(), String>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("https task failed: {err}")),
            }
        }

        Ok(())
    })
}

pub(super) fn stream_keeps_nat_alive(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let total = http_stream(
            http_addr,
            "foo.allowed",
            std::time::Duration::from_millis(1500),
            std::time::Duration::from_secs(5),
        )
        .await?;
        if total == 0 {
            return Err("stream returned no data".to_string());
        }
        Ok(())
    })
}

pub(super) fn dns_allowlist_gc_evicts_idle(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let deny_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 9999);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http = http_get(http_addr, "foo.allowed").await?;
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        tokio::time::sleep(std::time::Duration::from_secs(
            cfg.idle_timeout_secs.saturating_add(2),
        ))
        .await;
        let _ = udp_echo(
            udp_bind,
            deny_server,
            b"gc-probe",
            std::time::Duration::from_millis(200),
        )
        .await;
        tokio::time::sleep(allowlist_gc_delay(cfg)).await;

        match http_get(http_addr, "foo.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded after allowlist GC".to_string()),
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn dns_allowlist_gc_keeps_active_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let stream = tokio::spawn(http_stream_path(
            http_addr,
            "foo.allowed",
            "/stream-long",
            std::time::Duration::from_secs(4),
            std::time::Duration::from_secs(10),
        ));

        tokio::time::sleep(allowlist_gc_delay(cfg)).await;

        let payload = b"gc-keepalive";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        match stream.await {
            Ok(Ok(total)) if total > 0 => Ok(()),
            Ok(Ok(_)) => Err("stream returned no data".to_string()),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(format!("stream task failed: {err}")),
        }
    })
}
