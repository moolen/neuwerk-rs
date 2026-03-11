#![allow(clippy::disallowed_names)]

use super::*;

pub(super) fn cluster_policy_update_applies(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let http_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 80);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
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
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Allow DNS allowlist GC to clear any entries created before policy applied.
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        tokio::time::sleep(Duration::from_secs(cfg.idle_timeout_secs + 2)).await;
        let dp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let evict_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port + 1);
        send_udp_once(dp_bind, evict_addr, b"evict")?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster.rcode != 0 || cluster.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy update".to_string());
        }

        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("http to cluster.allowed failed after policy update".to_string());
        }

        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("http to foo.allowed succeeded after deny update".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

pub(super) fn cluster_policy_update_denies_existing_flow(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
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
            baseline_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if foo.rcode != 0 || foo.ips.is_empty() {
            return Err("foo.allowed DNS did not resolve before policy update".to_string());
        }

        let dp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let socket = UdpSocket::bind(dp_bind)
            .await
            .map_err(|e| format!("udp bind failed: {e}"))?;

        socket
            .send_to(b"before", udp_server)
            .await
            .map_err(|e| format!("udp send before failed: {e}"))?;
        let mut buf = vec![0u8; 2048];
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .map_err(|_| "udp recv before timed out".to_string())?
            .map_err(|e| format!("udp recv before failed: {e}"))?;

        http_set_policy(
            api_addr,
            &tls_dir,
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        socket
            .send_to(b"after", udp_server)
            .await
            .map_err(|e| format!("udp send after failed: {e}"))?;
        match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((_len, _))) => {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err("udp to foo.allowed succeeded after deny update".to_string());
            }
            Ok(Err(err)) => {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err(format!("udp recv after failed: {err}"));
            }
            Err(_) => {}
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

pub(super) fn cluster_policy_update_https_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 443);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
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
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;

        let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster.rcode != 0 || cluster.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy update".to_string());
        }

        let https_resp = https_get(https_addr_alt, "cluster.allowed").await;
        if https_resp.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("https to cluster.allowed failed after policy update".to_string());
        }

        let udp_resp = udp_echo(
            udp_bind,
            udp_server_alt,
            b"cluster-udp",
            std::time::Duration::from_millis(500),
        )
        .await;
        if udp_resp.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("udp to cluster.allowed failed after policy update".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

pub(super) fn cluster_policy_update_churn(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let http_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 80);

    let policy_a = parse_policy(policy_allow_cluster_deny_foo())?;
    let policy_b = parse_policy(policy_allow_foo_deny_cluster())?;
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
            policy_a.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy A did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let cluster_dns = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster_dns.rcode != 0 || cluster_dns.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy A".to_string());
        }
        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed http failed after policy A".to_string());
        }
        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed http succeeded after policy A".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            policy_b.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
            if cluster.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy B did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if foo.rcode != 0 || foo.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed DNS did not resolve after policy B".to_string());
        }

        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed http failed after policy B".to_string());
        }
        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed http succeeded after policy B".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}
