use crate::e2e::services::{http_get_policy_by_name, http_upsert_policy_by_name};

pub(super) fn api_policy_persisted_local(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
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
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let store_dir = std::path::PathBuf::from("/var/lib/neuwerk/local-policy-store");
        let active_path = store_dir.join("active.json");
        wait_for_path(&active_path, Duration::from_secs(5))?;
        let active: PolicyActive =
            serde_json::from_slice(&std::fs::read(&active_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("active json error: {e}"))?;
        if active.id != record.id {
            return Err("local active policy id mismatch".to_string());
        }
        let record_path = store_dir
            .join("policies")
            .join(format!("{}.json", record.id));
        wait_for_path(&record_path, Duration::from_secs(5))?;
        let stored: PolicyRecord =
            serde_json::from_slice(&std::fs::read(&record_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("stored policy json error: {e}"))?;
        if stored.id != record.id {
            return Err("stored policy id mismatch".to_string());
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

pub(super) fn api_policy_active_semantics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let audit_policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let enforce_policy = parse_policy(policy_allow_foo_deny_cluster())?;
    let store_dir = std::path::PathBuf::from("/var/lib/neuwerk/local-policy-store");
    let active_path = store_dir.join("active.json");
    wait_for_path(&active_path, Duration::from_secs(5))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let baseline = read_active_id(&active_path)?;
        let audited = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let after_audit = read_active_id(&active_path)?;
        if after_audit != audited.id {
            return Err("audit policy did not become active".to_string());
        }
        let enforced = http_set_policy(
            api_addr,
            &tls_dir,
            enforce_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let after_enforce = read_active_id(&active_path)?;
        if after_enforce != enforced.id {
            return Err("enforce policy did not update active id".to_string());
        }
        if after_enforce == baseline {
            return Err("enforce policy did not replace baseline active id".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_policy_get_update_delete(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
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
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy.clone(),
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;

        let fetched =
            http_get_policy(api_addr, &tls_dir, &record.id.to_string(), Some(&token)).await?;
        if fetched.id != record.id {
            return Err("policy get returned wrong record".to_string());
        }

        let mut updated_policy = baseline_policy.clone();
        updated_policy.default_policy = Some(PolicyValue::String("allow".to_string()));
        let updated = http_update_policy(
            api_addr,
            &tls_dir,
            &record.id.to_string(),
            updated_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let updated_default = match updated.policy.default_policy {
            Some(PolicyValue::String(value)) => value,
            _ => "missing".to_string(),
        };
        if updated_default != "allow" {
            return Err(format!(
                "unexpected updated default_policy {}",
                updated_default
            ));
        }

        let status =
            http_delete_policy(api_addr, &tls_dir, &record.id.to_string(), Some(&token)).await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected delete status {status}"));
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            &format!("/api/v1/policies/{}", record.id),
            Some(&token),
        )
        .await?;
        if status != reqwest::StatusCode::NOT_FOUND {
            return Err(format!("expected 404 after delete, got {status}"));
        }
        Ok(())
    })
}

pub(super) fn api_policy_upsert_by_name(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_name = "terraform-prod";
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
        let created = http_upsert_policy_by_name(
            api_addr,
            &tls_dir,
            policy_name,
            baseline_policy.clone(),
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        if created.name.as_deref() != Some(policy_name) {
            return Err("policy upsert by-name returned wrong name".to_string());
        }

        let fetched = http_get_policy_by_name(api_addr, &tls_dir, policy_name, Some(&token)).await?;
        if fetched.id != created.id {
            return Err("policy get by-name returned wrong record".to_string());
        }

        let mut updated_policy = baseline_policy.clone();
        updated_policy.default_policy = Some(PolicyValue::String("allow".to_string()));
        let updated = http_upsert_policy_by_name(
            api_addr,
            &tls_dir,
            policy_name,
            updated_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        if updated.id != created.id {
            return Err("policy upsert by-name did not preserve stable id".to_string());
        }
        if updated.name.as_deref() != Some(policy_name) {
            return Err("policy upsert by-name changed stable name".to_string());
        }
        let updated_default = match updated.policy.default_policy {
            Some(PolicyValue::String(value)) => value,
            _ => "missing".to_string(),
        };
        if updated_default != "allow" {
            return Err(format!(
                "unexpected by-name updated default_policy {}",
                updated_default
            ));
        }

        let list = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        let matching: Vec<&PolicyRecord> = list
            .iter()
            .filter(|record| record.name.as_deref() == Some(policy_name))
            .collect();
        if matching.len() != 1 {
            return Err(format!(
                "expected exactly one policy named {policy_name}, found {}",
                matching.len()
            ));
        }
        if matching[0].id != created.id {
            return Err("policy list returned wrong record for stable name".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_policy_list_ordering(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_a = parse_policy(policy_allow_cluster_deny_foo())?;
    let policy_b = parse_policy(policy_allow_foo_deny_cluster())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let _ = http_set_policy(
            api_addr,
            &tls_dir,
            policy_a,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = http_set_policy(
            api_addr,
            &tls_dir,
            policy_b,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let list = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        if list.len() < 2 {
            return Err("policy list missing entries".to_string());
        }
        for window in list.windows(2) {
            let left = parse_created_at(&window[0])?;
            let right = parse_created_at(&window[1])?;
            if left > right {
                return Err("policy list not sorted by created_at".to_string());
            }
            if left == right && window[0].id.as_bytes() > window[1].id.as_bytes() {
                return Err("policy list not stable by id".to_string());
            }
        }
        Ok(())
    })
}

pub(super) fn api_policy_scale_last_rule_effective(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rule_count = policy_scale_rule_count()?;

    let policy_yaml = build_policy_scale_yaml(cfg, rule_count);
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let target = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
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
        tokio::time::sleep(Duration::from_millis(200)).await;

        let resp = http_get(target, "policy-scale.allowed").await?;
        let status = first_line(&resp);
        if !status.contains("200") {
            return Err(format!(
                "policy scale target request failed with status line: {status}"
            ));
        }
        Ok(())
    })
}

pub(super) fn api_dns_cache_grouped(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let expected_ip = IpAddr::V4(cfg.up_dp_ip);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if resp.rcode != 0 || resp.ips.is_empty() {
            return Err("dns query did not return expected answer".to_string());
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let cache = http_get_dns_cache(api_addr, &tls_dir, Some(&token)).await?;
            if let Some(entry) = cache
                .entries
                .iter()
                .find(|entry| entry.hostname == "foo.allowed")
            {
                if entry.ips.iter().any(|ip| *ip == expected_ip) {
                    return Ok(());
                }
                return Err("dns cache entry missing expected ip".to_string());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for dns cache entry".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

fn policy_scale_rule_count() -> Result<usize, String> {
    const ENV_KEY: &str = "NEUWERK_E2E_POLICY_SCALE_RULES";
    const DEFAULT_RULES: usize = 1_000;
    const MIN_RULES: usize = 2;
    const MAX_RULES: usize = 5_000;

    let value = match std::env::var(ENV_KEY) {
        Ok(value) => value,
        Err(_) => return Ok(DEFAULT_RULES),
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|_| format!("{ENV_KEY} must be an integer between {MIN_RULES}-{MAX_RULES}"))?;
    if !(MIN_RULES..=MAX_RULES).contains(&parsed) {
        return Err(format!(
            "{ENV_KEY} must be between {MIN_RULES} and {MAX_RULES}, got {parsed}"
        ));
    }
    Ok(parsed)
}

#[allow(clippy::format_in_format_args)]
fn build_policy_scale_yaml(cfg: &TopologyConfig, rule_count: usize) -> String {
    let mut yaml = format!(
        r#"default_policy: deny
source_groups:
  - id: "policy-scale"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip)
    );

    for i in 0..rule_count.saturating_sub(1) {
        let a = ((i / 256) % 256) as u8;
        let b = (i % 256) as u8;
        let filler_ip = Ipv4Addr::new(198, 18, a, b);
        let filler_port = 10_000u16.saturating_add((i % 10_000) as u16);
        yaml.push_str(&format!(
            r#"      - id: "allow-filler-{i}"
        priority: {i}
        action: allow
        match:
          dst_ips: ["{filler_ip}"]
          proto: tcp
          dst_ports: [{filler_port}]
"#
        ));
    }

    yaml.push_str(&format!(
        r#"      - id: "allow-target-last"
        priority: {priority}
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [80]
"#,
        priority = rule_count - 1,
        dst_ip = cfg.up_dp_ip
    ));

    yaml
}

pub(super) fn api_stats_snapshot(cfg: &TopologyConfig) -> Result<(), String> {
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
        let stats = http_get_stats(api_addr, &tls_dir, Some(&token)).await?;
        let dataplane = stats.get("dataplane").ok_or("missing dataplane stats")?;
        let dns = stats.get("dns").ok_or("missing dns stats")?;
        let tls = stats.get("tls").ok_or("missing tls stats")?;
        let dhcp = stats.get("dhcp").ok_or("missing dhcp stats")?;
        let cluster = stats.get("cluster").ok_or("missing cluster stats")?;

        if !dataplane.is_object()
            || !dns.is_object()
            || !tls.is_object()
            || !dhcp.is_object()
            || !cluster.is_object()
        {
            return Err("stats payload not structured as expected".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_metrics_exposed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_api_health(api_addr, &tls_dir).await?;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        if !body.contains("http_requests_total") {
            return Err("metrics response missing http_requests_total".to_string());
        }
        if !body.contains("http_auth_total") {
            return Err("metrics response missing http_auth_total".to_string());
        }
        if !body.contains("dns_queries_total") {
            return Err("metrics response missing dns_queries_total".to_string());
        }
        if !body.contains("dp_packets_total") {
            return Err("metrics response missing dp_packets_total".to_string());
        }
        if !body.contains("raft_is_leader") {
            return Err("metrics response missing raft_is_leader".to_string());
        }
        if !body.contains("rocksdb_estimated_num_keys") {
            return Err("metrics response missing rocksdb_estimated_num_keys".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_body_limit_rejects_large(cfg: &TopologyConfig) -> Result<(), String> {
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
        let body = vec![b'a'; 3 * 1024 * 1024];
        let status =
            http_api_post_raw(api_addr, &tls_dir, "/api/v1/policies", body, Some(&token)).await?;
        if status != reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(format!("expected 413, got {}", status));
        }
        Ok(())
    })
}

pub(super) fn api_metrics_unauthenticated(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let status = http_api_status(api_addr, &tls_dir, "/api/v1/policies", None).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized status, got {status}"));
        }
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        if !body.contains("http_requests_total") {
            return Err("metrics response missing http_requests_total".to_string());
        }
        if !body.contains("http_auth_total") {
            return Err("metrics response missing http_auth_total".to_string());
        }
        let auth_denied = metric_value_with_labels(
            &body,
            "http_auth_total",
            &[("outcome", "deny"), ("reason", "missing_token")],
        )
        .ok_or_else(|| "missing http auth deny metrics".to_string())?;
        if auth_denied < 1.0 {
            return Err("http auth deny metrics did not increment".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_metrics_integrity(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_api_health(api_addr, &tls_dir).await?;
        let _ =
            http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Audit, Some(&token)).await?;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let health = metric_value(&body, "/health", "GET", "200")
            .ok_or_else(|| "missing health metrics".to_string())?;
        if health < 1.0 {
            return Err("health metrics did not increment".to_string());
        }
        let policy_post = metric_value(&body, "/api/v1/policies", "POST", "200")
            .ok_or_else(|| "missing policy post metrics".to_string())?;
        if policy_post < 1.0 {
            return Err("policy post metrics did not increment".to_string());
        }
        let auth_allow = metric_value_with_labels(
            &body,
            "http_auth_total",
            &[("outcome", "allow"), ("reason", "valid_token")],
        )
        .ok_or_else(|| "missing http auth allow metrics".to_string())?;
        if auth_allow < 1.0 {
            return Err("http auth allow metrics did not increment".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_metrics_dns_dataplane(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;

        let allow = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        assert_dns_allowed(&allow, cfg.up_dp_ip_alt)?;

        let deny = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&deny)?;

        let payload = b"metrics-udp";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_millis(500),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;

        let dns_allow = metric_value_with_labels(
            &body,
            "dns_queries_total",
            &[
                ("result", "allow"),
                ("reason", "policy_allow"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing dns allow metrics".to_string())?;
        if dns_allow < 1.0 {
            return Err("dns allow metrics did not increment".to_string());
        }
        let svc_dns_allow = metric_value_with_labels(
            &body,
            "svc_dns_queries_total",
            &[
                ("result", "allow"),
                ("reason", "policy_allow"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing svc dns allow metrics".to_string())?;
        if svc_dns_allow < 1.0 {
            return Err("svc dns allow metrics did not increment".to_string());
        }

        let dns_deny = metric_value_with_labels(
            &body,
            "dns_queries_total",
            &[
                ("result", "deny"),
                ("reason", "policy_deny"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing dns deny metrics".to_string())?;
        if dns_deny < 1.0 {
            return Err("dns deny metrics did not increment".to_string());
        }
        let svc_dns_deny = metric_value_with_labels(
            &body,
            "svc_dns_queries_total",
            &[
                ("result", "deny"),
                ("reason", "policy_deny"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing svc dns deny metrics".to_string())?;
        if svc_dns_deny < 1.0 {
            return Err("svc dns deny metrics did not increment".to_string());
        }

        let dns_nxdomain =
            metric_value_with_labels(&body, "dns_nxdomain_total", &[("source", "policy")])
                .ok_or_else(|| "missing dns nxdomain metrics".to_string())?;
        if dns_nxdomain < 1.0 {
            return Err("dns nxdomain metrics did not increment".to_string());
        }
        let svc_dns_nxdomain =
            metric_value_with_labels(&body, "svc_dns_nxdomain_total", &[("source", "policy")])
                .ok_or_else(|| "missing svc dns nxdomain metrics".to_string())?;
        if svc_dns_nxdomain < 1.0 {
            return Err("svc dns nxdomain metrics did not increment".to_string());
        }

        let dns_rtt_count = metric_value_with_labels(
            &body,
            "dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream rtt metrics".to_string())?;
        if dns_rtt_count < 1.0 {
            return Err("dns upstream rtt metrics did not increment".to_string());
        }
        let svc_dns_rtt_count = metric_value_with_labels(
            &body,
            "svc_dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing svc dns upstream rtt metrics".to_string())?;
        if svc_dns_rtt_count < 1.0 {
            return Err("svc dns upstream rtt metrics did not increment".to_string());
        }

        let dp_out = metric_value_with_labels(
            &body,
            "dp_packets_total",
            &[
                ("direction", "outbound"),
                ("proto", "udp"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        )
        .ok_or_else(|| "missing outbound dataplane packet metrics".to_string())?;
        if dp_out < 1.0 {
            return Err("outbound dataplane packet metrics did not increment".to_string());
        }

        let dp_in = metric_value_with_labels(
            &body,
            "dp_packets_total",
            &[
                ("direction", "inbound"),
                ("proto", "udp"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        )
        .ok_or_else(|| "missing inbound dataplane packet metrics".to_string())?;
        if dp_in < 1.0 {
            return Err("inbound dataplane packet metrics did not increment".to_string());
        }

        let flow_opens = metric_value_with_labels(
            &body,
            "dp_flow_opens_total",
            &[("proto", "udp"), ("source_group", "internal")],
        )
        .ok_or_else(|| "missing dataplane flow open metrics".to_string())?;
        if flow_opens < 1.0 {
            return Err("dataplane flow open metrics did not increment".to_string());
        }

        Ok(())
    })
}
