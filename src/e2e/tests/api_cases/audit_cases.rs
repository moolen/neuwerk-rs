pub(super) fn api_audit_policy_listed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let before = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        let created =
            http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Audit, Some(&token)).await?;
        let after = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        if after.len() != before.len() + 1 {
            return Err("policy list size did not increase".to_string());
        }
        if !after.iter().any(|record| record.id == created.id) {
            return Err("created policy not found in list".to_string());
        }
        Ok(())
    })
}

pub(super) fn api_audit_passthrough_overrides_deny(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let audit_policy = parse_policy(
        r#"default_policy: allow
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "deny-foo"
        mode: enforce
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
"#,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

pub(super) fn api_audit_findings_dns_passthrough_records_event(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let audit_policy = parse_policy(
        r#"default_policy: allow
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "deny-foo"
        mode: enforce
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
"#,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        let query = build_audit_query(
            Some(record.id),
            Some("dns_deny"),
            Some("client-primary"),
            Some(50),
        )?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::DnsDeny
                && item.policy_id == Some(record.id)
                && item.source_group == "client-primary"
                && item.fqdn.as_deref() == Some("foo.allowed")
                && item.hostname.as_deref() == Some("foo.allowed")
                && item.query_type == Some(1)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing dns_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

pub(super) fn api_audit_findings_l4_passthrough_records_event(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let payload = b"audit-l4";
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "apps"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-upstream-udp"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
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
        let query = build_audit_query(Some(record.id), Some("l4_deny"), Some("apps"), Some(50))?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::L4Deny
                && item.policy_id == Some(record.id)
                && item.source_group == "apps"
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.dst_port == Some(cfg.up_udp_port)
                && item.proto == Some(17)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing l4_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

pub(super) fn api_audit_findings_tls_passthrough_captures_sni(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let sni = "foo.allowed";
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "tls-audit"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-tls-sni"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            sni:
              exact: ["{sni}"]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        sni = sni
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let _record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        // Prime DNS allowlist entry for upstream IP before HTTPS.
        let dns = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&dns, cfg.up_dp_ip)?;
        let start_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(5);
        let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
        let _ = https_get_tls12(https_addr, sni).await;
        let _ = tls_client_hello_raw(https_addr, sni, 2000).await;
        let query =
            build_audit_query_with_since(None, Some("tls_deny"), None, Some(start_ts), Some(200))?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(5))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::TlsDeny
                && item.sni.as_deref() == Some(sni)
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.dst_port == Some(443)
                && item.proto == Some(6)
                && item.last_seen >= start_ts
                && item.count >= 1
        }) {
            return Err(format!(
                "missing tls_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

pub(super) fn api_audit_findings_icmp_passthrough_records_type_code(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "icmp-audit"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-icmp-echo"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [8]
          icmp_codes: [0]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    let record = rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await
    })?;
    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_secs(3)) {
        Ok(()) => {}
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            return Err(format!("{err}\n-- dataplane debug --\n{debug}"));
        }
    }
    rt.block_on(async {
        let query = build_audit_query(
            Some(record.id),
            Some("icmp_deny"),
            Some("icmp-audit"),
            Some(50),
        )?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::IcmpDeny
                && item.policy_id == Some(record.id)
                && item.source_group == "icmp-audit"
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.proto == Some(1)
                && item.icmp_type == Some(8)
                && item.icmp_code == Some(0)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing icmp_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

pub(super) fn api_audit_findings_policy_id_filter_isolates_rotated_policies(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let payload_a = b"audit-policy-a";
    let payload_b = b"audit-policy-b";
    let policy_a_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "rotate-a"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-a"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy_b_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "rotate-b"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-b"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy_a: PolicyConfig =
        serde_yaml::from_str(&policy_a_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let policy_b: PolicyConfig =
        serde_yaml::from_str(&policy_b_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record_a = http_set_policy(
            api_addr,
            &tls_dir,
            policy_a,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp_a = udp_echo(
            udp_bind,
            udp_server,
            payload_a,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp_a != payload_a {
            return Err("udp echo payload mismatch for policy A".to_string());
        }
        let query_a = build_audit_query(Some(record_a.id), Some("l4_deny"), None, Some(100))?;
        let findings_a =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query_a, Duration::from_secs(3))
                .await?;
        if !has_audit_finding(&findings_a.items, AuditFindingType::L4Deny, "rotate-a")
            || findings_a
                .items
                .iter()
                .all(|item| item.policy_id != Some(record_a.id))
        {
            return Err(format!(
                "policy A findings missing expected item: {:?}",
                findings_a.items
            ));
        }

        let record_b = http_set_policy(
            api_addr,
            &tls_dir,
            policy_b,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp_b = udp_echo(
            udp_bind,
            udp_server,
            payload_b,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp_b != payload_b {
            return Err("udp echo payload mismatch for policy B".to_string());
        }
        let query_b = build_audit_query(Some(record_b.id), Some("l4_deny"), None, Some(100))?;
        let findings_b =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query_b, Duration::from_secs(3))
                .await?;
        if !has_audit_finding(&findings_b.items, AuditFindingType::L4Deny, "rotate-b")
            || findings_b
                .items
                .iter()
                .all(|item| item.policy_id != Some(record_b.id))
        {
            return Err(format!(
                "policy B findings missing expected item: {:?}",
                findings_b.items
            ));
        }

        let recheck_a =
            http_get_audit_findings(api_addr, &tls_dir, Some(&query_a), Some(&token)).await?;
        if recheck_a
            .items
            .iter()
            .any(|item| item.policy_id != Some(record_a.id))
        {
            return Err(format!(
                "policy A query leaked other policy ids: {:?}",
                recheck_a.items
            ));
        }
        if recheck_a
            .items
            .iter()
            .any(|item| item.source_group != "rotate-a")
        {
            return Err(format!(
                "policy A query leaked other source groups: {:?}",
                recheck_a.items
            ));
        }

        let recheck_b =
            http_get_audit_findings(api_addr, &tls_dir, Some(&query_b), Some(&token)).await?;
        if recheck_b
            .items
            .iter()
            .any(|item| item.policy_id != Some(record_b.id))
        {
            return Err(format!(
                "policy B query leaked other policy ids: {:?}",
                recheck_b.items
            ));
        }
        if recheck_b
            .items
            .iter()
            .any(|item| item.source_group != "rotate-b")
        {
            return Err(format!(
                "policy B query leaked other source groups: {:?}",
                recheck_b.items
            ));
        }

        Ok(())
    })
}

