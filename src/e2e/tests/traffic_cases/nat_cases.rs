use super::*;

pub(super) fn nat_idle_eviction_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "udp"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}", "{dst_ip_alt}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_ip_alt = cfg.up_dp_ip_alt,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

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

        let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
        let payload = b"nat-evict";
        let resp = udp_echo(client_bind, udp_server, payload, Duration::from_millis(500)).await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let baseline_active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
        let baseline_opens = metric_value_with_labels(
            &body,
            "dp_flow_opens_total",
            &[("proto", "udp"), ("source_group", "udp")],
        )
        .unwrap_or(0.0);
        let baseline_closes =
            metric_value_with_labels(&body, "dp_flow_closes_total", &[("reason", "idle_timeout")])
                .unwrap_or(0.0);

        let udp_server_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);
        let resp = udp_echo(
            client_bind,
            udp_server_alt,
            payload,
            Duration::from_millis(500),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch (alt)".to_string());
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let opens = metric_value_with_labels(
                &body,
                "dp_flow_opens_total",
                &[("proto", "udp"), ("source_group", "udp")],
            )
            .unwrap_or(0.0);
            let active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
            if opens > baseline_opens || active > baseline_active {
                break;
            }
            if Instant::now() >= deadline {
                return Err("expected flow opens to increase after udp flow".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tokio::time::sleep(Duration::from_secs(cfg.idle_timeout_secs + 2)).await;
        let drop_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port + 1);
        send_udp_once(client_bind, drop_addr, b"evict")?;

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let closes = metric_value_with_labels(
                &body,
                "dp_flow_closes_total",
                &[("reason", "idle_timeout")],
            )
            .unwrap_or(0.0);
            let active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
            if closes > baseline_closes || active <= baseline_active {
                break;
            }
            if Instant::now() >= deadline {
                return Err("expected nat entries to evict after idle timeout".to_string());
            }
        }

        Ok(())
    })
}

pub(super) fn nat_port_deterministic(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "natdet"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
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
        Ok::<(), String>(())
    })?;

    let ports: Vec<u16> = (42000..42020).collect();
    let marker = b"natdet";
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let listen_timeout = Duration::from_secs(3);
    let port_count = ports.len();
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let mut first: HashMap<u16, u16> = HashMap::new();
            let mut second: HashMap<u16, u16> = HashMap::new();
            while first.len() < port_count || second.len() < port_count {
                let packet = match wait_for_udp_packet_on_fd(
                    fd,
                    expected_src,
                    expected_dst,
                    expected_dst_port,
                    Some(marker),
                    listen_timeout,
                ) {
                    Ok(packet) => packet,
                    Err(err) => {
                        return Err(format!(
                            "nat capture timed out (first={}, second={}): {err}",
                            first.len(),
                            second.len()
                        ));
                    }
                };
                let offset = marker.len();
                if packet.payload.len() < offset + 3 {
                    continue;
                }
                let round = packet.payload[offset];
                let internal_port =
                    u16::from_be_bytes([packet.payload[offset + 1], packet.payload[offset + 2]]);
                match round {
                    0 => {
                        first.entry(internal_port).or_insert(packet.src_port);
                    }
                    1 => {
                        second.entry(internal_port).or_insert(packet.src_port);
                    }
                    _ => {}
                }
            }
            unsafe {
                libc::close(fd);
            }
            Ok((first, second))
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    for &port in &ports {
        let mut payload = Vec::new();
        payload.extend_from_slice(marker);
        payload.push(0);
        payload.extend_from_slice(&port.to_be_bytes());
        send_udp_with_payload_from_port(
            cfg.client_dp_ip,
            port,
            cfg.up_dp_ip,
            cfg.up_udp_port,
            &payload,
        )?;
    }
    for &port in &ports {
        let mut payload = Vec::new();
        payload.extend_from_slice(marker);
        payload.push(1);
        payload.extend_from_slice(&port.to_be_bytes());
        send_udp_with_payload_from_port(
            cfg.client_dp_ip,
            port,
            cfg.up_dp_ip,
            cfg.up_udp_port,
            &payload,
        )?;
    }

    let result = result_rx
        .recv_timeout(Duration::from_secs(3))
        .map_err(|e| format!("nat capture timed out: {e}"))?;
    let _ = handle.join();
    let (first, second) = result.map_err(|e| format!("{e}"))??;
    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for &port in &ports {
        match (first.get(&port), second.get(&port)) {
            (Some(a), Some(b)) => {
                if a != b {
                    mismatches.push((port, *a, *b));
                }
            }
            _ => missing.push(port),
        }
    }
    if !missing.is_empty() {
        return Err(format!("missing NAT captures for ports: {:?}", missing));
    }
    if !mismatches.is_empty() {
        return Err(format!(
            "NAT mapping changed across packets: {:?}",
            mismatches
        ));
    }
    Ok(())
}

pub(super) fn nat_port_collision_isolation(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "nat-collision"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

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
        Ok::<(), String>(())
    })?;

    let mut alias_octets = cfg.client_dp_ip.octets();
    alias_octets[3] = alias_octets[3].saturating_add(1);
    let client_ip_alt = Ipv4Addr::from(alias_octets);
    set_client_dp_alias(cfg, client_ip_alt, true)?;

    let result = (|| -> Result<(), String> {
        let marker = b"nat-collision:";
        let fixed_port = 45000u16;
        let expected_src = cfg.dp_public_ip;
        let expected_dst = cfg.up_dp_ip;
        let expected_dst_port = cfg.up_udp_port;
        let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
        let (ready_tx, ready_rx) = std_mpsc::channel();
        let (result_tx, result_rx) = std_mpsc::channel();
        let listen_timeout = Duration::from_secs(3);
        let handle = std::thread::spawn(move || {
            let res = upstream_ns.run(|_| {
                let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
                let _ = ready_tx.send(());
                let mut seen: HashMap<u8, u16> = HashMap::new();
                while seen.len() < 2 {
                    let packet = wait_for_udp_packet_on_fd(
                        fd,
                        expected_src,
                        expected_dst,
                        expected_dst_port,
                        Some(marker),
                        listen_timeout,
                    )?;
                    if packet.payload.len() < marker.len() + 1 {
                        continue;
                    }
                    let marker_id = packet.payload[marker.len()];
                    if marker_id <= 1 {
                        seen.entry(marker_id).or_insert(packet.src_port);
                    }
                }
                unsafe {
                    libc::close(fd);
                }
                Ok::<HashMap<u8, u16>, String>(seen)
            });
            let _ = result_tx.send(res);
        });

        ready_rx
            .recv_timeout(Duration::from_secs(1))
            .map_err(|e| format!("upstream listener not ready: {e}"))?;

        for _ in 0..3 {
            let mut payload_a = Vec::new();
            payload_a.extend_from_slice(marker);
            payload_a.push(0);
            send_udp_with_payload_from_port(
                cfg.client_dp_ip,
                fixed_port,
                cfg.up_dp_ip,
                cfg.up_udp_port,
                &payload_a,
            )?;

            let mut payload_b = Vec::new();
            payload_b.extend_from_slice(marker);
            payload_b.push(1);
            send_udp_with_payload_from_port(
                client_ip_alt,
                fixed_port,
                cfg.up_dp_ip,
                cfg.up_udp_port,
                &payload_b,
            )?;
            std::thread::sleep(Duration::from_millis(25));
        }

        let result = result_rx
            .recv_timeout(Duration::from_secs(4))
            .map_err(|e| format!("nat collision capture timed out: {e}"))?;
        let _ = handle.join();
        let seen = result.map_err(|e| format!("{e}"))??;
        let src_a = seen
            .get(&0)
            .copied()
            .ok_or_else(|| "missing packet for client A".to_string())?;
        let src_b = seen
            .get(&1)
            .copied()
            .ok_or_else(|| "missing packet for client B".to_string())?;
        if src_a == src_b {
            return Err(format!(
                "SNAT port collision: both clients mapped to {src_a} (fixed src port {fixed_port})"
            ));
        }
        Ok(())
    })();

    let _ = set_client_dp_alias(cfg, client_ip_alt, false);
    result
}

pub(super) fn nat_stream_payload_integrity(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "nat-stream"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-http"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [80]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
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

        let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
        let resp = http_get_path(http_addr, "foo.allowed", "/stream-long").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected stream response: {}", first_line(&resp)));
        }
        let body = http_body(&resp).as_bytes();
        let expected_len = 60 * 256;
        if body.len() != expected_len {
            return Err(format!(
                "unexpected stream length {} (expected {expected_len})",
                body.len()
            ));
        }
        if let Some(idx) = body.iter().position(|b| *b != b'x') {
            return Err(format!("stream payload corrupted at byte {idx}"));
        }
        Ok(())
    })
}

pub(super) fn snat_override_applied(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "snat"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-http"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [80]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

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
        let body = http_get_path(
            SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80),
            "foo.allowed",
            "/whoami",
        )
        .await?;
        let whoami = http_body(&body);
        if whoami.trim() != cfg.dp_public_ip.to_string() {
            return Err(format!(
                "expected snat ip {}, got {}",
                cfg.dp_public_ip,
                whoami.trim()
            ));
        }
        Ok(())
    })
}

fn set_client_dp_alias(cfg: &TopologyConfig, ip: Ipv4Addr, add: bool) -> Result<(), String> {
    let action = if add { "add" } else { "del" };
    let output = Command::new("ip")
        .args([
            "addr",
            action,
            &format!("{ip}/24"),
            "dev",
            &cfg.client_dp_iface,
        ])
        .output()
        .map_err(|e| format!("ip addr {action} failed: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if add && stderr.contains("File exists") {
        return Ok(());
    }
    if !add
        && (stderr.contains("Cannot assign requested address")
            || stderr.contains("Cannot find device"))
    {
        return Ok(());
    }
    Err(format!("ip addr {action} failed: {}", stderr.trim()))
}
