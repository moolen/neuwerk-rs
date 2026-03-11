#![allow(clippy::format_in_format_args)]

use super::*;

pub(super) fn icmp_ttl_exceeded(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let dst_port = 33434u16;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "ttl"
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
        dst_port = dst_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        let before_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let before = metric_plain_value(&before_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);

        let ttl_candidates = [1u32, 2u32];
        let mut last_ttl = ttl_candidates[0];
        let mut last_icmp_err: Option<String> = None;
        let mut ttl_idx = 1usize;
        let deadline = Instant::now() + Duration::from_secs(6);
        let icmp_fd = open_icmp_socket(cfg.client_dp_ip, Duration::from_millis(400))?;
        loop {
            let rx_before = dp_iface_rx_packets(cfg).unwrap_or(0);
            let ttl = last_ttl;
            let port = send_udp_with_ttl(
                cfg.client_dp_ip,
                cfg.up_dp_ip,
                dst_port,
                ttl,
            )?;
            let mut saw_rx = false;
            for _ in 0..5 {
                if dp_iface_rx_packets(cfg).unwrap_or(0) > rx_before {
                    saw_rx = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let icmp_result = wait_for_icmp_time_exceeded_on_fd(
                icmp_fd,
                cfg.client_dp_ip,
                cfg.up_dp_ip,
                port,
                dst_port,
                Some(cfg.dp_public_ip),
            );
            if let Err(err) = &icmp_result {
                last_icmp_err = Some(err.clone());
            }
            let after_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let after =
                metric_plain_value(&after_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);
            if after >= before + 1.0 {
                if icmp_result.is_ok() {
                    break;
                }
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ttl exceeded metrics incremented but ICMP time exceeded was not observed (ttl_exceeded_total={}, last_ttl={}, icmp_err={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    last_ttl,
                    icmp_result.unwrap_err()
                ));
            } else if icmp_result.is_ok() {
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ICMP time exceeded observed without ttl metrics increment (ttl_exceeded_total={}, last_ttl={}, expected_src={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    last_ttl,
                    cfg.dp_public_ip
                ));
            }
            if Instant::now() >= deadline {
                let dp_packets = metric_value_with_labels(
                    &after_body,
                    "dp_packets_total",
                    &[
                        ("direction", "outbound"),
                        ("proto", "udp"),
                        ("decision", "allow"),
                        ("source_group", "ttl"),
                    ],
                )
                .unwrap_or(0.0);
                let flow_opens = metric_value_with_labels(
                    &after_body,
                    "dp_flow_opens_total",
                    &[("proto", "udp"), ("source_group", "ttl")],
                )
                .unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ttl exceeded metrics did not increment (ttl_exceeded_total={}, dp_packets_total={}, dp_flow_opens_total={}, dp0_rx_packets={}, last_ttl={}, last_icmp_err={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    dp_packets,
                    flow_opens,
                    dp_iface_rx_packets(cfg).unwrap_or(0),
                    last_ttl,
                    last_icmp_err.unwrap_or_else(|| "none".to_string())
                ));
            }
            let next_ttl = ttl_candidates[ttl_idx];
            ttl_idx = (ttl_idx + 1) % ttl_candidates.len();
            last_ttl = next_ttl;
            if !saw_rx {
                continue;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        unsafe {
            libc::close(icmp_fd);
        }
        Ok(())
    })
}

pub(super) fn udp_ttl_decremented(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let ttl_port = cfg.up_udp_port.saturating_add(10);
    let ttl_send = 4u32;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "ttl-dec"
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
        dst_port = ttl_port
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

    let marker = b"ttl-decrement";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = ttl_port;
    let listen_timeout = Duration::from_secs(2);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let socket = std::net::UdpSocket::bind((expected_dst, expected_dst_port))
                .map_err(|e| format!("udp listen bind failed: {e}"))?;
            let fd = socket.as_raw_fd();
            enable_ip_recv_ttl(fd)?;
            set_socket_timeout(fd, listen_timeout)?;
            let _ = ready_tx.send(());
            let ttl = recv_udp_ttl(fd, listen_timeout)?;
            Ok::<u8, String>(ttl)
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    let _ = send_udp_with_ttl_payload(cfg.client_dp_ip, cfg.up_dp_ip, ttl_port, ttl_send, marker)?;
    let ttl_result = result_rx.recv_timeout(Duration::from_secs(3)).map_err(|e| {
        let debug = overlay_debug_snapshot(cfg);
        let metrics = overlay_metrics_snapshot(metrics_addr);
        format!(
            "upstream capture timed out: {e}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
        )
    })?;
    let ttl = match ttl_result {
        Ok(Ok(ttl)) => ttl,
        Ok(Err(err)) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "udp ttl capture failed: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "udp ttl capture netns error: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
    };
    let _ = handle.join();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    let after_body =
        rt.block_on(async { http_get_path(metrics_addr, "metrics", "/metrics").await })?;
    let after_packets = metric_value_with_labels(
        &after_body,
        "dp_packets_total",
        &[
            ("direction", "outbound"),
            ("proto", "udp"),
            ("decision", "allow"),
            ("source_group", "ttl-dec"),
        ],
    )
    .unwrap_or(0.0);
    if after_packets < 1.0 {
        return Err("udp ttl test did not record outbound dataplane packets".to_string());
    }
    if ttl > 2 {
        return Err(format!(
            "ttl not decremented enough (sent={}, observed={ttl})",
            ttl_send
        ));
    }
    Ok(())
}

pub(super) fn ipv4_fragment_drop_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let before_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let before =
            metric_plain_value(&before_body, "dp_ipv4_fragments_dropped_total").unwrap_or(0.0);

        send_ipv4_udp_fragment(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            45000,
            cfg.up_udp_port,
            b"frag",
        )?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let after_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let after =
            metric_plain_value(&after_body, "dp_ipv4_fragments_dropped_total").unwrap_or(0.0);
        if after < before + 1.0 {
            return Err("fragment drop metrics did not increment".to_string());
        }
        Ok(())
    })
}

pub(super) fn ipv4_fragment_not_forwarded(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "frag"
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

    let marker = b"frag-block";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let listen_timeout = Duration::from_millis(400);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let result = match wait_for_udp_packet_on_fd(
                fd,
                expected_src,
                expected_dst,
                expected_dst_port,
                Some(marker),
                listen_timeout,
            ) {
                Ok(packet) => Err(format!(
                    "fragment unexpectedly forwarded (src_port={})",
                    packet.src_port
                )),
                Err(err) => {
                    if err.contains("timed out") {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            };
            unsafe {
                libc::close(fd);
            }
            result
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    send_ipv4_udp_fragment(
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        45001,
        cfg.up_udp_port,
        marker,
    )?;
    let result = result_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("fragment capture timed out: {e}"))?;
    let _ = handle.join();
    result.map_err(|e| format!("{e}"))??;
    Ok(())
}
