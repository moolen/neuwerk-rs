use super::*;

pub(super) fn icmp_echo_allowed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "icmp"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-icmp-echo"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [0, 8, 3, 11]
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
        Ok::<(), String>(())
    })?;

    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_secs(3)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            Err(format!("{err}\n-- dataplane debug --\n{debug}"))
        }
    }
}

pub(super) fn icmp_type_filtering(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "icmp-filter"
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
      - id: "allow-icmp-time-exceeded"
        priority: 1
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [11]
          icmp_codes: [0]
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

    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_millis(500)) {
        Ok(_) => {
            return Err("icmp echo unexpectedly allowed".to_string());
        }
        Err(err) => {
            if !err.contains("timed out") {
                return Err(format!("icmp echo unexpected error: {err}"));
            }
        }
    }

    let internal_port = 40123u16;
    let marker = b"icmp-filter";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let listen_timeout = Duration::from_secs(3);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let packet = wait_for_udp_packet_on_fd(
                fd,
                expected_src,
                expected_dst,
                expected_dst_port,
                Some(marker),
                listen_timeout,
            )?;
            unsafe {
                libc::close(fd);
            }
            Ok::<u16, String>(packet.src_port)
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(marker);
    payload.extend_from_slice(&internal_port.to_be_bytes());
    send_udp_with_payload_from_port(
        cfg.client_dp_ip,
        internal_port,
        cfg.up_dp_ip,
        cfg.up_udp_port,
        &payload,
    )?;
    let ext_port_result = result_rx.recv_timeout(Duration::from_secs(3)).map_err(|e| {
        let debug = overlay_debug_snapshot(cfg);
        let metrics = overlay_metrics_snapshot(metrics_addr);
        format!(
            "upstream capture timed out: {e}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
        )
    })?;
    let ext_port = match ext_port_result {
        Ok(Ok(ext_port)) => ext_port,
        Ok(Err(err)) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "upstream capture failed: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "upstream capture netns error: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
    };
    let _ = handle.join();

    let icmp_fd = open_icmp_socket(cfg.client_dp_ip, Duration::from_secs(3))?;
    let upstream_ns_sender = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let send_result = upstream_ns_sender
        .run(|_| {
            send_icmp_time_exceeded(
                cfg.up_dp_ip,
                cfg.dp_public_ip,
                cfg.dp_public_ip,
                cfg.up_dp_ip,
                ext_port,
                cfg.up_udp_port,
            )
        })
        .map_err(|e| format!("{e}"));
    let icmp_result = match send_result {
        Ok(Ok(())) => wait_for_icmp_time_exceeded_on_fd(
            icmp_fd,
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            internal_port,
            cfg.up_udp_port,
            Some(cfg.up_dp_ip),
        ),
        Ok(Err(err)) => Err(format!("send icmp time exceeded failed: {err}")),
        Err(err) => Err(format!("upstream netns send failed: {err}")),
    };
    let icmp_result = icmp_result.map_err(|err| {
        let debug = overlay_debug_snapshot(cfg);
        let metrics = overlay_metrics_snapshot(metrics_addr);
        format!(
            "icmp time exceeded validation failed: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
        )
    });
    unsafe {
        libc::close(icmp_fd);
    }
    icmp_result
}
