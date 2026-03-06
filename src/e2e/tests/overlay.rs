use super::*;

pub fn overlay_cases_vxlan() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "overlay_vxlan_round_trip",
            func: overlay_vxlan_round_trip,
        },
        TestCase {
            name: "overlay_vxlan_wrong_vni_drop",
            func: overlay_vxlan_wrong_vni_drop,
        },
        TestCase {
            name: "overlay_vxlan_wrong_port_drop",
            func: overlay_vxlan_wrong_port_drop,
        },
        TestCase {
            name: "overlay_vxlan_mtu_drop",
            func: overlay_vxlan_mtu_drop,
        },
    ]
}

pub fn overlay_cases_vxlan_dual_tunnel() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "overlay_vxlan_dual_internal_to_external_swap",
            func: overlay_vxlan_dual_internal_to_external_swap,
        },
        TestCase {
            name: "overlay_vxlan_dual_external_to_internal_swap",
            func: overlay_vxlan_dual_external_to_internal_swap,
        },
    ]
}

pub fn overlay_cases_geneve() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "overlay_geneve_round_trip",
            func: overlay_geneve_round_trip,
        },
        TestCase {
            name: "overlay_geneve_wrong_vni_drop",
            func: overlay_geneve_wrong_vni_drop,
        },
        TestCase {
            name: "overlay_geneve_wrong_port_drop",
            func: overlay_geneve_wrong_port_drop,
        },
        TestCase {
            name: "overlay_geneve_mtu_drop",
            func: overlay_geneve_mtu_drop,
        },
    ]
}

fn overlay_vxlan_dual_internal_to_external_swap(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_vxlan_round_trip_expected(
        cfg,
        b"overlay-vxlan-dual-int-ext",
        40500,
        5655,
        cfg.overlay_vxlan_port,
        cfg.overlay_vxlan_vni,
        overlay_vxlan_external_port(cfg),
        overlay_vxlan_external_vni(cfg),
    )
}

fn overlay_vxlan_dual_external_to_internal_swap(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_vxlan_round_trip_expected(
        cfg,
        b"overlay-vxlan-dual-ext-int",
        40501,
        5656,
        overlay_vxlan_external_port(cfg),
        overlay_vxlan_external_vni(cfg),
        cfg.overlay_vxlan_port,
        cfg.overlay_vxlan_vni,
    )
}

fn overlay_vxlan_external_port(cfg: &TopologyConfig) -> u16 {
    cfg.overlay_vxlan_port.wrapping_add(1)
}

fn overlay_vxlan_external_vni(cfg: &TopologyConfig) -> u32 {
    cfg.overlay_vxlan_vni.wrapping_add(1)
}

fn overlay_vxlan_round_trip_expected(
    cfg: &TopologyConfig,
    inner_payload: &[u8],
    inner_src_port: u16,
    send_port: u16,
    inbound_port: u16,
    inbound_vni: u32,
    expected_outbound_port: u16,
    expected_outbound_vni: u32,
) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x31],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x32],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        inner_src_port,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_vxlan_payload(&inner, inbound_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, expected_outbound_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;

    let outer_dst_ip = cfg.dp_public_ip;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, send_port))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (outer_dst_ip, inbound_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, src) = match recv_socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
                let metrics = overlay_metrics_snapshot(metrics_addr);
                let in_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "in")],
                )
                .unwrap_or(0.0);
                let out_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "out")],
                )
                .unwrap_or(0.0);
                let decap_err =
                    metric_plain_value(&metrics, "overlay_decap_errors_total").unwrap_or(0.0);
                let encap_err =
                    metric_plain_value(&metrics, "overlay_encap_errors_total").unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                return Err(format!(
                    "overlay recv failed: {err} (overlay_packets in={}, out={}, decap_errors={}, encap_errors={})\n-- overlay debug --\n{debug}",
                    in_count, out_count, decap_err, encap_err
                ));
            }
            return Err(format!("overlay recv failed: {err}"));
        }
    };
    if src.ip() != IpAddr::V4(outer_dst_ip) {
        return Err(format!("unexpected overlay src ip: {}", src.ip()));
    }
    if src.port() != send_port {
        return Err(format!("unexpected overlay src port: {}", src.port()));
    }
    let (vni, inner_buf) = parse_vxlan_payload(&buf[..n])?;
    if vni != expected_outbound_vni {
        return Err(format!(
            "vxlan vni mismatch: expected {expected_outbound_vni}, got {vni}"
        ));
    }
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_inner_ipv4_udp(inner_buf)?;
    if src_ip != cfg.client_dp_ip || dst_ip != cfg.up_dp_ip {
        return Err("inner ip mismatch".to_string());
    }
    if src_port != inner_src_port || dst_port != cfg.up_udp_port {
        return Err("inner port mismatch".to_string());
    }
    if payload != inner_payload {
        return Err("inner payload mismatch".to_string());
    }
    Ok(())
}

fn overlay_vxlan_round_trip(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let inner_payload = b"overlay-vxlan";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40000,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;

    let send_port = 5555u16;
    let outer_dst_ip = cfg.dp_public_ip;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, send_port))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (outer_dst_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, src) = match recv_socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
                let metrics = overlay_metrics_snapshot(metrics_addr);
                let in_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "in")],
                )
                .unwrap_or(0.0);
                let out_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "out")],
                )
                .unwrap_or(0.0);
                let decap_err =
                    metric_plain_value(&metrics, "overlay_decap_errors_total").unwrap_or(0.0);
                let encap_err =
                    metric_plain_value(&metrics, "overlay_encap_errors_total").unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                return Err(format!(
                    "overlay recv failed: {err} (overlay_packets in={}, out={}, decap_errors={}, encap_errors={})\n-- overlay debug --\n{debug}",
                    in_count, out_count, decap_err, encap_err
                ));
            }
            return Err(format!("overlay recv failed: {err}"));
        }
    };
    if src.ip() != IpAddr::V4(outer_dst_ip) {
        return Err(format!("unexpected overlay src ip: {}", src.ip()));
    }
    if src.port() != send_port {
        return Err(format!("unexpected overlay src port: {}", src.port()));
    }
    let (vni, inner_buf) = parse_vxlan_payload(&buf[..n])?;
    if vni != cfg.overlay_vxlan_vni {
        return Err(format!("vxlan vni mismatch: {vni}"));
    }
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_inner_ipv4_udp(inner_buf)?;
    if src_ip != cfg.client_dp_ip || dst_ip != cfg.up_dp_ip {
        return Err("inner ip mismatch".to_string());
    }
    if src_port != 40000 || dst_port != cfg.up_udp_port {
        return Err("inner port mismatch".to_string());
    }
    if payload != inner_payload {
        return Err("inner payload mismatch".to_string());
    }
    Ok(())
}

fn overlay_vxlan_wrong_vni_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-vxlan-bad-vni";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x04],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40100,
        cfg.up_udp_port,
        inner_payload,
    );
    let bad_vni = cfg.overlay_vxlan_vni.wrapping_add(1);
    let payload = build_vxlan_payload(&inner, bad_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5601))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for wrong vni".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_vxlan_wrong_port_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-vxlan-bad-port";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x05],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x06],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40101,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);
    let wrong_port = cfg.overlay_vxlan_port.wrapping_add(1);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5602))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, wrong_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for wrong port".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_vxlan_mtu_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);

    let payload_len = 1250usize;
    let inner_payload = vec![0xa5u8; payload_len];
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x07],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x08],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40102,
        cfg.up_udp_port,
        &inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5603))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for mtu drop".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(150));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay mtu drops did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_round_trip(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let inner_payload = b"overlay-geneve";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x11],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x22],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40001,
        cfg.up_udp_port,
        inner_payload,
    );
    let options = vec![0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04];
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &options)?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;

    let send_port = 5556u16;
    let outer_dst_ip = cfg.dp_public_ip;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, send_port))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (outer_dst_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, src) = match recv_socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
                let metrics = overlay_metrics_snapshot(metrics_addr);
                let in_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "geneve"), ("direction", "in")],
                )
                .unwrap_or(0.0);
                let out_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "geneve"), ("direction", "out")],
                )
                .unwrap_or(0.0);
                let decap_err =
                    metric_plain_value(&metrics, "overlay_decap_errors_total").unwrap_or(0.0);
                let encap_err =
                    metric_plain_value(&metrics, "overlay_encap_errors_total").unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                return Err(format!(
                    "overlay recv failed: {err} (overlay_packets in={}, out={}, decap_errors={}, encap_errors={})\n-- overlay debug --\n{debug}",
                    in_count, out_count, decap_err, encap_err
                ));
            }
            return Err(format!("overlay recv failed: {err}"));
        }
    };
    if src.ip() != IpAddr::V4(outer_dst_ip) {
        return Err(format!("unexpected overlay src ip: {}", src.ip()));
    }
    if src.port() != send_port {
        return Err(format!("unexpected overlay src port: {}", src.port()));
    }
    let (vni, opts, inner_buf) = parse_geneve_payload(&buf[..n])?;
    if vni != cfg.overlay_geneve_vni {
        return Err(format!("geneve vni mismatch: {vni}"));
    }
    if opts != options {
        return Err("geneve options mismatch".to_string());
    }
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_inner_ipv4_udp(inner_buf)?;
    if src_ip != cfg.client_dp_ip || dst_ip != cfg.up_dp_ip {
        return Err("inner ip mismatch".to_string());
    }
    if src_port != 40001 || dst_port != cfg.up_udp_port {
        return Err("inner port mismatch".to_string());
    }
    if payload != inner_payload {
        return Err("inner payload mismatch".to_string());
    }
    Ok(())
}

fn overlay_geneve_wrong_vni_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-geneve-bad-vni";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x13],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x14],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40110,
        cfg.up_udp_port,
        inner_payload,
    );
    let bad_vni = cfg.overlay_geneve_vni.wrapping_add(1);
    let payload = build_geneve_payload(&inner, bad_vni, &[])?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5604))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for wrong vni".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_wrong_port_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-geneve-bad-port";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x15],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x16],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40111,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &[])?;
    let wrong_port = cfg.overlay_geneve_port.wrapping_add(1);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5605))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, wrong_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for wrong port".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_mtu_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);

    let payload_len = 1250usize;
    let inner_payload = vec![0x5au8; payload_len];
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x17],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x18],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40112,
        cfg.up_udp_port,
        &inner_payload,
    );
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &[])?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5606))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for mtu drop".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(150));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay mtu drops did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + inner.len()];
    buf[0] = 0x08;
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[8..].copy_from_slice(inner);
    buf
}

fn build_geneve_payload(inner: &[u8], vni: u32, options: &[u8]) -> Result<Vec<u8>, String> {
    if options.len() % 4 != 0 {
        return Err("geneve options must be a multiple of 4 bytes".to_string());
    }
    let opt_len_words = (options.len() / 4) as u8;
    let header_len = 8 + options.len();
    let mut buf = vec![0u8; header_len + inner.len()];
    buf[0] = opt_len_words & 0x3f;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&0x6558u16.to_be_bytes());
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[7] = 0;
    buf[8..header_len].copy_from_slice(options);
    buf[header_len..].copy_from_slice(inner);
    Ok(buf)
}

fn parse_vxlan_payload(buf: &[u8]) -> Result<(u32, &[u8]), String> {
    if buf.len() < 8 {
        return Err("vxlan payload too short".to_string());
    }
    if buf[0] & 0x08 == 0 {
        return Err("vxlan invalid flags".to_string());
    }
    let vni = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
    Ok((vni, &buf[8..]))
}

fn parse_geneve_payload(buf: &[u8]) -> Result<(u32, Vec<u8>, &[u8]), String> {
    if buf.len() < 8 {
        return Err("geneve payload too short".to_string());
    }
    let ver = buf[0] >> 6;
    if ver != 0 {
        return Err("geneve version mismatch".to_string());
    }
    let opt_len = (buf[0] & 0x3f) as usize * 4;
    let header_len = 8 + opt_len;
    if buf.len() < header_len {
        return Err("geneve options truncated".to_string());
    }
    let proto = u16::from_be_bytes([buf[2], buf[3]]);
    if proto != 0x6558 {
        return Err("geneve proto mismatch".to_string());
    }
    let vni = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
    let options = buf[8..header_len].to_vec();
    Ok((vni, options, &buf[header_len..]))
}

fn parse_inner_ipv4_udp(frame: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>), String> {
    let ip_off = if frame.len() >= 14 {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == 0x0800 {
            14
        } else {
            0
        }
    } else {
        0
    };
    if frame.len() < ip_off + 20 {
        return Err("inner ipv4 too short".to_string());
    }
    if (frame[ip_off] >> 4) != 4 {
        return Err("inner not ipv4".to_string());
    }
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl + 8 {
        return Err("inner ipv4 header invalid".to_string());
    }
    if frame[ip_off + 9] != 17 {
        return Err("inner not udp".to_string());
    }
    let src = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    let udp_off = ip_off + ihl;
    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
    let len = u16::from_be_bytes([frame[udp_off + 4], frame[udp_off + 5]]) as usize;
    if len < 8 || frame.len() < udp_off + len {
        return Err("inner udp length invalid".to_string());
    }
    let payload = frame[udp_off + 8..udp_off + len].to_vec();
    Ok((src, dst, src_port, dst_port, payload))
}
