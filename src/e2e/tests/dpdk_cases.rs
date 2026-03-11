use super::*;

pub(super) fn dpdk_dhcp_l2_hairpin(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::UNSPECIFIED,
            32,
            dataplane_config.clone(),
        );

        let mut dst_ips = IpSetV4::new();
        let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
        dst_ips.add_ip(upstream_ip);

        let rule = Rule {
            id: "allow-upstream".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(dst_ips),
                proto: Proto::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };

        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };

        policy_store
            .rebuild(
                vec![group],
                DnsPolicy::new(Vec::new()),
                Some(DefaultPolicy::Deny),
                crate::dataplane::policy::EnforcementMode::Enforce,
            )
            .map_err(|e| e.to_string())?;

        let policy = policy_store.snapshot();
        let mut state = EngineState::new_with_idle_timeout(
            policy,
            Ipv4Addr::UNSPECIFIED,
            32,
            Ipv4Addr::UNSPECIFIED,
            0,
            120,
        );
        state.set_dataplane_config(dataplane_config.clone());

        let (dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(32);
        let (cp_to_dp_tx, cp_to_dp_rx) = mpsc::channel(32);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(200),
                retry_max: 5,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: dataplane_config.clone(),
            policy_store: policy_store.clone(),
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });

        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        let lease_ip = Ipv4Addr::new(10, 0, 0, 1);
        let _ = mac_tx.send(fw_mac);

        let mut adapter = DpdkAdapter::new("dpdk-test".to_string())?;
        adapter.set_mac(fw_mac);
        adapter.set_dhcp_channels(dp_to_cp_tx, cp_to_dp_rx);

        let mut dhcp = DhcpTestServer::new(server_ip, server_mac, lease_ip, 120);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(cfg) = dataplane_config.get() {
                if cfg.ip == lease_ip {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("dhcp lease not applied".to_string());
            }
            while let Some(frame) = adapter.next_dhcp_frame(&state) {
                if let Some(resp) = dhcp.handle_client_frame(&frame) {
                    let _ = adapter.process_frame(&resp, &mut state);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client_mac = [0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let arp_req = build_arp_request(client_mac, client_ip, lease_ip);
        let arp_reply = adapter
            .process_frame(&arp_req, &mut state)
            .ok_or_else(|| "expected arp reply".to_string())?;
        assert_arp_reply(&arp_reply, client_mac, client_ip, fw_mac, lease_ip)?;

        let outbound = build_ipv4_udp_frame(
            client_mac,
            fw_mac,
            client_ip,
            upstream_ip,
            40_000,
            80,
            b"ping",
        );
        let outbound_frame = adapter
            .process_frame(&outbound, &mut state)
            .ok_or_else(|| "expected outbound frame".to_string())?;
        let (out_src, out_dst, out_sport, out_dport) = parse_ipv4_udp(&outbound_frame)?;
        if out_src != lease_ip {
            return Err(format!("expected snat ip {lease_ip}, got {out_src}"));
        }
        if out_dst != upstream_ip || out_dport != 80 {
            return Err("unexpected outbound tuple".to_string());
        }

        let inbound = build_ipv4_udp_frame(
            server_mac,
            fw_mac,
            upstream_ip,
            lease_ip,
            80,
            out_sport,
            b"pong",
        );
        let inbound_frame = adapter
            .process_frame(&inbound, &mut state)
            .ok_or_else(|| "expected inbound frame".to_string())?;
        let (in_src, in_dst, in_sport, in_dport) = parse_ipv4_udp(&inbound_frame)?;
        if in_src != upstream_ip || in_sport != 80 {
            return Err("unexpected inbound src tuple".to_string());
        }
        if in_dst != client_ip || in_dport != 40_000 {
            return Err("reverse nat failed".to_string());
        }

        dhcp_task.abort();
        Ok(())
    })
}

pub(super) fn dpdk_dhcp_retries_exhausted(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);

        let (_dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(8);
        let (cp_to_dp_tx, mut cp_to_dp_rx) = mpsc::channel(8);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(50),
                retry_max: 2,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: DataplaneConfigStore::new(),
            policy_store,
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });
        let _ = mac_tx.send([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

        let drain_task = tokio::spawn(async move { while cp_to_dp_rx.recv().await.is_some() {} });

        let result = tokio::time::timeout(Duration::from_secs(2), dhcp_task).await;
        drain_task.abort();

        match result {
            Ok(Ok(Ok(()))) => Err("expected dhcp failure, got success".to_string()),
            Ok(Ok(Err(err))) => {
                if err.contains("dhcp discovery retries exceeded") {
                    Ok(())
                } else {
                    Err(format!("unexpected dhcp error: {err}"))
                }
            }
            Ok(Err(err)) => Err(format!("dhcp task join failed: {err}")),
            Err(_) => Err("dhcp task did not finish".to_string()),
        }
    })
}

pub(super) fn dpdk_dhcp_renewal_updates_config(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::UNSPECIFIED,
            32,
            dataplane_config.clone(),
        );

        let mut state = EngineState::new_with_idle_timeout(
            policy_store.snapshot(),
            Ipv4Addr::UNSPECIFIED,
            32,
            Ipv4Addr::UNSPECIFIED,
            0,
            120,
        );
        state.set_dataplane_config(dataplane_config.clone());

        let (dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(32);
        let (cp_to_dp_tx, cp_to_dp_rx) = mpsc::channel(32);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(100),
                retry_max: 5,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: dataplane_config.clone(),
            policy_store,
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });

        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xef];
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        let lease_ip = Ipv4Addr::new(10, 0, 0, 1);
        let lease_ip_new = Ipv4Addr::new(10, 0, 0, 9);
        let _ = mac_tx.send(fw_mac);

        let mut adapter = DpdkAdapter::new("dpdk-renew".to_string())?;
        adapter.set_mac(fw_mac);
        adapter.set_dhcp_channels(dp_to_cp_tx, cp_to_dp_rx);

        let mut dhcp = DhcpTestServer::new(server_ip, server_mac, lease_ip, 2);
        let mut saw_initial = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(cfg) = dataplane_config.get() {
                if cfg.ip == lease_ip_new {
                    break;
                }
                if cfg.ip == lease_ip && !saw_initial {
                    saw_initial = true;
                    dhcp.lease_ip = lease_ip_new;
                    dhcp.lease_time_secs = 2;
                }
            }
            if Instant::now() >= deadline {
                return Err("dhcp renewal did not update lease".to_string());
            }
            while let Some(frame) = adapter.next_dhcp_frame(&state) {
                if let Some(resp) = dhcp.handle_client_frame(&frame) {
                    let _ = adapter.process_frame(&resp, &mut state);
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        dhcp_task.abort();
        Ok(())
    })
}

pub(super) fn dpdk_tls_intercept_service_lane_round_trip(
    _cfg: &TopologyConfig,
) -> Result<(), String> {
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let client_mac = [0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_ip = Ipv4Addr::new(10, 0, 0, 42);
    let fw_ip = Ipv4Addr::new(10, 0, 0, 1);
    let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
    let client_port = 40_000;

    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let rule = Rule {
        id: "tls-intercept".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: Some(TlsMatch {
                mode: TlsMode::Intercept,
                sni: None,
                server_san: None,
                server_cn: None,
                fingerprints_sha256: Vec::new(),
                trust_anchors: Vec::new(),
                tls13_uninspectable: Tls13Uninspectable::Deny,
                intercept_http: None,
            }),
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    };
    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };
    let policy = Arc::new(RwLock::new(PolicySnapshot::new_with_generation(
        DefaultPolicy::Deny,
        vec![group],
        1,
    )));

    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(std::sync::atomic::AtomicU64::new(1)));
    state.set_intercept_to_host_steering(true);
    state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: fw_mac,
        lease_expiry: None,
    });

    let shared_arp = Arc::new(Mutex::new(SharedArpState::default()));
    let shared_demux = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));
    let mut ingress = DpdkAdapter::new("dpdk-ingress".to_string())?;
    let mut egress = DpdkAdapter::new("dpdk-egress".to_string())?;
    ingress.set_mac(fw_mac);
    egress.set_mac(fw_mac);
    ingress.set_shared_arp(shared_arp.clone());
    egress.set_shared_arp(shared_arp);
    ingress.set_shared_intercept_demux(shared_demux.clone());
    egress.set_shared_intercept_demux(shared_demux);

    let arp_req = build_arp_request(client_mac, client_ip, fw_ip);
    let arp_reply = ingress
        .process_frame(&arp_req, &mut state)
        .ok_or_else(|| "expected arp reply".to_string())?;
    assert_arp_reply(&arp_reply, client_mac, client_ip, fw_mac, fw_ip)?;

    let syn = build_ipv4_tcp_frame(
        client_mac,
        fw_mac,
        client_ip,
        upstream_ip,
        client_port,
        443,
        1,
        0,
        0x02,
        &[],
    );
    if ingress.process_frame(&syn, &mut state).is_some() {
        return Err("intercept flow should not egress dataplane directly".to_string());
    }
    let host_frame = ingress
        .next_host_frame()
        .ok_or_else(|| "expected service-lane host frame".to_string())?;
    let (host_src_ip, host_dst_ip, host_src_port, host_dst_port) = parse_ipv4_tcp(&host_frame)?;
    if host_src_ip != client_ip || host_src_port != client_port {
        return Err("service-lane host frame source tuple mismatch".to_string());
    }
    if host_dst_ip != Ipv4Addr::new(169, 254, 255, 1) || host_dst_port != 15_443 {
        return Err("service-lane host frame did not target intercept endpoint".to_string());
    }

    let service_lane_egress = build_ipv4_tcp_frame(
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        fw_mac,
        Ipv4Addr::new(169, 254, 255, 1),
        client_ip,
        15_443,
        client_port,
        2,
        2,
        0x18,
        b"ok",
    );
    let forwarded = egress
        .process_service_lane_egress_frame(&service_lane_egress, &state)
        .ok_or_else(|| "service-lane return frame did not forward".to_string())?;
    let (src_ip, dst_ip, src_port, dst_port) = parse_ipv4_tcp(&forwarded)?;
    if src_ip != upstream_ip || src_port != 443 {
        return Err("forwarded frame source tuple mismatch".to_string());
    }
    if dst_ip != client_ip || dst_port != client_port {
        return Err("forwarded frame destination tuple mismatch".to_string());
    }
    if forwarded[0..6] != client_mac || forwarded[6..12] != fw_mac {
        return Err("forwarded frame L2 rewrite mismatch".to_string());
    }
    if egress.next_dhcp_frame(&state).is_some() {
        return Err("unexpected ARP request queued on service-lane return path".to_string());
    }

    Ok(())
}
