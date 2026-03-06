fn init_port(iface: &str, queue_count: u16) -> Result<PortSetup, String> {
    let cached = PORT_INIT.get_or_init(|| {
            let mut queue_count = queue_count.max(1);
            let ports = available_ports();
            if ports.is_empty() {
                return Err("dpdk: no ethernet ports available".to_string());
            }
            eprintln!("dpdk: {} ports available", ports.len());
            for port in ports.iter() {
                eprintln!(
                    "dpdk: port {} mac {}{}",
                    port.id,
                    format_mac(port.mac),
                    port.name
                        .as_deref()
                        .map(|name| format!(" name={}", name))
                        .unwrap_or_default()
                );
            }
            let port_id = match port_id_for_iface_or_pci(iface, &ports) {
                Ok(id) => id,
                Err(err) => return Err(err),
            };
            eprintln!("dpdk: selected port {}", port_id);

            let dev_info = read_device_info_caps(port_id)?;
            let driver_name = dev_info.driver_name.clone();
            if let Some(name) = driver_name.as_deref() {
                eprintln!(
                    "dpdk: driver={} max_rx_queues={} max_tx_queues={} reta_size={} rss_offloads=0x{:x}",
                    name,
                    dev_info.max_rx_queues,
                    dev_info.max_tx_queues,
                    dev_info.reta_size,
                    dev_info.flow_type_rss_offloads
                );
            }
            let mut max_rx = dev_info.max_rx_queues;
            let mut max_tx = dev_info.max_tx_queues;
            let mut clamp_queue_count = true;
            if queue_caps_look_unreliable(max_rx, max_tx) {
                clamp_queue_count = false;
                eprintln!(
                    "dpdk: queue caps look unreliable (max_rx={} max_tx={}); skipping cap clamp and probing requested queue count",
                    max_rx, max_tx
                );
            } else {
                max_rx = max_rx.max(1);
                max_tx = max_tx.max(1);
            }
            if let Some(override_queues) = parse_queue_cap_override() {
                eprintln!(
                    "dpdk: NEUWERK_DPDK_QUEUE_OVERRIDE={} overriding reported queue caps rx={} tx={}",
                    override_queues, max_rx, max_tx
                );
                max_rx = override_queues;
                max_tx = override_queues;
                clamp_queue_count = true;
            }
            if clamp_queue_count {
                let max_supported = max_rx.min(max_tx).max(1);
                if queue_count > max_supported {
                    eprintln!(
                        "dpdk: requested {} queues, but device supports rx={} tx={}, clamping to {}",
                        queue_count, max_rx, max_tx, max_supported
                    );
                    queue_count = max_supported;
                }
            }

            let socket_id_raw = unsafe { rte_eth_dev_socket_id(port_id as u16) };
            let socket_id = if socket_id_raw < 0 {
                0i32
            } else {
                socket_id_raw
            };
            let socket_id_u32 = socket_id as u32;
            let pool_name = CString::new("mbuf_pool")
                .map_err(|_| "dpdk: invalid mempool name".to_string())?;
            let mempool = create_mempool(&pool_name, socket_id)?;

            let mut rss_hf = 0u64;
            let mut use_rss_mq = queue_count > 1;
            let tx_csum_env_enabled = std::env::var("NEUWERK_DPDK_TX_CSUM_OFFLOAD")
                .map(|val| !matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
                .unwrap_or_else(|_| {
                    let is_ena = driver_name
                        .as_deref()
                        .map(|name| name.to_ascii_lowercase().contains("ena"))
                        .unwrap_or(false);
                    if is_ena {
                        eprintln!(
                            "dpdk: driver {} defaulting tx checksum offload to disabled; set NEUWERK_DPDK_TX_CSUM_OFFLOAD=1 to force-enable",
                            driver_name.as_deref().unwrap_or("unknown")
                        );
                        false
                    } else {
                        true
                    }
                });
            let mut tx_csum_offload = TxChecksumOffloadCaps::default();
            if tx_csum_env_enabled {
                tx_csum_offload.ipv4 =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_IPV4_CKSUM as u64)) != 0;
                tx_csum_offload.tcp =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_TCP_CKSUM as u64)) != 0;
                tx_csum_offload.udp =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_UDP_CKSUM as u64)) != 0;
            }
            let mut tx_offloads = 0u64;
            if tx_csum_offload.ipv4 {
                tx_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM as u64;
            }
            if tx_csum_offload.tcp {
                tx_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM as u64;
            }
            if tx_csum_offload.udp {
                tx_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM as u64;
            }
            if (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64)) != 0 {
                tx_offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            }
            eprintln!(
                "dpdk: tx offload capa=0x{:x} enabled=0x{:x} (ipv4={}, tcp={}, udp={})",
                dev_info.tx_offload_capa,
                tx_offloads,
                tx_csum_offload.ipv4,
                tx_csum_offload.tcp,
                tx_csum_offload.udp
            );
            if queue_count > 1 {
                let is_gve_no_rss = driver_name
                    .as_deref()
                    .map(|name| name.to_ascii_lowercase().contains("gve"))
                    .unwrap_or(false)
                    && dev_info.flow_type_rss_offloads == 0;
                if is_gve_no_rss {
                    use_rss_mq = false;
                    eprintln!(
                        "dpdk: driver {} reports rss_offloads=0; configuring multi-queue without explicit RSS mq mode",
                        driver_name.as_deref().unwrap_or("unknown")
                    );
                }
            }
            if queue_count > 1 && use_rss_mq {
                if should_use_pmd_default_rss_hf(
                    driver_name.as_deref(),
                    dev_info.flow_type_rss_offloads,
                ) {
                    rss_hf = 0;
                    eprintln!(
                        "dpdk: driver {} using PMD default rss_hf due to limited supported_hf=0x{:x}",
                        driver_name.as_deref().unwrap_or("unknown"),
                        dev_info.flow_type_rss_offloads
                    );
                } else {
                    rss_hf = preferred_rss_hf(dev_info.flow_type_rss_offloads);
                    if rss_hf == 0 {
                        rss_hf = fallback_rss_hf();
                        eprintln!(
                            "dpdk: rss capability mask unavailable (supported_hf=0x{:x}); using fallback_hf=0x{:x}",
                            dev_info.flow_type_rss_offloads, rss_hf
                        );
                    }
                }
            }

            if queue_count > 1 && use_rss_mq {
                eprintln!(
                    "dpdk: rss supported_hf=0x{:x} selected_hf=0x{:x}",
                    dev_info.flow_type_rss_offloads, rss_hf
                );
            } else if queue_count > 1 {
                eprintln!(
                    "dpdk: queue_count={} with PMD default mq configuration (no explicit RSS settings)",
                    queue_count
                );
            }
            let mut requested_port_mtu = parse_port_mtu_override();
            if let Some(mut mtu) = requested_port_mtu {
                let requested_frame_len = (mtu as u32).saturating_add(MTU_FRAME_OVERHEAD);
                if dev_info.max_rx_pktlen > 0 && requested_frame_len > dev_info.max_rx_pktlen {
                    let clamped = dev_info.max_rx_pktlen.saturating_sub(MTU_FRAME_OVERHEAD);
                    let clamped_mtu = clamped.min(u16::MAX as u32) as u16;
                    if clamped_mtu < MIN_VALID_MTU {
                        eprintln!(
                            "dpdk: mtu override {} exceeds driver max_rx_pktlen={} and clamp would be invalid; ignoring",
                            mtu, dev_info.max_rx_pktlen
                        );
                        requested_port_mtu = None;
                    } else {
                        eprintln!(
                            "dpdk: clamped NEUWERK_DPDK_PORT_MTU {} -> {} (driver max_rx_pktlen={})",
                            mtu, clamped_mtu, dev_info.max_rx_pktlen
                        );
                        mtu = clamped_mtu;
                        requested_port_mtu = Some(mtu);
                    }
                }
            }
            if let Some(mtu) = requested_port_mtu {
                if mtu > 1500 {
                    let jumbo_supported =
                        (dev_info.rx_offload_capa & (DEV_RX_OFFLOAD_JUMBO_FRAME as u64)) != 0;
                    if jumbo_supported {
                        let frame_len = (mtu as u32).saturating_add(MTU_FRAME_OVERHEAD);
                        eprintln!(
                            "dpdk: jumbo mtu={} requested (frame_len={}) but runtime configure currently keeps PMD defaults; applying mtu via rte_eth_dev_set_mtu after start",
                            mtu, frame_len
                        );
                    } else {
                        eprintln!(
                            "dpdk: mtu override {} requested but DEV_RX_OFFLOAD_JUMBO_FRAME unsupported (rx_offload_capa=0x{:x})",
                            mtu, dev_info.rx_offload_capa
                        );
                    }
                } else {
                    eprintln!("dpdk: applying non-jumbo mtu override {}", mtu);
                }
            }
            let mut ret = unsafe {
                rust_rte_eth_dev_configure_basic(
                    port_id,
                    queue_count,
                    queue_count,
                    if queue_count > 1 && use_rss_mq { 1 } else { 0 },
                    rss_hf,
                    tx_offloads,
                )
            };
            if ret < 0 && queue_count > 1 && use_rss_mq && rss_hf != 0 {
                eprintln!(
                    "dpdk: multi-queue configure with rss_hf=0x{:x} failed (ret={}); retrying with rss_hf=0",
                    rss_hf, ret
                );
                ret = unsafe {
                    rust_rte_eth_dev_configure_basic(
                        port_id,
                        queue_count,
                        queue_count,
                        1,
                        0,
                        tx_offloads,
                    )
                };
            }
            if ret < 0 && queue_count > 2 {
                eprintln!(
                    "dpdk: multi-queue configure failed at {} queues (ret={}); probing 2 queues",
                    queue_count, ret
                );
                ret = unsafe {
                    rust_rte_eth_dev_configure_basic(
                        port_id,
                        2,
                        2,
                        if use_rss_mq { 1 } else { 0 },
                        rss_hf,
                        tx_offloads,
                    )
                };
                if ret < 0 && use_rss_mq && rss_hf != 0 {
                    eprintln!(
                        "dpdk: 2-queue configure with rss_hf=0x{:x} failed (ret={}); retrying with rss_hf=0",
                        rss_hf, ret
                    );
                    ret = unsafe {
                        rust_rte_eth_dev_configure_basic(port_id, 2, 2, 1, 0, tx_offloads)
                    };
                }
                if ret >= 0 {
                    queue_count = 2;
                    eprintln!("dpdk: configured 2 queues after probe fallback");
                }
            }
            if ret < 0 && queue_count > 1 {
                eprintln!(
                    "dpdk: multi-queue configure failed (ret={ret}); retrying with single queue"
                );
                queue_count = 1;
                ret = unsafe { rust_rte_eth_dev_configure_basic(port_id, 1, 1, 0, 0, tx_offloads) };
            }
            if ret < 0 {
                return Err(format!("dpdk: port configure failed ({ret})"));
            }

            // Let PMD constrain descriptor counts to hardware-supported values.
            let mut rx_desc = RX_RING_SIZE;
            let mut tx_desc = TX_RING_SIZE;
            let adjust_ret = unsafe {
                rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &mut rx_desc, &mut tx_desc)
            };
            if adjust_ret < 0 {
                eprintln!(
                    "dpdk: descriptor adjust failed (ret={}); using rx={} tx={}",
                    adjust_ret, rx_desc, tx_desc
                );
            } else if rx_desc != RX_RING_SIZE || tx_desc != TX_RING_SIZE {
                eprintln!(
                    "dpdk: descriptor sizes adjusted by PMD rx={}=>{} tx={}=>{}",
                    RX_RING_SIZE, rx_desc, TX_RING_SIZE, tx_desc
                );
            }

            for queue_id in 0..queue_count {
                let ret = unsafe {
                    rte_eth_rx_queue_setup(
                        port_id,
                        queue_id,
                        rx_desc,
                        socket_id_u32,
                        ptr::null(),
                        mempool,
                    )
                };
                if ret < 0 {
                    return Err(format!("dpdk: rx queue {} setup failed ({ret})", queue_id));
                }

                // Prefer PMD defaults for tx queue config to avoid ABI-sensitive
                // txconf layout issues across distro DPDK variants (observed on
                // AWS ENA as "Tx conf reserved fields not zero").
                let ret = unsafe {
                    rte_eth_tx_queue_setup(
                        port_id,
                        queue_id,
                        tx_desc,
                        socket_id_u32,
                        ptr::null(),
                    )
                };
                if ret < 0 {
                    return Err(format!("dpdk: tx queue {} setup failed ({ret})", queue_id));
                }
            }

            let ret = unsafe { rte_eth_dev_start(port_id) };
            if ret < 0 {
                return Err(format!("dpdk: port start failed ({ret})"));
            }

            unsafe {
                rte_eth_promiscuous_enable(port_id);
            }
            if let Some(mtu) = requested_port_mtu {
                let set_ret = unsafe { rte_eth_dev_set_mtu(port_id, mtu) };
                if set_ret < 0 {
                    eprintln!("dpdk: rte_eth_dev_set_mtu({}) failed ({})", mtu, set_ret);
                } else {
                    eprintln!("dpdk: rte_eth_dev_set_mtu({}) applied", mtu);
                }
                let mut effective_mtu = 0u16;
                let get_ret = unsafe { rte_eth_dev_get_mtu(port_id, &mut effective_mtu) };
                if get_ret < 0 {
                    eprintln!("dpdk: rte_eth_dev_get_mtu failed ({})", get_ret);
                } else {
                    eprintln!("dpdk: effective port mtu {}", effective_mtu);
                }
            }
            if queue_count > 1 && use_rss_mq {
                if let Err(err) =
                    configure_rss_reta(port_id, queue_count, dev_info.reta_size as u16)
                {
                    eprintln!("{err}");
                    eprintln!("dpdk: continuing without explicit reta override");
                }
            }

            let mut addr: ether_addr = unsafe { std::mem::zeroed() };
            unsafe {
                rte_eth_macaddr_get(port_id, &mut addr);
            }
            let mac = addr.addr_bytes;
            let ena_xstat_ids = discover_ena_allowance_xstats(port_id);

            Ok(PortSetup {
                port_id,
                mempool,
                mac,
                queue_count,
                tx_csum_offload,
                ena_xstat_ids,
            })
        });

    match cached {
        Ok(setup) => {
            if setup.queue_count != queue_count {
                eprintln!(
                    "dpdk: port already initialized with {} queues (requested {}), using {}",
                    setup.queue_count, queue_count, setup.queue_count
                );
            }
            Ok(PortSetup {
                port_id: setup.port_id,
                mempool: setup.mempool,
                mac: setup.mac,
                queue_count: setup.queue_count,
                tx_csum_offload: setup.tx_csum_offload,
                ena_xstat_ids: setup.ena_xstat_ids.clone(),
            })
        }
        Err(err) => Err(err.clone()),
    }
}

