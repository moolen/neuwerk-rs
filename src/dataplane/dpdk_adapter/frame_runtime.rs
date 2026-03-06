impl DpdkAdapter {
    pub fn process_frame(&mut self, frame: &[u8], state: &mut EngineState) -> Option<Vec<u8>> {
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETH_TYPE_ARP => return self.handle_arp(frame, state),
            ETH_TYPE_IPV4 => {}
            _ => return None,
        }

        if let Some(resp) = self.handle_health_probe(frame, state) {
            return Some(resp);
        }

        if self.handle_dhcp(frame) {
            return None;
        }

        if state.overlay.mode != EncapMode::None {
            let overlay_debug = overlay_debug_enabled();
            let overlay_pkt = match overlay::decap(frame, &state.overlay, state.metrics()) {
                Ok(pkt) => pkt,
                Err(_) => return None,
            };
            let mut inner = overlay_pkt.inner;
            if overlay_debug && (inner.src_ip().is_none() || inner.dst_ip().is_none()) {
                if OVERLAY_PARSE_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                    let buf = inner.buffer();
                    let ethertype = if buf.len() >= ETH_HDR_LEN {
                        u16::from_be_bytes([buf[12], buf[13]])
                    } else {
                        0
                    };
                    let head_len = buf.len().min(32);
                    eprintln!(
                        "dpdk: overlay inner parse failed (len={}, ethertype=0x{:04x}, head={:02x?}, meta={:?})",
                        buf.len(),
                        ethertype,
                        &buf[..head_len],
                        overlay_pkt.meta
                    );
                }
            }
            if overlay_debug && OVERLAY_SAMPLE_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                let src = inner.src_ip();
                let dst = inner.dst_ip();
                let proto = inner.protocol();
                eprintln!(
                    "dpdk: overlay inner sample src={:?} dst={:?} proto={:?} len={} meta={:?}",
                    src,
                    dst,
                    proto,
                    inner.len(),
                    overlay_pkt.meta
                );
            }
            if overlay_debug && OVERLAY_INTERNAL_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                if let (Some(src), Some(dst)) = (inner.src_ip(), inner.dst_ip()) {
                    if state.is_internal(src) || state.is_internal(dst) {
                        eprintln!(
                            "dpdk: overlay internal flow src={} dst={} proto={:?} meta={:?}",
                            src,
                            dst,
                            inner.protocol(),
                            overlay_pkt.meta
                        );
                    }
                }
            }
            overlay::maybe_clamp_mss(&mut inner, &state.overlay, &overlay_pkt.meta);
            let swap_tunnel = overlay_swap_tunnels();
            let mut out_meta = overlay::reply_meta(&overlay_pkt.meta, &state.overlay, swap_tunnel);
            if overlay_force_tunnel_src_port() {
                let port = out_meta.udp_port(&state.overlay);
                out_meta.set_outer_src_port(port);
            }
            if overlay_debug
                && overlay_pkt.meta.tunnel_label() != out_meta.tunnel_label()
                && OVERLAY_TUNNEL_LOGS.fetch_add(1, Ordering::Relaxed) < 10
            {
                eprintln!(
                    "dpdk: overlay tunnel swap {} -> {}",
                    overlay_pkt.meta.tunnel_label(),
                    out_meta.tunnel_label()
                );
            }
            let action = crate::dataplane::engine::handle_packet(&mut inner, state);
            if overlay_debug && OVERLAY_ACTION_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                let ports = inner.ports();
                eprintln!(
                    "dpdk: overlay action={:?} src={:?} dst={:?} ports={:?} meta={:?}",
                    action,
                    inner.src_ip(),
                    inner.dst_ip(),
                    ports,
                    &out_meta
                );
            }
            return match action {
                Action::Forward { .. } | Action::ToHost => {
                    match overlay::encap(&inner, &out_meta, &state.overlay, state.metrics()) {
                        Ok(frame) => Some(frame),
                        Err(err) => {
                            if overlay_debug
                                && OVERLAY_ENCAP_LOGS.fetch_add(1, Ordering::Relaxed) < 20
                            {
                                eprintln!(
                                    "dpdk: overlay encap failed err={:?} src={:?} dst={:?} meta={:?}",
                                    err,
                                    inner.src_ip(),
                                    inner.dst_ip(),
                                    &out_meta
                                );
                            }
                            None
                        }
                    }
                }
                Action::Drop => None,
            };
        }

        let mut pkt = Packet::from_bytes(frame);
        match crate::dataplane::engine::handle_packet(&mut pkt, state) {
            Action::Forward { .. } => self.rewrite_l2_for_forward(&mut pkt, state),
            Action::ToHost => {
                self.queue_intercept_host_frame(pkt.buffer());
                None
            }
            Action::Drop => None,
        }
    }

    pub fn process_packet_in_place<'a>(
        &'a mut self,
        pkt: &'a mut Packet,
        state: &mut EngineState,
    ) -> Option<FrameOut<'a>> {
        let frame = pkt.buffer();
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETH_TYPE_ARP => return self.handle_arp(frame, state).map(FrameOut::Owned),
            ETH_TYPE_IPV4 => {}
            _ => return None,
        }

        if let Some(resp) = self.handle_health_probe(frame, state) {
            return Some(FrameOut::Owned(resp));
        }

        if self.handle_dhcp(frame) {
            return None;
        }

        if state.overlay.mode != EncapMode::None {
            return self.process_frame(frame, state).map(FrameOut::Owned);
        }

        match crate::dataplane::engine::handle_packet(pkt, state) {
            Action::Forward { .. } => {
                if self.rewrite_l2_for_forward_in_place(pkt, state) {
                    Some(FrameOut::Borrowed(pkt.buffer()))
                } else {
                    None
                }
            }
            Action::ToHost => {
                self.queue_intercept_host_frame(pkt.buffer());
                None
            }
            Action::Drop => None,
        }
    }

    pub fn next_dhcp_frame(&mut self, state: &EngineState) -> Option<Vec<u8>> {
        if let Some(frame) = self.pending_frames.pop_front() {
            return Some(frame);
        }
        let rx = self.dhcp_rx.as_mut()?;
        let msg = match rx.try_recv() {
            Ok(msg) => msg,
            Err(_) => return None,
        };
        let frame = self.build_dhcp_frame(state, msg)?;
        eprintln!("dpdk: sending dhcp frame len={}", frame.len());
        Some(frame)
    }

    pub fn run(&mut self, _state: &mut EngineState) -> Result<(), String> {
        println!(
            "dataplane started (dpdk), data-plane-interface={}",
            self.data_iface
        );
        Err("dpdk adapter io not wired".to_string())
    }

    pub fn run_with_io<I: FrameIo>(
        &mut self,
        state: &mut EngineState,
        io: &mut I,
    ) -> Result<(), String> {
        println!(
            "dataplane started (dpdk), data-plane-interface={}",
            self.data_iface
        );
        if let Some(mac) = io.mac() {
            self.set_mac(mac);
        }
        let mut pkt = Packet::new(vec![0u8; 65536]);
        loop {
            self.refresh_service_lane_steering(state);
            let n = io.recv_packet(&mut pkt)?;
            if n == 0 {
                io.finish_rx_packet();
                io.flush()?;
                self.drain_service_lane_egress(state, io)?;
                self.flush_host_frames(io)?;
                while let Some(out) = self.next_dhcp_frame(state) {
                    io.send_frame(&out)?;
                }
                continue;
            }
            let step_result = (|| -> Result<(), String> {
                if let Some(out) = self.process_packet_in_place(&mut pkt, state) {
                    match out {
                        FrameOut::Borrowed(frame) => io.send_borrowed_frame(frame)?,
                        FrameOut::Owned(frame) => io.send_frame(&frame)?,
                    }
                }
                self.drain_service_lane_egress(state, io)?;
                self.flush_host_frames(io)?;
                while let Some(out) = self.next_dhcp_frame(state) {
                    io.send_frame(&out)?;
                }
                Ok(())
            })();
            io.finish_rx_packet();
            step_result?;
        }
    }

    fn handle_dhcp(&mut self, frame: &[u8]) -> bool {
        let eth = match parse_eth(frame) {
            Some(eth) => eth,
            None => return false,
        };
        let ipv4 = match parse_ipv4(frame, eth.payload_offset) {
            Some(ipv4) => ipv4,
            None => return false,
        };
        if ipv4.proto != 17 {
            return false;
        }
        let udp = match parse_udp(frame, ipv4.l4_offset) {
            Some(udp) => udp,
            None => return false,
        };
        if udp.dst_port != DHCP_CLIENT_PORT || udp.src_port != DHCP_SERVER_PORT {
            return false;
        }
        let payload = match frame.get(udp.payload_offset..udp.payload_offset + udp.payload_len) {
            Some(payload) => payload.to_vec(),
            None => return false,
        };
        if let Some(tx) = &self.dhcp_tx {
            let _ = tx.try_send(DhcpRx {
                src_ip: ipv4.src,
                payload,
            });
        }
        // DHCP replies come from a valid L2 peer; seed ARP for the sender so
        // early forwarded traffic after lease acquisition can resolve gateway MAC.
        self.insert_arp(ipv4.src, eth.src_mac);
        eprintln!("dpdk: received dhcp frame from {}", ipv4.src);
        self.dhcp_server_hint = Some(DhcpServerHint {
            ip: ipv4.src,
            mac: eth.src_mac,
        });
        true
    }

    fn handle_arp(&mut self, frame: &[u8], state: &EngineState) -> Option<Vec<u8>> {
        if let Some(reply) = parse_arp_reply(frame) {
            self.insert_arp(reply.sender_ip, reply.sender_mac);
            if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                eprintln!(
                    "dpdk: arp reply sender_ip={} sender_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    reply.sender_ip,
                    reply.sender_mac[0],
                    reply.sender_mac[1],
                    reply.sender_mac[2],
                    reply.sender_mac[3],
                    reply.sender_mac[4],
                    reply.sender_mac[5]
                );
            }
            return None;
        }

        let cfg = state.dataplane_config.get()?;
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return None;
        }
        parse_arp_request(frame, cfg.ip).map(|req| {
            self.insert_arp(req.sender_ip, req.sender_mac);
            state.inc_dp_arp_handled();
            build_arp_reply(req.sender_mac, req.sender_ip, cfg.mac, cfg.ip)
        })
    }

    fn insert_arp(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        if mac == [0; 6] || ip == Ipv4Addr::UNSPECIFIED {
            return;
        }
        let entry = ArpEntry {
            mac,
            last_seen: Instant::now(),
        };
        self.arp_cache.insert(ip, entry);
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                guard.cache.insert(ip, entry);
            }
        }
    }

    fn lookup_arp(&mut self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        if let Some(entry) = self.arp_cache.get(&ip).copied() {
            if entry.last_seen.elapsed() <= Duration::from_secs(ARP_CACHE_TTL_SECS) {
                return Some(entry.mac);
            }
            self.arp_cache.remove(&ip);
        }
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                if let Some(entry) = guard.cache.get(&ip).copied() {
                    if entry.last_seen.elapsed() <= Duration::from_secs(ARP_CACHE_TTL_SECS) {
                        self.arp_cache.insert(ip, entry);
                        return Some(entry.mac);
                    }
                    guard.cache.remove(&ip);
                }
            }
        }
        None
    }

    fn maybe_queue_arp_request(&mut self, src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
        let now = Instant::now();
        let mut should_send = match self.arp_last_request.get(&target_ip) {
            Some(last) => {
                now.duration_since(*last) >= Duration::from_millis(ARP_REQUEST_COOLDOWN_MS)
            }
            None => true,
        };
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                let shared_ok = match guard.last_request.get(&target_ip) {
                    Some(last) => {
                        now.duration_since(*last) >= Duration::from_millis(ARP_REQUEST_COOLDOWN_MS)
                    }
                    None => true,
                };
                should_send &= shared_ok;
                if should_send {
                    guard.last_request.insert(target_ip, now);
                }
            }
        }
        if !should_send {
            return;
        }
        self.arp_last_request.insert(target_ip, now);
        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dpdk: arp request src_ip={} target_ip={}",
                src_ip, target_ip
            );
        }
        let frame = build_arp_request(src_mac, src_ip, target_ip);
        self.pending_frames.push_back(frame);
    }

    fn rewrite_l2_for_forward(&mut self, pkt: &mut Packet, state: &EngineState) -> Option<Vec<u8>> {
        if self.rewrite_l2_for_forward_in_place(pkt, state) {
            return Some(pkt.buffer().to_vec());
        }
        None
    }

    fn rewrite_l2_for_forward_in_place(&mut self, pkt: &mut Packet, state: &EngineState) -> bool {
        let cfg = match state.dataplane_config.get() {
            Some(cfg) => cfg,
            None => return false,
        };
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return false;
        }
        let dst_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => return false,
        };
        let buf = pkt.buffer_mut();
        if buf.len() < ETH_HDR_LEN {
            return false;
        }
        if u16::from_be_bytes([buf[12], buf[13]]) != ETH_TYPE_IPV4 {
            return true;
        }

        let next_hop = if cfg.gateway != Ipv4Addr::UNSPECIFIED
            && !ipv4_in_subnet(dst_ip, cfg.ip, cfg.prefix)
        {
            cfg.gateway
        } else {
            dst_ip
        };

        let src_mac = select_mac(self.mac, Some(cfg.mac));
        let dst_mac = match self.lookup_arp(next_hop) {
            Some(mac) => mac,
            None => {
                if next_hop == cfg.gateway {
                    if let Some(mac) = azure_gateway_mac() {
                        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                            eprintln!(
                                "dpdk: using azure gateway mac for next_hop={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                next_hop,
                                mac[0],
                                mac[1],
                                mac[2],
                                mac[3],
                                mac[4],
                                mac[5]
                            );
                        }
                        self.insert_arp(next_hop, mac);
                        if let Some(mac) = self.lookup_arp(next_hop) {
                            mac
                        } else {
                            return false;
                        }
                    } else {
                        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                            eprintln!(
                                "dpdk: arp miss next_hop={} src_ip={} dst_ip={}",
                                next_hop, cfg.ip, dst_ip
                            );
                        }
                        self.maybe_queue_arp_request(src_mac, cfg.ip, next_hop);
                        return false;
                    }
                } else {
                    if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                        eprintln!(
                            "dpdk: arp miss next_hop={} src_ip={} dst_ip={}",
                            next_hop, cfg.ip, dst_ip
                        );
                    }
                    self.maybe_queue_arp_request(src_mac, cfg.ip, next_hop);
                    return false;
                }
            }
        };

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        true
    }

    fn build_dhcp_frame(&self, state: &EngineState, msg: DhcpTx) -> Option<Vec<u8>> {
        let cfg = state.dataplane_config.get();
        let src_mac = select_mac(self.mac, cfg.map(|c| c.mac));
        let (dst_ip, src_ip, payload, dst_mac) = match msg {
            DhcpTx::Broadcast { payload } => (
                Ipv4Addr::BROADCAST,
                Ipv4Addr::UNSPECIFIED,
                payload,
                [0xff; 6],
            ),
            DhcpTx::Unicast { payload, dst_ip } => {
                let src_ip = cfg.map(|c| c.ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
                let dst_mac = self
                    .dhcp_server_hint
                    .filter(|hint| hint.ip == dst_ip)
                    .map(|hint| hint.mac)
                    .unwrap_or([0xff; 6]);
                (dst_ip, src_ip, payload, dst_mac)
            }
        };
        Some(build_udp_frame(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            &payload,
        ))
    }

    fn handle_health_probe(&self, frame: &[u8], state: &EngineState) -> Option<Vec<u8>> {
        let cfg = state.dataplane_config.get()?;
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return None;
        }
        let eth = parse_eth(frame)?;
        let ipv4 = parse_ipv4(frame, eth.payload_offset)?;
        if ipv4.proto != 6 || ipv4.dst != cfg.ip {
            return None;
        }
        let tcp = parse_tcp(frame, ipv4.l4_offset)?;
        if tcp.dst_port != HEALTH_PROBE_PORT {
            return None;
        }
        let metrics = state.metrics();
        let probe_debug = health_probe_debug_enabled();
        if tcp.flags & TCP_FLAG_SYN != 0 {
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_health_probe("syn_seen");
                metrics.inc_dpdk_health_probe("synack_sent");
            }
            if probe_debug && HEALTH_PROBE_DEBUG_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
                eprintln!(
                    "dpdk: health probe syn src={}:{} dst={}:{} seq={} ack={} flags=0x{:02x}",
                    ipv4.src, tcp.src_port, cfg.ip, HEALTH_PROBE_PORT, tcp.seq, tcp.ack, tcp.flags
                );
            }
            let ack = tcp.seq.wrapping_add(1);
            if !HEALTH_PROBE_LOGGED.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "dpdk: health probe response src={} dst={} port={}",
                    ipv4.src, cfg.ip, tcp.dst_port
                );
            }
            return Some(build_tcp_control(
                cfg.mac,
                eth.src_mac,
                cfg.ip,
                ipv4.src,
                HEALTH_PROBE_PORT,
                tcp.src_port,
                0,
                ack,
                TCP_FLAG_SYN | TCP_FLAG_ACK,
            ));
        }
        if tcp.flags & TCP_FLAG_FIN != 0 {
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_health_probe("fin_seen");
                metrics.inc_dpdk_health_probe("finack_sent");
            }
            if probe_debug && HEALTH_PROBE_DEBUG_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
                eprintln!(
                    "dpdk: health probe fin src={}:{} dst={}:{} seq={} ack={} flags=0x{:02x}",
                    ipv4.src, tcp.src_port, cfg.ip, HEALTH_PROBE_PORT, tcp.seq, tcp.ack, tcp.flags
                );
            }
            let ack = tcp.seq.wrapping_add(1);
            return Some(build_tcp_control(
                cfg.mac,
                eth.src_mac,
                cfg.ip,
                ipv4.src,
                HEALTH_PROBE_PORT,
                tcp.src_port,
                1,
                ack,
                TCP_FLAG_ACK,
            ));
        }
        if tcp.flags & TCP_FLAG_ACK != 0 {
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_health_probe("ack_seen");
            }
            if probe_debug && HEALTH_PROBE_DEBUG_LOGS.fetch_add(1, Ordering::Relaxed) < 64 {
                eprintln!(
                    "dpdk: health probe ack src={}:{} dst={}:{} seq={} ack={} flags=0x{:02x}",
                    ipv4.src, tcp.src_port, cfg.ip, HEALTH_PROBE_PORT, tcp.seq, tcp.ack, tcp.flags
                );
            }
            return None;
        }
        if tcp.flags & TCP_FLAG_RST != 0 {
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_health_probe("rst_seen");
            }
            return None;
        }
        if let Some(metrics) = metrics {
            metrics.inc_dpdk_health_probe("other_seen");
        }
        None
    }
}
