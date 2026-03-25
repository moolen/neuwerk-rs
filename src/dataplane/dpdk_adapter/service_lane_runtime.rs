impl DpdkAdapter {
    fn observe_intercept_demux_size(&self, metrics: Option<&crate::metrics::Metrics>) {
        let Some(metrics) = metrics else {
            return;
        };
        let size = if let Some(shared) = &self.shared_intercept_demux {
            shared.len()
        } else {
            self.intercept_demux.len()
        };
        metrics.set_dpdk_intercept_demux_size(size);
    }

    fn observe_host_frame_queue_depth(&self, metrics: Option<&crate::metrics::Metrics>) {
        if let Some(metrics) = metrics {
            metrics.set_dpdk_host_frame_queue_depth(self.pending_host_frames.len());
        }
    }

    pub fn service_lane_ready(&mut self) -> bool {
        if self.service_lane_tap.is_some() {
            return true;
        }
        if let Some(last_attempt) = self.service_lane_tap_last_attempt {
            if last_attempt.elapsed() < Duration::from_millis(SERVICE_LANE_TAP_RETRY_MS) {
                return false;
            }
        }
        self.service_lane_tap_last_attempt = Some(Instant::now());
        let iface = std::env::var("NEUWERK_DPDK_SERVICE_LANE_IFACE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "svc0".to_string());
        match open_tap(&iface) {
            Ok(file) => {
                match read_interface_mac(&iface) {
                    Ok(mac) => self.service_lane_mac = Some(mac),
                    Err(err) => tracing::debug!(
                        iface = %iface,
                        error = %err,
                        "dpdk service lane MAC unavailable"
                    ),
                }
                self.service_lane_tap = Some(file);
                true
            }
            Err(err) => {
                tracing::debug!(
                    iface = %iface,
                    error = %err,
                    "dpdk service lane TAP unavailable"
                );
                false
            }
        }
    }

    pub fn refresh_service_lane_steering(&mut self, state: &mut EngineState) {
        self.set_runtime_metrics(state.metrics());
        state.set_intercept_to_host_steering(self.service_lane_ready());
    }

    fn enqueue_host_frame_internal(
        &mut self,
        frame: Vec<u8>,
        metrics: Option<&crate::metrics::Metrics>,
    ) {
        let queue_max = host_frame_queue_max();
        if self.pending_host_frames.len() >= queue_max {
            self.pending_host_frames.pop_front();
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_host_frame_dropped();
            }
        }
        self.pending_host_frames.push_back(frame);
        self.observe_host_frame_queue_depth(metrics);
    }

    fn queue_host_frame(&mut self, frame: &[u8], metrics: Option<&crate::metrics::Metrics>) {
        if frame.len() < ETH_HDR_LEN {
            return;
        }
        let mut host_frame = frame.to_vec();
        host_frame[0..6].copy_from_slice(
            &self
                .service_lane_mac
                .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        );
        self.enqueue_host_frame_internal(host_frame, metrics);
    }

    fn gc_intercept_demux_map(
        map: &mut HashMap<InterceptDemuxKey, InterceptDemuxEntry>,
        now: Instant,
    ) -> usize {
        let before = map.len();
        map.retain(|_, entry| {
            now.duration_since(entry.last_seen) <= Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS)
        });
        before.saturating_sub(map.len())
    }

    fn maybe_gc_local_intercept_demux(&mut self, metrics: Option<&crate::metrics::Metrics>) {
        if self.intercept_demux_last_gc.elapsed() < intercept_demux_gc_interval() {
            return;
        }
        let now = Instant::now();
        let removed = Self::gc_intercept_demux_map(&mut self.intercept_demux, now);
        self.intercept_demux_last_gc = now;
        if removed > 0 {
            self.observe_intercept_demux_size(metrics);
        }
    }

    fn upsert_intercept_demux_entry(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
        metrics: Option<&crate::metrics::Metrics>,
    ) -> bool {
        if let Some(shared) = &self.shared_intercept_demux {
            let inserted = shared.upsert(client_ip, client_port, upstream_ip, upstream_port);
            if !inserted {
                if let Some(metrics) = metrics {
                    metrics.inc_dpdk_intercept_demux_insert_dropped();
                }
            }
            self.observe_intercept_demux_size(metrics);
            return inserted;
        }
        self.maybe_gc_local_intercept_demux(metrics);
        let key = InterceptDemuxKey {
            client_ip,
            client_port,
        };
        if let Some(entry) = self.intercept_demux.get_mut(&key) {
            *entry = InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen: Instant::now(),
            };
            self.observe_intercept_demux_size(metrics);
            return true;
        }
        if self.intercept_demux.len() >= intercept_demux_max_entries() {
            if let Some(metrics) = metrics {
                metrics.inc_dpdk_intercept_demux_insert_dropped();
            }
            self.observe_intercept_demux_size(metrics);
            return false;
        }
        self.intercept_demux.insert(
            key,
            InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen: Instant::now(),
            },
        );
        self.observe_intercept_demux_size(metrics);
        true
    }

    fn remove_intercept_demux_entry(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        metrics: Option<&crate::metrics::Metrics>,
    ) {
        if let Some(shared) = &self.shared_intercept_demux {
            shared.remove(client_ip, client_port);
            self.observe_intercept_demux_size(metrics);
            return;
        }
        let _ = self.intercept_demux.remove(&InterceptDemuxKey {
            client_ip,
            client_port,
        });
        self.observe_intercept_demux_size(metrics);
    }

    fn lookup_intercept_demux_entry(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        metrics: Option<&crate::metrics::Metrics>,
    ) -> Option<InterceptDemuxEntry> {
        if let Some(shared) = &self.shared_intercept_demux {
            let out = shared
                .lookup(client_ip, client_port)
                .map(|(upstream_ip, upstream_port)| InterceptDemuxEntry {
                    upstream_ip,
                    upstream_port,
                    last_seen: Instant::now(),
                });
            self.observe_intercept_demux_size(metrics);
            return out;
        }
        self.maybe_gc_local_intercept_demux(metrics);
        let key = InterceptDemuxKey {
            client_ip,
            client_port,
        };
        if let Some(entry) = self.intercept_demux.get_mut(&key) {
            entry.last_seen = Instant::now();
            Some(*entry)
        } else {
            None
        }
    }

    fn queue_intercept_host_frame(&mut self, frame: &[u8], metrics: Option<&crate::metrics::Metrics>) {
        if frame.len() < ETH_HDR_LEN {
            return;
        }
        let mut pkt = Packet::from_bytes(frame);
        let (src_port, dst_port) = match pkt.ports() {
            Some(ports) => ports,
            None => {
                self.queue_host_frame(frame, metrics);
                return;
            }
        };
        let src_ip = match pkt.src_ip() {
            Some(ip) => ip,
            None => {
                self.queue_host_frame(frame, metrics);
                return;
            }
        };
        let dst_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => {
                self.queue_host_frame(frame, metrics);
                return;
            }
        };
        if pkt.protocol() != Some(6) {
            self.queue_host_frame(frame, metrics);
            return;
        }

        if !self.upsert_intercept_demux_entry(src_ip, src_port, dst_ip, dst_port, metrics) {
            return;
        }
        if !pkt.set_dst_ip(intercept_service_ip())
            || !pkt.set_dst_port(intercept_service_port())
            || !pkt.recalc_checksums()
        {
            return;
        }
        if let Some(flags) = pkt.tcp_flags() {
            if flags & (0x01 | 0x04) != 0 {
                self.remove_intercept_demux_entry(src_ip, src_port, metrics);
            }
        }
        self.queue_host_frame(pkt.buffer(), metrics);
    }

    fn rewrite_intercept_service_lane_egress(
        &mut self,
        pkt: &mut Packet,
        metrics: Option<&crate::metrics::Metrics>,
    ) {
        if pkt.protocol() != Some(6) {
            return;
        }
        let (src_port, dst_port) = match pkt.ports() {
            Some(ports) => ports,
            None => return,
        };
        if src_port != intercept_service_port() {
            return;
        }
        let src_ip = match pkt.src_ip() {
            Some(ip) => ip,
            None => return,
        };
        if src_ip != intercept_service_ip() {
            return;
        }
        let client_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => return,
        };
        let Some(entry) = self.lookup_intercept_demux_entry(client_ip, dst_port, metrics) else {
            return;
        };

        if !pkt.set_src_ip(entry.upstream_ip)
            || !pkt.set_src_port(entry.upstream_port)
            || !pkt.recalc_checksums()
        {
            return;
        }
        if let Some(flags) = pkt.tcp_flags() {
            if flags & (0x01 | 0x04) != 0 {
                self.remove_intercept_demux_entry(client_ip, dst_port, metrics);
            }
        }
    }

    pub fn next_host_frame(&mut self) -> Option<Vec<u8>> {
        let frame = self.pending_host_frames.pop_front();
        if frame.is_some() {
            self.observe_host_frame_queue_depth(self.runtime_metrics());
        }
        frame
    }

    pub fn enqueue_host_frame(&mut self, frame: Vec<u8>) {
        let metrics = self.runtime_metrics().cloned();
        self.enqueue_host_frame_internal(frame, metrics.as_ref());
    }

    pub fn take_pending_host_frames(&mut self) -> Vec<Vec<u8>> {
        let frames: Vec<Vec<u8>> = self.pending_host_frames.drain(..).collect();
        if !frames.is_empty() {
            self.observe_host_frame_queue_depth(self.runtime_metrics());
        }
        frames
    }

    pub fn flush_host_frames<I: FrameIo>(&mut self, io: &mut I) -> Result<(), String> {
        if self.pending_host_frames.is_empty() {
            return Ok(());
        }
        let Some(tap) = self.service_lane_tap.as_mut() else {
            return Err("dpdk: service lane steering unavailable".to_string());
        };
        while let Some(frame) = self.pending_host_frames.pop_front() {
            tap.write_all(&frame)
                .map_err(|err| format!("dpdk: service lane write failed: {err}"))?;
        }
        self.observe_host_frame_queue_depth(self.runtime_metrics());
        io.flush()
    }

    pub fn process_service_lane_egress_frame(
        &mut self,
        frame: &[u8],
        state: &EngineState,
    ) -> Option<Vec<u8>> {
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let mut pkt = Packet::from_bytes(frame);
        self.rewrite_intercept_service_lane_egress(&mut pkt, state.metrics());
        self.rewrite_l2_for_forward(&mut pkt, state)
    }

    pub fn drain_service_lane_egress<I: FrameIo>(
        &mut self,
        state: &EngineState,
        io: &mut I,
    ) -> Result<(), String> {
        if self.service_lane_tap.is_none() {
            return Ok(());
        }
        let mut buf = [0u8; 65536];
        loop {
            let n = {
                let tap = self
                    .service_lane_tap
                    .as_mut()
                    .ok_or_else(|| "dpdk: service lane tap unavailable".to_string())?;
                match tap.read(&mut buf) {
                    Ok(n) => n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(err) => return Err(format!("dpdk: service lane read failed: {err}")),
                }
            };
            if n == 0 {
                break;
            }
            if let Some(frame) = self.process_service_lane_egress_frame(&buf[..n], state) {
                io.send_frame(&frame)?;
            }
        }
        Ok(())
    }
}
