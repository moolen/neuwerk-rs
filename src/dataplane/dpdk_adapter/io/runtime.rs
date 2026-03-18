impl DpdkIo {
    pub fn effective_queue_count(iface: &str, queue_count: u16) -> Result<u16, String> {
        init_eal(iface)?;
        let setup = init_port(iface, queue_count)?;
        Ok(setup.queue_count.max(1))
    }

    pub fn new(iface: &str, metrics: Option<Metrics>) -> Result<Self, String> {
        Self::new_with_queue(iface, 0, 1, metrics)
    }

    pub fn new_with_queue(
        iface: &str,
        queue_id: u16,
        queue_count: u16,
        metrics: Option<Metrics>,
    ) -> Result<Self, String> {
        init_eal(iface)?;
        let setup = init_port(iface, queue_count)?;
        if queue_id >= setup.queue_count {
            return Err(format!(
                "dpdk: queue_id {} out of range (queue_count={})",
                queue_id, setup.queue_count
            ));
        }
        Ok(Self {
            port_id: setup.port_id,
            port_label: setup.port_id.to_string(),
            queue_id,
            queue_label: queue_id.to_string(),
            mempool: setup.mempool,
            mac: setup.mac,
            tx_csum_offload: setup.tx_csum_offload,
            metrics,
            rx_bufs: [ptr::null_mut(); RX_BURST_SIZE],
            rx_count: 0,
            rx_index: 0,
            held_rx_mbuf: ptr::null_mut(),
            tx_bufs: [ptr::null_mut(); TX_BURST_SIZE],
            tx_lens: [0; TX_BURST_SIZE],
            tx_classes: [TxPacketClass::Other; TX_BURST_SIZE],
            tx_count: 0,
            metric_batch: IoMetricBatch::default(),
            ena_xstat_ids: setup.ena_xstat_ids.clone(),
            ena_xstat_values: vec![0; setup.ena_xstat_ids.len()],
            ena_xstats_last_poll: Instant::now(),
        })
    }

    fn record_rx_packet(&mut self, bytes: u64) {
        self.metric_batch.rx_packets = self.metric_batch.rx_packets.saturating_add(1);
        self.metric_batch.rx_bytes = self.metric_batch.rx_bytes.saturating_add(bytes);
        self.flush_metrics_if_needed(false);
    }

    fn record_rx_dropped(&mut self, count: u64) {
        self.metric_batch.rx_dropped = self.metric_batch.rx_dropped.saturating_add(count);
        self.flush_metrics_if_needed(false);
    }

    fn record_tx_packet(&mut self, count: u64, bytes: u64) {
        self.metric_batch.tx_packets = self.metric_batch.tx_packets.saturating_add(count);
        self.metric_batch.tx_bytes = self.metric_batch.tx_bytes.saturating_add(bytes);
        self.flush_metrics_if_needed(false);
    }

    fn record_tx_dropped(&mut self, count: u64) {
        self.metric_batch.tx_dropped = self.metric_batch.tx_dropped.saturating_add(count);
        self.flush_metrics_if_needed(false);
    }

    fn observe_tx_stage(
        &self,
        stage: &str,
        packet_count: u64,
        byte_count: u64,
        classes: &[TxPacketClass],
    ) {
        if packet_count == 0 {
            return;
        }
        let Some(metrics) = &self.metrics else {
            return;
        };
        metrics.inc_dpdk_tx_stage_packets(
            &self.port_label,
            &self.queue_label,
            stage,
            packet_count,
        );
        if byte_count > 0 {
            metrics.add_dpdk_tx_stage_bytes(
                &self.port_label,
                &self.queue_label,
                stage,
                byte_count,
            );
        }
        let mut other = 0u64;
        let mut syn = 0u64;
        let mut synack = 0u64;
        for class in classes {
            match class {
                TxPacketClass::Other => other = other.saturating_add(1),
                TxPacketClass::TcpSyn => syn = syn.saturating_add(1),
                TxPacketClass::TcpSynAck => synack = synack.saturating_add(1),
            }
        }
        for (label, count) in [
            (TxPacketClass::Other.as_metric_label(), other),
            (TxPacketClass::TcpSyn.as_metric_label(), syn),
            (TxPacketClass::TcpSynAck.as_metric_label(), synack),
        ] {
            if count > 0 {
                metrics.inc_dpdk_tx_stage_packet_class(
                    &self.port_label,
                    &self.queue_label,
                    stage,
                    label,
                    count,
                );
            }
        }
    }

    fn observe_single_tx_stage(&self, stage: &str, class: TxPacketClass, frame_len: usize) {
        self.observe_tx_stage(stage, 1, frame_len as u64, &[class]);
    }

    fn flush_metrics_if_needed(&mut self, force: bool) {
        if self.metrics.is_none() {
            self.metric_batch = IoMetricBatch::default();
            return;
        }
        self.maybe_poll_ena_xstats(force);
        if !force && self.metric_batch.pending_packets() < METRICS_FLUSH_PACKET_THRESHOLD {
            return;
        }
        if self.metric_batch.is_empty() {
            return;
        }
        let Some(metrics) = &self.metrics else {
            return;
        };
        if self.metric_batch.rx_packets > 0 {
            metrics.inc_dpdk_rx_packets(self.metric_batch.rx_packets);
            metrics.inc_dpdk_rx_packets_queue(&self.queue_label, self.metric_batch.rx_packets);
        }
        if self.metric_batch.rx_bytes > 0 {
            metrics.add_dpdk_rx_bytes(self.metric_batch.rx_bytes);
            metrics.add_dpdk_rx_bytes_queue(&self.queue_label, self.metric_batch.rx_bytes);
        }
        if self.metric_batch.rx_dropped > 0 {
            metrics.inc_dpdk_rx_dropped(self.metric_batch.rx_dropped);
            metrics.inc_dpdk_rx_dropped_queue(&self.queue_label, self.metric_batch.rx_dropped);
        }
        if self.metric_batch.tx_packets > 0 {
            metrics.inc_dpdk_tx_packets(self.metric_batch.tx_packets);
            metrics.inc_dpdk_tx_packets_queue(&self.queue_label, self.metric_batch.tx_packets);
        }
        if self.metric_batch.tx_bytes > 0 {
            metrics.add_dpdk_tx_bytes(self.metric_batch.tx_bytes);
            metrics.add_dpdk_tx_bytes_queue(&self.queue_label, self.metric_batch.tx_bytes);
        }
        if self.metric_batch.tx_dropped > 0 {
            metrics.inc_dpdk_tx_dropped(self.metric_batch.tx_dropped);
            metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, self.metric_batch.tx_dropped);
        }
        self.metric_batch = IoMetricBatch::default();
    }

    fn maybe_poll_ena_xstats(&mut self, force: bool) {
        if self.queue_id != 0 {
            return;
        }
        if self.ena_xstat_ids.is_empty() {
            return;
        }
        let Some(metrics) = &self.metrics else {
            return;
        };
        if !force && self.ena_xstats_last_poll.elapsed() < ENA_XSTATS_POLL_INTERVAL {
            return;
        }
        self.ena_xstats_last_poll = Instant::now();
        if self.ena_xstat_values.len() != self.ena_xstat_ids.len() {
            self.ena_xstat_values.resize(self.ena_xstat_ids.len(), 0);
        }
        let ids = self.ena_xstat_ids.iter().map(|x| x.id).collect::<Vec<_>>();
        let ret = unsafe {
            rte_eth_xstats_get_by_id(
                self.port_id,
                ids.as_ptr(),
                self.ena_xstat_values.as_mut_ptr(),
                ids.len() as u32,
            )
        };
        if ret < 0 {
            if DPDK_XSTATS_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                tracing::warn!(
                    "dpdk: rte_eth_xstats_get_by_id failed ret={} port={}",
                    ret,
                    self.port_id
                );
            }
            return;
        }
        for (idx, x) in self.ena_xstat_ids.iter().enumerate() {
            let value = self.ena_xstat_values.get(idx).copied().unwrap_or(0);
            metrics.set_dpdk_xstat(&x.label, value);
        }
    }

    fn release_held_rx_mbuf(&mut self) {
        if !self.held_rx_mbuf.is_null() {
            unsafe { rust_rte_pktmbuf_free(self.held_rx_mbuf) };
            self.held_rx_mbuf = ptr::null_mut();
        }
    }

    pub fn take_rx_packet_for_transfer(&mut self, pkt: &Packet) -> Option<DpdkTransferredRxPacket> {
        let mbuf = self.held_rx_mbuf;
        if mbuf.is_null() {
            return None;
        }
        let mbuf_data = unsafe { rust_rte_pktmbuf_mtod(mbuf) } as *const u8;
        let mbuf_len = unsafe { rust_rte_pktmbuf_pkt_len(mbuf) as usize };
        if mbuf_data.is_null() || pkt.buffer().as_ptr() != mbuf_data || pkt.len() != mbuf_len {
            return None;
        }
        self.held_rx_mbuf = ptr::null_mut();
        Some(DpdkTransferredRxPacket::new(mbuf, mbuf_len))
    }

    pub fn adopt_transferred_rx_packet(
        &mut self,
        transferred: DpdkTransferredRxPacket,
    ) -> Result<Packet, String> {
        let data_ptr = transferred.data_ptr();
        if data_ptr.is_null() || transferred.len() == 0 {
            return Err("dpdk: transferred rx packet missing payload".to_string());
        }
        let packet = unsafe { Packet::from_borrowed_mut(data_ptr, transferred.len()) }
            .ok_or_else(|| "dpdk: failed to rebuild transferred rx packet".to_string())?;
        self.release_held_rx_mbuf();
        let (mbuf, _) = transferred.into_raw();
        self.held_rx_mbuf = mbuf;
        Ok(packet)
    }

    fn enqueue_tx_mbuf(
        &mut self,
        mbuf: *mut rte_mbuf,
        frame_len: usize,
        class: TxPacketClass,
    ) -> Result<(), String> {
        if self.tx_count as usize >= TX_BURST_SIZE {
            self.flush_tx()?;
        }
        let idx = self.tx_count as usize;
        self.tx_bufs[idx] = mbuf;
        self.tx_lens[idx] = frame_len as u32;
        self.tx_classes[idx] = class;
        self.tx_count += 1;
        if self.tx_count as usize >= TX_BURST_SIZE {
            self.flush_tx()?;
        }
        Ok(())
    }

    fn flush_tx(&mut self) -> Result<(), String> {
        if self.tx_count == 0 {
            return Ok(());
        }
        let mut queued = self.tx_count as usize;
        let attempted_bytes: u64 = self.tx_lens.iter().take(queued).map(|len| *len as u64).sum();
        self.observe_tx_stage("attempted", queued as u64, attempted_bytes, &self.tx_classes[..queued]);
        if self.tx_csum_offload.any() {
            let prepared = unsafe {
                rust_rte_eth_tx_prepare(
                    self.port_id,
                    self.queue_id,
                    self.tx_bufs.as_mut_ptr(),
                    self.tx_count,
                )
            } as usize;
            if prepared < queued {
                let dropped = queued.saturating_sub(prepared);
                let dropped_bytes: u64 = self.tx_lens[prepared..queued]
                    .iter()
                    .map(|len| *len as u64)
                    .sum();
                self.observe_tx_stage(
                    "prepare_rejected",
                    dropped as u64,
                    dropped_bytes,
                    &self.tx_classes[prepared..queued],
                );
                for idx in prepared..queued {
                    let mbuf = self.tx_bufs[idx];
                    if !mbuf.is_null() {
                        unsafe { rust_rte_pktmbuf_free(mbuf) };
                    }
                }
                self.record_tx_dropped(dropped as u64);
                queued = prepared;
                self.tx_count = prepared as u16;
            }
            if queued == 0 {
                self.tx_count = 0;
                return Ok(());
            }
        }
        let prepared_bytes: u64 = self.tx_lens.iter().take(queued).map(|len| *len as u64).sum();
        self.observe_tx_stage("prepared", queued as u64, prepared_bytes, &self.tx_classes[..queued]);
        let sent = unsafe {
            rust_rte_eth_tx_burst(
                self.port_id,
                self.queue_id,
                self.tx_bufs.as_mut_ptr(),
                queued as u16,
            )
        };
        let sent_usize = sent as usize;
        let mut bytes = 0u64;
        let mut syn_sent = 0u64;
        let mut synack_sent = 0u64;
        for len in self.tx_lens.iter().take(sent_usize) {
            bytes += *len as u64;
        }
        for class in self.tx_classes.iter().take(sent_usize) {
            match class {
                TxPacketClass::TcpSyn => syn_sent = syn_sent.saturating_add(1),
                TxPacketClass::TcpSynAck => synack_sent = synack_sent.saturating_add(1),
                TxPacketClass::Other => {}
            }
        }
        self.record_tx_packet(sent as u64, bytes);
        self.observe_tx_stage("sent", sent as u64, bytes, &self.tx_classes[..sent_usize]);
        if let Some(metrics) = &self.metrics {
            if syn_sent > 0 {
                metrics.inc_dpdk_tx_packet_class_queue(&self.queue_label, "tcp_syn", syn_sent);
            }
            if synack_sent > 0 {
                metrics.inc_dpdk_tx_packet_class_queue(
                    &self.queue_label,
                    "tcp_synack",
                    synack_sent,
                );
            }
        }
        if sent_usize < queued {
            let dropped = queued.saturating_sub(sent_usize);
            let dropped_bytes: u64 = self.tx_lens[sent_usize..queued]
                .iter()
                .map(|len| *len as u64)
                .sum();
            self.observe_tx_stage(
                "burst_unsent",
                dropped as u64,
                dropped_bytes,
                &self.tx_classes[sent_usize..queued],
            );
            for idx in sent_usize..queued {
                let mbuf = self.tx_bufs[idx];
                if !mbuf.is_null() {
                    unsafe { rust_rte_pktmbuf_free(mbuf) };
                }
            }
            self.record_tx_dropped(dropped as u64);
        }
        self.tx_count = 0;
        Ok(())
    }
}

impl Drop for DpdkIo {
    fn drop(&mut self) {
        self.release_held_rx_mbuf();
    }
}

impl FrameIo for DpdkIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        self.release_held_rx_mbuf();
        let mbuf = loop {
            if self.rx_index >= self.rx_count {
                let received = unsafe {
                    rust_rte_eth_rx_burst(
                        self.port_id,
                        self.queue_id,
                        self.rx_bufs.as_mut_ptr(),
                        RX_BURST_SIZE as u16,
                    )
                };
                if received == 0 {
                    self.flush_metrics_if_needed(true);
                    return Ok(0);
                }
                self.rx_count = received;
                self.rx_index = 0;
                let first = self.rx_bufs[0];
                if !first.is_null() {
                    unsafe { rust_rte_mbuf_prefetch_part1(first) };
                }
            }
            let mbuf = self.rx_bufs[self.rx_index as usize];
            self.rx_index += 1;
            if !mbuf.is_null() {
                unsafe {
                    rust_rte_mbuf_prefetch_part1(mbuf);
                    rust_rte_mbuf_prefetch_part2(mbuf);
                }
                if self.rx_index < self.rx_count {
                    let next = self.rx_bufs[self.rx_index as usize];
                    if !next.is_null() {
                        unsafe { rust_rte_mbuf_prefetch_part1(next) };
                    }
                }
                break mbuf;
            }
            self.record_rx_dropped(1);
            if self.rx_index >= self.rx_count {
                return Ok(0);
            }
        };

        let pkt_len = unsafe { rust_rte_pktmbuf_pkt_len(mbuf) as usize };
        let data_len = unsafe { rust_rte_pktmbuf_data_len(mbuf) as usize };
        let nb_segs = unsafe { rust_rte_pktmbuf_nb_segs(mbuf) };
        let data_off = unsafe { rust_rte_pktmbuf_headroom(mbuf) };

        if pkt_len > buf.len() {
            if DPDK_RX_OVERSIZE_LOGS.fetch_add(1, Ordering::Relaxed) < 10 {
                tracing::warn!(
                    "dpdk: rx frame too large (pkt_len={}, buf_len={}, nb_segs={}, data_len={})",
                    pkt_len,
                    buf.len(),
                    nb_segs,
                    data_len
                );
            }
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.record_rx_dropped(1);
            return Ok(0);
        }

        let mut offset = 0usize;
        let mut copy_len = if pkt_len == 0 { data_len } else { pkt_len };
        copy_len = copy_len.min(buf.len());
        if copy_len > 0 {
            let out = unsafe {
                rust_rte_pktmbuf_read(mbuf, 0, copy_len as u32, buf.as_mut_ptr() as *mut _)
            };
            if out.is_null() {
                let data_ptr = unsafe { rust_rte_pktmbuf_mtod(mbuf) };
                let fallback_len = data_len.min(buf.len());
                if !data_ptr.is_null() && fallback_len > 0 {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            data_ptr as *const u8,
                            buf.as_mut_ptr(),
                            fallback_len,
                        )
                    };
                    offset = fallback_len;
                } else {
                    tracing::warn!(
                            "dpdk: rte_pktmbuf_read returned null (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                            pkt_len, data_len, nb_segs, data_off
                        );
                }
            } else {
                if out != buf.as_ptr() as *const _ {
                    unsafe {
                        ptr::copy_nonoverlapping(out as *const u8, buf.as_mut_ptr(), copy_len)
                    };
                }
                offset = copy_len;
            }
        }

        unsafe { rust_rte_pktmbuf_free(mbuf) };
        if offset == 0 {
            tracing::warn!(
                    "dpdk: rx mbuf had zero-length payload (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                    pkt_len, data_len, nb_segs, data_off
                );
            self.record_rx_dropped(1);
        }
        if offset > 0 && !DPDK_RX_LOGGED.swap(true, Ordering::Relaxed) {
            let head_len = offset.min(32);
            let mut hex = String::new();
            for byte in buf.iter().take(head_len) {
                use std::fmt::Write;
                let _ = write!(&mut hex, "{:02x} ", byte);
            }
            tracing::debug!(
                "dpdk: first rx frame len={} head={}",
                offset,
                hex.trim_end()
            );
        }
        if offset > 0 {
            self.record_rx_packet(offset as u64);
        }
        Ok(offset)
    }

    fn recv_packet(&mut self, pkt: &mut Packet) -> Result<usize, String> {
        const MAX_RX_PACKET_LEN: usize = 65536;

        self.release_held_rx_mbuf();
        let mbuf = loop {
            if self.rx_index >= self.rx_count {
                let received = unsafe {
                    rust_rte_eth_rx_burst(
                        self.port_id,
                        self.queue_id,
                        self.rx_bufs.as_mut_ptr(),
                        RX_BURST_SIZE as u16,
                    )
                };
                if received == 0 {
                    self.flush_metrics_if_needed(true);
                    return Ok(0);
                }
                self.rx_count = received;
                self.rx_index = 0;
                let first = self.rx_bufs[0];
                if !first.is_null() {
                    unsafe { rust_rte_mbuf_prefetch_part1(first) };
                }
            }
            let mbuf = self.rx_bufs[self.rx_index as usize];
            self.rx_index += 1;
            if !mbuf.is_null() {
                unsafe {
                    rust_rte_mbuf_prefetch_part1(mbuf);
                    rust_rte_mbuf_prefetch_part2(mbuf);
                }
                if self.rx_index < self.rx_count {
                    let next = self.rx_bufs[self.rx_index as usize];
                    if !next.is_null() {
                        unsafe { rust_rte_mbuf_prefetch_part1(next) };
                    }
                }
                break mbuf;
            }
            self.record_rx_dropped(1);
            if self.rx_index >= self.rx_count {
                return Ok(0);
            }
        };

        let pkt_len = unsafe { rust_rte_pktmbuf_pkt_len(mbuf) as usize };
        let data_len = unsafe { rust_rte_pktmbuf_data_len(mbuf) as usize };
        let nb_segs = unsafe { rust_rte_pktmbuf_nb_segs(mbuf) };
        let data_off = unsafe { rust_rte_pktmbuf_headroom(mbuf) };
        let rx_len = if pkt_len == 0 { data_len } else { pkt_len };

        if rx_len > MAX_RX_PACKET_LEN {
            if DPDK_RX_OVERSIZE_LOGS.fetch_add(1, Ordering::Relaxed) < 10 {
                tracing::warn!(
                    "dpdk: rx frame too large (pkt_len={}, buf_len={}, nb_segs={}, data_len={})",
                    pkt_len,
                    MAX_RX_PACKET_LEN,
                    nb_segs,
                    data_len
                );
            }
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.record_rx_dropped(1);
            return Ok(0);
        }

        if rx_len > 0 && nb_segs == 1 && data_len >= rx_len {
            let data_ptr = unsafe { rust_rte_pktmbuf_mtod(mbuf) } as *mut u8;
            if !data_ptr.is_null() {
                if let Some(borrowed) = unsafe { Packet::from_borrowed_mut(data_ptr, rx_len) } {
                    *pkt = borrowed;
                    self.held_rx_mbuf = mbuf;
                    if !DPDK_RX_LOGGED.swap(true, Ordering::Relaxed) {
                        let buf = pkt.buffer();
                        let head_len = buf.len().min(32);
                        let mut hex = String::new();
                        for byte in buf.iter().take(head_len) {
                            use std::fmt::Write;
                            let _ = write!(&mut hex, "{:02x} ", byte);
                        }
                        tracing::debug!(
                            "dpdk: first rx frame len={} head={}",
                            buf.len(),
                            hex.trim_end()
                        );
                    }
                    self.record_rx_packet(rx_len as u64);
                    return Ok(rx_len);
                }
            }
        }

        pkt.prepare_for_rx(MAX_RX_PACKET_LEN);
        let mut offset = 0usize;
        let copy_len = rx_len.min(MAX_RX_PACKET_LEN);
        if copy_len > 0 {
            let dst_ptr = pkt.buffer_mut().as_mut_ptr();
            let out = unsafe { rust_rte_pktmbuf_read(mbuf, 0, copy_len as u32, dst_ptr as *mut _) };
            if out.is_null() {
                let data_ptr = unsafe { rust_rte_pktmbuf_mtod(mbuf) };
                let fallback_len = data_len.min(MAX_RX_PACKET_LEN);
                if !data_ptr.is_null() && fallback_len > 0 {
                    unsafe {
                        ptr::copy_nonoverlapping(data_ptr as *const u8, dst_ptr, fallback_len)
                    };
                    offset = fallback_len;
                } else {
                    tracing::warn!(
                            "dpdk: rte_pktmbuf_read returned null (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                            pkt_len, data_len, nb_segs, data_off
                        );
                }
            } else {
                if out != dst_ptr as *const _ {
                    unsafe { ptr::copy_nonoverlapping(out as *const u8, dst_ptr, copy_len) };
                }
                offset = copy_len;
            }
        }

        unsafe { rust_rte_pktmbuf_free(mbuf) };
        pkt.truncate(offset);
        if offset == 0 {
            tracing::warn!(
                    "dpdk: rx mbuf had zero-length payload (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                    pkt_len, data_len, nb_segs, data_off
                );
            self.record_rx_dropped(1);
        } else {
            if !DPDK_RX_LOGGED.swap(true, Ordering::Relaxed) {
                let buf = pkt.buffer();
                let head_len = buf.len().min(32);
                let mut hex = String::new();
                for byte in buf.iter().take(head_len) {
                    use std::fmt::Write;
                    let _ = write!(&mut hex, "{:02x} ", byte);
                }
                tracing::debug!(
                    "dpdk: first rx frame len={} head={}",
                    buf.len(),
                    hex.trim_end()
                );
            }
            self.record_rx_packet(offset as u64);
        }
        Ok(offset)
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        let class = classify_tx_packet(frame);
        let mbuf = unsafe { rust_rte_pktmbuf_alloc(self.mempool) };
        if mbuf.is_null() {
            self.observe_single_tx_stage("alloc_failed", class, frame.len());
            self.record_tx_dropped(1);
            return Err("dpdk: failed to allocate mbuf".to_string());
        }
        if frame.len() > u16::MAX as usize {
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.observe_single_tx_stage("append_failed", class, frame.len());
            self.record_tx_dropped(1);
            return Err("dpdk: frame exceeds mbuf max length".to_string());
        }
        let dst = unsafe { rust_rte_pktmbuf_append(mbuf, frame.len() as u16) };
        if dst.is_null() {
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.observe_single_tx_stage("append_failed", class, frame.len());
            self.record_tx_dropped(1);
            return Err("dpdk: frame exceeds mbuf tailroom".to_string());
        }
        unsafe {
            ptr::copy_nonoverlapping(frame.as_ptr(), dst as *mut u8, frame.len());
        }
        maybe_prepare_tx_checksum_offload(mbuf, frame, self.tx_csum_offload);
        if let Err(err) = self.enqueue_tx_mbuf(mbuf, frame.len(), class) {
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.observe_single_tx_stage("enqueue_failed", class, frame.len());
            self.record_tx_dropped(1);
            return Err(err);
        }
        Ok(())
    }

    fn send_borrowed_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        let class = classify_tx_packet(frame);
        if self.tx_csum_offload.any() {
            // Keep offload path conservative: avoid reusing RX mbufs as TX
            // buffers while checksum offload metadata is active.
            return self.send_frame(frame);
        }
        let mbuf = self.held_rx_mbuf;
        if mbuf.is_null() {
            return self.send_frame(frame);
        }

        let mbuf_data = unsafe { rust_rte_pktmbuf_mtod(mbuf) } as *const u8;
        let mbuf_len = unsafe { rust_rte_pktmbuf_pkt_len(mbuf) as usize };
        if mbuf_data.is_null() || frame.as_ptr() != mbuf_data || frame.len() != mbuf_len {
            return self.send_frame(frame);
        }

        self.held_rx_mbuf = ptr::null_mut();
        maybe_prepare_tx_checksum_offload(mbuf, frame, self.tx_csum_offload);
        if let Err(err) = self.enqueue_tx_mbuf(mbuf, frame.len(), class) {
            unsafe { rust_rte_pktmbuf_free(mbuf) };
            self.observe_single_tx_stage("enqueue_failed", class, frame.len());
            self.record_tx_dropped(1);
            return Err(err);
        }
        Ok(())
    }

    fn finish_rx_packet(&mut self) {
        self.release_held_rx_mbuf();
    }

    fn flush(&mut self) -> Result<(), String> {
        self.release_held_rx_mbuf();
        self.flush_tx()?;
        self.flush_metrics_if_needed(true);
        Ok(())
    }

    fn mac(&self) -> Option<[u8; 6]> {
        Some(self.mac)
    }
}

fn classify_tx_packet(frame: &[u8]) -> TxPacketClass {
    const ETH_HDR_LEN: usize = 14;
    const ETH_TYPE_IPV4: u16 = 0x0800;
    const IPPROTO_TCP: u8 = 6;
    const TCP_FLAG_SYN: u8 = 0x02;
    const TCP_FLAG_RST: u8 = 0x04;
    const TCP_FLAG_ACK: u8 = 0x10;
    const TCP_SYN_MASK: u8 = TCP_FLAG_SYN | TCP_FLAG_ACK | TCP_FLAG_RST;

    if frame.len() < ETH_HDR_LEN + 20 {
        return TxPacketClass::Other;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_TYPE_IPV4 {
        return TxPacketClass::Other;
    }

    let ip_off = ETH_HDR_LEN;
    if (frame[ip_off] >> 4) != 4 {
        return TxPacketClass::Other;
    }
    let ihl = ((frame[ip_off] & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < ip_off + ihl + 20 {
        return TxPacketClass::Other;
    }
    if frame[ip_off + 9] != IPPROTO_TCP {
        return TxPacketClass::Other;
    }

    let tcp_off = ip_off + ihl;
    let data_offset = ((frame[tcp_off + 12] >> 4) as usize) * 4;
    if data_offset < 20 || frame.len() < tcp_off + data_offset {
        return TxPacketClass::Other;
    }
    let flags = frame[tcp_off + 13];
    if (flags & TCP_SYN_MASK) == TCP_FLAG_SYN {
        return TxPacketClass::TcpSyn;
    }
    if (flags & TCP_SYN_MASK) == (TCP_FLAG_SYN | TCP_FLAG_ACK) {
        return TxPacketClass::TcpSynAck;
    }
    TxPacketClass::Other
}
