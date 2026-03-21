use super::*;

impl Metrics {
    pub fn bind_dataplane_shard_metrics(&self, shard: usize) -> DataplaneShardMetricHandles {
        let shard = shard.to_string();
        DataplaneShardMetricHandles {
            active_flows_shard: self.dp_active_flows_shard.with_label_values(&[&shard]),
            active_nat_entries_shard: self
                .dp_active_nat_entries_shard
                .with_label_values(&[&shard]),
        }
    }

    pub fn bind_dpdk_flow_steer_metrics(&self, worker_count: usize) -> DpdkFlowSteerMetricHandles {
        let mut dispatch_packets = Vec::with_capacity(worker_count * worker_count);
        let mut dispatch_bytes = Vec::with_capacity(worker_count * worker_count);
        let mut fail_open_tx_missing = Vec::with_capacity(worker_count);
        let mut fail_open_owner_missing = Vec::with_capacity(worker_count);
        let mut queue_wait = Vec::with_capacity(worker_count);
        let mut queue_depth = Vec::with_capacity(worker_count);
        let mut queue_utilization_ratio = Vec::with_capacity(worker_count);

        for from_worker in 0..worker_count {
            let from_worker = from_worker.to_string();
            for to_worker in 0..worker_count {
                let to_worker = to_worker.to_string();
                dispatch_packets.push(
                    self.dpdk_flow_steer_dispatch_packets
                        .with_label_values(&[&from_worker, &to_worker]),
                );
                dispatch_bytes.push(
                    self.dpdk_flow_steer_dispatch_bytes
                        .with_label_values(&[&from_worker, &to_worker]),
                );
            }
        }

        for worker in 0..worker_count {
            let worker = worker.to_string();
            fail_open_tx_missing.push(
                self.dpdk_flow_steer_fail_open_events
                    .with_label_values(&[&worker, "tx_missing"]),
            );
            fail_open_owner_missing.push(
                self.dpdk_flow_steer_fail_open_events
                    .with_label_values(&[&worker, "owner_missing"]),
            );
            queue_wait.push(
                self.dpdk_flow_steer_queue_wait_seconds
                    .with_label_values(&[&worker]),
            );
            queue_depth.push(
                self.dpdk_flow_steer_queue_depth
                    .with_label_values(&[&worker]),
            );
            queue_utilization_ratio.push(
                self.dpdk_flow_steer_queue_utilization_ratio
                    .with_label_values(&[&worker]),
            );
        }

        DpdkFlowSteerMetricHandles {
            worker_count,
            dispatch_packets,
            dispatch_bytes,
            fail_open_tx_missing,
            fail_open_owner_missing,
            queue_wait,
            queue_depth,
            queue_utilization_ratio,
        }
    }

    pub fn observe_http(&self, path: &str, method: &str, status: u16, duration: Duration) {
        let status = status.to_string();
        self.http_requests
            .with_label_values(&[path, method, &status])
            .inc();
        self.http_duration
            .with_label_values(&[path, method, &status])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_http_auth(&self, outcome: &str, reason: &str) {
        self.http_auth.with_label_values(&[outcome, reason]).inc();
    }

    pub fn observe_http_auth_sso(&self, outcome: &str, reason: &str, provider: &str) {
        self.http_auth_sso
            .with_label_values(&[outcome, reason, provider])
            .inc();
    }

    pub fn observe_http_auth_sso_latency(&self, provider: &str, stage: &str, duration: Duration) {
        self.http_auth_sso_latency
            .with_label_values(&[provider, stage])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_dns_query(&self, result: &str, reason: &str, source_group: &str) {
        self.dns_queries
            .with_label_values(&[result, reason, source_group])
            .inc();
        self.svc_dns_queries
            .with_label_values(&[result, reason, source_group])
            .inc();
    }

    pub fn observe_dns_upstream_rtt(&self, source_group: &str, duration: Duration) {
        self.dns_upstream_rtt
            .with_label_values(&[source_group])
            .observe(duration.as_secs_f64());
        self.svc_dns_upstream_rtt
            .with_label_values(&[source_group])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_dns_nxdomain(&self, source: &str) {
        self.dns_nxdomain.with_label_values(&[source]).inc();
        self.svc_dns_nxdomain.with_label_values(&[source]).inc();
    }

    pub fn observe_dns_upstream_mismatch(&self, reason: &str, source_group: &str) {
        self.dns_upstream_mismatch
            .with_label_values(&[reason, source_group])
            .inc();
    }

    pub fn inc_svc_tls_intercept_flow(&self, result: &str) {
        self.svc_tls_intercept_flows
            .with_label_values(&[result])
            .inc();
    }

    pub fn inc_svc_http_request(&self, proto: &str, decision: &str) {
        self.svc_http_requests
            .with_label_values(&[proto, decision])
            .inc();
    }

    pub fn inc_svc_http_deny(&self, proto: &str, phase: &str, reason: &str) {
        self.svc_http_denies
            .with_label_values(&[proto, phase, reason])
            .inc();
    }

    pub fn inc_svc_policy_rst(&self, reason: &str) {
        self.svc_policy_rst.with_label_values(&[reason]).inc();
    }

    pub fn inc_svc_fail_closed(&self, component: &str) {
        self.svc_fail_closed.with_label_values(&[component]).inc();
    }

    pub fn inc_svc_tls_intercept_error(&self, stage: &str, reason: &str) {
        self.svc_tls_intercept_errors
            .with_label_values(&[stage, reason])
            .inc();
    }

    pub fn observe_svc_tls_intercept_phase(&self, phase: &str, duration: Duration) {
        self.svc_tls_intercept_phase
            .with_label_values(&[phase])
            .observe(duration.as_secs_f64());
    }

    pub fn inc_svc_tls_intercept_inflight(&self, kind: &str) {
        self.svc_tls_intercept_inflight
            .with_label_values(&[kind])
            .inc();
    }

    pub fn dec_svc_tls_intercept_inflight(&self, kind: &str) {
        self.svc_tls_intercept_inflight
            .with_label_values(&[kind])
            .dec();
    }

    pub fn inc_svc_tls_intercept_upstream_h2_pool(&self, result: &str) {
        self.svc_tls_intercept_upstream_h2_pool
            .with_label_values(&[result])
            .inc();
    }

    pub fn inc_svc_tls_intercept_upstream_h2_shard_select(&self, shard: usize) {
        let shard = shard.to_string();
        self.svc_tls_intercept_upstream_h2_shard_select
            .with_label_values(&[&shard])
            .inc();
    }

    pub fn observe_svc_tls_intercept_upstream_h2_send_wait(&self, phase: &str, duration: Duration) {
        self.svc_tls_intercept_upstream_h2_send_wait
            .with_label_values(&[phase])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_svc_tls_intercept_upstream_h2_selected_inflight(&self, in_flight: usize) {
        self.svc_tls_intercept_upstream_h2_selected_inflight
            .observe(in_flight as f64);
    }

    pub fn observe_svc_tls_intercept_upstream_h2_pool_width(&self, pool_width: usize) {
        self.svc_tls_intercept_upstream_h2_pool_width
            .observe(pool_width as f64);
    }

    pub fn inc_svc_tls_intercept_upstream_h2_ready_error(&self, kind: &str) {
        self.svc_tls_intercept_upstream_h2_ready_errors
            .with_label_values(&[kind])
            .inc();
    }

    pub fn inc_svc_tls_intercept_upstream_response_error(&self, kind: &str) {
        self.svc_tls_intercept_upstream_response_errors
            .with_label_values(&[kind])
            .inc();
    }

    pub fn inc_svc_tls_intercept_upstream_h2_conn_closed(&self, reason: &str) {
        self.svc_tls_intercept_upstream_h2_conn_closed
            .with_label_values(&[reason])
            .inc();
    }

    pub fn inc_svc_tls_intercept_upstream_h2_conn_termination(&self, kind: &str, reason: &str) {
        self.svc_tls_intercept_upstream_h2_conn_termination
            .with_label_values(&[kind, reason])
            .inc();
    }

    pub fn inc_svc_tls_intercept_upstream_h2_retry(&self, cause: &str) {
        self.svc_tls_intercept_upstream_h2_retry
            .with_label_values(&[cause])
            .inc();
    }

    pub fn set_svc_tls_intercept_upstream_h2_selected_inflight_peak(&self, value: usize) {
        self.svc_tls_intercept_upstream_h2_selected_inflight_peak
            .set(value as f64);
    }

    pub fn inc_threat_match(
        &self,
        indicator_type: &str,
        layer: &str,
        severity: &str,
        feed: &str,
        source: &str,
    ) {
        self.threat_matches
            .with_label_values(&[indicator_type, layer, severity, feed, source])
            .inc();
    }

    pub fn inc_threat_alertable_match(
        &self,
        indicator_type: &str,
        layer: &str,
        severity: &str,
        feed: &str,
    ) {
        self.threat_alertable_matches
            .with_label_values(&[indicator_type, layer, severity, feed])
            .inc();
    }

    pub fn observe_threat_feed_refresh(&self, feed: &str, outcome: &str) {
        self.threat_feed_refresh
            .with_label_values(&[feed, outcome])
            .inc();
    }

    pub fn set_threat_feed_snapshot_age_seconds(&self, feed: &str, age: u64) {
        self.threat_feed_snapshot_age_seconds
            .with_label_values(&[feed])
            .set(age as f64);
    }

    pub fn set_threat_feed_indicators(&self, feed: &str, indicator_type: &str, count: usize) {
        self.threat_feed_indicators
            .with_label_values(&[feed, indicator_type])
            .set(count as f64);
    }

    pub fn inc_threat_backfill_run(&self, outcome: &str) {
        self.threat_backfill_runs
            .with_label_values(&[outcome])
            .inc();
    }

    pub fn observe_threat_backfill_duration(&self, duration: Duration) {
        self.threat_backfill_duration_seconds
            .observe(duration.as_secs_f64());
    }

    pub fn inc_threat_enrichment_request(&self, provider: &str, outcome: &str) {
        self.threat_enrichment_requests
            .with_label_values(&[provider, outcome])
            .inc();
    }

    pub fn set_threat_enrichment_queue_depth(&self, depth: usize) {
        self.threat_enrichment_queue_depth.set(depth as f64);
    }

    pub fn inc_threat_observation_enqueue_failure(&self) {
        self.threat_observation_enqueue_failures.inc();
    }

    pub fn set_threat_findings_active(&self, severity: &str, count: usize) {
        self.threat_findings_active
            .with_label_values(&[severity])
            .set(count as f64);
    }

    pub fn set_threat_cluster_snapshot_version(&self, version: u64) {
        self.threat_cluster_snapshot_version.set(version as f64);
    }

    pub fn set_raft_is_leader(&self, is_leader: bool) {
        self.raft_is_leader.set(if is_leader { 1.0 } else { 0.0 });
    }

    pub fn inc_raft_leader_changes(&self) {
        self.raft_leader_changes.inc();
    }

    pub fn set_raft_current_term(&self, term: u64) {
        self.raft_current_term.set(term as f64);
    }

    pub fn set_raft_last_log_index(&self, index: Option<u64>) {
        self.raft_last_log_index.set(index.unwrap_or(0) as f64);
    }

    pub fn set_raft_last_applied(&self, index: Option<u64>) {
        self.raft_last_applied.set(index.unwrap_or(0) as f64);
    }

    pub fn observe_raft_peer_rtt(&self, peer_id: &str, rpc: &str, duration: Duration) {
        self.raft_peer_rtt
            .with_label_values(&[peer_id, rpc])
            .observe(duration.as_secs_f64());
    }

    pub fn inc_raft_peer_error(&self, peer_id: &str, rpc: &str, kind: &str) {
        self.raft_peer_errors
            .with_label_values(&[peer_id, rpc, kind])
            .inc();
    }

    pub fn set_rocksdb_estimated_num_keys(&self, value: u64) {
        self.rocksdb_estimated_num_keys.set(value as f64);
    }

    pub fn set_rocksdb_live_sst_files_size_bytes(&self, value: u64) {
        self.rocksdb_live_sst_files_size_bytes.set(value as f64);
    }

    pub fn set_rocksdb_total_sst_files_size_bytes(&self, value: u64) {
        self.rocksdb_total_sst_files_size_bytes.set(value as f64);
    }

    pub fn set_rocksdb_memtable_bytes(&self, value: u64) {
        self.rocksdb_memtable_bytes.set(value as f64);
    }

    pub fn set_rocksdb_num_running_compactions(&self, value: u64) {
        self.rocksdb_num_running_compactions.set(value as f64);
    }

    pub fn set_rocksdb_num_immutable_memtables(&self, value: u64) {
        self.rocksdb_num_immutable_memtables.set(value as f64);
    }

    pub fn observe_dp_packet(
        &self,
        direction: &str,
        proto: &str,
        decision: &str,
        source_group: &str,
        bytes: usize,
    ) {
        if proto == "tcp" && decision == "allow" && source_group == "default" {
            if direction == "outbound" {
                self.dp_packets_outbound_tcp_allow_default.inc();
                self.dp_bytes_outbound_tcp_allow_default
                    .inc_by(bytes as f64);
                return;
            }
            if direction == "inbound" {
                self.dp_packets_inbound_tcp_allow_default.inc();
                self.dp_bytes_inbound_tcp_allow_default.inc_by(bytes as f64);
                return;
            }
        }
        self.dp_packets
            .with_label_values(&[direction, proto, decision, source_group])
            .inc();
        self.dp_bytes
            .with_label_values(&[direction, proto, decision, source_group])
            .inc_by(bytes as f64);
    }

    pub fn inc_dp_flow_open(&self, proto: &str, source_group: &str) {
        if source_group == "default" {
            if proto == "tcp" {
                self.dp_flow_opens_tcp_default.inc();
                self.dp_active_flows_source_group_default.inc();
                return;
            }
            if proto == "udp" {
                self.dp_flow_opens_udp_default.inc();
                self.dp_active_flows_source_group_default.inc();
                return;
            }
        }
        self.dp_flow_opens
            .with_label_values(&[proto, source_group])
            .inc();
        self.dp_active_flows_source_group
            .with_label_values(&[source_group])
            .inc();
    }

    pub fn inc_dp_flow_close(&self, reason: &str, count: u64) {
        self.dp_flow_closes
            .with_label_values(&[reason])
            .inc_by(count as f64);
    }

    pub fn add_dp_flow_lifecycle_event(
        &self,
        worker: usize,
        event: &str,
        reason: &str,
        count: u64,
    ) {
        let worker = worker.to_string();
        self.dp_flow_lifecycle_events
            .with_label_values(&[&worker, event, reason])
            .inc_by(count as f64);
    }

    pub fn observe_dp_flow_close(&self, source_group: &str, reason: &str, lifetime_secs: f64) {
        self.dp_flow_closes.with_label_values(&[reason]).inc();
        self.dp_flow_lifetime_seconds
            .with_label_values(&[source_group, reason])
            .observe(lifetime_secs.max(0.0));
        if source_group == "default" {
            self.dp_active_flows_source_group_default.dec();
        } else {
            self.dp_active_flows_source_group
                .with_label_values(&[source_group])
                .dec();
        }
    }

    pub fn add_dp_active_flows(&self, delta: i64) {
        if delta > 0 {
            self.dp_active_flows.inc();
        } else if delta < 0 {
            self.dp_active_flows.dec();
        }
    }

    pub fn add_dp_active_flows_shard(&self, shard: usize, delta: i64) {
        let shard_label = shard.to_string();
        let shard_gauge = self
            .dp_active_flows_shard
            .with_label_values(&[&shard_label]);
        if delta > 0 {
            shard_gauge.inc();
            self.dp_active_flows.inc();
        } else if delta < 0 {
            shard_gauge.dec();
            self.dp_active_flows.dec();
        }
    }

    pub fn set_dp_active_flows(&self, count: usize) {
        self.dp_active_flows.set(count as f64);
    }

    pub fn set_dp_active_flows_shard(&self, shard: usize, count: usize) {
        let shard_label = shard.to_string();
        self.dp_active_flows_shard
            .with_label_values(&[&shard_label])
            .set(count as f64);
        if let Ok(mut lock) = self.dp_active_flows_counts.lock() {
            lock.insert(shard, count);
            let total: usize = lock.values().sum();
            self.dp_active_flows.set(total as f64);
        }
    }

    pub fn set_dp_active_nat_entries(&self, count: usize) {
        self.dp_active_nat_entries.set(count as f64);
    }

    pub fn add_dp_active_nat_entries(&self, delta: i64) {
        if delta > 0 {
            self.dp_active_nat_entries.add(delta as f64);
        } else if delta < 0 {
            self.dp_active_nat_entries.sub((-delta) as f64);
        }
    }

    pub fn set_dp_active_nat_entries_shard(&self, shard: usize, count: usize) {
        let shard_label = shard.to_string();
        self.dp_active_nat_entries_shard
            .with_label_values(&[&shard_label])
            .set(count as f64);
        if let Ok(mut lock) = self.dp_active_nat_counts.lock() {
            lock.insert(shard, count);
            let total: usize = lock.values().sum();
            self.dp_active_nat_entries.set(total as f64);
        }
    }

    pub fn add_dp_active_nat_entries_shard(&self, shard: usize, delta: i64) {
        let shard_label = shard.to_string();
        let shard_gauge = self
            .dp_active_nat_entries_shard
            .with_label_values(&[&shard_label]);
        if delta > 0 {
            shard_gauge.add(delta as f64);
            self.dp_active_nat_entries.add(delta as f64);
        } else if delta < 0 {
            let delta = (-delta) as f64;
            shard_gauge.sub(delta);
            self.dp_active_nat_entries.sub(delta);
        }
    }

    pub fn set_dp_nat_port_utilization_ratio(&self, ratio: f64) {
        self.dp_nat_port_utilization_ratio.set(ratio);
    }

    pub fn set_dp_flow_table_utilization_ratio(&self, ratio: f64) {
        self.dp_flow_table_utilization_ratio.set(ratio);
    }

    pub fn set_dp_flow_table_utilization_ratio_shard(&self, shard: usize, ratio: f64) {
        let shard_label = shard.to_string();
        self.dp_flow_table_utilization_ratio_shard
            .with_label_values(&[&shard_label])
            .set(ratio);
    }

    pub fn set_dp_flow_table_capacity_worker(&self, worker: usize, capacity: usize) {
        let worker = worker.to_string();
        self.dp_flow_table_capacity
            .with_label_values(&[&worker])
            .set(capacity as f64);
    }

    pub fn set_dp_flow_table_tombstones_worker(&self, worker: usize, tombstones: usize) {
        let worker = worker.to_string();
        self.dp_flow_table_tombstones
            .with_label_values(&[&worker])
            .set(tombstones as f64);
    }

    pub fn set_dp_flow_table_used_slots_ratio_worker(&self, worker: usize, ratio: f64) {
        let worker = worker.to_string();
        self.dp_flow_table_used_slots_ratio
            .with_label_values(&[&worker])
            .set(ratio);
    }

    pub fn set_dp_flow_table_tombstone_ratio_worker(&self, worker: usize, ratio: f64) {
        let worker = worker.to_string();
        self.dp_flow_table_tombstone_ratio
            .with_label_values(&[&worker])
            .set(ratio);
    }

    pub fn add_dp_flow_table_resize_event(&self, worker: usize, reason: &str, count: u64) {
        if count == 0 {
            return;
        }
        let worker = worker.to_string();
        self.dp_flow_table_resize_events
            .with_label_values(&[&worker, reason])
            .inc_by(count as f64);
    }

    pub fn set_dp_syn_only_active_flows(&self, worker: usize, count: usize) {
        let worker = worker.to_string();
        self.dp_syn_only_active_flows
            .with_label_values(&[&worker])
            .set(count as f64);
    }

    pub fn inc_dp_syn_only_lookup(&self, worker: usize, result: &str) {
        let worker = worker.to_string();
        self.dp_syn_only_lookup
            .with_label_values(&[&worker, result])
            .inc();
    }

    pub fn inc_dp_syn_only_promotion(&self, worker: usize, reason: &str) {
        let worker = worker.to_string();
        self.dp_syn_only_promotions
            .with_label_values(&[&worker, reason])
            .inc();
    }

    pub fn add_dp_syn_only_eviction(&self, worker: usize, reason: &str, count: u64) {
        if count == 0 {
            return;
        }
        let worker = worker.to_string();
        self.dp_syn_only_evictions
            .with_label_values(&[&worker, reason])
            .inc_by(count as f64);
    }

    pub fn set_dp_nat_table_utilization_ratio(&self, ratio: f64) {
        self.dp_nat_table_utilization_ratio.set(ratio);
    }

    pub fn set_dp_nat_table_utilization_ratio_shard(&self, shard: usize, ratio: f64) {
        let shard_label = shard.to_string();
        self.dp_nat_table_utilization_ratio_shard
            .with_label_values(&[&shard_label])
            .set(ratio);
    }

    pub fn observe_dp_state_lock_wait(&self, wait: Duration) {
        self.dp_state_lock_wait_seconds.observe(wait.as_secs_f64());
    }

    pub fn inc_dp_state_lock_contended(&self) {
        self.dp_state_lock_contended.inc();
    }

    pub fn observe_dp_state_lock_wait_worker(&self, worker: usize, shard: usize, wait: Duration) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        let secs = wait.as_secs_f64();
        self.dp_state_lock_wait_seconds.observe(secs);
        self.dp_state_lock_wait_seconds_worker
            .with_label_values(&[&worker])
            .observe(secs);
        self.dp_state_lock_wait_seconds_shard
            .with_label_values(&[&shard])
            .observe(secs);
    }

    pub fn observe_dp_state_lock_hold_worker(&self, worker: usize, shard: usize, hold: Duration) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        let secs = hold.as_secs_f64();
        self.dp_state_lock_hold_seconds_worker
            .with_label_values(&[&worker])
            .observe(secs);
        self.dp_state_lock_hold_seconds_shard
            .with_label_values(&[&shard])
            .observe(secs);
    }

    pub fn inc_dp_state_lock_contended_worker(&self, worker: usize, shard: usize) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        self.dp_state_lock_contended.inc();
        self.dp_state_lock_contended_worker
            .with_label_values(&[&worker])
            .inc();
        self.dp_state_lock_contended_shard
            .with_label_values(&[&shard])
            .inc();
    }

    pub fn observe_dp_state_lock_wait_detailed(&self, worker: usize, shard: usize, wait: Duration) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        let secs = wait.as_secs_f64();
        self.dp_state_lock_wait_seconds_worker
            .with_label_values(&[&worker])
            .observe(secs);
        self.dp_state_lock_wait_seconds_shard
            .with_label_values(&[&shard])
            .observe(secs);
    }

    pub fn observe_dp_state_lock_hold_detailed(&self, worker: usize, shard: usize, hold: Duration) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        let secs = hold.as_secs_f64();
        self.dp_state_lock_hold_seconds_worker
            .with_label_values(&[&worker])
            .observe(secs);
        self.dp_state_lock_hold_seconds_shard
            .with_label_values(&[&shard])
            .observe(secs);
    }

    pub fn inc_dp_state_lock_contended_detailed(&self, worker: usize, shard: usize) {
        let worker = worker.to_string();
        let shard = shard.to_string();
        self.dp_state_lock_contended_worker
            .with_label_values(&[&worker])
            .inc();
        self.dp_state_lock_contended_shard
            .with_label_values(&[&shard])
            .inc();
    }

    pub fn observe_dpdk_shared_io_lock_wait(&self, wait: Duration) {
        self.dpdk_shared_io_lock_wait_seconds
            .observe(wait.as_secs_f64());
    }

    pub fn inc_dpdk_shared_io_lock_contended(&self) {
        self.dpdk_shared_io_lock_contended.inc();
    }

    pub fn observe_dpdk_shared_io_lock_wait_worker(&self, worker: usize, wait: Duration) {
        let worker = worker.to_string();
        let secs = wait.as_secs_f64();
        self.dpdk_shared_io_lock_wait_seconds.observe(secs);
        self.dpdk_shared_io_lock_wait_seconds_worker
            .with_label_values(&[&worker])
            .observe(secs);
    }

    pub fn observe_dpdk_shared_io_lock_hold_worker(&self, worker: usize, hold: Duration) {
        let worker = worker.to_string();
        self.dpdk_shared_io_lock_hold_seconds_worker
            .with_label_values(&[&worker])
            .observe(hold.as_secs_f64());
    }

    pub fn inc_dpdk_shared_io_lock_contended_worker(&self, worker: usize) {
        let worker = worker.to_string();
        self.dpdk_shared_io_lock_contended.inc();
        self.dpdk_shared_io_lock_contended_worker
            .with_label_values(&[&worker])
            .inc();
    }

    pub fn inc_dp_tls_decision(&self, outcome: &str) {
        self.dp_tls_decisions.with_label_values(&[outcome]).inc();
    }

    pub fn observe_dp_icmp_decision(
        &self,
        direction: &str,
        icmp_type: u8,
        icmp_code: u8,
        decision: &str,
        source_group: &str,
    ) {
        self.dp_icmp_decisions
            .with_label_values(&[
                direction,
                &icmp_type.to_string(),
                &icmp_code.to_string(),
                decision,
                source_group,
            ])
            .inc();
    }

    pub fn inc_dp_ipv4_fragment_drop(&self) {
        self.dp_ipv4_fragments_dropped.inc();
    }

    pub fn inc_dp_ipv4_ttl_exceeded(&self) {
        self.dp_ipv4_ttl_exceeded.inc();
    }

    pub fn inc_dp_arp_handled(&self) {
        self.dp_arp_handled.inc();
    }

    pub fn inc_overlay_decap_error(&self) {
        self.overlay_decap_errors.inc();
    }

    pub fn inc_overlay_encap_error(&self) {
        self.overlay_encap_errors.inc();
    }

    pub fn observe_overlay_packet(&self, mode: &str, direction: &str) {
        self.overlay_packets
            .with_label_values(&[mode, direction])
            .inc();
    }

    pub fn inc_overlay_mtu_drop(&self) {
        self.overlay_mtu_drops.inc();
    }

    pub fn set_dpdk_init_ok(&self, ok: bool) {
        self.dpdk_init_ok.set(if ok { 1.0 } else { 0.0 });
    }

    pub fn inc_dpdk_init_failure(&self) {
        self.dpdk_init_failures.inc();
    }

    pub fn inc_dpdk_rx_packets(&self, count: u64) {
        self.dpdk_rx_packets.inc_by(count as f64);
    }

    pub fn add_dpdk_rx_bytes(&self, bytes: u64) {
        self.dpdk_rx_bytes.inc_by(bytes as f64);
    }

    pub fn inc_dpdk_rx_dropped(&self, count: u64) {
        self.dpdk_rx_dropped.inc_by(count as f64);
    }

    pub fn inc_dpdk_tx_packets(&self, count: u64) {
        self.dpdk_tx_packets.inc_by(count as f64);
    }

    pub fn add_dpdk_tx_bytes(&self, bytes: u64) {
        self.dpdk_tx_bytes.inc_by(bytes as f64);
    }

    pub fn inc_dpdk_tx_dropped(&self, count: u64) {
        self.dpdk_tx_dropped.inc_by(count as f64);
    }

    pub fn inc_dpdk_rx_packets_queue(&self, queue: &str, count: u64) {
        self.dpdk_rx_packets_by_queue
            .with_label_values(&[queue])
            .inc_by(count as f64);
    }

    pub fn add_dpdk_rx_bytes_queue(&self, queue: &str, bytes: u64) {
        self.dpdk_rx_bytes_by_queue
            .with_label_values(&[queue])
            .inc_by(bytes as f64);
    }

    pub fn inc_dpdk_rx_dropped_queue(&self, queue: &str, count: u64) {
        self.dpdk_rx_dropped_by_queue
            .with_label_values(&[queue])
            .inc_by(count as f64);
    }

    pub fn inc_dpdk_tx_packets_queue(&self, queue: &str, count: u64) {
        self.dpdk_tx_packets_by_queue
            .with_label_values(&[queue])
            .inc_by(count as f64);
    }

    pub fn add_dpdk_tx_bytes_queue(&self, queue: &str, bytes: u64) {
        self.dpdk_tx_bytes_by_queue
            .with_label_values(&[queue])
            .inc_by(bytes as f64);
    }

    pub fn inc_dpdk_tx_dropped_queue(&self, queue: &str, count: u64) {
        self.dpdk_tx_dropped_by_queue
            .with_label_values(&[queue])
            .inc_by(count as f64);
    }

    pub fn inc_dpdk_tx_packet_class_queue(&self, queue: &str, class: &str, count: u64) {
        self.dpdk_tx_packet_class_by_queue
            .with_label_values(&[queue, class])
            .inc_by(count as f64);
    }

    pub fn inc_dpdk_tx_stage_packets(&self, port: &str, queue: &str, stage: &str, count: u64) {
        self.dpdk_tx_stage_packets
            .with_label_values(&[port, queue, stage])
            .inc_by(count as f64);
    }

    pub fn add_dpdk_tx_stage_bytes(&self, port: &str, queue: &str, stage: &str, bytes: u64) {
        self.dpdk_tx_stage_bytes
            .with_label_values(&[port, queue, stage])
            .inc_by(bytes as f64);
    }

    pub fn inc_dpdk_tx_stage_packet_class(
        &self,
        port: &str,
        queue: &str,
        stage: &str,
        class: &str,
        count: u64,
    ) {
        self.dpdk_tx_stage_packet_class
            .with_label_values(&[port, queue, stage, class])
            .inc_by(count as f64);
    }

    pub fn inc_dpdk_flow_steer_dispatch(&self, from_worker: usize, to_worker: usize) {
        let from_worker = from_worker.to_string();
        let to_worker = to_worker.to_string();
        self.dpdk_flow_steer_dispatch_packets
            .with_label_values(&[&from_worker, &to_worker])
            .inc();
    }

    pub fn add_dpdk_flow_steer_bytes(&self, from_worker: usize, to_worker: usize, bytes: usize) {
        let from_worker = from_worker.to_string();
        let to_worker = to_worker.to_string();
        self.dpdk_flow_steer_dispatch_bytes
            .with_label_values(&[&from_worker, &to_worker])
            .inc_by(bytes as f64);
    }

    pub fn inc_dpdk_flow_steer_fail_open_event(&self, worker: usize, event: &str) {
        let worker = worker.to_string();
        self.dpdk_flow_steer_fail_open_events
            .with_label_values(&[&worker, event])
            .inc();
    }

    pub fn observe_dpdk_flow_steer_queue_wait(&self, to_worker: usize, wait: Duration) {
        let to_worker = to_worker.to_string();
        self.dpdk_flow_steer_queue_wait_seconds
            .with_label_values(&[&to_worker])
            .observe(wait.as_secs_f64());
    }

    pub fn set_dpdk_flow_steer_queue_depth(&self, to_worker: usize, depth: usize) {
        let to_worker = to_worker.to_string();
        self.dpdk_flow_steer_queue_depth
            .with_label_values(&[&to_worker])
            .set(depth as f64);
    }

    pub fn inc_dpdk_service_lane_forward(&self, from_worker: usize) {
        let from_worker = from_worker.to_string();
        self.dpdk_service_lane_forward_packets
            .with_label_values(&[&from_worker])
            .inc();
    }

    pub fn add_dpdk_service_lane_forward_bytes(&self, from_worker: usize, bytes: usize) {
        let from_worker = from_worker.to_string();
        self.dpdk_service_lane_forward_bytes
            .with_label_values(&[&from_worker])
            .inc_by(bytes as f64);
    }

    pub fn observe_dpdk_service_lane_forward_queue_wait(&self, from_worker: usize, wait: Duration) {
        let from_worker = from_worker.to_string();
        self.dpdk_service_lane_forward_queue_wait_seconds
            .with_label_values(&[&from_worker])
            .observe(wait.as_secs_f64());
    }

    pub fn set_dpdk_service_lane_forward_queue_depth(&self, depth: usize) {
        self.dpdk_service_lane_forward_queue_depth.set(depth as f64);
        self.dpdk_service_lane_forward_queue_utilization_ratio
            .set((depth as f64) / 1024.0);
    }

    pub fn inc_dp_tcp_handshake_event(&self, worker: usize, event: &str) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_events
            .with_label_values(&[&worker, event])
            .inc();
    }

    pub fn inc_dp_tcp_handshake_event_by_target(
        &self,
        worker: usize,
        event: &str,
        target_host: &str,
    ) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_events
            .with_label_values(&[&worker, event])
            .inc();
        self.dp_tcp_handshake_events_by_target
            .with_label_values(&[&worker, event, target_host])
            .inc();
    }

    pub fn inc_dp_tcp_handshake_final_ack_in(
        &self,
        worker: usize,
        source_group: &str,
        target_host: &str,
    ) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_final_ack_in
            .with_label_values(&[&worker, source_group])
            .inc();
        self.dp_tcp_handshake_final_ack_in_by_target
            .with_label_values(&[&worker, source_group, target_host])
            .inc();
    }

    pub fn inc_dp_tcp_handshake_synack_out_without_followup_ack(
        &self,
        worker: usize,
        source_group: &str,
        target_host: &str,
        reason: &str,
    ) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_synack_out_without_followup_ack
            .with_label_values(&[&worker, source_group, reason])
            .inc();
        self.dp_tcp_handshake_synack_out_without_followup_ack_by_target
            .with_label_values(&[&worker, source_group, target_host, reason])
            .inc();
    }

    pub fn inc_dp_tcp_handshake_drop(&self, worker: usize, phase: &str, reason: &str) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_drops
            .with_label_values(&[&worker, phase, reason])
            .inc();
    }

    pub fn observe_dp_tcp_handshake_close_age(
        &self,
        worker: usize,
        reason: &str,
        phase: &str,
        age_secs: f64,
    ) {
        let worker = worker.to_string();
        self.dp_tcp_handshake_close_age_seconds
            .with_label_values(&[&worker, reason, phase])
            .observe(age_secs.max(0.0));
    }

    pub fn observe_dp_handshake_stage(
        &self,
        worker: usize,
        direction: &str,
        stage: &str,
        duration: Duration,
    ) {
        let worker = worker.to_string();
        self.dp_handshake_stage_seconds
            .with_label_values(&[&worker, direction, stage])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_dp_table_probe(
        &self,
        worker: usize,
        table: &str,
        operation: &str,
        result: &str,
        steps: usize,
    ) {
        let worker = worker.to_string();
        self.dp_table_probe_steps
            .with_label_values(&[&worker, table, operation, result])
            .observe(steps as f64);
    }

    pub fn observe_dp_nat_port_scan(&self, worker: usize, result: &str, steps: usize) {
        let worker = worker.to_string();
        self.dp_nat_port_scan_steps
            .with_label_values(&[&worker, result])
            .observe(steps as f64);
    }

    pub fn inc_dpdk_health_probe(&self, event: &str) {
        self.dpdk_health_probe_packets
            .with_label_values(&[event])
            .inc();
    }

    pub fn set_dpdk_xstat(&self, name: &str, value: u64) {
        self.dpdk_xstats
            .with_label_values(&[name])
            .set(value as f64);
    }

    pub fn set_dhcp_lease_active(&self, active: bool) {
        self.dhcp_lease_active.set(if active { 1.0 } else { 0.0 });
    }

    pub fn set_dhcp_lease_expiry_epoch(&self, expiry: u64) {
        self.dhcp_lease_expiry_epoch.set(expiry as f64);
    }

    pub fn inc_dhcp_lease_change(&self) {
        self.dhcp_lease_changes.inc();
    }

    pub fn inc_integration_route_change(&self) {
        self.integration_route_changes.inc();
    }

    pub fn inc_integration_assignment_change(&self) {
        self.integration_assignment_changes.inc();
    }

    pub fn add_integration_assignment_changes(&self, count: u64) {
        self.integration_assignment_changes.inc_by(count as f64);
    }

    pub fn inc_integration_termination_event(&self) {
        self.integration_termination_events.inc();
    }

    pub fn inc_integration_termination_complete(&self) {
        self.integration_termination_complete.inc();
    }

    pub fn inc_integration_protection_error(&self) {
        self.integration_protection_errors.inc();
    }

    pub fn inc_integration_termination_poll_error(&self) {
        self.integration_termination_poll_errors.inc();
    }

    pub fn inc_integration_termination_publish_error(&self) {
        self.integration_termination_publish_errors.inc();
    }

    pub fn inc_integration_termination_complete_error(&self) {
        self.integration_termination_complete_errors.inc();
    }

    pub fn observe_integration_drain(&self, duration_secs: i64) {
        let value = (duration_secs as f64).max(0.0);
        self.integration_drain_duration
            .with_label_values(&["complete"])
            .observe(value);
    }

    pub fn observe_integration_termination_drain_start(&self, duration_secs: i64) {
        let value = (duration_secs as f64).max(0.0);
        self.integration_termination_drain_start.observe(value);
    }
}
