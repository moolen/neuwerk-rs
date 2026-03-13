use super::*;

impl Metrics {
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
        self.dp_flow_opens
            .with_label_values(&[proto, source_group])
            .inc();
        self.add_dp_active_flows_source_group(source_group, 1);
    }

    pub fn inc_dp_flow_close(&self, reason: &str, count: u64) {
        self.dp_flow_closes
            .with_label_values(&[reason])
            .inc_by(count as f64);
    }

    pub fn observe_dp_flow_close(&self, source_group: &str, reason: &str, lifetime_secs: f64) {
        self.dp_flow_closes.with_label_values(&[reason]).inc();
        self.dp_flow_lifetime_seconds
            .with_label_values(&[source_group, reason])
            .observe(lifetime_secs.max(0.0));
        self.add_dp_active_flows_source_group(source_group, -1);
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

    fn add_dp_active_flows_source_group(&self, source_group: &str, delta: i64) {
        if let Ok(mut lock) = self.dp_active_flows_source_group_counts.lock() {
            let next = {
                let entry = lock.entry(source_group.to_string()).or_insert(0);
                *entry = (*entry + delta).max(0);
                *entry
            };
            self.dp_active_flows_source_group
                .with_label_values(&[source_group])
                .set(next as f64);
        }
    }

    pub fn set_dp_active_nat_entries(&self, count: usize) {
        self.dp_active_nat_entries.set(count as f64);
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

    pub fn set_dp_nat_port_utilization_ratio(&self, ratio: f64) {
        self.dp_nat_port_utilization_ratio.set(ratio);
    }

    pub fn observe_dp_state_lock_wait(&self, wait: Duration) {
        self.dp_state_lock_wait_seconds.observe(wait.as_secs_f64());
    }

    pub fn inc_dp_state_lock_contended(&self) {
        self.dp_state_lock_contended.inc();
    }

    pub fn observe_dpdk_shared_io_lock_wait(&self, wait: Duration) {
        self.dpdk_shared_io_lock_wait_seconds
            .observe(wait.as_secs_f64());
    }

    pub fn inc_dpdk_shared_io_lock_contended(&self) {
        self.dpdk_shared_io_lock_contended.inc();
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
