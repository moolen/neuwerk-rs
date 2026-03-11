use super::*;

impl Metrics {
    pub fn new() -> Result<Self, String> {
        let registry = Registry::new();
        let http_requests = CounterVec::new(
            Opts::new("http_requests_total", "Total HTTP requests"),
            &["path", "method", "status"],
        )
        .map_err(|err| err.to_string())?;
        let http_duration = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request duration seconds",
            ),
            &["path", "method", "status"],
        )
        .map_err(|err| err.to_string())?;
        let http_auth = CounterVec::new(
            Opts::new("http_auth_total", "HTTP auth outcomes"),
            &["outcome", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let http_auth_sso = CounterVec::new(
            Opts::new("http_auth_sso_total", "HTTP SSO auth outcomes"),
            &["outcome", "reason", "provider"],
        )
        .map_err(|err| err.to_string())?;
        let http_auth_sso_latency = HistogramVec::new(
            HistogramOpts::new(
                "http_auth_sso_latency_seconds",
                "HTTP SSO auth stage latency seconds",
            ),
            &["provider", "stage"],
        )
        .map_err(|err| err.to_string())?;
        let dns_queries = CounterVec::new(
            Opts::new("dns_queries_total", "DNS proxy queries"),
            &["result", "reason", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dns_upstream_rtt = HistogramVec::new(
            HistogramOpts::new(
                "dns_upstream_rtt_seconds",
                "DNS upstream round trip time seconds",
            ),
            &["source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dns_nxdomain = CounterVec::new(
            Opts::new("dns_nxdomain_total", "DNS NXDOMAIN responses"),
            &["source"],
        )
        .map_err(|err| err.to_string())?;
        let dns_upstream_mismatch = CounterVec::new(
            Opts::new(
                "dns_upstream_mismatch_total",
                "DNS upstream response validation mismatches",
            ),
            &["reason", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let svc_dns_queries = CounterVec::new(
            Opts::new("svc_dns_queries_total", "Service-plane DNS queries"),
            &["result", "reason", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let svc_dns_upstream_rtt = HistogramVec::new(
            HistogramOpts::new(
                "svc_dns_upstream_rtt_seconds",
                "Service-plane DNS upstream round trip time seconds",
            ),
            &["source_group"],
        )
        .map_err(|err| err.to_string())?;
        let svc_dns_nxdomain = CounterVec::new(
            Opts::new(
                "svc_dns_nxdomain_total",
                "Service-plane DNS NXDOMAIN responses",
            ),
            &["source"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_flows = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_flows_total",
                "Service-plane TLS intercept flow outcomes",
            ),
            &["result"],
        )
        .map_err(|err| err.to_string())?;
        let svc_http_requests = CounterVec::new(
            Opts::new(
                "svc_http_requests_total",
                "Service-plane HTTP request decisions",
            ),
            &["proto", "decision"],
        )
        .map_err(|err| err.to_string())?;
        let svc_http_denies = CounterVec::new(
            Opts::new("svc_http_denies_total", "Service-plane HTTP deny decisions"),
            &["proto", "phase", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let svc_policy_rst = CounterVec::new(
            Opts::new("svc_policy_rst_total", "Service-plane policy RSTs"),
            &["reason"],
        )
        .map_err(|err| err.to_string())?;
        let svc_fail_closed = CounterVec::new(
            Opts::new("svc_fail_closed_total", "Service-plane fail-closed events"),
            &["component"],
        )
        .map_err(|err| err.to_string())?;
        let raft_is_leader = Gauge::with_opts(Opts::new("raft_is_leader", "Raft leader status"))
            .map_err(|err| err.to_string())?;
        let raft_leader_changes = Counter::with_opts(Opts::new(
            "raft_leader_changes_total",
            "Raft leader changes",
        ))
        .map_err(|err| err.to_string())?;
        let raft_current_term = Gauge::with_opts(Opts::new("raft_current_term", "Raft term"))
            .map_err(|err| err.to_string())?;
        let raft_last_log_index =
            Gauge::with_opts(Opts::new("raft_last_log_index", "Raft last log index"))
                .map_err(|err| err.to_string())?;
        let raft_last_applied = Gauge::with_opts(Opts::new(
            "raft_last_applied",
            "Raft last applied log index",
        ))
        .map_err(|err| err.to_string())?;
        let raft_peer_rtt = HistogramVec::new(
            HistogramOpts::new(
                "raft_peer_rtt_seconds",
                "Raft peer RPC round trip time seconds",
            ),
            &["peer_id", "rpc"],
        )
        .map_err(|err| err.to_string())?;
        let raft_peer_errors = CounterVec::new(
            Opts::new("raft_peer_errors_total", "Raft peer RPC errors"),
            &["peer_id", "rpc", "kind"],
        )
        .map_err(|err| err.to_string())?;
        let rocksdb_estimated_num_keys = Gauge::with_opts(Opts::new(
            "rocksdb_estimated_num_keys",
            "RocksDB estimated number of keys",
        ))
        .map_err(|err| err.to_string())?;
        let rocksdb_live_sst_files_size_bytes = Gauge::with_opts(Opts::new(
            "rocksdb_live_sst_files_size_bytes",
            "RocksDB live SST files size bytes",
        ))
        .map_err(|err| err.to_string())?;
        let rocksdb_total_sst_files_size_bytes = Gauge::with_opts(Opts::new(
            "rocksdb_total_sst_files_size_bytes",
            "RocksDB total SST files size bytes",
        ))
        .map_err(|err| err.to_string())?;
        let rocksdb_memtable_bytes = Gauge::with_opts(Opts::new(
            "rocksdb_memtable_bytes",
            "RocksDB memtable bytes",
        ))
        .map_err(|err| err.to_string())?;
        let rocksdb_num_running_compactions = Gauge::with_opts(Opts::new(
            "rocksdb_num_running_compactions",
            "RocksDB running compactions",
        ))
        .map_err(|err| err.to_string())?;
        let rocksdb_num_immutable_memtables = Gauge::with_opts(Opts::new(
            "rocksdb_num_immutable_memtables",
            "RocksDB immutable memtables",
        ))
        .map_err(|err| err.to_string())?;
        let dp_packets = CounterVec::new(
            Opts::new("dp_packets_total", "Dataplane packets"),
            &["direction", "proto", "decision", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_bytes = CounterVec::new(
            Opts::new("dp_bytes_total", "Dataplane bytes"),
            &["direction", "proto", "decision", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_opens = CounterVec::new(
            Opts::new("dp_flow_opens_total", "Dataplane flow opens"),
            &["proto", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_closes = CounterVec::new(
            Opts::new("dp_flow_closes_total", "Dataplane flow closes"),
            &["reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_active_flows =
            Gauge::with_opts(Opts::new("dp_active_flows", "Dataplane active flows"))
                .map_err(|err| err.to_string())?;
        let dp_active_flows_shard = GaugeVec::new(
            Opts::new("dp_active_flows_shard", "Dataplane active flows per shard"),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dp_active_flows_source_group = GaugeVec::new(
            Opts::new(
                "dp_active_flows_by_source_group",
                "Dataplane active flows by source group",
            ),
            &["source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_lifetime_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dp_flow_lifetime_seconds",
                "Dataplane flow lifetime seconds",
            )
            .buckets(vec![
                0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0,
            ]),
            &["source_group", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_active_nat_entries = Gauge::with_opts(Opts::new(
            "dp_active_nat_entries",
            "Dataplane active NAT entries",
        ))
        .map_err(|err| err.to_string())?;
        let dp_active_nat_entries_shard = GaugeVec::new(
            Opts::new(
                "dp_active_nat_entries_shard",
                "Dataplane active NAT entries per shard",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dp_nat_port_utilization_ratio = Gauge::with_opts(Opts::new(
            "dp_nat_port_utilization_ratio",
            "Dataplane NAT port utilization ratio",
        ))
        .map_err(|err| err.to_string())?;
        let dp_state_lock_wait_seconds = Histogram::with_opts(HistogramOpts::new(
            "dp_state_lock_wait_seconds",
            "Dataplane state lock wait time (seconds)",
        ))
        .map_err(|err| err.to_string())?;
        let dp_state_lock_contended = Counter::with_opts(Opts::new(
            "dp_state_lock_contended_total",
            "Dataplane state lock contention events",
        ))
        .map_err(|err| err.to_string())?;
        let dp_tls_decisions = CounterVec::new(
            Opts::new("dp_tls_decisions_total", "Dataplane TLS flow decisions"),
            &["outcome"],
        )
        .map_err(|err| err.to_string())?;
        let dp_icmp_decisions = CounterVec::new(
            Opts::new("dp_icmp_decisions_total", "Dataplane ICMP decisions"),
            &["direction", "type", "code", "decision", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_ipv4_fragments_dropped = Counter::with_opts(Opts::new(
            "dp_ipv4_fragments_dropped_total",
            "Dataplane IPv4 fragments dropped",
        ))
        .map_err(|err| err.to_string())?;
        let dp_ipv4_ttl_exceeded = Counter::with_opts(Opts::new(
            "dp_ipv4_ttl_exceeded_total",
            "Dataplane IPv4 TTL exceeded responses",
        ))
        .map_err(|err| err.to_string())?;
        let dp_arp_handled =
            Counter::with_opts(Opts::new("dp_arp_handled_total", "Dataplane ARP handled"))
                .map_err(|err| err.to_string())?;
        let overlay_decap_errors = Counter::with_opts(Opts::new(
            "overlay_decap_errors_total",
            "Overlay decapsulation errors",
        ))
        .map_err(|err| err.to_string())?;
        let overlay_encap_errors = Counter::with_opts(Opts::new(
            "overlay_encap_errors_total",
            "Overlay encapsulation errors",
        ))
        .map_err(|err| err.to_string())?;
        let overlay_packets = CounterVec::new(
            Opts::new("overlay_packets_total", "Overlay packets"),
            &["mode", "direction"],
        )
        .map_err(|err| err.to_string())?;
        let overlay_mtu_drops =
            Counter::with_opts(Opts::new("overlay_mtu_drops_total", "Overlay MTU drops"))
                .map_err(|err| err.to_string())?;
        let dpdk_init_ok = Gauge::with_opts(Opts::new("dpdk_init_ok", "DPDK init success (0/1)"))
            .map_err(|err| err.to_string())?;
        let dpdk_init_failures =
            Counter::with_opts(Opts::new("dpdk_init_failures_total", "DPDK init failures"))
                .map_err(|err| err.to_string())?;
        let dpdk_rx_packets =
            Counter::with_opts(Opts::new("dpdk_rx_packets_total", "DPDK RX packets"))
                .map_err(|err| err.to_string())?;
        let dpdk_rx_bytes = Counter::with_opts(Opts::new("dpdk_rx_bytes_total", "DPDK RX bytes"))
            .map_err(|err| err.to_string())?;
        let dpdk_rx_dropped = Counter::with_opts(Opts::new(
            "dpdk_rx_dropped_total",
            "DPDK RX dropped packets",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_tx_packets =
            Counter::with_opts(Opts::new("dpdk_tx_packets_total", "DPDK TX packets"))
                .map_err(|err| err.to_string())?;
        let dpdk_tx_bytes = Counter::with_opts(Opts::new("dpdk_tx_bytes_total", "DPDK TX bytes"))
            .map_err(|err| err.to_string())?;
        let dpdk_tx_dropped = Counter::with_opts(Opts::new(
            "dpdk_tx_dropped_total",
            "DPDK TX dropped packets",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_rx_packets_by_queue = CounterVec::new(
            Opts::new("dpdk_rx_packets_queue_total", "DPDK RX packets per queue"),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_rx_bytes_by_queue = CounterVec::new(
            Opts::new("dpdk_rx_bytes_queue_total", "DPDK RX bytes per queue"),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_rx_dropped_by_queue = CounterVec::new(
            Opts::new(
                "dpdk_rx_dropped_queue_total",
                "DPDK RX dropped packets per queue",
            ),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_packets_by_queue = CounterVec::new(
            Opts::new("dpdk_tx_packets_queue_total", "DPDK TX packets per queue"),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_bytes_by_queue = CounterVec::new(
            Opts::new("dpdk_tx_bytes_queue_total", "DPDK TX bytes per queue"),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_dropped_by_queue = CounterVec::new(
            Opts::new(
                "dpdk_tx_dropped_queue_total",
                "DPDK TX dropped packets per queue",
            ),
            &["queue"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_health_probe_packets = CounterVec::new(
            Opts::new(
                "dpdk_health_probe_packets_total",
                "DPDK dataplane health probe packets by event",
            ),
            &["event"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_xstats = GaugeVec::new(Opts::new("dpdk_xstat", "DPDK xstat values"), &["name"])
            .map_err(|err| err.to_string())?;
        let dhcp_lease_active =
            Gauge::with_opts(Opts::new("dhcp_lease_active", "DHCP lease active (0/1)"))
                .map_err(|err| err.to_string())?;
        let dhcp_lease_expiry_epoch = Gauge::with_opts(Opts::new(
            "dhcp_lease_expiry_epoch",
            "DHCP lease expiry epoch",
        ))
        .map_err(|err| err.to_string())?;
        let dhcp_lease_changes =
            Counter::with_opts(Opts::new("dhcp_lease_changes_total", "DHCP lease changes"))
                .map_err(|err| err.to_string())?;
        let integration_route_changes = Counter::with_opts(Opts::new(
            "integration_route_changes_total",
            "Integration route changes",
        ))
        .map_err(|err| err.to_string())?;
        let integration_assignment_changes = Counter::with_opts(Opts::new(
            "integration_assignment_changes_total",
            "Integration assignment changes",
        ))
        .map_err(|err| err.to_string())?;
        let integration_termination_events = Counter::with_opts(Opts::new(
            "integration_termination_events_total",
            "Integration termination events",
        ))
        .map_err(|err| err.to_string())?;
        let integration_termination_complete = Counter::with_opts(Opts::new(
            "integration_termination_complete_total",
            "Integration termination completion",
        ))
        .map_err(|err| err.to_string())?;
        let integration_protection_errors = Counter::with_opts(Opts::new(
            "integration_protection_errors_total",
            "Integration instance protection errors",
        ))
        .map_err(|err| err.to_string())?;
        let integration_termination_poll_errors = Counter::with_opts(Opts::new(
            "integration_termination_poll_errors_total",
            "Integration termination poll errors",
        ))
        .map_err(|err| err.to_string())?;
        let integration_termination_publish_errors = Counter::with_opts(Opts::new(
            "integration_termination_publish_errors_total",
            "Integration termination publish errors",
        ))
        .map_err(|err| err.to_string())?;
        let integration_termination_complete_errors = Counter::with_opts(Opts::new(
            "integration_termination_complete_errors_total",
            "Integration termination completion errors",
        ))
        .map_err(|err| err.to_string())?;
        let integration_drain_duration = HistogramVec::new(
            HistogramOpts::new(
                "integration_drain_duration_seconds",
                "Integration drain durations seconds",
            ),
            &["result"],
        )
        .map_err(|err| err.to_string())?;
        let integration_termination_drain_start = Histogram::with_opts(HistogramOpts::new(
            "integration_termination_drain_start_seconds",
            "Time from termination notice to drain start seconds",
        ))
        .map_err(|err| err.to_string())?;

        registry
            .register(Box::new(http_requests.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(http_duration.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(http_auth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(http_auth_sso.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(http_auth_sso_latency.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dns_queries.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dns_upstream_rtt.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dns_nxdomain.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dns_upstream_mismatch.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_dns_queries.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_dns_upstream_rtt.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_dns_nxdomain.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_flows.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_http_requests.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_http_denies.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_policy_rst.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_fail_closed.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_is_leader.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_leader_changes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_current_term.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_last_log_index.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_last_applied.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_peer_rtt.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(raft_peer_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_estimated_num_keys.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_live_sst_files_size_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_total_sst_files_size_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_memtable_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_num_running_compactions.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(rocksdb_num_immutable_memtables.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_opens.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_closes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_active_flows.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_active_flows_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_active_flows_source_group.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_lifetime_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_active_nat_entries.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_active_nat_entries_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_nat_port_utilization_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_wait_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_contended.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tls_decisions.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_icmp_decisions.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_ipv4_fragments_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_ipv4_ttl_exceeded.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_arp_handled.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(overlay_decap_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(overlay_encap_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(overlay_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(overlay_mtu_drops.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_init_ok.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_init_failures.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_packets_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_bytes_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_rx_dropped_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_packets_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_bytes_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_dropped_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_health_probe_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_xstats.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dhcp_lease_active.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dhcp_lease_expiry_epoch.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dhcp_lease_changes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_route_changes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_assignment_changes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_events.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_complete.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_protection_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_poll_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_publish_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_complete_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_drain_duration.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(integration_termination_drain_start.clone()))
            .map_err(|err| err.to_string())?;

        // Prime counters with a minimal, low-cardinality series so the metrics
        // are always visible even before first use.
        http_auth
            .with_label_values(&["allow", "valid_token"])
            .inc_by(0.0);
        http_auth
            .with_label_values(&["deny", "missing_token"])
            .inc_by(0.0);
        http_auth_sso
            .with_label_values(&["deny", "missing_state", "unknown"])
            .inc_by(0.0);
        dns_queries
            .with_label_values(&["allow", "policy_allow", "default"])
            .inc_by(0.0);
        dns_queries
            .with_label_values(&["deny", "policy_deny", "default"])
            .inc_by(0.0);
        dns_nxdomain.with_label_values(&["policy"]).inc_by(0.0);
        dns_upstream_mismatch
            .with_label_values(&["txid", "default"])
            .inc_by(0.0);
        svc_dns_queries
            .with_label_values(&["allow", "policy_allow", "default"])
            .inc_by(0.0);
        svc_dns_queries
            .with_label_values(&["deny", "policy_deny", "default"])
            .inc_by(0.0);
        svc_dns_nxdomain.with_label_values(&["policy"]).inc_by(0.0);
        svc_tls_intercept_flows
            .with_label_values(&["allow"])
            .inc_by(0.0);
        svc_tls_intercept_flows
            .with_label_values(&["deny"])
            .inc_by(0.0);
        svc_http_requests
            .with_label_values(&["http1", "allow"])
            .inc_by(0.0);
        svc_http_requests
            .with_label_values(&["h2", "deny"])
            .inc_by(0.0);
        svc_http_denies
            .with_label_values(&["http1", "request", "policy"])
            .inc_by(0.0);
        svc_policy_rst.with_label_values(&["policy"]).inc_by(0.0);
        svc_fail_closed.with_label_values(&["tls"]).inc_by(0.0);
        dp_packets
            .with_label_values(&["outbound", "other", "deny", "default"])
            .inc_by(0.0);
        dp_bytes
            .with_label_values(&["outbound", "other", "deny", "default"])
            .inc_by(0.0);
        dp_flow_opens
            .with_label_values(&["other", "default"])
            .inc_by(0.0);
        dp_flow_closes
            .with_label_values(&["idle_timeout"])
            .inc_by(0.0);
        dp_active_flows_source_group
            .with_label_values(&["default"])
            .set(0.0);
        dp_flow_lifetime_seconds
            .with_label_values(&["default", "idle_timeout"])
            .observe(0.0);
        dp_tls_decisions.with_label_values(&["pending"]).inc_by(0.0);
        dp_icmp_decisions
            .with_label_values(&["outbound", "0", "0", "deny", "default"])
            .inc_by(0.0);
        let dp_packets_outbound_tcp_allow_default =
            dp_packets.with_label_values(&["outbound", "tcp", "allow", "default"]);
        let dp_bytes_outbound_tcp_allow_default =
            dp_bytes.with_label_values(&["outbound", "tcp", "allow", "default"]);
        let dp_packets_inbound_tcp_allow_default =
            dp_packets.with_label_values(&["inbound", "tcp", "allow", "default"]);
        let dp_bytes_inbound_tcp_allow_default =
            dp_bytes.with_label_values(&["inbound", "tcp", "allow", "default"]);
        dp_ipv4_fragments_dropped.inc_by(0.0);
        dp_ipv4_ttl_exceeded.inc_by(0.0);
        dp_arp_handled.inc_by(0.0);
        overlay_decap_errors.inc_by(0.0);
        overlay_encap_errors.inc_by(0.0);
        overlay_mtu_drops.inc_by(0.0);
        for mode in ["none", "vxlan", "geneve"] {
            overlay_packets.with_label_values(&[mode, "in"]).inc_by(0.0);
            overlay_packets
                .with_label_values(&[mode, "out"])
                .inc_by(0.0);
        }

        raft_is_leader.set(0.0);
        raft_current_term.set(0.0);
        raft_last_log_index.set(0.0);
        raft_last_applied.set(0.0);
        rocksdb_estimated_num_keys.set(0.0);
        rocksdb_live_sst_files_size_bytes.set(0.0);
        rocksdb_total_sst_files_size_bytes.set(0.0);
        rocksdb_memtable_bytes.set(0.0);
        rocksdb_num_running_compactions.set(0.0);
        rocksdb_num_immutable_memtables.set(0.0);
        dp_active_flows.set(0.0);
        dp_active_flows_shard.with_label_values(&["0"]).set(0.0);
        dp_active_nat_entries.set(0.0);
        dp_active_nat_entries_shard
            .with_label_values(&["0"])
            .set(0.0);
        dp_nat_port_utilization_ratio.set(0.0);
        dp_state_lock_wait_seconds.observe(0.0);
        dp_state_lock_contended.inc_by(0.0);
        dpdk_init_ok.set(0.0);
        dpdk_init_failures.inc_by(0.0);
        dpdk_rx_packets.inc_by(0.0);
        dpdk_rx_bytes.inc_by(0.0);
        dpdk_rx_dropped.inc_by(0.0);
        dpdk_tx_packets.inc_by(0.0);
        dpdk_tx_bytes.inc_by(0.0);
        dpdk_tx_dropped.inc_by(0.0);
        dpdk_rx_packets_by_queue
            .with_label_values(&["0"])
            .inc_by(0.0);
        dpdk_rx_bytes_by_queue.with_label_values(&["0"]).inc_by(0.0);
        dpdk_rx_dropped_by_queue
            .with_label_values(&["0"])
            .inc_by(0.0);
        dpdk_tx_packets_by_queue
            .with_label_values(&["0"])
            .inc_by(0.0);
        dpdk_tx_bytes_by_queue.with_label_values(&["0"]).inc_by(0.0);
        dpdk_tx_dropped_by_queue
            .with_label_values(&["0"])
            .inc_by(0.0);
        for event in [
            "syn_seen",
            "synack_sent",
            "ack_seen",
            "fin_seen",
            "finack_sent",
            "rst_seen",
            "other_seen",
        ] {
            dpdk_health_probe_packets
                .with_label_values(&[event])
                .inc_by(0.0);
        }
        for name in [
            "bw_in_allowance_exceeded",
            "bw_out_allowance_exceeded",
            "pps_allowance_exceeded",
            "conntrack_allowance_exceeded",
            "conntrack_allowance_available",
            "linklocal_allowance_exceeded",
        ] {
            dpdk_xstats.with_label_values(&[name]).set(0.0);
        }
        dhcp_lease_active.set(0.0);
        dhcp_lease_expiry_epoch.set(0.0);
        dhcp_lease_changes.inc_by(0.0);
        integration_route_changes.inc_by(0.0);
        integration_assignment_changes.inc_by(0.0);
        integration_termination_events.inc_by(0.0);
        integration_termination_complete.inc_by(0.0);
        integration_protection_errors.inc_by(0.0);
        integration_termination_poll_errors.inc_by(0.0);
        integration_termination_publish_errors.inc_by(0.0);
        integration_termination_complete_errors.inc_by(0.0);
        integration_drain_duration
            .with_label_values(&["complete"])
            .observe(0.0);
        integration_termination_drain_start.observe(0.0);

        Ok(Self {
            registry,
            http_requests,
            http_duration,
            http_auth,
            http_auth_sso,
            http_auth_sso_latency,
            dns_queries,
            dns_upstream_rtt,
            dns_nxdomain,
            dns_upstream_mismatch,
            svc_dns_queries,
            svc_dns_upstream_rtt,
            svc_dns_nxdomain,
            svc_tls_intercept_flows,
            svc_http_requests,
            svc_http_denies,
            svc_policy_rst,
            svc_fail_closed,
            raft_is_leader,
            raft_leader_changes,
            raft_current_term,
            raft_last_log_index,
            raft_last_applied,
            raft_peer_rtt,
            raft_peer_errors,
            rocksdb_estimated_num_keys,
            rocksdb_live_sst_files_size_bytes,
            rocksdb_total_sst_files_size_bytes,
            rocksdb_memtable_bytes,
            rocksdb_num_running_compactions,
            rocksdb_num_immutable_memtables,
            dp_packets,
            dp_bytes,
            dp_packets_outbound_tcp_allow_default,
            dp_bytes_outbound_tcp_allow_default,
            dp_packets_inbound_tcp_allow_default,
            dp_bytes_inbound_tcp_allow_default,
            dp_flow_opens,
            dp_flow_closes,
            dp_active_flows,
            dp_active_flows_shard,
            dp_active_flows_source_group,
            dp_flow_lifetime_seconds,
            dp_active_nat_entries,
            dp_active_nat_entries_shard,
            dp_nat_port_utilization_ratio,
            dp_state_lock_wait_seconds,
            dp_state_lock_contended,
            dp_tls_decisions,
            dp_icmp_decisions,
            dp_ipv4_fragments_dropped,
            dp_ipv4_ttl_exceeded,
            dp_arp_handled,
            overlay_decap_errors,
            overlay_encap_errors,
            overlay_packets,
            overlay_mtu_drops,
            dpdk_init_ok,
            dpdk_init_failures,
            dpdk_rx_packets,
            dpdk_rx_bytes,
            dpdk_rx_dropped,
            dpdk_tx_packets,
            dpdk_tx_bytes,
            dpdk_tx_dropped,
            dpdk_rx_packets_by_queue,
            dpdk_rx_bytes_by_queue,
            dpdk_rx_dropped_by_queue,
            dpdk_tx_packets_by_queue,
            dpdk_tx_bytes_by_queue,
            dpdk_tx_dropped_by_queue,
            dpdk_health_probe_packets,
            dpdk_xstats,
            dhcp_lease_active,
            dhcp_lease_expiry_epoch,
            dhcp_lease_changes,
            integration_route_changes,
            integration_assignment_changes,
            integration_termination_events,
            integration_termination_complete,
            integration_protection_errors,
            integration_termination_poll_errors,
            integration_termination_publish_errors,
            integration_termination_complete_errors,
            integration_drain_duration,
            integration_termination_drain_start,
            dp_active_flows_counts: Arc::new(Mutex::new(HashMap::new())),
            dp_active_flows_source_group_counts: Arc::new(Mutex::new(HashMap::new())),
            dp_active_nat_counts: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}
