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
        let svc_tls_intercept_errors = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_errors_total",
                "Service-plane TLS intercept errors by stage and reason",
            ),
            &["stage", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_phase = HistogramVec::new(
            HistogramOpts::new(
                "svc_tls_intercept_phase_seconds",
                "Service-plane TLS intercept phase latency seconds",
            ),
            &["phase"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_inflight = GaugeVec::new(
            Opts::new(
                "svc_tls_intercept_inflight",
                "Service-plane TLS intercept in-flight work",
            ),
            &["kind"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_pool = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_pool_total",
                "Service-plane TLS intercept upstream HTTP/2 pool events",
            ),
            &["result"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_shard_select = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_shard_select_total",
                "Service-plane TLS intercept upstream HTTP/2 shard selections",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_send_wait = HistogramVec::new(
            HistogramOpts::new(
                "svc_tls_intercept_upstream_h2_send_wait_seconds",
                "Service-plane TLS intercept upstream HTTP/2 send-path wait time seconds",
            )
            .buckets(vec![
                0.000001, 0.000005, 0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05,
                0.1, 0.5, 1.0,
            ]),
            &["phase"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_selected_inflight = Histogram::with_opts(
            HistogramOpts::new(
                "svc_tls_intercept_upstream_h2_selected_inflight",
                "Service-plane TLS intercept selected upstream HTTP/2 session in-flight stream count",
            )
            .buckets(vec![0.0, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0]),
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_pool_width = Histogram::with_opts(
            HistogramOpts::new(
                "svc_tls_intercept_upstream_h2_pool_width",
                "Service-plane TLS intercept upstream HTTP/2 candidate session count per shard",
            )
            .buckets(vec![0.0, 1.0, 2.0, 3.0, 4.0, 8.0, 16.0, 32.0]),
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_ready_errors = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_ready_errors_total",
                "Service-plane TLS intercept upstream HTTP/2 ready error kinds",
            ),
            &["kind"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_response_errors = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_response_errors_total",
                "Service-plane TLS intercept upstream response error kinds",
            ),
            &["kind"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_conn_closed = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_conn_closed_total",
                "Service-plane TLS intercept upstream HTTP/2 connection close events by reason",
            ),
            &["reason"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_conn_termination = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_conn_termination_total",
                "Service-plane TLS intercept upstream HTTP/2 termination classes and reasons",
            ),
            &["kind", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_retry = CounterVec::new(
            Opts::new(
                "svc_tls_intercept_upstream_h2_retry_total",
                "Service-plane TLS intercept upstream HTTP/2 reconnect retry causes",
            ),
            &["cause"],
        )
        .map_err(|err| err.to_string())?;
        let svc_tls_intercept_upstream_h2_selected_inflight_peak = Gauge::with_opts(Opts::new(
            "svc_tls_intercept_upstream_h2_selected_inflight_peak",
            "Service-plane TLS intercept selected upstream HTTP/2 session peak in-flight streams over the current second window",
        ))
        .map_err(|err| err.to_string())?;
        let threat_matches = CounterVec::new(
            Opts::new(
                "neuwerk_threat_matches_total",
                "Threat-intel indicator matches by type, layer, severity, feed, and source",
            ),
            &[
                "indicator_type",
                "observation_layer",
                "severity",
                "feed",
                "match_source",
            ],
        )
        .map_err(|err| err.to_string())?;
        let threat_alertable_matches = CounterVec::new(
            Opts::new(
                "neuwerk_threat_alertable_matches_total",
                "Threat-intel alertable indicator matches by type, layer, severity, and feed",
            ),
            &["indicator_type", "observation_layer", "severity", "feed"],
        )
        .map_err(|err| err.to_string())?;
        let threat_feed_refresh = CounterVec::new(
            Opts::new(
                "neuwerk_threat_feed_refresh_total",
                "Threat feed refresh attempts by feed and outcome",
            ),
            &["feed", "outcome"],
        )
        .map_err(|err| err.to_string())?;
        let threat_feed_snapshot_age_seconds = GaugeVec::new(
            Opts::new(
                "neuwerk_threat_feed_snapshot_age_seconds",
                "Age of the current threat feed snapshot in seconds",
            ),
            &["feed"],
        )
        .map_err(|err| err.to_string())?;
        let threat_feed_indicators = GaugeVec::new(
            Opts::new(
                "neuwerk_threat_feed_indicators",
                "Threat feed indicator counts by feed and indicator type",
            ),
            &["feed", "indicator_type"],
        )
        .map_err(|err| err.to_string())?;
        let threat_backfill_runs = CounterVec::new(
            Opts::new(
                "neuwerk_threat_backfill_runs_total",
                "Threat backfill runs by outcome",
            ),
            &["outcome"],
        )
        .map_err(|err| err.to_string())?;
        let threat_backfill_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "neuwerk_threat_backfill_duration_seconds",
            "Threat backfill duration seconds",
        ))
        .map_err(|err| err.to_string())?;
        let threat_enrichment_requests = CounterVec::new(
            Opts::new(
                "neuwerk_threat_enrichment_requests_total",
                "Threat enrichment requests by provider and outcome",
            ),
            &["provider", "outcome"],
        )
        .map_err(|err| err.to_string())?;
        let threat_enrichment_queue_depth = Gauge::with_opts(Opts::new(
            "neuwerk_threat_enrichment_queue_depth",
            "Threat enrichment queue depth",
        ))
        .map_err(|err| err.to_string())?;
        let threat_observation_enqueue_failures = Counter::with_opts(Opts::new(
            "neuwerk_threat_observation_enqueue_failures_total",
            "Threat observation enqueue failures",
        ))
        .map_err(|err| err.to_string())?;
        let threat_findings_active = GaugeVec::new(
            Opts::new(
                "neuwerk_threat_findings_active",
                "Active threat findings by severity",
            ),
            &["severity"],
        )
        .map_err(|err| err.to_string())?;
        let threat_cluster_snapshot_version = Gauge::with_opts(Opts::new(
            "neuwerk_threat_cluster_snapshot_version",
            "Threat cluster snapshot version",
        ))
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
        let dp_flow_opens_tcp_default = dp_flow_opens.with_label_values(&["tcp", "default"]);
        let dp_flow_opens_udp_default = dp_flow_opens.with_label_values(&["udp", "default"]);
        let dp_flow_closes = CounterVec::new(
            Opts::new("dp_flow_closes_total", "Dataplane flow closes"),
            &["reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_lifecycle_events = CounterVec::new(
            Opts::new(
                "dp_flow_lifecycle_events_total",
                "Dataplane flow lifecycle events by worker, event, and reason",
            ),
            &["worker", "event", "reason"],
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
        let dp_active_flows_source_group_default =
            dp_active_flows_source_group.with_label_values(&["default"]);
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
        let dp_flow_table_utilization_ratio = Gauge::with_opts(Opts::new(
            "dp_flow_table_utilization_ratio",
            "Dataplane flow-table utilization ratio",
        ))
        .map_err(|err| err.to_string())?;
        let dp_flow_table_utilization_ratio_shard = GaugeVec::new(
            Opts::new(
                "dp_flow_table_utilization_ratio_shard",
                "Dataplane flow-table utilization ratio per shard",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_table_capacity = GaugeVec::new(
            Opts::new(
                "dp_flow_table_capacity",
                "Dataplane flow-table slot capacity by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_table_tombstones = GaugeVec::new(
            Opts::new(
                "dp_flow_table_tombstones",
                "Dataplane flow-table tombstone slots by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_table_used_slots_ratio = GaugeVec::new(
            Opts::new(
                "dp_flow_table_used_slots_ratio",
                "Dataplane flow-table used-slot ratio ((live+tombstones)/capacity) by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_table_tombstone_ratio = GaugeVec::new(
            Opts::new(
                "dp_flow_table_tombstone_ratio",
                "Dataplane flow-table tombstone ratio (tombstones/capacity) by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_flow_table_resize_events = CounterVec::new(
            Opts::new(
                "dp_flow_table_resize_events_total",
                "Dataplane flow-table resize events by worker and reason",
            ),
            &["worker", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_syn_only_active_flows = GaugeVec::new(
            Opts::new(
                "dp_syn_only_active_flows",
                "Dataplane SYN-only half-open flows by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_syn_only_lookup = CounterVec::new(
            Opts::new(
                "dp_syn_only_lookup_total",
                "Dataplane SYN-only lookup outcomes by worker and result",
            ),
            &["worker", "result"],
        )
        .map_err(|err| err.to_string())?;
        let dp_syn_only_promotions = CounterVec::new(
            Opts::new(
                "dp_syn_only_promotions_total",
                "Dataplane SYN-only promotions into full flow-table entries by worker and reason",
            ),
            &["worker", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_syn_only_evictions = CounterVec::new(
            Opts::new(
                "dp_syn_only_evictions_total",
                "Dataplane SYN-only evictions/removals by worker and reason",
            ),
            &["worker", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_nat_table_utilization_ratio = Gauge::with_opts(Opts::new(
            "dp_nat_table_utilization_ratio",
            "Dataplane NAT-table utilization ratio",
        ))
        .map_err(|err| err.to_string())?;
        let dp_nat_table_utilization_ratio_shard = GaugeVec::new(
            Opts::new(
                "dp_nat_table_utilization_ratio_shard",
                "Dataplane NAT-table utilization ratio per shard",
            ),
            &["shard"],
        )
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
        let dp_state_lock_wait_seconds_worker = HistogramVec::new(
            HistogramOpts::new(
                "dp_state_lock_wait_seconds_worker",
                "Dataplane state lock wait time by worker (seconds)",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_state_lock_wait_seconds_shard = HistogramVec::new(
            HistogramOpts::new(
                "dp_state_lock_wait_seconds_shard",
                "Dataplane state lock wait time by shard (seconds)",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dp_state_lock_hold_seconds_worker = HistogramVec::new(
            HistogramOpts::new(
                "dp_state_lock_hold_seconds_worker",
                "Dataplane state lock hold time by worker (seconds)",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_state_lock_hold_seconds_shard = HistogramVec::new(
            HistogramOpts::new(
                "dp_state_lock_hold_seconds_shard",
                "Dataplane state lock hold time by shard (seconds)",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dp_state_lock_contended_worker = CounterVec::new(
            Opts::new(
                "dp_state_lock_contended_worker_total",
                "Dataplane state lock contention events by worker",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dp_state_lock_contended_shard = CounterVec::new(
            Opts::new(
                "dp_state_lock_contended_shard_total",
                "Dataplane state lock contention events by shard",
            ),
            &["shard"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_shared_io_lock_wait_seconds = Histogram::with_opts(HistogramOpts::new(
            "dpdk_shared_io_lock_wait_seconds",
            "DPDK shared IO lock wait time (seconds)",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_shared_io_lock_contended = Counter::with_opts(Opts::new(
            "dpdk_shared_io_lock_contended_total",
            "DPDK shared IO lock contention events",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_shared_io_lock_wait_seconds_worker = HistogramVec::new(
            HistogramOpts::new(
                "dpdk_shared_io_lock_wait_seconds_worker",
                "DPDK shared IO lock wait time by worker (seconds)",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_shared_io_lock_hold_seconds_worker = HistogramVec::new(
            HistogramOpts::new(
                "dpdk_shared_io_lock_hold_seconds_worker",
                "DPDK shared IO lock hold time by worker (seconds)",
            ),
            &["worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_shared_io_lock_contended_worker = CounterVec::new(
            Opts::new(
                "dpdk_shared_io_lock_contended_worker_total",
                "DPDK shared IO lock contention events by worker",
            ),
            &["worker"],
        )
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
        let dpdk_tx_packet_class_by_queue = CounterVec::new(
            Opts::new(
                "dpdk_tx_packet_class_queue_total",
                "DPDK TX accepted packets by queue and classified packet type",
            ),
            &["queue", "class"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_stage_packets = CounterVec::new(
            Opts::new(
                "dpdk_tx_stage_packets_total",
                "DPDK TX packets by port, queue, and send-path stage",
            ),
            &["port", "queue", "stage"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_stage_bytes = CounterVec::new(
            Opts::new(
                "dpdk_tx_stage_bytes_total",
                "DPDK TX bytes by port, queue, and send-path stage",
            ),
            &["port", "queue", "stage"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_tx_stage_packet_class = CounterVec::new(
            Opts::new(
                "dpdk_tx_stage_packet_class_total",
                "DPDK TX packets by port, queue, send-path stage, and packet class",
            ),
            &["port", "queue", "stage", "class"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_dispatch_packets = CounterVec::new(
            Opts::new(
                "dpdk_flow_steer_dispatch_packets_total",
                "DPDK packets dispatched through shared RX software demux",
            ),
            &["from_worker", "to_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_dispatch_bytes = CounterVec::new(
            Opts::new(
                "dpdk_flow_steer_dispatch_bytes_total",
                "DPDK bytes dispatched through shared RX software demux",
            ),
            &["from_worker", "to_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_fail_open_events = CounterVec::new(
            Opts::new(
                "dpdk_flow_steer_fail_open_events_total",
                "DPDK shared RX software demux fail-open events by worker and reason",
            ),
            &["worker", "event"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_queue_wait_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dpdk_flow_steer_queue_wait_seconds",
                "DPDK shared RX software demux queue wait time (seconds)",
            ),
            &["to_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_queue_depth = GaugeVec::new(
            Opts::new(
                "dpdk_flow_steer_queue_depth",
                "DPDK shared RX software demux queue depth by target worker",
            ),
            &["to_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_flow_steer_queue_utilization_ratio = GaugeVec::new(
            Opts::new(
                "dpdk_flow_steer_queue_utilization_ratio",
                "DPDK shared RX software demux queue utilization ratio by target worker",
            ),
            &["to_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_service_lane_forward_packets = CounterVec::new(
            Opts::new(
                "dpdk_service_lane_forward_packets_total",
                "DPDK service-lane host frames forwarded to the owner worker",
            ),
            &["from_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_service_lane_forward_bytes = CounterVec::new(
            Opts::new(
                "dpdk_service_lane_forward_bytes_total",
                "DPDK service-lane host-frame bytes forwarded to the owner worker",
            ),
            &["from_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_service_lane_forward_queue_wait_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dpdk_service_lane_forward_queue_wait_seconds",
                "DPDK service-lane forward queue wait time (seconds)",
            ),
            &["from_worker"],
        )
        .map_err(|err| err.to_string())?;
        let dpdk_service_lane_forward_queue_depth = Gauge::with_opts(Opts::new(
            "dpdk_service_lane_forward_queue_depth",
            "DPDK service-lane forward queue depth",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_service_lane_forward_queue_utilization_ratio = Gauge::with_opts(Opts::new(
            "dpdk_service_lane_forward_queue_utilization_ratio",
            "DPDK service-lane forward queue utilization ratio",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_intercept_demux_size = Gauge::with_opts(Opts::new(
            "dpdk_intercept_demux_size",
            "DPDK intercept demux current entry count",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_host_frame_queue_depth = Gauge::with_opts(Opts::new(
            "dpdk_host_frame_queue_depth",
            "DPDK service-lane host-frame queue depth",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_pending_arp_queue_depth = Gauge::with_opts(Opts::new(
            "dpdk_pending_arp_queue_depth",
            "DPDK pending ARP frame queue depth",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_intercept_demux_insert_dropped = Counter::with_opts(Opts::new(
            "dpdk_intercept_demux_insert_dropped_total",
            "DPDK intercept demux inserts dropped due to cap",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_host_frame_dropped = Counter::with_opts(Opts::new(
            "dpdk_host_frame_dropped_total",
            "DPDK host frames dropped from queue due to cap",
        ))
        .map_err(|err| err.to_string())?;
        let dpdk_pending_arp_frame_dropped = Counter::with_opts(Opts::new(
            "dpdk_pending_arp_frame_dropped_total",
            "DPDK queued ARP frames dropped due to cap",
        ))
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_events = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_events_total",
                "Dataplane TCP handshake packet events by worker",
            ),
            &["worker", "event"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_events_by_target = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_events_by_target_total",
                "Dataplane TCP handshake packet events by worker, event, and target host",
            ),
            &["worker", "event", "target_host"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_final_ack_in = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_final_ack_in_total",
                "Dataplane TCP final-ACK ingress events by worker and source group",
            ),
            &["worker", "source_group"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_final_ack_in_by_target = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_final_ack_in_by_target_total",
                "Dataplane TCP final-ACK ingress events by worker, source group, and target host",
            ),
            &["worker", "source_group", "target_host"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_synack_out_without_followup_ack = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_synack_out_without_followup_ack_total",
                "Dataplane TCP SYN-ACK forwards that never observed a follow-up final ACK, by worker, source group, and close reason",
            ),
            &["worker", "source_group", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_synack_out_without_followup_ack_by_target = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_synack_out_without_followup_ack_by_target_total",
                "Dataplane TCP SYN-ACK forwards that never observed a follow-up final ACK, by worker, source group, target host, and close reason",
            ),
            &["worker", "source_group", "target_host", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_drops = CounterVec::new(
            Opts::new(
                "dp_tcp_handshake_drops_total",
                "Dataplane TCP handshake drops by worker, phase, and reason",
            ),
            &["worker", "phase", "reason"],
        )
        .map_err(|err| err.to_string())?;
        let dp_tcp_handshake_close_age_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dp_tcp_handshake_close_age_seconds",
                "Dataplane TCP flow close age by worker, reason, and handshake phase state (seconds)",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 30.0,
                60.0, 120.0, 300.0,
            ]),
            &["worker", "reason", "completion"],
        )
        .map_err(|err| err.to_string())?;
        let dp_handshake_stage_seconds = HistogramVec::new(
            HistogramOpts::new(
                "dp_handshake_stage_seconds",
                "Dataplane TCP-handshake stage time by worker, direction, and stage (seconds)",
            )
            .buckets(vec![
                0.000_000_5,
                0.000_001,
                0.000_002_5,
                0.000_005,
                0.000_01,
                0.000_025,
                0.000_05,
                0.000_1,
                0.000_25,
                0.000_5,
                0.001,
                0.002_5,
                0.005,
                0.01,
                0.025,
                0.05,
            ]),
            &["worker", "direction", "stage"],
        )
        .map_err(|err| err.to_string())?;
        let dp_table_probe_steps = HistogramVec::new(
            HistogramOpts::new(
                "dp_table_probe_steps",
                "Dataplane flow/NAT table probe steps by worker, table, operation, and result",
            )
            .buckets(vec![
                1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0, 32.0, 48.0, 64.0, 96.0, 128.0,
                256.0,
            ]),
            &["worker", "table", "operation", "result"],
        )
        .map_err(|err| err.to_string())?;
        let dp_nat_port_scan_steps = HistogramVec::new(
            HistogramOpts::new(
                "dp_nat_port_scan_steps",
                "Dataplane NAT port-allocation scan steps by worker and result",
            )
            .buckets(vec![
                1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0, 24.0, 32.0, 48.0, 64.0, 96.0, 128.0,
                256.0, 512.0, 1024.0,
            ]),
            &["worker", "result"],
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
            .register(Box::new(svc_tls_intercept_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_phase.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_inflight.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_pool.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_shard_select.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_send_wait.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                svc_tls_intercept_upstream_h2_selected_inflight.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_pool_width.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_ready_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_response_errors.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_conn_closed.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                svc_tls_intercept_upstream_h2_conn_termination.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(svc_tls_intercept_upstream_h2_retry.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                svc_tls_intercept_upstream_h2_selected_inflight_peak.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_matches.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_alertable_matches.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_feed_refresh.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_feed_snapshot_age_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_feed_indicators.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_backfill_runs.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_backfill_duration_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_enrichment_requests.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_enrichment_queue_depth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_observation_enqueue_failures.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_findings_active.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(threat_cluster_snapshot_version.clone()))
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
            .register(Box::new(dp_flow_lifecycle_events.clone()))
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
            .register(Box::new(dp_flow_table_utilization_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_utilization_ratio_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_capacity.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_tombstones.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_used_slots_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_tombstone_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_flow_table_resize_events.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_syn_only_active_flows.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_syn_only_lookup.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_syn_only_promotions.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_syn_only_evictions.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_nat_table_utilization_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_nat_table_utilization_ratio_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_wait_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_contended.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_wait_seconds_worker.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_wait_seconds_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_hold_seconds_worker.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_hold_seconds_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_contended_worker.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_state_lock_contended_shard.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_shared_io_lock_wait_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_shared_io_lock_contended.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_shared_io_lock_wait_seconds_worker.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_shared_io_lock_hold_seconds_worker.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_shared_io_lock_contended_worker.clone()))
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
            .register(Box::new(dpdk_tx_packet_class_by_queue.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_stage_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_stage_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_tx_stage_packet_class.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_dispatch_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_dispatch_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_fail_open_events.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_queue_wait_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_queue_depth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_flow_steer_queue_utilization_ratio.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_service_lane_forward_packets.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_service_lane_forward_bytes.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                dpdk_service_lane_forward_queue_wait_seconds.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_service_lane_forward_queue_depth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                dpdk_service_lane_forward_queue_utilization_ratio.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_intercept_demux_size.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_host_frame_queue_depth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_pending_arp_queue_depth.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_intercept_demux_insert_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_host_frame_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_pending_arp_frame_dropped.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_events.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_events_by_target.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_final_ack_in.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_final_ack_in_by_target.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                dp_tcp_handshake_synack_out_without_followup_ack.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(
                dp_tcp_handshake_synack_out_without_followup_ack_by_target.clone(),
            ))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_drops.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_tcp_handshake_close_age_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_handshake_stage_seconds.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_table_probe_steps.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_nat_port_scan_steps.clone()))
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
        threat_matches
            .with_label_values(&["domain", "dns", "high", "default", "inline"])
            .inc_by(0.0);
        threat_alertable_matches
            .with_label_values(&["domain", "dns", "high", "default"])
            .inc_by(0.0);
        threat_feed_refresh
            .with_label_values(&["default", "success"])
            .inc_by(0.0);
        threat_feed_snapshot_age_seconds
            .with_label_values(&["default"])
            .set(0.0);
        threat_feed_indicators
            .with_label_values(&["default", "domain"])
            .set(0.0);
        threat_backfill_runs
            .with_label_values(&["success"])
            .inc_by(0.0);
        threat_backfill_duration_seconds.observe(0.0);
        threat_enrichment_requests
            .with_label_values(&["default", "success"])
            .inc_by(0.0);
        threat_enrichment_queue_depth.set(0.0);
        threat_observation_enqueue_failures.inc_by(0.0);
        threat_findings_active.with_label_values(&["high"]).set(0.0);
        threat_cluster_snapshot_version.set(0.0);
        svc_fail_closed.with_label_values(&["tls"]).inc_by(0.0);
        svc_tls_intercept_errors
            .with_label_values(&["other", "failure"])
            .inc_by(0.0);
        svc_tls_intercept_phase
            .with_label_values(&["client_tls_accept"])
            .observe(0.0);
        svc_tls_intercept_inflight
            .with_label_values(&["connections"])
            .set(0.0);
        svc_tls_intercept_upstream_h2_pool
            .with_label_values(&["hit"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_shard_select
            .with_label_values(&["0"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_send_wait
            .with_label_values(&["sender_clone_lock_wait"])
            .observe(0.0);
        svc_tls_intercept_upstream_h2_send_wait
            .with_label_values(&["ready_wait"])
            .observe(0.0);
        svc_tls_intercept_upstream_h2_selected_inflight.observe(0.0);
        svc_tls_intercept_upstream_h2_pool_width.observe(0.0);
        svc_tls_intercept_upstream_h2_ready_errors
            .with_label_values(&["other"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_response_errors
            .with_label_values(&["other"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_conn_closed
            .with_label_values(&["other"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_conn_termination
            .with_label_values(&["other", "other"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_retry
            .with_label_values(&["other"])
            .inc_by(0.0);
        svc_tls_intercept_upstream_h2_selected_inflight_peak.set(0.0);
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
        dp_flow_lifecycle_events
            .with_label_values(&["0", "open", "new"])
            .inc_by(0.0);
        dp_flow_lifecycle_events
            .with_label_values(&["0", "close", "idle_timeout"])
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
        dpdk_shared_io_lock_wait_seconds.observe(0.0);
        dpdk_shared_io_lock_contended.inc_by(0.0);
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
        dpdk_tx_packet_class_by_queue
            .with_label_values(&["0", "tcp_syn"])
            .inc_by(0.0);
        dpdk_tx_packet_class_by_queue
            .with_label_values(&["0", "tcp_synack"])
            .inc_by(0.0);
        dpdk_tx_stage_packets
            .with_label_values(&["0", "0", "attempted"])
            .inc_by(0.0);
        dpdk_tx_stage_bytes
            .with_label_values(&["0", "0", "attempted"])
            .inc_by(0.0);
        dpdk_tx_stage_packet_class
            .with_label_values(&["0", "0", "attempted", "tcp_syn"])
            .inc_by(0.0);
        dpdk_tx_stage_packet_class
            .with_label_values(&["0", "0", "burst_unsent", "tcp_syn"])
            .inc_by(0.0);
        dpdk_flow_steer_dispatch_packets
            .with_label_values(&["0", "0"])
            .inc_by(0.0);
        dpdk_flow_steer_dispatch_bytes
            .with_label_values(&["0", "0"])
            .inc_by(0.0);
        dpdk_flow_steer_fail_open_events
            .with_label_values(&["0", "dispatch_failed"])
            .inc_by(0.0);
        dpdk_flow_steer_queue_wait_seconds
            .with_label_values(&["0"])
            .observe(0.0);
        dpdk_flow_steer_queue_depth
            .with_label_values(&["0"])
            .set(0.0);
        dpdk_flow_steer_queue_utilization_ratio
            .with_label_values(&["0"])
            .set(0.0);
        dpdk_service_lane_forward_packets
            .with_label_values(&["1"])
            .inc_by(0.0);
        dpdk_service_lane_forward_bytes
            .with_label_values(&["1"])
            .inc_by(0.0);
        dpdk_service_lane_forward_queue_wait_seconds
            .with_label_values(&["1"])
            .observe(0.0);
        dpdk_service_lane_forward_queue_depth.set(0.0);
        dpdk_service_lane_forward_queue_utilization_ratio.set(0.0);
        dpdk_intercept_demux_size.set(0.0);
        dpdk_host_frame_queue_depth.set(0.0);
        dpdk_pending_arp_queue_depth.set(0.0);
        dpdk_intercept_demux_insert_dropped.inc_by(0.0);
        dpdk_host_frame_dropped.inc_by(0.0);
        dpdk_pending_arp_frame_dropped.inc_by(0.0);
        dp_state_lock_wait_seconds_worker
            .with_label_values(&["0"])
            .observe(0.0);
        dp_state_lock_wait_seconds_shard
            .with_label_values(&["0"])
            .observe(0.0);
        dp_state_lock_hold_seconds_worker
            .with_label_values(&["0"])
            .observe(0.0);
        dp_state_lock_hold_seconds_shard
            .with_label_values(&["0"])
            .observe(0.0);
        dp_state_lock_contended_worker
            .with_label_values(&["0"])
            .inc_by(0.0);
        dp_state_lock_contended_shard
            .with_label_values(&["0"])
            .inc_by(0.0);
        dpdk_shared_io_lock_wait_seconds_worker
            .with_label_values(&["0"])
            .observe(0.0);
        dpdk_shared_io_lock_hold_seconds_worker
            .with_label_values(&["0"])
            .observe(0.0);
        dpdk_shared_io_lock_contended_worker
            .with_label_values(&["0"])
            .inc_by(0.0);
        dp_flow_table_utilization_ratio.set(0.0);
        dp_flow_table_utilization_ratio_shard
            .with_label_values(&["0"])
            .set(0.0);
        dp_flow_table_capacity.with_label_values(&["0"]).set(0.0);
        dp_flow_table_tombstones.with_label_values(&["0"]).set(0.0);
        dp_flow_table_used_slots_ratio
            .with_label_values(&["0"])
            .set(0.0);
        dp_flow_table_tombstone_ratio
            .with_label_values(&["0"])
            .set(0.0);
        dp_flow_table_resize_events
            .with_label_values(&["0", "grow"])
            .inc_by(0.0);
        dp_flow_table_resize_events
            .with_label_values(&["0", "shrink"])
            .inc_by(0.0);
        dp_flow_table_resize_events
            .with_label_values(&["0", "rehash"])
            .inc_by(0.0);
        dp_syn_only_active_flows.with_label_values(&["0"]).set(0.0);
        dp_syn_only_lookup
            .with_label_values(&["0", "miss"])
            .inc_by(0.0);
        dp_syn_only_lookup
            .with_label_values(&["0", "hit"])
            .inc_by(0.0);
        dp_syn_only_lookup
            .with_label_values(&["0", "promoted"])
            .inc_by(0.0);
        dp_syn_only_lookup
            .with_label_values(&["0", "removed"])
            .inc_by(0.0);
        dp_syn_only_promotions
            .with_label_values(&["0", "inbound_synack"])
            .inc_by(0.0);
        dp_syn_only_evictions
            .with_label_values(&["0", "idle_timeout"])
            .inc_by(0.0);
        dp_nat_table_utilization_ratio.set(0.0);
        dp_nat_table_utilization_ratio_shard
            .with_label_values(&["0"])
            .set(0.0);
        for event in ["syn_in", "syn_out", "synack_in", "synack_out", "completed"] {
            dp_tcp_handshake_events
                .with_label_values(&["0", event])
                .inc_by(0.0);
            dp_tcp_handshake_events_by_target
                .with_label_values(&["0", event, "0.0.0.0"])
                .inc_by(0.0);
        }
        dp_tcp_handshake_final_ack_in
            .with_label_values(&["0", "default"])
            .inc_by(0.0);
        dp_tcp_handshake_final_ack_in_by_target
            .with_label_values(&["0", "default", "0.0.0.0"])
            .inc_by(0.0);
        for reason in [
            "tcp_rst",
            "tcp_fin",
            "idle_timeout",
            "policy_drop",
            "policy_deny",
        ] {
            dp_tcp_handshake_synack_out_without_followup_ack
                .with_label_values(&["0", "default", reason])
                .inc_by(0.0);
            dp_tcp_handshake_synack_out_without_followup_ack_by_target
                .with_label_values(&["0", "default", "0.0.0.0", reason])
                .inc_by(0.0);
        }
        for (phase, reason) in [
            ("syn", "parse"),
            ("syn", "policy_deny"),
            ("syn", "nat_alloc_failed"),
            ("synack", "nat_miss"),
            ("ack", "rewrite_failed"),
        ] {
            dp_tcp_handshake_drops
                .with_label_values(&["0", phase, reason])
                .inc_by(0.0);
        }
        for reason in ["tcp_rst", "tcp_fin", "idle_timeout"] {
            for phase in ["unknown", "syn_only", "synack_seen", "completed"] {
                let _ = dp_tcp_handshake_close_age_seconds.with_label_values(&["0", reason, phase]);
            }
        }
        let _ = dp_handshake_stage_seconds.with_label_values(&["0", "outbound", "flow_probe"]);
        let _ = dp_table_probe_steps.with_label_values(&["0", "flow", "lookup", "miss"]);
        let _ = dp_nat_port_scan_steps.with_label_values(&["0", "allocated"]);
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

        Ok(Self(Arc::new(MetricsInner {
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
            svc_tls_intercept_errors,
            svc_tls_intercept_phase,
            svc_tls_intercept_inflight,
            svc_tls_intercept_upstream_h2_pool,
            svc_tls_intercept_upstream_h2_shard_select,
            svc_tls_intercept_upstream_h2_send_wait,
            svc_tls_intercept_upstream_h2_selected_inflight,
            svc_tls_intercept_upstream_h2_pool_width,
            svc_tls_intercept_upstream_h2_ready_errors,
            svc_tls_intercept_upstream_response_errors,
            svc_tls_intercept_upstream_h2_conn_closed,
            svc_tls_intercept_upstream_h2_conn_termination,
            svc_tls_intercept_upstream_h2_retry,
            svc_tls_intercept_upstream_h2_selected_inflight_peak,
            threat_matches,
            threat_alertable_matches,
            threat_feed_refresh,
            threat_feed_snapshot_age_seconds,
            threat_feed_indicators,
            threat_backfill_runs,
            threat_backfill_duration_seconds,
            threat_enrichment_requests,
            threat_enrichment_queue_depth,
            threat_observation_enqueue_failures,
            threat_findings_active,
            threat_cluster_snapshot_version,
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
            dp_flow_opens_tcp_default,
            dp_flow_opens_udp_default,
            dp_flow_closes,
            dp_flow_lifecycle_events,
            dp_active_flows,
            dp_active_flows_shard,
            dp_active_flows_source_group,
            dp_active_flows_source_group_default,
            dp_flow_lifetime_seconds,
            dp_active_nat_entries,
            dp_active_nat_entries_shard,
            dp_nat_port_utilization_ratio,
            dp_flow_table_utilization_ratio,
            dp_flow_table_utilization_ratio_shard,
            dp_flow_table_capacity,
            dp_flow_table_tombstones,
            dp_flow_table_used_slots_ratio,
            dp_flow_table_tombstone_ratio,
            dp_flow_table_resize_events,
            dp_syn_only_active_flows,
            dp_syn_only_lookup,
            dp_syn_only_promotions,
            dp_syn_only_evictions,
            dp_nat_table_utilization_ratio,
            dp_nat_table_utilization_ratio_shard,
            dp_state_lock_wait_seconds,
            dp_state_lock_contended,
            dp_state_lock_wait_seconds_worker,
            dp_state_lock_wait_seconds_shard,
            dp_state_lock_hold_seconds_worker,
            dp_state_lock_hold_seconds_shard,
            dp_state_lock_contended_worker,
            dp_state_lock_contended_shard,
            dpdk_shared_io_lock_wait_seconds,
            dpdk_shared_io_lock_contended,
            dpdk_shared_io_lock_wait_seconds_worker,
            dpdk_shared_io_lock_hold_seconds_worker,
            dpdk_shared_io_lock_contended_worker,
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
            dpdk_tx_packet_class_by_queue,
            dpdk_tx_stage_packets,
            dpdk_tx_stage_bytes,
            dpdk_tx_stage_packet_class,
            dpdk_flow_steer_dispatch_packets,
            dpdk_flow_steer_dispatch_bytes,
            dpdk_flow_steer_fail_open_events,
            dpdk_flow_steer_queue_wait_seconds,
            dpdk_flow_steer_queue_depth,
            dpdk_flow_steer_queue_utilization_ratio,
            dpdk_service_lane_forward_packets,
            dpdk_service_lane_forward_bytes,
            dpdk_service_lane_forward_queue_wait_seconds,
            dpdk_service_lane_forward_queue_depth,
            dpdk_service_lane_forward_queue_utilization_ratio,
            dpdk_intercept_demux_size,
            dpdk_host_frame_queue_depth,
            dpdk_pending_arp_queue_depth,
            dpdk_intercept_demux_insert_dropped,
            dpdk_host_frame_dropped,
            dpdk_pending_arp_frame_dropped,
            dp_tcp_handshake_events,
            dp_tcp_handshake_events_by_target,
            dp_tcp_handshake_final_ack_in,
            dp_tcp_handshake_final_ack_in_by_target,
            dp_tcp_handshake_synack_out_without_followup_ack,
            dp_tcp_handshake_synack_out_without_followup_ack_by_target,
            dp_tcp_handshake_drops,
            dp_tcp_handshake_close_age_seconds,
            dp_handshake_stage_seconds,
            dp_table_probe_steps,
            dp_nat_port_scan_steps,
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
            dp_active_nat_counts: Arc::new(Mutex::new(HashMap::new())),
        })))
    }
}
