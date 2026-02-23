use std::time::Duration;

use prometheus::{
    Counter, CounterVec, Encoder, Gauge, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
    TextEncoder,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
    pub dataplane: DataplaneStats,
    pub dns: DnsStats,
    pub tls: TlsStats,
    pub dhcp: DhcpStats,
    pub cluster: ClusterStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct DataplaneStats {
    pub active_flows: u64,
    pub active_nat_entries: u64,
    pub nat_port_utilization: f64,
    pub packets: DecisionCounters,
    pub bytes: DecisionCounters,
    pub flows_opened: u64,
    pub flows_closed: u64,
    pub ipv4_fragments_dropped: u64,
    pub ipv4_ttl_exceeded: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionCounters {
    pub allow: u64,
    pub deny: u64,
    pub pending_tls: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsStats {
    pub queries_allow: u64,
    pub queries_deny: u64,
    pub nxdomain_policy: u64,
    pub nxdomain_upstream: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TlsStats {
    pub allow: u64,
    pub deny: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DhcpStats {
    pub lease_active: bool,
    pub lease_expiry_epoch: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClusterStats {
    pub is_leader: bool,
    pub current_term: u64,
    pub last_log_index: u64,
    pub last_applied: u64,
}

#[derive(Clone, Debug)]
pub struct Metrics {
    registry: Registry,
    http_requests: CounterVec,
    http_duration: HistogramVec,
    http_auth: CounterVec,
    dns_queries: CounterVec,
    dns_upstream_rtt: HistogramVec,
    dns_nxdomain: CounterVec,
    dns_upstream_mismatch: CounterVec,
    raft_is_leader: Gauge,
    raft_leader_changes: Counter,
    raft_current_term: Gauge,
    raft_last_log_index: Gauge,
    raft_last_applied: Gauge,
    raft_peer_rtt: HistogramVec,
    raft_peer_errors: CounterVec,
    rocksdb_estimated_num_keys: Gauge,
    rocksdb_live_sst_files_size_bytes: Gauge,
    rocksdb_total_sst_files_size_bytes: Gauge,
    rocksdb_memtable_bytes: Gauge,
    rocksdb_num_running_compactions: Gauge,
    rocksdb_num_immutable_memtables: Gauge,
    dp_packets: CounterVec,
    dp_bytes: CounterVec,
    dp_flow_opens: CounterVec,
    dp_flow_closes: CounterVec,
    dp_active_flows: Gauge,
    dp_active_nat_entries: Gauge,
    dp_nat_port_utilization_ratio: Gauge,
    dp_tls_decisions: CounterVec,
    dp_icmp_decisions: CounterVec,
    dp_ipv4_fragments_dropped: Counter,
    dp_ipv4_ttl_exceeded: Counter,
    dp_arp_handled: Counter,
    dpdk_init_ok: Gauge,
    dpdk_init_failures: Counter,
    dhcp_lease_active: Gauge,
    dhcp_lease_expiry_epoch: Gauge,
    dhcp_lease_changes: Counter,
    integration_route_changes: Counter,
    integration_assignment_changes: Counter,
    integration_termination_events: Counter,
    integration_termination_complete: Counter,
    integration_protection_errors: Counter,
    integration_termination_poll_errors: Counter,
    integration_termination_publish_errors: Counter,
    integration_termination_complete_errors: Counter,
    integration_drain_duration: HistogramVec,
    integration_termination_drain_start: Histogram,
}

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
        let raft_is_leader =
            Gauge::with_opts(Opts::new("raft_is_leader", "Raft leader status"))
                .map_err(|err| err.to_string())?;
        let raft_leader_changes = Counter::with_opts(Opts::new(
            "raft_leader_changes_total",
            "Raft leader changes",
        ))
        .map_err(|err| err.to_string())?;
        let raft_current_term = Gauge::with_opts(Opts::new("raft_current_term", "Raft term"))
            .map_err(|err| err.to_string())?;
        let raft_last_log_index = Gauge::with_opts(Opts::new(
            "raft_last_log_index",
            "Raft last log index",
        ))
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
        let dp_active_nat_entries = Gauge::with_opts(Opts::new(
            "dp_active_nat_entries",
            "Dataplane active NAT entries",
        ))
        .map_err(|err| err.to_string())?;
        let dp_nat_port_utilization_ratio = Gauge::with_opts(Opts::new(
            "dp_nat_port_utilization_ratio",
            "Dataplane NAT port utilization ratio",
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
        let dpdk_init_ok =
            Gauge::with_opts(Opts::new("dpdk_init_ok", "DPDK init success (0/1)"))
                .map_err(|err| err.to_string())?;
        let dpdk_init_failures = Counter::with_opts(Opts::new(
            "dpdk_init_failures_total",
            "DPDK init failures",
        ))
        .map_err(|err| err.to_string())?;
        let dhcp_lease_active =
            Gauge::with_opts(Opts::new("dhcp_lease_active", "DHCP lease active (0/1)"))
                .map_err(|err| err.to_string())?;
        let dhcp_lease_expiry_epoch =
            Gauge::with_opts(Opts::new("dhcp_lease_expiry_epoch", "DHCP lease expiry epoch"))
                .map_err(|err| err.to_string())?;
        let dhcp_lease_changes = Counter::with_opts(Opts::new(
            "dhcp_lease_changes_total",
            "DHCP lease changes",
        ))
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
        let integration_termination_drain_start = Histogram::with_opts(
            HistogramOpts::new(
                "integration_termination_drain_start_seconds",
                "Time from termination notice to drain start seconds",
            )
        )
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
            .register(Box::new(dp_active_nat_entries.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dp_nat_port_utilization_ratio.clone()))
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
            .register(Box::new(dpdk_init_ok.clone()))
            .map_err(|err| err.to_string())?;
        registry
            .register(Box::new(dpdk_init_failures.clone()))
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
        dp_tls_decisions
            .with_label_values(&["pending"])
            .inc_by(0.0);
        dp_icmp_decisions
            .with_label_values(&["outbound", "0", "0", "deny", "default"])
            .inc_by(0.0);
        dp_ipv4_fragments_dropped.inc_by(0.0);
        dp_ipv4_ttl_exceeded.inc_by(0.0);
        dp_arp_handled.inc_by(0.0);

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
        dp_active_nat_entries.set(0.0);
        dp_nat_port_utilization_ratio.set(0.0);
        dpdk_init_ok.set(0.0);
        dpdk_init_failures.inc_by(0.0);
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
            dns_queries,
            dns_upstream_rtt,
            dns_nxdomain,
            dns_upstream_mismatch,
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
            dp_flow_opens,
            dp_flow_closes,
            dp_active_flows,
            dp_active_nat_entries,
            dp_nat_port_utilization_ratio,
            dp_tls_decisions,
            dp_icmp_decisions,
            dp_ipv4_fragments_dropped,
            dp_ipv4_ttl_exceeded,
            dp_arp_handled,
            dpdk_init_ok,
            dpdk_init_failures,
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
        })
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
        self.http_auth
            .with_label_values(&[outcome, reason])
            .inc();
    }

    pub fn observe_dns_query(&self, result: &str, reason: &str, source_group: &str) {
        self.dns_queries
            .with_label_values(&[result, reason, source_group])
            .inc();
    }

    pub fn observe_dns_upstream_rtt(&self, source_group: &str, duration: Duration) {
        self.dns_upstream_rtt
            .with_label_values(&[source_group])
            .observe(duration.as_secs_f64());
    }

    pub fn observe_dns_nxdomain(&self, source: &str) {
        self.dns_nxdomain.with_label_values(&[source]).inc();
    }

    pub fn observe_dns_upstream_mismatch(&self, reason: &str, source_group: &str) {
        self.dns_upstream_mismatch
            .with_label_values(&[reason, source_group])
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
        self.raft_last_log_index
            .set(index.unwrap_or(0) as f64);
    }

    pub fn set_raft_last_applied(&self, index: Option<u64>) {
        self.raft_last_applied
            .set(index.unwrap_or(0) as f64);
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
        self.rocksdb_live_sst_files_size_bytes
            .set(value as f64);
    }

    pub fn set_rocksdb_total_sst_files_size_bytes(&self, value: u64) {
        self.rocksdb_total_sst_files_size_bytes
            .set(value as f64);
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
    }

    pub fn inc_dp_flow_close(&self, reason: &str, count: u64) {
        self.dp_flow_closes
            .with_label_values(&[reason])
            .inc_by(count as f64);
    }

    pub fn set_dp_active_flows(&self, count: usize) {
        self.dp_active_flows.set(count as f64);
    }

    pub fn set_dp_active_nat_entries(&self, count: usize) {
        self.dp_active_nat_entries.set(count as f64);
    }

    pub fn set_dp_nat_port_utilization_ratio(&self, ratio: f64) {
        self.dp_nat_port_utilization_ratio.set(ratio);
    }

    pub fn inc_dp_tls_decision(&self, outcome: &str) {
        self.dp_tls_decisions
            .with_label_values(&[outcome])
            .inc();
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

    pub fn set_dpdk_init_ok(&self, ok: bool) {
        self.dpdk_init_ok.set(if ok { 1.0 } else { 0.0 });
    }

    pub fn inc_dpdk_init_failure(&self) {
        self.dpdk_init_failures.inc();
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

    pub fn snapshot(&self) -> StatsSnapshot {
        let families = self.registry.gather();
        let packets_allow = sum_metric(&families, "dp_packets_total", &[("decision", "allow")]);
        let packets_deny = sum_metric(&families, "dp_packets_total", &[("decision", "deny")]);
        let packets_pending =
            sum_metric(&families, "dp_packets_total", &[("decision", "pending_tls")]);
        let bytes_allow = sum_metric(&families, "dp_bytes_total", &[("decision", "allow")]);
        let bytes_deny = sum_metric(&families, "dp_bytes_total", &[("decision", "deny")]);
        let bytes_pending = sum_metric(&families, "dp_bytes_total", &[("decision", "pending_tls")]);
        let flows_opened = sum_metric(&families, "dp_flow_opens_total", &[]);
        let flows_closed = sum_metric(&families, "dp_flow_closes_total", &[]);

        let queries_allow = sum_metric(&families, "dns_queries_total", &[("result", "allow")]);
        let queries_deny = sum_metric(&families, "dns_queries_total", &[("result", "deny")]);
        let nxdomain_policy = sum_metric(&families, "dns_nxdomain_total", &[("source", "policy")]);
        let nxdomain_upstream =
            sum_metric(&families, "dns_nxdomain_total", &[("source", "upstream")]);

        let tls_allow = sum_metric(&families, "dp_tls_decisions_total", &[("outcome", "allow")]);
        let tls_deny = sum_metric(&families, "dp_tls_decisions_total", &[("outcome", "deny")]);

        let active_flows = gauge_metric(&families, "dp_active_flows");
        let active_nat_entries = gauge_metric(&families, "dp_active_nat_entries");
        let nat_port_utilization = gauge_metric_f64(&families, "dp_nat_port_utilization_ratio");
        let ipv4_fragments_dropped = sum_metric(&families, "dp_ipv4_fragments_dropped_total", &[]);
        let ipv4_ttl_exceeded = sum_metric(&families, "dp_ipv4_ttl_exceeded_total", &[]);

        let lease_active = gauge_metric(&families, "dhcp_lease_active") > 0;
        let lease_expiry_epoch = gauge_metric(&families, "dhcp_lease_expiry_epoch");

        let raft_is_leader = gauge_metric(&families, "raft_is_leader") > 0;
        let raft_current_term = gauge_metric(&families, "raft_current_term");
        let raft_last_log_index = gauge_metric(&families, "raft_last_log_index");
        let raft_last_applied = gauge_metric(&families, "raft_last_applied");

        StatsSnapshot {
            dataplane: DataplaneStats {
                active_flows,
                active_nat_entries,
                nat_port_utilization,
                packets: DecisionCounters {
                    allow: packets_allow,
                    deny: packets_deny,
                    pending_tls: packets_pending,
                },
                bytes: DecisionCounters {
                    allow: bytes_allow,
                    deny: bytes_deny,
                    pending_tls: bytes_pending,
                },
                flows_opened,
                flows_closed,
                ipv4_fragments_dropped,
                ipv4_ttl_exceeded,
            },
            dns: DnsStats {
                queries_allow,
                queries_deny,
                nxdomain_policy,
                nxdomain_upstream,
            },
            tls: TlsStats {
                allow: tls_allow,
                deny: tls_deny,
            },
            dhcp: DhcpStats {
                lease_active,
                lease_expiry_epoch,
            },
            cluster: ClusterStats {
                is_leader: raft_is_leader,
                current_term: raft_current_term,
                last_log_index: raft_last_log_index,
                last_applied: raft_last_applied,
            },
        }
    }

    pub fn render(&self) -> Result<String, String> {
        let encoder = TextEncoder::new();
        let metrics = self.registry.gather();
        let mut buf = Vec::new();
        encoder
            .encode(&metrics, &mut buf)
            .map_err(|err| err.to_string())?;
        String::from_utf8(buf).map_err(|err| err.to_string())
    }
}

fn sum_metric(
    families: &[prometheus::proto::MetricFamily],
    name: &str,
    labels: &[(&str, &str)],
) -> u64 {
    let mut total = 0.0f64;
    for family in families {
        if family.get_name() != name {
            continue;
        }
        for metric in family.get_metric() {
            if !labels_match(metric, labels) {
                continue;
            }
            total += metric_value(metric);
        }
    }
    total.round().max(0.0) as u64
}

fn gauge_metric(families: &[prometheus::proto::MetricFamily], name: &str) -> u64 {
    gauge_metric_f64(families, name).round().max(0.0) as u64
}

fn gauge_metric_f64(families: &[prometheus::proto::MetricFamily], name: &str) -> f64 {
    for family in families {
        if family.get_name() != name {
            continue;
        }
        if let Some(metric) = family.get_metric().first() {
            return metric_value(metric);
        }
    }
    0.0
}

fn labels_match(metric: &prometheus::proto::Metric, labels: &[(&str, &str)]) -> bool {
    if labels.is_empty() {
        return true;
    }
    let metric_labels = metric.get_label();
    labels.iter().all(|(name, value)| {
        metric_labels
            .iter()
            .any(|label| label.get_name() == *name && label.get_value() == *value)
    })
}

fn metric_value(metric: &prometheus::proto::Metric) -> f64 {
    if metric.has_counter() {
        metric.get_counter().get_value()
    } else if metric.has_gauge() {
        metric.get_gauge().get_value()
    } else if metric.has_histogram() {
        metric.get_histogram().get_sample_sum()
    } else {
        0.0
    }
}
