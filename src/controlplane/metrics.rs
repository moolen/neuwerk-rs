use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prometheus::{
    Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts,
    Registry, TextEncoder,
};
use serde::Serialize;
use utoipa::ToSchema;

mod construct;
mod methods;

thread_local! {
    static CURRENT_DPDK_WORKER_ID: std::cell::Cell<Option<usize>> = const {
        std::cell::Cell::new(None)
    };
}

pub fn set_current_dpdk_worker_id(worker_id: Option<usize>) {
    CURRENT_DPDK_WORKER_ID.with(|cell| cell.set(worker_id));
}

pub fn current_dpdk_worker_id() -> Option<usize> {
    CURRENT_DPDK_WORKER_ID.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StatsSnapshot {
    pub dataplane: DataplaneStats,
    pub dns: DnsStats,
    pub tls: TlsStats,
    pub dhcp: DhcpStats,
    pub cluster: ClusterStats,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
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

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DecisionCounters {
    pub allow: u64,
    pub deny: u64,
    pub pending_tls: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DnsStats {
    pub queries_allow: u64,
    pub queries_deny: u64,
    pub nxdomain_policy: u64,
    pub nxdomain_upstream: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TlsStats {
    pub allow: u64,
    pub deny: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DhcpStats {
    pub lease_active: bool,
    pub lease_expiry_epoch: u64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClusterStats {
    pub is_leader: bool,
    pub current_term: u64,
    pub last_log_index: u64,
    pub last_applied: u64,
    pub node_count: u64,
    pub follower_count: u64,
    pub followers_caught_up: u64,
    pub nodes: Vec<ClusterNodeCatchup>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClusterNodeCatchup {
    pub node_id: String,
    pub addr: String,
    pub role: String,
    pub matched_index: Option<u64>,
    pub lag_entries: Option<u64>,
    pub caught_up: bool,
}

#[derive(Clone, Debug)]
pub struct Metrics(Arc<MetricsInner>);

#[derive(Debug)]
pub struct MetricsInner {
    registry: Registry,
    http_requests: CounterVec,
    http_duration: HistogramVec,
    http_auth: CounterVec,
    http_auth_sso: CounterVec,
    http_auth_sso_latency: HistogramVec,
    dns_queries: CounterVec,
    dns_upstream_rtt: HistogramVec,
    dns_nxdomain: CounterVec,
    dns_upstream_mismatch: CounterVec,
    svc_dns_queries: CounterVec,
    svc_dns_upstream_rtt: HistogramVec,
    svc_dns_nxdomain: CounterVec,
    svc_tls_intercept_flows: CounterVec,
    svc_http_requests: CounterVec,
    svc_http_denies: CounterVec,
    svc_policy_rst: CounterVec,
    svc_fail_closed: CounterVec,
    svc_tls_intercept_errors: CounterVec,
    svc_tls_intercept_phase: HistogramVec,
    svc_tls_intercept_inflight: GaugeVec,
    svc_tls_intercept_upstream_h2_pool: CounterVec,
    svc_tls_intercept_upstream_h2_shard_select: CounterVec,
    svc_tls_intercept_upstream_h2_send_wait: HistogramVec,
    svc_tls_intercept_upstream_h2_selected_inflight: Histogram,
    svc_tls_intercept_upstream_h2_pool_width: Histogram,
    svc_tls_intercept_upstream_h2_ready_errors: CounterVec,
    svc_tls_intercept_upstream_response_errors: CounterVec,
    svc_tls_intercept_upstream_h2_conn_closed: CounterVec,
    svc_tls_intercept_upstream_h2_conn_termination: CounterVec,
    svc_tls_intercept_upstream_h2_retry: CounterVec,
    svc_tls_intercept_upstream_h2_selected_inflight_peak: Gauge,
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
    dp_packets_outbound_tcp_allow_default: Counter,
    dp_bytes_outbound_tcp_allow_default: Counter,
    dp_packets_inbound_tcp_allow_default: Counter,
    dp_bytes_inbound_tcp_allow_default: Counter,
    dp_flow_opens: CounterVec,
    dp_flow_opens_tcp_default: Counter,
    dp_flow_opens_udp_default: Counter,
    dp_flow_closes: CounterVec,
    dp_flow_lifecycle_events: CounterVec,
    dp_active_flows: Gauge,
    dp_active_flows_shard: GaugeVec,
    dp_active_flows_source_group: GaugeVec,
    dp_active_flows_source_group_default: Gauge,
    dp_flow_lifetime_seconds: HistogramVec,
    dp_active_nat_entries: Gauge,
    dp_active_nat_entries_shard: GaugeVec,
    dp_nat_port_utilization_ratio: Gauge,
    dp_flow_table_utilization_ratio: Gauge,
    dp_flow_table_utilization_ratio_shard: GaugeVec,
    dp_flow_table_capacity: GaugeVec,
    dp_flow_table_tombstones: GaugeVec,
    dp_flow_table_used_slots_ratio: GaugeVec,
    dp_flow_table_tombstone_ratio: GaugeVec,
    dp_flow_table_resize_events: CounterVec,
    dp_syn_only_active_flows: GaugeVec,
    dp_syn_only_lookup: CounterVec,
    dp_syn_only_promotions: CounterVec,
    dp_syn_only_evictions: CounterVec,
    dp_nat_table_utilization_ratio: Gauge,
    dp_nat_table_utilization_ratio_shard: GaugeVec,
    dp_state_lock_wait_seconds: Histogram,
    dp_state_lock_contended: Counter,
    dp_state_lock_wait_seconds_worker: HistogramVec,
    dp_state_lock_wait_seconds_shard: HistogramVec,
    dp_state_lock_hold_seconds_worker: HistogramVec,
    dp_state_lock_hold_seconds_shard: HistogramVec,
    dp_state_lock_contended_worker: CounterVec,
    dp_state_lock_contended_shard: CounterVec,
    dpdk_shared_io_lock_wait_seconds: Histogram,
    dpdk_shared_io_lock_contended: Counter,
    dpdk_shared_io_lock_wait_seconds_worker: HistogramVec,
    dpdk_shared_io_lock_hold_seconds_worker: HistogramVec,
    dpdk_shared_io_lock_contended_worker: CounterVec,
    dp_tls_decisions: CounterVec,
    dp_icmp_decisions: CounterVec,
    dp_ipv4_fragments_dropped: Counter,
    dp_ipv4_ttl_exceeded: Counter,
    dp_arp_handled: Counter,
    overlay_decap_errors: Counter,
    overlay_encap_errors: Counter,
    overlay_packets: CounterVec,
    overlay_mtu_drops: Counter,
    dpdk_init_ok: Gauge,
    dpdk_init_failures: Counter,
    dpdk_rx_packets: Counter,
    dpdk_rx_bytes: Counter,
    dpdk_rx_dropped: Counter,
    dpdk_tx_packets: Counter,
    dpdk_tx_bytes: Counter,
    dpdk_tx_dropped: Counter,
    dpdk_rx_packets_by_queue: CounterVec,
    dpdk_rx_bytes_by_queue: CounterVec,
    dpdk_rx_dropped_by_queue: CounterVec,
    dpdk_tx_packets_by_queue: CounterVec,
    dpdk_tx_bytes_by_queue: CounterVec,
    dpdk_tx_dropped_by_queue: CounterVec,
    dpdk_tx_packet_class_by_queue: CounterVec,
    dpdk_tx_stage_packets: CounterVec,
    dpdk_tx_stage_bytes: CounterVec,
    dpdk_tx_stage_packet_class: CounterVec,
    dpdk_flow_steer_dispatch_packets: CounterVec,
    dpdk_flow_steer_dispatch_bytes: CounterVec,
    dpdk_flow_steer_fail_open_events: CounterVec,
    dpdk_flow_steer_queue_wait_seconds: HistogramVec,
    dpdk_flow_steer_queue_depth: GaugeVec,
    dpdk_flow_steer_queue_utilization_ratio: GaugeVec,
    dpdk_service_lane_forward_packets: CounterVec,
    dpdk_service_lane_forward_bytes: CounterVec,
    dpdk_service_lane_forward_queue_wait_seconds: HistogramVec,
    dpdk_service_lane_forward_queue_depth: Gauge,
    dpdk_service_lane_forward_queue_utilization_ratio: Gauge,
    dp_tcp_handshake_events: CounterVec,
    dp_tcp_handshake_events_by_target: CounterVec,
    dp_tcp_handshake_final_ack_in: CounterVec,
    dp_tcp_handshake_final_ack_in_by_target: CounterVec,
    dp_tcp_handshake_synack_out_without_followup_ack: CounterVec,
    dp_tcp_handshake_synack_out_without_followup_ack_by_target: CounterVec,
    dp_tcp_handshake_drops: CounterVec,
    dp_tcp_handshake_close_age_seconds: HistogramVec,
    dp_handshake_stage_seconds: HistogramVec,
    dp_table_probe_steps: HistogramVec,
    dp_nat_port_scan_steps: HistogramVec,
    dpdk_health_probe_packets: CounterVec,
    dpdk_xstats: GaugeVec,
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
    dp_active_flows_counts: Arc<Mutex<HashMap<usize, usize>>>,
    dp_active_nat_counts: Arc<Mutex<HashMap<usize, usize>>>,
}

impl Deref for Metrics {
    type Target = MetricsInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct DpdkFlowSteerMetricHandles {
    worker_count: usize,
    dispatch_packets: Vec<Counter>,
    dispatch_bytes: Vec<Counter>,
    fail_open_tx_missing: Vec<Counter>,
    fail_open_owner_missing: Vec<Counter>,
    queue_wait: Vec<Histogram>,
    queue_depth: Vec<Gauge>,
    queue_utilization_ratio: Vec<Gauge>,
}

#[derive(Clone, Debug)]
pub struct DataplaneShardMetricHandles {
    active_flows_shard: Gauge,
    active_nat_entries_shard: Gauge,
}

impl DataplaneShardMetricHandles {
    #[inline]
    pub fn inc_active_flows(&self) {
        self.active_flows_shard.inc();
    }

    #[inline]
    pub fn dec_active_flows(&self) {
        self.active_flows_shard.dec();
    }

    #[inline]
    pub fn add_active_nat_entries(&self, delta: i64) {
        if delta > 0 {
            self.active_nat_entries_shard.add(delta as f64);
        } else if delta < 0 {
            self.active_nat_entries_shard.sub((-delta) as f64);
        }
    }
}

impl DpdkFlowSteerMetricHandles {
    #[inline]
    fn worker_pair_index(&self, from_worker: usize, to_worker: usize) -> usize {
        debug_assert!(from_worker < self.worker_count);
        debug_assert!(to_worker < self.worker_count);
        from_worker * self.worker_count + to_worker
    }

    #[inline]
    pub fn observe_dispatch(
        &self,
        from_worker: usize,
        to_worker: usize,
        bytes: usize,
        wait: Duration,
    ) {
        let idx = self.worker_pair_index(from_worker, to_worker);
        self.dispatch_packets[idx].inc();
        self.dispatch_bytes[idx].inc_by(bytes as f64);
        self.queue_wait[to_worker].observe(wait.as_secs_f64());
    }

    #[inline]
    pub fn set_queue_depth(&self, to_worker: usize, depth: usize) {
        debug_assert!(to_worker < self.worker_count);
        self.queue_depth[to_worker].set(depth as f64);
        self.queue_utilization_ratio[to_worker].set((depth as f64) / 1024.0);
    }

    #[inline]
    pub fn inc_fail_open_tx_missing(&self, worker: usize) {
        debug_assert!(worker < self.worker_count);
        self.fail_open_tx_missing[worker].inc();
    }

    #[inline]
    pub fn inc_fail_open_owner_missing(&self, worker: usize) {
        debug_assert!(worker < self.worker_count);
        self.fail_open_owner_missing[worker].inc();
    }
}

impl Metrics {
    pub fn snapshot(&self) -> StatsSnapshot {
        let families = self.registry.gather();
        let packets_allow = sum_metric(&families, "dp_packets_total", &[("decision", "allow")]);
        let packets_deny = sum_metric(&families, "dp_packets_total", &[("decision", "deny")]);
        let packets_pending = sum_metric(
            &families,
            "dp_packets_total",
            &[("decision", "pending_tls")],
        );
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
                node_count: 1,
                follower_count: 0,
                followers_caught_up: 0,
                nodes: Vec::new(),
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
