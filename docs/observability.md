# Observability

## Cardinality Policy
- No per-IP, per-hostname, per-flow, or per-rule labels.
- Source segmentation is by policy source group `id` only; use `source_group="default"` when no group matches.
- Protocol label uses a fixed enum: `tcp`, `udp`, `icmp`, `other`.
- HTTP path labels are exact route templates only, no query strings.
- Raft peer latency labels: `peer_id` and `rpc` only.
- All other labels are from fixed, small enums.

## Metric Families
### HTTP API
- `http_requests_total{path,method,status}`
- `http_request_duration_seconds{path,method,status}`
- `http_auth_total{outcome,reason}`
  - `outcome`: `allow|deny`
  - `reason`: `valid_token|missing_token|invalid_scheme|invalid_token|keyset_error`

### DNS Proxy
- `dns_queries_total{result,reason,source_group}`
  - `result`: `allow|deny`
  - `reason`: `policy_allow|policy_deny|parse_error|unsupported_src_ip|upstream_error`
- `dns_upstream_rtt_seconds{source_group}` (histogram)
- `dns_nxdomain_total{source}`
  - `source`: `policy|upstream`

### TLS Intercept Service Plane
- `svc_tls_intercept_flows_total{result}`
  - `result`: `allow|deny`
- `svc_http_requests_total{proto,decision}`
  - `proto`: `http1|h2`
  - `decision`: `allow|deny`
- `svc_http_denies_total{proto,phase,reason}`
  - `phase`: `request|response`
  - `reason`: `policy`
- `svc_policy_rst_total{reason}`
- `svc_fail_closed_total{component}`
- `svc_tls_intercept_errors_total{stage,reason}`
  - `reason`: `timeout|failure|closed|policy|oversize|invalid|no_policy`
- `svc_tls_intercept_phase_seconds{phase}` (histogram)
  - `phase`: `client_tls_accept|upstream_tcp_connect|upstream_tls_handshake|upstream_h2_handshake|http1_request_read|http1_response_read|h2_request_body_read`
- `svc_tls_intercept_inflight{kind}`
  - `kind`: `connections|h2_streams|upstream_h2_sessions`
- `svc_tls_intercept_upstream_h2_pool_total{result}`
  - `result`: `hit|miss|reconnect`

### TLS Intercept Perf Triage
- Start with `svc_tls_intercept_phase_seconds` and compare phase counts plus `p95/p99`.
- If `svc_tls_intercept_errors_total{stage="h2_request_body_read",reason="timeout"}` climbs before CPU saturates, the intercept runtime is stalling while buffering downstream bodies rather than losing time on upstream setup.
- If `svc_tls_intercept_errors_total{stage="client_tls_accept",reason="timeout"}` climbs alongside the body-read timeout series, later handshakes are queueing behind earlier stalled work.
- If `upstream_tcp_connect`, `upstream_tls_handshake`, or `upstream_h2_handshake` dominates, the bottleneck is upstream session setup rather than dataplane forwarding.
- If `svc_tls_intercept_upstream_h2_pool_total{result="miss"}` tracks request volume, reuse is ineffective; healthy keep-alive traffic should show substantial `hit` growth.
- If `svc_tls_intercept_upstream_h2_pool_total{result="reconnect"}` is non-trivial, reused upstream sessions are failing and the retry path is burning capacity.
- If `client_tls_accept` dominates, investigate leaf certificate mint/cache behavior and server-side TLS crypto.
- If `h2_request_body_read` or `http1_request_read` dominates, the service plane is spending time buffering/parsing bodies rather than on upstream setup.
- Use `svc_tls_intercept_inflight{kind}` to distinguish pressure shape:
  - `connections` rising with low `h2_streams` suggests handshake-heavy traffic.
  - `h2_streams` rising while `upstream_h2_sessions` also rises suggests pool misses or per-host churn.
  - `h2_streams` rising while `upstream_h2_sessions` stays relatively flat is the expected pooled-H2 shape.

### Raft
- `raft_is_leader` (gauge, 0/1)
- `raft_leader_changes_total`
- `raft_current_term` (gauge)
- `raft_last_log_index` (gauge)
- `raft_last_applied` (gauge)
- `raft_peer_rtt_seconds{peer_id,rpc}` (histogram)
- `raft_peer_errors_total{peer_id,rpc,kind}`
  - `kind`: `transport|timeout|remote|other`

### RocksDB (Cluster Store)
- `rocksdb_estimated_num_keys` (gauge)
- `rocksdb_live_sst_files_size_bytes` (gauge)
- `rocksdb_total_sst_files_size_bytes` (gauge)
- `rocksdb_memtable_bytes` (gauge)
- `rocksdb_num_running_compactions` (gauge)
- `rocksdb_num_immutable_memtables` (gauge)

### Dataplane
- `dp_packets_total{direction,proto,decision,source_group}`
- `dp_bytes_total{direction,proto,decision,source_group}`
- `dp_flow_opens_total{proto,source_group}`
- `dp_flow_closes_total{reason}`
  - `reason`: `idle_timeout|explicit` (today only `idle_timeout`)
- `dp_active_flows` (gauge)
- `dp_active_nat_entries` (gauge)
- `dp_nat_port_utilization_ratio` (gauge)
- `dp_tls_decisions_total{outcome}`
  - `outcome`: `allow|deny|pending|deny_after_data`
- `dp_icmp_decisions_total{direction,type,code,decision,source_group}`
  - `direction`: `inbound|outbound`
  - `decision`: `allow|deny|pending_tls`
- `dp_ipv4_fragments_dropped_total`
- `dp_ipv4_ttl_exceeded_total`
- `dp_arp_handled_total`

### DPDK Runtime (DPI Path)
- `dpdk_shared_io_lock_wait_seconds` (histogram)
- `dpdk_shared_io_lock_contended_total`
- `dpdk_flow_steer_dispatch_packets_total{from_worker,to_worker}`
- `dpdk_flow_steer_dispatch_bytes_total{from_worker,to_worker}`
- `dpdk_flow_steer_fail_open_events_total{worker,event}`
  - `event`: `tx_missing|owner_missing|dispatch_failed|rx_disconnected`
- `dpdk_flow_steer_queue_wait_seconds{to_worker}` (histogram)
- `dpdk_flow_steer_queue_depth{to_worker}`
- `dpdk_service_lane_forward_packets_total{from_worker}`
- `dpdk_service_lane_forward_bytes_total{from_worker}`
- `dpdk_service_lane_forward_queue_wait_seconds{from_worker}` (histogram)
- `dpdk_service_lane_forward_queue_depth`

### DPDK Perf Triage
- If `dpdk_shared_io_lock_contended_total` and `dpdk_shared_io_lock_wait_seconds` climb rapidly, shared-IO lock contention is likely capping throughput.
- If `dpdk_service_lane_forward_packets_total` is high while `dpdk_flow_steer_dispatch_packets_total` is low, traffic is spending more time in service-lane forwarding than shared-demux dispatch.
- If `dpdk_flow_steer_fail_open_events_total` is non-zero, demux forwarding degraded and workers are falling back to local processing.
- Sustained `dpdk_flow_steer_queue_depth` or `dpdk_service_lane_forward_queue_depth` above zero indicates persistent backpressure, not just transient bursts.

### DHCP
- `dhcp_lease_active` (gauge, 0/1)
- `dhcp_lease_expiry_epoch` (gauge)
- `dhcp_lease_changes_total`

## Prometheus Example
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "neuwerk"
    metrics_path: /metrics
    static_configs:
      - targets:
          - "127.0.0.1:8080"
```

## Alertmanager (Minimal)
```yaml
route:
  receiver: "default"

receivers:
  - name: "default"
```

## Notes
- Throughput (MiB/s, PPS) should be computed in PromQL from counters.
- A Grafana dashboard is available at `docs/grafana/neuwerk-operations-dashboard.json`.
- Import it via Grafana: Dashboards -> New -> Import -> Upload JSON file.
