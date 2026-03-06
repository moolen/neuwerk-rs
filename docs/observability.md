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

### DHCP
- `dhcp_lease_active` (gauge, 0/1)
- `dhcp_lease_expiry_epoch` (gauge)
- `dhcp_lease_changes_total`

## Prometheus Example
```yaml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: "neuwerk-firewall"
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
- A Grafana dashboard is available at `docs/grafana/firewall-operations-dashboard.json`.
- Import it via Grafana: Dashboards -> New -> Import -> Upload JSON file.
