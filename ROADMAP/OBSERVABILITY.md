**Observability Plan**

**Goals**
Provide low-cardinality, actionable Prometheus metrics for Platform and Security Engineers covering DNS proxy, Raft, RocksDB, dataplane, and HTTP API/auth/TLS. Preserve existing `/metrics` behavior and keep the dataplane isolated from control-plane logic.

**Cardinality Policy**
- No per-IP, per-hostname, per-flow, per-rule labels.
- Source segmentation is by policy source group `id` only.
- Protocol label uses a fixed enum: `tcp`, `udp`, `icmp`, `other`.
- HTTP path labels are exact route templates only (already `request.uri().path()`), no query strings.
- Raft peer latency labels: `peer_id` and `rpc` only.
- All other labels are from fixed, small enums.

**Metric Schema (Proposed)**
HTTP API
- `http_requests_total{path,method,status}` (existing)
- `http_request_duration_seconds{path,method,status}` (existing)
- `http_auth_total{outcome,reason}` where `outcome` is `allow|deny`, `reason` in `valid_token|missing_token|invalid_scheme|invalid_token|keyset_error`

DNS Proxy
- `dns_queries_total{result,reason,source_group}` where `result` is `allow|deny`, `reason` in `policy_allow|policy_deny|parse_error|unsupported_src_ip|upstream_error`
- `dns_upstream_rtt_seconds{source_group}` histogram
- `dns_nxdomain_total{source}` where `source` is `policy|upstream`

Raft
- `raft_is_leader` gauge (0/1)
- `raft_leader_changes_total`
- `raft_current_term` gauge
- `raft_last_log_index` gauge
- `raft_last_applied` gauge
- `raft_peer_rtt_seconds{peer_id,rpc}` histogram
- `raft_peer_errors_total{peer_id,rpc,kind}` where `kind` is `transport|timeout|remote|other`

RocksDB (Cluster Store)
- `rocksdb_estimated_num_keys` gauge
- `rocksdb_live_sst_files_size_bytes` gauge
- `rocksdb_total_sst_files_size_bytes` gauge
- `rocksdb_memtable_bytes` gauge
- `rocksdb_num_running_compactions` gauge
- `rocksdb_num_immutable_memtables` gauge

Dataplane
- `dp_packets_total{direction,proto,decision,source_group}` where `direction` is `outbound|inbound`, `decision` is `allow|deny|pending_tls`
- `dp_bytes_total{direction,proto,decision,source_group}`
- `dp_flow_opens_total{proto,source_group}`
- `dp_flow_closes_total{reason}` where `reason` is `idle_timeout|explicit` (today only `idle_timeout`)
- `dp_active_flows` gauge
- `dp_active_nat_entries` gauge
- `dp_nat_port_utilization_ratio` gauge (active nat entries / NAT port range)
- `dp_tls_decisions_total{outcome}` where `outcome` is `allow|deny|pending|deny_after_data`

Notes
- Source group labels are derived from policy source group `id` at evaluation time. Use `source_group="default"` when no group matches.
- Throughput (MiB/s, PPS) should be computed in PromQL from counters.

**Implementation Plan**
1. Metrics foundation
- Extend `src/controlplane/metrics.rs` into a shared registry for control plane and dataplane.
- Add a `Metrics` API that exposes typed methods for each metric family and can be cloned across tasks/threads.
- Keep existing HTTP metrics intact to avoid breaking current tests.

2. Policy source group attribution
- Add a lightweight policy evaluation helper that returns `(decision, source_group_id)` without exposing rule IDs.
- Use `source_group_id` in dataplane and DNS metrics for per-source reporting.

3. HTTP API auth metrics
- Instrument `auth_middleware` in `src/controlplane/http_api.rs` to increment `http_auth_total` for allow/deny with bounded reasons.

4. DNS proxy metrics
- In `src/controlplane/dns_proxy.rs`, record:
  - allow/deny counters with reason
  - upstream RTT histogram (time from send to receive)
  - NXDOMAIN counters (policy vs upstream; parse upstream rcode in response header)
- Thread the shared `Metrics` into the DNS proxy task.

5. Raft metrics
- Add a background task that samples `openraft::RaftMetrics` and updates gauges for leader status, term, last log/applied.
- Track leader changes by caching previous leader id and incrementing `raft_leader_changes_total` on change.
- Instrument RPC client calls in `src/controlplane/cluster/rpc.rs` to emit `raft_peer_rtt_seconds` and `raft_peer_errors_total` with `peer_id` and `rpc` labels.

6. RocksDB metrics
- Add a periodic sampler in the control plane that reads RocksDB properties from `ClusterStore` and updates gauges.
- Keep sampling interval configurable or reuse an existing internal tick (e.g., 5s or 10s).

7. Dataplane metrics
- Add counters for packets/bytes and flow opens in `src/dataplane/engine.rs`.
- Add gauges for active flows and NAT entries (FlowTable len, NatTable len).
- Add NAT utilization ratio gauge using `PORT_MIN..=PORT_MAX` size and active NAT entries.
- Record TLS outcomes in `process_tls_packet` when decisions transition.
- Thread the shared `Metrics` into dataplane state (`EngineState`).

8. Tests and validation
- Extend e2e metrics tests to assert presence and monotonicity of new metric families.
- Add unit tests for DNS NXDOMAIN classification and auth failure metrics.
- Add a dataplane unit test that exercises allow/deny and asserts metric increments via `Metrics::render()`.

9. Documentation and dashboards
- Document metric names, labels, and cardinality rules in `README.md` or a dedicated `docs/observability.md`.
- Provide a minimal Prometheus/Alertmanager example and a sample Grafana dashboard JSON if needed.

**Open Questions**
- None remaining based on current requirements. Revisit if policy source group IDs or RPC types change.
