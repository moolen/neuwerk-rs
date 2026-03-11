# Alert Thresholds And Runbook Mapping

These thresholds are intentionally conservative defaults. Tune them after observing your own steady-state traffic and cluster size.

## Availability

- Alert: `/ready` returns non-`200` for more than 2 minutes.
  - Action: inspect the named readiness checks first, then follow the matching sections below.
- Alert: `/health` fails or the HTTPS API stops responding for more than 1 minute.
  - Action: treat as process or host failure; use the upgrade/rollback/DR runbook.

## DHCP / Bootstrap

- Alert: `dhcp_lease_active == 0` for 60 seconds.
  - Action: validate dataplane NIC wiring, DHCP reachability, and recent lease-flap events.
- Alert: `changes(dhcp_lease_expiry_epoch[10m]) > 3`
  - Action: investigate lease churn, packet loss, or upstream DHCP instability before it becomes a readiness flap.

## Cluster / Replication

- Alert: `increase(raft_peer_errors_total[5m]) > 0`
  - Action: check peer connectivity, TLS, and whether a node is mid-upgrade or partitioned.
- Alert: `raft_is_leader == 0` on every node for 1 minute.
  - Action: treat as quorum loss or partition; stop rollouts and restore cluster connectivity.
- Alert: `raft_last_log_index - raft_last_applied > 1000` for 5 minutes.
  - Action: check follower lag, disk pressure, and replication health before promoting or draining nodes.

## Dataplane Capacity / Correctness

- Alert: `dp_nat_port_utilization_ratio > 0.80` for 5 minutes.
  - Action: add capacity or reduce SNAT pressure before port exhaustion causes drops.
- Alert: `rate(dp_state_lock_contended_total[5m])` spikes above the baseline for the deployment.
  - Action: compare against recent throughput/worker changes and capacity-test before rollout continues.
- Alert: `increase(dp_ipv4_fragments_dropped_total[5m]) > 0`
  - Action: investigate upstream MTU/fragment sources; fragments are intentionally dropped.
- Alert: `increase(dp_ipv4_ttl_exceeded_total[5m]) > 0`
  - Action: verify routing loops or mis-steering.

## DNS / Service Plane / TLS Intercept

- Alert: `increase(dns_upstream_mismatch_total[5m]) > 0`
  - Action: inspect upstream DNS behavior and response validation failures.
- Alert: `increase(svc_fail_closed_total[5m]) > 0`
  - Action: treat as potentially user-visible deny behavior; inspect TLS intercept CA/runtime readiness and service-plane health.
- Alert: `increase(svc_http_denies_total[5m])` or `increase(svc_policy_rst_total[5m])` deviates sharply from baseline.
  - Action: verify whether a policy rollout or intercept change caused the increase.

## Auth / API

- Alert: `increase(http_auth_total{outcome="reject"}[5m])` is sharply above baseline.
  - Action: distinguish normal invalid-client noise from clock skew, key rotation, or auth-store failures.
- Alert: `increase(http_auth_sso_total{outcome="error"}[5m]) > 0`
  - Action: inspect SSO provider reachability, OIDC config, and token exchange failures.

## RocksDB / State Growth

- Alert: `rocksdb_total_sst_files_size_bytes` or `rocksdb_memtable_bytes` grows monotonically without returning toward baseline.
  - Action: inspect compaction health, disk pressure, and cluster write rate.
- Alert: `rocksdb_num_running_compactions > 0` continuously for 15 minutes with rising SST size.
  - Action: investigate disk saturation and compaction stalls before rolling further nodes.
