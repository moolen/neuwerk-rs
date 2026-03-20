# Azure VMSS Lifecycle Test Plan

## Scope
- Validate Azure VMSS rolling updates do not break sustained short-lived mixed traffic.
- Traffic model: concurrent short-lived flows (`dns_udp`, `dns_tcp`, `http`, `https`) plus delayed HTTP responses with ~5 second connection length.
- Success criteria: request failure rate across enabled traffic classes must stay at or below `0.01%` (`MAX_ERROR_RATE_PCT` override for tighter/looser runs).
- Drain window for test deployments: 30 seconds.
- Integration reconcile polling interval for Azure test stacks: 15 seconds (within the desired 10-60 second range to reduce ARM throttling risk).

## Clarified Requirements
- Stop creating default-route integration entries for management subnets.
- Trigger lifecycle via VMSS rolling update (not scale-out/delete workflow).
- Use delayed response traffic pattern.
- Fail test on any HTTP request error.
- Reduce integration drain timeout to 30 seconds.

## Design
1. Routing safety:
   - Exclude management subnets from Azure integration subnet discovery so default route management is dataplane-only.
2. Azure tag compatibility:
   - Accept slash/dot tag-key variants during discovery filtering so Azure resources tagged with dot keys still participate in integration selection.
3. Consumer-executed lifecycle traffic:
   - Add an executable consumer traffic script that continuously issues delayed HTTP requests and records failures.
4. Rollout orchestrator:
   - Add an Azure lifecycle script that:
     - Configures allow policy.
     - Pre-captures per-Neuwerk metrics.
     - Starts sustained mixed traffic on consumer.
     - Starts VMSS rollout using a Flexible-compatible rolling replacement: surge scale-out by +1, delete one old instance, wait for capacity/readiness to settle, repeat.
     - Waits for update completion and Neuwerk readiness.
     - Keeps post-rollout traffic running to cover drain timeout.
     - Captures post metrics and enforces zero traffic failures.

## Test Data + Metrics
- Traffic paths:
  - Consumer VM -> Neuwerk dataplane -> upstream VIP on UDP/TCP 53 (`upstream.test` lookup).
  - Consumer VM -> Neuwerk dataplane -> upstream VIP on TCP 80/443.
  - Consumer VM -> Neuwerk dataplane -> upstream private IP on TCP/9000 (`/delay/5` with server-side 5 second delay).
- Metrics snapshots (per Neuwerk instance):
  - `integration_termination_events_total`
  - `integration_termination_complete_total`
  - `integration_termination_poll_errors_total`
  - `integration_termination_publish_errors_total`
  - `integration_termination_complete_errors_total`
  - `integration_drain_duration_seconds_{sum,count}`
  - `integration_termination_drain_start_seconds_{sum,count}`
  - `dpdk_rx_bytes_total`, `dpdk_tx_bytes_total`, `dp_active_flows`
- Artifacts:
  - Store snapshots and consumer traffic log under `cloud-tests/azure/artifacts/lifecycle-<timestamp>/`.

## Execution Steps
1. Build Neuwerk binary with DPDK support.
2. Deploy Azure stack with Terraform apply (using updated cloud-init with 30s drain timeout).
3. Run lifecycle rollout test (`make lifecycle-rollout`).
4. Run termination drain-path test (`make lifecycle-termination-drain`).
   - Optional trigger override: `TRIGGER_ACTION=terminate` (default) or `TRIGGER_ACTION=reboot`.
5. Assert:
   - Consumer log reports `fail=0`.
   - Rolling update completed.
   - Neuwerk nodes remained ready.
   - Metrics snapshots were captured.
   - Termination drain-path test observed target-instance streamed max increases in `integration_termination_events_total` and `integration_termination_drain_start_seconds_count`.

## Risks and Mitigations
- VMSS rolling update duration variance:
  - Use timeout + polling on `latestModelApplied`.
- Azure Flexible VMSS does not allow `az vmss rolling-upgrade start` in this setup:
  - Use surge + replace (`az vmss scale` + `az vmss delete-instances`) to exercise termination notices and draining while preserving desired capacity.
- Upstream delayed endpoint conflicts:
  - Temporarily replace `longtcp` service with dedicated delayed HTTP service on port 9000 for the test, then restore.
- Instance IP churn during rollout:
  - Resolve Neuwerk management IPs dynamically before each metrics snapshot.
