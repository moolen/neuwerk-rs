# HTTP Webhook Performance Plan (Azure, DPDK)

Date: 2026-03-06  
Status: Proposed (manual workflow, non-CI)

## Confirmed Scope

- Traffic model: webhook-style `POST` requests with JSON payloads.
- Payload size: fixed `32 KiB`.
- SLO dimensions to track: max sustainable RPS tier, `p95/p99` latency, error/drop rate, Neuwerk CPU ceiling.
- Cloud: Azure, single region, use the currently configured bench (`Germany West Central` by default in current Terraform).
- Topology: existing Azure cloud-test topology (`consumer -> Neuwerk VMSS DPDK dataplane -> upstream`).
- Policy classes in v1:
  - L3/L4 policy behavior
  - TLS metadata policy (SNI matching only)
  - TLS intercept + HTTP DPI path matching
- TLS intercept behavior: fail-closed for constrained rules.
- Endpoint diversity: vary upstream IPs/ports (no need to model many domains).
- Run shape: `30s` ramp-up then steady state; complete full suite in about `15-20` minutes.
- Load strategy: fixed RPS tiers (not auto-search).
- Output format: JSON artifacts.
- Execution mode: manual first (no CI integration yet).

## SaaS Webhook Bench Model

- `consumer` VM(s): webhook sender workers (the SaaS platform).
- `neuwerk` VMSS: enforcement path under test (DPDK dataplane).
- `upstream` VM: customer endpoint service.
- Requests emulate high-volume event delivery to customer webhooks:
  - `Content-Type: application/json`
  - realistic webhook headers (`X-Webhook-Id`, `X-Tenant-Id`, `X-Event-Type`, `X-Signature`)
  - JSON body padded to `32 KiB`

## Proposed Test Matrix (v1)

### Policy Scenarios

1. `l34_allow_webhooks`
- L3/L4 allow rules for webhook destination ports; baseline throughput behavior.

2. `l34_mixed_allow_deny`
- L3/L4 rules allow subset of webhook ports and deny one destination port to capture deny-path behavior and drop/error counters.

3. `tls_sni_allow_only`
- TLS metadata rule with SNI exact match (`upstream.test`) and fail-closed behavior for non-matching SNI.

4. `tls_intercept_http_path`
- TLS intercept rule with HTTP path matcher:
  - allow: `/webhooks/allowed/*`
  - deny: `/webhooks/blocked/*`

### RPS Tiers (fixed)

- Default initial tiers: `500`, `1500`, `3000` RPS.
- Tier values are configurable via env/CLI (`RPS_TIERS=...`) so we can quickly retune after first baseline run.

### Runtime Budget

- Per scenario+tier run: `30s ramp + 45s steady + 10-15s settle/collect`.
- Total for `4 scenarios x 3 tiers`: approximately `18-20` minutes including policy push/verification overhead.

## Endpoint Layout for IP/Port Diversity

- Reuse existing reachable upstream addresses from Terraform outputs:
  - upstream LB VIP (`upstream_vip`)
  - upstream VM private IP (`upstream_private_ip`)
- Use multiple listener ports on upstream (for example `443`, `8443`, `9443`) to model customer endpoint spread.
- Keep SNI scenario traffic pinned to `upstream.test` so SNI enforcement is meaningful.

## Tooling Choice

- Use `k6` as the HTTP load generator (manual install/pinned version in scripts).
- Reason: fixed arrival-rate support, ramp profile support, HTTPS support, and JSON output (`--summary-export` and optional event output).
- Continue using existing Azure scripts for infra discovery, policy push, jumpbox SSH, and Neuwerk metrics collection.

## JSON Artifact Contract

Each run writes a timestamped artifact directory:

- `cloud-tests/azure/artifacts/http-perf-<timestamp>/`
  - `context.json` (region, vm sizes, instance counts, commit hash, scenario, tier config)
  - `load-summary.json` (k6 summary with throughput/latency/errors)
  - `Neuwerk-metrics-pre.prom` / `Neuwerk-metrics-post.prom`
  - `Neuwerk-metrics-delta.json` (selected counters)
  - `cpu-Neuwerk-*.json` (normalized CPU snapshots)
  - `result.json` (single normalized record per scenario+tier)
  - `matrix-summary.json` (aggregate across all scenarios/tiers)

`matrix-summary.json` will include:

- effective RPS
- `p50/p95/p99` latency
- success/error percentages
- Neuwerk CPU max/avg
- allow/deny/drop deltas from Neuwerk metrics
- highest tier reached per scenario

## Implementation Plan

### Phase 1: Bench Plumbing

Deliverables:

- Add Make targets in `cloud-tests/azure/Makefile`:
  - `http-perf.setup`
  - `http-perf.run`
  - `http-perf.quick`
- Add scripts:
  - `cloud-tests/azure/scripts/http-perf-setup.sh`
  - `cloud-tests/azure/scripts/http-perf-run.sh`
  - `cloud-tests/azure/scripts/http-perf-matrix.sh`
  - `cloud-tests/azure/scripts/http-perf-collect.sh`

Details:

- Resolve jumpbox/consumer/upstream/Neuwerk IPs from existing Terraform outputs and helper scripts.
- Verify readiness on all Neuwerk instances (`/ready`) before starting each scenario.
- Validate upstream listeners and TLS cert paths needed for tests.

### Phase 2: Upstream Webhook Endpoint Profile

Deliverables:

- Add upstream setup script:
  - `cloud-tests/azure/scripts/http-perf-upstream-configure.sh`

Details:

- Configure additional webhook listener ports on upstream.
- Expose deterministic paths used by policy tests:
  - `/webhooks/allowed/*`
  - `/webhooks/blocked/*`
- Ensure all listeners return deterministic JSON to simplify correctness/error parsing.

### Phase 3: Policy Fixtures for Perf Scenarios

Deliverables:

- New policy fixtures under:
  - `cloud-tests/azure/policies/http-perf/l34-allow.json`
  - `cloud-tests/azure/policies/http-perf/l34-mixed.json`
  - `cloud-tests/azure/policies/http-perf/tls-sni.json`
  - `cloud-tests/azure/policies/http-perf/tls-intercept-path.json`

Details:

- Reuse existing policy push flow (`configure-policy.sh`) for all scenarios.
- Add post-push consistency check across all Neuwerk mgmt endpoints before running load.

### Phase 4: Load Profiles and Matrix Runner

Deliverables:

- Add k6 script:
  - `cloud-tests/azure/http-perf/k6/webhook.js`

Details:

- Implement fixed-tier load execution with `30s` ramp then steady state.
- Generate `32 KiB` JSON payload bodies.
- Support weighted endpoint pools (IP/port mix) for webhook fanout.
- Support multi-consumer mode:
  - split configured RPS across `consumer_count` VMs
  - aggregate per-consumer summaries into one scenario result

### Phase 5: Metrics, Aggregation, and Reporting

Deliverables:

- Add result normalizer:
  - `cloud-tests/azure/scripts/http-perf-report.sh`
- Add docs:
  - `cloud-tests/azure/README.md` section for HTTP perf workflow

Details:

- Collect Neuwerk metrics before/after each run and derive deltas for:
  - policy allow/deny counters
  - DPDK RX/TX packet+byte counters
  - drop/reject/reset counters where available
- Collect CPU samples on Neuwerk instances during each run.
- Emit one JSON summary file per run and one aggregate matrix JSON.

## Success Criteria (v1)

- One command runs the full manual matrix and writes JSON artifacts.
- Full matrix completes in about `15-20` minutes on the current Azure bench.
- All requested dimensions are visible in JSON:
  - throughput by tier/scenario
  - `p95/p99` latency
  - error/drop behavior
  - Neuwerk CPU envelope
- TLS SNI scenario and TLS intercept-path scenario are both enforced and measurable under load.

## Risks and Mitigations

- Consumer saturation before Neuwerk saturation:
  - Mitigation: support `consumer_count > 1` and RPS split.
- Policy propagation race across VMSS instances:
  - Mitigation: verify policy consistency on all Neuwerk mgmt IPs before each run.
- TLS intercept CA not present:
  - Mitigation: seed/check CA via existing API flow before intercept scenarios.
- Artifact size growth:
  - Mitigation: keep event-level output optional; summary JSON always on.

## Deferred Items (Post-v1)

- Retry/backoff webhook behavior.
- Signature validation realism (HMAC verification on upstream app).
- Per-tenant/domain diversification.
- CI/nightly automation and budget guardrails.
