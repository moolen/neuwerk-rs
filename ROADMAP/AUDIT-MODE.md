# Audit / Passthrough Mode Roadmap

## Goals
- Add top-level policy mode: `disabled | audit | enforce`.
- In `audit` mode, policy is active but policy-denied traffic is not dropped (passthrough).
- Capture only traffic that would be denied by policy evaluation.
- Keep rule-level mode (`audit | enforce`) and apply it during evaluation.
- Persist audit findings per node on disk with a bounded budget (default target: 100 MB/node).
- Add HTTP API to query node-local and cluster-aggregated audit findings.
- Return partial results when some nodes are unavailable.
- Add UI `Audit` page (separate from live `Wiretap` page) for persisted, deduplicated findings.

## Non-Goals
- Full packet capture.
- Payload storage.
- Control-plane DNS parsing in dataplane.
- Replacing live `wiretap` SSE (it remains as-is for live debugging).

## Current Status (as of 2026-02-27)
- Top-level policy mode now supports `disabled | audit | enforce`.
- `audit` mode is active for evaluation and runs as passthrough for would-be denied traffic.
- Rule-level mode remains `audit | enforce` and participates in dual evaluation paths.
- Persistent per-node audit storage exists under `/var/lib/neuwerk/audit-store` with size budget enforcement.
- HTTP API exposes local and cluster-aggregated audit findings with partial-result semantics.
- UI has a dedicated `Audit` page in the sidebar.

## Target Semantics

### Top-Level Policy Mode
- `disabled`:
  - Policy record is stored but never active in dataplane/control-plane policy decisions.
  - No policy-based deny/audit capture from that policy.
- `audit`:
  - Policy becomes active for evaluation.
  - Policy-denied decisions become `allow` for forwarding (passthrough).
  - Every would-be-denied decision emits an audit finding.
- `enforce`:
  - Existing behavior preserved: policy-denied traffic is dropped.
  - Policy-denied events still emit audit findings (useful for persistent analytics).

### Rule-Level Mode (kept)
- `enforce` rules affect enforce decision path.
- `audit` rules are evaluated for audit finding generation.
- Audit evaluation tracks whether denial came from:
  - enforce-only evaluation,
  - audit-rule evaluation,
  - default action / default policy.

### Denial Capture Scope
Capture only decisions that would be denied by policy evaluation:
- DNS query denials.
- L4 deny flows (`dst_ip`, `dst_port`, `proto`, plus FQDN from DNS map when available).
- TLS SNI for denied TLS-constrained flows when observed.
- ICMP deny events (`type`, `code`, `dst_ip`).

## Data Model

### Core Finding Types
- `dns_deny`:
  - `policy_id`, `source_group`, `hostname`, `query_type`, `first_seen`, `last_seen`, `count`, `node_id`.
- `l4_deny`:
  - `policy_id`, `source_group`, `dst_ip`, `dst_port`, `proto`, `fqdn?`, `first_seen`, `last_seen`, `count`, `node_id`.
- `tls_deny`:
  - `policy_id`, `source_group`, `dst_ip`, `dst_port`, `sni?`, `fqdn?`, `first_seen`, `last_seen`, `count`, `node_id`.
- `icmp_deny`:
  - `policy_id`, `source_group`, `dst_ip`, `icmp_type`, `icmp_code`, `first_seen`, `last_seen`, `count`, `node_id`.

### Dedup Keys (agreed)
- DNS: `source_group + hostname`.
- L4: `source_group + dst_ip + dst_port + proto + fqdn?`.
- TLS: `source_group + sni + dst_ip + dst_port`.
- ICMP: `source_group + dst_ip + type + code`.

### On-Disk Store
- New local store path: `/var/lib/neuwerk/audit-store`.
- File-segmented append-only records plus compaction into deduplicated counters.
- Enforce max disk budget (default 100 MB) via oldest-segment eviction + index compaction.
- Keep writes node-local only; no Raft replication of raw findings.

## API Design

### Local + Aggregated Query Endpoint
- `GET /api/v1/audit/findings`
- Query params (initial):
  - `policy_id` (optional)
  - `finding_type` (`dns_deny|l4_deny|tls_deny|icmp_deny`, repeatable)
  - `source_group` (repeatable)
  - `since` / `until` (unix secs)
  - `limit` (default bounded)
- Response:
  - `items`: deduplicated findings (cluster-merged).
  - `partial`: boolean.
  - `node_errors`: per-node failures/timeouts.
  - `nodes_queried`, `nodes_responded`.

### Cluster Aggregation Behavior
- Leader fans out to all nodes over the existing HTTPS API (`/api/v1/audit/findings/local`) using cluster membership.
- Merge + dedup on leader.
- If some nodes fail, return `200` with `partial=true` and `node_errors`.
- Follower proxies to leader (reuse existing leader-proxy model).

### Optional Local Debug Endpoint (internal)
- `GET /api/v1/audit/findings/local` for node-local reads only.

## Dataplane / Control-Plane Integration

### Dataplane
- Extend policy evaluation to produce:
  - `enforce_decision`
  - `audit_decision`
  - `source_group`
  - deny reason metadata (rule/default/tls).
- In `audit` top-level mode:
  - convert policy `deny` to forwarding `allow`.
  - still emit deny finding event.
- In `enforce` mode:
  - keep drop behavior.
  - emit deny finding event before drop.
- Add audit event channel from dataplane to control-plane bridge (parallel to wiretap).

### DNS Proxy
- On policy deny (`NXDOMAIN` path), emit `dns_deny` audit event with source group + hostname.
- Keep existing DNS allowlist behavior unchanged.

### Hostname / SNI Enrichment
- FQDN enrichment via existing `DnsMap` (`dst_ip -> hostname`) where available.
- TLS SNI from existing TLS observation state when present.

## UI Plan
- Add new sidebar entry: `Audit`.
- New `AuditPage` with tabs/filters:
  - DNS, L4, TLS, ICMP.
  - Source group, time range, protocol/type filters.
- Show deduplicated rows with `count`, `first_seen`, `last_seen`, and source nodes.
- Keep `Wiretap` page unchanged for live streaming.

## Phased Implementation Plan

### Phase 0: Contract + Types
- Add `PolicyMode::Disabled`.
- Update OpenAPI/JSON/TS/UI type schemas for `disabled|audit|enforce`.
- Define audit event protobuf/Rust structs and shared query/response models.
- Add migration compatibility for existing `audit|enforce` records.

### Phase 1: Policy Evaluation Split (Enforce vs Audit)
- Refactor policy compile/evaluation so rule-level `mode` participates in dual evaluation:
  - enforce view.
  - audit view.
- Ensure top-level `audit` is active and passthrough.
- Ensure top-level `disabled` is inactive.
- Update startup/replication logic to treat `audit` as active policy mode for evaluation.

### Phase 2: Event Emission Pipeline
- Add dataplane audit emitter for would-deny events (L4/TLS/ICMP).
- Add DNS deny emission from DNS proxy.
- Introduce control-plane audit hub/ingest worker (separate from wiretap hub).
- Attach policy_id and node_id to emitted findings.

### Phase 3: Persistent Store + Budget Enforcement
- Implement `/var/lib/neuwerk/audit-store` with:
  - append segments,
  - dedup index,
  - compaction,
  - strict budget (100 MB default).
- Add metrics:
  - events ingested/dropped,
  - disk usage bytes,
  - compaction/eviction counters.

### Phase 4: HTTP + Cluster Aggregation
- Add `GET /api/v1/audit/findings`.
- Add cluster RPC for local findings query.
- Implement leader fan-out merge with partial-result semantics.
- Reuse auth + leader proxy middleware patterns.

### Phase 5: UI Audit Page
- Add `Audit` sidebar route and page.
- Add query controls and grouped tables.
- Show partial-result warnings with node error details.

### Phase 6: Tests + Hardening
- Unit tests:
  - policy mode semantics (`disabled`, `audit`, `enforce`),
  - rule-level audit/evaluate behavior,
  - dedup key correctness,
  - disk budget eviction logic.
- Integration/e2e:
  - audit-mode passthrough does not drop would-deny traffic,
  - enforce-mode still drops,
  - DNS deny capture,
  - TLS SNI/ICMP deny capture,
  - cluster aggregation returns partial results when a node is down,
  - UI/API contract tests (shape + filtering).

## Execution Tracker (updated during implementation)
- Phase 0: Completed (policy/UI/API types updated for `disabled|audit|enforce`; shared audit query/response model added).
- Phase 1: Completed (top-level `audit` active passthrough, `disabled` inactive, dual evaluation path retained with rule-level mode support).
- Phase 2: Completed (dataplane deny audit emission for L4/TLS/ICMP + DNS deny emission from DNS proxy; policy/node attribution wired).
- Phase 3: Completed (node-local persistent `AuditStore` with deduped snapshots + disk budget enforcement/eviction).
- Phase 4: Completed (HTTP endpoints `/api/v1/audit/findings` and `/api/v1/audit/findings/local`; cluster fanout merge + partial results).
- Phase 5: Completed (UI `Audit` sidebar/page with filters, table, and partial/node error surfacing).
- Phase 6: Completed (HTTP API and audit unit tests passing; DNS audit passthrough decision-path unit tests added; disabled-mode activation/deactivation semantics hardened in local+cluster HTTP lifecycle tests; e2e expectations updated to current audit semantics; full integration/e2e suite run completed).

## Implemented Validation Snapshot
- `cargo check` passes.
- `cargo test --test http_api -- --nocapture` passes (includes local dedup and cluster partial audit endpoint tests).
- `cargo test controlplane::audit -- --nocapture` passes (audit merge/dedup focused unit tests).
- `cargo test evaluate_dns_policy_decision_ -- --nocapture` passes (enforce deny, audit passthrough, and audit-rule deny signaling coverage).
- `cargo test --test http_api http_api_local_lifecycle -- --nocapture` passes (local disable clears active policy state).
- `cargo test --test http_api http_api_cluster_proxy_lifecycle -- --nocapture` passes (cluster disable clears replicated active key and follower active state).
- `make test.integration` passes (full root-required integration/e2e harness).

## Risks and Mitigations
- Risk: high event volume may exceed budget quickly.
  - Mitigation: aggressive dedup + compaction, bounded ingestion queues, drop counters.
- Risk: policy dual-evaluation adds dataplane complexity.
  - Mitigation: keep evaluation deterministic, isolate helpers, add packet/integration tests.
- Risk: partial cluster visibility can confuse users.
  - Mitigation: explicit `partial` flag + per-node error list in API/UI.

## Rollout Strategy
- Keep feature behind policy mode transitions (no CLI flag required).
- Backward-compatible read of old policy records (`audit|enforce`).
- Default behavior unchanged for existing `enforce` policies.
