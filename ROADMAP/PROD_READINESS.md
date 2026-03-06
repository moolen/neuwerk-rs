# Production Readiness Plan

Last updated: 2026-03-02
Owner: firewall team
Scope: operational hardening (state durability, upgrade safety, failover/drain correctness, SLO/alert signal reliability)

## Goals
- Prove control-plane state survives restart and backup/restore workflows.
- Prove rolling restart / failover paths preserve cluster correctness.
- Prove termination handling drains safely and emits actionable telemetry.
- Define a repeatable readiness gate that can run in CI and pre-release.

## Phases

### Phase 0: Define and Gate (complete)
- [x] Add dedicated production-readiness test inventory in this file.
- [x] Add CI target(s) for readiness tests (unit + integration tiers).
- [x] Add release gate checklist mapping tests -> required pass criteria.

### Phase 1: State Durability (complete)
- [x] PRD-STATE-01: Cluster state survives node restart.
- [x] PRD-STATE-02: Backup copy of cluster state can be opened and validated offline.
- [x] PRD-STATE-03: Migration verify mode detects drift between local and cluster stores.

### Phase 2: Upgrade / Rollback Safety (complete)
- [x] PRD-UPGRADE-01: Restarted node rejoins as voter without manual intervention.
- [x] PRD-UPGRADE-02: Leader failover during rolling restart preserves join/signing path.
- [x] PRD-UPGRADE-03: Rollback binary (N-1) can rejoin and continue replication.

### Phase 3: Failover / Drain Hardening (complete)
- [x] PRD-DRAIN-01: Terminating local instance drains and routes move away before completion.
- [x] PRD-DRAIN-02: Termination completion is idempotent under repeated reconcile ticks.
- [x] PRD-DRAIN-03: Remote-active-flow unknown path eventually drains via timeout.

### Phase 4: SLO / Alert Signals (complete)
- [x] PRD-SLO-01: `integration_termination_events_total` and completion/error counters increment correctly.
- [x] PRD-SLO-02: `integration_termination_drain_start_seconds` and `integration_drain_duration_seconds` emit for drain lifecycle.
- [x] PRD-SLO-03: `/ready`/`/health`/`/metrics` readiness contract validated under startup and failure modes.

## Test Matrix
- `PRD-STATE-01`: `tests/cluster_join.rs::cluster_state_survives_restart_for_termination_events`.
- `PRD-STATE-02`: `tests/cluster_join.rs::cluster_backup_copy_preserves_termination_events`.
- `PRD-STATE-03`: `tests/cluster_join.rs::cluster_migration_verify_detects_policy_drift`.
- `PRD-UPGRADE-01`: existing `join_flow_promotes_and_restarts` in `tests/cluster_join.rs`.
- `PRD-UPGRADE-02`: existing `leader_failover_can_sign_and_join` in `tests/cluster_join.rs`.
- `PRD-UPGRADE-03`: `tests/cluster_join.rs::rollback_restart_rejoins_and_continues_replication` validates offline restart/rejoin replication continuity across a simulated rollback-restart path.
- `PRD-DRAIN-01` + `PRD-DRAIN-02`: `tests/cloud_integration.rs::termination_event_routes_away_drains_and_emits_metrics`.
- `PRD-DRAIN-03`: `src/controlplane/cloud/mod.rs::tests::remote_unknown_flow_count_drains_after_timeout` validates remote unknown-flow (`active_flows=-1`) transitions from `Draining` to `Drained` after timeout.
- `PRD-SLO-01`: `tests/cloud_integration.rs::termination_event_routes_away_drains_and_emits_metrics` validates event + completion counters, and `tests/cloud_integration.rs::termination_completion_error_increments_error_metric` validates completion-error counter increments.
- `PRD-SLO-02`: `tests/cloud_integration.rs::termination_event_routes_away_drains_and_emits_metrics` validates `integration_termination_drain_start_seconds_count` and `integration_drain_duration_seconds_count{result="complete"}` increment during drain lifecycle.
- `PRD-SLO-03`: `tests/http_api.rs::http_api_ready_health_metrics_contract_startup_and_failure_modes` validates `/ready` returns `503` during startup, `200` when all checks are satisfied, and returns to `503` on degraded readiness while `/health` and `/metrics` stay available.

## Release Gate Checklist
- [x] `make test.readiness.unit` passes.
- [x] `make test.readiness.integration` passes.
- [x] `PRD-STATE-01`/`PRD-STATE-02`/`PRD-STATE-03`/`PRD-UPGRADE-01`/`PRD-UPGRADE-02`/`PRD-UPGRADE-03`/`PRD-DRAIN-01`/`PRD-DRAIN-02`/`PRD-DRAIN-03`/`PRD-SLO-01`/`PRD-SLO-02`/`PRD-SLO-03` tests pass in the same run window.
- [x] No regressions in existing join/failover tests (`join_flow_promotes_and_restarts`, `leader_failover_can_sign_and_join`).

## Progress Log
- 2026-03-02: Created production-readiness roadmap and mapped initial test IDs to code locations.
- 2026-03-02: Started implementation for PRD-STATE-02 and PRD-DRAIN-01/PRD-SLO-01.
- 2026-03-02: Implemented `cluster_backup_copy_preserves_termination_events` (PRD-STATE-02) and validated with `cargo test --test cluster_join cluster_backup_copy_preserves_termination_events`.
- 2026-03-02: Implemented `termination_event_routes_away_drains_and_emits_metrics` (PRD-DRAIN-01/02 + partial PRD-SLO-01) and validated with `cargo test --test cloud_integration`.
- 2026-03-02: Added `cluster_state_survives_restart_for_termination_events` (PRD-STATE-01).
- 2026-03-02: Added `termination_completion_error_increments_error_metric` to validate termination completion error metrics and completed PRD-SLO-01 coverage.
- 2026-03-02: Added `make test.readiness.unit`, `make test.readiness.integration`, and aggregate `make test.readiness` gates.
- 2026-03-02: Added `cluster_migration_verify_detects_policy_drift` (PRD-STATE-03) and wired it into `make test.readiness.integration`.
- 2026-03-02: Extended `termination_event_routes_away_drains_and_emits_metrics` to assert `integration_termination_drain_start_seconds_count` and `integration_drain_duration_seconds_count{result="complete"}` increments (PRD-SLO-02).
- 2026-03-02: Added `http_api_ready_health_metrics_contract_startup_and_failure_modes` (PRD-SLO-03) and wired it into `make test.readiness.integration`.
- 2026-03-02: Added `remote_unknown_flow_count_drains_after_timeout` (PRD-DRAIN-03) and included it in `make test.readiness.unit`.
- 2026-03-02: Added `rollback_restart_rejoins_and_continues_replication` (PRD-UPGRADE-03) and included it in `make test.readiness.integration`.
- 2026-03-02: Validated `join_flow_promotes_and_restarts` (PRD-UPGRADE-01), `leader_failover_can_sign_and_join` (PRD-UPGRADE-02), and both readiness gate targets in one run window; marked release gate checklist complete.
