# DPDK Scaling Roadmap (Behavior-Preserving)

## Current Context

- Integration pre-check completed before planning changes:
  - Command: `make test.integration`
  - Result: pass (`exit 0`)
  - Runtime: ~5m47s
- Measured throughput on `Standard_D2as_v5`:
  - `NEUWERK_DPDK_WORKERS=1`: ~6.95 Gbps
  - `NEUWERK_DPDK_WORKERS=2`: ~4.58 Gbps
- `lscpu -e` indicates both vCPUs are SMT siblings of one physical core on this SKU.
- Existing dataplane behavior includes queue-per-worker mode and single-queue shared-RX software demux fallback.

## Goals

1. Improve PMD scheduling determinism and scaling behavior.
2. Preserve all existing behavior and deployment defaults unless an operator explicitly opts in.
3. Provide a safe path to validate improvements on larger instances with true multi-core capacity.

## Non-Goals

- No immediate rewrite of dataplane policy/NAT logic.
- No default behavior change that could surprise existing deployments.
- No removal of control-plane features (DHCP, wiretap, audit, readiness, policy activation semantics).

## Guardrails (Must Not Break)

1. DPDK mode must continue to support DHCP-based dataplane config acquisition.
2. Existing CLI flags and environment variables must remain valid.
3. Existing default worker planning behavior must remain default unless a new explicit flag/env selects otherwise.
4. Policy activation and readiness behavior must remain unchanged.
5. `make test.integration` must stay green after each merged phase.
6. If a phase regresses throughput/stability, rollback must be one toggle (env/flag) or one revert.

## Phased Implementation Plan

### Phase 0 - Baseline and Instrumentation (No Behavior Change)

Purpose: capture reliable before/after evidence and make bottlenecks visible.

Planned changes:

1. Add/standardize startup logs for:
   - selected worker mode (`Single`, `QueuePerWorker`, `SharedRxDemux`)
   - effective queue count
   - worker count requested vs used
   - selected core IDs
2. Ensure benchmark artifacts are captured consistently:
   - iperf JSON output
   - `/metrics` snapshot before/after each run
   - firewall startup log
3. Keep behavior identical.

Files likely touched:

- `src/main.rs` (logging only)
- `ROADMAP/SCALING.md` (this document)

Exit criteria:

- No functional diffs.
- Integration tests pass.

### Phase 1 - PMD as Dedicated OS Thread (Keep Semantics)

Purpose: remove Tokio scheduler ownership of the dataplane execution thread while preserving lifecycle behavior.

Planned changes:

1. Replace dataplane launch via `tokio::task::spawn_blocking` with `std::thread::Builder::spawn`.
2. Preserve current orchestration semantics:
   - dataplane fatal errors still fail process
   - DNS/HTTP/control tasks remain managed as today
   - shutdown/error propagation remains equivalent
3. Keep worker internals unchanged for now.

Files likely touched:

- `src/main.rs` (dataplane launch/join orchestration)

Compatibility strategy:

- No flag needed; behavior should remain operationally equivalent.
- If there is unexpected lifecycle impact, keep a temporary internal fallback path during rollout.

Exit criteria:

- `make test.integration` passes.
- DPDK smoke/integration tests pass.
- No regressions in readiness or policy activation behavior.

### Phase 2 - Single-Queue Performance Mode (Opt-In)

Purpose: avoid known overhead of shared-RX software demux when only one effective RX queue exists.

Planned changes:

1. Introduce a new opt-in runtime toggle for single-queue strategy (name TBD):
   - default: existing behavior (`SharedRxDemux`)
   - opt-in: force `Single` worker when `effective_queues == 1`
2. Keep old behavior as default for backward compatibility.
3. Extend worker-plan unit tests for toggle-aware planning.

Files likely touched:

- `src/main.rs` (worker plan selection + tests)

Compatibility strategy:

- Existing deployments observe no behavior change by default.
- Operators can opt in only for throughput experiments.

Exit criteria:

- Unit tests for planning logic pass.
- `make test.integration` passes.
- On single-queue environments, opt-in mode shows equal or better throughput with stable retransmits.

### Phase 3 - Fast-Path Cross-Thread Interaction Audit (Selective, Optional)

Purpose: reduce hot-path contention/wakeup cost without removing required features.

Planned changes:

1. Inventory PMD hot-path cross-thread interactions:
   - DHCP message path
   - MAC publication path
   - wiretap/audit event path
   - shared-RX demux path
2. Prioritize replacements only where safe and measurable.
3. Prefer incremental bridge designs over full architectural rewrites:
   - preserve correctness first
   - keep drop behavior explicit and observable
4. Defer risky replacements (for example, unsafe shared-state patterns) unless backed by tests and strong measurable gain.

Files likely touched:

- `src/dataplane/dpdk_adapter.rs`
- `src/dataplane/wiretap.rs`
- `src/dataplane/audit.rs`
- `src/controlplane/dhcp.rs`
- `src/main.rs`

Compatibility strategy:

- Gate each optimization behind explicit toggles.
- Keep current path available until new path is validated in production-like tests.

Exit criteria:

- No feature regression (DHCP lease handling, audit/wiretap availability, readiness).
- Integration tests pass.
- Throughput/latency metrics improve or remain neutral in target scenarios.

### Phase 4 - Larger-Instance Validation (Scaling Proof)

Purpose: validate multi-core scaling where physical cores and multi-queue are available.

Target environments:

1. `Standard_D4as_v5` (or larger) as primary scaling validation.
2. Verify CPU topology (`lscpu -e`) and queue availability at runtime.

Benchmark matrix:

1. `workers=1`, default mode.
2. `workers=2`, queue-per-worker (if available).
3. `workers=2`, single-queue default behavior.
4. `workers=2`, single-queue forced-single opt-in mode (from Phase 2).

Per run capture:

1. iperf command + JSON output.
2. startup logs (mode/cores/queues).
3. `/metrics` snapshots including:
   - `dp_state_lock_contended_total`
   - `dp_state_lock_wait_seconds`
   - `dpdk_rx_dropped_total`
   - `dpdk_tx_dropped_total`
   - per-queue RX/TX counters

Acceptance criteria:

1. On real multi-core + multi-queue setups, `workers=2` outperforms `workers=1`.
2. Retransmits do not increase disproportionately.
3. No integration/regression test failures.

## Test and Release Gates

For every phase:

1. Run unit tests relevant to touched modules.
2. Run `make test.integration` before merge.
3. Run targeted DPDK integration/e2e tests where applicable.
4. Record benchmark deltas only after tests are green.

Rollout model:

1. Merge each phase independently.
2. Deploy canary with explicit toggles first.
3. Promote toggles to broader rollout only after validation window.

## Risk Register

1. Lifecycle regression when changing dataplane thread ownership.
   - Mitigation: preserve join/error semantics and readiness behavior.
2. Throughput regression from new toggles in unexpected topologies.
   - Mitigation: default remains unchanged; opt-in only.
3. Feature regression from channel/path replacements.
   - Mitigation: stage changes, keep fallback path, validate with integration tests.
4. Misleading benchmark conclusions from topology mismatch.
   - Mitigation: always capture `lscpu -e`, queue count, and worker mode in artifacts.

## Definition of Done

1. Dedicated PMD thread refactor is shipped with no functional regression.
2. Single-queue opt-in mode exists and is benchmark-validated.
3. Larger-instance test report shows scaling behavior and recommended production settings.
4. Existing behavior remains default unless operator opts into scaling modes.
