# Threat Intel Full Spec Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the approved threat-intel spec by adding feed refresh/snapshot publication, real feed-status state, and snapshot-version backfill, then rebuild and redeploy the DPDK binary to the homelab.

**Architecture:** Keep the existing split between the node-local threat matcher/store and the cluster-replicated baseline snapshot. Add a control-plane threat-intel manager that owns refresh state, persists a last-good snapshot locally, optionally publishes that snapshot through raft, and triggers local backfill when the active snapshot version changes. Extend the HTTP API to read the persisted manager state instead of returning placeholders.

**Tech Stack:** Rust, Tokio, Axum, OpenRaft, serde/JSON, existing Neuwerk metrics and store abstractions, DPDK release build.

---

### Task 1: Persisted Feed State Contracts

**Files:**
- Create: `src/controlplane/threat_intel/manager.rs`
- Modify: `src/controlplane/threat_intel/mod.rs`
- Test: `src/controlplane/threat_intel/manager.rs`

- [ ] **Step 1: Write the failing tests**

Add unit tests that prove:
- a feed-state snapshot can be persisted and loaded from `local_data_root/threat-intel/`
- the manager computes per-feed age and indicator counts from the active snapshot
- a replicated snapshot payload can be decoded from cluster state

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test threat_feed_state --lib`
Expected: FAIL because the manager/state helpers do not exist yet.

- [ ] **Step 3: Write the minimal implementation**

Implement:
- threat-intel cluster keys for snapshot payload and feed-status state
- serializable persisted structs for feed refresh timestamps, outcome, counts, and active snapshot metadata
- local load/store helpers for the snapshot and feed-status payloads

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test threat_feed_state --lib`
Expected: PASS

### Task 2: Feed Manager Refresh And Publication

**Files:**
- Modify: `src/controlplane/threat_intel/manager.rs`
- Modify: `src/runtime/startup/controlplane_runtime.rs`
- Test: `src/controlplane/threat_intel/manager.rs`

- [ ] **Step 1: Write the failing tests**

Add unit tests that prove:
- a leader refresh with fixture payloads produces a merged normalized `ThreatSnapshot`
- successful refresh persists the local snapshot and feed-status metadata
- cluster mode publishes the snapshot and feed-status payload through `ClusterCommand::Put`
- refresh failure keeps the last good snapshot active and records a failed outcome

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test threat_refresh --lib`
Expected: FAIL because the refresh manager loop and publication behavior are missing.

- [ ] **Step 3: Write the minimal implementation**

Implement:
- a manager entry point that can run on an interval
- leader detection based on raft metrics
- refresh execution using the existing feed adapters
- merged snapshot versioning, last-good persistence, metrics updates, and optional raft publication
- startup wiring from `controlplane_runtime.rs`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test threat_refresh --lib`
Expected: PASS

### Task 3: Backfill On Snapshot Version Change

**Files:**
- Modify: `src/controlplane/threat_intel/runtime.rs`
- Modify: `src/controlplane/threat_intel/manager.rs`
- Modify: `src/runtime/startup/controlplane_runtime.rs`
- Test: `src/controlplane/threat_intel/runtime.rs`
- Test: `src/runtime/startup/controlplane_runtime.rs`

- [ ] **Step 1: Write the failing tests**

Add tests that prove:
- retained audit findings are rescanned when a newer snapshot version becomes active
- new findings created by that rescan use `match_source=backfill`
- backfill metrics are emitted and duplicate rescans for the same version are avoided

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test threat_backfill --lib`
Expected: FAIL because no backfill worker exists.

- [ ] **Step 3: Write the minimal implementation**

Implement:
- audit-finding to threat-observation derivation for historical rescans
- local backfill execution when the applied snapshot version changes
- persisted backfill progress/version bookkeeping sufficient to avoid repeated full rescans on steady state
- throttled iteration hooks using the existing local store query path

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test threat_backfill --lib`
Expected: PASS

### Task 4: Real Feed Status API

**Files:**
- Modify: `src/controlplane/http_api/threats.rs`
- Modify: `src/controlplane/http_api/openapi.rs`
- Test: `tests/http_api/cluster_threat_cases.rs`
- Create: `tests/http_api/cluster_threat_cases/feed_status_cases.rs`

- [ ] **Step 1: Write the failing tests**

Add HTTP API tests that prove:
- `GET /api/v1/threats/feeds/status` returns persisted snapshot version and timestamps
- each feed entry reports enabled state, outcome, age, and indicator counts
- local mode reads from local persisted state and cluster mode reads replicated state

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test http_api_threat_feed_status --test http_api`
Expected: FAIL because the endpoint still returns placeholder values.

- [ ] **Step 3: Write the minimal implementation**

Replace the placeholder response with real loading/parsing from the new manager state, then update OpenAPI types if the response schema expands.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test http_api_threat_feed_status --test http_api`
Expected: PASS

### Task 5: Full Verification, Build, And Homelab Rollout

**Files:**
- Modify: `ui/types.ts` or related UI files only if backend schema changes require it

- [ ] **Step 1: Run focused Rust verification**

Run:
- `cargo test threat_ --lib`
- `cargo test http_api_threat --test http_api`

Expected: PASS

- [ ] **Step 2: Run broader regression coverage**

Run:
- `cargo test --lib`
- `cd ui && npm test`
- `cd ui && npm run build`

Expected: PASS

- [ ] **Step 3: Build the deployable binary**

Run:
```bash
DPDK_DIR=/home/moritz/dev/neuwerk-rs/firewall/third_party/dpdk/install/23.11.2 \
PKG_CONFIG_PATH=/home/moritz/dev/neuwerk-rs/firewall/third_party/dpdk/install/23.11.2/lib/pkgconfig:/home/moritz/dev/neuwerk-rs/firewall/third_party/dpdk/install/23.11.2/lib/x86_64-linux-gnu/pkgconfig:/home/moritz/dev/neuwerk-rs/firewall/third_party/dpdk/install/23.11.2/lib64/pkgconfig \
cargo build --release --features dpdk --target-dir target-homelab-threatintel-master-ui23
```

Expected: PASS and produce `target-homelab-threatintel-master-ui23/release/firewall`

- [ ] **Step 4: Redeploy and verify**

Deploy in this order:
1. `ubuntu@192.168.178.83`
2. `ubuntu@192.168.178.84`
3. `ubuntu@192.168.178.76`

Install target: `/usr/local/bin/firewall`
Service: `firewall.service`

Verify on all three hosts:
- `systemctl is-active firewall.service`
- `sha256sum /usr/local/bin/firewall`
- `http://<host>:8080/metrics`

Verify on `192.168.178.76`:
- `https://192.168.178.76:8443/health`
- `https://192.168.178.76:8443/threats`
- live bundle contains the `Threats` sidebar entry
