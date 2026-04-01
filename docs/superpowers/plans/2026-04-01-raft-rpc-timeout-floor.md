# Raft RPC Timeout Floor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent Raft peer RPCs from failing under tiny transport deadlines by enforcing a minimum timeout floor in the Raft gRPC transport layer.

**Architecture:** Keep the existing Raft heartbeat and election settings intact and patch only the transport layer. Add a small helper that derives an effective RPC timeout from `RPCOption`, clamps sub-floor values upward, and use it for `append_entries`, `vote`, and `install_snapshot`.

**Tech Stack:** Rust, OpenRaft, tonic gRPC, Tokio, cargo test

---

### Task 1: Add the regression test for the timeout floor helper

**Files:**
- Modify: `src/controlplane/cluster/rpc/tests.rs`
- Test: `src/controlplane/cluster/rpc/tests.rs`

- [ ] **Step 1: Write the failing test**

Add a unit test in `src/controlplane/cluster/rpc/tests.rs` that:
- builds an `RPCOption`
- sets a hard TTL below the intended floor
- asserts the new helper returns the floor
- also asserts that an above-floor TTL is preserved unchanged

- [ ] **Step 2: Run the targeted test to verify it fails**

Run: `cargo test controlplane::cluster::rpc::tests::raft_rpc_timeout_floor -- --nocapture`

Expected: FAIL because the helper does not exist yet.

- [ ] **Step 3: Commit the red test only if useful**

Optional if the repo flow prefers red-green in a single local iteration.

### Task 2: Implement the minimal timeout-floor helper

**Files:**
- Modify: `src/controlplane/cluster/rpc/raft_transport.rs`

- [ ] **Step 1: Add the helper**

Implement a small helper in `src/controlplane/cluster/rpc/raft_transport.rs` that:
- reads `option.hard_ttl()`
- clamps it to a constant minimum floor
- returns the effective timeout `Duration`

- [ ] **Step 2: Use the helper for all Raft peer RPCs**

Replace direct `timeout(option.hard_ttl(), ...)` calls in:
- `append_entries`
- `install_snapshot`
- `vote`

with `timeout(effective_timeout(...), ...)`.

- [ ] **Step 3: Keep the rest of the transport behavior unchanged**

Do not change:
- endpoint construction
- TLS setup
- error mapping
- metric reporting

### Task 3: Verify green on the focused transport tests

**Files:**
- Test: `src/controlplane/cluster/rpc/tests.rs`

- [ ] **Step 1: Run the new targeted test**

Run: `cargo test controlplane::cluster::rpc::tests::raft_rpc_timeout_floor -- --nocapture`

Expected: PASS

- [ ] **Step 2: Run the full cluster RPC transport test module**

Run: `cargo test controlplane::cluster::rpc::tests -- --nocapture`

Expected: PASS for the touched transport test module.

### Task 4: Run broader cluster/readiness verification

**Files:**
- Test: `src/controlplane/ready.rs`
- Test: cluster-focused test targets that compile in this worktree

- [ ] **Step 1: Run readiness-focused tests**

Run: `cargo test controlplane::ready::tests -- --nocapture`

Expected: PASS

- [ ] **Step 2: Run additional targeted cluster tests if needed**

Run the smallest additional cluster-focused targets that cover the transport path without expanding into unrelated failing suites.

- [ ] **Step 3: Record any unrelated pre-existing failures separately**

If unrelated tests fail, note them explicitly and do not conflate them with the Raft timeout-floor change.

### Task 5: Commit the fix

**Files:**
- Modify: `src/controlplane/cluster/rpc/raft_transport.rs`
- Modify: `src/controlplane/cluster/rpc/tests.rs`

- [ ] **Step 1: Commit the production change and regression test**

Run:

```bash
git add src/controlplane/cluster/rpc/raft_transport.rs src/controlplane/cluster/rpc/tests.rs
git commit -m "fix: floor raft rpc transport deadlines"
```

### Task 6: Deploy and validate on the homelab

**Files:**
- Use: `hack/deploy-homelab.sh`

- [ ] **Step 1: Build the merged artifact from the isolated worktree**

Run the release build needed for homelab deployment from the worktree at the fixed commit.

- [ ] **Step 2: Deploy to the homelab**

Use the existing homelab deployment path, avoiding unrelated dirty main-worktree source changes.

- [ ] **Step 3: Verify cluster stability**

Check:
- repeated `/ready` probes on all three nodes
- service status
- recent journal output for Raft timeout churn

- [ ] **Step 4: Confirm the original symptom improved**

Expected:
- fewer or no `timeout after 50ms when AppendEntries ...` messages
- no frequent `leader unknown`
- readiness remains stable under repeated probing
