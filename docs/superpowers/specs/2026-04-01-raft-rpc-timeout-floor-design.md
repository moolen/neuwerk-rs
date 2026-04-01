# Raft RPC Timeout Floor Design

## Goal

Stabilize homelab cluster leadership by preventing Raft peer RPCs from timing out under unrealistically small transport deadlines during transient gRPC/TLS reconnects or short CPU stalls.

## Problem

The homelab cluster intermittently reports `leader unknown` and `/ready` flaps with `cluster membership not ready`. Live node logs show repeated Raft transport failures such as:

- `timeout after 50ms when AppendEntries ...`
- `append_entries timeout`
- `vote timeout`
- `h2 protocol error: http2 error`

The relevant transport code wraps each Raft RPC in `timeout(option.hard_ttl(), ...)`. In practice, the `AppendEntries` hard TTL can be as low as `50ms`, which is too aggressive for reconnecting TLS/gRPC channels on saturated 2-vCPU homelab nodes. Once enough heartbeats miss, leaders lose quorum, followers become candidates, and readiness drops.

## Constraints

- Keep the existing Raft heartbeat and election settings unchanged for now.
- Avoid broad transport refactors in the first fix.
- Preserve normal behavior for already-reasonable RPC deadlines.
- Add a regression test first and implement the smallest viable production change.

## Proposed Change

Add a transport-side minimum deadline floor for peer RPCs in the Raft gRPC transport layer.

### Behavior

- Introduce a helper that derives the effective RPC timeout from `RPCOption`.
- If `option.hard_ttl()` is below a fixed minimum floor, use the floor instead.
- If `option.hard_ttl()` is already above the floor, keep it unchanged.
- Apply the helper consistently to:
  - `append_entries`
  - `vote`
  - `install_snapshot`

### Initial Floor

Use a fixed floor in the low-hundreds-of-milliseconds range. This should be large enough to tolerate channel setup and short scheduler stalls, while still remaining well below the existing `heartbeat_interval` of `500ms` and far below the `election_timeout_min` of `2000ms`.

## Why This Design

This directly addresses the observed failure mode without changing Raft semantics or cluster membership logic:

- The observed failures are transport-timeout-driven.
- The network itself is healthy.
- The cluster becomes unstable only after peer RPCs start missing tiny deadlines.

Raising the effective minimum transport deadline is the smallest change that makes the transport less brittle under load while preserving the current Raft timing model.

## Alternatives Considered

### 1. Change heartbeat/election timings

Rejected for the first fix. The current Raft timing configuration is not the outlier; the sub-`100ms` RPC deadline is.

### 2. Add gRPC keepalive / eager reconnect tuning

Potentially useful later, but it is a larger change and harder to validate in one iteration.

### 3. Reduce homelab runtime thread counts only

Useful as a mitigation, but it does not fix the transport fragility. A short transport timeout would still remain brittle.

## Testing Strategy

### Unit

Add a regression test around the new timeout helper:

- A sub-floor hard TTL should be clamped up to the floor.
- An above-floor hard TTL should remain unchanged.

### Focused verification

Run the cluster RPC transport tests after the change.

### Broader verification

Run the readiness / cluster-focused test targets that exercise the affected transport and membership behavior.

### Homelab verification

Deploy to the homelab and verify:

- `/ready` remains stable across repeated probes.
- leader election stops flapping under steady state.
- journal logs no longer show rapid-fire `timeout after 50ms when AppendEntries ...` churn.

## Non-Goals

- Reworking the Raft RPC channel lifecycle.
- Changing readiness semantics.
- Solving every source of homelab CPU pressure in the same change.
