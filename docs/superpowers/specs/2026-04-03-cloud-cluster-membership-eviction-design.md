# Cloud Cluster Membership Eviction Design

## Goal

Prevent stale Raft members from surviving cloud rollouts, instance refreshes, and long-lived node disappearance. The system should automatically evict members that are safely removable, while also giving operators explicit controls to inspect and manipulate cluster membership when automation is insufficient.

## Problem Summary

Today the cloud integration drains traffic and completes provider termination actions, but it does not shrink Raft membership. A node can therefore be drained and terminated while remaining a Raft voter. In small clusters this is operationally dangerous because readiness depends on healthy cluster membership and recent quorum acknowledgement. A dead stale voter can leave the surviving node unready even though traffic has already been reassigned.

## Requirements

### Functional

- Automatically evict cloud members that are explicitly terminating once they are drained.
- Optionally auto-evict stale members that no longer correspond to a discovered cloud instance for a configured timeout.
- Enforce a safe minimum voter threshold for automatic removal.
- Provide operator-facing HTTP API endpoints to list members, remove a member, and replace the voter set.
- Provide matching `neuwerk cluster ...` CLI commands as thin wrappers over the HTTP API.

### Safety

- Automatic eviction is leader-only.
- Automatic eviction must never remove the local leader node automatically.
- Automatic eviction must never reduce the voter set below the configured minimum.
- Automatic eviction must not run while Raft is already in a joint membership transition.
- Only one automatic eviction attempt should run per reconcile tick.

### Non-Goals

- General-purpose cloud-independent failure detection outside the existing cloud integration scope.
- Arbitrary background rebalancing of voter placement.
- Automatic wipe or rebootstrap of removed nodes.

## Runtime Configuration

Add a new operator-facing subsection under `integration` in `/etc/neuwerk/config.yaml`:

```yaml
integration:
  mode: aws-asg
  route_name: neuwerk-default
  cluster_name: neuwerk
  drain_timeout_secs: 300
  reconcile_interval_secs: 15
  membership:
    auto_evict_terminating: true
    stale_after_secs: 0
    min_voters: 3
```

Semantics:

- `integration.membership.auto_evict_terminating`
  - default `true`
  - when enabled, a member with a replicated termination event becomes eligible for automatic removal after its drain state reaches `Drained`
- `integration.membership.stale_after_secs`
  - default `0`
  - `0` disables stale-member auto-eviction
  - positive values enable removal of members that no longer map to any discovered cloud instance after the timeout
- `integration.membership.min_voters`
  - default `3`
  - automatic and normal operator removals must preserve at least this many voters unless the operator explicitly forces a break-glass override

## Cluster Membership Model

The implementation will continue using OpenRaft membership changes as the source of truth. Member removal is performed through `raft.change_membership(..., retain=false)` so removed voters actually leave the cluster rather than remaining as passive learners. The system should treat voter removal as the primary action; explicit node cleanup from ancillary state is best-effort and must not precede the committed membership change.

Automatic eviction decisions use current Raft metrics plus cloud integration state:

- current uniform voter set
- current leader identity
- drain state
- replicated termination events
- discovered cloud instances filtered by the active integration tags
- observed readiness / last-seen cloud observation timestamps

## Cloud-Side Correlation

Automatic cloud eviction requires mapping a Raft member to a discovered instance. The initial implementation should derive this by parsing the member’s advertised `node.addr` host and matching it to a discovered instance `mgmt_ip`.

Rules:

- exact single match: eligible for automation
- no match: candidate for stale-member logic
- multiple matches or unparsable host: automation skips this member and surfaces the ambiguity through the operator API

This keeps the implementation aligned with the current cluster model without introducing a second persisted node identity layer in the first pass.

## Automatic Eviction Flow

### Terminating Member

1. Cloud provider reports a termination notice.
2. The instance publishes the termination event into replicated integration state.
3. The leader reconcile loop excludes the instance from eligible traffic assignment and drives drain state.
4. Once the instance drain state becomes `Drained`, the leader evaluates eviction safety.
5. If removal preserves `min_voters`, the leader removes the node from the voter set.
6. Only after successful membership change does the existing lifecycle completion path continue normally.

### Stale Member

1. The leader compares current Raft members against discovered cloud instances.
2. If a member cannot be mapped to any discovered instance, it is marked missing.
3. If it remains missing for at least `stale_after_secs`, the leader evaluates eviction safety.
4. If removal preserves `min_voters`, the leader removes the node from the voter set.

The stale timer is leader-driven and should be persisted in replicated integration state so leadership changes do not immediately reset or duplicate stale-member decisions.

## Operator API

Add authenticated admin endpoints under `/api/v1/cluster`:

- `GET /api/v1/cluster/members`
  - returns current members with:
    - `node_id`
    - `addr`
    - `role`
    - `is_voter`
    - cloud correlation status
    - drain state if known
    - termination event if known
    - auto-eviction eligibility and reason
- `POST /api/v1/cluster/members/{node_id}/remove`
  - safe single-member removal
  - request body supports `force: bool`
- `PUT /api/v1/cluster/members/voters`
  - replace the voter set
  - request body contains explicit voter ids plus optional `force`

Behavior:

- non-force mutations enforce `min_voters`
- `force=true` is admin-only break-glass behavior and should be clearly labeled in API responses and audit logs
- requests received on a follower should reuse the existing leader-proxy behavior where appropriate rather than demanding the operator find the leader manually

## CLI Commands

Add a new command family:

- `neuwerk cluster members list --http-addr <host:port> --token <jwt> [--ca <path>]`
- `neuwerk cluster members remove <node-id> --http-addr <host:port> --token <jwt> [--ca <path>]`
- `neuwerk cluster members remove <node-id> --force --http-addr <host:port> --token <jwt> [--ca <path>]`
- `neuwerk cluster voters set --ids <csv> --http-addr <host:port> --token <jwt> [--ca <path>]`
- `neuwerk cluster voters set --ids <csv> --force --http-addr <host:port> --token <jwt> [--ca <path>]`

The CLI should be intentionally thin:

- it authenticates to the HTTP API with a bearer token
- it validates user input
- it renders compact operator-friendly output
- it does not contain separate membership business logic

## Internal Components

### Cloud Integration Membership Controller

Extend the existing leader reconcile path with a membership controller that:

- builds cloud-to-member correlation
- identifies terminating or stale candidates
- applies safety checks
- performs at most one membership change per tick

This logic belongs with the existing cloud integration because it already owns the relevant lifecycle inputs.

### Replicated Membership Metadata

Add replicated integration keys for missing-member tracking so stale timeouts survive leader changes and process restarts. This state only needs to track the first-observed-missing timestamp and can be removed once the member reappears or is evicted.

### HTTP API Surface

Add a new HTTP API module for cluster membership administration and status serialization. It should follow the existing `utoipa`-documented, admin-authenticated `/api/v1/...` pattern.

### Runtime CLI Surface

Add a new `runtime::cluster` command parser/executor parallel to the existing `runtime::auth` and `runtime::sysdump` entrypoints.

## Error Handling

- Membership changes that fail because the node is not leader should surface a clear leader/unavailable response.
- Safety-check failures should return structured validation errors that explain whether `min_voters`, self-removal, ambiguous cloud mapping, or joint membership state blocked the operation.
- Automatic eviction failures should be logged and retried on later reconcile ticks; they must not block traffic drain or provider lifecycle polling.
- Missing cloud inventory must not immediately evict all members; only per-member stale timers backed by repeated reconciliation may trigger stale removal.

## Testing Strategy

### Unit Tests

- config parsing and validation for new `integration.membership.*` paths
- candidate selection for terminating members
- candidate selection and timeout behavior for stale members
- `min_voters` enforcement
- self-removal rejection for automatic flow
- ambiguous cloud correlation skip behavior

### Integration-Style Control Plane Tests

- leader reconcile removes a drained terminating voter when safe
- leader reconcile does not remove a terminating voter when it would violate `min_voters`
- leader reconcile removes a stale voter only after the configured timeout
- operator remove endpoint proxies or succeeds correctly through the leader path
- voter-set replacement endpoint updates membership as requested

### CLI Tests

- argument parsing for `neuwerk cluster ...`
- request formatting and human-readable output
- force flag wiring

### Documentation

Update `www/src/content/docs/reference/runtime-configuration.mdx` in the same change to document the new supported runtime config paths and defaults.

## Rollout Notes

- The first safe default should preserve today’s behavior for stale members unless operators opt in via `stale_after_secs > 0`.
- Automatic terminating-member eviction should be enabled by default because it directly addresses the rollout bug and is guarded by drain completion plus `min_voters`.
- Operators of 2-node clusters should be able to keep `min_voters: 2`, which prevents automation from collapsing the cluster to a singleton unless they deliberately use a forced manual command.
