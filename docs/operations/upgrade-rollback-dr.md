# Upgrade, Rollback, And Disaster Recovery

## Upgrade Runbook

1. Preflight.
   - Take a fresh backup using `docs/operations/backup-restore.md`.
   - Confirm the target binary is built for a compatible glibc and DPDK runtime.
   - Confirm the target config does not change local or cluster storage paths accidentally.
2. Canary one node.
   - Drain the node.
   - Stop the service.
   - Replace the binary and any companion assets.
   - Start the service.
3. Validate the canary.
   - `/health` is `200`
   - `/ready` returns healthy after dataplane/bootstrap recovery
   - policy replication catches up
   - no sustained spikes in `raft_peer_errors_total`, `svc_fail_closed_total`, `dp_nat_port_utilization_ratio`, or auth failures
4. Roll through the remaining nodes one at a time.
   - In clustered deployments, keep quorum healthy during rollout.
   - In local/lifecycle-only deployments, keep the load balancer or steering plane pointed away from draining nodes until readiness is green again.

## Rollback Runbook

Use rollback when the new binary starts but degrades correctness, readiness, performance, or cluster stability.

1. Drain the bad node.
2. Stop the service.
3. Restore the previous binary and its matching runtime assets.
4. Start the service and verify health/readiness.
5. If the rollback still fails because on-disk state is incompatible or corrupted, restore the latest known-good backup for that node.

## Disaster Recovery

Use DR when the original host, disk, or instance group is unavailable.

### Local Mode

1. Provision a replacement host with the same network wiring.
2. Restore the latest backup set.
3. Start the service with the original local-state root or `NEUWERK_LOCAL_DATA_DIR`.
4. Revalidate health, readiness, and persisted policy/auth/integration state.

### Cluster Mode

1. Restore one seed node first with its cluster data, TLS material, node-id, and bootstrap token file.
2. Bring the restored seed node up and verify it can open the Raft store cleanly.
3. Restore additional nodes one by one.
4. Confirm leader election, follower catch-up, and policy replication before returning traffic.

## Abort Conditions

Abort the rollout and switch to rollback/DR if any of these persist beyond the expected warm-up window:

- `/ready` stays non-200 after dataplane DHCP/bootstrap should already be complete
- repeated `raft_peer_errors_total` growth
- sustained `svc_fail_closed_total` increments
- `dhcp_lease_active == 0`
- rapid growth in deny/error counters that was not present before the rollout
