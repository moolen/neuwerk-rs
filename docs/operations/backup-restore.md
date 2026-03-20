# Backup And Restore

## Scope

These steps cover the mutable state that must survive restart, host replacement, or rollback.

- Local mode:
  - local policy store: `/var/lib/neuwerk/local-policy-store`
  - service accounts: `/var/lib/neuwerk/service-accounts`
  - integrations: sibling directory of the local policy store root
  - audit findings snapshot: sibling `audit-store`
  - HTTP API auth keyset and local TLS material: `/var/lib/neuwerk/http-tls`
- Cluster mode:
  - Raft/RocksDB state: `/var/lib/neuwerk/cluster/raft`
  - cluster TLS material: `/var/lib/neuwerk/cluster/tls`
  - node identity: `/var/lib/neuwerk/node_id`
  - bootstrap token file used for CA/key recovery: configured `token_path`

If `NEUWERK_LOCAL_DATA_DIR` is set, treat that directory as the root for local mutable state instead of `/var/lib/neuwerk`.

## Auth Model

- Local or single-node mode stores API signing keys in `/var/lib/neuwerk/http-tls/api-auth.json` and CLI auth administration uses `neuwerk auth ... --http-tls-dir /var/lib/neuwerk/http-tls`.
- Cluster mode stores API signing keys in Raft state and CLI auth administration uses `neuwerk auth ... --cluster-addr <ip:port> [--cluster-tls-dir <path>]`.

## Backup Procedure

1. Quiesce writes.
   - Prefer draining the instance and stopping `neuwerk.service`.
   - In cluster mode, back up one node at a time and ensure another node remains healthy before stopping it.
2. Capture the mutable-state directories as a single backup set.
   - Local mode: archive the local data root plus `/var/lib/neuwerk/http-tls`.
   - Cluster mode: archive the cluster data dir, node-id file, token file, and any service manager unit/env files needed to reproduce startup flags.
3. Record the build/runtime tuple with the backup.
   - Neuwerk binary version or commit
   - Rust build target
   - DPDK ABI/runtime source
   - OS image or container base image
4. Store the archive checksum and verify it immediately after upload.

## Validation Steps

Run these checks against a restored copy before calling the backup usable:

1. Start Neuwerk on an isolated host or VM with the restored data.
2. Verify `/health` returns `200`.
3. Verify `/ready` reports the expected state for the restored mode.
   - Local mode without dataplane traffic may remain not-ready until DHCP/bootstrap conditions are satisfied.
4. Verify policy state is present.
   - `GET /api/v1/policies`
   - `GET /api/v1/policies/active`
5. Verify authentication state is present.
   - Existing API auth still works.
   - Service accounts/tokens list successfully.
6. Verify integrations load and decrypt successfully.
7. In cluster mode, verify the restored node can read Raft state without reopening from scratch and rejoins with the expected node identity.

## Restore Procedure

1. Stop the Neuwerk process on the target host.
2. Restore files with original ownership and permissions.
   - Keep token/key material at `0600`.
3. Start Neuwerk with the same storage paths used when the backup was taken.
4. Confirm:
   - `/health` is `200`
   - `/ready` reaches green once dataplane/control-plane prerequisites are satisfied
   - policies, service accounts, integrations, and TLS material are readable
5. For cluster restores, reintroduce one node first, confirm Raft health, then bring back additional nodes.

## Failure Notes

- Do not mix backups across different clusters.
- Do not restore cluster data while changing the node-id file unless you intend to create a new node identity.
- Keep the bootstrap token file with the backup set; cluster CA and sealed records depend on it.
