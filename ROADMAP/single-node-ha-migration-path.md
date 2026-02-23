# Single Node -> HA Cluster Migration Path

## Goals
- Provide a migration path from local single-node state to a multi-node HA cluster with distributed control-plane state.
- Preserve policies, service accounts, and API auth tokens during migration.
- Support unattended joins via bootstrap tokens for new nodes.
- Keep dataplane traffic unaffected; control-plane availability should be maintained or minimally impacted.

## Current State (Validated in Repo)
- Cluster is optional. When enabled, OpenRaft + RocksDB store lives at `/var/lib/neuwerk/cluster/raft`.
- Local single-node mode stores:
- Policies in `/var/lib/neuwerk/local-policy-store` (records, index, active policy).
- Service accounts and tokens in `/var/lib/neuwerk/service-accounts`.
- API auth keyset in `/var/lib/neuwerk/http-tls/api-auth.json`.
- HTTP TLS material in `/var/lib/neuwerk/http-tls` (`node.crt`, `node.key`, `ca.crt`).
- Cluster mode stores in Raft:
- Policies: `policies/index`, `policies/active`, `policies/item/<id>`.
- Service accounts: `auth/service-accounts/*`.
- API auth keyset: `auth/api_keys`.
- Cluster CA: `ca/cert` and `ca/envelope/<node_id>`.
- HTTP TLS CA: `http/ca/cert` and `http/ca/envelope`.
- Policy replication runs from Raft to local disk for dataplane enforcement.

## Migration Concept
- Prefer a single-member Raft cluster even for single-node deployments to enable future scale-out without data conversion.
- Add a one-time, idempotent migration that seeds Raft from local disk when enabling cluster mode on an existing single node.
- New nodes join via `--join <seed>` with a bootstrap token file and auto-promote to voters.

## Implementation Plan
1. Add a migration trigger and guard
- New flag `--cluster-migrate-from-local` or env `NEUWERK_CLUSTER_MIGRATE=1`.
- Only run when `cfg.cluster.enabled` and `cfg.cluster.join_seed` is `None`.
- Write a marker file under `cfg.cluster.data_dir` after success to avoid re-running.
- If Raft already has any control-plane keys, either skip or require a `--cluster-migrate-force` flag.

2. Seed API auth keyset into Raft
- If `auth/api_keys` missing in Raft, try to load `http-tls/api-auth.json`.
- If found, persist via Raft. If not found, fall back to `ensure_cluster_keyset`.
- Emit a clear log indicating which path was used.

3. Seed policies into Raft
- Read all records from `/var/lib/neuwerk/local-policy-store`.
- For each record, write `policies/item/<id>` and update `policies/index`.
- If local active policy is enforce mode, set `policies/active`. Otherwise delete it.
- Use the same ordering and metadata as `persist_cluster_policy` to keep deterministic indices.

4. Seed service accounts and tokens into Raft
- Read accounts and token metadata from `/var/lib/neuwerk/service-accounts`.
- Write each account to `auth/service-accounts/item/<id>`.
- Write token metadata to `auth/service-accounts/tokens/item/<token_id>`.
- Update account and token indices in Raft.

5. Persist HTTP TLS CA private key in local mode
- Persist the HTTP CA private key alongside `http-tls/ca.crt`, for example `http-tls/ca.key` with `0600` permissions.
- Update local-mode TLS bootstrap to re-use `ca.key` when present so the CA remains stable across restarts.

6. HTTP TLS CA handling during migration
- Load `http-tls/ca.key` + `http-tls/ca.crt` and encrypt the CA key with the bootstrap token into `http/ca/envelope`, storing `http/ca/cert` in Raft.
- If `ca.key` is missing, fail migration with a clear remediation message (generate/persist CA key first).

7. Bootstrap token readiness checks
- Validate `/var/lib/neuwerk/bootstrap-token` before migration starts.
- Fail fast with a clear error if missing or expired, since CA envelopes depend on it.

8. Wire migration into startup sequence
- Run migration after cluster runtime starts and before HTTP API starts.
- Block HTTP API from accepting requests until migration completes.
- Start policy replication after migration so local cache matches Raft immediately.

9. Operator workflow
- Step 1: Create or rotate the bootstrap token file on the seed node.
- Step 2: Restart the seed node with cluster flags plus `--cluster-migrate-from-local`.
- Step 3: Verify Raft leader and state with `/metrics` and `/health`.
- Step 4: Boot new nodes with `--join <seed>` and the same token file.
- Step 5: Shift external traffic/load balancer to include new nodes.

10. Safety and rollback
- Migration is read-only against local data; do not delete local files.
- If migration fails, leave the node running in local mode or exit with actionable errors.
- Provide a `--cluster-migrate-verify` mode that compares local vs Raft state for drift detection.

11. Tests
- Unit test: local API auth keyset -> Raft import.
- Unit test: service account and token import preserves status and metadata.
- Integration test: local single node -> migrate -> joiner auto-joins -> policy replication updates local store.
- Integration test: HTTP CA handling with and without local CA key.

## Concrete Implementation Details
1. `src/main.rs`: add CLI flags and config wiring for `--cluster-migrate-from-local`, `--cluster-migrate-force`, `--cluster-migrate-verify`.
Store these on the runtime config struct (where other cluster flags live) and pass into the migration call.

2. `src/main.rs`: after `cluster_runtime` is created and before starting HTTP API and policy replication, call `controlplane::cluster::migration::run(...)`.
Pass `cluster_runtime.raft`, `cluster_runtime.store`, `cfg.cluster`, `cfg.http_tls_dir`, `local_policy_store`, and the service account base dir (`/var/lib/neuwerk/service-accounts`).
If migration fails, exit with a clear error; if `--cluster-migrate-verify` is set, exit non-zero on drift.

3. New module `src/controlplane/cluster/migration.rs`.
Public entrypoint `run(migrate_cfg)` that:
Checks marker file under `cfg.cluster.data_dir/migrations/local-seed-v1.json`.
Loads bootstrap token via `controlplane::cluster::bootstrap::token::TokenStore`.
Validates Raft state emptiness by checking known keys (`auth/api_keys`, `policies/index`, `auth/service-accounts/index`, `http/ca/cert`).
Runs seeding steps and returns a report with counts.

4. `src/controlplane/cluster/migration.rs`: API auth keyset seeding.
Use `api_auth::load_keyset_from_store` to detect existing state.
If missing, load local keyset from `api_auth::local_keyset_path(http_tls_dir)` and call `api_auth::persist_keyset_via_raft`.
If local keyset is missing, call `api_auth::ensure_cluster_keyset`.

5. `src/controlplane/cluster/migration.rs`: policy seeding.
Read records from `PolicyDiskStore::list_records` and active id from `PolicyDiskStore::active_id`.
For each record, write `policies/item/<id>` and update `policies/index` using the same ordering as `persist_cluster_policy`.
If active policy is enforce mode, write `policies/active`; else delete `policies/active`.
If `--cluster-migrate-verify`, compare Raft policy index and active id against local.

6. `src/controlplane/cluster/migration.rs`: service account seeding.
Use `ServiceAccountDiskStore::list_accounts` and `list_tokens(account_id)` to read local state.
Instantiate `ServiceAccountClusterStore::new(raft.clone(), store.clone())` and call `write_account` + `write_token` to populate Raft indices.
If `--cluster-migrate-verify`, compare account + token counts and IDs.

7. `src/controlplane/http_tls.rs`: persist HTTP CA private key locally.
Introduce a default CA key path `http-tls/ca.key` (permission `0600`).
On CA generation in local mode, write `ca.key` alongside `ca.crt`.
On startup when `ca.crt` exists, if `ca.key` exists, re-use it instead of generating a new CA.

8. `src/controlplane/cluster/migration.rs`: HTTP CA envelope seeding.
Load `http-tls/ca.crt` and `http-tls/ca.key` and build a `CaSigner`.
Encrypt the CA key with the bootstrap token and store `http/ca/envelope` and `http/ca/cert` via Raft `ClusterCommand::Put`.
If `ca.key` missing, fail migration with a remediation message.

9. Marker file format.
Write `local-seed-v1.json` with `timestamp`, `node_id`, `counts` (policies, accounts, tokens), and `http_ca_seeded` boolean.
If marker exists and `--cluster-migrate-force` is not set, skip migration and log “already migrated”.

10. Error handling/logging.
Use clear, actionable errors: missing bootstrap token, missing CA key, partial Raft state.
Log the migration report and key decision points (keyset source, policy count, service account count).

11. Tests.
Add e2e coverage in `src/e2e/cluster_tests.rs`:
Case `cluster_migrate_from_local` sets up local policy + service accounts on seed, runs with `--cluster-migrate-from-local`, then joins a second node and verifies Raft state + policy replication.
Case `cluster_migrate_requires_http_ca_key` verifies migration fails without `http-tls/ca.key` and succeeds once present.

## Open Questions
- Should we expose the HTTP CA key path via explicit CLI flags, or keep it as a fixed `http-tls/ca.key` convention?
