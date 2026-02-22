# Bootstrap HA Implementation Plan

## Goals
- Provide an embedded, HA control-plane store using OpenRaft + RocksDB.
- Support unattended join with a PSK bootstrap token.
- Allow any leader to sign node certs by distributing the CA key material in the replicated store.
- Keep dataplane isolated and functional if the control-plane leader is lost.

## Non-Goals (for this phase)
- Cloud discovery integration (AWS/GCP/Azure). A placeholder interface will be defined.
- External user-facing API transport (HTTP/JSON).
- Cross-region clustering.

## Assumptions
- Single binary with isolated threads for control-plane and dataplane.
- Join is strict when `--join` is provided (fail fast on errors).
- Node identity is a UUID stored at `/var/lib/neuwerk/node_id`.
- PSK bootstrap token file is JSON at `/var/lib/neuwerk/bootstrap-token`.
- Control-plane RPC is internal only.
- Join uses retry + backoff + jitter when contact to seed fails.
- Node certificates only include the advertised endpoint (SANs).
- Binding the control-plane RPC to the mgmt address is sufficient and should be configurable by CLI.

## Data Model (State Machine)
- `rules/active` -> current ruleset + version.
- `rules/history/<rev>` -> optional audit/history.
- `dns/map/<hostname>/<ip>` -> mapping metadata.
- `dns/last_seen/<hostname>/<ip>` -> timestamp for GC.
- `ca/envelope/<node_id>` -> encrypted CA key envelope for node.
- `cluster/members` -> optional view of known endpoints (non-authoritative; source of truth is Raft membership).

## Token File Format (JSON)
Example:
```json
{
  "tokens": [
    { "kid": "2026-02-20-1", "token": "hex:9f2c...", "valid_until": "2026-03-20T00:00:00Z" },
    { "kid": "2025-12-01-1", "token": "b64:Z29vZC1zZWNyZXQ=", "valid_until": "2026-03-01T00:00:00Z" }
  ]
}
```
Rules:
- `kid` and `token` required.
- `valid_until` optional; if missing, token never expires.
- `token` supports `hex:` or `b64:` prefix.
- Reject duplicate `kid`s.
- Accept any non-expired token; pick newest non-expired as “current.”

## Bootstrap and Join Flow
### Join Mode (`--join <seed>`)
1. Read `node_id` from `/var/lib/neuwerk/node_id` or generate UUID and persist.
2. Read and parse `/var/lib/neuwerk/bootstrap-token`.
3. Create node keypair + CSR.
4. Connect to seed endpoint; send `JoinRequest { node_id, endpoint, csr, kid, psk_hmac, nonce }`.
5. If join fails, retry with backoff + jitter up to a bounded time budget.
6. Seed validates PSK token (by `kid`) and HMAC.
7. Seed signs CSR and returns node cert + CA chain.
8. Seed adds node as learner, waits for catch-up, then promotes via membership change.

### Bootstrap Mode (no `--join`, phase 1)
- If local Raft state exists, resume.
- If no local state exists, bootstrap a single-node cluster (manual seed).

### Bootstrap Mode (no `--join`, phase 2)
- Query discovery provider (cloud API, or static list for tests).
- If any cluster exists, join the discovered leader.
- If no cluster exists, initialize a new cluster as seed.

## CA Key Distribution
- Seed generates CA keypair at initial bootstrap.
- For each node, derive a wrapping key from that node’s PSK using HKDF.
- Encrypt CA private key into an envelope per node.
- Store envelopes at `ca/envelope/<node_id>` in Raft state.
- When a node is leader, it decrypts its own envelope to sign new node certs.
- Zeroize CA key material in memory after signing.

## Deterministic GC
- Only the Raft leader schedules GC.
- Leader proposes `Gc(cutoff_timestamp)` command.
- All replicas apply the same cutoff to delete stale `dns/last_seen` and `dns/map` entries.

## Module Layout (Proposed)
- `control_plane/cluster/` OpenRaft node, membership, transport.
- `control_plane/storage/` RocksDB-backed log + state machine.
- `control_plane/bootstrap/` token parsing, join flow, CA envelope management.
- `control_plane/rpc/` internal gRPC service definitions.
- `dataplane/` existing pipeline (no control-plane logic).

## Security Notes
- Raft control-plane RPC uses mTLS with node certificates signed by the cluster CA.
- Join RPC remains plaintext on the join bind address; it is restricted to the mgmt interface.
- PSK tokens should be file-permission restricted.
- Store token `kid` used for signing in the Raft log for auditability.

## Tests
- Unit tests for token JSON parsing and validation.
- Unit tests for envelope encryption/decryption and HKDF derivation.
- Integration test for join flow using two nodes with static IPs.
- Integration test for membership changes (add learner -> promote -> remove).
- GC determinism test: same cutoff applied on all replicas.

## Milestones
1. [x] Implement token JSON parser + validation and unit tests.
2. [x] Implement join RPC + HMAC validation and CSR signing.
3. [x] Implement CA envelope storage and leader signing.
4. [x] Integrate OpenRaft storage over RocksDB.
5. [x] Add integration tests for join + membership.
6. [x] Add deterministic GC command and tests.
7. [x] Wire mTLS into Raft gRPC transport.
8. [ ] Add discovery interface placeholder for future cloud integrations.

## Open Questions
- Should the CSR include the node’s mgmt IPs or only the control-plane endpoint?
- Should join be retried with exponential backoff or fail immediately on first error?
- How should the node choose its advertised endpoint in multi-NIC environments?
