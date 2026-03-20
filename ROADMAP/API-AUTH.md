# API Authentication Roadmap

## Goals
- Add JWT bearer authentication for the external API/UI domain.
- Health (`/health`) and Prometheus metrics (`/metrics`) must remain unauthenticated.
- Internal control-plane RPC (raft/replication) stays on existing mTLS, no JWT required.
- Fail closed: if auth config or key material is unavailable, deny requests.

## Non-Goals (for this phase)
- OIDC integration (planned later).
- Service accounts + fine-grained roles (planned later).
- Auth for internal replication/raft traffic (mTLS only).

## Chosen Design
- JWT algorithm: **Ed25519 (EdDSA)** for small keys and fast verify.
- One auth domain for API/UI only.
- Multiple active signing keys with `kid` to support explicit rotation.
- Tokens must include `exp` (required); CLI defaults to **7 days**.
- Fixed issuer/audience strings:
  - `iss`: `neuwerk-api`
  - `aud`: `neuwerk-api`

## Token Claims
Required:
- `iss`, `aud`, `sub`, `exp`, `iat`, `jti`
Optional (future use):
- `scope` or `roles` (read-only vs admin later)

Validation:
- `iss` and `aud` must match fixed strings.
- `exp` required and must be in the future.
- Allow small clock skew (e.g. ±60s) but still fail closed.

## Key Management
- Store API auth keyset in the replicated control-plane store.
- Structure: list of active keys with `{kid, public_key, private_key, created_at, status}`.
- Only **one** active signing key used for minting at a time, while old keys remain valid
  until their tokens expire.
- Explicit rotation via CLI:
  - `neuwerk auth key rotate` -> add new active signing key, keep old keys active.
  - `neuwerk auth key retire <kid>` -> mark old key as inactive (stop verifying).

Bootstrap:
- On first cluster seed, generate initial keyset and store it in replicated storage.
- On joiners, read keyset from the store. Fail closed if missing.

## API Enforcement
- HTTP API middleware validates `Authorization: Bearer <jwt>` on all API endpoints
  **except** `/health` and `/metrics`.
- Fail closed if:
  - No auth header
  - Token invalid / expired / wrong issuer / wrong audience
  - Keyset missing or cannot be loaded

## CLI Token Minting
- Add `neuwerk auth token mint --sub <id> [--ttl <dur>] [--kid <kid>]`
  - Defaults: TTL = 7d, `iss`/`aud` as above, `kid` = current active key.
- CLI may run on **any** node (keys are replicated).
- Printed token is a bearer JWT suitable for API/UI use.

## Implementation Plan
1. **Key Storage Schema**
   - Add a new replicated storage entry: `auth/api_keys`.
   - Define struct: `ApiKeySet { active_kid, keys: Vec<ApiKey> }`.
   - Add serialization + migration logic (if store absent, seed creates it).

2. **Key Generation + Rotation**
   - Implement Ed25519 keypair generation (rustls/ed25519-dalek).
   - Add CLI commands:
     - `auth key rotate`
     - `auth key list`
     - `auth key retire <kid>`

3. **JWT Minting**
   - Add CLI command:
     - `auth token mint --sub <id> [--ttl 7d] [--kid <kid>]`
   - Build JWT with header `{ alg: "EdDSA", kid }`.
   - Enforce required claims and TTL default = 7d.

4. **HTTP API Middleware**
   - Implement auth middleware in control plane HTTP server.
   - Bypass for `/health` and `/metrics`.
   - Validate JWT:
     - Signature using keyset by `kid`.
     - `iss`, `aud`, `exp`, `iat`, `jti`.
   - Fail closed on any error.

5. **Tests**
   - Unit tests for JWT encode/decode + claim validation.
   - Integration tests for HTTP API auth:
     - Valid token allows POST/GET policy.
     - Missing/invalid/expired token is denied.
     - `/health` and `/metrics` are unauthenticated.

6. **Documentation**
   - Update README/CLI usage to include auth commands.
   - Document token usage and rotation procedure.
