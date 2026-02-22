# Service Account Tokens

## Goals
- Provide a control-plane API to manage service accounts and their tokens.
- Tokens must be usable for UI and API access.
- Users can create, list, and revoke/delete tokens.
- Token creation supports a TTL (default 90d) or “eternal” (no expiration).
- Revocation is immediate (deny on next request as soon as the node observes the change).
- Works in cluster mode (replicated) and non-cluster mode (local disk).

## Non-Goals (for this phase)
- OIDC integration.
- Fine-grained authorization enforcement by role/scope (store now, enforce later).
- UI changes (separate roadmap item).

## Status
- Step 1 complete: JWT `exp` optional for service accounts, default TTL set to 90d, minting helper added, tests updated.
- Step 2/3/4 complete: service account store (cluster + local), HTTP API routes, auth middleware registry checks, `last_used_at` throttling.
- Step 7 complete: unit tests cover disk store + missing-exp validation; e2e lifecycle coverage added.
- Docs updated in `README.md`.

## Key Decisions (from clarification)
- Service accounts are first-class entities.
- Tokens are returned only once on creation; listing never returns token strings.
- “Eternal” means no JWT `exp` claim (no expiration enforced by claims).
- TTL parsing uses the existing CLI duration syntax (`90d`, `12h`, `3600`).
- Default TTL aligned everywhere to 90d (CLI and API).
- API base path: `/v1/service-accounts`.
- Non-cluster mode persists to disk.

## Proposed API
### Service Accounts
- `POST /v1/service-accounts`
  - Request: `{ "name": "...", "description": "..." }`
  - Response: `ServiceAccount` (metadata)
- `GET /v1/service-accounts`
  - Response: `ServiceAccount[]`
- `DELETE /v1/service-accounts/{id}`
  - Effect: disable/remove account + revoke all tokens.

### Tokens
- `POST /v1/service-accounts/{id}/tokens`
  - Request (TTL): `{ "name": "...", "ttl": "90d" }`
  - Request (eternal): `{ "name": "...", "eternal": true }`
  - Response: `{ "token": "<jwt>", "token_meta": TokenMeta }`
  - Token string is returned only here.
- `GET /v1/service-accounts/{id}/tokens`
  - Response: `TokenMeta[]` (no token strings)
- `DELETE /v1/service-accounts/{id}/tokens/{token_id}`
  - Effect: revoke token immediately (soft-delete with status + revoked_at).

## Token Semantics
- JWT is still Ed25519 signed with the existing API keyset.
- Add optional claim: `sa_id` (service account id).
- `jti` remains required and is used as the token id.
- TTL tokens include `exp` (unix seconds). Eternal tokens omit `exp`.
- `sub` should be the service account id (human name is metadata only).
- `roles`/`scope` remain optional and stored for future enforcement.

### Validation rules
- Always validate signature, `iss`, `aud`, `iat`, and `jti`.
- If `sa_id` is present:
  - Token must exist in the token registry and not be revoked.
  - If registry has `expires_at`, enforce it (and ensure `exp` is present).
  - If registry has no expiration, allow missing `exp`.
  - Update `last_used_at` with throttling (e.g., at most once per minute).
- If `sa_id` is absent:
  - Treat as legacy/CLI token; require `exp` and enforce it.
  - Do not require a registry lookup (keeps CLI working).

## Storage Design
### Cluster mode (replicated via raft)
Store JSON records in the cluster state keyspace:
- `auth/service-accounts/index` -> list of account ids
- `auth/service-accounts/item/<id>` -> ServiceAccount record
- `auth/service-accounts/tokens/index/<id>` -> list of token ids for account
- `auth/service-accounts/tokens/item/<token_id>` -> Token record

### Local mode (disk)
Mirror the above layout in a disk store similar to `PolicyDiskStore`:
- Base dir: `/var/lib/neuwerk/service-accounts`
- `index.json`, `accounts/<id>.json`
- `tokens/index/<account_id>.json`, `tokens/<token_id>.json`

## Data Model
### ServiceAccount
- `id: UUID`
- `name: String`
- `description: Option<String>`
- `created_at: RFC3339`
- `created_by: String` (from auth `sub`)
- `status: active|disabled`

### TokenMeta
- `id: UUID` (matches JWT `jti`)
- `service_account_id: UUID`
- `name: Option<String>`
- `created_at: RFC3339`
- `created_by: String`
- `expires_at: Option<RFC3339>`
- `revoked_at: Option<RFC3339>`
- `last_used_at: Option<RFC3339>`
- `kid: String`
- `status: active|revoked`

## Implementation Steps
1. **Auth core changes**
   - Update `JwtClaims` to allow `exp: Option<i64>` and add optional `sa_id`.
   - Adjust validation to accept missing `exp` only for service account tokens (via registry check).
   - Set `DEFAULT_TTL_SECS` to 90d and ensure CLI uses it.

2. **Service account store (cluster + local)**
   - Add new module `controlplane/service_accounts` with:
     - data structures (ServiceAccount, TokenMeta)
     - storage helpers for cluster keyspace and local disk
     - functions: create/list/delete accounts; create/list/revoke tokens
   - Use atomic write pattern for disk store.

3. **HTTP API routes**
   - Add `/v1/service-accounts` and `/v1/service-accounts/{id}/tokens` routes in `src/controlplane/http_api.rs`.
   - Ensure routes are behind existing auth middleware.
   - Return token only on create.

4. **Auth middleware integration**
   - Attach validated claims to request extensions for handlers.
   - If `sa_id` present, load token metadata by `jti` and enforce status/expiry.
   - Update `last_used_at` with throttling to avoid excessive raft writes.

5. **Revocation semantics**
   - Implement soft-revoke (status + revoked_at) rather than hard delete of token records.
   - `DELETE /v1/service-accounts/{id}` revokes all tokens and disables/removes the account.

6. **Cluster replication handling**
   - In cluster mode, write to raft-backed store for all mutations.
   - Followers continue proxying to leader (existing proxy mechanism).

7. **Testing**
   - Unit tests: token mint/validate with optional `exp`; registry checks; TTL parsing.
   - Integration/e2e tests:
     - Create account, mint token, access API, revoke token, verify immediate denial (covered in e2e harness).
     - Eternal token accepted without `exp` (covered in e2e harness).
     - Non-cluster local store persistence (pending).

8. **Docs**
   - Update `README.md` with new API endpoints and default TTL (90d).
   - Document “legacy CLI tokens” behavior and service account token creation flow.

## Acceptance Criteria
- Users can create/list/delete service accounts and tokens via `/v1/service-accounts` API.
- Tokens can be eternal (no `exp`) or time-bound (default 90d).
- Revoked tokens are denied immediately (subject to raft replication latency for followers).
- CLI tokens still work (backward compatible) and default to 90d TTL.
- Works in both cluster and non-cluster modes with disk persistence.
