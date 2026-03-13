# Service Account Authorization Roadmap

## Summary
- Add first-class authorization roles to service accounts and service-account tokens.
- Make machine identities usable for mutating API workflows, especially Terraform and rollout automation.
- Keep the phase-1 model intentionally small: `admin` and `readonly`.
- Implement the abstraction in a way that can later evolve into capabilities without reworking the whole storage and UI model.

## Why This Exists
Today the HTTP API already enforces roles:
- mutating HTTP methods require `admin`
- read-only requests can be served without `admin`

Human and SSO-minted JWTs can already carry `roles`, but service-account tokens currently authenticate with `sa_id` only and are minted with no roles. That means service accounts are effectively read-only even when the operator intends them to drive policy or settings changes.

This is a direct blocker for:
- Terraform provider write operations
- CI/CD policy rollout automation
- integration lifecycle management
- any non-human management client that should not depend on a human bearer token

## Goals
- Make service accounts suitable for write-capable automation.
- Preserve the existing JWT validation and token-registry checks.
- Keep the v1 authz model small, explicit, and easy to reason about.
- Expose the authz state clearly in the UI so operators can safely create and review machine identities.
- Fail closed when account roles are downgraded.

## Non-Goals
- Full capability-based RBAC in phase 1.
- Per-endpoint custom policy expressions.
- Role delegation chains between service accounts.
- Replacing human admin login or SSO.
- Solving bootstrap of the first admin machine token without an existing admin path.

## Current State

### Backend
Current service-account storage in [src/controlplane/service_accounts.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/service_accounts.rs):
- `ServiceAccount` has `id`, `name`, `description`, `created_at`, `created_by`, `status`
- `TokenMeta` has `id`, `service_account_id`, `name`, `created_at`, `created_by`, `expires_at`, `revoked_at`, `last_used_at`, `kid`, `status`

Current HTTP surface in [src/controlplane/http_api/service_accounts_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/service_accounts_api.rs):
- `GET /api/v1/service-accounts`
- `POST /api/v1/service-accounts`
- `DELETE /api/v1/service-accounts/:id`
- `GET /api/v1/service-accounts/:id/tokens`
- `POST /api/v1/service-accounts/:id/tokens`
- `DELETE /api/v1/service-accounts/:id/tokens/:token_id`

Current authz behavior in [src/controlplane/http_api/auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/auth.rs):
- `POST`, `PUT`, `PATCH`, `DELETE` require `admin`
- service-account token validation already checks:
  - token registry presence
  - service-account active state
  - revocation
  - expiry
  - `sub`/`sa_id` consistency

### UI
Current service-account UI surface:
- [ui/types/serviceAccounts.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types/serviceAccounts.ts)
- [ui/services/apiClient/serviceAccounts.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/apiClient/serviceAccounts.ts)
- [ui/pages/ServiceAccountsPage.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/ServiceAccountsPage.tsx)
- [ui/pages/service-accounts/useServiceAccountsPage.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/useServiceAccountsPage.ts)
- [ui/pages/service-accounts/useServiceAccountTokenPanel.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/useServiceAccountTokenPanel.ts)
- [ui/components/service-accounts/CreateServiceAccountModal.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/CreateServiceAccountModal.tsx)
- [ui/pages/service-accounts/components/CreateTokenModal.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/CreateTokenModal.tsx)
- [ui/components/service-accounts/ServiceAccountTable.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/ServiceAccountTable.tsx)
- [ui/components/service-accounts/TokenRevealDialog.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/TokenRevealDialog.tsx)

The UI currently supports account creation, disable, token minting, and token revoke, but it does not model authorization roles at all.

## Chosen v1 Model

### Roles
Use two explicit roles:
- `readonly`
- `admin`

### Assignment Model
- service accounts have a required account-level role
- tokens have an effective role
- token role defaults to the owning account role
- token role may be downscoped at mint time
- token role may never exceed the owning account role

Examples:
- `admin` account -> can mint `admin` token or `readonly` token
- `readonly` account -> can mint only `readonly` token

### Why This Model
- It solves the Terraform/provider problem without inventing a full RBAC system first.
- It reuses the existing role-based middleware.
- It gives operators a simple mental model.
- It creates a clean seam for a future capability layer.

## Future-Compatible Shape
Phase 1 should not hard-code authorization decisions all over the codebase. The right layering is:
1. durable storage type for account role
2. durable storage type for token effective role
3. one normalization/comparison module for roles
4. auth middleware calling a small authorization helper rather than open-coded string comparisons

That way the later move from `role -> capabilities` can happen under one abstraction boundary.

## Public API Contract

### Service Account Create
Extend `POST /api/v1/service-accounts`.

Request:
```json
{
  "name": "terraform-prod",
  "description": "Terraform automation for prod",
  "role": "admin"
}
```

Response adds:
- `role`

### Service Account Update
Add `PUT /api/v1/service-accounts/:id`.

Phase-1 request:
```json
{
  "name": "terraform-prod",
  "description": "Terraform automation for prod",
  "role": "readonly"
}
```

Notes:
- `PUT` is enough for v1; `PATCH` is not necessary yet
- status disable/enable can stay on the current disable flow for now
- we do not need a dedicated `GET /api/v1/service-accounts/:id` in phase 1 because list data is already sufficient for the UI

### Token Create
Extend `POST /api/v1/service-accounts/:id/tokens`.

Request:
```json
{
  "name": "terraform-prod-q2",
  "ttl": "90d",
  "role": "admin"
}
```

or

```json
{
  "name": "inventory-reader",
  "eternal": true,
  "role": "readonly"
}
```

Rules:
- omit `role` -> inherit account role
- set `role` -> must be equal to or narrower than the account role
- `ttl` and `eternal` remain mutually exclusive

Response still returns the token once, but `token_meta` now includes `role`.

### `whoami`
No contract change is required. `whoami` already returns `roles` in [ui/types/auth.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types/auth.ts). The improvement is that service-account tokens will now return meaningful role data there too.

## Storage And Data Model

### New Backend Enum
Add `ServiceAccountRole` in [src/controlplane/service_accounts.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/service_accounts.rs).

Phase-1 enum values:
- `readonly`
- `admin`

Required helper behavior:
- parsing/serde normalization
- ordering or comparison helper so `readonly <= admin`
- human-readable label method for UI/API messages if useful

### ServiceAccount
Add:
- `role: ServiceAccountRole`

### TokenMeta
Add:
- `role: ServiceAccountRole`

This matters because the token’s effective role must be durable and auditable even if the account later changes role.

### Compatibility / Migration
Existing stored accounts and tokens will not have `role`.

Phase-1 compatibility rule:
- missing account role -> treat as `readonly`
- missing token role -> treat as `readonly`

This is the safe default and avoids silent privilege expansion during upgrade.

## JWT And Auth Semantics

### JWT Minting
When minting service-account tokens:
- continue setting `sa_id`
- set `roles` to `[effective_role]`

Examples:
- admin machine token -> `roles: ["admin"]`
- readonly machine token -> `roles: ["readonly"]`

### Middleware Enforcement
Keep the existing request-path model:
- mutating HTTP methods still require `admin`
- read-only requests continue to work with `readonly`

Add one service-account-specific cross-check:
- token effective role must not exceed current account role

This gives immediate enforcement when an account is downgraded.

### Downgrade Behavior
If an account changes from `admin` to `readonly`:
- existing tokens remain stored
- broader existing tokens are rejected by auth middleware
- no automatic token deletion in v1

This is the recommended phase-1 behavior because it fails closed without making role changes destructive.

Optional later hardening:
- offer an explicit “revoke broader tokens now” workflow in the UI or API

## UI Roadmap

### UX Principles
- default to least privilege
- make effective permissions obvious
- keep the service-account page compact and operational, not abstract
- avoid making token creation feel like raw JWT plumbing

### Type And Client Changes
Update:
- [ui/types/serviceAccounts.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types/serviceAccounts.ts)
- [ui/services/apiClient/serviceAccounts.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/apiClient/serviceAccounts.ts)
- [ui/pages/service-accounts/remote.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/remote.ts)

Add role fields to:
- account types
- token types
- create-account request
- create-token request
- update-account request

### Service Accounts Table
Extend:
- [ui/components/service-accounts/ServiceAccountTable.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/ServiceAccountTable.tsx)
- [ui/components/service-accounts/ServiceAccountTableRow.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/ServiceAccountTableRow.tsx)

Changes:
- add `Role` column
- show compact role badge
- keep `status` visible separately from role
- add row-level `Edit` action

Recommended badge semantics:
- `readonly`: muted/neutral
- `admin`: stronger/high-attention

### Create Service Account Modal
Extend:
- [ui/components/service-accounts/CreateServiceAccountModal.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/CreateServiceAccountModal.tsx)
- [ui/components/service-accounts/CreateServiceAccountModalFields.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/CreateServiceAccountModalFields.tsx)
- [ui/components/service-accounts/createForm.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/createForm.ts)

Changes:
- add required role selector
- default role to `readonly`
- helper text:
  - `readonly`: can inspect state but cannot change policy or settings
  - `admin`: can create, update, and delete managed resources

### Edit Service Account Flow
Add an edit form or modal tied to the new update endpoint.

Suggested scope:
- edit `name`
- edit `description`
- edit `role`

If changing `admin -> readonly`, show a confirmation warning:
- broader existing tokens will stop working for admin-only API calls

### Token Creation Modal
Extend:
- [ui/pages/service-accounts/components/CreateTokenModal.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/CreateTokenModal.tsx)
- [ui/pages/service-accounts/components/CreateTokenModalFields.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/CreateTokenModalFields.tsx)
- [ui/pages/service-accounts/components/createTokenForm.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/createTokenForm.ts)

Changes:
- add optional role selector
- if selected account is `readonly`, hide or lock selector to `readonly`
- if selected account is `admin`, allow `admin` or `readonly`
- default token role to the account role

Helper copy:
- “Tokens inherit the account role by default.”
- “Use `readonly` for diagnostics, inventory, and other non-mutating automation.”

### Token List Panel
Extend:
- [ui/pages/service-accounts/components/ServiceAccountTokensPanel.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/ServiceAccountTokensPanel.tsx)

Changes:
- add `Role` column
- display effective token role
- leave space for a future “role exceeds current account” indicator

### Token Reveal Dialog
Extend:
- [ui/components/service-accounts/TokenRevealDialog.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/TokenRevealDialog.tsx)

Add a short note:
- the token carries the selected effective role
- the value is shown once

### Auth Context / Global UI
Optional but recommended small improvement:
- show auth type and role in the signed-in user context using `whoami`

Relevant files:
- [ui/types/auth.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types/auth.ts)
- [ui/services/apiClient/auth.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/apiClient/auth.ts)
- [ui/components/auth/AuthProvider.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/AuthProvider.tsx)

This is not a prerequisite for provider support, but it improves operator clarity.

## Backend Implementation Plan

### Phase 0: Contract Lock
- confirm role names: `readonly`, `admin`
- confirm token downscoping is part of v1
- confirm `PUT /service-accounts/:id` instead of `PATCH`
- confirm downgrade behavior:
  - reject overly broad token at request time
  - do not auto-revoke in phase 1

### Phase 1: Domain Model
- add `ServiceAccountRole`
- add `role` to `ServiceAccount`
- add `role` to `TokenMeta`
- add helpers:
  - parse/normalize role
  - compare role breadth
  - derive default role for legacy records

Primary files:
- [src/controlplane/service_accounts.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/service_accounts.rs)

### Phase 2: API Auth Plumbing
- mint service-account JWTs with `roles`
- keep `sa_id`
- add middleware check that token role does not exceed current account role
- keep existing revocation, expiry, and status checks

Primary files:
- [src/controlplane/api_auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/api_auth.rs)
- [src/controlplane/http_api/auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/auth.rs)

### Phase 3: Service Account HTTP API
- extend `POST /service-accounts` request/response
- add `PUT /service-accounts/:id`
- extend `POST /service-accounts/:id/tokens`
- return role fields in list responses and token responses

Primary files:
- [src/controlplane/http_api/service_accounts_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/service_accounts_api.rs)
- [src/controlplane/http_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api.rs)

### Phase 4: UI
- add role-aware types and client methods
- add create/edit account role flows
- add token downscoping selector
- add table badges and warnings

### Phase 5: Docs
- update service-account docs
- add automation guidance for Terraform and CI/CD
- document migration behavior and downgrade semantics

## Validation Rules

### Backend
- account create requires valid role
- account update requires valid role
- disabled account cannot mint tokens
- token requested role must be `<=` account role
- unknown role rejected with `400`
- empty name still rejected

### Frontend
- new accounts default to `readonly`
- impossible token role choices are hidden or disabled
- admin downgrade requires explicit confirmation
- API validation messages should pass through clearly

## Test Plan

### Backend Unit Tests
- role serde/parsing
- role ordering/comparison
- legacy record deserialization defaulting to `readonly`
- token role ceiling helper

Likely files:
- [src/controlplane/service_accounts.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/service_accounts.rs)
- [src/controlplane/api_auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/api_auth.rs)

### HTTP API Tests
Add/extend tests in:
- [tests/http_api/authz_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/tests/http_api/authz_cases.rs)
- [tests/http_api/lifecycle_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/tests/http_api/lifecycle_cases.rs)

Required cases:
- readonly service-account token can read
- readonly service-account token cannot mutate
- admin service-account token can mutate
- admin account can mint readonly token
- readonly account cannot mint admin token
- account role downgrade causes broader existing token to be rejected
- list responses include account and token role

### E2E / Real Binary
Add one real-binary API integration case so the full stack is exercised against the actual process:
- create `admin` service account
- mint `admin` token
- use it to perform a mutating call such as policy create/update
- downgrade account to `readonly`
- verify same token is denied on next mutating call

Likely locations:
- [tests/runtime_signal_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/tests/runtime_signal_cases.rs)
- [src/e2e/tests/api_auth_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/tests/api_auth_cases.rs)

### UI Tests
Add/extend tests around:
- [ui/components/service-accounts/createForm.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/createForm.test.ts)
- [ui/pages/service-accounts/components/createTokenForm.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/components/createTokenForm.test.ts)
- [ui/components/service-accounts/helpers.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/service-accounts/helpers.test.ts)
- [ui/pages/service-accounts/helpers.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/service-accounts/helpers.test.ts)
- component tests for table/modal rendering if present in the test setup

Required UI cases:
- create-account form defaults to `readonly`
- token form constrains role options by account role
- service-account table renders role badge
- downgrade warning appears before submit

## Rollout Plan

### Release Order
1. backend compatibility and authz logic
2. API surface updates
3. UI role visibility
4. UI edit/downscope flows
5. docs and provider integration

### Compatibility Expectations
- old stored accounts/tokens remain readable
- old stored accounts/tokens behave as `readonly`
- human JWTs and SSO JWTs continue to work unchanged

### Operational Note
The first admin machine identity still requires an existing admin path:
- human admin bearer token
- SSO admin session
- existing cluster auth admin tooling

That is acceptable for phase 1.

## Risks
- The two-role model may feel too coarse for long-term platform use.
- Operators may overuse `admin` machine identities.
- Downgrade semantics may surprise users if the UI does not explain them clearly.
- Legacy tokens silently becoming `readonly` may break automation after upgrade.

## Mitigations
- keep role logic centralized so capabilities can replace it later
- default all new UI flows to `readonly`
- add explicit downgrade warnings
- document migration behavior prominently
- recommend short-lived admin tokens for automation where practical

## Acceptance Criteria
- service accounts can be created with `readonly` or `admin`
- service-account tokens persist an effective role
- minted service-account JWTs include `roles`
- admin service-account tokens can perform mutating API calls
- readonly service-account tokens can read but not mutate
- admin accounts can mint readonly tokens
- readonly accounts cannot mint admin tokens
- downgrading an account immediately blocks broader existing tokens
- the UI supports viewing and editing account role and token role clearly
- the documented Terraform automation flow can use a dedicated admin service-account token
