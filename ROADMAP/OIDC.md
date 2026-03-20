# OIDC/SSO Production Implementation Plan

Date: 2026-03-06
Scope: control-plane HTTP API auth for UI/API access (no dataplane changes).

Status Update (2026-03-07):
- Implemented end-to-end SSO in the control-plane with Google + GitHub provider support, plus generic OIDC for Dex and enterprise IdPs.
- Implemented backend provider storage, admin settings APIs, public auth routes, role mapping, PKCE/state handling, callback replay guard, ID token signature/claim verification (OIDC providers), metrics, and audit events.
- Implemented UI login provider rendering and full settings-page SSO management.
- Added Dex-backed full-flow integration tests and CI wiring.
- Hardened Dex test/install reliability:
  - `scripts/setup-dex.sh` now falls back to source build (tag checkout + `go build`) when GitHub release binaries are unavailable.
  - Dex test harness now emits startup logs on failure, uses robust config generation, and supports current Dex redirect/login HTML behavior.
  - Strict, non-skipped full-flow validation now passes with `NEUWERK_SSO_REQUIRE_DEX=1 DEX_BIN=.bin/dex make test.integration.sso`.

## Goals
- Deliver production-grade SSO for Neuwerk UI/API.
- Support Google and GitHub as initial providers.
- Preserve existing token login as break-glass access.
- Work in both local mode and cluster mode.
- Fail closed on config/verification/runtime errors.

## Non-Goals
- No dataplane auth logic.
- No user/identity sync database.
- No per-resource RBAC in this phase (keep current `admin` vs `readonly` model).

## Current Baseline
- Auth is already cookie-backed for UI and bearer-token-capable in middleware.
- Existing auth routes: `/api/v1/auth/token-login`, `/api/v1/auth/whoami`, `/api/v1/auth/logout`.
- Existing role enforcement is method-based (`POST/PUT/PATCH/DELETE` require `admin`).
- Existing key management and JWT mint/verify are in place.

## Provider Strategy
- Introduce a shared SSO provider framework with provider kinds:
  - `google` (OIDC discovery + ID token verification)
  - `github` (provider adapter under the same SSO framework; if end-user OIDC ID token is unavailable, use OAuth2 user identity endpoints with equivalent verification and mapping)
  - `generic_oidc` (optional but recommended for enterprise IdPs and testing)
- Keep login UX provider-driven (dynamic list from backend; no hardcoded button behavior).

## High-Level Architecture
1. External SSO provider authenticates user.
2. Neuwerk validates provider response (state/nonce/pkce/code/token/user identity).
3. Neuwerk maps external identity to internal roles.
4. Neuwerk mints existing internal JWT and sets `neuwerk_auth` cookie.
5. Existing auth middleware continues to gate all protected routes.

This keeps one internal auth model while adding external identity bootstrap.

## Data Model and Storage

### SSO Provider Config
- Fields:
  - `id`, `name`, `kind`, `enabled`, `display_order`
  - OAuth/OIDC fields: `issuer_url`, `auth_url`, `token_url`, `userinfo_url`, `jwks_url`, `client_id`, encrypted `client_secret`, `scopes`, `pkce_required`
  - Claim/user mapping: `subject_claim`, `email_claim`, `groups_claim`
  - Role mapping:
    - explicit subjects/groups/email domains -> `admin|readonly`
    - `default_role`
  - Session config:
    - `session_ttl_secs`
    - optional `allowed_email_domains`
  - Audit metadata (`created_at`, `updated_at`)

### Secrets at Rest
- Store `client_secret` encrypted/sealed, never plaintext at rest.
- Follow existing local `0600` file-permission standards.
- Cluster mode stores config/secrets in raft-backed keys.

### Suggested Storage Keys
- `auth/sso/providers/index`
- `auth/sso/providers/item/<id>`
- `auth/sso/state_key` (shared key material for signed/encrypted state cookies)

## API Plan

### Public Auth Endpoints
- `GET /api/v1/auth/sso/providers`
  - Returns enabled providers for login page.
- `GET /api/v1/auth/sso/:id/start`
  - Starts auth flow, sets short-lived SSO state cookie, redirects to provider.
- `GET /api/v1/auth/sso/:id/callback`
  - Validates callback, mints internal JWT cookie, redirects to UI.
- `POST /api/v1/auth/sso/logout` (optional, phase 2+)
  - Clears local cookie and optionally performs provider logout redirect.

### Admin Config Endpoints (protected, admin role)
- `GET /api/v1/settings/sso/providers`
- `POST /api/v1/settings/sso/providers`
- `PUT /api/v1/settings/sso/providers/:id`
- `DELETE /api/v1/settings/sso/providers/:id`
- `POST /api/v1/settings/sso/providers/:id/test` (recommended: connectivity/metadata validation)

## UI Plan

### Login Page
- Replace placeholder SSO buttons with provider list from `/auth/sso/providers`.
- Clicking a provider goes to `/auth/sso/:id/start`.
- Keep token login visible as fallback/break-glass.

### Settings Page
- Add SSO provider management UI:
  - Create/edit/enable/disable/delete providers
  - Secret input write-only semantics
  - Role mapping configuration
  - Provider test action and validation feedback

## Security Requirements
- Authorization Code flow with PKCE for all browser-based flows.
- State + nonce required; strict verification on callback.
- Signed/encrypted short-lived SSO state cookie (`HttpOnly`, `Secure`, `SameSite=Lax`).
- Internal auth cookie remains `HttpOnly`, `Secure`, `SameSite=Strict`.
- Strict issuer/audience validation for OIDC ID tokens.
- JWK caching with TTL and key-id pinning behavior for verification path.
- Minimal accepted clock skew for token time claims.
- Callback URI exact-match enforcement.
- Login and callback rate limiting + bounded memory structures.
- No external provider tokens in query strings or logs.
- Structured audit events for:
  - start attempt
  - callback success/failure reason
  - role mapping result
  - provider config changes

## Role and Identity Mapping
- Canonical internal subject format: `sso:<provider_id>:<external_subject>`.
- Role mapping precedence:
  1. explicit subject rule
  2. group rule
  3. email domain rule
  4. `default_role`
- Deny login if no mapping and no default role is configured (fail closed).

## Implementation Phases

### Phase 1: Foundation and Storage
- Add SSO provider config structs and validation.
- Add local+cluster store implementations for provider config and encrypted secrets.
- Add migration/bootstrap for new storage roots/keys.

Acceptance:
- CRUD API tests pass.
- Secrets are encrypted at rest and permission-checked.

### Phase 2: Auth Flow Engine
- Add `/auth/sso/providers`, `/start`, `/callback`.
- Implement provider adapters (`google`, `github`, shared core flow).
- Add state/nonce/pkce handling and callback verification.
- Mint existing internal JWT + cookie on success.

Acceptance:
- Unit tests for state/nonce/pkce and token verification pass.
- Callback failure modes deny cleanly with auditable reason.

### Phase 3: UI Integration
- Wire login page to dynamic SSO providers.
- Add Settings SSO provider management UI.
- Keep token login fallback.

Acceptance:
- UI tests cover provider listing, redirect actions, and settings form validation.

### Phase 4: Observability and Hardening
- Add metrics:
  - `http_auth_sso_total{provider,outcome,reason}`
  - `http_auth_sso_latency_seconds{provider,stage}`
- Add audit event coverage and no-store caching headers for SSO endpoints.
- Add provider metadata fetch retry and backoff behavior.

Acceptance:
- Metrics and audit assertions in tests.

### Phase 5: E2E with Dex (Full Flow)
- Add e2e suite that runs Dex and exercises full browser-like auth flow end-to-end.
- Required scenario:
  - Configure Neuwerk SSO provider(s) against Dex issuer.
  - Start from login endpoint.
  - Complete authorize -> callback -> internal cookie issuance.
  - Verify `whoami` and protected API access with the new cookie session.
  - Verify logout clears session.
- Add negative scenarios:
  - invalid state
  - nonce mismatch
  - expired code/state
  - unmapped identity / denied role
  - provider disabled

Acceptance:
- New e2e test target passes in CI.

## Dex-Based E2E Design

### Test Topology
- Neuwerk under test.
- Dex as local IdP for deterministic OIDC behavior.
- Optional headless browser driver (or deterministic redirect/form driver) for full-flow traversal.

### Dex Config for Tests
- Static client(s) for Neuwerk callback URLs.
- Static user/password entries for deterministic test identities.
- Deterministic claims for group/email mapping tests.

### Test Matrix (Minimum)
1. `sso_google_like_success_via_dex`
2. `sso_github_like_success_via_dex`
3. `sso_state_tamper_denied`
4. `sso_role_mapping_readonly_enforced`
5. `sso_provider_disabled_denied`

Note:
- Dex primarily validates the OIDC core flow. If the GitHub adapter path requires provider-specific non-OIDC calls, keep dedicated adapter tests with mocked GitHub endpoints in addition to Dex e2e.

## CI Plan
- Add a dedicated e2e job (e.g., `e2e-sso-dex`) that starts Dex and runs the SSO suite.
- Keep this suite independent from hardware-dependent dataplane tests.
- Mark as blocking for auth-related PRs.

## Backward Compatibility and Rollout
- Token login remains available during rollout.
- SSO can be enabled per provider without disabling existing auth paths.
- Support staged rollout:
  1. configure provider disabled
  2. run provider test
  3. enable for pilot users
  4. enforce SSO-only policy later (optional future toggle)

## Risks and Mitigations
- Provider API differences: isolate adapter layer + adapter-specific tests.
- Callback CSRF/replay risk: strict state/nonce/pkce + one-time/short-lived state validation.
- Cluster consistency: use shared config storage and shared state-key material.
- Operational lockout: keep break-glass token login and document recovery.

## Concrete File/Module Breakdown (Execution Order)

### Wave 0: Runtime and Config Plumbing
- Update [src/runtime/cli/types.rs](/home/moritz/dev/neuwerk-rs/firewall/src/runtime/cli/types.rs):
  - add `http_external_url` (or equivalent canonical callback base URL).
- Update [src/runtime/cli/args.rs](/home/moritz/dev/neuwerk-rs/firewall/src/runtime/cli/args.rs):
  - parse `--http-external-url`.
- Update [src/runtime/cli/usage.rs](/home/moritz/dev/neuwerk-rs/firewall/src/runtime/cli/usage.rs):
  - document SSO-related flags.
- Update [src/runtime/bootstrap/startup.rs](/home/moritz/dev/neuwerk-rs/firewall/src/runtime/bootstrap/startup.rs):
  - derive canonical external URL when unset (from advertise/bind).
- Update [src/controlplane/http_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api.rs):
  - add external URL field to `HttpApiConfig`/state.

Definition of done:
- Server has a stable callback base URL independent of local bind internals.

### Wave 1: SSO Domain Model and Stores
- Add [src/controlplane/sso.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/sso.rs):
  - provider config types, validation, role mapping types.
  - local disk store (`0600`) and cluster store (raft keys).
  - encrypted `client_secret` handling (same secret-sealing pattern used by integrations).
- Update [src/controlplane/mod.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/mod.rs):
  - export `sso` module.
- Add unit tests in [src/controlplane/sso.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/sso.rs) (or split test module):
  - CRUD behavior.
  - encryption-at-rest.
  - validation failures.

Definition of done:
- SSO provider configs persist/reload in local and cluster modes with no plaintext secret on disk.

### Wave 2: HTTP API SSO Config Endpoints (Admin)
- Add [src/controlplane/http_api/sso_settings.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso_settings.rs):
  - `GET/POST/PUT/DELETE /api/v1/settings/sso/providers`.
  - optional `POST /api/v1/settings/sso/providers/:id/test`.
- Update [src/controlplane/http_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api.rs):
  - wire SSO store into `ApiState`.
  - register protected settings routes.
- Extend [src/controlplane/http_api/tests.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/tests.rs):
  - admin-only mutation checks.
  - secret write-only/read-redacted response semantics.

Definition of done:
- Provider config is API-manageable and respects existing admin authz.

### Wave 3: Public SSO Auth Routes and Core Flow
- Add [src/controlplane/http_api/sso_auth_routes.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso_auth_routes.rs):
  - `GET /api/v1/auth/sso/providers`
  - `GET /api/v1/auth/sso/:id/start`
  - `GET /api/v1/auth/sso/:id/callback`
- Add [src/controlplane/http_api/sso_flow.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso_flow.rs):
  - state/nonce/pkce generation and verification.
  - token exchange + identity extraction.
  - internal JWT mint + auth cookie issuance.
- Update [src/controlplane/http_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api.rs):
  - register new public routes.

Definition of done:
- End-to-end login flow works from provider redirect to internal session cookie.

### Wave 4: Provider Adapters (Google + GitHub)
- Add [src/controlplane/http_api/sso/providers/google.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso/providers/google.rs):
  - OIDC discovery, code exchange, ID token verification.
- Add [src/controlplane/http_api/sso/providers/github.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso/providers/github.rs):
  - GitHub login adapter with normalized identity extraction.
- Add [src/controlplane/http_api/sso/providers/mod.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso/providers/mod.rs):
  - shared provider trait + normalized identity model.
- Add [src/controlplane/http_api/sso/providers/generic_oidc.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/sso/providers/generic_oidc.rs) (recommended for Dex and enterprise IdPs).

Definition of done:
- Google and GitHub sign-in paths are both supported behind one normalized mapping pipeline.

### Wave 5: Security Hardening and Session Controls
- Update [src/controlplane/http_api/security.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/security.rs):
  - ensure all SSO endpoints are `Cache-Control: no-store`.
- Update [src/controlplane/http_api/auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/auth.rs):
  - keep middleware unchanged for protected routes; ensure SSO-issued JWT claims fit current checks.
- Add/extend rate limiting in [src/controlplane/http_api/auth.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/auth.rs) or dedicated SSO limiter module:
  - start/callback abuse controls with bounded memory.
- Add failure-path tests in [src/controlplane/http_api/tests.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/tests.rs):
  - state tamper, nonce mismatch, expired callback state, disabled provider.

Definition of done:
- SSO flow is fail-closed and protected against replay/CSRF/misconfiguration classes.

### Wave 6: Metrics and Audit
- Update [src/controlplane/metrics.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/metrics.rs), [src/controlplane/metrics/construct.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/metrics/construct.rs), [src/controlplane/metrics/methods.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/metrics/methods.rs):
  - add `http_auth_sso_total{provider,outcome,reason}`.
  - add `http_auth_sso_latency_seconds{provider,stage}`.
- Update audit handling under [src/controlplane/http_api/audit.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/audit.rs) or SSO modules:
  - emit structured SSO lifecycle events.
- Extend API metrics assertions in [src/e2e/tests/api_cases/policy_metrics_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/tests/api_cases/policy_metrics_cases.rs) if needed for new counters.

Definition of done:
- SSO success/failure/latency is observable and auditable.

### Wave 7: UI API Client + Types
- Add [ui/types/sso.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types/sso.ts):
  - provider view and settings DTOs.
- Update [ui/types.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/types.ts):
  - export SSO types.
- Add [ui/services/apiClient/sso.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/apiClient/sso.ts):
  - login provider list and settings CRUD API calls.
- Update [ui/services/api.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/api.ts):
  - export SSO client functions.

Definition of done:
- UI has typed transport coverage for all SSO endpoints.

### Wave 8: Login UI Wiring
- Add [ui/components/auth/SsoProviderButtons.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/SsoProviderButtons.tsx):
  - renders providers from backend.
- Add [ui/components/auth/useSsoProviders.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/useSsoProviders.ts):
  - load providers, handle loading/error.
- Update [ui/components/auth/LoginPage.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/LoginPage.tsx):
  - replace placeholder Google/GitHub buttons with live provider buttons.
- Keep [ui/components/auth/useTokenLogin.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/useTokenLogin.ts) unchanged as fallback path.

Definition of done:
- Login page offers functional SSO and token login fallback.

### Wave 9: Settings UI for Provider Management
- Add [ui/pages/settings/components/SsoProvidersPanel.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/settings/components/SsoProvidersPanel.tsx).
- Add [ui/pages/settings/useSsoSettings.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/settings/useSsoSettings.ts).
- Update [ui/pages/settings/useSettingsPage.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/settings/useSettingsPage.ts):
  - compose TLS-intercept settings and SSO settings.
- Update [ui/pages/SettingsPage.tsx](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/SettingsPage.tsx):
  - render SSO provider management section.

Definition of done:
- Admin can fully manage SSO providers from Settings.

### Wave 10: Unit/Integration Test Expansion
- Backend:
  - extend [src/controlplane/http_api/tests.rs](/home/moritz/dev/neuwerk-rs/firewall/src/controlplane/http_api/tests.rs) with SSO route + failure-mode coverage.
  - add provider-adapter tests with mocked upstream endpoints.
- UI:
  - add [ui/services/apiClient/sso.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/services/apiClient/sso.test.ts).
  - add [ui/components/auth/useSsoProviders.test.ts](/home/moritz/dev/neuwerk-rs/firewall/ui/components/auth/useSsoProviders.test.ts).
  - add settings helper/component tests under [ui/pages/settings](/home/moritz/dev/neuwerk-rs/firewall/ui/pages/settings).

Definition of done:
- Core SSO behavior is regression-tested outside full e2e.

### Wave 11: Dex E2E Full-Flow Suite
- Add Dex runtime helper module [src/e2e/services/dex.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/services/dex.rs):
  - start/stop Dex process, generate config, expose issuer URL.
- Update [src/e2e/services.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/services.rs):
  - export Dex helpers.
- Add SSO case file [src/e2e/tests/sso_cases.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/tests/sso_cases.rs):
  - `sso_google_like_success_via_dex`
  - `sso_github_like_success_via_dex`
  - `sso_state_tamper_denied`
  - `sso_role_mapping_readonly_enforced`
  - `sso_provider_disabled_denied`
- Update [src/e2e/tests.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/tests.rs) and [src/e2e/tests/case_catalog.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/tests/case_catalog.rs):
  - register SSO cases.
- Add helper functions to [src/e2e/services/http_api.rs](/home/moritz/dev/neuwerk-rs/firewall/src/e2e/services/http_api.rs):
  - settings API calls for SSO provider config.
  - callback/session verification helpers.

Definition of done:
- Full redirect/callback/cookie/authenticated API flow is validated against Dex in e2e.

### Wave 12: CI and Developer Workflow
- Update [Makefile](/home/moritz/dev/neuwerk-rs/firewall/Makefile):
  - add dedicated SSO integration target (for example `test.integration.sso`).
- Add CI workflow [.github/workflows/e2e-sso-dex.yml](/home/moritz/dev/neuwerk-rs/firewall/.github/workflows/e2e-sso-dex.yml):
  - install/start Dex.
  - run SSO e2e suite.
- Update [.github/workflows/ci-full-suite.yml](/home/moritz/dev/neuwerk-rs/firewall/.github/workflows/ci-full-suite.yml):
  - include SSO workflow or call target.
- Add setup helper script [scripts/setup-dex.sh](/home/moritz/dev/neuwerk-rs/firewall/scripts/setup-dex.sh) (or equivalent) for local reproducibility.

Definition of done:
- Dex-backed SSO e2e suite runs in CI and is required for auth-related changes.

## Deliverables Checklist
- [x] SSO provider store + encrypted secret handling (local/cluster)
- [x] Public SSO auth routes (`providers/start/callback`)
- [x] Admin SSO settings API
- [x] UI login integration with dynamic providers
- [x] UI settings integration for provider management
- [x] Metrics + audit coverage for SSO lifecycle
- [x] Unit/integration tests for validation/mapping/security checks
- [x] Dex-backed e2e full-flow scenarios in CI
- [x] Runbook/docs for Google and GitHub setup

## Runbook: Google and GitHub Setup

### Prerequisites
- Neuwerk control-plane started with a stable HTTPS external URL:
  - `--http-external-url https://<neuwerk-host-or-lb>`
- UI/API reachable over TLS at that host.
- Admin API token available for initial provider configuration.

### Google Provider
1. In Google Cloud Console, create an OAuth client (`Web application`).
2. Set the redirect URI to:
   - `https://<neuwerk-host-or-lb>/api/v1/auth/sso/<provider-id>/callback`
3. In Neuwerk Settings -> SSO Providers:
   - `kind`: `google`
   - `client_id` / `client_secret`: from Google OAuth app
   - `issuer_url`: optional (defaults to Google issuer)
   - `default_role` or explicit mapping rules:
     - `admin_subjects`, `admin_groups`, `admin_email_domains`
     - `readonly_subjects`, `readonly_groups`, `readonly_email_domains`
   - optional `allowed_email_domains` for domain restriction
4. Click **Test** in UI or call:
   - `POST /api/v1/settings/sso/providers/:id/test`
5. Enable provider and verify login from `/login`.

### GitHub Provider
1. In GitHub Developer Settings, create an OAuth App.
2. Set callback URL to:
   - `https://<neuwerk-host-or-lb>/api/v1/auth/sso/<provider-id>/callback`
3. In Neuwerk Settings -> SSO Providers:
   - `kind`: `github`
   - `client_id` / `client_secret`: from GitHub OAuth app
   - optional endpoint overrides for enterprise GitHub deployments
   - configure role mapping and optional domain restrictions
4. Run provider **Test**, then enable provider and validate login.

### Operational Recovery / Break-Glass
- Token login remains available (`/api/v1/auth/token-login`) for admin recovery.
- If SSO misconfiguration locks out users:
  1. Use token login.
  2. Disable or fix SSO providers in Settings/API.
  3. Re-test and re-enable.

### Verification Checklist
- `GET /api/v1/auth/sso/providers` returns enabled providers.
- `/api/v1/auth/sso/:id/start` redirects to provider and sets `neuwerk_sso` cookie.
- `/api/v1/auth/sso/:id/callback` sets `neuwerk_auth` and clears `neuwerk_sso`.
- `GET /api/v1/auth/whoami` returns `sub` in `sso:<provider_id>:<external_subject>` format and mapped role.
