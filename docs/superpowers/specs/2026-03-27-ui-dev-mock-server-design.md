# UI Dev Mock Server Design

## Goal

Make `npm run dev` in `ui/` always boot into a usable local development environment even when the Neuwerk backend is not running. The local environment must expose all major UI surfaces, support in-memory create/edit/delete flows for the main editor screens, and provide synthetic data for read-heavy and streaming pages.

## Context

The current Vite setup proxies `/api` to `http://localhost:3000`. That makes local frontend work brittle because page hooks fail immediately when the backend is unavailable. The UI already has a localhost-only auth bypass, so local development already recognizes a distinct preview-style workflow. The missing piece is a matching API surface that keeps the rest of the app functional.

## Requirements

- `npm run dev` must work with no backend process.
- Mock behavior must be automatic in Vite dev mode with no extra flags.
- Production builds and the embedded runtime UI must keep using the real backend.
- Existing `ui/services/apiClient/*` modules remain the canonical request/response boundary.
- CRUD-capable pages must support local create/edit/delete interactions well enough to exercise editor layouts.
- Threat and wiretap pages may use synthetic data and lightweight fake actions.
- The solution must avoid duplicating a second data-loading path per page.

## Recommended Approach

Embed a dev-only mock API server into the Vite dev server and answer the same `/api/v1/*` routes that the real backend exposes. Replace the current dev proxy with middleware that reads and mutates a shared in-memory mock state object. Keep the browser-side API client unchanged except for any small transport adjustments needed to support the dev middleware or mock SSE path.

This approach keeps all existing page hooks and API clients exercising realistic request and response flows. It also centralizes mock behavior in one place instead of scattering fixture branches through the UI.

## Alternatives Considered

### 1. Page-local fixture branches

Each page hook would detect dev mode and return local fixture state.

Pros:
- Fast to prototype for one or two pages.

Cons:
- Duplicates backend logic across many hooks.
- CRUD semantics drift quickly.
- Makes tests and future backend parity harder to maintain.

### 2. Browser request interception

Intercept `fetch` in the browser with a mocking library.

Pros:
- Self-contained inside the frontend bundle.

Cons:
- Less natural fit for SSE-style wiretap streaming.
- Harder to share state cleanly across requests.
- Adds another runtime mechanism instead of reusing the dev server boundary.

## Architecture

### Dev-only routing boundary

Add a Vite plugin or middleware layer that is enabled only for `vite serve`. It will intercept `/api/v1/*` requests and return JSON, text, blob, or event-stream responses from local handlers. The current proxy to `localhost:3000` will be removed for dev mode.

### Shared mock state

Create a dedicated mock-state module that owns seeded data and helper operations. This state lives in memory for the lifetime of the dev server process.

The state should include:

- authenticated preview user
- dashboard stats
- policies and policy telemetry
- integrations
- service accounts and service-account tokens
- TLS intercept CA status and certificate text
- performance-mode and threat-intel settings
- SSO providers and supported provider types
- DNS cache entries
- audit findings
- threat findings, feed status, and silences
- wiretap event seed data

CRUD-style handlers mutate this store directly and return updated records in the same shapes the UI already expects.

### Streaming behavior

Wiretap requires a synthetic stream in dev. The mock server should expose `/api/v1/wiretap/stream` as an event stream that periodically emits a small rotating set of events. The events do not need full backend fidelity; they only need to exercise the connected state, row rendering, and aggregation behavior.

### Auth behavior

Keep the existing localhost auth bypass. The mock API should also answer auth endpoints consistently so the login page and any direct auth calls still succeed in dev:

- `GET /api/v1/auth/whoami`
- `POST /api/v1/auth/token-login`
- `POST /api/v1/auth/logout`
- SSO provider listing and start-path behavior needed by the login screen

### State-reset model

Mock state resets when the Vite dev server restarts. No persistence is required for the first version. This keeps the implementation simple and predictable.

## Route Coverage

The mock server must cover the existing UI API surface under `ui/services/apiClient/`:

- auth
- stats
- policies and policy telemetry
- integrations
- service accounts and tokens
- settings, TLS intercept CA, threat-intel settings, performance mode, sysdump download
- DNS cache
- audit findings
- threats, feed status, silences
- SSO settings and supported provider listing
- wiretap stream

If an endpoint is not meaningfully interactive, it should still return realistic seeded data so the page renders without error.

## File Structure

Planned new or updated areas:

- `ui/vite.config.ts`
  - enable dev-only mock middleware instead of backend proxying
- `ui/dev-mock/`
  - mock server entrypoint and route registration
  - shared seeded state
  - route handlers grouped by domain
  - helper utilities for parsing requests and writing responses
- `ui/services/apiClient/transport.ts`
  - only if small transport changes are needed to align with the dev middleware boundary
- `ui/services/apiClient/wiretap.ts`
  - only if the mock SSE implementation needs a transport-safe adjustment
- `ui/README.md`
  - document that `npm run dev` uses the embedded mock API
- `ui/**/*.test.ts`
  - tests for route handlers, state mutation, and any updated transport behavior

## Data Model Principles

- Reuse existing UI types from `ui/types.ts` and `ui/types/*`.
- Seed data should be realistic enough to exercise empty, warning, active, and partially configured states.
- Mock records should include stable IDs and timestamps so tables and sorting logic stay deterministic.
- Mutation handlers should preserve the minimal invariants the UI relies on, but should not attempt to simulate every backend validation rule.

## Error Handling

- Unknown routes should return `404` with a small JSON error object.
- Malformed request payloads should return `400` with readable messages.
- Mock handlers may intentionally reject obviously invalid create/update payloads where the UI expects server feedback.
- Synthetic actions such as sysdump download or SSO provider test should return success-shaped responses unless a targeted failure state is needed for a specific page.

## Testing Strategy

- Add unit tests around mock-state operations for CRUD-heavy domains.
- Add route-level tests for representative endpoints and error cases.
- Preserve or extend existing API-client tests if transport behavior changes.
- Run the UI test suite after wiring in the mock server.

## Rollout Notes

- This change is dev-only and should not alter packaged runtime behavior.
- No control-plane or dataplane code should be affected.
- Future work may add an alternate script for talking to a real backend during UI development, but that is not required for the first version.
