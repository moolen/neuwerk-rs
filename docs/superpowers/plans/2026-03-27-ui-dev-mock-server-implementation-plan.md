# UI Dev Mock Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `npm run dev` in `ui/` always provide a fully navigable frontend backed by a dev-only in-memory mock API, including local create/edit/delete flows for the main editor pages and synthetic data for streaming or read-heavy views.

**Architecture:** Replace the Vite dev proxy with a dev-only mock API middleware layer that serves the existing `/api/v1/*` surface from a shared in-memory store under `ui/dev-mock/`. Keep `ui/services/apiClient/*` as the canonical transport boundary, implement domain handlers behind the Vite server, and add a small synthetic SSE path for wiretap so page hooks continue to behave as though they are talking to a real backend.

**Tech Stack:** Vite dev server middleware, TypeScript, React, existing UI types, Vitest

---

### Task 1: Add The Dev Mock Server Skeleton And Route Test Harness

**Files:**
- Create: `ui/dev-mock/types.ts`
- Create: `ui/dev-mock/http.ts`
- Create: `ui/dev-mock/router.ts`
- Create: `ui/dev-mock/plugin.ts`
- Create: `ui/dev-mock/router.test.ts`
- Modify: `ui/vite.config.ts`
- Test: `ui/dev-mock/router.test.ts`

- [ ] **Step 1: Write the failing route harness tests**

Add tests that prove:

- non-API requests fall through
- unknown `/api/v1/*` routes return `404`
- JSON route handlers can return status, headers, and bodies through one shared response helper

Suggested test shape:

```ts
import { describe, expect, it } from 'vitest';
import { createMockRouter } from './router';

it('returns 404 for unknown api routes', async () => {
  const router = createMockRouter();
  const response = await router.handle({
    method: 'GET',
    url: '/api/v1/does-not-exist',
    headers: {},
    body: undefined,
  });

  expect(response?.status).toBe(404);
  expect(response?.json).toEqual({ error: 'Not found' });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -- dev-mock/router.test.ts`
Expected: FAIL because the `ui/dev-mock/` router and helpers do not exist yet.

- [ ] **Step 3: Implement the shared router and Vite plugin boundary**

Add:

- a normalized request shape for dev handlers
- shared response helpers for JSON, text, blob, and SSE cases
- a router that dispatches `/api/v1/*` paths by method and pathname
- a Vite plugin that installs middleware only during `vite serve`

Target shape:

```ts
export function neuwerkDevMockPlugin(): Plugin {
  return {
    name: 'neuwerk-dev-mock',
    apply: 'serve',
    configureServer(server) {
      const router = createMockRouter();
      server.middlewares.use(async (req, res, next) => {
        const handled = await router.handleNodeRequest(req, res);
        if (!handled) next();
      });
    },
  };
}
```

Update `ui/vite.config.ts` to remove the backend proxy and install the plugin in dev mode only.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test -- dev-mock/router.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/dev-mock ui/vite.config.ts
git commit -m "feat(ui): add dev mock server scaffold"
```

### Task 2: Seed Shared Mock State And Cover Auth/Read-Only Domains

**Files:**
- Create: `ui/dev-mock/state.ts`
- Create: `ui/dev-mock/seed.ts`
- Create: `ui/dev-mock/routes/auth.ts`
- Create: `ui/dev-mock/routes/stats.ts`
- Create: `ui/dev-mock/routes/dns.ts`
- Create: `ui/dev-mock/routes/audit.ts`
- Create: `ui/dev-mock/routes/threats.ts`
- Create: `ui/dev-mock/routes/settings-read.ts`
- Modify: `ui/dev-mock/router.ts`
- Create: `ui/dev-mock/state.test.ts`
- Create: `ui/dev-mock/routes/read-domains.test.ts`
- Test: `ui/dev-mock/state.test.ts`
- Test: `ui/dev-mock/routes/read-domains.test.ts`

- [ ] **Step 1: Write the failing seed and read-route tests**

Cover at least:

- the seed state includes realistic records for dashboard, DNS cache, audit, threat findings, and SSO-supported providers
- `GET /api/v1/auth/whoami` returns an admin-like preview user
- `GET /api/v1/stats`, `GET /api/v1/dns-cache`, `GET /api/v1/audit/findings`, and `GET /api/v1/threats/findings` return successful payloads in the UI’s expected shape

Suggested pattern:

```ts
it('returns the seeded preview user', async () => {
  const { router } = createTestMockServer();
  const response = await router.handle({
    method: 'GET',
    url: '/api/v1/auth/whoami',
    headers: {},
  });

  expect(response?.status).toBe(200);
  expect(response?.json).toMatchObject({
    sub: 'local-preview-admin',
    roles: ['admin'],
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -- dev-mock/state.test.ts dev-mock/routes/read-domains.test.ts`
Expected: FAIL because the seed data and read-domain handlers do not exist yet.

- [ ] **Step 3: Implement the shared in-memory store and read-domain handlers**

Add:

- a seeded store factory that returns stable IDs and timestamps
- route handlers for auth, stats, DNS, audit, threat findings/feed status/silences reads, TLS/status reads, and SSO provider listing
- request parsing helpers for query strings used by audit and threat filters

Keep the state factory isolated so tests can create a fresh server per case:

```ts
export function createMockState(now = Date.now()): MockState {
  return {
    authUser: { sub: 'local-preview-admin', roles: ['admin'] },
    stats: buildSeedStats(now),
    policies: [],
    integrations: [],
    // ...
  };
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test -- dev-mock/state.test.ts dev-mock/routes/read-domains.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/dev-mock
git commit -m "feat(ui): seed dev mock read models"
```

### Task 3: Implement CRUD Mock Routes For Policies, Integrations, Service Accounts, Settings, And SSO

**Files:**
- Create: `ui/dev-mock/routes/policies.ts`
- Create: `ui/dev-mock/routes/integrations.ts`
- Create: `ui/dev-mock/routes/serviceAccounts.ts`
- Create: `ui/dev-mock/routes/settings-write.ts`
- Create: `ui/dev-mock/routes/sso.ts`
- Modify: `ui/dev-mock/state.ts`
- Modify: `ui/dev-mock/router.ts`
- Create: `ui/dev-mock/routes/crud-domains.test.ts`
- Test: `ui/dev-mock/routes/crud-domains.test.ts`

- [ ] **Step 1: Write the failing CRUD route tests**

Cover the workflows the UI needs most:

- create and update a policy, then fetch it again
- create and edit an integration, then list it
- create, update, and disable a service account
- create an SSO provider, update it, test it, and delete it
- toggle performance mode and threat-intel settings
- generate and fetch TLS intercept CA material

Suggested test shape:

```ts
it('persists policy creates and updates in memory', async () => {
  const server = createTestMockServer();

  const created = await server.requestJson('POST', '/api/v1/policies', {
    name: 'Local policy',
    default_action: 'allow',
    source_groups: [],
  });

  const updated = await server.requestJson('PUT', `/api/v1/policies/${created.id}`, {
    ...created,
    name: 'Renamed policy',
  });

  expect(updated.name).toBe('Renamed policy');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -- dev-mock/routes/crud-domains.test.ts`
Expected: FAIL because the mutable domain handlers do not exist yet.

- [ ] **Step 3: Implement mutable domain handlers backed by the shared store**

Add minimal-but-useful CRUD semantics for:

- policies and policy telemetry reads
- integrations
- service accounts and token issuance/revocation
- SSO settings CRUD and provider test action
- TLS intercept CA update/generate/download
- performance mode and threat-intel settings writes
- cluster sysdump download as a synthetic blob response

Preserve the request and response shapes from `ui/services/apiClient/*`, but keep server-side validation intentionally narrow:

```ts
if (!payload.name?.trim()) {
  return json(400, { error: 'Name is required' });
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test -- dev-mock/routes/crud-domains.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/dev-mock
git commit -m "feat(ui): add dev mock CRUD handlers"
```

### Task 4: Add Synthetic Wiretap Streaming And Verify Transport Compatibility

**Files:**
- Create: `ui/dev-mock/routes/wiretap.ts`
- Modify: `ui/dev-mock/router.ts`
- Modify: `ui/services/apiClient/wiretap.ts`
- Create: `ui/dev-mock/routes/wiretap.test.ts`
- Modify: `ui/services/api.test.ts`
- Test: `ui/dev-mock/routes/wiretap.test.ts`
- Test: `ui/services/api.test.ts`

- [ ] **Step 1: Write the failing streaming and transport tests**

Cover:

- `GET /api/v1/wiretap/stream` opens an event stream with the expected content type
- the stream emits `flow` and `flow_end` events in the same JSON shape the page state expects
- the browser transport still subscribes to `/api/v1/wiretap/stream` without changing production behavior

Suggested assertions:

```ts
expect(response.headers['content-type']).toContain('text/event-stream');
expect(firstChunk).toContain('event: flow');
expect(firstChunk).toContain('data:');
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm test -- dev-mock/routes/wiretap.test.ts services/api.test.ts`
Expected: FAIL because the SSE handler and any transport adjustments are not implemented yet.

- [ ] **Step 3: Implement the synthetic wiretap stream**

Add:

- a dev-only event-stream response that pushes a small rotating sample set every few seconds
- cleanup on client disconnect
- minimal helper coverage for emitting `flow` and `flow_end`

Only change `ui/services/apiClient/wiretap.ts` if needed to preserve compatibility with the mock SSE behavior while keeping the production URL and `EventSource` usage stable.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npm test -- dev-mock/routes/wiretap.test.ts services/api.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/dev-mock ui/services/apiClient/wiretap.ts ui/services/api.test.ts
git commit -m "feat(ui): add synthetic wiretap stream for dev"
```

### Task 5: Document The Local Workflow And Run Full Verification

**Files:**
- Modify: `ui/README.md`
- Modify: `ui/package.json`
- Test: `ui/README.md`

- [ ] **Step 1: Write the failing documentation checklist**

Capture the user-facing behaviors that must be true before closing the work:

- `npm run dev` works with no backend
- CRUD pages open and save against the in-memory mock server
- threat and wiretap pages render with synthetic data
- restarting the Vite process resets the mock state

Represent this as a short checklist in the README update so the workflow is explicit.

- [ ] **Step 2: Run the existing verification before documentation changes**

Run: `npm test`
Expected: PASS once the earlier implementation tasks are complete.

- [ ] **Step 3: Document the dev mock workflow**

Update `ui/README.md` to describe:

- `npm run dev` now uses an embedded mock API automatically
- no backend is required for local UI development
- create/edit/delete flows are in-memory and reset on restart
- threat and wiretap data are synthetic in dev

Only modify `ui/package.json` if a script name or description needs to be clarified; otherwise leave it unchanged.

- [ ] **Step 4: Run full verification**

Run: `npm test`
Run: `npm run build`
Expected: PASS

Then do one manual smoke pass:

Run: `npm run dev`
Verify in the browser:
- dashboard loads without backend
- policies, integrations, service accounts, and settings create/edit flows are usable
- threat pages show seeded findings and silences
- wiretap page shows a connected synthetic stream

- [ ] **Step 5: Commit**

```bash
git add ui/README.md ui/package.json
git commit -m "docs(ui): document dev mock workflow"
```
