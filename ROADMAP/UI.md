# UI Migration Plan (Neuwerk)

## Goals
- Serve the migrated React UI from the control-plane HTTPS server.
- Standardize API base path to `/api/v1` across server + tests + UI.
- JWT-only login (token input), with server auth endpoints for current and future OIDC integration.
- Align UI pages with the current Neuwerk API and data model.
- Add missing APIs: policy edit/delete, DNS cache (grouped), stats.

## Plan
1. **Port UI source into repo**
   - Copy `../../neuwerk/ui` into `ui/` (exclude `node_modules`).
   - Keep `ui/dist` for serving static assets.

2. **Serve UI from control-plane HTTPS server**
   - Add static file serving from `ui/dist` with SPA fallback to `index.html`.
   - Ensure static assets are public (no auth middleware).

3. **Standardize API base path**
   - Update HTTP API routes to `/api/v1/*`.
   - Update all tests (e2e + unit) to use `/api/v1` paths.

4. **Auth: JWT-only now, OIDC-ready later**
   - Add `/api/v1/auth/token-login` (public): validate token and return user info.
   - Add `/api/v1/auth/whoami` (protected): return claims for current token.
   - UI stores JWT locally and sends `Authorization: Bearer <token>` on API calls.
   - Wiretap SSE uses `?token=` query parameter.

5. **Policies API + UI**
   - Add `GET /api/v1/policies/:id`, `PUT /api/v1/policies/:id`, `DELETE /api/v1/policies/:id`.
   - Preserve current `POST /api/v1/policies`.
   - UI: replace Networks page with Policies page using YAML viewer (request YAML from API or render YAML client-side).

6. **Wiretap UI alignment**
   - Update UI to consume `/api/v1/wiretap/stream` payload (flow events).
   - Map fields to new layout (flow id, src/dst, proto, packets in/out, last seen, hostname, node).
   - Keep client-side filters; optionally pass server filters later.

7. **DNS Cache API + UI**
   - Add `/api/v1/dns-cache` returning entries grouped by hostname.
   - UI: update DNS Cache page to show hostname + IP list + last seen.

8. **Service Accounts UI alignment**
   - Update UI to use existing service account endpoints.
   - Add token list per account + token create/revoke flow.

9. **Dashboard / Stats**
   - Remove mode toggle.
   - Add `/api/v1/stats` returning key security/platform metrics.
   - Update dashboard cards to show dataplane/DNS/flow/lease/cluster status metrics.

10. **Cleanup**
   - Remove pages: DNS Audit, DPI, Integrations.
   - Settings page becomes blank placeholder for future diagnostics.
   - Remove unused API calls + types.

## TODO (Post-UI)
- Add YAML editor support on Policies page (read/write).

## Suggested Metrics for Dashboard
- Active flows (gauge), active NAT entries, NAT port utilization.
- Packets allowed/denied/pending_tls (totals).
- DNS queries allowed/denied, NXDOMAIN counts.
- IPv4 fragments dropped, TTL exceeded.
- DHCP lease active + expiry epoch.
- Cluster leader status + term (when enabled).
