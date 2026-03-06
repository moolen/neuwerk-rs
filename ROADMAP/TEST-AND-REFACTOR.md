# Production Readiness Assessment (Pass 70)

Date: 2026-03-06
Scope: control-plane, dataplane, API surface, UI, lifecycle/cluster stability, security posture.
Out of scope: cloud integration expansion work.

## Validation Snapshot

Commands executed in this pass:

- `make fuzz.check` -> pass
- `NEUWERK_FUZZ_SMOKE_RUNS=120 make fuzz.smoke` -> pass (executed with nightly)
- `NEUWERK_FUZZ_NIGHTLY_MAX_TIME=20 NEUWERK_FUZZ_NIGHTLY_SANITIZERS=address make fuzz.nightly` -> pass after dataplane packet checksum fix
- `npm --prefix ui test` -> pass
- `npm --prefix ui run build` -> pass
- `cargo fmt --all --check` -> pass
- `cargo test --lib` -> pass
- `cargo test -- --test-threads=1` -> pass

Representative suite status:

- UI tests: pass (`149/149` across `43` Vitest files)
- Unit tests: pass (`173/173` in `src/lib.rs` unit set)
- Main binary tests: pass (`16/16`)
- Cluster lifecycle/failover tests: pass (`13/13` in `tests/cluster_join.rs`)
- HTTP API lifecycle/readiness/cluster proxy/audit/wiretap/authz tests: pass (`18/18` in `tests/http_api.rs`)
- Dataplane integration/unit tests: pass (`integration_dpdk_l2`, `integration_nat`, `packet_unit`, `tls_*`)

## Executive Summary

All previously identified **P0** blockers are now closed. The codebase is now in a materially better security posture for production:

- Unattended join now uses token-only trust with encrypted bootstrap payload delivery.
- Server-side RBAC is enforced for mutating API routes.
- Integration secrets are encrypted at rest, and local sensitive write paths enforce strict file permissions.

Remaining gaps are now **P2 resilience + maintainability** items:

1. Fuzz/sanitizer assurance for parser/runtime paths.
2. Large-file refactor slices to reduce long-term change risk.

## Domain Scorecard

- Control-plane: **Yellow/Green** (P0/P1 controls complete; P2 assurance/refactor remains)
- Dataplane: **Yellow/Green** (correctness solid; fuzz/chaos confidence still needed)
- API surface: **Yellow/Green** (authn/authz + hardening controls in place; contract consistency remains)
- UI: **Yellow/Green** (functional and auth-aware; primary remaining gap is large-file maintainability)
- Lifecycle/cluster management: **Green** on tested scenarios

## Findings (Severity-Ordered)

### P0-1: Cluster Join Plaintext Transport (Closed)

Area: control-plane / cluster management

Implemented:

- Join response payload now uses PSK-authenticated encryption (CHACHA20-POLY1305) instead of plaintext cert material.
- Join request/response HMAC verification is enforced before decrypt/persist.
- Bootstrap token rotation windows implemented with `valid_from` + `valid_until`.

Validation:

- `tests/cluster_join.rs` full suite passes, including join/failover paths.
- join bootstrap tamper tests pass in `src/controlplane/cluster/bootstrap/mod.rs`.

Rotation mechanism in place:

1. Add new token with future `valid_from` while old token remains active.
2. Roll token file update across nodes.
3. Set old token `valid_until` near cutover end.
4. Remove old token after expiry and convergence.

---

### P0-2: Server-side RBAC for protected API routes (Closed)

Area: API surface / control-plane auth

Implemented:

- Mutating HTTP methods require `admin` role in validated JWT claims.
- Missing/readonly roles on mutating routes return `403`.
- Read-only operations remain allowed with valid authenticated tokens.
- Cluster auth token mint RPC/CLI supports explicit roles (`--roles`).

Validation:

- `tests/http_api/authz_cases.rs` enforces readonly/missing-role deny and admin allow.
- `cargo test --test http_api` passes with authz regression coverage.

---

### P0-3: Integration secrets-at-rest and file permission hardening (Closed)

Area: control-plane storage

Implemented:

- Integration records now persist `service_account_token` as encrypted envelope (`service_account_token_envelope`) instead of plaintext token.
- Envelope encryption/decryption uses existing token-backed/local key material via sealed payloads.
- Local integration disk store writes now enforce `0600` (`index`, item files, and local integration secret key file).
- Service-account local store atomic writes now enforce `0600`.

Compatibility:

- Legacy plaintext integration records are still readable and are re-written in sealed form on update.

Validation:

- `controlplane::integrations::tests::disk_store_encrypts_service_account_token_at_rest`
- `controlplane::integrations::tests::disk_store_secret_files_use_600_permissions`
- `controlplane::service_accounts::tests::disk_store_files_use_600_permissions`
- Full `cargo test` pass confirms no regression.

## High Priority (P1)

### P1-1: Metrics endpoint exposure is easy to misconfigure (Closed)

Area: API/ops hardening

Implemented:

- HTTP API startup now denies public metrics binds by default.
- Explicit override is required via `NEUWERK_ALLOW_PUBLIC_METRICS_BIND=1`.
- Private/loopback/link-local/unspecified binds remain allowed by default.

Validation:

- `controlplane::http_api::tests::metrics_bind_guardrail_requires_override_for_public_bind`
- `tests/http_api/readiness_policy_cases::http_api_metrics_bind_public_requires_explicit_allow_override`

---

### P1-2: TLS key file permissions in cluster bootstrap (Closed)

Area: control-plane bootstrap

Implemented:

- Cluster TLS persistence now writes `node.key` with `0600`, cert files with `0644`.

Validation:

- `controlplane::cluster::bootstrap::tests::persist_tls_material_sets_private_key_to_600`

---

### P1-3: Integration endpoint validation is minimal (Closed)

Area: API/control-plane input validation

Implemented:

- Integration `api_server_url` is now strictly parsed as an absolute URL.
- `https://` is required for non-loopback hosts.
- `http://` is allowed only for loopback test endpoints (`localhost`, `127.0.0.1`, `::1`).

Validation:

- `controlplane::integrations::tests::rejects_non_https_non_loopback_api_server_url`
- `controlplane::integrations::tests::rejects_malformed_api_server_url`
- `controlplane::integrations::tests::allows_http_loopback_api_server_url_for_local_tests`

---

### P1-4: Bootstrap token file permissions were not enforced (Closed)

Area: cluster bootstrap secret handling

Implemented:

- `TokenStore::load(...)` now validates bootstrap token file permissions on Unix and rejects group/world-accessible files.
- Added explicit error reporting for insecure token file modes.
- Updated shared test/e2e token fixture writers to persist bootstrap token files with `0600`.

Validation:

- `controlplane::cluster::bootstrap::token::tests::rejects_group_world_readable_token_file`
- `controlplane::cluster::bootstrap::token::tests::accepts_strict_token_file_permissions`
- `cargo test --test cluster_join` and full `cargo test` pass after fixture permission updates.

## Medium Priority (P2)

### P2-1: Parser/runtime assurance still depends mostly on example-driven tests (In Progress)

Area: dataplane reliability/security

Remediation:

- Add `cargo-fuzz` targets for packet parser, overlay decap, TLS reassembly.
- Add sanitizer lane in CI/nightly.

Implemented in this pass:

- Added `fuzz/` harness with targets:
  - `packet_parse`
  - `overlay_decap`
  - `tls_reassembly`
- Added fuzz runner docs in `fuzz/README.md`.
- Verified target crate compiles via `cargo check --manifest-path fuzz/Cargo.toml`.
- Added automation entry points:
  - `make fuzz.check` (compilation check)
  - `make fuzz.smoke` (bounded smoke fuzz across all targets)
  - `make test.readiness.fuzz` (composed fuzz readiness lane)
  - `make fuzz.nightly` (time-bounded sanitizer lane via `scripts/fuzz-nightly.sh`)
- Added seeded corpus directories under `fuzz/corpus/*`.
- Added CI workflow definitions:
  - `.github/workflows/fuzz-smoke.yml` (PR + push `main`)
  - `.github/workflows/fuzz-nightly.yml` (scheduled + manual dispatch)
- Expanded seed corpus beyond minimal bootstrap bytes:
  - `fuzz/corpus/packet_parse/{seed-ipv4-udp,seed-ipv4-tcp,seed-arp}.bin`
  - `fuzz/corpus/overlay_decap/{seed-vxlan-ish,seed-geneve-ish,seed-none-ish}.bin`
  - `fuzz/corpus/tls_reassembly/{seed-client-hello-ish,seed-two-way-ish,seed-fragmented-ish}.bin`
- Updated fuzz scripts to invoke nightly explicitly (`cargo +nightly fuzz ...`) and fail/skip with explicit diagnostics when nightly is unavailable.
- Updated PR fuzz workflow toolchain to nightly to align with sanitizer requirements.
- Installed nightly toolchain in the current environment and executed:
  - `make fuzz.smoke` (bounded run; pass)
  - `make fuzz.nightly` (time-bounded address-sanitized run; pass after fix below)
- Fuzz-discovered runtime panic fixed in dataplane packet rewrite path:
  - root cause: unchecked `total_len - ihl` subtraction in `Packet::recalc_checksums` for malformed IPv4 headers.
  - fix: switched to `checked_sub` with early reject path in `src/dataplane/packet/impl_packet/rewrites.rs`.
  - regression test added: `recalc_checksums_rejects_malformed_ipv4_total_len_smaller_than_ihl` in `src/dataplane/packet/tests.rs`.

Remaining for closure:

- Validate sanitizer runtime/performance budgets on hosted CI with the expanded corpus and adjust per-target time budgets if nightly queue time increases.

### P2-2: API/UI error contract mismatch reduces operability (Closed)

Area: API surface + UI

Implemented:

- UI API client now parses backend `error` field first, then `message`, then status-text fallback.
- Auth login error handling follows the same contract.

Validation:

- `ui/services/api.test.ts` covers backend `{error}` parsing and `{message}` fallback.
- `npm --prefix ui test` passes.

## Maintainability Hotspots (Current)

Maintainability slice completed in this pass:

- Extracted service-account HTTP API domain from `src/controlplane/http_api.rs` into `src/controlplane/http_api/service_accounts_api.rs` (route handlers + request/response payload types), preserving behavior and test results.
- Extracted startup bind/address resolution from `src/main.rs` into `src/runtime/bootstrap/startup.rs::resolve_bindings` (management IP + HTTP/metrics bind + Azure DPDK override), preserving behavior and test results.
- Completed cluster startup extraction from `src/main.rs` into `src/runtime/bootstrap/startup.rs`:
  - `start_cluster_runtime(...)`
  - `run_cluster_migration_if_requested(...)`
- Extracted wiretap/audit bridge thread orchestration from `src/main.rs` into `src/runtime/startup/bridges.rs::spawn_event_bridges(...)`.
- Extracted DNS/HTTP control-plane runtime thread startup from `src/main.rs` into `src/runtime/startup/controlplane_threads.rs`:
  - `spawn_dns_runtime_thread(...)`
  - `spawn_http_runtime_thread(...)`
  - `HttpRuntimeThreadConfig`
- Extracted integration-manager startup orchestration from `src/main.rs` into `src/runtime/startup/integration_task.rs::spawn_integration_manager_task(...)`.
- Extracted dataplane bootstrap/channel orchestration from `src/main.rs` into `src/runtime/startup/dataplane_bootstrap.rs::bootstrap_dataplane_runtime(...)` (DPDK DHCP channels, DHCP client spawn, and IMDS fallback bootstrap task).
- Decomposed dataplane policy engine file:
  - policy evaluation path moved to `src/dataplane/policy/evaluation.rs`
  - TLS metadata evaluation moved to `src/dataplane/policy/tls_eval.rs`
  - policy unit tests moved to `src/dataplane/policy/tests.rs`
  - `src/dataplane/policy.rs` now acts as the type/constructor shell.
- Extracted policy activation wait + mode-mapping helpers out of `src/controlplane/http_api.rs` into `src/controlplane/http_api/policy_activation.rs` to keep router file focused on wiring and route lifecycle.
- Decomposed Azure cloud provider implementation:
  - `src/controlplane/cloud/providers/azure.rs` is now a thin shell (constants + constructor + includes)
  - helper/runtime methods moved to `src/controlplane/cloud/providers/azure/helpers.rs`
  - `CloudProvider` trait implementation now delegates through `src/controlplane/cloud/providers/azure/provider_impl.rs`
  - provider method-domain logic is split under `src/controlplane/cloud/providers/azure/provider_impl/{identity,discovery,routes,lifecycle}.rs`
  - existing provider tests preserved in `src/controlplane/cloud/providers/azure/tests.rs`
- Decomposed dataplane packet implementation:
  - `src/dataplane/packet/impl_packet.rs` is now an include shell
  - packet method implementations are split across `src/dataplane/packet/impl_packet/{core,icmp,ip_ports,checksum_updates,rewrites}.rs`
  - behavior preserved and validated by full suite pass.
- Further decomposed HTTP API router file:
  - extracted auth route handlers into `src/controlplane/http_api/auth_routes.rs` (`auth_token_login`, `auth_whoami`, `auth_logout`)
  - extracted app/system handlers into `src/controlplane/http_api/app_routes.rs` (`/health`, `/ready`, UI fallback, `/dns-cache`, `/stats`)
  - `src/controlplane/http_api.rs` reduced from 641 LOC to 416 LOC while preserving behavior.
- Continued `main.rs` startup extraction:
  - local policy-store bootstrap + local service/integration path derivation moved into `src/runtime/bootstrap/policy_state.rs::init_local_controlplane_state(...)`
  - soft dataplane auto-IP warmup task moved into `src/runtime/bootstrap/dataplane_warmup.rs::maybe_spawn_soft_dataplane_autoconfig_task(...)`
  - control-plane runtime orchestration (wiretap/audit bridges, policy replication, Kubernetes resolver, TLS-intercept readiness plumbing, DNS startup gate, allowlist GC, HTTP API startup) moved into `src/runtime/startup/controlplane_runtime.rs::start_controlplane_runtime(...)`
  - `src/main.rs` reduced further from 597 LOC to 366 LOC while preserving behavior and full-suite results.
- Further decomposed dataplane policy module internals:
  - `src/dataplane/policy.rs` is now a 14-LOC shell/re-export module.
  - core policy/domain types moved to `src/dataplane/policy/model.rs`.
  - dynamic IP/CIDR set logic moved to `src/dataplane/policy/ip_sets.rs`.
  - evaluation (`evaluation.rs`) and TLS policy matching (`tls_eval.rs`) remain isolated and behavior is unchanged.
- Decomposed policy UI page into shell + hook + modules:
  - `ui/pages/PoliciesPage.tsx` is now a thin page shell (`206` LOC, down from `1708`).
  - state/load/save/CRUD orchestration moved into `ui/pages/policies/usePolicyBuilder.ts`.
  - shared policy-page helpers moved into `ui/pages/policies/helpers.ts`.
  - extracted reusable view components under `ui/pages/policies/components/`:
    - `PolicySnapshotsPanel.tsx`
    - `YamlPreviewTab.tsx`
    - `StringListMapEditor.tsx`
    - `TlsNameMatchEditor.tsx`
  - extracted large form body into `ui/pages/policies/components/PolicyBuilderForm.tsx` for isolated follow-up section decomposition.
- Completed section-level decomposition of policy builder form:
  - `ui/pages/policies/components/PolicyBuilderForm.tsx` is now a thin shell (`44` LOC, down from `1108`).
  - policy/global controls moved to `ui/pages/policies/components/PolicyBasicsSection.tsx`.
  - source-group and kubernetes-source editing moved to `ui/pages/policies/components/SourceGroupsSection.tsx`.
  - per-rule editing moved to `ui/pages/policies/components/RuleEditor.tsx`.
  - TLS metadata mode editors moved to `ui/pages/policies/components/TlsMetadataSection.tsx`.
  - TLS intercept HTTP request/response editors moved to `ui/pages/policies/components/TlsInterceptHttpSection.tsx`.
  - shared form callback/type contracts live in `ui/pages/policies/components/formTypes.ts`.
- Further decomposed source-group editing to reduce section-file blast radius:
  - `ui/pages/policies/components/SourceGroupsSection.tsx` reduced to routing shell (`73` LOC).
  - group-level editor extracted to `ui/pages/policies/components/SourceGroupCard.tsx` (`289` LOC).
  - Kubernetes source list/card editor extracted to `ui/pages/policies/components/KubernetesSourcesEditor.tsx` (`238` LOC).
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed rule + TLS intercept editors into focused modules:
  - `ui/pages/policies/components/RuleEditor.tsx` reduced to composition shell (`42` LOC).
  - extracted `RuleHeaderSection.tsx` (rule identity/action/order controls).
  - extracted `RuleMatchCriteriaSection.tsx` (protocol/l4/dns/icmp match controls).
  - extracted `RuleTlsSection.tsx` (TLS mode toggle/orchestration + metadata/intercept dispatch).
  - `ui/pages/policies/components/TlsInterceptHttpSection.tsx` reduced to shell (`125` LOC).
  - extracted `TlsInterceptRequestSection.tsx` (request host/method/path/query/header constraints).
  - extracted `TlsInterceptResponseSection.tsx` (response header constraints).
  - shared rule-editor props are centralized in `ui/pages/policies/components/ruleEditorTypes.ts`.
  - behavior preserved; full UI and Rust suites remained green.
- Further decomposed source-group card internals:
  - `ui/pages/policies/components/SourceGroupCard.tsx` reduced to orchestrator (`63` LOC).
  - extracted `SourceGroupHeaderSection.tsx` (group id/priority/default + move/duplicate/delete).
  - extracted `SourceGroupSourcesSection.tsx` (CIDRs/IPs + Kubernetes source editor composition).
  - extracted `SourceGroupRulesSection.tsx` (rule template chooser + rule list controls).
  - shared source-group props are centralized in `ui/pages/policies/components/sourceGroupTypes.ts`.
  - behavior preserved; full UI and Rust suites remained green.
- Further decomposed intercept request + policy validation modules:
  - `ui/pages/policies/components/TlsInterceptRequestSection.tsx` reduced from `298` to `161` LOC.
  - extracted `TlsInterceptRequestQuerySection.tsx` (query key/value exact/regex matchers).
  - extracted `TlsInterceptRequestHeadersSection.tsx` (header presence/exact/regex matchers).
  - `ui/utils/policyValidation.ts` reduced from `502` to `331` LOC.
  - extracted TLS HTTP matcher validation logic into `ui/utils/policyValidation/tlsHttpValidation.ts` (regex helper, TLS name matcher validation, request/response HTTP matcher validation).
  - behavior preserved; full UI and Rust suites remained green.
- Completed `policyModel` domain split while preserving import compatibility:
  - extracted normalization pipeline (`normalizeTls*`, `normalizeSource*`, `normalizePolicy{Config,Request}`) into `ui/utils/policyModel/normalize.ts` (`397` LOC).
  - extracted API sanitize pipeline (`sanitizeTls*`, `sanitizePolicyRequestForApi`) into `ui/utils/policyModel/sanitize.ts` (`277` LOC).
  - `ui/utils/policyModel.ts` is now a thin compatibility shell (`28` LOC) that re-exports factory/id/normalize/sanitize entry points.
  - behavior preserved; full UI and Rust suites remained green (`npm --prefix ui test`, `npm --prefix ui run build`, `cargo fmt --all --check`, `cargo test --lib`, `cargo test`).
- Decomposed integrations UI page into shell + hook + focused components:
  - `ui/pages/IntegrationsPage.tsx` reduced from `435` LOC to `68` LOC shell.
  - state/load/select/save/delete orchestration moved into `ui/pages/integrations/useIntegrationsPage.ts` (`177` LOC).
  - extracted presentation modules:
    - `ui/pages/integrations/components/IntegrationsHeader.tsx`
    - `ui/pages/integrations/components/IntegrationsListPanel.tsx`
    - `ui/pages/integrations/components/IntegrationEditorPanel.tsx`
  - form contracts/helpers moved into `ui/pages/integrations/types.ts`.
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed wiretap UI page into shell + hook + focused components:
  - `ui/pages/WiretapPage.tsx` reduced from `327` LOC to `53` LOC shell.
  - stream lifecycle/filter/view-mode orchestration moved into `ui/pages/wiretap/useWiretapPage.ts` (`127` LOC).
  - extracted utility/domain helpers into `ui/pages/wiretap/helpers.ts` and `ui/pages/wiretap/types.ts`.
  - extracted presentation modules:
    - `ui/pages/wiretap/components/WiretapViewModeToggle.tsx`
    - `ui/pages/wiretap/components/WiretapStatusBanners.tsx`
    - `ui/pages/wiretap/components/WiretapLiveTable.tsx`
    - `ui/pages/wiretap/components/WiretapAggregatedTable.tsx`
  - stream reconnect behavior is now stable across pause/resume toggles (pause no longer tears down and recreates SSE subscription).
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed service-accounts UI page into shell + hook + focused components:
  - `ui/pages/ServiceAccountsPage.tsx` reduced from `324` LOC to `110` LOC shell.
  - state/load/select/create/revoke orchestration moved into `ui/pages/service-accounts/useServiceAccountsPage.ts` (`135` LOC).
  - extracted token UI modules:
    - `ui/pages/service-accounts/components/CreateTokenModal.tsx`
    - `ui/pages/service-accounts/components/ServiceAccountTokensPanel.tsx`
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed UI API client into domain modules with shared transport/error handling:
  - `ui/services/api.ts` reduced to a compatibility barrel (`32` LOC) to preserve existing imports.
  - extracted shared transport/auth helpers into `ui/services/apiClient/transport.ts` (`APIError`, JSON/text fetch wrappers, cookie-auth defaults).
  - extracted domain clients into:
    - `ui/services/apiClient/auth.ts`
    - `ui/services/apiClient/policies.ts`
    - `ui/services/apiClient/integrations.ts`
    - `ui/services/apiClient/dns.ts`
    - `ui/services/apiClient/audit.ts`
    - `ui/services/apiClient/wiretap.ts`
    - `ui/services/apiClient/serviceAccounts.ts`
    - `ui/services/apiClient/settings.ts`
  - behavior preserved; `ui/services/api.test.ts` continues passing.
- Decomposed UI shared types into feature modules with a stable barrel:
  - `ui/types.ts` reduced to a re-export barrel (`9` LOC).
  - type domains now live in:
    - `ui/types/policy.ts`
    - `ui/types/integrations.ts`
    - `ui/types/stats.ts`
    - `ui/types/dns.ts`
    - `ui/types/wiretap.ts`
    - `ui/types/audit.ts`
    - `ui/types/auth.ts`
    - `ui/types/serviceAccounts.ts`
    - `ui/types/settings.ts`
  - behavior preserved while reducing cross-domain type blast radius.
- Extracted routing/navigation metadata out of app shell components:
  - added `ui/navigation.ts` for canonical page IDs, path parsing, path rendering, and nav definitions.
  - added `ui/app/renderPage.tsx` for page-component mapping.
  - `ui/App.tsx` now consumes typed `AppPage` + shared navigation helpers instead of local page string/switch state.
  - `ui/components/Sidebar.tsx` now consumes shared `NAV_ITEMS` and typed page IDs, reducing drift between router and navigation.
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed dashboard page into shell + hook + focused components:
  - `ui/pages/Dashboard.tsx` reduced from `166` LOC to `28` LOC shell.
  - stats polling/orchestration moved into `ui/pages/dashboard/useDashboardStats.ts`.
  - formatting helpers moved into `ui/pages/dashboard/helpers.ts`.
  - extracted rendering modules:
    - `ui/pages/dashboard/components/DashboardStatsView.tsx`
    - `ui/pages/dashboard/components/StatCard.tsx`
    - `ui/pages/dashboard/components/Metric.tsx`
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed audit page into shell + hook + focused components:
  - `ui/pages/AuditPage.tsx` reduced from `163` LOC to `79` LOC shell.
  - query/filter/load orchestration moved into `ui/pages/audit/useAuditPage.ts`.
  - extracted helper/constants modules:
    - `ui/pages/audit/helpers.ts`
    - `ui/pages/audit/constants.ts`
  - extracted rendering modules:
    - `ui/pages/audit/components/AuditFiltersPanel.tsx`
    - `ui/pages/audit/components/AuditNodeErrorsPanel.tsx`
    - `ui/pages/audit/components/AuditFindingsTable.tsx`
  - behavior preserved; full UI and Rust suites remained green.
- Decomposed DNS cache page into shell + hook + focused components:
  - `ui/pages/DNSCachePage.tsx` reduced from `162` LOC to `47` LOC shell.
  - data load/filter state moved into `ui/pages/dns-cache/useDNSCachePage.ts`.
  - extracted rendering/controls modules:
    - `ui/pages/dns-cache/components/DNSCacheControls.tsx`
    - `ui/pages/dns-cache/components/DNSCacheTable.tsx`
  - extracted filtering/timestamp helpers into `ui/pages/dns-cache/helpers.ts`.
  - added regression tests in `ui/pages/dns-cache/helpers.test.ts`.
- Decomposed settings page into shell + hook + focused components:
  - `ui/pages/SettingsPage.tsx` reduced from `130` LOC to `54` LOC shell.
  - load/submit orchestration moved into `ui/pages/settings/useSettingsPage.ts`.
  - extracted rendering modules:
    - `ui/pages/settings/components/SettingsStatusCard.tsx`
    - `ui/pages/settings/components/TlsInterceptCaForm.tsx`
  - extracted CA input validation helper into `ui/pages/settings/helpers.ts`.
  - added regression tests in `ui/pages/settings/helpers.test.ts`.
- Decomposed wiretap filters into focused subcomponents:
  - `ui/components/WiretapFilters.tsx` reduced from `149` LOC to `37` LOC shell.
  - filter form field rendering moved to `ui/components/wiretap/WiretapFilterFields.tsx`.
  - stream control/status rendering moved to `ui/components/wiretap/WiretapStreamControls.tsx`.
  - shared filter model moved to `ui/components/wiretap/types.ts`.
- Decomposed key-value editor into shell + helper + row/list modules:
  - `ui/components/KeyValueEditor.tsx` reduced from `149` LOC to `90` LOC shell.
  - row rendering moved to `ui/components/key-value/KeyValueEntryRow.tsx`.
  - list mapping/entry composition moved to `ui/components/key-value/KeyValueEntriesList.tsx`.
  - pure map mutation helpers moved to `ui/components/key-value/state.ts`.
  - added regression tests in `ui/components/key-value/state.test.ts`.
- Decomposed integration editor panel into header/sections/actions modules:
  - `ui/pages/integrations/components/IntegrationEditorPanel.tsx` reduced from `175` LOC to `60` LOC shell.
  - header/delete controls moved to `ui/pages/integrations/components/IntegrationEditorHeader.tsx`.
  - name/type/api-server controls moved to `ui/pages/integrations/components/IntegrationBasicsSection.tsx`.
  - CA/token credential controls moved to `ui/pages/integrations/components/IntegrationCredentialsSection.tsx`.
  - save/reset controls moved to `ui/pages/integrations/components/IntegrationEditorActions.tsx`.
- Decomposed service-account table into shell + row/status/empty-state modules:
  - `ui/components/service-accounts/ServiceAccountTable.tsx` reduced from `104` LOC to `47` LOC shell.
  - row rendering/actions moved to `ui/components/service-accounts/ServiceAccountTableRow.tsx`.
  - status badge rendering moved to `ui/components/service-accounts/ServiceAccountStatusBadge.tsx`.
  - empty-state rendering moved to `ui/components/service-accounts/ServiceAccountTableEmptyState.tsx`.
  - extracted formatting/status helpers to `ui/components/service-accounts/helpers.ts`.
  - added helper regression tests in `ui/components/service-accounts/helpers.test.ts`.
- Completed policy validation split by domain (core group/rule checks vs TLS checks):
  - `ui/utils/policyValidation.ts` reduced from `331` LOC to `45` LOC orchestration shell.
  - source-group validation moved to `ui/utils/policyValidation/sourceGroupValidation.ts`.
  - rule core/proto/port/icmp validation moved to `ui/utils/policyValidation/ruleMatchValidation.ts`.
  - TLS matcher/mode/intercept validation moved to `ui/utils/policyValidation/tlsMatchValidation.ts`.
  - existing TLS HTTP matcher helpers remain in `ui/utils/policyValidation/tlsHttpValidation.ts`.
  - added policy validation regression tests in `ui/utils/policyValidation.test.ts`.
- Decomposed service-account create modal into shell + form/actions + request helper:
  - `ui/components/service-accounts/CreateServiceAccountModal.tsx` reduced from `125` LOC to `84` LOC shell.
  - identity fields moved to `ui/components/service-accounts/CreateServiceAccountModalFields.tsx`.
  - submit/cancel actions moved to `ui/components/service-accounts/CreateServiceAccountModalActions.tsx`.
  - request normalization/validation moved to `ui/components/service-accounts/createForm.ts`.
  - added helper regression tests in `ui/components/service-accounts/createForm.test.ts`.
- Split integrations page hook by concern (remote orchestration vs form mutators):
  - `ui/pages/integrations/useIntegrationsPage.ts` reduced from `177` LOC to `139` LOC.
  - remote API orchestration moved to `ui/pages/integrations/remote.ts`.
  - form validation/normalization moved to `ui/pages/integrations/formValidation.ts`.
  - added validation regression tests in `ui/pages/integrations/formValidation.test.ts`.
- Further decomposed service-account orchestration and token-panel logic:
  - `ui/pages/service-accounts/useServiceAccountsPage.ts` reduced from `135` LOC to `69` LOC.
  - account-level API orchestration moved to `ui/pages/service-accounts/remote.ts`.
  - shared UI error mapping moved to `ui/pages/service-accounts/helpers.ts`.
  - token panel selection/load/create/revoke orchestration moved to `ui/pages/service-accounts/useServiceAccountTokenPanel.ts` (`87` LOC).
  - added regression tests in `ui/pages/service-accounts/helpers.test.ts`.
- Decomposed auth login page into shell + hook + form + helpers:
  - `ui/components/auth/LoginPage.tsx` reduced from `92` LOC to `40` LOC shell.
  - token submit/load/error orchestration moved to `ui/components/auth/useTokenLogin.ts`.
  - token form rendering moved to `ui/components/auth/LoginTokenForm.tsx`.
  - input validation + error mapping moved to `ui/components/auth/loginHelpers.ts`.
  - added helper regression tests in `ui/components/auth/loginHelpers.test.ts`.
- Decomposed service-account token panel table internals:
  - `ui/pages/service-accounts/components/ServiceAccountTokensPanel.tsx` reduced from `134` LOC to `67` LOC shell.
  - table structure moved to `ui/pages/service-accounts/components/ServiceAccountTokensTable.tsx`.
  - row rendering/actions moved to `ui/pages/service-accounts/components/ServiceAccountTokenTableRow.tsx`.
  - token timestamp/status helpers moved to `ui/pages/service-accounts/components/tokenTableHelpers.ts`.
  - helper regression tests added in `ui/pages/service-accounts/components/tokenTableHelpers.test.ts`.
- Decomposed policy-page helper module by concern and added direct helper tests:
  - `ui/pages/policies/helpers.ts` reduced from `94` LOC to `25` LOC compatibility shell.
  - list/text/protocol conversion helpers moved to `ui/pages/policies/valueCodec.ts`.
  - default draft object/id/move/issue helpers moved to `ui/pages/policies/policyDraftHelpers.ts`.
  - added coverage in `ui/pages/policies/helpers.test.ts` for conversion, proto parsing, move bounds, duplicate ID behavior, and validation-issue formatting.
- Decomposed wiretap aggregated table internals and extracted table config helpers:
  - `ui/pages/wiretap/components/WiretapAggregatedTable.tsx` reduced from `94` LOC to `44` LOC shell.
  - row rendering moved to `ui/pages/wiretap/components/WiretapAggregatedTableRow.tsx`.
  - column configuration and flow/hostname formatting moved to `ui/pages/wiretap/components/aggregatedTableHelpers.ts`.
  - helper regression tests added in `ui/pages/wiretap/components/aggregatedTableHelpers.test.ts`.
- Added shared TLS-intercept request draft mutation helpers:
  - `ui/pages/policies/components/TlsInterceptRequestQuerySection.tsx` reduced from `94` LOC to `74` LOC.
  - `ui/pages/policies/components/TlsInterceptRequestHeadersSection.tsx` reduced from `98` LOC to `86` LOC.
  - shared request access/defaulting logic moved to `ui/pages/policies/components/tlsInterceptRequestDraft.ts`.
  - `TlsInterceptRequestSection.tsx` host/method/path mutators now also use the shared draft helper.
  - regression coverage added in `ui/pages/policies/components/tlsInterceptRequestDraft.test.ts`.
- Decomposed service-account token create modal and isolated request/preset logic:
  - `ui/pages/service-accounts/components/CreateTokenModal.tsx` reduced from `95` LOC to `46` LOC shell.
  - input rendering moved to `ui/pages/service-accounts/components/CreateTokenModalFields.tsx` (`84` LOC).
  - action buttons moved to `ui/pages/service-accounts/components/CreateTokenModalActions.tsx`.
  - request normalization + TTL preset definitions moved to `ui/pages/service-accounts/components/createTokenForm.ts`.
  - helper regression tests added in `ui/pages/service-accounts/components/createTokenForm.test.ts`.
- Further decomposed TLS intercept request section internals:
  - `ui/pages/policies/components/TlsInterceptRequestSection.tsx` reduced from `147` LOC to `73` LOC shell.
  - methods editor extracted to `ui/pages/policies/components/TlsInterceptRequestMethodsField.tsx`.
  - path exact/prefix/regex editors extracted to `ui/pages/policies/components/TlsInterceptRequestPathSection.tsx`.
  - shared path defaulting moved into `ensureTlsRequestPath(...)` in `ui/pages/policies/components/tlsInterceptRequestDraft.ts`.
  - regression tests extended in `ui/pages/policies/components/tlsInterceptRequestDraft.test.ts` for path defaulting behavior.
- Decomposed wiretap live table internals and extracted table config helpers:
  - `ui/pages/wiretap/components/WiretapLiveTable.tsx` reduced from `89` LOC to `44` LOC shell.
  - live row rendering moved to `ui/pages/wiretap/components/WiretapLiveTableRow.tsx`.
  - live table column config + flow/hostname formatting moved to `ui/pages/wiretap/components/liveTableHelpers.ts`.
  - helper regression tests added in `ui/pages/wiretap/components/liveTableHelpers.test.ts`.
- Decomposed policy snapshots panel internals and extracted snapshot-format helpers:
  - `ui/pages/policies/components/PolicySnapshotsPanel.tsx` reduced from `84` LOC to `53` LOC shell.
  - policy snapshot row rendering/actions moved to `ui/pages/policies/components/PolicySnapshotRow.tsx`.
  - snapshot id/timestamp formatting moved to `ui/pages/policies/components/policySnapshotHelpers.ts`.
  - helper regression tests added in `ui/pages/policies/components/policySnapshotHelpers.test.ts`.
- Decomposed key-value editor internals into focused reusable modules:
  - `ui/components/KeyValueEditor.tsx` reduced from `90` LOC to `77` LOC shell.
  - `ui/components/key-value/KeyValueEntryRow.tsx` reduced from `88` LOC to `67` LOC.
  - entry input rendering extracted to `ui/components/key-value/KeyValueEntryInput.tsx`.
  - editor header/add-button extracted to `ui/components/key-value/KeyValueEditorHeader.tsx`.
  - empty-state rendering extracted to `ui/components/key-value/KeyValueEditorEmptyState.tsx`.
  - field-path/error lookup helpers extracted to `ui/components/key-value/fieldErrors.ts` with regression tests in `ui/components/key-value/fieldErrors.test.ts`.
  - shared datalist id centralized in `ui/components/key-value/constants.ts`.
- Decomposed rule match criteria editor by matcher domain:
  - `ui/pages/policies/components/RuleMatchCriteriaSection.tsx` reduced from `248` LOC to `18` LOC shell.
  - extracted matcher sections to:
    - `ui/pages/policies/components/RuleMatchProtocolDnsSection.tsx`
    - `ui/pages/policies/components/RuleMatchDestinationSection.tsx`
    - `ui/pages/policies/components/RuleMatchPortsSection.tsx`
    - `ui/pages/policies/components/RuleMatchIcmpSection.tsx`
  - shared guarded draft mutation helper centralized in `ui/pages/policies/components/ruleMatchDraft.ts`.
  - regression tests added in `ui/pages/policies/components/ruleMatchDraft.test.ts`.
- Decomposed Kubernetes source editor by card/field domain:
  - `ui/pages/policies/components/KubernetesSourcesEditor.tsx` reduced from `238` LOC to `59` LOC shell.
  - source card composition moved to `ui/pages/policies/components/KubernetesSourceCard.tsx`.
  - integration selector/input/remove row moved to `ui/pages/policies/components/KubernetesSourceIntegrationRow.tsx`.
  - selector type toggle moved to `ui/pages/policies/components/KubernetesSourceSelectorTypeRow.tsx`.
  - pod/node selector field editors moved to:
    - `ui/pages/policies/components/KubernetesPodSelectorFields.tsx`
    - `ui/pages/policies/components/KubernetesNodeSelectorFields.tsx`
  - shared guarded draft mutation helper centralized in `ui/pages/policies/components/kubernetesSourceDraft.ts`.
  - regression tests added in `ui/pages/policies/components/kubernetesSourceDraft.test.ts`.
- Decomposed TLS rule editor controls and metadata matcher sections:
  - `ui/pages/policies/components/RuleTlsSection.tsx` reduced from `143` LOC to `70` LOC shell.
  - extracted TLS header toggle to `ui/pages/policies/components/RuleTlsHeader.tsx`.
  - extracted TLS mode/TLS1.3 controls to `ui/pages/policies/components/RuleTlsModeControls.tsx`.
  - `ui/pages/policies/components/TlsMetadataSection.tsx` reduced from `166` LOC to `70` LOC shell.
  - extracted metadata subsections to:
    - `ui/pages/policies/components/TlsMetadataNameMatchersSection.tsx`
    - `ui/pages/policies/components/TlsMetadataServerDnField.tsx`
    - `ui/pages/policies/components/TlsMetadataFingerprintField.tsx`
    - `ui/pages/policies/components/TlsMetadataTrustAnchorsSection.tsx`
  - shared guarded TLS draft mutation + mode/toggle semantics centralized in `ui/pages/policies/components/ruleTlsDraft.ts`.
  - regression tests added in `ui/pages/policies/components/ruleTlsDraft.test.ts`.
- Decomposed source-group rules section into focused toolbar/list modules:
  - `ui/pages/policies/components/SourceGroupRulesSection.tsx` reduced from `111` LOC to `56` LOC shell.
  - template selector + add actions moved to `ui/pages/policies/components/SourceGroupRulesToolbar.tsx`.
  - rule list rendering moved to `ui/pages/policies/components/SourceGroupRulesList.tsx`.
  - empty-state rendering moved to `ui/pages/policies/components/SourceGroupRulesEmptyState.tsx`.
  - template selection/update helpers centralized in `ui/pages/policies/components/sourceGroupRulesDraft.ts`.
  - regression tests added in `ui/pages/policies/components/sourceGroupRulesDraft.test.ts`.
- Decomposed protocol+DNS rule match editor into field components with pure mutation helpers:
  - `ui/pages/policies/components/RuleMatchProtocolDnsSection.tsx` reduced from `101` LOC to `14` LOC shell.
  - protocol selector/custom-input field moved to `ui/pages/policies/components/RuleMatchProtocolField.tsx`.
  - DNS hostname matcher field moved to `ui/pages/policies/components/RuleMatchDnsHostnameField.tsx`.
  - protocol selection + DNS normalization helpers centralized in `ui/pages/policies/components/ruleMatchProtocolDraft.ts`.
  - regression tests added in `ui/pages/policies/components/ruleMatchProtocolDraft.test.ts`.
- Extracted policy-builder group/rule mutation domain out of `usePolicyBuilder` hook:
  - `ui/pages/policies/usePolicyBuilder.ts` reduced from `303` LOC to `295` LOC (hook remains orchestration-focused).
  - group/rule lifecycle mutation helpers centralized in `ui/pages/policies/policyBuilderDraftMutations.ts`:
    - add/duplicate/move/delete group
    - add/add-template/duplicate/move/delete rule
  - regression tests added in `ui/pages/policies/policyBuilderDraftMutations.test.ts`.
- Extracted policy-builder remote API lifecycle orchestration out of `usePolicyBuilder`:
  - `ui/pages/policies/usePolicyBuilder.ts` reduced further from `295` LOC to `286` LOC.
  - remote orchestration moved to `ui/pages/policies/policyBuilderRemote.ts`:
    - policy list load + created_at sorting
    - integration load + kubernetes filtering
    - policy snapshot load + normalization
    - create/update save path normalization
    - delete path wrapper
  - regression tests added in `ui/pages/policies/policyBuilderRemote.test.ts`.
- Decomposed policy-model sanitize pipeline into domain modules:
  - `ui/utils/policyModel/sanitize.ts` reduced from `277` LOC to `1` LOC compatibility shell.
  - extracted request-level orchestration to `ui/utils/policyModel/sanitize/request.ts`.
  - extracted source-group source sanitization to `ui/utils/policyModel/sanitize/sources.ts`.
  - extracted rule/match sanitization to `ui/utils/policyModel/sanitize/rules.ts`.
  - extracted TLS+HTTP matcher sanitization to `ui/utils/policyModel/sanitize/tls.ts`.
  - extracted shared string/map/list helpers to `ui/utils/policyModel/sanitize/shared.ts`.
  - added dedicated regression coverage in `ui/utils/policyModel/sanitize.test.ts` for:
    - source/rule trimming and kubernetes-source filtering
    - selector-only kubernetes source preservation semantics
    - empty/default TLS object elision
    - intercept TLS HTTP matcher sanitization + method uppercasing
- Further decomposed policy-builder orchestration hook by derived-state and action wiring:
  - `ui/pages/policies/usePolicyBuilder.ts` reduced from `286` LOC to `228` LOC.
  - extracted derived state helpers/hook into `ui/pages/policies/usePolicyBuilderDerived.ts`:
    - integration-name set derivation
    - policy validation issue derivation
    - sanitized YAML preview derivation
  - extracted group/rule draft action wiring into `ui/pages/policies/policyBuilderDraftActions.ts`:
    - add/duplicate/move/delete group
    - add/add-template/duplicate/move/delete rule
  - added helper coverage in `ui/pages/policies/usePolicyBuilderDerived.test.ts` for:
    - integration-name set deduplication
    - validation issue derivation from known integration set
    - YAML preview semantic equivalence to sanitized API payload
- Decomposed dashboard stats view into focused render sections:
  - `ui/pages/dashboard/components/DashboardStatsView.tsx` reduced from `214` LOC to `36` LOC shell.
  - extracted section/render modules:
    - `DashboardHeader.tsx`
    - `DashboardOverviewCards.tsx`
    - `DashboardDataplaneSection.tsx`
    - `DashboardControlPlaneSection.tsx`
    - `DashboardBytesSection.tsx`
    - `DashboardSystemSection.tsx`
    - `DashboardRaftCatchupSection.tsx`
    - shared frame wrapper `DashboardSectionCard.tsx`
  - added helper regression tests in `ui/pages/dashboard/helpers.test.ts` for number/bytes/epoch formatting behavior.
- Decomposed policies page shell into focused page modules:
  - `ui/pages/PoliciesPage.tsx` reduced from `200` LOC to `108` LOC shell.
  - extracted top header/actions into `ui/pages/policies/components/PoliciesPageHeader.tsx`.
  - extracted editor card (builder/yaml tabs + validation/error panels) into `ui/pages/policies/components/PolicyEditorCard.tsx`.
  - extracted bottom save/revert action row into `ui/pages/policies/components/PolicyEditorActions.tsx`.
  - extracted page helper logic to `ui/pages/policies/components/policiesPageHelpers.ts`.
  - added helper regression tests in `ui/pages/policies/components/policiesPageHelpers.test.ts`.
- Decomposed TLS HTTP validation helpers by request/response/name domains:
  - `ui/utils/policyValidation/tlsHttpValidation.ts` reduced from `204` LOC to `5` LOC compatibility shell.
  - extracted shared types + regex helper:
    - `ui/utils/policyValidation/tlsHttpValidation/types.ts`
    - `ui/utils/policyValidation/tlsHttpValidation/regex.ts`
  - extracted TLS-name matcher validation to `ui/utils/policyValidation/tlsHttpValidation/tlsName.ts`.
  - extracted request matcher validation to `ui/utils/policyValidation/tlsHttpValidation/request.ts`.
  - extracted response-header matcher validation to `ui/utils/policyValidation/tlsHttpValidation/response.ts`.
  - added focused regression coverage in `ui/utils/policyValidation/tlsHttpValidation.test.ts`:
    - regex validity checks
    - TLS name matcher empty/regex errors
    - HTTP request matcher method/path/query/header errors
    - HTTP response header matcher regex errors
- Decomposed sidebar shell into focused navigation modules:
  - `ui/components/Sidebar.tsx` reduced from `175` LOC to `45` LOC shell.
  - extracted sidebar modules:
    - `ui/components/sidebar/SidebarHeader.tsx`
    - `ui/components/sidebar/SidebarNav.tsx`
    - `ui/components/sidebar/SidebarNavItem.tsx`
    - `ui/components/sidebar/SidebarFooter.tsx`
    - `ui/components/sidebar/constants.tsx`
    - `ui/components/sidebar/helpers.ts`
  - added helper regression tests in `ui/components/sidebar/helpers.test.ts` for:
    - admin/readonly nav filtering
    - active/inactive nav style derivation
    - hover style apply/clear semantics
- Decomposed TLS policy-model normalization by name/http/match domains:
  - `ui/utils/policyModel/normalize/tls.ts` reduced from `156` LOC to `2` LOC compatibility shell.
  - extracted name matcher normalization to `ui/utils/policyModel/normalize/tls/name.ts`.
  - extracted HTTP request/response matcher normalization to `ui/utils/policyModel/normalize/tls/http.ts`.
  - extracted top-level TLS match normalization to `ui/utils/policyModel/normalize/tls/match.ts`.
  - added focused regression coverage in `ui/utils/policyModel/normalize/tls.test.ts` for:
    - string/list/object TLS name matcher normalization
    - intercept-mode HTTP request/response matcher normalization
    - empty metadata-only TLS matcher elision
- Extracted policy-builder lifecycle orchestration from `usePolicyBuilder`:
  - `ui/pages/policies/usePolicyBuilder.ts` reduced from `218` LOC to `158` LOC.
  - lifecycle handlers moved to `ui/pages/policies/policyBuilderLifecycle.ts`:
    - `handleCreate`
    - `loadEditorForPolicy`
    - `loadAll`
    - `handleDelete`
    - `handleSave`
  - extracted deterministic helper logic:
    - `deriveLoadAllFollowUp(...)`
    - `errorMessage(...)`
  - added helper coverage in `ui/pages/policies/policyBuilderLifecycle.test.ts`.
- Decomposed TLS sanitize helpers by name/http/match domains:
  - `ui/utils/policyModel/sanitize/tls.ts` reduced from `153` LOC to `1` LOC compatibility shell.
  - extracted name matcher sanitize logic to `ui/utils/policyModel/sanitize/tls/name.ts`.
  - extracted HTTP request/response matcher sanitize logic to `ui/utils/policyModel/sanitize/tls/http.ts`.
  - extracted top-level TLS sanitize logic to `ui/utils/policyModel/sanitize/tls/match.ts`.
  - existing sanitize regression coverage (`ui/utils/policyModel/sanitize.test.ts`) remains green across the split.
- Further decomposed policy-builder lifecycle module into flow/helpers/types:
  - `ui/pages/policies/policyBuilderLifecycle.ts` reduced from `164` LOC to `4` LOC compatibility shell.
  - lifecycle orchestration flow moved to `ui/pages/policies/policyBuilderLifecycleFlow.ts`.
  - follow-up/error helper logic moved to `ui/pages/policies/policyBuilderLifecycleHelpers.ts`.
  - lifecycle dependency/handler types moved to `ui/pages/policies/policyBuilderTypes.ts`.
  - existing lifecycle regression coverage (`ui/pages/policies/policyBuilderLifecycle.test.ts`) remains green.
- Decomposed rule header editor into fields/actions and draft helpers:
  - `ui/pages/policies/components/RuleHeaderSection.tsx` reduced from `150` LOC to `33` LOC shell.
  - rule identity/priority/action/mode controls moved to `ui/pages/policies/components/RuleHeaderFields.tsx`.
  - move/duplicate/delete action buttons moved to `ui/pages/policies/components/RuleHeaderActions.tsx`.
  - guarded rule-header mutation helpers moved to `ui/pages/policies/components/ruleHeaderDraft.ts`.
  - helper regression tests added in `ui/pages/policies/components/ruleHeaderDraft.test.ts`.
- Further decomposed policy editor card rendering:
  - `ui/pages/policies/components/PolicyEditorCard.tsx` reduced from `134` LOC to `84` LOC shell.
  - header + tab controls moved to `ui/pages/policies/components/PolicyEditorHeader.tsx`.
  - validation/error rendering moved to `ui/pages/policies/components/PolicyEditorMessages.tsx`.
- Decomposed TLS rule validation by domain:
  - `ui/utils/policyValidation/tlsMatchValidation.ts` reduced from `132` LOC to `53` LOC orchestration shell.
  - metadata matcher validation moved to `ui/utils/policyValidation/tlsMatchValidation/metadata.ts`.
  - mode/intercept semantics moved to `ui/utils/policyValidation/tlsMatchValidation/mode.ts`.
  - shared issue type moved to `ui/utils/policyValidation/tlsMatchValidation/types.ts`.
  - regression tests added in `ui/utils/policyValidation/tlsMatchValidation.test.ts`.
- Decomposed integrations lifecycle orchestration by operation:
  - `ui/pages/integrations/useIntegrationsPageLifecycle.ts` reduced from `112` LOC to `68` LOC composition shell.
  - split operation handlers under `ui/pages/integrations/lifecycle/`:
    - `createNew.ts`
    - `select.ts`
    - `load.ts`
    - `save.ts`
    - `delete.ts`
  - save follow-up helper regression coverage added in `ui/pages/integrations/lifecycle/save.test.ts`.
- Decomposed source-group header rendering and mutation helpers:
  - `ui/pages/policies/components/SourceGroupHeaderSection.tsx` reduced from `129` LOC to `30` LOC shell.
  - fields/actions rendering moved to:
    - `ui/pages/policies/components/SourceGroupHeaderFields.tsx`
    - `ui/pages/policies/components/SourceGroupHeaderActions.tsx`
  - guarded draft mutations centralized in `ui/pages/policies/components/sourceGroupHeaderDraft.ts`.
  - helper regression coverage added in `ui/pages/policies/components/sourceGroupHeaderDraft.test.ts`.
- Decomposed wiretap page state/connection orchestration:
  - `ui/pages/wiretap/useWiretapPage.ts` reduced from `127` LOC to `74` LOC.
  - SSE connect/reconnect lifecycle moved to `ui/pages/wiretap/useWiretapConnection.ts`.
  - event upsert/buffer/default-filter state helpers moved to `ui/pages/wiretap/state.ts`.
  - helper regression coverage added in `ui/pages/wiretap/state.test.ts`.
- Decomposed rule-match validation helpers by basics/core domains:
  - `ui/utils/policyValidation/ruleMatchValidation.ts` is now a thin compatibility shell.
  - basic rule field checks moved to `ui/utils/policyValidation/ruleMatchValidation/basics.ts`.
  - match proto/port/dns/icmp checks moved to `ui/utils/policyValidation/ruleMatchValidation/matchCore.ts`.
  - shared issue shape moved to `ui/utils/policyValidation/ruleMatchValidation/types.ts`.
  - regression tests added in `ui/utils/policyValidation/ruleMatchValidation.test.ts`.
- Decomposed policy-model rule template construction:
  - `ui/utils/policyModel/factories.ts` reduced from `136` LOC to `53` LOC.
  - rule template builders moved to `ui/utils/policyModel/ruleTemplates.ts`.
  - regression tests added in `ui/utils/policyModel/factories.test.ts`.
- Decomposed TLS intercept HTTP section controls and draft mutations:
  - `ui/pages/policies/components/TlsInterceptHttpSection.tsx` reduced from `125` LOC to `71` LOC.
  - request/response enable/disable controls extracted to `ui/pages/policies/components/TlsInterceptConstraintControls.tsx`.
  - request/response draft mutations centralized in `ui/pages/policies/components/tlsInterceptHttpDraft.ts`.
  - regression tests added in `ui/pages/policies/components/tlsInterceptHttpDraft.test.ts`.
- Decomposed string-list map editor and centralized row mutation helpers:
  - `ui/pages/policies/components/StringListMapEditor.tsx` reduced from `125` LOC to `68` LOC.
  - row rendering extracted to `ui/pages/policies/components/StringListMapEntryRow.tsx`.
  - empty-state rendering extracted to `ui/pages/policies/components/StringListMapEmptyState.tsx`.
  - deterministic add/rename/remove/update helpers centralized in `ui/pages/policies/components/stringListMapDraft.ts`.
  - regression tests added in `ui/pages/policies/components/stringListMapDraft.test.ts`.

Rust source hotspots (non-test paths):

- `src/controlplane/metrics/construct.rs` -> 873 LOC
- `src/controlplane/integrations.rs` -> 867 LOC
- `src/dataplane/overlay.rs` -> 837 LOC
- `src/controlplane/dns_proxy.rs` -> 830 LOC
- `src/controlplane/cloud/mod.rs` -> 830 LOC
- `src/runtime/dpdk/run.rs` -> 811 LOC
- `src/bin/e2e_kind_harness.rs` -> 796 LOC
- `src/controlplane/dhcp.rs` -> 746 LOC
- `src/controlplane/cluster/store.rs` -> 739 LOC
- `src/controlplane/kubernetes.rs` -> 713 LOC
- `src/runtime/cli/args.rs` -> 662 LOC
- `src/controlplane/cluster/migration.rs` -> 653 LOC
- `src/controlplane/api_auth.rs` -> 618 LOC
- `src/controlplane/service_accounts.rs` -> 606 LOC

UI hotspots:

- `ui/index.css` -> 245 LOC
- `ui/types/policy.ts` -> 125 LOC
- `ui/pages/policies/usePolicyBuilder.ts` -> 116 LOC
- `ui/pages/ServiceAccountsPage.tsx` -> 110 LOC
- `ui/pages/policies/policyBuilderDraftMutations.ts` -> 109 LOC
- `ui/pages/PoliciesPage.tsx` -> 108 LOC
- `ui/utils/policyModel/normalize/shared.ts` -> 107 LOC
- `ui/pages/policies/components/TlsInterceptResponseSection.tsx` -> 107 LOC
- `ui/utils/policyModel/sanitize/tls/http.ts` -> 104 LOC
- `ui/pages/policies/components/RuleHeaderFields.tsx` -> 103 LOC
- `ui/utils/policyValidation/ruleMatchValidation/matchCore.ts` -> 101 LOC
- `ui/pages/settings/useSettingsPage.ts` -> 92 LOC
- `ui/utils/policyModel/normalize/tls/http.ts` -> 91 LOC
- `ui/pages/policies/components/ruleTlsDraft.ts` -> 91 LOC
- `ui/utils/policyModel/ruleTemplates.ts` -> 89 LOC
- `ui/pages/policies/components/TlsInterceptRequestPathSection.tsx` -> 89 LOC
- `ui/utils/policyValidation/sourceGroupValidation.ts` -> 87 LOC
- `ui/utils/policyModel/normalize/rules.ts` -> 87 LOC
- `ui/pages/service-accounts/useServiceAccountTokenPanel.ts` -> 87 LOC
- `ui/pages/policies/components/SourceGroupHeaderFields.tsx` -> 87 LOC
- `ui/pages/policies/components/TlsInterceptRequestHeadersSection.tsx` -> 86 LOC
- `ui/pages/service-accounts/components/CreateTokenModalFields.tsx` -> 84 LOC
- `ui/pages/policies/components/PolicyEditorCard.tsx` -> 84 LOC
- `ui/components/service-accounts/CreateServiceAccountModal.tsx` -> 84 LOC
- `ui/pages/dns-cache/components/DNSCacheTable.tsx` -> 83 LOC

Recommended refactor slices:

- `ui/pages/policies/usePolicyBuilder.ts` -> optional follow-up convert action/lifecycle wiring into a small reducer + command layer if policy editor modes expand.
- `ui/pages/policies/components/ruleTlsDraft.ts` -> optional follow-up split pure mode-transform helpers vs updateDraft wrappers if TLS mode matrix expands.
- `ui/pages/policies/components/RuleMatchProtocolField.tsx` -> optional follow-up extract custom-protocol numeric input into reusable protocol selector control if other rule editors adopt protocol filtering.
- `ui/pages/policies/components/SourceGroupRulesToolbar.tsx` -> optional follow-up extract action buttons into a reusable rule-create control if additional templates/modes are added.
- `ui/pages/policies/policyBuilderLifecycleFlow.ts` -> optional follow-up split editor-selection/reload behavior into a reducer-style helper if additional editor modes are added.
- `ui/utils/policyModel/normalize/tls/http.ts` -> optional follow-up split request matcher normalization from response matcher normalization if HTTP matcher model expands further.
- `ui/utils/policyModel/sanitize/tls/http.ts` -> optional follow-up split request matcher sanitize logic from response matcher sanitize logic if intercept matcher model expands.
- `ui/utils/policyValidation/tlsHttpValidation/request.ts` -> optional follow-up split path/query/header request validation blocks into dedicated functions/modules if matcher branches keep growing.
- `ui/pages/policies/components/TlsInterceptHttpSection.tsx` -> optional follow-up split request/response tab state or field groups if intercept schema grows.
- `ui/pages/service-accounts/components/CreateTokenModalFields.tsx` -> optional follow-up extract TTL preset chip group into reusable token-issuance preset control if modal variants expand.
- `ui/pages/policies/components/TlsInterceptRequestPathSection.tsx` -> optional follow-up extract path editor triplet (`exact`/`prefix`/`regex`) into a reusable matcher component if response/request path constraints diverge.
- `src/controlplane/http_api.rs` -> optional follow-up: extract router assembly/builders to dedicated module and further trim cross-module prelude imports.

## Roadmap Status

### Phase 0 (Must-do before production)

- P0-1 complete.
- P0-2 complete.
- P0-3 complete.

### Phase 1 (Hardening)

- P1-1 complete.
- P1-2 complete.
- P1-3 complete.
- P1-4 complete.

### Phase 2 (Resilience + maintainability)

- In progress.

## Current Recommendation

Status: **Production-candidate with P0/P1 controls closed**, hard approval pending final P2 execution-environment closure.

Rationale: foundational auth/bootstrap/secret/storage/network hardening controls are in place, broad suites remain green, and maintainability hotspots are significantly reduced; remaining blocker is ensuring nightly Rust availability wherever fuzz smoke is required so P2-1 runs as an executed gate instead of a skip.
