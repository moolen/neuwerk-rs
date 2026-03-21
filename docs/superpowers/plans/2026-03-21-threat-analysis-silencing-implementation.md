# Threat Analysis Silencing And Disablement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cluster-global silences and a cluster-global hard disable switch so false-positive indicators are dropped before finding creation and threat analysis can be fully turned off without purging stored findings.

**Architecture:** Keep `ThreatIntelSettings.enabled` as the single replicated master feature gate and add a separate replicated silence state for exact-indicator and hostname-regex suppression. Enforce both controls in the runtime and manager layers, then expose them through the threat HTTP API and the Settings/Threats UI surfaces.

**Tech Stack:** Rust, Tokio, Axum, OpenRaft, serde/JSON, existing Neuwerk threat-intel runtime/store abstractions, React, Vite, Vitest.

---

## File Structure

**Backend files**

- Create: `src/controlplane/threat_intel/silences.rs`
  Purpose: replicated silence state model, exact/regex matcher, validation, cluster/local persistence helpers.
- Modify: `src/controlplane/threat_intel/mod.rs`
  Purpose: export silence module.
- Modify: `src/controlplane/threat_intel/runtime.rs`
  Purpose: apply silences before `ThreatFinding` creation and skip runtime processing when disabled.
- Modify: `src/runtime/startup/controlplane_runtime.rs`
  Purpose: thread settings + silences into the active runtime state, skip backfill when disabled, and reload matcher/silence state safely.
- Modify: `src/controlplane/threat_intel/manager.rs`
  Purpose: make the refresh loop hard-stop when disabled and keep API feed-status output disable-aware.
- Modify: `src/controlplane/http_api/threats.rs`
  Purpose: add silence CRUD endpoints and disabled-aware threat/feed responses.
- Modify: `src/controlplane/http_api/openapi.rs`
  Purpose: register new endpoint schemas and response types.

**Backend tests**

- Create: `tests/http_api/cluster_threat_cases/silence_cases.rs`
  Purpose: clustered HTTP regression coverage for silence CRUD, follower-visible replication, disabled threat API behavior, and drop-before-persist semantics.
- Modify: `tests/http_api/cluster_threat_cases.rs`
  Purpose: register the new cluster threat test module.
- Modify: `src/controlplane/threat_intel/runtime.rs`
  Purpose: add unit tests for exact silence, hostname regex silence, and disabled runtime behavior.
- Modify: `src/controlplane/threat_intel/manager.rs`
  Purpose: add unit tests for disabled refresh-loop behavior.

**Frontend files**

- Modify: `ui/types/threats.ts`
  Purpose: add silence types and disabled-aware API response types.
- Modify: `ui/services/apiClient/threats.ts`
  Purpose: add `listThreatSilences`, `createThreatSilence`, `deleteThreatSilence`, and update response handling for disabled threat state.
- Modify: `ui/services/api.ts`
  Purpose: re-export new threat API helpers.
- Modify: `ui/pages/threat-intel/useThreatIntelPage.ts`
  Purpose: load silences alongside findings/feed status and surface disabled state + CRUD actions.
- Modify: `ui/pages/ThreatIntelPage.tsx`
  Purpose: render disabled banner/state, silence management panel, and row-action workflows.
- Create: `ui/pages/threat-intel/components/CreateThreatSilenceModal.tsx`
  Purpose: collect exact/hostname-regex silence input, optional reason, and explicit suppression warning.
- Create: `ui/pages/threat-intel/components/ThreatSilencesPanel.tsx`
  Purpose: show current silences and deletion actions.
- Create: `ui/pages/threat-intel/components/ThreatDisableBanner.tsx`
  Purpose: explain hard-disabled behavior and direct users to Settings.
- Modify: `ui/pages/threat-intel/components/ThreatFindingsTable.tsx`
  Purpose: add silence actions per finding row.
- Modify: `ui/pages/settings/useSettingsPage.ts`
  Purpose: load/save threat settings enablement from the Settings page.
- Modify: `ui/pages/SettingsPage.tsx`
  Purpose: mount a threat-analysis settings card.
- Create: `ui/pages/settings/components/ThreatAnalysisCard.tsx`
  Purpose: master enable/disable control and status summary.

**Frontend tests**

- Create: `ui/pages/threat-intel/components/CreateThreatSilenceModal.test.tsx`
- Create: `ui/pages/threat-intel/components/ThreatSilencesPanel.test.tsx`
- Create: `ui/pages/threat-intel/components/ThreatDisableBanner.test.tsx`
- Modify: `ui/pages/threat-intel/components/ThreatFindingsTable.test.tsx`
- Create: `ui/pages/settings/components/ThreatAnalysisCard.test.tsx`
- Modify: `ui/pages/threat-intel/helpers.test.ts` only if helper/query-shape changes require it.

---

### Task 1: Add Silence State And Matcher Primitives

**Files:**
- Create: `src/controlplane/threat_intel/silences.rs`
- Modify: `src/controlplane/threat_intel/mod.rs`
- Test: `src/controlplane/threat_intel/silences.rs`

- [ ] **Step 1: Write the failing tests**

Add unit tests that prove:
- exact hostname silences match normalized hostnames
- exact IP silences match canonical IP indicators
- hostname regex silences only apply to hostname indicators
- invalid hostname regex patterns are rejected

Example test skeleton:

```rust
#[test]
fn hostname_regex_silence_matches_normalized_hostname_only() {
    let silences = ThreatSilenceList {
        items: vec![ThreatSilenceEntry::hostname_regex("^.*\\.example\\.com$".to_string(), None)],
    };
    let matcher = ThreatSilenceMatcher::compile(&silences).expect("compile");

    assert!(matcher.matches(ThreatIndicatorType::Hostname, "bad.example.com"));
    assert!(!matcher.matches(ThreatIndicatorType::Ip, "203.0.113.10"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test threat_silence --lib`
Expected: FAIL because silence state and matcher types do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement:
- `ThreatSilenceKind`
- `ThreatSilenceEntry`
- `ThreatSilenceList`
- `ThreatSilenceMatcher`
- exact-match normalization for hostname/IP entries
- hostname-regex compilation/validation
- cluster/local load + persist helpers under a new replicated key

Keep regex scope intentionally narrow: hostname indicators only.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test threat_silence --lib`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/controlplane/threat_intel/silences.rs src/controlplane/threat_intel/mod.rs
git commit -m "feat: add threat silence state and matcher"
```

---

### Task 2: Enforce Silences And Hard Disablement In Runtime/Manager

**Files:**
- Modify: `src/controlplane/threat_intel/runtime.rs`
- Modify: `src/runtime/startup/controlplane_runtime.rs`
- Modify: `src/controlplane/threat_intel/manager.rs`
- Test: `src/controlplane/threat_intel/runtime.rs`
- Test: `src/controlplane/threat_intel/manager.rs`
- Test: `src/runtime/startup/controlplane_runtime.rs`

- [ ] **Step 1: Write the failing tests**

Add tests that prove:
- an exact silence drops a stream match before `ThreatStore::upsert_finding`
- a hostname regex silence drops a matching hostname stream event
- backfill does not persist silenced findings
- disabled runtime state prevents new observations from producing findings
- disabled manager state prevents feed refresh execution

Example test skeleton:

```rust
#[tokio::test]
async fn runtime_drops_silenced_hostname_before_persist() {
    let silences = ThreatSilenceList {
        items: vec![ThreatSilenceEntry::exact_hostname("bad.example.com".to_string(), None)],
    };
    let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
        snapshot: snapshot_with_hostname("bad.example.com", ThreatSeverity::High, "threatfox"),
        silences,
        enabled: true,
        store: store.clone(),
        metrics: metrics.clone(),
        queue_capacity: 16,
    });

    assert!(handle.try_observe(ThreatObservation::dns("bad.example.com", "apps", "node-a", 100).unwrap()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(store.query(&ThreatFindingQuery::default()).unwrap().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
- `cargo test silenced --lib`
- `cargo test threat_disabled --lib`

Expected: FAIL because the runtime and manager do not yet honor silences or full disablement.

- [ ] **Step 3: Write minimal implementation**

Implement:
- a silence-aware `ThreatRuntimeConfig`
- suppression checks after `match_observation*` but before `build_finding` / `upsert_finding`
- backfill suppression using the same matcher
- disabled runtime state that keeps the slot empty and prevents observation processing
- disabled refresh-loop guard in `manager.rs`
- startup reload path that refreshes runtime state from both settings and silences

Do **not** hide findings only at query time; enforce disablement and silencing in the processing path.

- [ ] **Step 4: Run tests to verify they pass**

Run:
- `cargo test silenced --lib`
- `cargo test threat_disabled --lib`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/controlplane/threat_intel/runtime.rs src/runtime/startup/controlplane_runtime.rs src/controlplane/threat_intel/manager.rs
git commit -m "feat: enforce threat silences and hard disablement"
```

---

### Task 3: Add Silence CRUD And Disabled-Aware Threat HTTP Responses

**Files:**
- Modify: `src/controlplane/http_api/threats.rs`
- Modify: `src/controlplane/http_api/openapi.rs`
- Create: `tests/http_api/cluster_threat_cases/silence_cases.rs`
- Modify: `tests/http_api/cluster_threat_cases.rs`

- [ ] **Step 1: Write the failing tests**

Add clustered HTTP integration tests that prove:
- `POST /api/v1/threats/silences` creates a replicated silence entry
- `GET /api/v1/threats/silences` returns the same entry from a follower
- `DELETE /api/v1/threats/silences/:id` removes the entry cluster-wide
- `POST /api/v1/threats/silences` rejects invalid hostname regex input with `400`
- when threat intel is disabled, `GET /api/v1/threats/findings` returns an empty disabled response
- when threat intel is disabled, `GET /api/v1/threats/findings/local` returns the same disabled-aware empty response
- when threat intel is disabled, `GET /api/v1/threats/feeds/status` returns `disabled=true`
- a created silence prevents future matching through the external HTTP/runtime path

Example API assertion:

```rust
assert_eq!(payload.get("disabled").and_then(|v| v.as_bool()), Some(true));
assert_eq!(payload.get("items").and_then(|v| v.as_array()).unwrap().len(), 0);
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test cluster_threat_cases --test http_api`
Expected: FAIL because the silence endpoints and disabled-aware response contracts do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement:
- silence list/create/delete handlers in `threats.rs`
- request/response DTOs for silence management
- disabled-aware response types for findings, local fanout findings, and feed status
- route wiring and OpenAPI schema registration

Keep clustered aggregation behavior consistent with the local-fanout disabled contract so leaders do not merge stale per-node results while disabled.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test cluster_threat_cases --test http_api`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/controlplane/http_api/threats.rs src/controlplane/http_api/openapi.rs tests/http_api/cluster_threat_cases.rs tests/http_api/cluster_threat_cases/silence_cases.rs
git commit -m "feat: add threat silence http api"
```

---

### Task 4: Add Threats UI Silence Management And Disabled State

**Files:**
- Modify: `ui/types/threats.ts`
- Modify: `ui/services/apiClient/threats.ts`
- Modify: `ui/services/api.ts`
- Modify: `ui/pages/threat-intel/useThreatIntelPage.ts`
- Modify: `ui/pages/ThreatIntelPage.tsx`
- Create: `ui/pages/threat-intel/components/CreateThreatSilenceModal.tsx`
- Create: `ui/pages/threat-intel/components/ThreatSilencesPanel.tsx`
- Create: `ui/pages/threat-intel/components/ThreatDisableBanner.tsx`
- Modify: `ui/pages/threat-intel/components/ThreatFindingsTable.tsx`
- Test: `ui/pages/threat-intel/components/CreateThreatSilenceModal.test.tsx`
- Test: `ui/pages/threat-intel/components/ThreatSilencesPanel.test.tsx`
- Test: `ui/pages/threat-intel/components/ThreatDisableBanner.test.tsx`
- Test: `ui/pages/threat-intel/components/ThreatFindingsTable.test.tsx`

- [ ] **Step 1: Write the failing tests**

Add UI tests that prove:
- the Threats page shows a disabled banner/state when `disabled=true`
- the create-silence modal shows the candidate value, optional reason field, and drop-before-create warning copy
- the findings table exposes silence actions
- the silences panel renders current entries and delete affordances
- hostname findings expose both exact and hostname-regex silence actions, while IP findings expose only exact silence

Example test skeleton:

```tsx
it('renders a disabled threat-analysis state', () => {
  const html = renderToStaticMarkup(
    <ThreatDisableBanner disabled={true} onOpenSettings={() => {}} />
  );
  expect(html).toContain('Threat analysis disabled');
  expect(html).toContain('new URLs and IPs are not processed');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
- `npm test -- pages/threat-intel/components/CreateThreatSilenceModal.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatDisableBanner.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatSilencesPanel.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatFindingsTable.test.tsx`

Expected: FAIL because the new components and actions do not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement:
- silence types and disabled-aware threat response types
- API client functions for silence CRUD
- page state for loading silences and invoking create/delete actions
- a create-silence modal that supports exact and hostname-regex entry creation with optional reason text
- disabled-state banner on the Threats page
- silence management panel
- exact/regex silence row actions in the findings table
- manual create affordance from the Threats page so operators can manage silences even while findings are hidden

Preserve the existing visual language from the current Threats page; do not introduce a second, unrelated settings style.

- [ ] **Step 4: Run tests to verify they pass**

Run:
- `npm test -- pages/threat-intel/components/CreateThreatSilenceModal.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatDisableBanner.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatSilencesPanel.test.tsx`
- `npm test -- pages/threat-intel/components/ThreatFindingsTable.test.tsx`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/types/threats.ts ui/services/apiClient/threats.ts ui/services/api.ts ui/pages/ThreatIntelPage.tsx ui/pages/threat-intel
git commit -m "feat: add threat silencing ui"
```

---

### Task 5: Add Settings-Surface Master Toggle

**Files:**
- Modify: `ui/pages/settings/useSettingsPage.ts`
- Modify: `ui/pages/SettingsPage.tsx`
- Create: `ui/pages/settings/components/ThreatAnalysisCard.tsx`
- Create: `ui/pages/settings/components/ThreatAnalysisCard.test.tsx`

- [ ] **Step 1: Write the failing tests**

Add a component test that proves:
- the settings card renders current enabled state
- toggling the control calls the save callback with the next state

Example test skeleton:

```tsx
it('renders the current threat analysis enablement state', () => {
  const html = renderToStaticMarkup(
    <ThreatAnalysisCard status={{ enabled: false, source: 'cluster' }} loading={false} saving={false} onToggle={() => {}} />
  );
  expect(html).toContain('Threat Analysis');
  expect(html).toContain('Disabled');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npm test -- pages/settings/components/ThreatAnalysisCard.test.tsx`
Expected: FAIL because the settings card does not exist yet.

- [ ] **Step 3: Write minimal implementation**

Implement:
- threat-settings load/save helpers in `useSettingsPage`
- a `ThreatAnalysisCard` component mounted near the other operational settings cards
- wording that clearly states disabled mode stops new URL/IP processing cluster-wide

- [ ] **Step 4: Run tests to verify they pass**

Run: `npm test -- pages/settings/components/ThreatAnalysisCard.test.tsx`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add ui/pages/settings/useSettingsPage.ts ui/pages/SettingsPage.tsx ui/pages/settings/components/ThreatAnalysisCard.tsx ui/pages/settings/components/ThreatAnalysisCard.test.tsx
git commit -m "feat: add threat analysis settings control"
```

---

### Task 6: Full Verification

**Files:**
- No new files; verification only

- [ ] **Step 1: Run focused Rust verification**

Run:
- `cargo test threat_silence --lib`
- `cargo test threat_disabled --lib`
- `cargo test cluster_threat_cases --test http_api`

Expected: PASS

- [ ] **Step 2: Run focused UI verification**

Run:
- `cd ui && npm test -- pages/threat-intel/components/ThreatDisableBanner.test.tsx pages/threat-intel/components/ThreatSilencesPanel.test.tsx pages/threat-intel/components/ThreatFindingsTable.test.tsx pages/settings/components/ThreatAnalysisCard.test.tsx`
- `cd ui && npm test -- pages/threat-intel/components/CreateThreatSilenceModal.test.tsx`

Expected: PASS

- [ ] **Step 3: Run existing threat UI regressions**

Run:
- `cd ui && npm test -- navigation.test.ts components/sidebar/helpers.test.ts pages/threat-intel/helpers.test.ts pages/threat-intel/components/ThreatFiltersPanel.test.tsx pages/threat-intel/components/ThreatFindingsTable.test.tsx pages/audit/threatAnnotations.test.ts pages/audit/components/AuditFindingsTable.test.tsx`

Expected: PASS

- [ ] **Step 4: Run production UI build**

Run:
- `cd ui && npm run build`

Expected: PASS

- [ ] **Step 5: Optional wider Rust sweep before deploy**

Run:
- `cargo test controlplane::threat_intel::manager::tests::load_effective_feed_status_repairs_stale_local_status_from_newer_snapshot`
- `cargo test runtime::auth::tests::execute_auth_command_prefers_cluster_keyset_when_present`

Expected: PASS
