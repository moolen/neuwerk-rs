# Firewall UI Workflow Density Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the two densest operator workflows, `Policies` and `Threats`, easier to scan and act on without changing their underlying behavior.

**Architecture:** Rebalance the `Policies` page by separating the snapshot rail from the editor and converting the top-level editor sections into clearer surface groups. In parallel, restructure the `Threats` filter panel into stronger desktop lanes with clearer grouping and action hierarchy while preserving the existing filter state and callbacks.

**Tech Stack:** React 19, TypeScript, Vite, Vitest, render-to-static-markup tests, shared CSS tokens in `ui/index.css`

---

### Task 1: Lock Workflow Polish Contracts With Tests

**Files:**
- Modify: `ui/pages/SharedPageFrames.test.tsx`
- Modify: `ui/pages/threat-intel/components/ThreatFiltersPanel.test.tsx`
- Create: `ui/pages/policies/components/PolicyBuilderForm.test.tsx`
- Test: `ui/pages/threat-intel/components/ThreatFiltersPanel.test.tsx`, `ui/pages/policies/components/PolicyBuilderForm.test.tsx`, `ui/pages/SharedPageFrames.test.tsx`

- [ ] **Step 1: Write failing tests for the new policy and threat layout contracts**

```tsx
expect(html).toContain('xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)]');
expect(html).toContain('Policy scope');
expect(html).toContain('Decision defaults');
```

```tsx
expect(html).toContain('2xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.9fr)]');
expect(html).toContain('Refine by feed and severity');
expect(html).toContain('Scope and timing');
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx ThreatFiltersPanel.test.tsx SharedPageFrames.test.tsx`

Expected: FAIL because the current `Policies` editor and `Threats` filter panel do not expose the new structure or copy.

- [ ] **Step 3: Implement the minimal presentational changes to satisfy the contracts**

```tsx
<div className="grid gap-6 xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)]">
  <aside>...</aside>
  <section>...</section>
</div>
```

```tsx
<section>
  <h3>Policy scope</h3>
  ...
</section>
<section>
  <h3>Decision defaults</h3>
  ...
</section>
```

```tsx
<div className="grid gap-5 2xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.9fr)]">
  <div>Refine by feed and severity</div>
  <div>Scope and timing</div>
</div>
```

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx ThreatFiltersPanel.test.tsx SharedPageFrames.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/pages/SharedPageFrames.test.tsx ui/pages/threat-intel/components/ThreatFiltersPanel.test.tsx ui/pages/policies/components/PolicyBuilderForm.test.tsx
git commit -m "test: lock workflow density polish contracts"
```

### Task 2: Rebalance The Policies Workspace

**Files:**
- Modify: `ui/pages/PoliciesPage.tsx`
- Modify: `ui/pages/policies/components/PolicyBuilderForm.tsx`
- Modify: `ui/pages/policies/components/PolicySnapshotsPanel.tsx`
- Modify: `ui/pages/policies/components/PolicyEditorCard.tsx`
- Modify: `ui/pages/policies/components/PolicyEditorActions.tsx`
- Modify: `ui/pages/policies/components/PolicyBasicsSection.tsx`
- Modify: `ui/pages/policies/components/SourceGroupsSection.tsx`
- Test: `ui/pages/policies/components/PolicyBuilderForm.test.tsx`, `ui/pages/SharedPageFrames.test.tsx`

- [ ] **Step 1: Run the focused policies tests to keep the red/green loop tight**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx SharedPageFrames.test.tsx`

Expected: FAIL until the page and editor sections are restructured.

- [ ] **Step 2: Split the page into a stronger desktop workspace**

```tsx
<div className="grid gap-6 xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)] xl:items-start">
  <aside className="space-y-4">...</aside>
  <div className="space-y-4">...</div>
</div>
```

- [ ] **Step 3: Convert the top editor form into named surface groups**

```tsx
<div className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(18rem,0.95fr)]">
  <section>Policy scope</section>
  <section>Decision defaults</section>
</div>
```

- [ ] **Step 4: Tighten snapshot/editor/action surfaces without changing behavior**

```tsx
<div className="rounded-2xl ...">...</div>
```

Keep the existing callbacks and state wiring unchanged.

- [ ] **Step 5: Run focused verification**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx SharedPageFrames.test.tsx policiesPageHelpers.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ui/pages/PoliciesPage.tsx ui/pages/policies/components/PolicyBuilderForm.tsx ui/pages/policies/components/PolicySnapshotsPanel.tsx ui/pages/policies/components/PolicyEditorCard.tsx ui/pages/policies/components/PolicyEditorActions.tsx ui/pages/policies/components/PolicyBasicsSection.tsx ui/pages/policies/components/SourceGroupsSection.tsx
git commit -m "refactor: rebalance policies workspace"
```

### Task 3: Clarify The Threats Investigation Surface

**Files:**
- Modify: `ui/pages/threat-intel/components/ThreatFiltersPanel.tsx`
- Test: `ui/pages/threat-intel/components/ThreatFiltersPanel.test.tsx`

- [ ] **Step 1: Run the targeted threats filter test**

Run: `cd ui && npm test -- ThreatFiltersPanel.test.tsx`

Expected: FAIL until the filter panel uses the new lane/group structure.

- [ ] **Step 2: Recompose the filter panel into clearer lanes**

```tsx
<div className="grid gap-5 2xl:grid-cols-[minmax(0,1.5fr)_minmax(20rem,0.9fr)]">
  <div className="space-y-5">Refine by feed and severity</div>
  <div className="space-y-5">Scope and timing</div>
</div>
```

- [ ] **Step 3: Strengthen action hierarchy and copy**

```tsx
<div>
  <h3>Refine by feed and severity</h3>
  <p>...</p>
</div>
```

Keep the existing `onRefresh`, `onUpdateFilters`, and `auditKey` behavior unchanged.

- [ ] **Step 4: Run focused verification**

Run: `cd ui && npm test -- ThreatFiltersPanel.test.tsx ThreatDisableBanner.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/pages/threat-intel/components/ThreatFiltersPanel.tsx ui/pages/threat-intel/components/ThreatFiltersPanel.test.tsx
git commit -m "refactor: clarify threats investigation filters"
```

### Task 4: Run Full Verification And Refresh Live Review Artifacts

**Files:**
- Verify: `ui`
- Review artifacts: `tmp/ui-review-implemented-2026-03-22/`

- [ ] **Step 1: Run the full UI suite**

Run: `cd ui && npm test`

Expected: PASS.

- [ ] **Step 2: Run the production build**

Run: `cd ui && npm run build`

Expected: PASS.

- [ ] **Step 3: Refresh the affected live-data screenshots**

Capture fresh desktop and mobile screenshots for:
- `Policies`
- `Threats`

Save into:
- `tmp/ui-review-implemented-2026-03-22/`

- [ ] **Step 4: Review the updated screenshots for density regressions**

Confirm:
- Policies snapshot rail and editor read as separate surfaces on desktop
- Threat filter controls scan in grouped lanes instead of one long control wall
- Mobile remains intact

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/plans/2026-03-22-firewall-ui-workflow-density-polish.md
git commit -m "docs: add workflow density polish plan"
```
