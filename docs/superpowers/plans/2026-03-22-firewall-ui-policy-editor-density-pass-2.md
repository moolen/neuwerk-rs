# Firewall UI Policy Editor Density Pass 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make nested source-group and rule editing on the `Policies` page easier to scan without changing any draft mutation behavior.

**Architecture:** Keep the existing policy builder state, callbacks, and nested editor controls intact. Improve only the presentation by splitting source-group cards into stronger named surfaces and by giving each rule a clearer top-level hierarchy around header controls, match criteria, and TLS handling.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, shared CSS tokens in `ui/index.css`

---

### Task 1: Lock Nested Editor Layout Contracts With Tests

**Files:**
- Create: `ui/pages/policies/components/SourceGroupCard.test.tsx`
- Create: `ui/pages/policies/components/RuleEditor.test.tsx`
- Test: `ui/pages/policies/components/SourceGroupCard.test.tsx`
- Test: `ui/pages/policies/components/RuleEditor.test.tsx`

- [ ] **Step 1: Write failing tests for source-group and rule presentation contracts**

```tsx
expect(html).toContain('Source group 1');
expect(html).toContain('Source selectors');
expect(html).toContain('Rule stack');
expect(html).toContain('xl:grid-cols-[minmax(0,1.15fr)_minmax(19rem,0.95fr)]');
```

```tsx
expect(html).toContain('Rule 1');
expect(html).toContain('Match criteria');
expect(html).toContain('TLS handling');
expect(html).toContain('xl:grid-cols-[minmax(0,1.2fr)_minmax(18rem,0.9fr)]');
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cd ui && npm test -- SourceGroupCard.test.tsx RuleEditor.test.tsx`

Expected: FAIL because the nested editor currently renders unnamed stacked blocks.

- [ ] **Step 3: Implement the minimal presentational hierarchy**

Keep all existing callbacks and draft mutation paths unchanged.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `cd ui && npm test -- SourceGroupCard.test.tsx RuleEditor.test.tsx`

Expected: PASS.

### Task 2: Recompose The Source-Group Card

**Files:**
- Modify: `ui/pages/policies/components/SourceGroupCard.tsx`
- Modify: `ui/pages/policies/components/SourceGroupHeaderSection.tsx`
- Modify: `ui/pages/policies/components/SourceGroupSourcesSection.tsx`
- Modify: `ui/pages/policies/components/SourceGroupRulesSection.tsx`
- Modify: `ui/pages/policies/components/SourceGroupRulesToolbar.tsx`
- Modify: `ui/pages/policies/components/SourceGroupRulesEmptyState.tsx`
- Test: `ui/pages/policies/components/SourceGroupCard.test.tsx`

- [ ] **Step 1: Split each source-group card into stronger surfaces**

- [ ] **Step 2: Add visible section labels for group identity, source selectors, and rule stack**

- [ ] **Step 3: Tighten empty and toolbar states so the rule area still reads intentionally with zero rules**

- [ ] **Step 4: Run focused verification**

Run: `cd ui && npm test -- SourceGroupCard.test.tsx`

Expected: PASS.

### Task 3: Recompose The Rule Card

**Files:**
- Modify: `ui/pages/policies/components/RuleEditor.tsx`
- Modify: `ui/pages/policies/components/RuleHeaderSection.tsx`
- Test: `ui/pages/policies/components/RuleEditor.test.tsx`

- [ ] **Step 1: Give each rule a clearer top-level header**

- [ ] **Step 2: Wrap the body in named `Match criteria` and `TLS handling` surfaces**

- [ ] **Step 3: Preserve existing rule action controls and field semantics**

- [ ] **Step 4: Run focused verification**

Run: `cd ui && npm test -- RuleEditor.test.tsx`

Expected: PASS.

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

- [ ] **Step 3: Refresh the affected live screenshots**

Capture fresh screenshots for:
- `policies-desktop-implemented.png`
- `policies-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- nested source-group cards read as distinct sections instead of a single form wall
- rule cards expose clearer hierarchy around matching and TLS controls
- mobile remains readable
