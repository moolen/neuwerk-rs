# Firewall UI Audit Triage Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `Audit` page scan like a triage surface instead of a flat filter-plus-table screen.

**Architecture:** Preserve the existing `useAuditPage` data flow, filters, threat annotation links, and table/card responsiveness. Recompose only the presentation so the page leads with a compact findings posture strip, the filter controls become a labeled control surface, and the findings list/table reads as ranked deny incidents with stronger hierarchy.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared design tokens from `ui/index.css`

---

### Task 1: Lock The New Audit Page Structure With Tests

**Files:**
- Create: `ui/pages/audit/components/AuditPageStructure.test.tsx`
- Test: `ui/pages/audit/components/AuditPageStructure.test.tsx`

- [ ] **Step 1: Write failing tests for the new Audit triage landmarks**

```tsx
expect(html).toContain('Visible findings');
expect(html).toContain('Node coverage');
expect(html).toContain('Active filters');
expect(html).toContain('Review queue');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- AuditPageStructure.test.tsx`

Expected: FAIL because the current Audit page is still a flat filter-and-table layout.

- [ ] **Step 3: Implement the minimal presentational changes**

Preserve all current load, filter, and disable behavior.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- AuditPageStructure.test.tsx`

Expected: PASS.

### Task 2: Lock The New Findings Hierarchy With Tests

**Files:**
- Modify: `ui/pages/audit/components/AuditFindingsTable.test.tsx`
- Test: `ui/pages/audit/components/AuditFindingsTable.test.tsx`

- [ ] **Step 1: Extend the findings test with new hierarchy cues**

```tsx
expect(html).toContain('Review queue');
expect(html).toContain('Finding volume');
expect(html).toContain('Threat linked');
```

- [ ] **Step 2: Run the focused findings test to verify it fails**

Run: `cd ui && npm test -- AuditFindingsTable.test.tsx`

Expected: FAIL because the current findings cards and table do not expose those new structure labels.

- [ ] **Step 3: Implement the minimal row/card presentation changes**

Keep the same item rendering semantics and threat links.

- [ ] **Step 4: Run the focused findings test to verify it passes**

Run: `cd ui && npm test -- AuditFindingsTable.test.tsx`

Expected: PASS.

### Task 3: Recompose The Audit Page

**Files:**
- Modify: `ui/pages/AuditPage.tsx`
- Modify: `ui/pages/audit/components/AuditFiltersPanel.tsx`
- Modify: `ui/pages/audit/components/AuditNodeErrorsPanel.tsx`
- Test: `ui/pages/audit/components/AuditPageStructure.test.tsx`

- [ ] **Step 1: Add a compact findings posture strip above the filters**

- [ ] **Step 2: Turn the filters into a labeled control surface with clearer intent**

- [ ] **Step 3: Group node-error and partial-state messaging so the page reads in triage order**

- [ ] **Step 4: Run the focused Audit page test**

Run: `cd ui && npm test -- AuditPageStructure.test.tsx`

Expected: PASS.

### Task 4: Recompose The Findings Table And Mobile Cards

**Files:**
- Modify: `ui/pages/audit/components/AuditFindingsTable.tsx`
- Modify: `ui/pages/audit/components/AuditFindingsTable.test.tsx`

- [ ] **Step 1: Add a section header and compact review summary above the findings**

- [ ] **Step 2: Make mobile cards read as incidents with stronger metadata hierarchy**

- [ ] **Step 3: Strengthen desktop row hierarchy without changing columns or links**

- [ ] **Step 4: Run the focused findings test**

Run: `cd ui && npm test -- AuditFindingsTable.test.tsx`

Expected: PASS.

### Task 5: Run Full Verification And Refresh Live Review Artifacts

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
- `audit-desktop-implemented.png`
- `audit-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- Audit now reads with a clear triage layer before the table
- filters feel like a control surface rather than loose inputs
- desktop and mobile findings are easier to scan by priority and count
