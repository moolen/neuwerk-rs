# Firewall UI Policies Snapshot Rail Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each `Policies` snapshot rail row faster to scan by replacing the current chip-heavy metadata wall with clearer hierarchy.

**Architecture:** Preserve the existing snapshot selection and delete interactions, helper semantics, and data source shape. Recompose only the row presentation so each entry has a stronger title/meta header, a compact stats strip, and labeled scope/target summaries that carry the load previously spread across many chips.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, shared CSS tokens in `ui/index.css`

---

### Task 1: Lock Snapshot Row Contracts With Tests

**Files:**
- Create: `ui/pages/policies/components/PolicySnapshotRow.test.tsx`
- Test: `ui/pages/policies/components/PolicySnapshotRow.test.tsx`

- [ ] **Step 1: Write failing tests for the new snapshot row structure**

```tsx
expect(html).toContain('Source scope');
expect(html).toContain('Target profile');
expect(html).toContain('grid grid-cols-3 gap-2');
expect(html).toContain('Open');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- PolicySnapshotRow.test.tsx`

Expected: FAIL because the current row is still rendered as a metadata chip wall.

- [ ] **Step 3: Implement the minimal presentational restructure**

Keep `onSelect`, `onDelete`, and helper outputs intact.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- PolicySnapshotRow.test.tsx`

Expected: PASS.

### Task 2: Recompose The Snapshot Rail Row

**Files:**
- Modify: `ui/pages/policies/components/PolicySnapshotRow.tsx`
- Test: `ui/pages/policies/components/PolicySnapshotRow.test.tsx`

- [ ] **Step 1: Replace the wide chip set with a clearer header and stat strip**

- [ ] **Step 2: Convert source and target summaries into labeled summary rows**

- [ ] **Step 3: Keep mode, DPI, counts, and actions visible without adding behavior**

- [ ] **Step 4: Run focused verification**

Run: `cd ui && npm test -- PolicySnapshotRow.test.tsx`

Expected: PASS.

### Task 3: Run Full Verification And Refresh Live Review Artifacts

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
- snapshot rows read top-to-bottom instead of as a chip cloud
- key counts and mode remain fast to scan
- mobile row density still holds up
