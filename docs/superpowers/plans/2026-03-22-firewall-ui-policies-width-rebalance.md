# Firewall UI Policies Width Rebalance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebalance the top-level `Policies` workspace so the content-heavy `Policy scope` editor gets more usable width at standard desktop sizes.

**Architecture:** Keep the authenticated shell, page framing, and nested policy editor hierarchy intact. Change only the page-level column allocation and the top-level `PolicyBuilderForm` composition so `Decision defaults` stops competing with `Policy scope` at common desktop widths and instead behaves more like a secondary rail on very wide screens.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared CSS tokens in `ui/index.css`

---

### Task 1: Lock Width-Rebalance Contracts With Tests

**Files:**
- Modify: `ui/pages/policies/components/PolicyBuilderForm.test.tsx`
- Modify: `ui/pages/SharedPageFrames.test.tsx`
- Test: `ui/pages/policies/components/PolicyBuilderForm.test.tsx`
- Test: `ui/pages/SharedPageFrames.test.tsx`

- [ ] **Step 1: Write failing tests for the new desktop width contracts**

```tsx
expect(html).toContain('2xl:grid-cols-[minmax(0,1.24fr)_minmax(15rem,0.76fr)]');
expect(html).toContain('2xl:sticky 2xl:top-28');
```

```tsx
expect(html).toContain('xl:grid-cols-[minmax(16rem,20rem)_minmax(0,1fr)]');
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx SharedPageFrames.test.tsx`

Expected: FAIL because the current page still uses the wider snapshot rail and the form still splits at `xl`.

- [ ] **Step 3: Implement the minimal presentational change**

Keep existing callbacks, mutation paths, and editor copy unchanged.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx SharedPageFrames.test.tsx`

Expected: PASS.

### Task 2: Reflow The Top-Level Policies Workspace

**Files:**
- Modify: `ui/pages/PoliciesPage.tsx`
- Modify: `ui/pages/policies/components/PolicyBuilderForm.tsx`
- Test: `ui/pages/policies/components/PolicyBuilderForm.test.tsx`
- Test: `ui/pages/SharedPageFrames.test.tsx`

- [ ] **Step 1: Tighten the snapshot rail on desktop**

- [ ] **Step 2: Stack `Policy scope` and `Decision defaults` until very wide screens**

- [ ] **Step 3: Make the `Decision defaults` card act like a secondary sticky rail only when the split is active**

- [ ] **Step 4: Run focused verification**

Run: `cd ui && npm test -- PolicyBuilderForm.test.tsx SharedPageFrames.test.tsx`

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
- `Policy scope` gets materially more width at typical desktop sizes
- `Decision defaults` still reads as a secondary control surface
- mobile remains intact
