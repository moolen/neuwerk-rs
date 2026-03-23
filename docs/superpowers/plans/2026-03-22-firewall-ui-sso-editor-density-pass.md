# Firewall UI SSO Editor Density Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce perceived complexity in the `Settings` SSO provider editor while restoring all provider draft fields to the form.

**Architecture:** Preserve the existing `SsoProviderDraft` model, save/delete/test flows, and payload builders. Recompose only the editor presentation by grouping core fields up front and moving claim mapping plus role-specific override fields into progressive-disclosure sections with compact summaries.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared CSS tokens in `ui/index.css`

---

### Task 1: Lock The New SSO Editor Structure With Tests

**Files:**
- Create: `ui/pages/settings/components/SsoProvidersForm.test.tsx`
- Test: `ui/pages/settings/components/SsoProvidersForm.test.tsx`

- [ ] **Step 1: Write failing tests for restored advanced fields and disclosure sections**

```tsx
expect(html).toContain('Claim mapping');
expect(html).toContain('Admin access overrides');
expect(html).toContain('Readonly access overrides');
expect(html).toContain('Subject Claim');
expect(html).toContain('Admin Groups');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- SsoProvidersForm.test.tsx`

Expected: FAIL because the current form omits several draft fields and does not yet expose the new disclosure structure.

- [ ] **Step 3: Implement the minimal presentational changes**

Preserve the existing draft update semantics and submit behavior.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- SsoProvidersForm.test.tsx`

Expected: PASS.

### Task 2: Recompose The SSO Editor

**Files:**
- Modify: `ui/pages/settings/components/SsoProvidersForm.tsx`
- Test: `ui/pages/settings/components/SsoProvidersForm.test.tsx`

- [ ] **Step 1: Add an editor summary strip for provider state, role, and secret status**

- [ ] **Step 2: Keep basics and endpoints visible, but move claim mapping and role override details into compact disclosure sections**

- [ ] **Step 3: Restore all missing draft fields to the visible form without changing payload behavior**

- [ ] **Step 4: Run the focused SSO test**

Run: `cd ui && npm test -- SsoProvidersForm.test.tsx`

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
- `settings-desktop-implemented.png`
- `settings-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- SSO editor reads as progressive layers instead of one long field wall
- advanced claim and role override fields remain available
- desktop and mobile preserve a clear scan path
