# Firewall UI Integrations And Settings Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recompose the `Integrations` and `Settings` pages so they scan like deliberate product surfaces instead of stacked admin forms.

**Architecture:** Keep all existing hooks, mutations, and form semantics intact. Change only the page and component presentation by adding summary/status bands, clearer section grouping, and stronger list/editor hierarchy cues that reuse the existing data already available on each page.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared design tokens from `ui/index.css`

---

### Task 1: Lock The New Integrations Structure With Tests

**Files:**
- Create: `ui/pages/integrations/components/IntegrationPageStructure.test.tsx`
- Test: `ui/pages/integrations/components/IntegrationPageStructure.test.tsx`

- [ ] **Step 1: Write failing tests for the new `Integrations` hierarchy**

```tsx
expect(html).toContain('Configured');
expect(html).toContain('Selection');
expect(html).toContain('Connection Profile');
expect(html).toContain('Credentials');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- IntegrationPageStructure.test.tsx`

Expected: FAIL because the current page does not render those hierarchy markers yet.

- [ ] **Step 3: Implement the minimal presentational changes**

Preserve selection, save, delete, and form update behavior.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- IntegrationPageStructure.test.tsx`

Expected: PASS.

### Task 2: Lock The New Settings Grouping With Tests

**Files:**
- Create: `ui/pages/settings/components/SettingsPageStructure.test.tsx`
- Test: `ui/pages/settings/components/SettingsPageStructure.test.tsx`

- [ ] **Step 1: Write failing tests for the new `Settings` summary and grouping**

```tsx
expect(html).toContain('Control plane posture');
expect(html).toContain('TLS intercept readiness');
expect(html).toContain('Identity providers');
expect(html).toContain('Trust material');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- SettingsPageStructure.test.tsx`

Expected: FAIL because the current page is still a flat vertical stack.

- [ ] **Step 3: Implement the minimal presentational changes**

Keep the same settings actions, form submissions, and status rendering semantics.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- SettingsPageStructure.test.tsx`

Expected: PASS.

### Task 3: Implement The Integrations Presentational Pass

**Files:**
- Modify: `ui/pages/IntegrationsPage.tsx`
- Modify: `ui/pages/integrations/components/IntegrationsListPanel.tsx`
- Modify: `ui/pages/integrations/components/IntegrationEditorPanel.tsx`
- Modify: `ui/pages/integrations/components/IntegrationEditorHeader.tsx`
- Modify: `ui/pages/integrations/components/IntegrationEditorActions.tsx`
- Modify: `ui/pages/integrations/components/IntegrationBasicsSection.tsx`
- Modify: `ui/pages/integrations/components/IntegrationCredentialsSection.tsx`
- Test: `ui/pages/integrations/components/IntegrationPageStructure.test.tsx`

- [ ] **Step 1: Add a compact page-level summary strip and rebalance the page grid**

- [ ] **Step 2: Turn the integrations list into a stronger rail with better item metadata**

- [ ] **Step 3: Split the editor into labeled connection and credential sections with a richer header**

- [ ] **Step 4: Run the focused integrations test**

Run: `cd ui && npm test -- IntegrationPageStructure.test.tsx`

Expected: PASS.

### Task 4: Implement The Settings Presentational Pass

**Files:**
- Modify: `ui/pages/SettingsPage.tsx`
- Modify: `ui/pages/settings/components/PerformanceModeCard.tsx`
- Modify: `ui/pages/settings/components/SettingsStatusCard.tsx`
- Modify: `ui/pages/settings/components/ThreatAnalysisCard.tsx`
- Modify: `ui/pages/settings/components/TlsInterceptCaForm.tsx`
- Modify: `ui/pages/settings/components/SupportBundleCard.tsx`
- Modify: `ui/pages/settings/components/SsoProvidersForm.tsx`
- Test: `ui/pages/settings/components/SettingsPageStructure.test.tsx`
- Test: `ui/pages/settings/components/ThreatAnalysisCard.test.tsx`

- [ ] **Step 1: Add a top-level settings posture strip and grouped section containers**

- [ ] **Step 2: Recompose the toggle and status cards into denser, more legible control surfaces**

- [ ] **Step 3: Strengthen the CA, support bundle, and SSO list/editor hierarchy without changing form behavior**

- [ ] **Step 4: Run the focused settings tests**

Run: `cd ui && npm test -- SettingsPageStructure.test.tsx ThreatAnalysisCard.test.tsx`

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
- `integrations-desktop-implemented.png`
- `integrations-mobile-implemented.png`
- `settings-desktop-implemented.png`
- `settings-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- integrations list/editor separation is stronger
- settings reads in grouped layers rather than as a long card stack
- mobile still preserves scan order and action clarity
