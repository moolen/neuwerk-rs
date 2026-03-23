# Firewall UI Shell Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the authenticated firewall UI usable on mobile, unify page framing across core pages, and tighten the visual token foundation so live operator data is easier to scan.

**Architecture:** Extract the authenticated shell into a presentational component with explicit desktop and mobile navigation states, then introduce shared page-layout primitives so top-level pages stop reinventing spacing and title/action rows. Finish by tuning the global theme tokens and shared surface styles so the redesign changes propagate broadly without page-by-page color edits.

**Tech Stack:** React 19, TypeScript, Vite, Vitest, render-to-static-markup component tests, global CSS tokens in `ui/index.css`

---

### Task 1: Lock Shell And Page-Frame Contracts With Tests

**Files:**
- Create: `ui/app/AuthenticatedShell.test.tsx`
- Create: `ui/components/layout/PageLayout.test.tsx`
- Modify: `ui/navigation.test.ts`
- Test: `ui/app/AuthenticatedShell.test.tsx`, `ui/components/layout/PageLayout.test.tsx`, `ui/navigation.test.ts`

- [ ] **Step 1: Write the failing shell and layout tests**

```tsx
it('renders a mobile drawer overlay when mobile navigation is open', () => {
  const html = renderToStaticMarkup(
    <AuthenticatedShell
      user={user}
      currentPage="dashboard"
      sidebarCollapsed={false}
      mobileNavigationOpen={true}
      onNavigate={() => {}}
      onToggleSidebar={() => {}}
      onToggleMobileNavigation={() => {}}
      onLogout={async () => {}}
    />
  );

  expect(html).toContain('Mobile navigation');
  expect(html).toContain('fixed inset-0');
});
```

```tsx
it('renders a shared page layout title, description, and actions', () => {
  const html = renderToStaticMarkup(
    <PageLayout title="Policies" description="Form-driven policy builder." actions={<button>New</button>}>
      <div>Body</div>
    </PageLayout>
  );

  expect(html).toContain('Policies');
  expect(html).toContain('Form-driven policy builder.');
  expect(html).toContain('New');
});
```

```ts
it('returns labels for app pages used by the shell header', () => {
  expect(getPageLabel('service-accounts')).toBe('Service Accounts');
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ui && npm test -- AuthenticatedShell.test.tsx PageLayout.test.tsx navigation.test.ts`

Expected: FAIL because `AuthenticatedShell`, `PageLayout`, and `getPageLabel` do not exist yet.

- [ ] **Step 3: Implement the minimal shell metadata and presentational components**

```tsx
export function getPageLabel(page: AppPage): string {
  return NAV_ITEMS.find((item) => item.id === page)?.label ?? 'Dashboard';
}
```

```tsx
export const PageLayout: React.FC<PageLayoutProps> = ({ title, description, actions, children }) => (
  <div className="space-y-6">
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div>...</div>
      {actions ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
    </div>
    {children}
  </div>
);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ui && npm test -- AuthenticatedShell.test.tsx PageLayout.test.tsx navigation.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/app/AuthenticatedShell.test.tsx ui/components/layout/PageLayout.test.tsx ui/navigation.test.ts ui/navigation.ts ui/components/layout/PageLayout.tsx ui/app/AuthenticatedShell.tsx
git commit -m "test: lock shell and page layout contracts"
```

### Task 2: Implement The Responsive Authenticated Shell

**Files:**
- Create: `ui/app/AuthenticatedShell.tsx`
- Create: `ui/components/sidebar/MobileNavigationDrawer.tsx`
- Modify: `ui/app/AuthenticatedApp.tsx`
- Modify: `ui/app/AppHeader.tsx`
- Modify: `ui/components/Sidebar.tsx`
- Modify: `ui/components/sidebar/SidebarHeader.tsx`
- Test: `ui/app/AuthenticatedShell.test.tsx`

- [ ] **Step 1: Extend the shell test with desktop/mobile navigation behavior**

```tsx
it('shows the current page label in the header and keeps the desktop sidebar hidden on mobile markup', () => {
  const html = renderToStaticMarkup(...);
  expect(html).toContain('Policies');
  expect(html).toContain('lg:flex');
  expect(html).toContain('lg:hidden');
});
```

- [ ] **Step 2: Run the targeted test to verify it fails**

Run: `cd ui && npm test -- AuthenticatedShell.test.tsx`

Expected: FAIL because the current shell has no responsive/mobile behavior.

- [ ] **Step 3: Implement the responsive shell minimally**

```tsx
const [mobileNavigationOpen, setMobileNavigationOpen] = useState(false);

const handleNavigate = (page: AppPage) => {
  navigateTo(page);
  setMobileNavigationOpen(false);
};
```

```tsx
<Sidebar className="hidden lg:flex" ... />
<MobileNavigationDrawer open={mobileNavigationOpen} currentPage={currentPage} ... />
<AppHeader currentPage={currentPage} onOpenMobileNavigation={() => setMobileNavigationOpen(true)} ... />
```

- [ ] **Step 4: Run the targeted test and the related suite**

Run: `cd ui && npm test -- AuthenticatedShell.test.tsx authenticatedHelpers.test.ts navigation.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/app/AuthenticatedShell.tsx ui/components/sidebar/MobileNavigationDrawer.tsx ui/app/AuthenticatedApp.tsx ui/app/AppHeader.tsx ui/components/Sidebar.tsx ui/components/sidebar/SidebarHeader.tsx ui/app/AuthenticatedShell.test.tsx
git commit -m "feat: add responsive authenticated shell"
```

### Task 3: Unify Top-Level Page Framing

**Files:**
- Create: `ui/components/layout/PageLayout.tsx`
- Modify: `ui/pages/IntegrationsPage.tsx`
- Modify: `ui/pages/AuditPage.tsx`
- Modify: `ui/pages/DNSCachePage.tsx`
- Modify: `ui/pages/ServiceAccountsPage.tsx`
- Modify: `ui/pages/SettingsPage.tsx`
- Modify: `ui/pages/WiretapPage.tsx`
- Modify: `ui/pages/ThreatIntelPage.tsx`
- Modify: `ui/pages/policies/components/PoliciesPageHeader.tsx`
- Modify: `ui/pages/integrations/components/IntegrationsHeader.tsx`
- Test: `ui/components/layout/PageLayout.test.tsx`, affected component tests

- [ ] **Step 1: Add failing page-layout tests for actions wrapping and shared copy rendering**

```tsx
expect(html).toContain('lg:flex-row');
expect(html).toContain('flex-wrap');
```

- [ ] **Step 2: Run the layout test to verify it fails**

Run: `cd ui && npm test -- PageLayout.test.tsx`

Expected: FAIL until the shared layout component exists and pages consume it.

- [ ] **Step 3: Refactor pages to the shared layout primitive**

```tsx
return (
  <PageLayout
    title="Integrations"
    description="Configure external inventory providers used by policy dynamic source selectors."
    actions={<IntegrationsHeaderActions ... />}
  >
    ...
  </PageLayout>
);
```

- [ ] **Step 4: Run focused UI tests**

Run: `cd ui && npm test -- PageLayout.test.tsx ThreatAnalysisCard.test.tsx ThreatDisableBanner.test.tsx AuditFindingsTable.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ui/components/layout/PageLayout.tsx ui/components/layout/PageLayout.test.tsx ui/pages/IntegrationsPage.tsx ui/pages/AuditPage.tsx ui/pages/DNSCachePage.tsx ui/pages/ServiceAccountsPage.tsx ui/pages/SettingsPage.tsx ui/pages/WiretapPage.tsx ui/pages/ThreatIntelPage.tsx ui/pages/policies/components/PoliciesPageHeader.tsx ui/pages/integrations/components/IntegrationsHeader.tsx
git commit -m "refactor: unify page frame across core UI pages"
```

### Task 4: Tighten Theme Tokens And Shared Surface Contrast

**Files:**
- Modify: `ui/index.css`
- Modify: `ui/index.html`
- Modify: `ui/app/AppHeader.tsx`
- Test: `ui/components/layout/PageLayout.test.tsx` (sanity) + full UI suite

- [ ] **Step 1: Write a failing navigation/header test that expects stronger shared shell semantics**

```tsx
expect(html).toContain('Operator console');
expect(html).toContain('border-subtle');
```

Use the smallest test that forces the header/shell copy or structure you actually want to keep stable.

- [ ] **Step 2: Run the targeted test to verify it fails**

Run: `cd ui && npm test -- AuthenticatedShell.test.tsx`

Expected: FAIL until the shell/header markup is updated.

- [ ] **Step 3: Tune the visual foundation**

```css
:root {
  --bg: #eef3f8;
  --bg-glass-strong: rgba(255,255,255,0.88);
  --border-subtle: rgba(148, 163, 184, 0.38);
  --text-secondary: #52627a;
  --text-muted: #6f819a;
}
```

```html
<!-- remove the runtime Tailwind CDN dependency once the class set is captured locally or otherwise justified -->
```

If removing the CDN script is too large for this slice, keep it and only ship the token/contrast improvements now.

- [ ] **Step 4: Run the full UI suite**

Run: `cd ui && npm test`

Expected: PASS with 0 failures.

- [ ] **Step 5: Commit**

```bash
git add ui/index.css ui/index.html ui/app/AppHeader.tsx ui/app/AuthenticatedShell.test.tsx
git commit -m "style: strengthen shell contrast and shared surfaces"
```

### Task 5: Manual Verification Against The Live Appliance

**Files:**
- Modify: none
- Test: live screenshots under `tmp/ui-review-live-2026-03-22/` or a fresh capture directory

- [ ] **Step 1: Rebuild screenshots from the live appliance after the refactor**

Run the same Playwright flow used during review against `https://192.168.178.76:8443/`.

- [ ] **Step 2: Verify desktop shell and mobile shell behavior**

Check:
- desktop pages preserve navigation and page titles
- mobile screenshots no longer show a permanently visible desktop sidebar
- audit, threats, and policies remain readable with live data

- [ ] **Step 3: Record any regressions before further page-specific redesign work**

Only after this manual pass should the next plan cover dense-screen redesigns such as `Policies` and `Audit`.
