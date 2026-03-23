# Firewall UI Dashboard Hierarchy Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `Dashboard` read as an intentional health surface instead of a stack of independent metric cards.

**Architecture:** Preserve the existing dashboard data source, refresh cadence, and metric content. Recompose only the presentation so the page opens with a stronger cluster-health summary band, overview cards carry more meaning, and lower sections are grouped into clearer traffic/control/replication layers without changing the underlying stats.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared design tokens from `ui/index.css`

---

### Task 1: Lock The New Dashboard Landmarks With Tests

**Files:**
- Create: `ui/pages/dashboard/components/DashboardHierarchy.test.tsx`
- Test: `ui/pages/dashboard/components/DashboardHierarchy.test.tsx`

- [ ] **Step 1: Write failing tests for the new Dashboard grouping cues**

```tsx
expect(html).toContain('Cluster posture');
expect(html).toContain('Traffic and policy');
expect(html).toContain('Control-plane state');
expect(html).toContain('Replication and system');
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd ui && npm test -- DashboardHierarchy.test.tsx`

Expected: FAIL because the current Dashboard has no explicit grouping or posture layer.

- [ ] **Step 3: Implement the minimal presentational changes**

Preserve all existing metrics and refresh behavior.

- [ ] **Step 4: Run the focused test to verify it passes**

Run: `cd ui && npm test -- DashboardHierarchy.test.tsx`

Expected: PASS.

### Task 2: Recompose The Dashboard Surface

**Files:**
- Modify: `ui/pages/Dashboard.tsx`
- Modify: `ui/pages/dashboard/components/DashboardHeader.tsx`
- Modify: `ui/pages/dashboard/components/DashboardStatsView.tsx`
- Modify: `ui/pages/dashboard/components/DashboardOverviewCards.tsx`
- Modify: `ui/pages/dashboard/components/DashboardSectionCard.tsx`
- Modify: `ui/pages/dashboard/components/DashboardSystemSection.tsx`
- Modify: `ui/pages/dashboard/components/DashboardRaftCatchupSection.tsx`
- Test: `ui/pages/dashboard/components/DashboardHierarchy.test.tsx`
- Test: `ui/pages/SharedPageFrames.test.tsx`

- [ ] **Step 1: Add a compact posture band that summarizes cluster state and refresh cadence**

- [ ] **Step 2: Strengthen the overview cards so each one reads as a health signal, not just a number**

- [ ] **Step 3: Group lower sections into traffic, control-plane, and replication/system layers**

- [ ] **Step 4: Run the focused dashboard tests**

Run: `cd ui && npm test -- DashboardHierarchy.test.tsx SharedPageFrames.test.tsx`

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
- `dashboard-desktop-implemented.png`
- `dashboard-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- dashboard opens with a stronger health narrative
- section rhythm is clearer from top to bottom
- mobile keeps a clean scan path instead of feeling like a long series of similar cards
