# Firewall UI DNS Cache Hierarchy Pass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `DNS Cache` page read as an intentional operator surface instead of a loose search box plus raw table.

**Architecture:** Preserve the existing DNS cache fetch, search filtering, and refresh behavior. Recompose only the presentation so the page opens with a compact cache posture summary, the search and refresh controls sit inside a labeled operator panel, and the results area reads as an “observed mappings” surface across desktop and mobile.

**Tech Stack:** React 19, TypeScript, Vitest, render-to-static-markup tests, Tailwind utility classes, shared design tokens from `ui/index.css`

---

### Task 1: Lock The New DNS Cache Landmarks With Tests

**Files:**
- Create: `ui/pages/dns-cache/components/DNSCachePageStructure.test.tsx`
- Modify: `ui/pages/dns-cache/components/DNSCacheTable.test.tsx`
- Test: `ui/pages/dns-cache/components/DNSCachePageStructure.test.tsx`
- Test: `ui/pages/dns-cache/components/DNSCacheTable.test.tsx`

- [ ] **Step 1: Write failing tests for the new page-level hierarchy cues**

```tsx
expect(html).toContain('Cache posture');
expect(html).toContain('Search and refresh');
expect(html).toContain('Observed mappings');
expect(html).toContain('2 hostnames');
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `cd ui && npm test -- DNSCachePageStructure.test.tsx DNSCacheTable.test.tsx`

Expected: FAIL because the current DNS Cache page has no summary strip or explicit results framing.

- [ ] **Step 3: Implement the minimal presentational changes**

Preserve all existing fetch, refresh, and filtering behavior.

- [ ] **Step 4: Run the focused tests to verify they pass**

Run: `cd ui && npm test -- DNSCachePageStructure.test.tsx DNSCacheTable.test.tsx`

Expected: PASS.

### Task 2: Recompose The DNS Cache Surface

**Files:**
- Modify: `ui/pages/DNSCachePage.tsx`
- Modify: `ui/pages/dns-cache/components/DNSCacheControls.tsx`
- Modify: `ui/pages/dns-cache/components/DNSCacheTable.tsx`
- Test: `ui/pages/dns-cache/components/DNSCachePageStructure.test.tsx`
- Test: `ui/pages/dns-cache/components/DNSCacheTable.test.tsx`

- [ ] **Step 1: Add a compact cache posture band that summarizes visible mappings, search state, and refresh affordances**

- [ ] **Step 2: Turn the search and refresh row into a labeled operator panel with better scan cues**

- [ ] **Step 3: Wrap the table and mobile cards in an “observed mappings” section with stronger empty-state language**

- [ ] **Step 4: Run the focused DNS tests**

Run: `cd ui && npm test -- DNSCachePageStructure.test.tsx DNSCacheTable.test.tsx`

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
- `dns-desktop-implemented.png`
- `dns-mobile-implemented.png`

- [ ] **Step 4: Review the updated screenshots**

Confirm:
- DNS Cache opens with a stronger posture summary instead of jumping straight into widgets
- controls read as one coherent search-and-refresh surface
- empty and populated result states feel deliberate on both desktop and mobile
