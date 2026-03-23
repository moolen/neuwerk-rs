# Threats Sidebar Split Design

## Summary

The current admin UI exposes one `Threats` destination that combines three different workflows:

- feed freshness and section overview
- investigation of threat findings
- management of threat silences

This design splits those workflows into a threat section with one overview page and two child destinations in the sidebar:

- `Threats` stays the top-level section entry and overview page
- `Findings` becomes a child page for investigation
- `Silences` becomes a child page for suppression management

The sidebar only expands the `Threats` submenu while the current route is inside the threat section.

## Goals

- Reduce the cognitive load on the current `Threats` page
- Preserve `Threats` as the high-level entry point for feed health and freshness
- Give investigation and silence management distinct URLs and page labels
- Keep the sidebar model aligned with the routing model
- Reuse the existing threat UI components and data hooks where practical

## Non-Goals

- Redesign the overall app shell
- Change threat-intel backend APIs
- Add new threat workflows beyond the existing feeds, findings, and silences features
- Introduce permanently expanded sidebar groups outside the threat section

## User Experience

### Sidebar Behavior

The sidebar becomes section-aware for threat pages.

- `Threats` remains a visible top-level nav item
- `Findings` and `Silences` render as indented child nav items under `Threats`
- the child items remain hidden for non-threat routes
- when the current page is `Threats`, `Findings`, or `Silences`, the threat section expands
- the exact current destination receives the active item treatment
- the parent `Threats` item also remains visually active at the section level while a child page is selected

This produces a compact sidebar in normal use while still exposing the section structure once the user is working inside threats.

### Route Model

The threat section uses explicit routes:

- `/threats` for the overview page
- `/threats/findings` for findings
- `/threats/silences` for silences

Backward compatibility:

- `/threat-intel` should continue to resolve into the threat overview route

### Page Boundaries

#### Threats Overview

The overview page is responsible for section-wide status.

Content kept on this page:

- threat analysis disabled banner
- partial cluster response banner
- node query error summary
- feed freshness and feed status panels
- optional compact headline metrics that summarize current findings volume

Content removed from this page:

- detailed findings filters and results table
- silence management panel and create/delete workflows

#### Findings

The findings page becomes the investigation workspace.

Content on this page:

- findings count and findings-focused page actions
- audit-linked view state and reset action
- findings filters
- threat findings table
- row actions that create exact or hostname-regex silences
- any lightweight banners needed to explain disabled or partial results

This page keeps the existing investigation workflow intact while separating it from operational feed status.

#### Silences

The silences page becomes the suppression workspace.

Content on this page:

- create silence action
- current silence list
- delete silence actions
- supporting text for exact and hostname-regex silences
- any lightweight banners needed to explain disabled or partial results if the page still depends on shared threat state

## Architecture

### Navigation Metadata

The existing flat `AppPage` and `NAV_ITEMS` model is extended to support threat child pages.

Required changes:

- add dedicated app pages for threat findings and threat silences
- extend navigation metadata so a nav item can optionally declare a parent
- add helpers that determine:
  - whether an item belongs to the currently active section
  - whether a parent section should be expanded
  - whether a parent item is active because one of its children is selected

The canonical navigation model remains centralized in `ui/navigation.ts`.

### Page Rendering

The shell continues to render pages from the canonical `AppPage` mapping.

Required changes:

- add route-to-page parsing for `/threats/findings` and `/threats/silences`
- update page-to-path rendering for the new pages
- add dedicated page components for the two new child routes
- keep `Threats` mapped to the overview page

### Shared Threat UI State

The current threat page fetches and manages state for feeds, findings, silences, banners, and create/delete operations in one place. That should be split by concern without duplicating backend logic.

Recommended structure:

- keep shared domain types and API clients as-is
- extract common threat loading logic into shared hook/helpers where needed
- give each route-level page a focused hook or focused selector layer
- only request and render the data a page actually needs

Likely split:

- overview page hook: feed status, disabled state, partial state, node errors, optional summary counts
- findings page hook: findings, filters, disabled state, partial state, node errors, create silence
- silences page hook: silences, disabled state if needed, create/delete silence

The exact implementation can be incremental. A temporary shared hook is acceptable if the route-level pages stay distinct and the data dependencies remain readable.

## Data Flow

### Threats Overview

1. route resolves to `/threats`
2. overview page loads section status data
3. page renders banners first, then feed freshness, then summary metrics

### Findings

1. route resolves to `/threats/findings`
2. findings page loads findings and filter metadata
3. user updates filters or refreshes
4. page reloads findings for the current filter set
5. user can create a silence directly from a finding row
6. successful silence creation updates the relevant local state and removes or suppresses affected findings according to current behavior

### Silences

1. route resolves to `/threats/silences`
2. silences page loads current silence data
3. user creates or deletes a silence
4. page refreshes silence state and reflects the update

## Error Handling

- existing threat error banner behavior should remain consistent across the split pages
- pages that depend on cluster-wide threat queries should continue to surface partial results and node-level errors
- the overview page must still surface threat analysis disabled state clearly because it is the section landing page
- findings and silences pages should avoid blank states that hide actionable problems such as request failures or disabled analysis

## Testing

### Navigation Tests

Add or update tests for:

- parsing `/threats`, `/threats/findings`, `/threats/silences`, and legacy `/threat-intel`
- path generation for the new app pages
- page labels for overview and child pages
- sidebar filtering and section expansion behavior
- active-state behavior for parent and child nav items

### Page Rendering Tests

Add focused tests for:

- overview page rendering feed freshness without findings and silences content mixed into the same page
- findings page rendering the findings-specific controls and table
- silences page rendering the silence list and creation controls
- authenticated shell header label showing the selected child page label

### Regression Tests

- preserve existing threat table and silence interaction behavior
- preserve mobile navigation rendering with threat child items visible only while in the threat section

## Implementation Notes

- prefer reusing existing threat components over rewriting them
- the sidebar visual treatment for children should stay consistent with the current shell style system
- the implementation should avoid introducing ad hoc route parsing outside `ui/navigation.ts`
- any shared logic extracted from the current `ThreatIntelPage` should be named by responsibility rather than by old page identity

## Risks

- a naive split can duplicate threat loading logic across three pages
- parent/child active-state styling can become inconsistent between desktop and mobile sidebars if the shell uses separate assumptions
- route parsing drift can break direct-link navigation if path handling is not centralized

## Recommendation

Implement a true threat section with nested destinations at the routing level and conditional child items in the sidebar. Keep `Threats` as the overview page and move investigation and silence workflows to their own focused pages. This matches the intended information architecture and keeps future threat-related destinations extensible without reworking the sidebar again.
