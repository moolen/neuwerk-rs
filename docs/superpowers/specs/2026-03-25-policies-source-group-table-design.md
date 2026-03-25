# Policies Source-Group Table Design

## Summary

Restructure the UI Policies page so the default view shows a source-group table for a selected policy instead of a permanent split view with a policy rail and full editor. Opening a source group should render an in-page overlay editor on the same Policies route. The existing backend policy data model remains unchanged: multiple policy records still exist and remain visible in the UI through a policy selector so policies created outside the UI, such as via Terraform, stay discoverable.

The redesign also introduces simple cluster-global policy telemetry for the table `Hits` column. Telemetry stores hourly source-group hit counters per node and aggregates them across the cluster on demand. The initial metric is hit count only, not throughput.

## Goals

- Make the default Policies page a scan-friendly list view instead of a permanent editor.
- Show source groups, not entire policy records, as the primary table rows.
- Keep multiple policy records visible and selectable in the UI.
- Reuse as much of the existing policy builder and save lifecycle as possible.
- Add a simple cluster-global telemetry path so the table can show 24h hit totals and a previous-window trend indicator.

## Non-Goals

- Changing the persisted policy data model or API semantics around multiple policies.
- Adding per-rule throughput, bytes, or PPS telemetry.
- Introducing a brand-new source-group-only persistence API.
- Cross-policy source-group movement or bulk editing.
- Changing the dataplane/control-plane boundary by moving control-plane logic into the dataplane.

## Current Problem

Today the Policies page permanently renders both:

- a left-side policy blade / snapshot rail
- a full policy editor

This makes the page editing-heavy even when the user only wants to inspect configured policies. It also emphasizes policy records instead of the source groups that users actually reason about most often.

## User Experience

### Default Page State

The default Policies page loads into a pure list state with no editor open.

The page includes:

- the existing page header actions (`Refresh`, `New Policy`)
- a policy selector dropdown showing all available policy records
- a source-group table for the currently selected policy

If policies exist, the page selects one policy in the dropdown but does not auto-open an editor. If no policies exist, the page still renders the page shell and empty-state messaging for creating the first policy.

### Policy Selection

The selected policy determines the table contents. The dropdown must list all policy records returned by the existing API so externally managed policies remain visible in the UI. Changing the selected policy:

- reloads the current draft/editor state for that policy as needed
- updates the source-group table
- closes any open source-group overlay editor

### Table Rows

The table shows one row per source group within the selected policy.

#### Columns

`Source Identity`
- Primary information: source group identifier / display name
- Secondary information: CIDRs and IPs
- Optional compact Kubernetes summary if the group contains Kubernetes sources

`L3/L4/DNS/DPI Rules`
- Render as muted pills
- Summarize major rule selectors for scanability rather than full fidelity
- Examples:
  - `TCP:443,80`
  - `UDP:53`
  - `*.api.internal`
  - `TLS intercept`

`Action`
- Render as a colored pill
- Group-level summary rules:
  - `Allow` if all rules in the source group resolve to allow
  - `Deny` if all rules in the source group resolve to deny
  - `Mixed` if both allow and deny rules are present

`Hits`
- Show the aggregated hit count for the last 24 hours
- Show an up/down indicator plus percentage change compared with the previous 24-hour window
- If telemetry is missing or partial, show a fallback state instead of blocking the table

Right-side controls
- Reorder affordance for changing source-group order within the selected policy
- Three-dots context menu for source-group actions such as edit and delete

### Row Interaction

Clicking a source-group row opens the source-group editor overlay for that group.

### Empty States

If the selected policy has no source groups, the page shows an empty state with a CTA to create the first source group. This does not open automatically unless the user explicitly chooses to create one.

## Overlay Editor

### Behavior

The source-group editor is an overlay over the Policies page content area. It is not a modal and does not use a dimmed backdrop. The user stays on the same Policies page route.

The overlay includes:

- a header showing the source-group identity
- the selected policy name or identifier for context
- close and save actions

### Editor Scope

The overlay edits exactly one source group from the selected policy at a time.

The current full policy builder content is reused where possible, but rendering is scoped to the selected source group:

- only the targeted source group is rendered in the editor body
- the rest of the policy draft remains in memory but is not shown
- source-group and rule editing controls remain available inside the scoped view

### Create / Edit / Delete

`Edit source group`
- Opens the overlay for the clicked row

`Create source group`
- Opens the overlay in create mode for the selected policy
- Appends a new source group into the selected policy draft

`Delete source group`
- Removes the group from the selected policy draft
- Persists through the existing policy save path
- Closes the overlay after a successful delete

### Save Semantics

The UI continues to persist full policy records using the existing API. The overlay is only a scoped editing surface over the policy draft, not a new persistence model.

## Ordering

Reordering in the table updates the source-group order within the selected policy only. No cross-policy movement is supported.

The UI should preserve or update the existing source-group ordering mechanism already used by the builder. The selected policy record remains the persistence boundary.

## Telemetry

### Purpose

The table needs a simple `Hits` column that reflects cluster-global activity for each source group. Existing UI data sources do not provide stable per-policy or per-source-group traffic telemetry, so a dedicated telemetry path is required.

### Metric

The initial metric is source-group hit count.

Out of scope for this iteration:

- bytes
- throughput
- PPS
- per-rule breakdown

### Aggregation Model

Telemetry is keyed by:

- `policy_id`
- `source_group_id`
- `hour_bucket`

Each node stores local hourly buckets. The cluster leader aggregates node-local results on demand into a cluster-global response, using the same general leader fan-out pattern already used for audit aggregation.

### Granularity

- Bucket size: 1 hour
- Retention only needs to support the current and previous 24-hour windows plus a small buffer for boundary handling

### Read Path

The UI needs a control-plane API that returns, for the selected policy:

- per-source-group hit total for the last 24 hours
- per-source-group hit total for the previous 24-hour window
- partial-cluster metadata if some nodes fail to respond

The UI computes or receives:

- current 24h value
- previous 24h value
- trend direction
- trend percentage

### Partial Results

If some cluster members fail to return telemetry:

- the API returns aggregated data from responsive nodes
- the response is marked partial
- node errors are included for diagnostics
- the UI still renders available values

If no telemetry is available for a source group, the UI renders a neutral fallback such as `No data`.

### Collection Semantics

Telemetry counts source-group hits at the policy/source-group level. It should remain simple and should not introduce control-plane parsing into the dataplane. Instrumentation should attach to existing decision points and emit compact counters that can be stored by the control plane without changing the visible policy model.

## State Management

The existing policy draft shape remains the primary editing model.

Additional UI state is needed for:

- selected policy id
- overlay open/closed
- overlay mode (`create-group` or `edit-group`)
- selected source-group id

Switching policies resets source-group overlay state to avoid accidental edits against the wrong policy.

## Error Handling

The page should fail soft where possible:

- policy list or policy load failures continue to surface as page-level errors
- telemetry failures do not block table rendering
- partial telemetry responses render available counts and a degraded state rather than collapsing the page

Overlay save/delete failures remain scoped to the editor surface and should not destroy the current draft state.

## Testing Requirements

### UI

- Policies page renders a policy selector and source-group table instead of the permanent split-view editor
- The default page state has no editor open
- Switching the policy updates the table and closes any open overlay
- Clicking a row opens the source-group overlay
- The overlay renders only the targeted source group
- Reorder controls update source-group ordering within the selected policy
- Action badges show `Allow`, `Deny`, or `Mixed` correctly
- Hits cells render populated, empty, and partial states correctly

### Control Plane

- Hourly buckets roll up correctly into current and previous 24h windows
- Cluster aggregation merges node-local telemetry correctly
- Partial node failures still return partial aggregated results
- Unknown or deleted source groups do not corrupt aggregation behavior
- Retention and pruning keep bucket storage bounded

### Regression

- Existing policy create, update, and delete flows still persist through the current policy API
- Policies created outside the UI remain visible through the selector
- The scoped overlay editor does not mutate unrelated source groups accidentally

## Risks And Constraints

- The current builder is policy-centric, so scoping it to a single source group must avoid introducing a second draft model that can drift from the saved policy representation.
- Group-level `Action` is inherently a summary over rule-level actions, so the UI must use `Mixed` when needed instead of forcing a misleading single value.
- Telemetry must remain control-plane aggregation and storage logic; no DNS parsing or control-plane behavior should move into the dataplane.

## Recommended Implementation Direction

Implement this as a page restructure plus scoped editor composition, not a backend policy-model change.

Specifically:

- keep the current policy APIs and persisted model
- replace the current list/editor split layout with a selector + source-group table
- add a same-page overlay editor scoped to one source group
- add a simple cluster-global hourly hit counter path for source-group rows

This keeps the UX aligned with the requested workflow while minimizing data-model churn and preserving compatibility with Terraform-managed policies.
