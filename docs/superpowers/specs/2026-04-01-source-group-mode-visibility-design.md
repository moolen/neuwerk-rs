# Source Group Mode Visibility Design

## Summary

The policy model still supports `mode` on each source group, but the Policies UI does not currently surface it. Users can neither see the effective source-group rollout posture in the list nor edit it from the source-group editor.

This change adds source-group mode back to the UI in two places: an editable control inside the source-group editor and a read-only status chip in the source-group list.

## Goals

- Make source-group `audit` vs `enforce` visible in the Policies UI.
- Keep editing localized to the source-group editor.
- Show the current mode in the source-group list for quick scanning.
- Preserve rule-level mode overrides and existing save behavior.

## Non-Goals

- Adding table-inline editing for source-group mode.
- Reintroducing unsupported top-level policy mode controls.
- Changing DNS or dataplane enforcement semantics.

## Current Problem

- The source-group editor exposes group name and fallback action, but not group mode.
- The source-group list shows identity, rule summary, fallback action, and hits, but not rollout posture.
- Users cannot verify from the UI whether a source group defaults to `audit` or `enforce`.

## Proposed Design

### Source-Group Editor

Add a `Mode` control to the source-group header section with two chips:

- `Audit`
- `Enforce`

This control edits `group.mode` in the current policy draft. It sits alongside the existing group name and fallback fields because all three define group-level defaults.

Supporting copy should explain that source-group mode is the default enforcement posture for the group and that individual rules may override it.

### Source-Group List

Add a small read-only mode chip to each source-group row.

The chip should:

- Show `Audit` or `Enforce`
- Use the existing chip/badge visual language
- Be informational only

This keeps the list scannable without introducing a second editing surface.

## Interaction Flow

1. User opens a source group from the list.
2. The source-group editor shows the current group mode.
3. User changes mode in the editor if needed.
4. Returning to the list shows the updated mode chip immediately in draft state.
5. Saving persists the policy through the existing singleton policy save path.

## Implementation Notes

- Reuse the existing draft update pattern used for source-group ID and fallback action.
- Add a focused draft mutation/helper for source-group mode updates instead of inlining object mutation across components.
- Update the source-group row rendering to include a read-only mode chip without making the row more interactive than it already is.
- Keep list and editor copy aligned with the actual product model: mode exists on source groups and rules, not on the top-level singleton policy.

## Testing

- Add or update a source-group editor test to verify mode is rendered and can be changed.
- Add or update a source-group row/table test to verify the mode chip is visible.
- Add or update a page-level test to verify the Policies page surfaces source-group mode in the list.
- Run focused UI tests, then the full `ui` test suite.

## Risks

- The row layout is already dense, so the new chip must not make the table harder to scan on smaller widths.
- Editor copy must distinguish clearly between group mode and group fallback action.
- Existing tests may assume only fallback action is shown at the group summary level.
