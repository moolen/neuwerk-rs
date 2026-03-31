# Policies Full-Page Source Group Overlay Design

## Summary

The Policies page currently opens source-group editing inside an inline overlay anchored to `data-overlay-anchor="policy-main-content"`. That surface is narrower than the full Policies page and leaves the page header/actions visible, which makes the interaction feel misaligned with the rest of the policy editor. The source-group row action menu copy is also longer than needed.

This change keeps the existing overlay interaction model, but promotes the source-group editor to a full-page Policies overlay that covers the entire Policies page surface, including the header action row.

## Goals

- Make source-group editing feel like a first-class editing state of the Policies page.
- Cover the full Policies page, including `Refresh`, `Delete policy`, and `New Policy`.
- Keep the current save/close lifecycle and avoid a larger rewrite into a separate page mode.
- Shorten the row action menu labels to `Edit` and `Delete`.

## Non-Goals

- Replacing the overlay system with route navigation or a dedicated page mode.
- Changing policy save/delete lifecycle behavior.
- Reworking the source-group editor fields or builder structure.

## Current Problem

- The editor overlay is anchored inside the main content area, not the full Policies page.
- The overlay width is capped as an inline panel, so it does not match the full policy editor width.
- The header/action row remains visible outside the editing surface.
- The row action menu uses longer labels than necessary.

## Proposed Design

### Overlay Scope

Move the source-group editor overlay anchor from the current `policy-main-content` subtree to the top-level Policies page content container.

Result:

- Opening a source group covers the entire Policies page surface.
- The overlay includes the header/action row in its covered area.
- The underlying Policies page remains mounted, but is visually fully overlaid.

### Overlay Width And Layout

Keep the overlay implementation, but make the editing surface full-width relative to the Policies page shell instead of rendering it as a right-aligned inline panel.

Result:

- The editor width matches the full page content width used by the policy editor.
- The source-group editor reads as a full editing state instead of a side panel.

### Menu Copy

In the source-group row overflow menu:

- `Edit source group` becomes `Edit`
- `Delete source group` becomes `Delete`

This keeps the menu compact without changing behavior.

## Interaction Flow

1. User clicks the row overflow menu or a source-group row.
2. Policies page enters source-group overlay state.
3. A full-page overlay covers the entire Policies page, including the header/action row.
4. User edits the selected source group.
5. `Close` returns to the underlying Policies page state without saving.
6. `Save policy` persists the current policy snapshot using the existing save path.

## Implementation Notes

- Reuse the existing overlay state machine (`closed`, `create-group`, `edit-group`).
- Reuse the existing `ScopedSourceGroupEditor` and current save/close wiring.
- Update the Policies page composition so the overlay is rendered from the full page container rather than the main content subtree.
- Adjust overlay markup/styles so the surface spans the full page width.
- Update tests that currently assert the old inline overlay anchoring behavior.

## Testing

- Add or update page-structure tests to assert the full-page overlay anchor placement.
- Update overlay tests to assert the surface is full-page rather than inline-panel scoped.
- Update row/menu tests to assert the shorter `Edit` and `Delete` labels.
- Run focused Policies UI tests and a fresh UI build.

## Risks

- Moving the anchor higher in the page tree may affect z-index or stacking relative to the page shell.
- Full-page coverage must not break existing save/close behavior.
- Existing tests referencing inline overlay semantics will need to be updated deliberately rather than loosened.
