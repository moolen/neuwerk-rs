# `neuwerk_policy`

Manages an aggregate Neuwerk policy document through the by-name policy API.

## Key Arguments

- `name`
- `mode`
- `default_action`
- `document_json`
- `source_group`

## Computed Attributes

- `id`
- `created_at`
- `compiled_json`

## Notes

- Policy is managed as one aggregate document.
- `document_json` is the low-level escape hatch.
- Nested `source_group` blocks are compiled into canonical API policy JSON.

## Import

Import by policy name.
