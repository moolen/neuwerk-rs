# Singleton Policy Design

## Summary

Neuwerk currently exposes multiple stored policy records in the UI, HTTP API, cluster replication,
and Terraform provider, while the dataplane only evaluates one active policy at a time. This
design removes that mismatch.

The new model is a single canonical policy document that is always present and always active. The
UI becomes source-group and rule oriented instead of policy-record oriented. Top-level policy
identity and lifecycle concepts disappear: no policy selector, no policy name, no create/delete
controls, no active-policy pointer, and no record history.

This is a hard product cut. No backward-compatible API surface is retained.

## Goals

- Align control-plane product behavior with dataplane reality.
- Remove multi-policy record management from the UI and HTTP API.
- Eliminate top-level policy mode and move rollout semantics to `source_group` and optional rule
  overrides.
- Remove policy CRUD from the Terraform provider instead of replacing it with source-group or rule
  resources.
- Collapse local persistence and cluster replication from record-store semantics to singleton-state
  semantics.
- Remove policy-id coupling from telemetry and audit surfaces where it no longer carries meaning.

## Non-Goals

- Preserving backward compatibility for policy APIs, UI flows, docs, or Terraform resources.
- Retaining user-visible policy history, revisions, rollback, or named policy imports.
- Turning `source_group` and `rule` into independent backend CRUD resources.
- Preserving the current meaning of top-level `PolicyMode` and `rule.mode`.

## Product Decisions

### Singleton Policy

- There is exactly one policy document.
- It is automatically provisioned if none exists yet.
- It is always active.
- It has no user-visible `id`, `name`, `created_at`, or top-level lifecycle operations.

### No Top-Level Mode

- Remove top-level policy `mode`.
- Remove the concept of a disabled policy.
- Remove whole-policy audit mode.

### Mode Lives Lower In The Tree

- Add `mode` to `source_group`.
- Allow rules to optionally override the containing source-group mode.
- Supported values are `enforce` and `audit`.

Recommended semantics:

- source-group mode is the default for rules inside that group.
- rule mode, when present, overrides the source-group mode.
- `enforce` means a matching deny is enforced.
- `audit` means the deny is recorded but traffic is allowed.

This is intentionally not the same as the current evaluator split between top-level policy mode and
rule participation mode. The evaluator should be redesigned around effective match mode, not
renamed in place.

## Why Not Independent Source-Group And Rule Resources

The backend should remain an aggregate policy document.

Evaluation depends on:

- ordered source groups
- ordered rules
- source-group defaults
- first-match semantics
- mode inheritance from source group to rule

Splitting this into separate backend resources would introduce transactional problems, ordering
conflicts, and inconsistent intermediate states for a policy model that is fundamentally evaluated
as one ordered graph. The cleaner design is a singleton aggregate backend with a UI centered on
editing source groups and rules inside that document.

## External API Design

Replace record CRUD with a singleton API:

- `GET /api/v1/policy`
- `PUT /api/v1/policy`

Remove:

- `GET /api/v1/policies`
- `GET /api/v1/policies/{id}`
- `GET /api/v1/policies/by-name/{name}`
- `POST /api/v1/policies`
- `PUT /api/v1/policies/{id}`
- `PUT /api/v1/policies/by-name/{name}`
- `DELETE /api/v1/policies/{id}`

The singleton request/response body should contain only the policy document. It should not include
record metadata or top-level mode.

## UI Design

The Policies page becomes a singleton editor surface:

- remove the policy selector
- remove the policy name field
- remove create, delete, and policy-level refresh controls
- remove policy snapshot and selected-policy concepts
- load one canonical policy document on entry
- save the canonical policy document in place

The primary authoring model becomes:

- source groups
- rules within a source group
- source-group mode
- optional rule mode override

The UI should still keep local draft editing, validation, and save behavior, but it should no
longer model selection among multiple policy records.

## Local Persistence Design

Replace the local policy repository model:

- remove `index.json`
- remove `active.json`
- remove `policies/<id>.json`

Replace it with one canonical local policy state file.

Recommended local semantics:

- one persisted singleton document
- one persisted compiled/runtime-ready projection only if needed by existing startup code
- no active pointer
- no record metadata

`PolicyStore` should stop carrying active policy identifiers. It should just expose the compiled
singleton policy state.

## Cluster Replication Design

Replace cluster record-store keys:

- remove `policies/index`
- remove `policies/active`
- remove `policies/item/<id>`

Replace them with one singleton policy key.

Recommended semantics:

- leader writes the singleton document
- followers replay the singleton document
- readiness is based on replay of the singleton policy, not active-pointer resolution

This removes current edge cases where the active pointer and policy record can move independently.

## Telemetry And Audit Design

Current policy telemetry is keyed by `policy_id`, which stops making sense under a singleton model.

Change policy telemetry to:

- stop storing `policy_id`
- stop exposing telemetry endpoints under `/api/v1/policies/{id}/telemetry`
- expose singleton policy telemetry without a policy identifier

Audit surfaces should also stop carrying `policy_id` once there is only one policy. Leaving it as
permanently `null` would preserve dead schema.

## Terraform Provider Design

Remove policy management from the provider.

Specifically:

- remove `neuwerk_policy`
- remove by-name policy client helpers
- remove policy docs and examples
- remove policy-specific provider tests

Do not replace it in this change with `source_group` or `rule` Terraform resources. The backend is
still aggregate and singleton; forcing source groups or rules into standalone Terraform resources
would push the provider toward managing partial state that the backend does not model natively.

## Migration Design

This is a hard cut, but existing installations still need deterministic migration.

### Legacy To Singleton Migration

If legacy record-based state exists:

- if an active policy record exists, migrate that active record into the singleton policy document
- ignore inactive policy records
- remove legacy local files and cluster keys after successful migration

If no legacy policy exists:

- bootstrap a singleton policy automatically

Recommended bootstrapped policy shape:

- preserve current default runtime behavior
- keep `source_groups` empty

This avoids surprising operators with a behavior change caused purely by storage conversion.

### No History Retention

- do not retain inactive records
- do not keep hidden revisions
- do not preserve import-by-name aliases

There is no cleanup problem after migration because saves overwrite the one canonical document.

## Documentation Changes

Update operator-facing docs to describe:

- singleton always-active policy
- no policy naming or selection
- no top-level policy mode
- source-group and rule-level mode semantics
- no Terraform policy resource

Docs that currently describe policy records, active policy selection, or policy-name import must be
rewritten rather than patched around with legacy notes.

## Codebase Areas Expected To Change

### UI

- `ui/pages/PoliciesPage.tsx`
- `ui/pages/policies/usePolicyBuilder.ts`
- `ui/pages/policies/usePolicyBuilderState.ts`
- `ui/pages/policies/policyBuilderRemote.ts`
- `ui/pages/policies/policyBuilderLifecycle*`
- `ui/pages/policies/components/PolicySelector.tsx`
- `ui/pages/policies/components/PolicySnapshotsPanel.tsx`
- `ui/pages/policies/components/PolicySnapshotRow.tsx`
- `ui/pages/policies/components/PolicyEditorActions.tsx`
- `ui/pages/policies/components/PolicyBasicsSection.tsx`
- related UI tests and dev-mock routes

### HTTP API And OpenAPI

- `src/controlplane/http_api/policy.rs`
- `src/controlplane/http_api.rs`
- `src/controlplane/http_api/openapi.rs`
- `www/public/openapi/neuwerk-v1.json`

### Persistence, Replication, Readiness, Sysdump

- `src/controlplane/policy_repository.rs`
- `src/controlplane/http_api/cluster_persistence.rs`
- `src/controlplane/policy_replication.rs`
- `src/controlplane/ready.rs`
- `src/runtime/bootstrap/policy_state.rs`
- `src/runtime/sysdump.rs`
- `src/controlplane/cluster/migration.rs`

### Policy Evaluation

- `src/controlplane/policy_config.rs`
- `src/controlplane/policy_config/parse.rs`
- `src/dataplane/policy/model.rs`
- `src/dataplane/policy/evaluation.rs`
- policy tests in dataplane, control plane, HTTP API, and e2e coverage

### Telemetry And Audit

- `src/controlplane/policy_telemetry.rs`
- `src/controlplane/http_api/policy_telemetry.rs`
- `ui/services/apiClient/policies.ts`
- `ui/pages/policies/policyTelemetryRemote.ts`
- audit filters and UI types carrying `policy_id`

### Terraform Provider

- `terraform-provider-neuwerk/internal/provider/resource_policy.go`
- `terraform-provider-neuwerk/internal/provider/client.go`
- `terraform-provider-neuwerk/internal/provider/policy_test.go`
- `terraform-provider-neuwerk/docs/resources/policy.md`
- `terraform-provider-neuwerk/README.md`
- `terraform-provider-neuwerk/examples/basic/main.tf`

### Docs

- `www/src/content/docs/configuration/policy-model.mdx`
- `www/src/content/docs/interfaces/web-ui.mdx`
- `www/src/content/docs/interfaces/http-api.mdx`
- `www/src/content/docs/interfaces/terraform-provider.mdx`
- `www/src/content/docs/reference/glossary.mdx`
- `www/src/content/docs/tutorials/create-your-first-policy.mdx`
- backup, restore, troubleshooting, cluster replication, and control-plane architecture docs

## Risks

- Changing evaluator semantics incorrectly while removing top-level mode.
- Accidentally preserving old rule-mode semantics under a new schema name.
- Leaving stale `policy_id` assumptions in telemetry, audit, UI filters, or tests.
- Incomplete migration where legacy and singleton state coexist too long.
- Breaking cluster replay/readiness if singleton replication is not cut through all startup paths.
- Breaking docs and examples by leaving policy-record language in place after the product model
  changes.

## Verification

Required acceptance criteria:

- The UI edits exactly one policy document and never exposes policy selection, naming, creation, or
  deletion.
- The HTTP API exposes only singleton policy read/write endpoints.
- Local storage and cluster replication use only singleton policy state.
- Legacy active-record state migrates correctly into the singleton model.
- Policy telemetry and audit surfaces no longer require `policy_id`.
- The Terraform provider no longer exposes a policy resource.
- Operator-facing docs describe the singleton model and lower-level mode semantics accurately.

Required test coverage:

- singleton HTTP API read/write
- bootstrap of the canonical empty policy
- legacy record-to-singleton migration
- cluster replication and join behavior for singleton policy state
- evaluator behavior for source-group mode and rule override mode
- focused Policies UI lifecycle and rendering tests
- Terraform provider/docs tests after policy removal
- sysdump/readiness behavior after migration
