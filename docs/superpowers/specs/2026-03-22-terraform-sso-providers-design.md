# Terraform SSO Provider Resources Design

Date: 2026-03-22

## Summary

Neuwerk will add first-class Terraform management for SSO providers through three
separate resources:

- `neuwerk_sso_provider_google`
- `neuwerk_sso_provider_github`
- `neuwerk_sso_provider_generic_oidc`

All three resources manage the existing control-plane SSO provider settings API with
plain CRUD semantics. The design keeps the provider surface explicit and
provider-specific, preserves sensitive `client_secret` state across refresh even though
the API does not return the raw secret, and avoids expanding scope into test actions,
login-flow verification, or new API primitives.

## Goals

- Add Terraform CRUD support for all currently supported Neuwerk SSO provider kinds.
- Make each provider kind a first-class Terraform resource rather than a generic union
  resource.
- Keep the implementation aligned with the existing Terraform provider structure:
  shared API client logic, shared state-mapping helpers, and thin resource wrappers.
- Handle `client_secret` in a way that matches Terraform user expectations for
  sensitive-but-write-only API fields.
- Keep the first implementation small enough for a single focused plan and review
  cycle.

## Non-Goals

- Adding a generic `neuwerk_sso_provider` resource.
- Adding SSO data sources.
- Exposing `/api/v1/settings/sso/providers/:id/test` in Terraform.
- Verifying full login-flow correctness or browser redirects from Terraform.
- Adding secret-manager integrations or alternate secret storage models.
- Expanding the Neuwerk control-plane API unless implementation uncovers a hard
  blocker.

## Current State

The Neuwerk control plane already supports SSO provider management through the HTTP
API:

- `GET /api/v1/settings/sso/providers`
- `POST /api/v1/settings/sso/providers`
- `GET /api/v1/settings/sso/providers/:id`
- `PUT /api/v1/settings/sso/providers/:id`
- `DELETE /api/v1/settings/sso/providers/:id`

The provider kinds currently implemented in the control plane are:

- `google`
- `github`
- `generic-oidc`

The SSO API returns sanitized views rather than the raw secret material. Specifically,
responses include `client_secret_configured: bool` instead of returning `client_secret`.
This means Terraform cannot reconstruct secret state from a read or import operation.

The existing Terraform provider already has established patterns for:

- CRUD resources backed by the Neuwerk HTTP API
- direct unit tests around schema, request shaping, import behavior, and refresh/state
  convergence
- preserving write-only secrets in Terraform state when the API does not return them
  back to the client

The SSO work should follow those patterns rather than introducing a separate framework.

## Decision

Neuwerk will implement three separate Terraform resources:

- `neuwerk_sso_provider_google`
- `neuwerk_sso_provider_github`
- `neuwerk_sso_provider_generic_oidc`

Each resource will map to the same SSO provider API endpoints but will hardcode its
provider kind internally. This keeps Terraform configuration readable, keeps resource
schemas easy to understand, and avoids a large generic schema with kind-dependent field
behavior.

The implementation will use:

- shared API client request and response types for SSO providers
- shared internal schema/state helpers for common fields and lifecycle behavior
- thin per-kind resource wrappers that supply the fixed provider kind and any small
  schema differences

This shape gives users the first-class provider-specific resources they expect while
keeping the implementation maintainable.

## Resource Model

### Shared lifecycle model

All three resources use in-place CRUD against `/api/v1/settings/sso/providers`.

Computed fields:

- `id`
- `created_at`
- `updated_at`

All resources import by provider UUID.

### Shared managed fields

The common resource surface should include:

- `name`
- `enabled`
- `display_order`
- `client_id`
- `client_secret`
- `scopes`
- `pkce_required`
- `subject_claim`
- `email_claim`
- `groups_claim`
- `default_role`
- `admin_subjects`
- `admin_groups`
- `admin_email_domains`
- `readonly_subjects`
- `readonly_groups`
- `readonly_email_domains`
- `allowed_email_domains`
- `session_ttl_secs`

Collection intent:

- `scopes` should behave as an unordered Terraform set of strings.
- the subject, group, and email-domain match lists should also behave as unordered
  Terraform sets of strings.

These values are membership-oriented rather than order-oriented, so the provider should
avoid introducing plan churn from API ordering differences.

### Endpoint and issuer fields

`google` and `github` should expose the endpoint override fields already supported by
the API:

- `issuer_url`
- `authorization_url`
- `token_url`
- `userinfo_url`

Those fields remain optional because Neuwerk already has built-in defaults for Google
and GitHub endpoints.

`generic_oidc` should make the endpoint fields a normal first-class part of the
resource surface:

- `issuer_url` optional
- `authorization_url` required
- `token_url` required
- `userinfo_url` required

This mirrors the control-plane behavior, where generic OIDC has no built-in endpoint
defaults and therefore requires explicit endpoint configuration to operate.

## Secret Handling

`client_secret` is the main lifecycle constraint in this design.

The resource contract should be:

- Terraform schema should model `client_secret` as optional and sensitive, not computed.
- `Create` must reject missing, unknown, null, or blank `client_secret` values.
- `client_secret` is therefore required by provider behavior on create, while remaining
  omittable for import and for updates that do not rotate the secret.
- `client_secret` is stored in Terraform state as sensitive.
- `Read` preserves the prior state value for `client_secret` when the API reports only
  `client_secret_configured: true`.
- `Read` should set `client_secret` to null when the API reports
  `client_secret_configured: false`.
- `Import` restores metadata but cannot recover the raw secret.
- After import, users must supply `client_secret` in configuration again if they want
  Terraform to manage future secret updates.

Update behavior should be in-place:

- when configuration supplies `client_secret`, the provider sends it in the update
  request
- when configuration omits `client_secret`, the provider does not send a replacement
  secret during update
- when configuration keeps the existing `client_secret`, refresh must not cause drift
  simply because the API redacts the secret

This matches common Terraform expectations for write-only secrets exposed by external
APIs.

## Validation

Provider-side validation should stay intentionally minimal and structural.

The provider should validate:

- blank required string inputs
- blank list elements where the API expects non-empty strings
- empty import IDs
- generic OIDC missing `authorization_url`, `token_url`, or `userinfo_url`

The provider should not attempt to fully duplicate control-plane validation for:

- URL semantics beyond simple required-field structure
- TTL bounds
- SSO claim semantics
- provider-specific runtime behavior
- login-flow correctness

The Neuwerk API remains the source of truth for semantic validation and should surface
those errors directly through Terraform diagnostics.

## Read And Import Semantics

Refresh behavior should converge cleanly with the API rather than fighting server
defaults.

That includes:

- preserving `client_secret` from prior state
- accepting API-defaulted scopes when the control plane returns effective values
- accepting API-defaulted endpoint values for Google and GitHub when explicit overrides
  were not configured

Import behavior should be:

- all resources import by provider UUID
- imported state includes readable metadata and configuration fields returned by the API
- imported state does not include the raw `client_secret`
- resource `Read` fails with a clear diagnostic if the imported object kind does not
  match the Terraform resource type

That last rule is important for safety. Importing a GitHub provider into the Google
resource should not silently reinterpret the object.

## Testing Strategy

The implementation should follow the existing provider testing style with focused unit
tests and `httptest`-backed request checks.

Required test coverage:

- schema tests for each resource, including sensitive `client_secret`
- import parsing and kind-mismatch behavior
- create, read, update, and delete request/response tests
- refresh/state convergence tests for:
  - preserved `client_secret`
  - API-defaulted scopes
  - API-defaulted Google/GitHub endpoints
  - import without secret recovery
- shared helper tests for the internal SSO mapping layer

The first pass does not need end-to-end browser or identity-provider integration tests.
The correctness target is provider behavior against the Neuwerk HTTP API contract.

## Documentation Changes

Documentation should stay minimal and practical.

Update the Terraform provider README to:

- list the three new SSO provider resources
- add one concise example for each provider kind
- document `client_secret` lifecycle semantics
- document import format as provider UUID for all three resources

The documentation should emphasize the one thing most users will otherwise miss:
importing an SSO provider cannot recover the redacted secret, so secret rotation after
import requires the configuration to supply `client_secret` again.

## Implementation Shape

This feature should remain contained within the Terraform provider module.

Expected implementation areas:

### 1. API client support

- add SSO provider request and response types
- add list/get/create/update/delete helpers for the SSO settings endpoints

### 2. Shared provider internals

- add shared model structs or helper functions for common SSO state handling
- centralize request building and state mapping so secret-preservation logic is
  implemented once

### 3. Per-kind resources

- add `neuwerk_sso_provider_google`
- add `neuwerk_sso_provider_github`
- add `neuwerk_sso_provider_generic_oidc`

### 4. Tests and README updates

- add unit coverage for shared logic and per-kind resource behavior
- extend the Terraform provider README with examples and import/secret notes

This scope is intentionally narrow enough for one implementation plan.

## Risks And Mitigations

### Risk: refresh drift from API-defaulted values

Mitigation:
preserve managed inputs where appropriate and treat effective API defaults as converged
state when the API intentionally returns the resolved values.

### Risk: secret handling surprises users after import

Mitigation:
document the write-only secret behavior explicitly and preserve secrets on normal
refresh so the only surprise surface is import, where recovery is impossible by design.

### Risk: duplicated logic across the three resources

Mitigation:
implement shared SSO request/state helpers and keep per-kind resources thin.

## Plan Readiness

This design is ready to move into a single implementation plan focused on the Terraform
provider module. It defines:

- the resource model
- the lifecycle contract
- the secret-handling behavior
- the validation boundary
- the testing and documentation expectations

No further product decomposition is required before planning.
