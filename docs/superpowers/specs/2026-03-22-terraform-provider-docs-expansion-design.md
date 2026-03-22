# Terraform Provider Docs Expansion Design

## Goal

Turn the Terraform provider documentation into a first-class reference surface for first-time users
by making every provider and resource page example-first, field-complete, and aligned with the
actual public release and install model.

## Current Problems

The current provider docs are functional but too thin for real operator adoption:

- the provider landing page is mostly an install note, not a documentation entry point
- resource pages list only top-level arguments and computed fields
- most resources do not include a runnable example at the top of the page
- nested structures such as the policy resource are under-documented
- the surrounding monorepo Terraform docs describe release and Registry onboarding, but not in a
  way that cleanly matches the provider reference pages a user reads first

This leaves a first-time user with the right files but the wrong experience: they still need to
inspect provider schemas or code to understand how to use the provider confidently.

## Non-Goals

- Rewrite the provider schema or change Terraform behavior.
- Add new provider resources or arguments.
- Turn the reference docs into long tutorials.
- Introduce generated documentation tooling in this phase.

## Target Outcome

The provider docs should read like a serious Terraform provider, not a placeholder:

- the top-level docs page explains install, verification, quick start, and where to go next
- the provider configuration page includes a concrete provider block and field-level guidance for
  every argument
- every resource page starts with a full example
- every resource page documents all arguments, computed attributes, and nested blocks where present
- caveats such as sensitive values, import semantics, replacement behavior, and API redaction are
  explicit
- the monorepo Terraform release and Registry docs tell the same install and publication story as
  the provider docs

## Chosen Structure

Use a strict Terraform-reference structure on all provider docs pages:

1. short description
2. example usage
3. argument reference
4. attribute reference
5. nested block reference where applicable
6. import
7. notes / caveats

This is the format users already expect from provider documentation. It optimizes for skimmability,
copy-paste onboarding, and exact answers during authoring.

## Scope

### Provider Docs Surface

Refresh these provider reference files under `terraform-provider-neuwerk/docs/`:

- `index.md`
- `provider.md`
- `resources/policy.md`
- `resources/kubernetes_integration.md`
- `resources/tls_intercept_ca.md`
- `resources/service_account.md`
- `resources/service_account_token.md`
- `resources/sso_provider_google.md`
- `resources/sso_provider_github.md`
- `resources/sso_provider_generic_oidc.md`

### Monorepo Terraform Docs

Refresh these monorepo docs so they stay aligned with the provider reference:

- `docs/operations/terraform-provider-release.md`
- `docs/operations/terraform-provider-registry-publication.md`

### Public Release Surface

Publish the expanded docs through the public provider release-source repository and cut a new
provider release after the docs refresh lands.

## Content Design

### Top-Level Docs Page

`terraform-provider-neuwerk/docs/index.md` should become the real entry page for provider users:

- provider source address
- install and verification flow
- a short quick-start configuration example
- links to the provider page, resource pages, and example configurations
- clear note about current distribution path versus Registry onboarding state

### Provider Page

`terraform-provider-neuwerk/docs/provider.md` should document:

- a concrete provider block example
- endpoint failover behavior
- bearer-token expectations
- custom CA configuration
- request and retry timeout semantics
- extra headers behavior
- manual install and verification steps

Every provider argument should have a field-level description with type and behavior guidance.

### Resource Pages

Each resource page should:

- start with one realistic example
- document every field exposed by the schema
- explicitly call out sensitive fields
- explicitly call out replacement semantics where relevant
- document import format in the exact expected form

For simple resources such as service accounts, TLS intercept CA, and SSO providers, this is mostly
about completeness and consistent formatting.

For the policy resource, the page must go deeper. It should document:

- top-level arguments
- nested `source_group`
- nested `sources`
- nested `kubernetes_selector`
- nested `rule`
- high-level matcher/helper blocks that the provider compiles into the API model
- `document_json` as the low-level escape hatch

The goal is not to restate every internal implementation detail, but to ensure a Terraform author
does not need to inspect provider code to understand the authoring surface.

## Verification Strategy

Add lightweight regression coverage that proves the provider docs stay at the new quality bar.

The minimum useful coverage is:

- provider docs pages exist
- every resource page contains an example section near the top
- every resource page contains argument and attribute reference sections
- the provider index and provider page still mention the expected public source address and install
  path

This should be enforced in repository tests so future provider changes do not silently regress the
docs surface.

## Release Strategy

After the docs refresh is verified locally:

1. sync the updated release-source tree to `moolen/terraform-provider-neuwerk`
2. run the public repository provider release workflow for a new version
3. verify the resulting release assets and docs state

The docs update itself does not require a provider behavior change, but releasing it promptly keeps
the public repository and release artifacts in sync with the improved documentation surface.

## Risks And Mitigations

### Risk: docs drift from actual provider schema

Mitigation:

- derive the docs content directly from the current provider resource schemas and tests
- add regression tests that check for required documentation sections

### Risk: policy docs become verbose but still incomplete

Mitigation:

- document the provider-authoring surface in terms of user-visible blocks and fields
- keep internal compilation details in notes, not as the main structure

### Risk: release docs and provider docs diverge

Mitigation:

- update the monorepo release/install docs in the same batch
- release from the synced public release-source repository immediately after merge

## Success Criteria

- every provider resource page contains an example-first reference layout
- every provider/resource field that users can configure is documented
- the provider install and verification path is clear from both provider docs and monorepo docs
- the public provider release-source repository is synced with the expanded docs
- a new provider release is published from the public repository with the updated documentation
