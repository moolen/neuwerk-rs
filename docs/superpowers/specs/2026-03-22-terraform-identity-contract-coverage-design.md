# Terraform Identity Contract Coverage Design

## Goal

Extend the Terraform provider contract suite so it exercises the identity-oriented provider resources that are already implemented but not yet covered end to end:

- `neuwerk_service_account`
- `neuwerk_service_account_token`
- `neuwerk_sso_provider_google`
- `neuwerk_sso_provider_github`
- `neuwerk_sso_provider_generic_oidc`

## Current Gap

The existing contract suite covers:

- `neuwerk_policy`
- `neuwerk_kubernetes_integration`
- `neuwerk_tls_intercept_ca`

It does not currently run real `terraform init/apply/import/plan/destroy` flows for service accounts, service-account tokens, or SSO providers. That leaves a gap between unit coverage and OSS-launch confidence for the current provider surface.

## Design

Add one new identity-focused golden fixture and one new contract case in `tests/terraform_provider_e2e.rs`.

The fixture should create:

- one admin service account
- one token for that account
- one Google SSO provider
- one GitHub SSO provider
- one Generic OIDC SSO provider

The contract case should verify:

1. `terraform apply` creates all resources successfully.
2. A follow-up `terraform plan -detailed-exitcode` is clean.
3. The Neuwerk HTTP API reflects the expected service-account, token, and SSO provider state.
4. A fresh workspace can `terraform import` all created resources and converge cleanly.
5. `terraform destroy` removes all of them from the API.

## API Assertions

Use direct HTTP API checks in the harness rather than provider internals.

For service accounts:

- list `/api/v1/service-accounts`
- find the account by name
- confirm `role` and non-empty `id`

For service-account tokens:

- list `/api/v1/service-accounts/{id}/tokens`
- find the token by name
- confirm `role`, `status = active`, and that the raw token is not required after import

For SSO providers:

- list `/api/v1/settings/sso/providers`
- find providers by `name`
- confirm `kind`
- confirm `client_secret_configured = true`
- confirm Generic OIDC explicit endpoints round-trip

## Import Semantics

The import pass should exercise the intended IDs:

- service account by UUID
- service-account token by `<service_account_id>/<token_id>`
- all SSO providers by provider UUID

The imported workspace should reuse the original Terraform configuration so secrets are re-supplied where the API intentionally redacts them.

## Non-Goals

- Adding provider data sources
- Expanding website docs beyond what was already fixed
- Adding `/settings/sso/providers/:id/test` Terraform coverage
- Adding cluster failover coverage for identity resources in this slice

## Acceptance Criteria

- The new contract test fails before the fixture/assertion implementation exists.
- The new contract test passes after implementation.
- The broader `terraform_provider_e2e` test remains green.
- No existing Terraform provider contract cases regress.
