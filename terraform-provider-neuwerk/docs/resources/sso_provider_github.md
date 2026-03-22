# `neuwerk_sso_provider_github`

Manages a GitHub SSO provider record.

## Key Arguments

- `name`
- `client_id`
- `client_secret`
- optional claim-mapping and access-control fields from the shared SSO schema

## Computed Attributes

- `id`
- `created_at`
- `updated_at`

## Notes

- `client_secret` is required on create and stored as a sensitive Terraform value.
- The API only returns `client_secret_configured`, not the raw secret.
- Defaulted provider endpoints may be computed by the API.

## Import

Import by provider UUID.
