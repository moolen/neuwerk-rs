# `neuwerk_sso_provider_generic_oidc`

Manages a generic OIDC SSO provider record.

## Key Arguments

- `name`
- `client_id`
- `client_secret`
- `authorization_url`
- `token_url`
- `userinfo_url`
- optional claim-mapping and access-control fields from the shared SSO schema

## Computed Attributes

- `id`
- `created_at`
- `updated_at`

## Notes

- `client_secret` is required on create and stored as a sensitive Terraform value.
- Generic OIDC requires explicit non-empty endpoint URLs.
- The API only returns `client_secret_configured`, not the raw secret.

## Import

Import by provider UUID.
