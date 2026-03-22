# `neuwerk_service_account_token`

Mints a service-account bearer token.

## Key Arguments

- `service_account_id`
- `name`
- `ttl`
- `eternal`
- `role`

## Computed Attributes

- `id`
- `token`
- `created_at`
- `created_by`
- `expires_at`
- `revoked_at`
- `last_used_at`
- `kid`
- `status`

## Notes

- `token` is sensitive.
- The raw token value is returned only at create time.
- Reads and imports restore metadata only, not the raw secret.
- The resource is immutable after creation; changing inputs replaces it and mints a new token.

## Import

Import by `<service_account_id>/<token_id>`.
