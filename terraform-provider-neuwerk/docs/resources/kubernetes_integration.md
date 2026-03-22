# `neuwerk_kubernetes_integration`

Manages a Kubernetes integration record.

## Key Arguments

- `name`
- `api_server_url`
- `ca_cert_pem`
- `service_account_token`

## Computed Attributes

- `id`
- `created_at`
- `kind`
- `auth_type`
- `token_configured`

## Notes

- `service_account_token` is sensitive.
- The API does not return the raw token value on read or import.
- Imported resources should be paired with configuration that re-supplies `service_account_token`.

## Import

Import by integration name.
