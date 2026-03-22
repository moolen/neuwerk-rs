# `neuwerk_service_account`

Manages a service account for automation and API access.

## Key Arguments

- `name`
- `description`
- `role`

## Computed Attributes

- `id`
- `created_at`
- `created_by`
- `status`

## Notes

- Service accounts are the intended machine identity for Terraform automation.
- Deleting this resource disables the service account in the API.

## Import

Import by service-account UUID.
