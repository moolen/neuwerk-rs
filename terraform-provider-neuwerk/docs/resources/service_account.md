# `neuwerk_service_account`

Manages a service account for automation and API access.

## Example Usage

```hcl
resource "neuwerk_service_account" "automation" {
  name        = "terraform-automation"
  description = "automation identity"
  role        = "admin"
}
```

## Argument Reference

- `name` (String, Required)
  Human-readable service account name. Blank names are rejected by the provider.
- `description` (String, Optional)
  Optional description stored alongside the account.
- `role` (String, Required)
  Neuwerk role assigned to the service account, such as `admin` or `readonly`.

## Attribute Reference

- `id` (String)
  Service account UUID.
- `created_at` (String)
  RFC3339 timestamp for when the account was created.
- `created_by` (String)
  Identity that created the service account.
- `status` (String)
  Current status returned by the API.

## Import

Import by service account UUID:

```bash
terraform import neuwerk_service_account.automation acc-123
```

## Notes

- Service accounts are the intended long-lived machine identity for Terraform automation.
- Empty or whitespace-only descriptions are omitted from API requests.
