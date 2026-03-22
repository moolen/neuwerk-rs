# `neuwerk_service_account_token`

Mints a service-account bearer token.

## Example Usage

```hcl
resource "neuwerk_service_account" "automation" {
  name = "terraform-automation"
  role = "admin"
}

resource "neuwerk_service_account_token" "automation" {
  service_account_id = neuwerk_service_account.automation.id
  name               = "terraform-admin"
  role               = "admin"
  eternal            = true
}
```

## Argument Reference

- `service_account_id` (String, Required, Forces Replacement)
  ID of the service account that owns the token.
- `name` (String, Optional, Forces Replacement)
  Optional display name for the token.
- `ttl` (String, Optional, Forces Replacement)
  Token lifetime string passed through to the API.
- `eternal` (Bool, Optional, Forces Replacement)
  Whether to mint a non-expiring token.
- `role` (String, Optional, Forces Replacement)
  Optional token role override.

## Attribute Reference

- `id` (String)
  Token ID.
- `token` (String, Sensitive)
  Raw bearer token returned only when the resource is created.
- `created_at` (String)
  RFC3339 timestamp for when the token was minted.
- `created_by` (String)
  Identity that created the token.
- `expires_at` (String)
  Expiration timestamp if the token is time-limited.
- `revoked_at` (String)
  Revocation timestamp if the token was revoked.
- `last_used_at` (String)
  Last observed use timestamp returned by the API.
- `kid` (String)
  Key ID associated with the token.
- `status` (String)
  Current token status.

## Import

Import by `<service_account_id>/<token_id>`:

```bash
terraform import neuwerk_service_account_token.automation acc-123/tok-456
```

## Notes

- The raw `token` secret is only available at create time. Reads and imports restore token metadata
  but not the secret value itself.
- Every configurable argument forces replacement because Neuwerk service account tokens are
  immutable after creation.
- `ttl` cannot be set when `eternal = true`.
