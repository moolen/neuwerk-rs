# `neuwerk_sso_provider_generic_oidc`

Manages a generic OIDC SSO provider record.

## Example Usage

```hcl
resource "neuwerk_sso_provider_generic_oidc" "oidc" {
  name              = "Corp OIDC"
  client_id         = var.oidc_client_id
  client_secret     = var.oidc_client_secret
  authorization_url = "https://idp.example.com/oauth2/authorize"
  token_url         = "https://idp.example.com/oauth2/token"
  userinfo_url      = "https://idp.example.com/oauth2/userinfo"
  scopes            = ["openid", "email", "profile"]
  default_role      = "readonly"
  allowed_email_domains = [
    "example.com",
  ]
  session_ttl_secs = 3600
}
```

## Argument Reference

- `name` (String, Required)
  Display name for the SSO provider.
- `enabled` (Bool, Optional)
  Whether the provider is enabled for login. If omitted, the API default is used.
- `display_order` (Number, Optional)
  Ordering hint for login-provider presentation.
- `issuer_url` (String, Optional)
  Issuer URL recorded for the provider.
- `client_id` (String, Required)
  OAuth client ID.
- `client_secret` (String, Optional, Sensitive)
  OAuth client secret. Required when creating the resource. On later updates, it may be omitted if
  the API already has secret material configured.
- `scopes` (Set of String, Optional)
  OAuth scopes requested during login.
- `pkce_required` (Bool, Optional)
  Whether PKCE is required for the provider.
- `subject_claim` (String, Optional)
  Claim used as the Neuwerk subject identifier.
- `email_claim` (String, Optional)
  Claim used as the user email.
- `groups_claim` (String, Optional)
  Claim used as the group list.
- `default_role` (String, Optional)
  Default Neuwerk role granted to users who authenticate through this provider.
- `admin_subjects` (Set of String, Optional)
  Subjects that should receive admin access.
- `admin_groups` (Set of String, Optional)
  Groups that should receive admin access.
- `admin_email_domains` (Set of String, Optional)
  Email domains that should receive admin access.
- `readonly_subjects` (Set of String, Optional)
  Subjects that should receive readonly access.
- `readonly_groups` (Set of String, Optional)
  Groups that should receive readonly access.
- `readonly_email_domains` (Set of String, Optional)
  Email domains that should receive readonly access.
- `allowed_email_domains` (Set of String, Optional)
  Email domains allowed to sign in through this provider.
- `authorization_url` (String, Required)
  Authorization endpoint URL for the OIDC provider.
- `token_url` (String, Required)
  Token endpoint URL for the OIDC provider.
- `userinfo_url` (String, Required)
  Userinfo endpoint URL for the OIDC provider.
- `session_ttl_secs` (Number, Optional)
  Session TTL in seconds.

## Attribute Reference

- `id` (String)
  SSO provider UUID.
- `created_at` (String)
  RFC3339 timestamp for when the provider was created.
- `updated_at` (String)
  RFC3339 timestamp for the last update.

## Import

Import by provider UUID:

```bash
terraform import neuwerk_sso_provider_generic_oidc.oidc sso-123
```

## Notes

- `authorization_url`, `token_url`, and `userinfo_url` are required for the generic OIDC resource.
- The API only reports whether `client_secret` is configured, not the raw secret value. Keep the
  secret in configuration or secret inputs if Terraform must continue managing updates.
