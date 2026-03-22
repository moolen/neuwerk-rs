# `neuwerk_sso_provider_google`

Manages a Google SSO provider record.

## Example Usage

```hcl
resource "neuwerk_sso_provider_google" "google" {
  name          = "Corp Google"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret
  scopes        = ["openid", "email", "profile"]
  allowed_email_domains = [
    "example.com",
  ]
  default_role     = "readonly"
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
  Google OAuth client ID.
- `client_secret` (String, Optional, Sensitive)
  Google OAuth client secret. Required when creating the resource. On later updates, it may be
  omitted if the API already has secret material configured.
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
- `authorization_url` (String, Optional)
  Authorization endpoint URL. For Google, the API may default this value.
- `token_url` (String, Optional)
  Token endpoint URL. For Google, the API may default this value.
- `userinfo_url` (String, Optional)
  Userinfo endpoint URL. For Google, the API may default this value.
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
terraform import neuwerk_sso_provider_google.google sso-123
```

## Notes

- The API only reports whether `client_secret` is configured, not the raw secret value.
- Google endpoint URLs may be defaulted by the API and then read back into Terraform state even if
  they were omitted in configuration.
