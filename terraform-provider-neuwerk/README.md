# Terraform Provider Neuwerk

This module contains the initial Terraform provider implementation for the Neuwerk HTTP API.

Implemented resources:

- `neuwerk_policy`
- `neuwerk_kubernetes_integration`
- `neuwerk_tls_intercept_ca`
- `neuwerk_service_account`
- `neuwerk_service_account_token`
- `neuwerk_sso_provider_google`
- `neuwerk_sso_provider_github`
- `neuwerk_sso_provider_generic_oidc`

Provider authentication uses the existing bearer-token HTTP API. Admin-capable service-account tokens are supported and are the intended machine-auth mechanism for automation.

## Example

```hcl
provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_bootstrap_token
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}
```

## Service Account Resources

Service accounts are the intended automation identity for the provider. Tokens are mint-once secrets and should be stored in Terraform state as sensitive values.
An existing admin-capable token is required to create service accounts and mint tokens; the minted token is intended for subsequent Terraform runs or downstream automation.

```hcl
resource "neuwerk_service_account" "automation" {
  name  = "terraform-automation"
  role = "admin"
}

resource "neuwerk_service_account_token" "automation" {
  service_account_id = neuwerk_service_account.automation.id
  name               = "terraform-admin"
  role    = "admin"
  eternal = true
}

provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_bootstrap_token
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}
```

Token lifecycle semantics:

- Raw token material is returned only at create time. The provider stores that value in Terraform state as a sensitive secret.
- Importing an existing token restores metadata only; the raw token remains unavailable after import.

Import semantics:

- `neuwerk_service_account` imports by UUID.
- `neuwerk_service_account_token` imports by `<service_account_id>/<token_id>`.

## SSO Provider Resources

```hcl
resource "neuwerk_sso_provider_google" "corp" {
  name          = "Corp Google"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret
  scopes        = ["openid", "email", "profile"]
}

resource "neuwerk_sso_provider_github" "corp" {
  name          = "Corp GitHub"
  client_id     = var.github_client_id
  client_secret = var.github_client_secret
}

resource "neuwerk_sso_provider_generic_oidc" "corp" {
  name              = "Corp OIDC"
  client_id         = var.oidc_client_id
  client_secret     = var.oidc_client_secret
  authorization_url = "https://idp.example.com/oauth2/authorize"
  token_url         = "https://idp.example.com/oauth2/token"
  userinfo_url      = "https://idp.example.com/oauth2/userinfo"
}
```

- All SSO provider resources import by provider UUID.
- `client_secret` is required on create, stored as a sensitive value in Terraform state, and cannot be recovered from the API during import.

## Policy Resource

The provider now supports higher-level nested HCL sugar for the policy resource and compiles it into the current aggregate HTTP API policy document. `document_json` remains available as an escape hatch.

```hcl
resource "neuwerk_policy" "main" {
  name           = "prod-default"
  mode           = "enforce"
  default_action = "deny"

  source_group = [
    {
      id = "corp-clients"

      sources = {
        cidrs = ["10.20.0.0/16"]
      }

      rule = [
        {
          id     = "allow-dns"
          action = "allow"

          dns = {
            exact    = ["github.com", "api.github.com"]
            suffixes = ["example.com"]
          }
        },
        {
          id     = "allow-external-secrets"
          action = "allow"

          destination = {
            protocol = "tcp"
            ports    = [443]
          }

          tls = {
            mode = "intercept"

            request = {
              methods = ["GET"]
              target = [
                {
                  hosts       = ["vault-a.example.com", "vault-b.example.com"]
                  path_prefix = ["/external-secrets/"]
                },
                {
                  hosts       = ["secrets.internal.example.com"]
                  path_prefix = ["/v1/"]
                }
              ]
            }

            response = {
              deny_headers = ["x-forbidden"]
            }
          }
        }
      ]
    }
  ]
}
```

## Import

- `neuwerk_policy` imports by policy name.
- `neuwerk_kubernetes_integration` imports by integration name.
- `neuwerk_tls_intercept_ca` can be imported with any placeholder ID and will bind to the singleton setting.
- `neuwerk_service_account` imports by UUID.
- `neuwerk_service_account_token` imports by `<service_account_id>/<token_id>`.
- All SSO provider resources import by provider UUID.

Note: the integrations API intentionally redacts `service_account_token`, so imported integration resources must be paired with configuration that supplies the token again.
