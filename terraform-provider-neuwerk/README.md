# Terraform Provider Neuwerk

This module contains the initial Terraform provider implementation for the Neuwerk firewall HTTP API.

Implemented resources:

- `neuwerk_policy`
- `neuwerk_kubernetes_integration`
- `neuwerk_tls_intercept_ca`

Provider authentication uses the existing bearer-token HTTP API. Admin-capable service-account tokens are supported and are the intended machine-auth mechanism for automation.

## Example

```hcl
provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_service_account_token
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}
```

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

Note: the integrations API intentionally redacts `service_account_token`, so imported integration resources must be paired with configuration that supplies the token again.
