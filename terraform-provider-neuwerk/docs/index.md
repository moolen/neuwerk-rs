# Terraform Provider Docs

The Neuwerk Terraform provider manages Neuwerk control-plane resources such as Kubernetes
integrations, service accounts, service account tokens, TLS intercept CA settings, and SSO
providers.

The intended provider source address is:

```hcl
terraform {
  required_providers {
    neuwerk = {
      source = "moolen/neuwerk"
    }
  }
}
```

The current signed distribution path is GitHub Releases from
`moolen/terraform-provider-neuwerk`. These docs describe that release contract and the current
manual install flow.

## Install And Verify

1. Download the provider archive for your platform from `moolen/terraform-provider-neuwerk`.
2. Download `terraform-provider-neuwerk_<version>_SHA256SUMS` and
   `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`.
3. Download the tracked public signing key `terraform-provider-neuwerk-signing-key.asc`.
4. Verify the signing key fingerprint `DC34EB84D498D1445B68CB405E6B936CF37928C3`.
5. Verify the checksum file signature and then verify the provider archive checksum.
6. Unpack the provider binary into a Terraform filesystem mirror path under
   `registry.terraform.io/moolen/neuwerk/<version>/<os>_<arch>/`.

Unsigned provider releases are intentionally unsupported.

## Quick Start

```hcl
terraform {
  required_providers {
    neuwerk = {
      source = "moolen/neuwerk"
    }
  }
}

provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_admin_token
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}

resource "neuwerk_service_account" "terraform" {
  name = "terraform"
  role = "admin"
}
```

Start with an admin-capable service account token, create Terraform-managed service accounts and
tokens for long-lived automation, and then move on to Kubernetes integrations, TLS interception, or
SSO.

## Reference Pages

- [Provider Configuration](./provider.md)
- [Kubernetes Integration Resource](./resources/kubernetes_integration.md)
- [TLS Intercept CA Resource](./resources/tls_intercept_ca.md)
- [Service Account Resource](./resources/service_account.md)
- [Service Account Token Resource](./resources/service_account_token.md)
- [Google SSO Provider Resource](./resources/sso_provider_google.md)
- [GitHub SSO Provider Resource](./resources/sso_provider_github.md)
- [Generic OIDC SSO Provider Resource](./resources/sso_provider_generic_oidc.md)

## Examples

- `terraform-provider-neuwerk/examples/basic/main.tf`
- `terraform-provider-neuwerk/examples/service-accounts/main.tf`
- `terraform-provider-neuwerk/examples/sso/main.tf`

## Notes

- Use the provider source address `moolen/neuwerk` in Terraform configuration even though the
  signed release assets currently come from `moolen/terraform-provider-neuwerk`.
- Terraform Registry publication may later automate installation, but it does not change the
  provider source address or the release asset naming contract described here.
