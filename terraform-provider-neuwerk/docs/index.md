# Terraform Provider Docs

The Neuwerk Terraform provider is published under:

```hcl
terraform {
  required_providers {
    neuwerk = {
      source = "moolen/neuwerk"
    }
  }
}
```

Use these docs as the provider reference for the current signed GitHub Releases distribution path
from `moolen/terraform-provider-neuwerk`. The intended provider source address remains
`moolen/neuwerk`.

## Install

Current distribution path:

1. download the matching provider archive for your platform from GitHub Releases
2. download `terraform-provider-neuwerk-signing-key.asc`
3. verify the signing key fingerprint `DC34EB84D498D1445B68CB405E6B936CF37928C3`
4. verify `terraform-provider-neuwerk_<version>_SHA256SUMS`
5. verify the detached checksum signature
6. place the unpacked provider binary under the local Terraform filesystem mirror path for `registry.terraform.io/moolen/neuwerk`

Unsigned provider releases are intentionally unsupported.
Terraform Registry publication is follow-up work. Until onboarding is complete, install from the
signed GitHub Releases in `moolen/terraform-provider-neuwerk`.

## References

- [Provider Configuration](./provider.md)
- [Policy Resource](./resources/policy.md)
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
