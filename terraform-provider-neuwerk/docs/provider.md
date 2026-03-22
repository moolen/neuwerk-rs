# Provider Configuration

Configure the provider with one or more Neuwerk API endpoints plus a bearer token that is
authorized to manage the resources in this provider. The provider normalizes endpoint URLs, uses
HTTPS transport, and retries transient transport failures across the configured endpoint list.

## Example Usage

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
  token           = var.neuwerk_token
  ca_cert_file    = "${path.module}/neuwerk-ca.crt"
  request_timeout = "30s"
  retry_timeout   = "5s"
  headers = {
    "X-Request-Origin" = "terraform"
  }
}
```

## Argument Reference

- `endpoints` (List of String, Required)
  Ordered list of HTTPS base URLs for the Neuwerk API. The provider tries endpoints in order and
  fails over on transient transport errors.
- `token` (String, Required, Sensitive)
  Bearer token used for API authentication. For automation, use an admin-capable service account
  token instead of a user session token.
- `ca_cert_pem` (String, Optional)
  PEM-encoded CA certificate used to verify the Neuwerk API server.
- `ca_cert_file` (String, Optional)
  Path to a PEM-encoded CA certificate used to verify the Neuwerk API server.
- `request_timeout` (String, Optional)
  Per-request timeout in Go duration syntax such as `30s`. If unset, the provider uses `30s`.
- `retry_timeout` (String, Optional)
  Total retry budget for transient transport failures in Go duration syntax. If unset, the
  provider uses `5s`.
- `headers` (Map of String, Optional)
  Extra headers attached to every HTTP request the provider sends to the Neuwerk API.

## Manual Install

1. Download the provider archive for your platform from `moolen/terraform-provider-neuwerk`.
2. Download `terraform-provider-neuwerk_<version>_SHA256SUMS` and
   `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`.
3. Download `terraform-provider-neuwerk-signing-key.asc` from the repository root.
4. Verify the signing key fingerprint `DC34EB84D498D1445B68CB405E6B936CF37928C3`.
5. Verify the checksum signature, then verify the provider archive checksum.
6. Unpack the provider binary into a filesystem mirror path under
   `registry.terraform.io/moolen/neuwerk/<version>/<os>_<arch>/`.

Use `source = "moolen/neuwerk"` in Terraform configuration even while installation still happens
through the signed GitHub Release assets.

## Notes

- Configure exactly one of `ca_cert_pem` or `ca_cert_file`. Setting both is an error.
- `request_timeout` and `retry_timeout` must be valid positive Go duration strings.
- Endpoint failover applies to transport-level failures. A server-side API error returned by a
  reachable endpoint is surfaced back to Terraform.
- All values in `headers` are sent on every API request, so reserve them for static metadata and
  not per-request secrets.
