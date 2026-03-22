# Provider Configuration

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
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
  retry_timeout   = "5s"
}
```

## Arguments

- `endpoints`
  Required list of HTTPS API base URLs. Endpoints are tried in order.
- `token`
  Required bearer token. Admin-capable service-account tokens are the intended automation credential.
- `ca_cert_pem`
  Optional PEM-encoded CA certificate.
- `ca_cert_file`
  Optional path to a PEM-encoded CA certificate. Use either this or `ca_cert_pem`.
- `request_timeout`
  Optional per-request timeout in Go duration syntax.
- `retry_timeout`
  Optional total retry budget for transient transport failures.
- `headers`
  Optional extra headers attached to every API request.

## Transport Behavior

- HTTPS endpoint normalization
- bearer-token authentication
- optional custom CA trust
- endpoint failover across the configured `endpoints`
- retries for transient transport failures up to `retry_timeout`

## Manual Install

The current supported install path is signed GitHub Releases:

1. download the archive for your platform
2. verify the SHA256SUMS file
3. verify the detached SHA256SUMS signature
4. place the unpacked binary in a Terraform filesystem mirror under `registry.terraform.io/moolen/neuwerk`

Terraform Registry publication is planned as a later step and does not change the intended source
address.
