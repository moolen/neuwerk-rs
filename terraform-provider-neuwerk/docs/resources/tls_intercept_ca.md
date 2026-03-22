# `neuwerk_tls_intercept_ca`

Manages the singleton TLS intercept CA setting.

## Example Usage

Generate a Neuwerk-managed CA:

```hcl
resource "neuwerk_tls_intercept_ca" "generated" {
  generate = true
}
```

Upload an existing CA:

```hcl
resource "neuwerk_tls_intercept_ca" "uploaded" {
  ca_cert_pem = file("${path.module}/neuwerk-ca.pem")
  ca_key_pem  = file("${path.module}/neuwerk-ca-key.pem")
}
```

## Argument Reference

- `generate` (Bool, Optional)
  If `true`, Neuwerk generates and stores the TLS intercept CA.
- `ca_cert_pem` (String, Optional)
  PEM-encoded CA certificate for an uploaded TLS intercept CA.
- `ca_key_pem` (String, Optional, Sensitive)
  PEM-encoded private key for an uploaded TLS intercept CA.
- `ca_key_der_b64` (String, Optional, Sensitive)
  Base64-encoded DER private key for an uploaded TLS intercept CA.

## Attribute Reference

- `id` (String)
  Synthetic singleton ID used by the resource. The provider stores `tls-intercept-ca`.
- `configured` (Bool)
  Whether Neuwerk currently has TLS intercept CA material configured.
- `source` (String)
  Source description returned by the API.
- `fingerprint_sha256` (String)
  SHA256 fingerprint of the configured certificate.

## Import

Import with any placeholder ID:

```bash
terraform import neuwerk_tls_intercept_ca.main singleton
```

## Notes

- Set `generate = true` for Neuwerk-generated material, or upload `ca_cert_pem` plus exactly one of
  `ca_key_pem` or `ca_key_der_b64`.
- `generate` cannot be combined with uploaded certificate or key material.
- Deleting the resource deletes the singleton TLS intercept CA setting from Neuwerk.
