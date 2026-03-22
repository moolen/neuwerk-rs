# `neuwerk_tls_intercept_ca`

Manages the singleton TLS intercept CA setting.

## Key Arguments

- `generate`
- `ca_cert_pem`
- `ca_key_pem`
- `ca_key_der_b64`

## Computed Attributes

- `id`
- `configured`
- `source`
- `fingerprint_sha256`

## Notes

- Use `generate = true` to have Neuwerk mint the CA.
- Uploaded CA material requires `ca_cert_pem` plus exactly one of `ca_key_pem` or `ca_key_der_b64`.
- Key material is sensitive.

## Import

Import with any placeholder ID; the resource binds to the singleton setting.
