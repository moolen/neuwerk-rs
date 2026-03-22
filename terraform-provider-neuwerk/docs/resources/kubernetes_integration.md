# `neuwerk_kubernetes_integration`

Manages a Kubernetes integration record that Neuwerk can reference from policy source selectors.

## Example Usage

```hcl
resource "neuwerk_kubernetes_integration" "prod" {
  name                  = "prod-k8s"
  api_server_url        = "https://10.0.0.10:6443"
  ca_cert_pem           = file("${path.module}/k8s-ca.pem")
  service_account_token = var.k8s_service_account_token
}
```

## Argument Reference

- `name` (String, Required)
  Integration name. This is also the identifier used by policy `kubernetes_selector.integration`
  references and by `terraform import`.
- `api_server_url` (String, Required)
  Kubernetes API server URL that Neuwerk should contact.
- `ca_cert_pem` (String, Required)
  PEM-encoded Kubernetes cluster CA certificate used to verify the API server.
- `service_account_token` (String, Required, Sensitive)
  Bearer token Neuwerk uses to authenticate to the Kubernetes API.

## Attribute Reference

- `id` (String)
  Server-generated integration ID.
- `created_at` (String)
  RFC3339 timestamp for when the integration was created.
- `kind` (String)
  Integration kind returned by the API. For this resource it is `kubernetes`.
- `auth_type` (String)
  Authentication mode recorded by the API for the integration.
- `token_configured` (Bool)
  Whether the API currently has service-account token material stored for this integration.

## Import

Import by integration name:

```bash
terraform import neuwerk_kubernetes_integration.prod prod-k8s
```

## Notes

- The API does not return the raw `service_account_token` value on reads or imports. Keep the
  token in configuration or a secret input so Terraform can continue to manage the resource.
- Renaming the integration changes the name Neuwerk policies must reference in
  `kubernetes_selector.integration`.
