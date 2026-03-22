# `neuwerk_policy`

Manages an aggregate Neuwerk policy document through the by-name policy API. You can either submit
low-level `document_json` directly or use the higher-level nested `source_group` authoring surface
that the provider compiles into canonical API policy JSON.

## Example Usage

```hcl
resource "neuwerk_policy" "prod" {
  name           = "prod-default"
  mode           = "enforce"
  default_action = "deny"

  source_group = [
    {
      id             = "corp-clients"
      priority       = 10
      default_action = "deny"

      sources = {
        cidrs = ["10.20.0.0/16"]
        kubernetes_selector = [
          {
            integration = "prod-k8s"
            pod_selector = {
              namespace = "apps"
              match_labels = {
                app  = "api"
                tier = "backend"
              }
            }
          }
        ]
      }

      rule = [
        {
          id     = "allow-github-dns"
          action = "allow"
          dns = {
            exact    = ["github.com", "api.github.com"]
            suffixes = ["example.com"]
          }
        },
        {
          id       = "allow-external-secrets"
          action   = "allow"
          mode     = "audit"
          priority = 20
          destination = {
            protocol = "tcp"
            ports    = [443]
            ips      = ["203.0.113.10"]
          }
          tls = {
            mode = "intercept"
            request = {
              methods         = ["GET"]
              require_headers = ["x-request-id"]
              target = [
                {
                  hosts       = ["vault-a.example.com"]
                  path_prefix = ["/external-secrets/"]
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

## Argument Reference

- `name` (String, Required)
  Policy name. Neuwerk stores and looks up this resource by name.
- `mode` (String, Required)
  Top-level policy mode. Allowed values are `disabled`, `audit`, and `enforce`.
- `default_action` (String, Optional)
  Default action for the compiled policy when you use nested `source_group` authoring. Allowed
  values are `allow` and `deny`.
- `document_json` (String, Optional)
  Low-level JSON policy document submitted directly to the API. This is the escape hatch for shapes
  not modeled by the higher-level Terraform blocks.
- `source_group` (List of Object, Optional)
  Higher-level authoring surface for source groups, match rules, Kubernetes selectors, and TLS/DNS
  sugar that the provider compiles into canonical API JSON.

## Attribute Reference

- `id` (String)
  Server-generated policy ID.
- `created_at` (String)
  RFC3339 timestamp for when the policy record was created.
- `compiled_json` (String)
  Canonical JSON that the provider submitted to the Neuwerk API after normalization or sugar
  compilation.

## Nested Block Reference

### `source_group`

- `id` (String, Required)
  Stable source-group identifier inside the policy document.
- `priority` (Number, Optional)
  Optional priority value attached to the source group in the compiled policy.
- `default_action` (String, Optional)
  Group-local default action. Allowed values are `allow` and `deny`.
- `sources` (Object, Required)
  Source selector set for the group. At least one of `cidrs`, `ips`, or `kubernetes_selector` must
  be present.
- `rule` (List of Object, Optional)
  Rules applied to traffic that matches the source group.

### `source_group.sources`

- `cidrs` (List of String, Optional)
  Source CIDR matches for the group.
- `ips` (List of String, Optional)
  Exact source IP matches for the group.
- `kubernetes_selector` (List of Object, Optional)
  Kubernetes workload selectors associated with a named Neuwerk Kubernetes integration.

### `source_group.sources.kubernetes_selector`

- `integration` (String, Required)
  Name of a `neuwerk_kubernetes_integration` resource or an existing Neuwerk Kubernetes integration.
- `pod_selector` (Object, Optional)
  Pod selector for workloads in a namespace.
- `node_selector` (Object, Optional)
  Node selector for matching cluster nodes.

Exactly one of `pod_selector` or `node_selector` must be configured.

### `source_group.sources.kubernetes_selector.pod_selector`

- `namespace` (String, Required)
  Kubernetes namespace to search for matching pods.
- `match_labels` (Map of String, Optional)
  Label map that pods must match inside the namespace.

### `source_group.sources.kubernetes_selector.node_selector`

- `match_labels` (Map of String, Optional)
  Label map that Kubernetes nodes must match.

### `source_group.rule`

- `id` (String, Required)
  Stable rule identifier inside the source group.
- `priority` (Number, Optional)
  Optional rule priority in the compiled policy.
- `action` (String, Required)
  Rule action. Allowed values are `allow` and `deny`.
- `mode` (String, Optional)
  Rule mode override. Allowed values are `audit` and `enforce`. If omitted, the provider uses
  `enforce`.
- `dns` (Object, Optional)
  DNS hostname matcher sugar.
- `destination` (Object, Optional)
  Destination transport matcher sugar.
- `tls` (Object, Optional)
  TLS metadata or HTTP intercept matcher sugar.

### `source_group.rule.dns`

- `exact` (List of String, Optional)
  Exact hostnames to allow or deny. Values are normalized to lowercase.
- `suffixes` (List of String, Optional)
  Hostname suffixes that match any subdomain as well as the bare suffix.

At least one of `exact` or `suffixes` must be set when `dns` is present.

### `source_group.rule.destination`

- `protocol` (String, Optional)
  Transport protocol. Allowed values are `any`, `tcp`, `udp`, and `icmp`.
- `ports` (List of Number, Optional)
  Destination ports.
- `cidrs` (List of String, Optional)
  Destination CIDR matches.
- `ips` (List of String, Optional)
  Exact destination IP matches.

### `source_group.rule.tls`

- `mode` (String, Required)
  TLS matching mode. Allowed values are `metadata` and `intercept`.
- `request` (Object, Optional)
  HTTP request constraints used with `mode = "intercept"`.
- `response` (Object, Optional)
  HTTP response constraints used with `mode = "intercept"`.

`mode = "metadata"` cannot be combined with `request` or `response`. `mode = "intercept"`
requires at least one request or response constraint.

### `source_group.rule.tls.request`

- `methods` (List of String, Optional)
  Allowed HTTP methods. Values are normalized to uppercase.
- `require_headers` (List of String, Optional)
  Headers that must be present on the request.
- `deny_headers` (List of String, Optional)
  Headers that must not be present on the request.
- `target` (List of Object, Optional)
  Host and path constraints. Multiple targets expand into multiple compiled policy rules.

### `source_group.rule.tls.request.target`

- `hosts` (List of String, Required)
  One or more hostnames for the request target. Values are normalized to lowercase.
- `path_exact` (List of String, Optional)
  Exact HTTP path matches.
- `path_prefix` (List of String, Optional)
  HTTP path prefixes.
- `path_regex` (String, Optional)
  Regex applied to the HTTP path.

### `source_group.rule.tls.response`

- `deny_headers` (List of String, Required)
  Headers that must not be present on the response.

## Import

Import by policy name:

```bash
terraform import neuwerk_policy.prod prod-default
```

## Notes

- `document_json` cannot be combined with `default_action` or `source_group`.
- When you use `source_group` authoring, the provider clears `document_json` in state and stores the
  resulting canonical document in `compiled_json`.
- The provider sorts and de-duplicates many list inputs during compilation. Expect `compiled_json`
  to be normalized even when the HCL input order differs.
- A TLS request with multiple `target` entries expands into multiple compiled rules with generated
  rule IDs derived from the base rule ID.
