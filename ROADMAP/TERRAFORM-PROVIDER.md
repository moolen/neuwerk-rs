# Terraform Provider Plan

## Goals
- Provide a first-class Terraform provider for the firewall HTTP API.
- Make Terraform authoring center on firewall intent, not raw HTTP endpoints.
- Optimize the v1 UX around policies and rules, with good support for many URLs sharing the same behavior.
- Preserve the current control-plane architecture: the provider talks only to the HTTP API.
- Keep the provider safe for cluster deployments where any node may proxy writes to the leader.

## Non-Goals (Phase 1)
- Expose every existing HTTP endpoint as a Terraform resource.
- Manage live/debug surfaces such as wiretap streams or audit query results.
- Mirror the API 1:1 when a higher-level Terraform abstraction is clearly better.
- Solve long-term RBAC/authz design for all machine identities in the first provider milestone.
- Ship fine-grained per-rule Terraform resources.

## Current API Snapshot

### HTTP Surface
- Public auth routes:
  - `POST /api/v1/auth/token-login`
  - `POST /api/v1/auth/logout`
  - `GET /api/v1/auth/sso/providers`
  - `GET /api/v1/auth/sso/:id/start`
  - `GET /api/v1/auth/sso/:id/callback`
- Protected routes:
  - `/api/v1/policies`
  - `/api/v1/integrations`
  - `/api/v1/service-accounts`
  - `/api/v1/settings/tls-intercept-ca`
  - `/api/v1/settings/sso/providers`
  - `/api/v1/stats`
  - `/api/v1/dns-cache`
  - `/api/v1/audit/findings`
  - `/api/v1/support/sysdump/*`

### Auth Semantics
- Protected API requests require a valid JWT bearer token or auth cookie.
- All mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) require the `admin` role.
- Current service-account tokens are minted without roles and are therefore not suitable for Terraform write operations.

### Policy Semantics
- Policies are full documents with:
  - `mode`: `disabled | audit | enforce`
  - optional top-level `default_policy`
  - `source_groups`
- Each source group can combine:
  - static IPs and CIDRs
  - Kubernetes-backed dynamic selectors
- Rules can match:
  - destination IPs and CIDRs
  - protocols and ports
  - ICMP type/code
  - DNS hostnames
  - TLS metadata and TLS-intercept HTTP request/response properties
- Policy activation is synchronous from the API caller's perspective and may return `503` if activation times out.

## Chosen v1 Provider Model

### Provider
- `provider "neuwerk"`

### First-Class Resources
- `neuwerk_policy`
- `neuwerk_kubernetes_integration`
- `neuwerk_tls_intercept_ca`

### Deferred Resources
- `neuwerk_service_account`
- `neuwerk_service_account_token`
- `neuwerk_sso_provider`

The provider should be centered on `neuwerk_policy`. This matches how the API compiles, validates, activates, and replicates policy state as a whole document rather than as independently addressable sub-objects.

## Why The Policy Should Be Aggregate
- The API performs validation and activation on the whole policy document.
- Splitting policy into `policy`, `source_group`, and `rule` resources would create ordering problems and partial-update failure modes.
- Terraform users generally want to express one desired effective policy per environment, not a mutable collection of independent rule objects.
- URL/application matching is nested enough that a raw 1:1 schema would be tedious and repetitive.

## Provider Configuration

### Proposed Schema
- `endpoints` - list of HTTPS base URLs
- `token` - admin JWT bearer token
- `ca_cert_pem` or `ca_cert_file` - server trust anchor
- `request_timeout`
- `retry_timeout`
- `headers` - optional future escape hatch for custom headers

### Behavioral Requirements
- Accept multiple endpoints and try them in order until one succeeds.
- Treat follower proxying as normal behavior, not as an error case.
- Use conservative retry behavior for transient transport failures.
- Do not retry non-idempotent operations after the server has accepted a request unless the request outcome is known.
- Surface API error bodies verbatim where useful.

### Example
```hcl
provider "neuwerk" {
  endpoints       = ["https://fw-a.example.com", "https://fw-b.example.com"]
  token           = var.neuwerk_admin_jwt
  ca_cert_pem     = file("${path.module}/neuwerk-ca.crt")
  request_timeout = "30s"
}
```

## Resource Design

### `neuwerk_kubernetes_integration`
This maps closely to the existing integrations API and should be low-abstraction in v1.

Proposed schema:
- `name`
- `api_server_url`
- `ca_cert_pem`
- `service_account_token` (sensitive)
- computed:
  - `id`
  - `kind`
  - `created_at`
  - `token_configured`

Example:
```hcl
resource "neuwerk_kubernetes_integration" "prod" {
  name                  = "prod-k8s"
  api_server_url        = "https://10.0.0.10:6443"
  ca_cert_pem           = file("${path.module}/k8s-ca.pem")
  service_account_token = var.k8s_service_account_token
}
```

Notes:
- The API does not return the token. The provider must preserve the configured token in state as a sensitive value.
- Import should be supported by integration name.

### `neuwerk_tls_intercept_ca`
This should model the singleton control-plane setting rather than an inventory object.

Proposed schema:
- exactly one of:
  - `generate = true`
  - `ca_cert_pem` + (`ca_key_pem` or `ca_key_der_b64`)
- computed:
  - `configured`
  - `source`
  - `fingerprint_sha256`

Example:
```hcl
resource "neuwerk_tls_intercept_ca" "main" {
  generate = true
}
```

or

```hcl
resource "neuwerk_tls_intercept_ca" "main" {
  ca_cert_pem = file("${path.module}/dpi-root-ca.crt")
  ca_key_pem  = file("${path.module}/dpi-root-ca.key")
}
```

### `neuwerk_policy`
This is the main abstraction and should optimize for readability and reuse.

#### Top-Level Schema
- `name`
- `mode`
- `default_action`
- repeated `source_group`

#### Source Group Schema
- `id`
- `priority`
- `default_action`
- `sources`
- repeated `rule`

#### Source Schema
- `cidrs`
- `ips`
- repeated `kubernetes_selector`

#### Rule Schema
- `id`
- `priority`
- `action`
- `mode`
- one or more match blocks, with provider-side normalization to API shape

#### Provider-Side UX Abstractions
The provider should add limited high-value abstractions that compile into the current API model:

1. `dns` matcher sugar
- allow exact hostnames and suffixes
- compile to the current regex-based `dns_hostname` field

2. `destination` block
- group `protocol`, `ports`, `cidrs`, and `ips` into one authoring surface

3. `tls.request.target` repeated block
- allow many hosts and shared request/path/header constraints under one logical rule shape
- compile into one or more concrete low-level API rules

4. consistent list/set normalization
- uppercase HTTP methods
- lowercase hostnames where appropriate
- stable ordering for generated API payloads

#### Example
```hcl
resource "neuwerk_policy" "main" {
  name           = "prod-default"
  mode           = "enforce"
  default_action = "deny"

  source_group {
    id             = "corp-clients"
    priority       = 10
    default_action = "deny"

    sources {
      cidrs = ["10.20.0.0/16"]

      kubernetes_selector {
        integration = neuwerk_kubernetes_integration.prod.name

        pod_selector {
          namespace    = "apps"
          match_labels = { app = "api" }
        }
      }
    }

    rule {
      id       = "allow-dns"
      priority = 10
      action   = "allow"

      dns {
        exact    = ["github.com", "api.github.com"]
        suffixes = ["example.com"]
      }
    }

    rule {
      id     = "allow-external-secrets"
      action = "allow"

      destination {
        protocol = "tcp"
        ports    = [443]
      }

      tls {
        mode = "intercept"

        request {
          methods = ["GET"]

          target {
            hosts       = ["vault-a.example.com", "vault-b.example.com"]
            path_prefix = ["/external-secrets/"]
          }

          target {
            hosts       = ["secrets.internal.example.com"]
            path_prefix = ["/v1/"]
          }
        }

        response {
          deny_headers = ["x-forbidden"]
        }
      }
    }
  }
}
```

## Mapping Strategy

### API Mapping
- `neuwerk_kubernetes_integration` maps directly to `/api/v1/integrations`.
- `neuwerk_tls_intercept_ca` maps directly to `/api/v1/settings/tls-intercept-ca`.
- `neuwerk_policy` maps to `/api/v1/policies` and `/api/v1/policies/:id`.

### Provider Compilation Layer
The provider should compile high-level Terraform configuration into the current API `PolicyConfig` document.

This compilation layer should:
- expand `dns.exact` and `dns.suffixes` into deterministic regex
- expand repeated `tls.request.target` blocks into concrete low-level rules
- sort generated rules and nested fields for stable plans
- emit diagnostics that reference Terraform field paths, not only raw API error strings

### Stable Identity
Current API identity for policies is UUID-based and server-assigned.

For v1:
- the provider stores the server UUID in Terraform state
- `name` is treated as descriptive, not as the authoritative object key
- import is by UUID

Known limitation:
- the current API does not support upsert-by-name or singleton desired-policy semantics
- drift recovery is therefore weaker than it could be for policy resources

## Recommended API Prerequisites

### Required Before Provider GA
1. Admin-capable machine auth
- Terraform must have a supported way to authenticate for write operations without depending on a human-minted admin JWT workflow.

2. Stable policy identity with upsert-by-name
- Terraform needs a durable policy identity that does not depend on server-assigned UUID history objects.
- Add `PUT /api/v1/policies/by-name/:name` as a supported control-plane API contract before provider GA.
- Expected semantics:
  - create if missing
  - replace if existing
  - return the canonical `PolicyRecord`
  - preserve normal validation, activation, and cluster replication behavior
- `GET /api/v1/policies/by-name/:name` is also recommended for clean import and drift reconciliation.

### Nice To Have
1. Structured DNS hostname matcher in the API
- avoids provider-only regex compilation

2. Explicit active-policy endpoint
- cleaner drift detection and import semantics

3. Server-side dry-run/validate endpoint
- would improve Terraform diagnostics and plan-time validation

## Implementation Plan

### Phase 0: API Contract Hardening
- Finalize the v1 Terraform resource model and field names.
- Implement stable-name policy upsert:
  - `PUT /api/v1/policies/by-name/:name`
  - preferably `GET /api/v1/policies/by-name/:name` as well
- Design and implement admin-capable machine auth.
- Confirm import semantics and documented operational expectations.

### Phase 1: Provider Repository Skeleton
- Create a new provider module in this repository or a sibling repository.
- Preferred monorepo layout if kept here:
  - `terraform-provider-neuwerk/`
- Scaffold:
  - provider entrypoint
  - schema definitions
  - client package
  - acceptance test harness
  - docs/examples directory
- Choose the Terraform provider implementation stack and pin it in the module.

### Phase 2: HTTP Client And Transport Layer
- Implement client configuration from provider schema.
- Implement endpoint failover across `endpoints`.
- Implement TLS trust configuration from PEM/file input.
- Implement request timeout and retry behavior.
- Implement consistent error decoding.
- Add request/response tracing hooks behind debug logging.

### Phase 3: Direct-Mapping Resources
- Implement `neuwerk_kubernetes_integration`.
- Implement `neuwerk_tls_intercept_ca`.
- Cover:
  - create/read/update/delete
  - import
  - sensitive-state handling
  - cluster follower proxy behavior

### Phase 4: Policy Core Resource
- Implement `neuwerk_policy` with a near-API schema first.
- Build translation to the API `PolicyConfig` document.
- Support CRUD and import.
- Preserve server UUID in state.
- Add plan normalization so reordering in user config does not create noisy diffs.

### Phase 5: Policy UX Abstractions
- Add provider-side sugar for:
  - DNS exact/suffix matchers
  - destination grouping
  - repeated TLS/HTTP target blocks for shared URL behavior
- Ensure every abstraction compiles deterministically into the same concrete API payload.
- Add high-quality validation diagnostics before API submission where feasible.

### Phase 6: Testing And Dev Harness
- Unit tests for schema normalization and compilation.
- Client tests with mocked HTTP responses.
- Acceptance tests against a real local firewall node:
  - integration lifecycle
  - TLS intercept CA lifecycle
  - policy create/update/delete
  - policy update that triggers synchronous activation
  - follower endpoint write proxied to leader
- Cluster-aware acceptance tests:
  - provider configured with multiple endpoints
  - first endpoint unavailable
  - second endpoint succeeds

### Phase 7: Documentation And Release
- Write provider docs for:
  - provider authentication
  - cluster endpoint configuration
  - policy authoring patterns
  - URL-sharing examples
  - Kubernetes-backed source groups
- Add examples:
  - simple DNS allow/deny
  - TLS intercept with shared URL policy
  - Kubernetes integration plus dynamic source groups
- Define versioning and release process.

## Testing Strategy

### Unit Tests
- Terraform schema validation
- policy compilation and normalization
- deterministic ordering of generated payloads
- DNS matcher to regex compilation
- repeated URL target expansion

### Integration Tests
- provider client against local API
- non-admin token rejection
- sensitive field persistence behavior
- import and drift handling

### Acceptance Tests
- single-node local mode
- clustered mode with leader proxying
- activation timeout handling
- TLS intercept CA upload and generate flows

### Negative Coverage
- unknown Kubernetes integration referenced by policy
- malformed JWT or insufficient role
- invalid TLS intercept CA/key pair
- invalid policy match combinations

## File-Level Change Map (planned)

### In This Repository
- `ROADMAP/TERRAFORM-PROVIDER.md`
- provider source tree if hosted here, for example:
  - `terraform-provider-neuwerk/main.go`
  - `terraform-provider-neuwerk/internal/provider/*`
  - `terraform-provider-neuwerk/internal/client/*`
  - `terraform-provider-neuwerk/examples/*`
  - `terraform-provider-neuwerk/docs/*`

### Likely Firewall API Changes
- admin-capable machine auth additions
- possible policy upsert or singleton policy endpoint
- optional policy validate endpoint

## Risks And Mitigations
- Risk: provider UX becomes a thin wrapper around a complex nested API shape.
  - Mitigation: keep `neuwerk_policy` aggregate and add targeted abstractions for repeated URL behavior.

- Risk: current policy UUID identity leads to awkward drift and import stories.
  - Mitigation: explicitly document the limitation for v1 or add by-name/singleton API support before GA.

- Risk: Terraform state may contain sensitive values for integrations and CA material.
  - Mitigation: mark all secret fields sensitive, minimize read-back requirements, and document state-handling expectations.

- Risk: machine auth remains human-token-centric.
  - Mitigation: make admin-capable machine auth a Phase 0 prerequisite, not a follow-up.

## Initial Recommendation
- Build the provider around `neuwerk_policy`, `neuwerk_kubernetes_integration`, and `neuwerk_tls_intercept_ca`.
- Keep policy as a single aggregate resource.
- Implement the repeated-URL abstraction in the provider first.
- Do not start provider implementation until the machine-auth story is settled.
