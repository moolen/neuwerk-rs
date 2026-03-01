# Kubernetes Integration Plan

## Goals
- Add a first-class Kubernetes integration type in the control-plane and UI.
- Let policies reference Kubernetes selectors so source groups can resolve to pod IPs or node IPs dynamically.
- Keep dataplane free of Kubernetes logic; all List/Watch logic remains in control-plane.
- Validate end-to-end that selector-driven source groups actually enforce policy behavior on traffic.

## Non-Goals (Phase 1)
- Cloud autodiscovery of API server/CA/token (EKS/GKE/AKS).
- Additional auth methods (basic auth, mTLS client certs).
- IPv6 selector resolution.
- Generic external integrations beyond Kubernetes.

## Proposed Policy YAML Schema

### Source Group Extension
Add a new optional `kubernetes` source block under `source_groups[].sources`.

```yaml
mode: enforce
policy:
  default_policy: deny
  source_groups:
    - id: apps-k8s
      priority: 10
      sources:
        # Existing static sources remain supported
        cidrs: ["10.10.0.0/16"]
        ips: ["10.10.1.10"]

        # New dynamic Kubernetes selectors
        kubernetes:
          - integration: prod-cluster
            pod_selector:
              namespace: payments
              match_labels:
                app: checkout
          - integration: prod-cluster
            node_selector:
              match_labels:
                nodepool: workers

      rules:
        - id: allow-web
          action: allow
          match:
            proto: tcp
            dst_ports: [80, 443]
```

### Validation Rules
- `integration` must match an existing integration name.
- Exactly one of `pod_selector` or `node_selector` per entry.
- `pod_selector.namespace` required when `pod_selector` is used.
- `match_labels` is key/value exact match in v1; no set-based expressions in phase 1.
- `sources` may combine static and Kubernetes-derived addresses (union semantics).
- Source group cannot be empty after schema validation; dynamic-only groups are allowed.

## API + Data Model

### Integration Record
New persisted object:
- `id` (UUID)
- `name` (unique, user-provided)
- `kind` (`kubernetes`)
- `created_at` (RFC3339)
- `spec`:
  - `api_server_url`
  - `ca_cert_pem`
  - `auth`:
    - `type: service_account_token`
    - `token` (write-only on API responses)
- `status` (derived/runtime):
  - `state` (`ready|degraded|error`)
  - `last_sync_at`
  - `last_error`

### HTTP Endpoints
Under `/api/v1`:
- `GET /integrations`
- `POST /integrations`
- `GET /integrations/:name`
- `PUT /integrations/:name`
- `DELETE /integrations/:name`

Behavior:
- `name` uniqueness enforced per integration kind.
- Secret token never returned by `GET` (masked metadata only).
- Policy create/update fails fast if referenced integration does not exist.

## Architecture

### Control-Plane Components
1. **Integration repository**
- New storage abstraction for integration records.
- Local mode: disk-backed store.
- Cluster mode: raft-backed keys, same leader/proxy semantics as policy APIs.

2. **Kubernetes resolver manager**
- New control-plane runtime task that tracks active policy generation and selector bindings.
- For each distinct `(integration, selector)`:
  - establish Kubernetes client
  - perform initial List
  - continue Watch
  - maintain resolved IPv4 set
- Push resolved IPs into `DynamicIpSetV4` bound to source groups.

3. **Policy compile/runtime binding**
- Extend policy config compile output to include Kubernetes binding descriptors and dynamic source handles.
- `PolicyStore::rebuild` installs policy snapshot with dynamic sets.
- Resolver manager rebinds watchers on policy generation changes.

### Dataplane Boundary (kept strict)
- Dataplane consumes only resolved IP sets via existing `IpSetV4::with_dynamic` behavior.
- No Kubernetes client, no label parsing, no API calls in dataplane.

## Runtime Behavior Details
- Pod selector source IP extraction: `pod.status.podIP` (IPv4 only) for all pods with a non-empty `podIP` that match namespace+labels (phase is not filtered in v1).
- Node selector source IP extraction: `node.status.addresses[type=InternalIP]` (IPv4).
- Watch reconnect with bounded exponential backoff.
- On `410 Gone` watch expiry: relist and resume.
- Stale-IP grace behavior:
  - If Kubernetes API is temporarily unreachable, keep last known resolved IPs for a configured grace period.
  - After grace expiry, treat selector resolution as empty (normal policy deny path for unmatched sources).
- Add metrics:
  - `k8s_resolver_sync_total{integration,kind,result}`
  - `k8s_resolver_objects{integration,kind}`
  - `k8s_resolver_ips{integration,kind}`
  - `k8s_resolver_errors_total{integration,kind,reason}`
  - `k8s_resolver_stale_grace_active{integration,kind}`

## UI Plan

### Navigation
- Add `Integrations` page in sidebar and route.

### Integrations Page (Phase 1)
- List existing integrations.
- Create Kubernetes integration form:
  - Name
  - API server URL
  - CA cert (PEM textarea)
  - Service account token (password input)
- Edit/delete actions.
- Runtime status column (`ready/degraded/error`).

### Policies Page updates
- Update YAML schema (`ui/utils/policySchema.ts`) with `sources.kubernetes` definitions.
- Add template snippet examples for pod and node selector usage.

## Testing Strategy

### Unit Tests
- Policy schema parsing and validation for Kubernetes source entries.
- Compile output contains dynamic source bindings.
- Selector validation (exactly one of pod/node selector, required namespace, etc.).
- Resolver mapping logic from Pod/Node objects to IPv4 sets.

### HTTP API Integration Tests (`tests/http_api.rs`)
- CRUD lifecycle for integrations.
- Name uniqueness and validation failures.
- Secret redaction on reads.
- Policy POST/PUT rejects unknown integration references.

### Resolver Tests
- Use a mock Kubernetes API server (HTTPS + token auth) in Rust tests.
- Validate List/Watch handling:
  - initial sync
  - add/update/delete events
  - reconnect and relist on watch expiration.

### E2E Test (required)
Deterministic harness case (required in CI):
- Add e2e case in existing netns harness:
  1. start firewall
  2. create Kubernetes integration pointing to in-process mock Kubernetes API
  3. apply policy with pod/node selector source group
  4. drive traffic from IP not in selector set -> denied
  5. emit watch event adding matching pod/node IP -> allowed
  6. emit delete event removing IP -> denied again
- This validates both watch pipeline and real dataplane policy enforcement path.

Real Kubernetes case (required in CI):
- Add `kind`-backed e2e that validates the same selector-to-policy behavior against a real Kubernetes API server and real pods.

## Incremental Implementation Phases

### Phase 0: Contracts and Schema
- Add Rust config types for integration records and Kubernetes selector references.
- Extend policy YAML schema/types (backend + UI schema).
- Add strict validation and user-facing errors.

### Phase 1: Integration Persistence + API
- Implement local/cluster integration store.
- Add `/api/v1/integrations` endpoints with auth and leader proxy behavior.
- Add secret write-only handling.

### Phase 2: Policy Binding to Dynamic Sources
- Extend policy compile output to include Kubernetes selector bindings.
- Wire bindings into `PolicyStore` rebuild path and generation tracking.
- Ensure DNS policy source-group evaluation includes dynamic sources.
- Extend TLS intercept steering path to support dynamic Kubernetes-backed source groups in phase 1 (no static-CIDR-only restriction).

### Phase 3: Kubernetes Resolver Runtime
- Implement Kubernetes client + list/watch manager in control-plane.
- Attach runtime to active policy generation lifecycle.
- Add metrics and robust reconnect behavior.

### Phase 4: UI
- Add Integrations route/page and API client methods.
- Add creation/edit forms and status rendering.
- Update policy editor schema for Kubernetes source syntax.

### Phase 5: End-to-End Validation
- Add resolver + API integration tests.
- Add e2e selector-to-traffic enforcement test in harness.
- Add mandatory `kind`-backed e2e coverage in CI.

## File-Level Change Map (planned)
- `src/controlplane/http_api.rs` (new integrations endpoints)
- `src/controlplane/policy_config.rs` (schema + compile bindings)
- `src/controlplane/policy_store.rs` (binding lifecycle integration)
- `src/controlplane/mod.rs` (new integrations module export)
- `src/controlplane/<new>/integrations/*` (store, k8s resolver manager, types)
- `src/main.rs` (spawn resolver runtime)
- `tests/http_api.rs` (integration API tests)
- `src/e2e/tests.rs` + `src/e2e/services.rs` (mock kube API + e2e case)
- `ui/App.tsx` + `ui/components/Sidebar.tsx` (route/nav)
- `ui/pages/IntegrationsPage.tsx` (new page)
- `ui/services/api.ts` + `ui/types.ts` (integration API models)
- `ui/utils/policySchema.ts` (YAML schema extension)

## Risks and Mitigations
- Risk: High watch churn in large clusters.
  - Mitigation: deduplicate identical selector registrations and share watchers.
- Risk: Secret handling exposure.
  - Mitigation: write-only token fields and redaction in API responses/logs.
- Risk: Dynamic sources interacting with TLS intercept steering.
  - Mitigation: implement dynamic-source-aware steering behavior in phase 1 and add explicit e2e coverage for TLS-intercept + Kubernetes-selected sources.
- Risk: Real Kubernetes e2e flakiness in CI.
  - Mitigation: keep deterministic mock-API e2e as a fast gate and add retries/timeouts/resource cleanup hardening for mandatory `kind` CI coverage.

## Resolved Decisions (from clarification)
- Selector language in phase 1: `match_labels` only (no `matchExpressions` yet).
- Pod source eligibility: include all pods that have a `podIP` (not only `Running`).
- Node source IP choice: use `InternalIP`.
- API outage behavior: keep stale resolved IPs during a grace period; expire to empty set after grace.
- Integration naming: unique per integration kind.
- Real Kubernetes e2e (`kind`): mandatory in CI.
- `tls.mode=intercept` with Kubernetes-backed dynamic source groups: supported in phase 1.
