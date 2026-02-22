# HTTP API + TLS Roadmap

Date: 2026-02-21

## Goals
- Add a RESTful HTTPS control-plane API to manage policies.
- Persist policies to distributed storage when the cluster is enabled, and to local disk always.
- Allow multiple policies; each policy has a `mode` (audit|enforce). Only `enforce` is used for dataplane behavior; audit is stored but ignored for now.
- HTTPS is required for the policy API.
- Provide a separate HTTP-only Prometheus metrics endpoint.
- Bootstrap HTTP API TLS from disk if present; otherwise generate a CA, store it (encrypted) in distributed storage, and allow other nodes to issue their own certs.
- Support user-provided SAN/IP entries via CLI.

## Non-Goals (for this iteration)
- Authentication/authorization.
- Policy validation beyond existing parsing/compilation.
- Audit reporting/telemetry for audit-mode policies or rules.
- DNS parsing or any control-plane logic inside the dataplane.

## API Surface
- `POST /v1/policies` (HTTPS)
  - Request body JSON: `{ "mode": "audit"|"enforce", "policy": <PolicyConfig JSON> }`
  - Response JSON: `{ "id": "<uuid>", "created_at": "<rfc3339>", "mode": "audit|enforce", "policy": <PolicyConfig JSON> }`
- `GET /v1/policies` (HTTPS)
  - Response JSON: list of policy records, each: `{ "id", "created_at", "mode", "policy" }`

Notes:
- `policy` is the existing internal `PolicyConfig` JSON shape (currently used in YAML), with a **new rule-level field** `mode: audit|enforce`.
- Policy record `mode` controls whether this policy becomes **active** for dataplane use. When a policy is created with `mode=enforce`, it becomes the active policy (overwriting the previous active policy pointer). Audit policies are stored but do not change the active policy.

## Policy Data Model
- New `PolicyMode` enum: `Audit | Enforce`.
- New `PolicyRecord` struct:
  - `id: Uuid`
  - `created_at: RFC3339 string`
  - `mode: PolicyMode`
  - `policy: PolicyConfig`
- Add `mode: Option<PolicyMode>` to rule config. Default if missing: `Enforce`.
- Compilation behavior:
  - Only rules with `mode == Enforce` are compiled into dataplane policy and DNS policy.
  - Audit rules are ignored for now (kept in storage and API responses only).

## Storage Design
### Distributed (Cluster) Store
Use the existing Raft KV (ClusterStore) and new key prefixes:
- `policies/index` -> JSON list of `PolicyRecord` metadata (id, created_at, mode)
- `policies/item/<id>` -> JSON `PolicyRecord` (full payload, including policy)
- `policies/active` -> active policy id (string/uuid)

Write path when cluster is enabled:
1. Validate/parse policy JSON.
2. Persist full record under `policies/item/<id>`.
3. Update `policies/index` (append, sort by created_at).
4. If `mode == Enforce`, set `policies/active` to `<id>`.

### Local Store (Always-on)
- Directory: `/var/lib/neuwerk/local-policy-store`
- Files:
  - `index.json` (list of metadata)
  - `active.json` (active policy id)
  - `policies/<id>.json` (full policy record)

Write path always persists locally first, then to cluster (if enabled).

## Active Policy Resolution
- The active policy is the record pointed at by `policies/active` (cluster) or `active.json` (local).
- `POST` with `mode=enforce` overwrites the active pointer.
- This keeps “multiple policies” while still providing a single enforce policy for dataplane behavior.

## HTTP API Server
- New control-plane module, e.g. `controlplane/http_api`.
- Bind only on management interface IP.
- HTTPS on `--http-bind` (default `<mgmt-ip>:8443`).
- Implementation: `hyper` or `axum` with `tokio-rustls` for TLS.
- JSON parsing with `serde_json`.

## Leader Proxying
- If cluster is enabled and the node is **not** the leader, proxy the HTTP request to the leader.
- To support this, extend Raft node metadata to include HTTP advertise address:
  - Replace `Node = openraft::BasicNode` with a custom `Node` struct that includes `raft_addr` and `http_addr`.
  - Populate it on startup from CLI config.
  - Use raft metrics membership to resolve leader -> `http_addr`.
- Proxy implementation:
  - Recreate the incoming request (method, path, headers, body) and forward via HTTPS client.
  - Propagate response status/headers/body back to caller.
  - If leader unknown, return `503` with a JSON error.

## HTTP TLS Bootstrap
Separate CA from cluster CA.

### Disk Layout
- Default dir: `/var/lib/neuwerk/http-tls`
- Files:
  - `ca.crt`
  - `node.crt`
  - `node.key`

### CLI Flags
- `--http-bind <ip:port>` (default `<mgmt-ip>:8443`)
- `--http-advertise <ip:port>` (default same as bind)
- `--http-tls-dir <path>` (default `/var/lib/neuwerk/http-tls`)
- `--http-cert-path <path>` (optional override)
- `--http-key-path <path>` (optional override)
- `--http-ca-path <path>` (optional override)
- `--http-tls-san <csv>` (comma-separated SAN entries; each entry is parsed as IP or DNS)

### Bootstrap Behavior
1. **If `node.crt` + `node.key` exist on disk**:
   - Load and use them.
   - If CA cert is present on disk and distributed storage is empty, publish CA cert + encrypted CA key to distributed storage.
2. **If cert/key do not exist**:
   - If cluster is seed and HTTP CA is missing, generate a new CA and store:
     - `http/ca/cert` = CA cert PEM
     - `http/ca/envelope` = encrypted CA key (using bootstrap token)
   - If cluster joiner, fetch CA cert + encrypted CA key from distributed store and decrypt.
   - Generate node key/cert signed by HTTP CA and persist to disk.

### Storage Keys for HTTP CA
- `http/ca/cert` -> CA cert PEM
- `http/ca/envelope` -> encrypted CA key (single envelope, shared across nodes)

Implementation detail: add `ClusterCommand::SetHttpCaCert` and `ClusterCommand::UpsertHttpCaEnvelope` (or use `Put` with these keys).

### SANs
- Always include:
  - Management interface IP
  - `--http-advertise` IP
- Add user-provided SANs from `--http-tls-san` (comma-separated). Each entry is parsed:
  - If it parses as an IP, add as IP SAN
  - Otherwise, add as DNS SAN

## Metrics Endpoint
- Separate HTTP-only listener on `--metrics-bind` (default `<mgmt-ip>:8080`).
- Expose `GET /metrics` with Prometheus format.
- Use `prometheus` crate with basic counters/gauges:
  - `http_requests_total{path,method,status}`
  - `http_request_duration_seconds`
  - Build info (static gauge) if desired.

## Policy Replication Updates
- Replace `rules/active` polling with `policies/active` pointer resolution.
- For cluster-enabled nodes:
  - Read `policies/active` and fetch `policies/item/<id>`.
  - Compile and update `PolicyStore` when the active policy changes.
- For cluster-disabled nodes:
  - Load from local store active pointer at startup, and update `PolicyStore` on local writes.

## CLI/Config Updates
- Extend `usage()` text and `parse_args()` to include new flags.
- Add a shared helper to resolve management interface IP (e.g., via `rtnetlink`).

## Tests
- Integration tests (root-required if using netns):
  1. HTTPS API happy path: POST policy with `mode=enforce`, GET list, ensure active policy applied.
  2. Leader proxying: send POST to follower; verify it reaches leader and is stored.
  3. TLS bootstrap: no certs -> CA created, cert issued; connect with rustls client.
  4. Metrics endpoint: GET `/metrics` returns 200 and contains expected metric names.

## Implementation Order
1. Data model changes: add `PolicyMode`, rule-level `mode`, update compile to ignore audit rules.
2. Storage layer: local policy store + distributed policy keys.
3. HTTP API server (HTTPS) + JSON model + proxying.
4. HTTP TLS bootstrap + CA storage/envelope integration.
5. Metrics HTTP server.
6. Policy replication update + tests.
7. CLI flags + docs + usage.

## Resolved Decisions
- Leader HTTP address is derived from the leader’s cluster addr IP plus the fixed HTTPS port `8443` (no custom node metadata).
- `policies/index` is ordered strictly by `created_at`.
- HTTP API CA key is **not** persisted on disk; only the encrypted envelope is stored in distributed storage.
