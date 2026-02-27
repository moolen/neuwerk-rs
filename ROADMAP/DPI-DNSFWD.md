# DPI + DNS Service-Lane Roadmap

Date: 2026-02-27

## Goals
- Replace the current management-NIC DNS runtime with dataplane-routed DNS handling via a dedicated in-process service-plane runtime component.
- Support DNS interception for configured destination IPs, short-circuiting normal dataplane policy evaluation.
- Support both DNS over UDP and DNS over TCP for intercepted DNS traffic.
- Add explicit TLS interception policy mode that is separate from existing TLS metadata matching mode.
- Terminate selected TLS flows in service-plane and enforce L7 HTTP policy:
  - Request: host, method, path, query, headers.
  - Response: headers.
- Enforce fail-closed behavior end-to-end.
- Send TCP RST to client when intercepted HTTP/TLS policy denies.
- Remove old DNS listen runtime in one step.
- Update Azure deployment and cloud-tests accordingly.

## Non-Goals
- Preserve `--dns-listen` / old control-plane DNS runtime compatibility.
- Fail-open fallbacks for TLS/DPI or DNS service unavailability.
- External GitHub dependency for smoke tests (use upstream VM-hosted targets instead).

## Resolved Decisions
- Service lane: TAP-based host/service interface (`svc0`) between dataplane and service-plane runtime.
- `trafficd` is an in-process runtime component (not a separate OS process).
- DNS uses two explicit lists:
  - DNS target IPs (intercept match in dataplane).
  - DNS upstream resolver endpoints (service-plane forwarding targets).
- DNS traffic not matching target IP list uses normal dataplane policy path.
- Keep existing DNS policy/allowlist logic, but execute in service-plane DNS handler.
- TLS interception uses a dedicated interception CA.
- In cluster mode, interception CA cert/key is stored in distributed settings in Raft.
- CA material is managed from the UI Settings page.
- HTTP/1.1 and HTTP/2 are both in scope for interception.
- Deny action for intercepted URL/policy violations is TCP RST.
- URL matching supports separate host/path/query matching.
- Fail-closed always.
- One coordinated (flag-day) rollout is acceptable.
- In local mode, interception CA cert/key are persisted on disk; on cluster join they are migrated to Raft-backed settings.
- TLS intercept steering is allowed only when rule preconditions match source group + destination (IP/CIDR or DNS-allowlist-derived mapping).
- If repeated DNS flags and CSV DNS flags are both provided, startup fails (no precedence rule).
- For intercepted TCP flows, service-plane failure path sends client TCP RST (not silent drop).
- Policy write APIs wait for both dataplane and service-plane generation ack with a 2s timeout; timeout returns `503`.

## High-Level Architecture
1. Dataplane process (`data0` owner, DPDK):
   - Classifies packets.
   - Short-circuits DNS packets by destination IP + port/protocol.
   - Steers intercepted DNS/TLS flows to service lane interface (`svc0`).
   - Maintains NAT/flow bookkeeping for forwarded flows.
2. Service-plane runtime (`trafficd`, userspace):
   - Binds service lane sockets/listeners.
   - DNS proxy engine (UDP+TCP) with existing DNS policy/allowlist semantics.
   - TLS MITM proxy and HTTP policy engine (req/res checks).
   - Emits RST on deny for intercepted TLS/HTTP flows.
3. Control-plane:
   - Policy/setting management only.
   - Distributes interception CA and policy snapshots to service-plane.
   - Exposes UI/API for settings and policy edits.

## Data Path Design

### A) DNS (short-circuit path)
1. Packet arrives on dataplane.
2. If `dst_ip in dns_target_ips` and (`udp/53` or `tcp/53`), bypass normal policy evaluation.
3. Dataplane steers packet/flow to service lane (`svc0`) and tracks state.
4. Service-plane DNS handler:
   - Applies DNS policy + source-group logic.
   - For allowed query: forwards to configured upstream resolver(s), validates response, updates allowlist + DNS map.
   - For denied query: returns NXDOMAIN (same semantics as today).
5. Response is returned through service lane and egressed by dataplane.

### B) TLS interception path
1. Packet is eligible for interception when:
   - Rule has `tls.mode = intercept`.
   - Source matches policy source-group semantics.
   - Destination matches policy destination semantics by IP/CIDR or DNS mapping populated from prior allowed DNS query (DNS "punch-hole" behavior).
2. Dataplane steers flow to service lane.
3. Service-plane performs TLS termination with interception cert.
4. HTTP parser/enforcer evaluates request and response policy constraints.
5. Allow:
   - Proxy upstream connection and relay data.
6. Deny:
   - Emit TCP RST to client (and close upstream side).

### C) Non-intercepted traffic
- Existing dataplane behavior remains:
  - Non-DNS-target DNS traffic goes through normal policy evaluation.
  - TLS metadata matching (`pending_tls`/SNI/cert checks) remains available and distinct from interception mode.

## CLI / Runtime Flag Changes

### Remove
- `--dns-listen` (removed immediately).

### Add
- `--dns-target-ip <ipv4>` (repeatable; at least one required for DNS interception feature enablement).
- `--dns-upstream <ip:port>` (repeatable; now interpreted as service-plane resolver list, replacing single endpoint semantics).
  - Keep flag name for compatibility with deployment tooling, but allow repeated values.
- Optional explicit form (if preferred over repeated):
  - `--dns-target-ips <csv>` and `--dns-upstreams <csv>`.
  - CSV and repeated forms are mutually exclusive; specifying both forms for the same setting is a startup error.

### Keep
- `--dns-allowlist-idle-secs`, `--dns-allowlist-gc-interval-secs`.

## Policy Model Changes

### 1) Keep existing TLS metadata mode
- Existing `tls` matcher behavior remains for pass-through validation.

### 2) Add explicit TLS interception mode
- Extend rule schema:

```yaml
match:
  proto: tcp
  tls:
    mode: intercept
    # L7 HTTP policy block
    http:
      request:
        host:
          exact: ["example.com"]
          regex: null
        methods: ["GET", "POST"]
        path:
          exact: []
          prefix: ["/external-secrets/"]
          regex: null
        query:
          # key/value constraints (all optional)
          keys_present: ["ref"]
          key_values_exact:
            ref: ["main"]
          key_values_regex:
            ref: "^[a-z0-9._-]+$"
        headers:
          require_present: ["user-agent"]
          deny_present: ["x-block-me"]
          exact:
            x-env: ["prod"]
          regex:
            x-request-id: "^[a-f0-9-]{8,}$"
      response:
        headers:
          require_present: ["content-type"]
          deny_present: ["x-forbidden"]
          exact: {}
          regex:
            content-type: "^text/|^application/json"
```

### 3) URL match granularity
- Host/path/query are matched independently.
- Full URL policy is represented by combining these submatchers.

### 4) Future-safe policy options (additive)
- Request:
  - body size limit, content-type allowlist, authority/host consistency checks, ALPN constraints.
- Response:
  - status code allow/deny, max header size.
- Action semantics:
  - currently `rst` only (fail-closed), with optional future `http_error` mode.

## Settings / Distributed Storage

### New distributed settings keys (Raft)
- `settings/tls_intercept/ca_cert_pem`
- `settings/tls_intercept/ca_key_pem`
- Optional:
  - `settings/tls_intercept/cert_ttl_secs`
  - `settings/tls_intercept/default_san_template`

### API/UI
- Add Settings API for interception CA upload/update/get metadata.
- UI Settings page:
  - Upload CA cert PEM + private key PEM.
  - Validate key-cert pair before commit.
  - Show active CA fingerprint and update timestamp.

### Local mode persistence + cluster migration
- Local (non-cluster) mode persists interception CA files at:
  - `/var/lib/neuwerk/http-tls/intercept-ca.crt`
  - `/var/lib/neuwerk/http-tls/intercept-ca.key`
- When cluster mode is enabled or a node joins a cluster, local CA material is migrated into Raft settings and local files are no longer treated as source of truth.

## Service-Plane Runtime Plan (`trafficd`)

### Responsibilities
- Own `svc0` endpoint(s).
- DNS handlers:
  - UDP + TCP listeners.
  - Upstream forwarding with timeout/retry policy and validation.
- TLS interception handlers:
  - Terminate client TLS with minted leaf certs signed by interception CA.
  - Upstream TLS client mode to target server.
  - HTTP/1.1 + HTTP/2 decoding and policy checks.
- Metrics export hooks (reuse existing metrics registry where possible).

### Integration model
- Spawned/managed in-process by the main process as an isolated runtime component (not a separate OS process), with explicit failure handling and lifecycle supervision.
- Dataplane and service-plane communicate via kernel datapath over `svc0` (TAP lane), not blocking dataplane worker loops.

## Dataplane Changes
1. Add DNS target-IP matcher before normal policy path.
2. Add steering actions for service lane for:
   - DNS target flows.
   - TLS intercept-mode flows.
3. Preserve normal policy behavior for non-matching flows.
4. Keep existing TLS metadata mode path untouched.
5. Fail-closed behavior:
   - If service lane unavailable or steering fails:
     - intercepted TCP flows: send client TCP RST.
     - non-TCP intercepted traffic: drop/deny.

## Control-Plane Changes
1. Remove old `dns_proxy::run_dns_proxy` runtime thread and readiness surface as a standalone mgmt DNS listener.
2. Keep DNS policy and allowlist logic, move invocation to service-plane DNS handlers.
3. Add interception CA settings storage + replication + validation.
4. Extend policy compiler for `tls.mode = intercept` and HTTP rules.
5. Add policy activation synchronization for service-plane generation updates.
   - `POST`/`PUT`/`DELETE /api/v1/policies` wait for both dataplane and service-plane generation acknowledgements.
   - Timeout is 2 seconds; timeout returns `503`.

## Metrics and Observability
- Add service-plane metrics families:
  - `svc_dns_queries_total`, `svc_dns_upstream_rtt_seconds`, `svc_dns_nxdomain_total`.
  - `svc_tls_intercept_flows_total`, `svc_http_requests_total`, `svc_http_denies_total`.
  - `svc_policy_rst_total` (reason labels).
  - `svc_fail_closed_total` (component labels: dns, tls, io, parse).
- Preserve existing dataplane packet decision metrics.
- Add explicit labels to distinguish metadata TLS mode vs intercept TLS mode.

## Security Constraints
- Interception CA private key never leaves control-plane storage/API boundaries (local files in local mode; Raft-backed settings in cluster mode).
- Key material file permissions and memory handling hardened.
- Fail-closed when CA missing for intercept policy.
- Cert minting constraints:
  - SAN based on requested host.
  - Short leaf cert validity.
  - Rotation-safe cache invalidation.

## Cloud / Azure Deployment Updates

### Remove mgmt DNS LB
- Remove `module "mgmt_dns_lb"` from Azure Terraform root.
- Remove related backend pool attachment for firewall mgmt NIC.
- Remove output `mgmt_dns_lb_ip`.
- Remove scripts logic that prefers DNS LB IP.

### Firewall cloud-init/systemd args
- Remove `--dns-listen`.
- Pass new DNS service flags:
  - repeated `--dns-target-ip ...`
  - repeated `--dns-upstream ...`
- Add these values as Terraform variables and plumb through:
  - `dns_target_ips` (list)
  - `dns_upstreams` (list of `ip:port`)

### Azure vars/modules to update
- `cloud-tests/azure/terraform/variables.tf`
- `cloud-tests/azure/terraform/main.tf`
- `cloud-tests/azure/terraform/modules/firewall_vmss/variables.tf`
- `cloud-tests/azure/terraform/modules/firewall_vmss/main.tf`
- `cloud-tests/azure/terraform/cloud-init/firewall.yaml.tmpl`
- Delete/retire `modules/mgmt_dns_lb` references.

### Azure docs/scripts
- Update:
  - `cloud-tests/azure/README.md`
  - `cloud-tests/azure/scripts/run-tests.sh`
  - `cloud-tests/azure/Makefile` (`policy-smoke` target env setup)
  - `cloud-tests/common/run-policy-smoke.sh`

## Cloud Smoke Test Changes

### Replace GitHub dependency with upstream VM-hosted test target
- Upstream VM serves deterministic HTTPS endpoints for path checks:
  - Allow path: `/external-secrets/external-secrets`
  - Deny path: `/moolen`
- Domain for test stays local (e.g. `${DNS_ZONE}`), resolved via DNS interception path.

### New smoke tests
1. `tls_http_path_allow`:
   - Policy allows host/path for `/external-secrets/external-secrets`.
   - Request succeeds (2xx expected).
2. `tls_http_path_deny_rst`:
   - Same policy denies `/moolen`.
   - Client observes TCP reset / connection failure consistent with RST.

### Existing DNS smoke adjustments
- DNS server target in tests becomes configured DNS target IP (dataplane path), not mgmt DNS LB.
- Add DNS over TCP smoke:
  - `dig +tcp @<dns-target-ip> <zone>` success case.

## Test Plan

### Unit tests
- DNS target matching logic in dataplane (UDP and TCP).
- Policy compiler:
  - `tls.mode` separation correctness.
  - HTTP matcher schema compile/validation.
- URL matcher components (host/path/query/header) for exact/prefix/regex.

### Integration tests (local harness)
- DNS interception short-circuits policy.
- Non-target DNS still evaluated by normal dataplane policy.
- DNS UDP + TCP end-to-end via service lane.
- TLS intercept allow/deny with RST behavior.
- HTTP/1.1 and HTTP/2 allow/deny coverage.
- Fail-closed cases:
  - service-plane down,
  - missing interception CA,
  - malformed HTTP on intercepted flow.

### Cloud tests
- Azure policy smoke includes:
  - DNS UDP + TCP checks.
  - TLS L7 allow path success.
  - TLS L7 deny path RST.
- Remove reliance on `mgmt_dns_lb_ip` output and module.

## Migration / Rollout
1. Land config/policy/runtime/dataplane changes as one coordinated rollout.
2. Remove old DNS runtime and `--dns-listen` in the same rollout.
3. Update Azure deployment in lockstep to pass new flags.
4. Update cloud tests and docs.

## Implementation Phases

### Phase 1: Config + Policy Surface
- Add CLI flags for DNS target IP list and repeated DNS upstreams.
- Remove `--dns-listen` parsing and runtime wiring.
- Add policy schema for `tls.mode = intercept` and HTTP match blocks.
- Add settings API/storage for interception CA cert/key in Raft.

### Phase 2: Service-Plane Runtime
- Create `trafficd` in-process runtime scaffold.
- Implement DNS UDP/TCP handlers with existing DNS policy/allowlist logic.
- Implement runtime lifecycle, health, and metrics.

### Phase 3: Dataplane Steering
- Add DNS target short-circuit steer path.
- Add TLS intercept steer path.
- Wire TAP `svc0` lane and fail-closed behavior.

### Phase 4: TLS MITM + HTTP Enforcement
- Cert minting from dedicated interception CA.
- HTTP/1.1 + HTTP/2 parsing/enforcement.
- Deny => client RST implementation.
- Response header validation path.

### Phase 5: Azure + Cloud Tests
- Remove mgmt DNS LB Terraform module wiring.
- Add new DNS variables/flags in Azure deployment.
- Update smoke scripts + runner tests for upstream-hosted allow/deny URL checks.
- Add DNS over TCP smoke coverage.

### Phase 6: Hardening + Observability
- Add fail-closed counters and explicit alerts.
- Load/latency characterization.
- Validate rollover behavior for CA updates and policy generation sync.

## Acceptance Criteria
- Firewall starts without `--dns-listen`; old DNS runtime is removed.
- DNS target IP short-circuit works for UDP and TCP port 53.
- Non-target DNS traffic uses normal policy path.
- TLS intercept mode is distinct from existing TLS metadata mode.
- Intercepted deny generates TCP RST.
- HTTP/1.1 and HTTP/2 request enforcement and response-header checks are functional.
- Interception CA is settable in UI and stored/replicated in Raft.
- In local mode, interception CA persists on disk and migrates into Raft on cluster join.
- Azure cloud-test no longer uses mgmt DNS LB and passes updated smoke suite.
- All new behaviors fail closed.
- Policy writes wait for both dataplane and service-plane generation ack and return `503` after 2s timeout.

## Risks and Mitigations
- Risk: TAP service lane throughput bottleneck.
  - Mitigation: profile early; keep option to move to DPDK ring IPC later.
- Risk: HTTP/2 policy parser complexity.
  - Mitigation: explicit limits/timeouts and strict fail-closed defaults.
- Risk: CA misconfiguration causes broad outages.
  - Mitigation: pre-commit validation + visible settings status in UI.
- Risk: Cloud test flakiness due to external dependencies.
  - Mitigation: upstream VM-hosted deterministic endpoints only.

## File-Level Change Map (planned)
- Runtime / dataplane:
  - `src/main.rs`
  - `src/dataplane/engine.rs`
  - `src/dataplane/dpdk_adapter.rs`
  - new: `src/serviceplane/*` (or `src/controlplane/trafficd/*`)
- Policy/config/settings/UI:
  - `src/controlplane/policy_config.rs`
  - `src/dataplane/policy.rs`
  - `src/controlplane/http_api.rs`
  - `ui/src/*` (Settings page + API client)
  - cluster settings store modules under `src/controlplane/cluster/*`
- Azure cloud deployment/tests:
  - `cloud-tests/azure/terraform/main.tf`
  - `cloud-tests/azure/terraform/variables.tf`
  - `cloud-tests/azure/terraform/outputs.tf`
  - `cloud-tests/azure/terraform/modules/firewall_vmss/{main.tf,variables.tf}`
  - `cloud-tests/azure/terraform/cloud-init/firewall.yaml.tmpl`
  - `cloud-tests/azure/scripts/run-tests.sh`
  - `cloud-tests/common/run-policy-smoke.sh`
  - `cloud-tests/runner/src/main.rs`
  - `cloud-tests/azure/README.md`
