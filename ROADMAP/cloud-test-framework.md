# Cloud Policy Smoke Test Framework (Plan)

## Goals
- Add a **cloud‑agnostic** consumer‑side test suite that validates **dataplane policy behavior** against real infrastructure.
- Tests must **push policy via HTTPS API**, **verify results from the consumer**, and **restore the prior policy** even on failure.
- Reusable across clouds (Azure/AWS/GCP) with provider‑specific orchestration in `cloud-tests/<provider>/Makefile`.

## Non‑Goals
- No internet egress tests for now (keep consumer → Neuwerk → upstream path only).
- No cluster or control‑plane API feature tests beyond policy manipulation needed for dataplane validation.
- No implementation in this phase; this is the high‑level plan.

## Architecture Overview
**Components**
- **Cloud‑agnostic consumer runner** (Rust binary) invoked on a consumer VM.
- **Provider orchestration** (Makefile targets) responsible for:
  1. Terraform apply
  2. Building the runner
  3. Copying runner to the consumer
  4. Generating a **policy API token** via SSH into a Neuwerk mgmt node
  5. Running the runner with env/config inputs

**Common inputs (env vars passed to the runner)**
- `NEUWERK_POLICY_API_BASE` → `https://<mgmt-lb-ip>:8443`
- `NEUWERK_POLICY_API_TOKEN` → bearer token minted on a Neuwerk node
- `NEUWERK_POLICY_API_INSECURE` → `1` to skip TLS verification (acceptable for now)
- `NEUWERK_UPSTREAM_VIP` → upstream VIP (e.g. `10.20.4.10`)
- `NEUWERK_DNS_SERVER` → mgmt DNS LB IP (e.g. `10.20.1.10`) (intentional: DNS is control-plane and updates dataplane allowlist)
- `NEUWERK_DNS_ZONE` → e.g. `upstream.test`
- `NEUWERK_TEST_TIMEOUT_SECS` → overall timeout budget

**Policy lifecycle**
- Runner **GETs the current policy** and stores it in memory (or temp file). The API does not expose active policy ID, so treat the **most recent policy** in `GET /api/v1/policies` as the current policy for restore (or add an explicit active-policy endpoint later).
- Runner **applies test policy set** per test (or per group of tests).
- On exit or failure: **restore original policy**.

## Core Cloud Tests (10)
These are **policy‑driven dataplane validations** that can run on any cloud with the same upstream VIP.

1. **DNS allowlist allow**
   - Policy: allow DNS for `upstream.test`.
   - Expect: `dig @DNS upstream.test` returns A record to VIP.

2. **DNS allowlist deny (NXDOMAIN)**
   - Policy: deny DNS for `blocked.test`.
   - Expect: `dig @DNS blocked.test` returns **NXDOMAIN**.

3. **DNS allowlist reset on policy rebuild**
   - Policy A: allow `upstream.test`; resolve once.
   - Policy B: deny `upstream.test`.
   - Expect: subsequent query returns **NXDOMAIN** (ensures allowlist cleared).

4. **CIDR + port allow**
   - Policy: allow `tcp/80` from consumer CIDR to upstream VIP.
   - Expect: HTTP 200 from upstream VIP.

5. **CIDR + port deny**
   - Policy: deny `tcp/443` from consumer CIDR to upstream VIP.
   - Expect: TLS connection fails (timeout / reset).

6. **TLS SNI allow**
   - Policy: allow TLS SNI `upstream.test`.
   - Client forces TLS1.2 (inspectable).
   - Expect: HTTPS request succeeds.

7. **TLS SNI deny**
   - Policy: allow only SNI `upstream.test`.
   - Client uses SNI `blocked.test`.
   - Expect: TLS connection denied.

8. **TLS 1.3 uninspectable deny**
   - Policy: TLS rule with `tls13_uninspectable: deny`.
   - Client forces TLS1.3 to `upstream.test`.
   - Expect: connection denied.

9. **Policy re‑evaluation on existing flow**
   - Establish long‑lived TCP connection (port 9000).
   - Apply deny policy for that port.
   - Expect: next send fails (soft‑cut enforcement).

10. **Dataplane counters move for allow + deny**
   - Fetch `/metrics` before/after an allow test and a deny test.
   - Expect: counters like `dp_packets_total{decision="allow|deny"}` and/or `dns_queries_total{result="allow|deny"}` increment as expected.

## Extended Cloud Tests (8) — ICMP + UDP Coverage
11. **ICMP allow (echo request)**
    - Policy: allow `icmp_types: [8]` (echo request) from consumer CIDR to upstream VIP.
    - Expect: `ping -c 3 <vip>` succeeds.

12. **ICMP deny (echo request)**
    - Policy: deny ICMP echo request (type 8) from consumer CIDR.
    - Expect: `ping -c 3 <vip>` fails.

13. **ICMP type/code filtering**
    - Policy: allow `icmp_types: [3]` with `icmp_codes: [4]` (frag-needed) only.
    - Expect: `ping` fails but a crafted ICMP type 3/code 4 test passes (via helper in runner). Requires raw sockets (root or `CAP_NET_RAW`) on the consumer VM.

14. **UDP allow (iperf3 UDP mode)**
    - Policy: allow `udp/5201` from consumer CIDR.
    - Expect: `iperf3 -u` to upstream VIP succeeds with non‑zero throughput. Ensure TCP/5201 control channel is allowed to avoid false negatives.

15. **UDP deny (iperf3 UDP mode)**
    - Policy: deny `udp/5201`.
    - Expect: `iperf3 -u` reports zero throughput / loss (or fails to establish control channel). Prefer allowing TCP/5201 so failures are attributable to UDP.

16. **UDP port‑scoped allow**
    - Policy: allow `udp/53` only.
    - Expect: `dig @DNS upstream.test` succeeds; UDP to another port (e.g. 5201) fails. If using iperf3 for the negative check, allow TCP/5201 control.

17. **TCP allow + UDP deny same port**
    - Policy: allow `tcp/5201` and deny `udp/5201`.
    - Expect: TCP iperf3 succeeds; UDP iperf3 fails.

18. **Policy swap with UDP**
    - Policy A: allow `udp/5201` (succeeds).
    - Policy B: deny `udp/5201` (fails).
    - Expect: failure after policy swap without restarting consumer.

## Test Suite Shape
**Common suite entrypoint** (cloud‑agnostic):
- New Rust binary, e.g. `cloud-tests/runner` or `tools/cloud-test-runner`.
- `cloud-tests/common/run-policy-smoke.sh` to invoke it consistently from any provider.
- Provider Makefile target calls the common script.

**Example invocation flow**
1. `make azure.apply` → Terraform apply
2. `make azure.policy-smoke` → build runner, scp to consumer, mint token, execute

## Orchestration Details
**Make targets (provider‑specific)**
- `azure.policy-smoke` (example):
  - Build runner binary
  - Resolve consumer IP
  - Resolve mgmt LB IP
  - SSH into Neuwerk mgmt node to mint API token
  - SCP runner to consumer
  - Run runner with env vars

**Token minting**
- Reuse existing mint logic from `cloud-tests/azure/scripts/configure-policy.sh`
- The token is generated via **SSH to mgmt node**, then passed as env var to the runner.

## Implementation Plan (High‑Level)
1. **Define runner interface**
   - CLI + env vars
   - JSON test output (pass/fail + timings)
2. **Add cloud‑agnostic runner crate**
   - Minimal deps: `reqwest`, `tokio`, `serde`, `trust-dns` (or `hickory`), `openssl` (if needed)
   - Implement helpers: DNS query, HTTP/HTTPS client, TLS handshake with SNI
3. **Policy management layer**
   - `GET /api/v1/policies` to capture current policy ID
   - `POST /api/v1/policies` to apply per‑test policies
   - Restore original policy at end (or on failure)
4. **Test catalog**
   - Implement core + extended tests above, grouped by policy set to reduce policy churn
5. **Common entrypoint**
   - `cloud-tests/common/run-policy-smoke.sh` handles env setup and invokes runner
6. **Provider integration**
   - Add `make <provider>.policy-smoke` to call common entrypoint
   - Add logic to mint token and pass it in
7. **CI hooks (optional later)**
   - Integrate into provider e2e workflow

## Open Questions (Resolved by User)
- Run tests **from consumer** and modify policy via API.
- Use **Rust** runner.
- Include TLS SNI tests for **both TLS1.2 and TLS1.3 uninspectable**.
- Only test **consumer → Neuwerk → upstream** (ignore internet path).
- Common entrypoint and provider‑specific orchestration.
