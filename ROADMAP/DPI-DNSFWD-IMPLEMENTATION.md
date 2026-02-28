# DPI + DNSFWD Implementation Plan

Date: 2026-02-27

This plan breaks `ROADMAP/DPI-DNSFWD.md` into implementation-sized steps with explicit test gates.

## Current State (Implemented)
- CLI/config surface for repeated/CSV DNS targets/upstreams is implemented.
- Legacy `--dns-listen` is removed from runtime flags.
- DNS runtime runs through `trafficd` + `dns_proxy` (UDP/TCP).
- Dataplane DNS target short-circuit for UDP/TCP :53 is implemented.
- TLS intercept policy schema (`tls.mode=intercept`, `tls.http`) compiles and validates.
- Intercept CA settings API + UI wiring is implemented.
- Cluster migration for intercept CA into Raft keys is implemented.
- TLS MITM forwarding and HTTP policy enforcement are implemented for HTTP/1.1 and HTTP/2, with deny fail-closed behavior.
- Service-lane runtime plumbing is implemented with explicit `svc0` interface bring-up and NAT steering to service listeners.
- Policy write APIs gate on dataplane + service-plane generation acknowledgement (2s timeout, `503` on timeout).
- Cloud smoke strict allow/deny path behavior is enabled in the runner (`tls_intercept_http_path_enforcement`).
- Service-plane metrics families are implemented (`svc_dns_*`, `svc_tls_intercept_flows_total`, `svc_http_requests_total`, `svc_http_denies_total`, `svc_policy_rst_total`, `svc_fail_closed_total`).
- TLS intercept now mints per-host leaf certificates on demand from SNI with an in-memory cache (TTL + bounded size).
- Integration coverage includes HTTP/2 intercept concurrency smoke (`tls_intercept_h2_concurrency_smoke`) and DPDK fail-closed intercept RST parity (`process_frame_intercept_fail_closed_returns_rst`).
- TLS intercept CA updates now trigger deterministic runtime reload via a CA-generation signal (`tls_intercept_ca_rotation_reloads_runtime` e2e coverage).
- DPDK dataplane now has intercept-to-host steering plumbing: intercept-eligible flows can emit `Action::ToHost`, and the DPDK adapter queues/writes those frames to the service-lane TAP (`svc0`) when available (unit + packet/integration coverage added).
- DPDK adapter now drains service-lane (`svc0`) egress back into dataplane TX with deterministic L2 rewrite/ARP behavior (`process_service_lane_egress_frame`, `drain_service_lane_egress`, plus unit/integration coverage).
- Azure smoke script now enforces strict TLS intercept path behavior by default (allowed path succeeds, denied path must reset/refuse).

## Remaining Workstreams

### 1) Hardening / Follow-ups
Goal: production hardening now that roadmap-scope behavior is implemented.

Remaining candidate:
- Run real DPDK/cloud validation of the service-lane return path (Azure policy-smoke on current images) and promote from validated to deployment-default parity once observed stable in cloud.

## Commit Order (Recommended)
Completed.

## Definition of Done
- All acceptance criteria from `ROADMAP/DPI-DNSFWD.md` are green.
- `cargo test --tests -- --nocapture` passes.
- `sudo make test.integration` passes.
- Cloud runner and Azure smoke pass with TLS deny-path checks enabled by default.
