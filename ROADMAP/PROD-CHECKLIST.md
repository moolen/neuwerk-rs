# Production Checklist

Last updated: 2026-03-10
Owner: firewall team
Scope: isolated structured-logging hardening slice for upstream review

This branch intentionally carries only the structured-logging completion work from a broader local production-readiness effort. The checklist below is limited to the changes that are actually present in this branch so the roadmap stays accurate when reviewed and merged independently.

## Release Hardening
- [x] Add structured logging with log-level controls and redaction guidance.
  Current progress: the runtime now initializes `tracing` with `NEUWERK_LOG_LEVEL` / `NEUWERK_LOG_FORMAT` (`plain` or `json`), operator redaction guidance lives in `docs/operations/logging.md`, and operational control-plane/runtime logging is structured across startup, HTTP API, DNS, DHCP, policy replication, trafficd/TLS intercept, cloud integration management, Kubernetes resolution, audit/wiretap bridges, dataplane bootstrap/warmup, and DPDK adapter/runtime orchestration. Remaining `println!/eprintln!` call sites are intentional user-facing CLI/auth output and test-harness progress output.

## Progress Log
- [x] 2026-03-09: Added `tracing`-based logging initialization with level/format env controls plus initial structured startup/HTTP lifecycle logs and redaction guidance.
- [x] 2026-03-10: Finished migrating operational control-plane/runtime logging to structured `tracing` across DNS, DHCP, policy replication, trafficd/TLS intercept, integration management, Kubernetes resolution, audit/wiretap emitters, dataplane warmup, and DPDK runtime orchestration.
- [x] 2026-03-10: Finished migrating low-level dataplane/DPDK adapter diagnostics to structured `tracing`; the only remaining raw stdout/stderr sites are intentional CLI/auth and test-harness progress output.
