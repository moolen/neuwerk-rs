# Production Checklist

Last updated: 2026-03-10
Owner: Neuwerk team
Scope: remaining production-hardening, compatibility, operational, and coverage work after feature completion

## Release Hardening
- [x] Add structured logging with log-level controls and redaction guidance.
  Current progress: the runtime now initializes `tracing` with `NEUWERK_LOG_LEVEL` / `NEUWERK_LOG_FORMAT` (`plain` or `json`), operator redaction guidance lives in `docs/operations/logging.md`, and operational control-plane/runtime logging is structured across startup, HTTP API, DNS, DHCP, policy replication, trafficd/TLS intercept, cloud integration management, Kubernetes resolution, audit/wiretap bridges, dataplane bootstrap/warmup, and DPDK adapter/runtime orchestration. Remaining `println!/eprintln!` call sites are intentional user-facing CLI/auth output and test-harness progress output.
- [x] Add backup/restore workflow documentation and operator-facing validation steps.
- [x] Add upgrade, rollback, and disaster-recovery runbooks.
- [x] Add alert thresholds and runbook mappings on top of the existing metrics/dashboard set.
- [x] Add CI lanes for `clippy -D warnings`, dependency/security checks, and scheduled nightly fuzzing.
  Current progress: PR/push full-suite CI and PR/push fuzz-smoke CI are present, a scheduled nightly fuzz workflow runs `make fuzz.nightly`, dependency/security CI runs `cargo audit` plus `npm audit --omit=dev`, and strict clippy now runs in CI via `make test.clippy` with `cargo clippy --workspace --all-targets --no-default-features --no-deps -- -D warnings`.

## State Compatibility And Persistence
- [x] Add explicit schema/version compatibility coverage for local JSON-backed stores:
  policy repository, service accounts, integrations, and SSO providers.
- [x] Add restart/persistence coverage for integrations:
  create, restart, read, update, restart, and token-envelope recovery.
- [x] Add restart/persistence coverage for service accounts and tokens:
  create, restart, list, revoke, restart, and revoked-token enforcement.
- [x] Add policy repository corruption handling coverage:
  invalid index JSON, missing indexed records, missing active file, atomic rewrite replacement.
- [x] Add local boot/restart policy recovery coverage:
  active record missing, inactive record, corrupted JSON, compile failure.
- [x] Add audit-store retention coverage:
  max-bytes eviction, persistence boundary behavior, restart reload after eviction.
- [x] Add cluster log-store invariant coverage:
  append/get_log_state, truncate, purge, and snapshot restore after purge.

## Dataplane And Bootstrap Coverage
- [x] Add dataplane bootstrap coverage for DHCP/IMDS fallback paths:
  no DHCP when config exists, MAC channel close, fallback trigger timing, IMDS failure leaves config unset.
- [x] Add DHCP renewal/failure coverage:
  renew timeout, NAK, lease change, and readiness behavior during lease flap.
- [x] Add NAT/flow resource-exhaustion coverage:
  port exhaustion, wrap-around allocation, eviction-then-reuse, reverse collision behavior, deterministic hashing.
- [x] Add DPDK MAC-interface selection coverage:
  CLI parsing, port lookup by MAC, and not-found failure path.

## Control Plane And Cluster Coverage
- [x] Add policy replication edge-case coverage:
  invalid active policy JSON, disabled active policy, compile failure, and local persistence failure.
- [x] Add readiness coverage beyond drain-only:
  cluster membership degradation and policy-replication mismatch paths.
- [x] Add TLS intercept CA cluster-path coverage:
  missing envelope/token, mismatched cert/envelope, and fail-closed readiness behavior.
- [x] Add mixed-version / rolling-upgrade compatibility coverage for cluster and local state.
  Current progress: local JSON-backed store compatibility is covered for policy/service-account/integration/SSO state, integration/SSO secret payload overlap is covered for mixed-version upgrades, cluster migration verification now accepts schema-compatible future fields for API auth + policy/service-account state, and policy replication now replays schema-compatible cluster policy records.

## Cloud And Lifecycle Coverage
- [x] Add AWS lifecycle coverage beyond XML parsing:
  IMDSv2 token failures, IAM credential decode errors, SigV4 signing correctness, lifecycle-heartbeat renewal.
  Current progress: IMDS token failure, IAM credential decode, SigV4 canonical signing output, lifecycle heartbeat/idempotent no-active-action helper paths, and provider-level autoscaling request coverage for `RecordLifecycleActionHeartbeat` and `CompleteLifecycleAction` are now covered.
- [x] Add failure-injection coverage for operational faults:
  disk/IO failures, RocksDB corruption, metrics bind failures, auth clock skew, DHCP lease flaps, and partition-like conditions.
  Current progress: local policy/service-account/integration stores now have path-collision disk/IO regression coverage, RocksDB open-read-only rejects corrupted manifest pointers, metrics bind conflicts fail startup deterministically instead of only logging from a background task, DHCP lease-flap readiness is covered, HTTP auth clock-skew boundaries are covered for both API-user and service-account bearer tokens, and partition-like conditions are covered through readiness degradation plus partial cluster audit aggregation behavior.

## Runtime Behavior
- [x] Add binary-level shutdown/drain coverage for service stop / `SIGTERM`:
  readiness false before exit, listener shutdown, restart recovery.
  Current progress: signal-triggered shutdown wiring now drives readiness false + drain and HTTP graceful shutdown; runtime/http lifecycle tests cover readiness degradation, listener close, and restart recovery on the same bind addresses, and a real binary `SIGTERM` integration test now verifies readiness flips false before exit, listeners close, ports are reusable, and persisted local policy state survives restart.

## Progress Log
- [x] 2026-03-09: Added initial production checklist and started implementing high-priority test gaps from the production-readiness review.
- [x] 2026-03-09: Added policy-repository, local-boot policy recovery, audit retention, cluster log-store, readiness, NAT, and policy-replication coverage with targeted regression tests.
- [x] 2026-03-09: Added dataplane bootstrap IMDS-failure coverage plus DPDK MAC selector CLI/port-resolution tests; remaining high-value gaps are DHCP renewal/failure, TLS intercept CA cluster paths, and restart persistence for integrations/service accounts.
- [x] 2026-03-09: Added DHCP timeout, NAK, and renewal lease-change tests; remaining DHCP work is lease-flap/readiness behavior plus broader renewal failure scenarios.
- [x] 2026-03-09: Added TLS intercept CA cluster-path tests for missing envelope/token, mismatched cert/envelope, and supervisor fail-closed behavior when cluster CA loading breaks.
- [x] 2026-03-09: Added integration restart/token-envelope recovery coverage plus service-account restart/revoke persistence and auth-layer revoked-token enforcement after local store reopen.
- [x] 2026-03-09: Added explicit schema-compatibility coverage for local JSON-backed policy, service-account, integration, and SSO stores, including legacy/plaintext records, minimal payloads, and ignored unknown fields.
- [x] 2026-03-09: Hardened DHCP lease-loss behavior to clear dataplane config and lease-expiry metrics before reacquire, with regression coverage proving readiness drops during renew-timeout lease flap.
- [x] 2026-03-09: Added mixed-version secret-payload compatibility tests for integrations and SSO providers so new readers accept legacy plaintext records and prefer sealed envelopes when both formats coexist during rolling upgrades.
- [x] 2026-03-09: Added AWS cloud-provider hardening coverage for IMDSv2 token failures, IAM credential decode errors, deterministic SigV4 signing output, and lifecycle heartbeat helper behavior/idempotent missing-action handling.
- [x] 2026-03-09: Added signal-driven shutdown plumbing for runtime drain/readiness degradation plus HTTP graceful shutdown handles, with regression coverage for listener close and restart recovery.
- [x] 2026-03-09: Hardened HTTP metrics startup to fail on bind conflicts and added occupied-port regression coverage instead of relying on background-task log-only failures.
- [x] 2026-03-09: Added HTTP auth clock-skew integration coverage for both API-user and service-account bearer tokens, proving the skew grace window is honored and out-of-window tokens are rejected with `401`.
- [x] 2026-03-09: Extended AWS lifecycle coverage with provider-level autoscaling request-path tests for heartbeat renewal and lifecycle completion against a local HTTP endpoint, exercising real signed request construction and parameter wiring.
- [x] 2026-03-09: Closed rolling-upgrade compatibility coverage by adding schema-compatible cluster-state verification for API auth, policy, service-account, and token payloads plus policy-replication coverage for future-field cluster policy records.
- [x] 2026-03-09: Added real binary shutdown coverage for `SIGTERM`, including readiness=false observation before process exit, HTTP/metrics listener teardown, same-port restart recovery, and persisted local-policy reload via `NEUWERK_LOCAL_DATA_DIR`.
- [x] 2026-03-09: Added operator runbooks under `docs/operations/` for backup/restore validation, upgrade/rollback/disaster-recovery, and alert-threshold-to-runbook mappings on top of the existing metrics/dashboard surface.
- [x] 2026-03-09: Added a scheduled nightly fuzz workflow so long-running sanitizer fuzzing is exercised automatically outside PR smoke lanes; remaining CI hardening is `clippy -D warnings` plus dependency/security gating.
- [x] 2026-03-09: Closed operational fault-injection coverage by adding disk-path collision tests for local policy/service-account/integration stores and RocksDB corruption coverage for cluster-store reopen failures; the remaining listed sub-cases were already covered by metrics-bind, auth clock-skew, DHCP lease-flap, and partition/readiness regressions.
- [x] 2026-03-09: Added `tracing`-based logging initialization with level/format env controls plus structured startup/HTTP lifecycle logs and redaction guidance; follow-on work later completed the remaining stderr/println migration.
- [x] 2026-03-10: Migrated operational cloud/control-plane/runtime logging to structured `tracing` across DNS, DHCP, policy replication, trafficd/TLS intercept, integration management, Kubernetes resolution, audit/wiretap emitters, dataplane warmup, and DPDK runtime orchestration; remaining raw output is now mostly limited to low-level DPDK adapter diagnostics and intentional CLI/test-harness output.
- [x] 2026-03-10: Finished migrating low-level dataplane/DPDK adapter diagnostics to structured `tracing`; the only remaining raw stdout/stderr sites are intentional CLI/auth and test-harness progress output, so the structured-logging production item is now complete.
- [x] 2026-03-09: Closed the CI hardening lane by paying down the remaining strict-clippy debt across runtime/dataplane/test targets and wiring `make test.clippy` plus a dedicated CI `clippy -D warnings` job.
