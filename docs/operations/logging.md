# Logging

## Controls

- `NEUWERK_LOG_LEVEL`
  - Primary log filter for the firewall process.
  - Defaults to `info`.
- `RUST_LOG`
  - Used only when `NEUWERK_LOG_LEVEL` is unset.
- `NEUWERK_LOG_FORMAT`
  - `plain` for compact human-readable logs.
  - `json` for structured machine-ingestible logs.
  - Defaults to `plain`.

## Current Coverage

Structured logging is now wired for operational runtime paths across process startup, listener binding, HTTP API lifecycle, cluster migration progress, control-plane background tasks, and dataplane/DPDK orchestration. Remaining raw stdout/stderr output is limited to intentional CLI/auth output and test harness progress messages.

## Redaction Guidance

Never log these values in plaintext:

- bearer tokens
- bootstrap tokens
- service account tokens
- OIDC client secrets
- cookies or session identifiers
- private keys or sealed-envelope plaintext

Use `firewall::logging::redact_secret(...)` when a log line must indicate presence of a secret without exposing it.
