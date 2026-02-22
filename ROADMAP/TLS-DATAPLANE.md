# TLS Dataplane Validation Roadmap

Date: 2026-02-21

## Goals
- Validate TLS ClientHello SNI and server certificate attributes in the dataplane without proxying or terminating TLS.
- Apply validation only when a policy rule includes TLS constraints.
- Fail-closed for TLS-constrained flows while still allowing handshake traffic needed for inspection.
- Support SHA-256 certificate fingerprint matching.
- Support full chain validation using system trust store plus policy-embedded anchors.
- Keep dataplane minimal, deterministic, and testable without NIC hardware.

## Non-Goals
- TLS decryption or MITM proxying.
- DPI or HTTP parsing.
- TLS 1.3 certificate inspection (not possible without decryption).
- Certificate time validity checks.

## Resolved Decisions
- Packet-by-packet dataplane with TCP reassembly for TLS handshake parsing.
- TLS 1.3 certs are uninspectable; behavior must be configurable per rule (drop or allow).
- Policy-driven per flow. No global TLS enforcement.
- SAN/CN matching supports both exact and regex.
- Leaf certificate fingerprint matching only (SHA-256).

## Policy Model Changes
- Extend `tls` matcher to express SNI, SAN, CN, and fingerprint constraints plus trust anchors and TLS 1.3 behavior.
- Proposed schema (YAML/JSON):
```
tls:
  sni:
    exact: ["api.example.com"]
    regex: ".*\\.example\\.com$"
  server_san:
    exact: ["api.example.com"]
    regex: ".*\\.example\\.com$"
  server_cn:
    exact: ["api.example.com"]
    regex: ".*\\.example\\.com$"
  fingerprint_sha256:
    - "ab12...hex..."
  trust_anchors_pem:
    - "-----BEGIN CERTIFICATE-----..."
  tls13_uninspectable: deny|allow
```
- Matching semantics:
  - If a field is present, it must match.
  - `exact` and `regex` are ANDed when both are present.
  - `trust_anchors_pem` adds to the system trust store.
  - `tls13_uninspectable` is applied only when cert validation is required and TLS 1.3 is detected.

## Dataplane State Changes
- Extend flow state to include TLS inspection state.
- Introduce `TlsFlowState` keyed by `FlowKey` with:
  - `pending_rule`: TLS match criteria + intended action.
  - `client_reassembly` and `server_reassembly`.
  - `sni` extracted from ClientHello.
  - `server_hello_version` (TLS 1.2 or TLS 1.3).
  - `cert_chain` (DER bytes) when visible.
  - `validation_result`: Pending | Allowed | Denied.
- Ensure flow decisions are checked even when the flow already exists, so pending TLS flows remain gated.

## TCP Reassembly Plan
- Implement bounded, in-order reassembly with limited out-of-order buffering.
- Track per-direction `expected_seq` and a small segment map for gaps.
- Enforce limits:
  - `max_tls_reassembly_bytes` (e.g. 64 KiB).
  - `max_tls_segments` (e.g. 32).
- If limits are exceeded or persistent gaps exist, mark TLS validation as failed and drop (fail-closed).
- Ignore IP fragments for TLS parsing. Fragmented packets still get NATed, but TLS inspection marks flow failed if required data cannot be reassembled.

## TLS Parsing Plan
- Parse TCP payload into TLS records (content type, version, length).
- Parse handshake messages inside records.
- ClientHello:
  - Extract SNI from `server_name` extension.
  - Record as normalized lowercase without trailing dot.
- ServerHello:
  - Detect TLS 1.3 by `supported_versions` extension (0x002b, version 0x0304).
- Certificate (TLS 1.2 only):
  - Extract DER chain from `Certificate` handshake message.
  - Parse leaf cert SAN/CN and compute SHA-256 fingerprint.
- Minimal parser only; ignore non-handshake records while TLS is pending.

## Certificate Validation Plan
- Build trust store:
  - System trust anchors.
  - Policy-embedded PEM anchors.
- Verify chain (leaf to root) without time checks:
  - Check issuer/subject linkage.
  - Verify signatures for each cert in chain.
  - Enforce CA constraints for intermediates when present.
- Validate leaf SAN/CN and SHA-256 fingerprint as required by rule.
- Only leaf fingerprint is matched.

## TLS 1.3 Handling
- If TLS 1.3 is detected and cert constraints are required:
  - Apply `tls13_uninspectable` (allow or deny).
- If only SNI constraints exist, evaluate SNI and allow/deny accordingly.

## Dataplane Policy Evaluation Changes
- Replace `PolicySnapshot::evaluate(&PacketMeta)` with a flow-aware evaluation that returns:
  - `Allow`
  - `Deny`
  - `PendingTls { rule_id, tls_match, action }`
- For `PendingTls`:
  - Allow only TLS handshake records until validation passes or fails.
  - Drop application data records until validation succeeds.
  - Once validated, apply the rule’s action for the rest of the flow.

## Integration Points
- `src/dataplane/packet.rs`
  - Add TCP parsing helpers (seq number, flags, payload slice).
- `src/dataplane/flow.rs`
  - Extend `FlowEntry` to carry TLS state.
- `src/dataplane/engine.rs`
  - Gate flow forwarding by TLS decision state.
  - Feed payloads into TLS reassembly and parser.
- `src/dataplane/policy.rs`
  - Extend `TlsMatch` to compiled matchers.
  - Implement match against parsed TLS observations.
- `src/controlplane/policy_config.rs`
  - Parse TLS matcher configuration and compile regexes.

## Testing Plan
- `tests/packet_unit.rs`
  - TLS record parsing, ClientHello SNI extraction, ServerHello TLS 1.3 detection.
  - Certificate chain parsing from TLS 1.2 `Certificate` message.
  - Reassembly edge cases (out-of-order, gaps, truncation).
- `tests/integration_nat.rs`
  - TLS 1.2 allowlist based on SNI + SAN + fingerprint.
  - TLS 1.2 deny on SAN/CN mismatch.
  - TLS 1.3 with `tls13_uninspectable=deny` drops after ServerHello.
  - TLS 1.3 with `tls13_uninspectable=allow` passes when only SNI is required.

## Implementation Order
1. Extend policy config + compiled TLS matcher types.
2. Add TCP parsing helpers and payload extraction.
3. Implement TLS reassembly and parsing utilities.
4. Extend flow state to track TLS inspection.
5. Update policy evaluation to return `PendingTls`.
6. Integrate TLS gating in dataplane engine.
7. Add cert chain verification and matching.
8. Add unit tests and integration tests.

## Risks and Mitigations
- Out-of-order TCP can cause false negatives.
  - Mitigation: bounded reassembly buffer and clear limits.
- TLS 1.3 cert inspection is not possible.
  - Mitigation: explicit per-rule `tls13_uninspectable` policy.
- Chain verification without time checks is complex.
  - Mitigation: keep implementation small and well-tested with unit vectors.
