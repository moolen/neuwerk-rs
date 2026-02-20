# Firewall Repository Guidance

## Architectural Philosophy
- Strict separation of dataplane and control plane.
- Dataplane contains only packet processing and stateful NAT logic.
- Control plane handles DNS proxying, cluster replication, and future management APIs.
- No DNS parsing or control-plane logic inside the dataplane.

## NIC Model
- `data0` is DPDK-bound (VFIO) and owned by the dataplane.
- `mgmt0` is kernel-owned and used exclusively by the control plane.
- Dataplane must never process management traffic.
- Control plane must never process forwarded dataplane traffic.

## Supported Traffic Flows
- DNS queries targeted at the firewall itself
- Firewall-originated upstream DNS traffic
- Firewall-originated cluster replication traffic
- Traffic under policy (DPDK data plane)

## Testing Model
- Packet-level unit tests in `tests/packet_unit.rs`.
- Integration tests in `tests/integration_nat.rs`.
- DPDK is isolated behind `dpdk_adapter.rs` and currently runs as a no-op dataplane.
- CI must run without NIC hardware or hugepages.

## Design Constraints
- Favor correctness and deterministic behavior over micro-optimizations.
- Keep unsafe code isolated (only in `dpdk_adapter.rs` when added).
- Avoid global mutable state; use explicit state passing.
- NAT behavior must be deterministic and symmetric.

## Future Extension Notes
- DPI may be added as a dedicated dataplane layer later.
- Any L7 proxying or DNS/L7 parsing stays in the control plane.
- Dataplane must remain minimal and testable with pure Rust unit tests.

## Self-Improving Prompt
- If you learn something important about this repository, its constraints, or workflows, add it to this `AGENTS.md` so future work benefits from it.

## Runtime CLI
- The binary requires `--management-interface`, `--data-plane-interface`, `--dns-upstream`, and `--dns-listen` flags to start.
- The software dataplane uses `--data-plane-mode tun|tap` (default `tun`) and attaches to a Linux TUN/TAP device.
- NAT/flow idle eviction is controlled by `--idle-timeout-secs` (default 300, must be >= 1).
- Default policy is controlled by `--default-policy allow|deny` (default `deny`).
- Policy YAML can be loaded at startup via `--policy-config <path>`.

## Integration Tests
- `make test.integration` runs the Rust e2e harness which builds Linux netns/veth topology via netlink; it must be run as root.
