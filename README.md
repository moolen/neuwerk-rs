# Firewall MVP (Rust)

This repository bootstraps a high-performance firewall MVP with a strict separation between dataplane (DPDK) and control plane (kernel networking). The current focus is correctness, determinism, and testability.

## Structure
- `src/dataplane/` contains packet parsing, NAT, flow tracking, and policy checks.
- `src/controlplane/` contains DNS proxy logic and cluster stubs.
- `src/dataplane/dpdk_adapter.rs` is the only place DPDK FFI may live.
- `src/dataplane/soft_adapter.rs` implements the software dataplane using a Linux TUN/TAP interface.

## Build
Default build does not require DPDK.

```bash
cd firewall
cargo build
```

The software dataplane uses `--data-plane-mode tun|tap` (default `tun`) and requires a TUN/TAP device on Linux.

## Tests
All tests run without NIC hardware or hugepages.

```bash
cd firewall
cargo test
```

Integration e2e harness (Linux root required):

```bash
sudo make test.integration
```

## Notes
- IPv4-only MVP with symmetric NAT.
- Control plane uses Tokio for async networking.
- DNS parsing and allowlist management live in the control plane only.
