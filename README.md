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

### DPDK Build (vendored)
`make build.dpdk` builds a pinned DPDK release from source and then builds the firewall with the `dpdk` feature.

```bash
make build.dpdk
```

Notes:
- The DPDK version is pinned in `third_party/dpdk/VERSION`.
- The build installs DPDK into `third_party/dpdk/install/<version>`.
- To use a custom DPDK install, set `DPDK_DIR=/path/to/dpdk-prefix` before running `make build.dpdk`.
- To rebuild an existing install, set `DPDK_FORCE_REBUILD=1`.
- Default build disables `net/ionic` due to GCC 15 type conflicts; override via `DPDK_DISABLE_DRIVERS=...` or `DPDK_MESON_ARGS`.
- Local patches in `third_party/dpdk/patches/*.patch` are applied during the vendored build.
- Build dependencies: `meson`, `ninja`, `python3`, `pkg-config`, `libnuma` headers, and `pyelftools` (python module).

## Runtime
The binary requires the management interface, dataplane interface, DNS upstream, and DNS listen flags.

Notes:
- `--management-interface` and `--data-plane-interface` must be different.
- DPDK mode requires DHCP on the dataplane NIC and the process exits if DHCP fails.
- Software mode can override SNAT with `--snat <ipv4>` (useful for tests); production SNAT IPs are still expected to come from DHCP in DPDK mode.

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

## Local HA Lab (netns)
Spin up a 3-node control-plane cluster with a software dataplane and route your host traffic through `fw1` using Linux network namespaces.

Prereqs:
- Linux + iproute2
- iptables
- sudo

Run:

```bash
make ha.up
```

Tear down and restore host routing:

```bash
make ha.down
```

Notes:
- UI: `https://192.168.100.11:8443/` (self-signed TLS; use `-k` for curl)
- Health: `https://192.168.100.11:8443/health`
- Logs: `/tmp/neuwerk-ha/logs/`
- Default policy is `allow` for safety; override via `DEFAULT_POLICY=deny make ha.up`.
- To test DNS allowlist behavior, point your host DNS at `192.168.100.11`.

## API Auth
The HTTP API requires `Authorization: Bearer <jwt>` for `/v1/*`. `/health` and `/metrics` stay unauthenticated.

CLI (mTLS to cluster RPC):

```bash
firewall auth key rotate --cluster-addr <ip:port>
firewall auth key list --cluster-addr <ip:port>
firewall auth key retire <kid> --cluster-addr <ip:port>
firewall auth token mint --sub <id> --cluster-addr <ip:port> [--ttl 90d] [--kid <kid>]
```

## Service Accounts
Service account tokens are managed over the HTTP API and can be used for UI/API access.

Endpoints:
- `POST /v1/service-accounts` (create)
- `GET /v1/service-accounts` (list)
- `DELETE /v1/service-accounts/{id}` (disable + revoke tokens)
- `POST /v1/service-accounts/{id}/tokens` (mint token; default TTL 90d or `eternal: true`)
- `GET /v1/service-accounts/{id}/tokens` (list token metadata)
- `DELETE /v1/service-accounts/{id}/tokens/{token_id}` (revoke)

## Observability
Prometheus metrics are exposed on `/metrics` (default `:8080`). See `docs/observability.md` for metric schema, label policy, and scrape examples.

## Notes
- IPv4-only MVP with symmetric NAT.
- Control plane uses Tokio for async networking.
- DNS parsing and allowlist management live in the control plane only.
- DNS allowlist entries are garbage-collected when idle and no active flows remain (`--dns-allowlist-idle-secs`, interval via `--dns-allowlist-gc-interval-secs`).
