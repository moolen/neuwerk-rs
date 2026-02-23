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
- Cloud integrations must identify NICs via tags: `neuwerk.io/management` and `neuwerk.io/dataplane` on the cloud NIC resources.

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

## Cloud Dataplane Assumptions
- DPDK dataplane is the target deployment mode for AWS/GCP/Azure.
- Dataplane IPv4 config (IP/prefix/gateway) is obtained via DHCP on the dataplane NIC; DHCP is mandatory.
- All policy source groups are treated as internal networks; the DHCP-derived prefix is the default internal group.
- Dataplane answers ARP only for its dataplane IPv4 address (no public IP ARP).
- IPv4 fragments are dropped with metrics only (no logging).
- TTL is decremented on forwarded packets; ICMP Time Exceeded is generated when TTL expires.
- ICMP is fully supported in dataplane and policy-controlled (type/code allow/deny). Default policy allows common ICMP types.
- DNS allowlist enforcement is per source group (DNS policy decides which internal groups can access which hostnames).

## Future Extension Notes
- DPI may be added as a dedicated dataplane layer later.
- Any HTTPS proxying or DNS/HTTP parsing stays in the control plane.
- TLS verification should be done in the dataplane, allowing verification of the TLS client hello and server hello packets. We'll extend the policy engine to validate SNI, certificate hostnames or fingerprints.
- Dataplane must remain minimal and testable with pure Rust unit tests.
- Dataplane TLS validation is policy-driven per flow, uses TCP reassembly, and is fail-closed for TLS-constrained rules.
- TLS 1.3 certificates are uninspectable; policy must configure allow/deny behavior for those flows.
- Trust anchors for TLS validation come from the system store plus policy-embedded anchors; skip certificate time validity checks.

## Self-Improving Prompt
- If you learn something important about this repository, its constraints, or workflows, add it to this `AGENTS.md` so future work benefits from it.
### UI Notes
- The React UI lives under `ui/` and is served by the control-plane HTTPS server from `ui/dist`.
- Control-plane HTTP API routes are rooted at `/api/v1` (UI calls `/api/v1/*`).

## Control-Plane Storage Notes
- Local (non-cluster) policies live in `/var/lib/neuwerk/local-policy-store`.
- Local (non-cluster) service accounts and token metadata live in `/var/lib/neuwerk/service-accounts`.
- Local (non-cluster) API auth keyset lives in `/var/lib/neuwerk/http-tls/api-auth.json`.
- Cluster mode stores policies, service accounts, API auth keyset, and CA material in the Raft-backed RocksDB store under `/var/lib/neuwerk/cluster/raft`.
- HTTP TLS CA cert and private key should be persisted in local mode (proposed `http-tls/ca.key` alongside `ca.crt`).
- Policy rebuilds clear the DNS allowlist so deny updates take effect immediately.
- Policy rebuilds bump a generation counter so the dataplane re-evaluates existing flows on their next packet (soft-cut enforcement).
- Control-plane tracks the active policy ID to avoid redundant rebuilds during cluster replication.

## Runtime CLI
- The binary requires `--management-interface`, `--data-plane-interface`, `--dns-upstream`, and `--dns-listen` flags to start.
- The software dataplane uses `--data-plane-mode tun|tap` (default `tun`) and attaches to a Linux TUN/TAP device. `dpdk` is accepted for DPDK mode; real DPDK IO requires the `dpdk` cargo feature and a system DPDK install.
- NAT/flow idle eviction is controlled by `--idle-timeout-secs` (default 300, must be >= 1).
- DNS allowlist GC is controlled by `--dns-allowlist-idle-secs` (default `idle-timeout + 120`, must be >= 1).
- DNS allowlist GC interval is controlled by `--dns-allowlist-gc-interval-secs` (default 30, must be >= 1).
- Default policy is controlled by `--default-policy allow|deny` (default `deny`).
- DHCP tuning flags: `--dhcp-timeout-secs` (default 5), `--dhcp-retry-max` (default 5), `--dhcp-lease-min-secs` (default 60), all must be >= 1.
- `--snat-ip <ipv4>` overrides the SNAT address in software dataplane mode only (tests use this to keep the SNAT IP off kernel interfaces); DPDK mode relies on DHCP.
- `--management-interface` and `--data-plane-interface` must not be the same interface.
- In DPDK mode, the process exits if DHCP fails to obtain a lease.
- Policy management is via HTTPS API on `--http-bind` (default management IP `:8443`) using `POST /v1/policies` and `GET /v1/policies`; `/health` is available for readiness checks.
- Service account tokens are managed via HTTP API: `POST /v1/service-accounts`, `GET /v1/service-accounts`, `DELETE /v1/service-accounts/{id}`, `POST /v1/service-accounts/{id}/tokens`, `GET /v1/service-accounts/{id}/tokens`, `DELETE /v1/service-accounts/{id}/tokens/{token_id}`.
- Token creation defaults to 90d TTL or `eternal: true`; token strings are returned only on create.
- Prometheus metrics are served over HTTP on `--metrics-bind` (default management IP `:8080`) at `/metrics`.
- API auth CLI: `firewall auth key rotate|list|retire <kid>` and `firewall auth token mint --sub <id> [--ttl <dur>] [--kid <kid>]` require `--cluster-addr <ip:port>` and mTLS material in `--cluster-tls-dir` (default `/var/lib/neuwerk/cluster/tls`).
- DNS hostname access control is configured via policy YAML rule matches using `dns_hostname` (regex); unmatched DNS queries return NXDOMAIN.
- Policy YAML rules can match ICMP with `icmp_types` and `icmp_codes` lists. For `proto: icmp` rules with no ICMP filters, defaults apply: types `[0, 3, 11]` and codes `[0, 4]` (echo-reply, dest-unreachable, time-exceeded, frag-needed).
- Cluster joiners must use `--join <seed-endpoint>` and a per-node PSK for unattended bootstrap.
- The initial seed generates the cluster CA; CA key material is stored in the embedded replicated store so any control-plane leader can sign node certs.
- Each node generates a UUID once and stores it at `/var/lib/neuwerk/node_id`.
- Any node can act as the initial seed if started without `--join`; control-plane RPC is strictly internal (external API is separate transport).
- Future deployments will use cloud APIs (ASG/instance tags + age) for peer discovery; local e2e tests use static IPs.
- The bootstrap PSK lives at `/var/lib/neuwerk/bootstrap-token` and should support rotation.
- The bootstrap token file uses a JSON format; join uses a single seed endpoint.
- Cluster RPC binds with `--cluster-bind <ip:port>` and advertises via `--cluster-advertise <ip:port>` (default: bind).
- Join RPC binds with `--cluster-join-bind <ip:port>` (default: `cluster-bind` + 1).
- Cluster storage defaults to `/var/lib/neuwerk/cluster` and can be overridden via `--cluster-data-dir`.
- Node identity path defaults to `/var/lib/neuwerk/node_id` and can be overridden via `--node-id-path`.
- Bootstrap token path defaults to `/var/lib/neuwerk/bootstrap-token` and can be overridden via `--bootstrap-token-path`.
- Raft control-plane RPC uses mTLS; join RPC stays plaintext on the join bind address.
- The UI is embedded from `ui/dist` at build time. Rebuild the UI bundle before building the Rust binary when UI assets change.

## Integration Tests
- `make test.integration` runs the Rust e2e harness which builds Linux netns/veth topology via netlink; it must be run as root.
- Running integration tests as root can leave `target/` root-owned; if builds fail with permission errors, `sudo chown -R $USER target` or remove `target/`.
- Every feature that changes control-plane or data-plane behavior must be covered by an integration test.
- The e2e harness now includes control-plane cluster checks (mTLS enforcement and leader failover join) inside the firewall netns.
- Favor e2e coverage over unit tests to preserve freedom to replace internal implementations; unit tests are still valuable for correctness.
