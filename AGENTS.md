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
  - Azure tags cannot contain `/`, so the Azure e2e stack uses `neuwerk.io.management` and `neuwerk.io.dataplane`; the control-plane accepts both spellings.

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

## Build Notes
- DPDK builds use a pinned, vendored DPDK source build (`third_party/dpdk/VERSION`) via `scripts/build-dpdk.sh` and `make build.dpdk` (installs into `third_party/dpdk/install/<version>`).
- `DPDK_DIR` can point to a custom DPDK install prefix; `third_party/dpdk-sys` compiles a small wrapper C shim against those headers/libs.
- When building in a container, set `DPDK_DIR` to an absolute path (relative paths resolve from the dpdk-sys crate and will miss headers), and ensure `protobuf-compiler`, `libclang-14-dev`, and `llvm-14-dev` are installed so build scripts can run.
- DPDK build dependencies include `meson`, `ninja`, `python3`, `pkg-config`, `libnuma` headers, and Python `pyelftools`.
- Default vendored build disables `net/ionic` via `DPDK_DISABLE_DRIVERS` to avoid GCC 15 type conflicts; override as needed.
- Set `DPDK_FORCE_REBUILD=1` to rebuild an existing vendored DPDK install.
- Vendored DPDK patches live in `third_party/dpdk/patches` and are applied during `scripts/build-dpdk.sh`.
- Azure e2e images are Ubuntu 24.04 (glibc 2.39). Binaries built on newer glibc will fail to run; build the firewall binary inside a 24.04 (or older) environment or ship compatible runtime libs.
- Vendored DPDK 23.11.2 installs ABI `.so.24` (e.g., `librte_eal.so.24`). If you link against a different system DPDK (e.g., `.so.26`), you must install matching DPDK libs on the VM or the firewall binary will not start.
- Azure Germany West Central now offers Ubuntu 24.04 via `publisher=Canonical`, `offer=ubuntu-24_04-lts`, `sku=server` for the e2e stack.
- Azure MANA DPDK uses devargs `mac=` to select the NIC; kernel MANA drivers remain bound (no vfio binding). The dataplane can accept `--data-plane-interface mac:aa:bb:cc:dd:ee:ff` and map the DPDK port by MAC.
- Azure DPDK on NetVSC may miss ARP replies for the gateway in multiqueue mode; when `NEUWERK_CLOUD_PROVIDER=azure` the dataplane now falls back to `NEUWERK_AZURE_GATEWAY_MAC` (default `12:34:56:78:9a:bc`) to seed the gateway ARP entry.

## Design Constraints
- Favor correctness and deterministic behavior over micro-optimizations.
- Keep unsafe code isolated (only in `dpdk_adapter.rs` when added).
- Avoid global mutable state; use explicit state passing.
- NAT behavior must be deterministic and symmetric.

## Cloud Dataplane Assumptions
- DPDK dataplane is the target deployment mode for AWS/GCP/Azure.
- Dataplane IPv4 config (IP/prefix/gateway) is obtained via DHCP on the dataplane NIC; DHCP is mandatory.
- All policy source groups are treated as internal networks; the DHCP-derived prefix is the default internal group.
- VXLAN GWLB deployments with internal/external tunnels swap the tunnel/VNI on replies (internal -> external, external -> internal) when both tunnel configs are present.
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
- TLS intercept CA local files are `http-tls/intercept-ca.crt` and `http-tls/intercept-ca.key`; cluster migration seeds them into Raft keys `settings/tls_intercept/ca_cert_pem` and `settings/tls_intercept/ca_key_envelope` when present.
- Policy rebuilds clear the DNS allowlist so deny updates take effect immediately.
- Policy rebuilds bump a generation counter so the dataplane re-evaluates existing flows on their next packet (soft-cut enforcement).
- Control-plane tracks the active policy ID to avoid redundant rebuilds during cluster replication.
- The built-in `internal` DNS allowlist source group is intentionally lowest-priority; explicit source groups (including TLS intercept rules) must evaluate first to prevent DNS allowlist bypass of higher-layer policy.

## Runtime CLI
- The binary requires `--management-interface`, `--data-plane-interface`, at least one `--dns-target-ip` (or `--dns-target-ips` CSV), and at least one `--dns-upstream` (or `--dns-upstreams` CSV) to start. CSV and repeated forms are mutually exclusive per setting.
- The software dataplane uses `--data-plane-mode tun|tap` (default `tun`) and attaches to a Linux TUN/TAP device. `dpdk` is accepted for DPDK mode; real DPDK IO requires the `dpdk` cargo feature and a system DPDK install.
- NAT/flow idle eviction is controlled by `--idle-timeout-secs` (default 300, must be >= 1).
- DNS allowlist GC is controlled by `--dns-allowlist-idle-secs` (default `idle-timeout + 120`, must be >= 1).
- DNS allowlist GC interval is controlled by `--dns-allowlist-gc-interval-secs` (default 30, must be >= 1).
- Default policy is controlled by `--default-policy allow|deny` (default `deny`).
- DHCP tuning flags: `--dhcp-timeout-secs` (default 5), `--dhcp-retry-max` (default 5), `--dhcp-lease-min-secs` (default 60), all must be >= 1.
- Internal network override: `--internal-cidr <cidr>` sets the default internal group and disables DHCP-based internal CIDR updates when set.
- `--snat none|auto|<ipv4>` controls SNAT (software only for `<ipv4>`); DPDK mode relies on DHCP.
- Overlay flags: `--encap none|vxlan|geneve`, `--encap-vni <id>`, `--encap-udp-port <port>`, `--encap-vni-internal`, `--encap-vni-external`, `--encap-udp-port-internal`, `--encap-udp-port-external`, `--encap-mtu <bytes>`.
- Azure GWLB VXLAN defaults: UDP `10800` (internal tunnel) and UDP `10801` (external tunnel).
- `--management-interface` and `--data-plane-interface` must not be the same interface.
- In DPDK mode, the process exits if DHCP fails to obtain a lease.
- Policy management is via HTTPS API on `--http-bind` (default management IP `:8443`) using `POST /api/v1/policies` and `GET /api/v1/policies`; `/ready` is available for readiness checks.
- `POST`/`PUT`/`DELETE /api/v1/policies` block until the dataplane observes the new policy generation when the dataplane is running (2s timeout; returns `503` on activation timeout). When no dataplane is running (e.g., control-plane-only cluster tests), they return immediately.
- Service-lane runtime ensures `svc0` (TAP) exists with `169.254.255.1/30`. In DPDK mode, TLS intercept steering uses dataplane packet demux: intercept-eligible client flows are rewritten to `169.254.255.1:15443` on `svc0` and mapped by `(client_ip,client_port)` so service-lane egress packets can be rewritten back to the original upstream tuple before DPDK TX.
- In DPDK mode, the adapter now drains egress packets from `svc0` and emits them on DPDK TX after standard L2 rewrite/ARP resolution; service-lane return-path packets can trigger ARP requests when neighbor MAC is not cached.
- DPDK intercept steering foundation: when `svc0` TAP is attachable, the dataplane can emit `Action::ToHost` for intercept-eligible flows and the DPDK adapter writes those frames to `svc0` (env override: `NEUWERK_DPDK_SERVICE_LANE_IFACE`, default `svc0`).
- TLS intercept runtime now mints per-host leaf certificates from SNI using the configured intercept CA and caches minted certs in-memory (15m TTL, 1024-entry bound).
- TLS intercept CA `PUT`/`DELETE` now bumps a CA-generation signal; `trafficd` restarts the live intercept runtime when that generation changes so new leaf certs are minted from the updated CA without process restart.
- Startup now waits for DNS/service-plane runtime initialization before marking readiness (`dns`/`service_plane`), with a 2s startup timeout; DNS bind/config failures fail process startup early.
- Service account tokens are managed via HTTP API: `POST /v1/service-accounts`, `GET /v1/service-accounts`, `DELETE /v1/service-accounts/{id}`, `POST /v1/service-accounts/{id}/tokens`, `GET /v1/service-accounts/{id}/tokens`, `DELETE /v1/service-accounts/{id}/tokens/{token_id}`.
- Token creation defaults to 90d TTL or `eternal: true`; token strings are returned only on create.
- Prometheus metrics are served over HTTP on `--metrics-bind` (default management IP `:8080`) at `/metrics`.
- `NEUWERK_DPDK_STATE_SHARDS=<n>` overrides the number of dataplane state shards (defaults to worker count); sharding reduces lock contention in multi-worker DPDK mode.
- When DPDK has only one effective RX queue, runtime can still use multiple workers via shared-RX software flow demux (single DPDK RX queue with flow-affine worker dispatch); HTTPS/TLS flows on TCP/443 are pinned to worker `0` so service-lane intercept steering remains deterministic.
- In multi-worker DPDK mode, only worker `0` should drain service-lane egress frames; draining from every worker can create cross-shard lock contention and inflate `dp_state_lock_*` metrics.
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
- The e2e harness now runs overlay VXLAN and GENEVE suites after baseline tests using `overlay_vxlan_*` and `overlay_geneve_*` fields in `TopologyConfig`.
- TLS intercept fail-closed e2e can manifest as TCP reset/broken pipe or immediate connect refusal (`ECONNREFUSED`); treat both as valid fail-closed outcomes.
- E2E includes `tls_intercept_h2_concurrency_smoke` to stress HTTP/2 intercept allow-path behavior under concurrent load.
- E2E includes `tls_intercept_ca_rotation_reloads_runtime` to verify CA rotation updates served intercept leaf certificates while preserving allow/deny policy behavior.
- The root-required e2e harness launches the firewall with `--data-plane-mode tun`; DPDK service-lane regressions are covered by in-process DPDK e2e cases like `dpdk_tls_intercept_service_lane_round_trip`.

## Completed (Test Gaps)
- TTL decrement test asserts forwarded UDP TTL is reduced by exactly 1.
- ICMP policy coverage includes deny cases and type/code filtering.
- Fragment-forwarding negative test ensures fragments are not forwarded.
- NAT determinism coverage adds port allocation stability under load.
- Overlay negative tests cover wrong VNI/UDP port/MTU drop.

## Cloud Tests
- Azure e2e test bench lives under `cloud-tests/azure` (Terraform + scripts); SSH keys are generated under `cloud-tests/.secrets` and are gitignored.
- Azure GWLB service chaining requires a Standard **public** LB frontend (or VM public IP). Internal LBs cannot be chained, and a NIC associated to GWLB must keep a Standard public IP attached. For private-only dataplane tests, use UDR + internal LB instead of GWLB.
- For the internal LB + UDR Azure e2e topology, set `firewall_snat_mode=none` so the upstream sees the original consumer IP; SNAT can break multi-connection protocols like `iperf3` when flows land on different firewall nodes.
- Azure internal LB + UDR e2e defaults `firewall_snat_mode=none` so return traffic stays symmetric; SNAT can break consumer->upstream VIP flows.
- `cloud-tests/azure/scripts/run-tests.sh` throughput smoke test uses a 4 MiB payload and `socat -T 5` to avoid hanging on close; increase size/timeouts if you want larger throughput checks.
- DPDK dataplane exports `dpdk_rx_*`/`dpdk_tx_*` counters for throughput debugging in `/metrics`.
- DPDK multi-worker sharding exports `dp_state_lock_wait_seconds`/`dp_state_lock_contended_total` plus per-queue counters to validate RSS distribution.
- On some Azure MANA/netvsc setups, DPDK reports `flow_type_rss_offloads=0` (no usable RSS); runtime now auto-falls back to a single queue/worker even when `NEUWERK_DPDK_WORKERS>1` to avoid multi-worker throughput regressions.
- In local (non-cluster) Azure e2e mode, API auth keysets are node-local (`/var/lib/neuwerk/http-tls/api-auth.json`), so a single token via the mgmt LB may fail on some nodes; cloud policy-smoke orchestration must mint per-node tokens and push/test policy against each firewall mgmt IP.
- Azure policy-smoke UDP allow tests require an upstream ILB rule for UDP/5201; without it, allow-case validation fails even when dataplane policy is correct.
- Azure load balancers do not forward ICMP, so policy-smoke ICMP tests must target `upstream_private_ip` (routed via UDR through the firewall), not the upstream ILB VIP.
- The common smoke test `tls_intercept_http_path_enforcement` requires a firewall image that serves `GET/PUT/DELETE /api/v1/settings/tls-intercept-ca` and preserves `tls.mode=intercept` + HTTP matchers; older images typically return UI HTML on that settings path and silently drop intercept-specific TLS fields during policy create.
