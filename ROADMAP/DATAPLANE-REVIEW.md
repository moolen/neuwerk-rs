# Dataplane Review Implementation Plan

**Goals**
- Run the dataplane on DPDK in AWS/GCP/Azure with same-NIC L2 hairpin forwarding.
- Obtain dataplane IPv4 config via DHCP on the dataplane NIC (mandatory).
- Use policy-defined source groups as internal networks, with the DHCP prefix as the default internal group.
- Implement ARP responder for the dataplane IPv4 address.
- Implement full ICMP support with policy-controlled type/code, and default allow of common ICMP types.
- Decrement TTL on forwarded packets and generate ICMP Time Exceeded when TTL expires.
- Drop IPv4 fragments with metrics only (no logging).
- Keep dataplane minimal and deterministic; keep control-plane logic out of dataplane.

**Non-Goals**
- IPv6 support.
- VLAN tags or multi-MAC/ENI-style dataplane.
- Fragment reassembly.
- Logging of fragment drops.
- DHCP optional mode or manual static config as a requirement.

**Assumptions**
- One DPDK-bound dataplane interface and one kernel-owned management interface.
- The internet gateway performs public NAT; the firewall SNATs to its own dataplane IPv4 address.
- All policy source groups are internal networks.
- DNS allowlist enforcement is per source group.

**Design Outline**
- Introduce a DHCP-driven dataplane config state shared with the dataplane engine (data IP, prefix, gateway, MAC, lease times).
- Treat internal CIDRs as the union of all policy source groups plus the DHCP-derived prefix.
- Build a DPDK RX/TX pipeline that handles ARP at L2, DHCP frames via a control-plane channel, and IPv4 for NAT/policy.
- Extend policy matching to include ICMP type/code.

**Status**
- Step 1 complete: added `DataplaneConfig`/`DataplaneConfigStore`, shared handle wiring, `PolicyStore::update_internal_cidr`, `PolicySnapshot::is_internal`, and unit tests.
- Step 2 complete: added DHCPv4 client state machine, DHCP frame channel types (DPDK wiring in Step 3), lease application into dataplane config + policy store, CLI tuning flags, and unit tests for DHCP parsing.
- Step 3 complete: added DPDK adapter frame processing helpers (Ethernet/ARP/IPv4/UDP), DHCP channel bridging helpers, ARP responder for dataplane IP, DHCP frame builder, and unit tests. Added an optional `dpdk` feature with a `dpdk-sys` backend; default builds still use `UnwiredDpdkIo`.
- Follow-up: DPDK port selection now maps PCI device names to port IDs when possible; metrics added for DPDK init and DHCP lease state.
- Step 4 complete: IPv4 fragment drops with metrics, TTL decrement, ICMP Time Exceeded generation, and packet-level unit tests for fragment/TTL handling.
- Step 5 complete: ICMP policy filters (type/code), default ICMP allowlist, ICMP echo NAT using identifier, ICMP error reverse-NAT based on embedded headers, and unit tests for ICMP flows.
- Step 6 complete: SNAT/reverse-NAT now prefer DHCP-derived dataplane IP, internal detection uses DHCP prefix plus policy source groups, NAT port exhaustion returns an explicit error, and integration coverage updated to validate DHCP SNAT IP.
- Follow-up: soft-mode e2e uses `--snat` to keep the SNAT address off kernel interfaces, ensuring inbound traffic is routed through the tun dataplane.
- Step 7 complete: added dataplane metrics for ARP handled, ICMP decisions (type/code), DHCP lease changes, and tests covering the new counters.
- Step 8 complete: test coverage added for ARP metric and ICMP decision counters; existing fragment/TTL/ICMP/NAT unit tests cover the remaining dataplane behaviors.
- Step 9 complete: documentation updated for DHCP-driven dataplane config and observability, plus safety checks to ensure management and dataplane interfaces are distinct.
- Follow-up complete: added an e2e harness case that simulates DHCP, ARP responder, and same-NIC hairpin via the DPDK L2 pipeline in-process (no netns required).

**Work Plan**
1. Dataplane configuration state: add a `DataplaneConfig` structure with `ip`, `prefix`, `gateway`, `mac`, `lease_expiry`; expose a thread-safe handle to the dataplane engine and policy store; update `PolicyStore` to rebuild the base group when DHCP lease changes; add `PolicySnapshot::is_internal(ip)` that checks if an IP belongs to any source group.
2. DHCPv4 client (control plane): implement a DHCPv4 client state machine (DISCOVER, OFFER, REQUEST, ACK, RENEW); send/receive DHCP frames over DPDK via a bounded channel; update `DataplaneConfig` on lease changes and trigger policy rebuild; add optional CLI tuning flags `--dhcp-timeout-secs`, `--dhcp-retry-max`, `--dhcp-lease-min-secs`.
3. DPDK adapter RX/TX pipeline: parse Ethernet frames and dispatch by EtherType; handle ARP in dataplane by replying to ARP requests for the dataplane IPv4 address only; forward DHCP UDP frames (src/dst 67/68) to the control-plane DHCP channel; pass IPv4 frames to the engine and transmit them out the same port.
4. IPv4 handling updates: detect and drop IPv4 fragments with metrics; decrement TTL on forwarded packets and generate ICMP Time Exceeded when TTL expires; ensure IPv4 header and transport checksums are updated.
5. ICMP support and policy: extend policy schema to allow `icmp_types` and `icmp_codes` filters; implement ICMP echo handling using ICMP identifier as NAT port analog; implement ICMP error handling by parsing embedded IP headers and reverse-NATing mapped flows; default allowlist `echo-reply`, `dest-unreachable`, `time-exceeded`, `frag-needed`.
6. NAT and direction logic: replace `public_ip` with DHCP-derived dataplane IPv4 for SNAT and reverse NAT; determine outbound flows using `is_internal(src_ip)` and `!is_internal(dst_ip)`; maintain deterministic NAT port allocation and return an explicit error when ports are exhausted.
7. Metrics: add counters for ARP handled, DHCP lease changes, IPv4 fragments dropped, TTL exceeded, ICMP allow/deny per type/code; extend existing dataplane metrics with ICMP protocol labels.
8. Tests: add packet-level unit tests for fragment detection, TTL decrement, ICMP Time Exceeded, ICMP NAT (echo and error reverse-NAT), and `is_internal` with DHCP prefix plus multiple source groups; add ARP reply construction tests.
9. Docs and safety checks: update `README.md` and CLI usage for DHCP-driven dataplane config; add startup failure behavior when DHCP fails; ensure management and dataplane interfaces cannot be the same.

**Open Risks**
- DHCP client implementation complexity and correctness on DPDK.
- ICMP error NAT parsing can be error-prone and requires strong tests.

**Deliverables**
- Working DPDK dataplane with DHCP-based IPv4 config, ARP responder, and hairpin NAT.
- Policy-controlled ICMP and TTL handling.
- Fragment drop behavior with metrics.
- Test coverage for new dataplane logic.
