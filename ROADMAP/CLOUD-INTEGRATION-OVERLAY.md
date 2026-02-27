**Goal**
Add a configurable overlay dataplane so the firewall can operate in:
1. `encap none` + `snat on` for GCP-style deployments.
2. `encap vxlan` (Azure GWLB) with re-encapsulation and no SNAT by default.
3. `encap geneve` (AWS GWLB) with re-encapsulation and no SNAT by default.

Policies must always be evaluated on the **inner** L3/L4 headers. Overlay headers are transport only.

**Key Facts**
1. AWS GWLB uses **GENEVE over UDP/6081**.
2. AWS GWLB embeds **metadata (including a flow cookie)** in GENEVE TLVs; appliances must preserve these TLVs on return traffic.
3. Azure GWLB chains traffic using **VXLAN tunnels** between GWLB and the backend appliances.
4. Azure GWLB deployments commonly use **two tunnels** (internal/external) with **separate VNIs and UDP ports**. Treat these as configurable, not hardcoded.
5. Azure GWLB default tunnel ports are **10800 (internal)** and **10801 (external)** when using dual-tunnel chaining.

**Design Goals**
1. Overlay behavior is **explicit** and **configurable** via flags.
2. Inner‑packet policy and NAT are **decoupled** from overlay encapsulation.
3. Overlay support works in **DPDK** and **software (tun)** mode for local testing.
4. Re‑encapsulation preserves overlay metadata (GENEVE TLVs / flow cookie) for correct return path.
5. MTU/MSS issues are handled deterministically.

**Proposed CLI**
1. `--encap none|vxlan|geneve` (default `none`).
2. `--snat none|auto|<ip>`:
   1. `none` for AWS/Azure (overlay return path).
   2. `auto` for GCP (SNAT using DHCP dataplane IP).
3. `--encap-vni <id>` (VXLAN VNI; required for Azure).
4. `--encap-udp-port <port>` (VXLAN/Geneve UDP port).
5. Optional: `--encap-vni-internal` and `--encap-vni-external` for Azure dual‑tunnel support.

**Overlay Pipeline (Data Plane)**
1. **Ingress**
   1. Parse outer L2/L3/UDP.
   2. If `encap=geneve`:
      1. Parse GENEVE header.
      2. Preserve all TLVs in an opaque buffer for egress (including flow cookie metadata).
   3. If `encap=vxlan`:
      1. Parse VXLAN header, read VNI and inner payload.
   4. Extract inner Ethernet/IP packet.
   5. Apply policy/NAT to **inner** packet only.
2. **Egress**
   1. If `encap=none`:
      1. Standard NAT/forward path.
   2. If `encap=geneve`:
      1. Re‑encapsulate inner packet with GENEVE.
      2. Preserve TLVs observed on ingress unless explicitly configured otherwise.
      3. Use UDP/6081 and send to GWLB endpoint.
   3. If `encap=vxlan`:
      1. Re‑encapsulate inner packet with VXLAN.
      2. Use configured VNI/port and send to GWLB.
3. **MTU/MSS handling**
   1. Ensure effective MTU supports overlay overhead.
   2. If MTU cannot be raised, clamp TCP MSS in the inner flow.

**Cloud‑Specific Behavior**
1. **AWS GWLB**
   1. GENEVE UDP/6081.
   2. Preserve GENEVE TLVs; they include metadata (flow cookie) required for return routing.
   3. Management health checks use management plane endpoints.
2. **Azure GWLB**
   1. VXLAN tunnels with VNI/port configured via GWLB tunnel interfaces.
   2. Two tunnels (internal/external) are common; support both via config.
   3. Re‑encapsulate to GWLB; no SNAT by default.
3. **GCP**
   1. `encap=none`, SNAT enabled (`--snat auto`).
   2. Continue to use DHCP IP as SNAT source.

**Software (Local) Overlay Test Path**
1. Add a tun‑based overlay receiver to inject VXLAN/GENEVE frames for local tests.
2. Provide a test helper that generates encapsulated traffic (scapy or custom Rust tool).
3. Validate decap/encap correctness and inner policy evaluation with unit tests.

**Metrics**
1. `overlay_decap_errors_total`
2. `overlay_encap_errors_total`
3. `overlay_packets_total{mode=geneve|vxlan|none, direction=in|out}`
4. `overlay_mtu_drops_total`

**Failure Behavior**
1. Overlay parse errors: drop packet, increment metrics, no logging spam.
2. Unsupported encap mode on build: fail fast at startup.
3. Missing required config (e.g., VNI for VXLAN): fail fast.

**Testing Plan**
1. Unit tests:
   1. GENEVE TLV parsing and preservation.
   2. VXLAN VNI parsing and re‑encapsulation.
   3. Inner policy evaluation for encapsulated traffic.
2. Integration tests:
   1. Local overlay injector -> firewall -> re‑encap path.
   2. MTU/MSS clamping behavior with overlay overhead.
3. Azure E2E:
   1. GWLB egress path with VXLAN.
4. AWS E2E:
   1. GWLB egress path with GENEVE.

**Open Questions**
1. Confirm whether we should parse any GENEVE TLVs beyond opaque preservation (likely not in MVP).
