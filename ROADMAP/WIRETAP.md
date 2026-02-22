Wiretap API (Packet Metadata Streaming)

Goals
- Provide a single HTTPS streaming endpoint for per-flow metadata (not full packet capture).
- Allow filtering by source/destination CIDR, hostname regex, proto, and ports.
- Expose monotonic packet counters per flow, with in/out from the public-internet perspective.
- Keep dataplane minimal; no DNS parsing or control-plane logic inside the dataplane.
- Aggregate streams across all cluster nodes.

Non-Goals
- Full packet capture, payload inspection, or tcpdump-level fidelity.
- DNS parsing in the dataplane.
- Persistent storage of wiretap streams.
- Cross-flow aggregation beyond per-flow counters.

API Shape
- Endpoint: `GET /v1/wiretap/stream`
- Auth: reuse existing bearer token middleware.
- Response: `text/event-stream` (SSE) with JSON payloads.
- Query parameters (repeatable, AND across fields, OR within a field):
  - `src_cidr` (CIDR list)
  - `dst_cidr` (CIDR list)
  - `hostname` (regex list, matched against normalized DNS hostname)
  - `proto` (tcp|udp|icmp|any|<number>)
  - `src_port` (port or range, e.g. `80` or `1000-2000`)
  - `dst_port` (port or range)

Event Format
- SSE event type: `flow`
  - JSON fields:
    - `flow_id`: stable ID derived from pre-NAT 5-tuple
    - `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`
    - `packets_in`, `packets_out` (monotonic per flow)
    - `last_seen` (unix seconds)
    - `hostname` (optional, DNS allowlist mapping for `dst_ip`)
    - `node_id` (UUID)
- SSE event type: `flow_end` (when a flow expires)
  - Same fields as `flow`, with final counters

Direction Semantics
- `packets_out`: internal -> public (egress from firewall to internet).
- `packets_in`: public -> internal (ingress from internet to firewall).

Design Overview
1. Dataplane records per-flow counters and emits periodic flow updates.
2. Each node’s control plane receives events from its local dataplane.
3. A local wiretap hub fans out events to HTTP and cluster subscribers.
4. The HTTP API runs on the leader; it subscribes to all nodes via mTLS gRPC,
   merges the streams, and returns an aggregated SSE stream.
5. Filtering is applied on each node (control plane), so hostname lookups are local.

Dataplane Changes
- Extend `FlowEntry` with:
  - `packets_in`, `packets_out`
  - `first_seen`, `last_seen` (if needed for reporting)
  - `last_reported` (for rate limiting updates)
- Add a lightweight `WiretapEvent` struct in `dataplane` that contains only metadata.
- Add an optional `WiretapEmitter` to `EngineState` that can `try_send` events.
- Update `handle_packet`:
  - On outbound (internal -> public): increment `packets_out`.
  - On inbound (public -> internal): increment `packets_in`.
  - Emit `flow` updates when `now - last_reported >= report_interval`.
  - Emit `flow_end` on eviction via `evict_expired`.
- Keep all logic purely metadata; no DNS parsing or hostname handling in dataplane.

Control Plane Changes (Per Node)
- Introduce `controlplane::wiretap` module:
  - `WiretapFilter`: compiled CIDRs, ports, proto, and hostname regex.
  - `WiretapHub`: broadcast ring buffer for events; drops on slow consumers.
  - `WiretapSubscriber`: filters events and yields a stream for SSE and gRPC.
- DNS mapping:
  - Extend `dns_proxy` to update a local `DnsMap` of `dst_ip -> hostname`.
  - Use the DNS allowlist response parsing as the source of truth.
  - Evict stale entries using the existing DNS allowlist idle/GC settings.
- HTTP SSE handler:
  - Parse query params into `WiretapFilter`.
  - Subscribe to the local hub and stream SSE events.

Cluster Aggregation
- Add a new gRPC service in `proto/cluster.proto`:
  - `service Wiretap { rpc Subscribe(WiretapSubscribeRequest) returns (stream WiretapEvent); }`
  - Request includes the wiretap filter; response sends `WiretapEvent`.
- Register the Wiretap server alongside Raft/Policy/Auth in `cluster/bootstrap`.
- Leader HTTP endpoint:
  - Determine leader via existing raft metrics logic.
  - If follower, proxy the SSE stream with true streaming semantics.
  - If leader, open gRPC subscriptions to all nodes (including itself) and merge.
  - Emit `node_id` in each event so clients can trace the source node.

Backpressure Model
- Dataplane uses `try_send` into a bounded channel.
- Control plane uses `broadcast` as a ring buffer; slow consumers drop events.
- SSE clients that fall behind will observe skipped updates but retain monotonic counters.

Implementation Plan
1. Dataplane flow counters
   - Update `src/dataplane/flow.rs` to add counters and timestamps.
   - Update `src/dataplane/engine.rs` to increment counters and emit events.
   - Add `WiretapEvent` and `WiretapEmitter` in `src/dataplane`.
2. DNS mapping
   - Add a `DnsMap` in `src/controlplane` to map `dst_ip -> hostname`.
   - Update `src/controlplane/dns_proxy.rs` to record hostname mappings on responses.
   - Tie eviction to existing DNS allowlist GC timing.
3. Wiretap hub and filters
   - Add `src/controlplane/wiretap.rs` for filters and hub.
   - Implement filter parsing for CIDR, proto, port ranges, and hostname regex.
4. SSE endpoint
   - Add `GET /v1/wiretap/stream` to `src/controlplane/http_api.rs`.
   - Use `axum::response::sse::Sse` and stream `WiretapEvent` as JSON.
   - Ensure bearer auth applies and metrics record requests.
5. Cluster aggregation
   - Extend `proto/cluster.proto` and regenerate gRPC code.
   - Implement `Wiretap` gRPC server in `src/controlplane/cluster/rpc.rs`.
   - Leader opens gRPC subscriptions to all nodes and merges into SSE.
   - Follower proxies SSE stream with true streaming (no full-body buffering).
6. Tests
   - Add e2e test:
     - Start a 2-node cluster.
     - Generate a flow on each node.
     - Connect to the leader’s SSE endpoint.
     - Assert both nodes’ flow IDs and counters appear.
   - Add unit tests for filter parsing and matching logic.

Notes
- SSE in browsers typically uses `fetch` + stream parsing to include the bearer token.
- If `hostname` is set in the filter, only flows with a known DNS mapping match.
- No changes to dataplane packet parsing beyond counters and event emission.
