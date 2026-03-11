# Firewall Repository Guidance

## Architectural Philosophy
- Strict separation of dataplane and control plane.
- Dataplane contains only packet processing and stateful NAT logic.
- Control plane handles DNS proxying, cluster replication, and future management APIs.
- No DNS parsing or control-plane logic inside the dataplane.

## Supported Traffic Flows
- DNS queries targeted at the firewall itself
- Firewall-originated upstream DNS traffic
- Firewall-originated cluster replication traffic
- Traffic under policy (DPDK data plane)
