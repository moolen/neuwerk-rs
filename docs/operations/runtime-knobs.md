# Runtime Knobs

This page is the canonical operator-facing reference for Neuwerk runtime configuration in `/etc/neuwerk/config.yaml`.

On appliance images, edit that YAML file and restart `neuwerk.service` after changes. The earlier environment-variable model described in this PR is no longer the supported appliance interface. Generated runtime env is now an internal implementation detail, not the operator contract.

## Scope

- Includes supported YAML paths in `/etc/neuwerk/config.yaml`.
- Excludes build/packer, CI, benchmark/fuzz, e2e-harness, and cloud-test-harness overrides.
- Excludes generated internal runtime state.
- Unknown keys are rejected, and the file schema version must be `1`.

## Conventions

- `required`: the path must be present in the file.
- `derived`: Neuwerk computes the effective value when the path is omitted.
- `unset`: optional; no explicit override is configured.
- `auto`: Neuwerk selects behavior at startup.

## Minimal Packaged Example

```yaml
version: 1

bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: dpdk

dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
```

## Full Reference `config.yaml`

Use this as a shape/reference document, not as a copy-paste baseline. Remove sections you do not need for your deployment.

```yaml
# Neuwerk runtime configuration
# Edit /etc/neuwerk/config.yaml and restart neuwerk.service after changes.

version: 1

bootstrap:
  # Management NIC used for HTTP, metrics, DNS control-plane traffic, and cloud discovery.
  management_interface: eth0
  # Dataplane NIC used for policy-enforced traffic.
  data_interface: eth1
  # One of: none, aws, azure, gcp.
  cloud_provider: aws
  # One of: tun, tap, dpdk.
  data_plane_mode: dpdk

dns:
  # IPs Neuwerk should answer DNS on.
  target_ips:
    - 10.0.0.53
  # Upstream resolvers reachable from the management network.
  upstreams:
    - 10.0.0.2:53
    - 10.0.0.3:53

runtime:
  # Tokio worker count for DNS/control-plane background tasks.
  controlplane_worker_threads: 4
  # Tokio worker count for the HTTP API/UI runtime.
  http_worker_threads: 2
  kubernetes:
    # Reconcile cadence for Kubernetes-backed integration state.
    reconcile_interval_secs: 5
    # Grace window before stale Kubernetes state is dropped.
    stale_grace_secs: 300

policy:
  # Startup default policy: allow or deny.
  default: deny
  # Optional internal CIDR used for local/internal traffic classification.
  internal_cidr: 10.123.0.0/16

http:
  # Bind address for the HTTP API and UI.
  bind: 10.0.0.10:8443
  # Address Neuwerk advertises to peers/clients if it differs from bind.
  advertise: 10.0.0.10:8443
  # External URL when Neuwerk sits behind a reverse proxy or DNS name.
  external_url: https://neuwerk.example.com
  # Directory for generated or managed HTTP TLS assets.
  tls_dir: /var/lib/neuwerk/http-tls
  # Optional explicit TLS material paths.
  cert_path: /var/lib/neuwerk/http-tls/server.crt
  key_path: /var/lib/neuwerk/http-tls/server.key
  ca_path: /var/lib/neuwerk/http-tls/ca.crt
  # Extra SANs for generated or validated certificates.
  tls_san:
    - neuwerk.example.com
    - neuwerk.internal

metrics:
  # Metrics listener; if omitted Neuwerk derives it from the management IP.
  bind: 10.0.0.10:8080
  # Must be true before binding metrics on a public/non-private address.
  allow_public_bind: false

cluster:
  # Cluster bind enables cluster mode when any cluster.* setting is present.
  bind: 10.0.0.10:9600
  # Optional separate join listener; defaults to bind port + 1.
  join_bind: 10.0.0.10:9601
  # Address advertised to other nodes.
  advertise: 10.0.0.10:9600
  # Seed node to join; omit on the first cluster node.
  join_seed: 10.0.0.11:9600
  # Persistent cluster state paths.
  data_dir: /var/lib/neuwerk/cluster
  node_id_path: /var/lib/neuwerk/node_id
  token_path: /var/lib/neuwerk/bootstrap-token
  # Migration controls for moving local state into clustered storage.
  migrate_from_local: false
  migrate_force: false
  migrate_verify: false

integration:
  # One of: none, aws-asg, azure-vmss, gcp-mig.
  mode: aws-asg
  route_name: neuwerk-default
  cluster_name: neuwerk
  drain_timeout_secs: 300
  reconcile_interval_secs: 15
  # Populate only the subsection that matches integration.mode.
  aws:
    region: us-east-1
    vpc_id: vpc-0123456789abcdef0
    asg_name: neuwerk-asg
  # azure:
  #   subscription_id: 00000000-0000-0000-0000-000000000000
  #   resource_group: rg-neuwerk
  #   vmss_name: vmss-neuwerk
  # gcp:
  #   project: my-project
  #   region: us-central1
  #   ig_name: neuwerk-mig

tls_intercept:
  # One of: strict, insecure.
  upstream_verify: strict
  # Upstream TLS handshake/read timeout.
  io_timeout_secs: 3
  # Listener backlog for the intercept path.
  listen_backlog: 1024
  h2:
    body_timeout_secs: 10
    max_concurrent_streams: 64
    max_requests_per_connection: 800
    pool_shards: 1
    detailed_metrics: false
    selection_inflight_weight: 128
    reconnect_backoff_base_ms: 5
    reconnect_backoff_max_ms: 250

dataplane:
  idle_timeout_secs: 300
  dns_allowlist_idle_secs: 420
  dns_allowlist_gc_interval_secs: 30
  dhcp_timeout_secs: 5
  dhcp_retry_max: 5
  dhcp_lease_min_secs: 60
  # Either a scalar:
  snat: auto
  # Or a structured static form:
  # snat:
  #   mode: static
  #   ip: 198.51.100.20
  # Overlay mode: none, vxlan, geneve.
  encap_mode: none
  # VXLAN options. Use encap_vni or the internal/external pair, not both.
  # encap_vni: 1001
  # encap_vni_internal: 1002
  # encap_vni_external: 1003
  # Optional UDP port overrides for overlay traffic.
  # encap_udp_port: 10800
  # encap_udp_port_internal: 10810
  # encap_udp_port_external: 10811
  encap_mtu: 1500
  flow_table_capacity: 32768
  nat_table_capacity: 32768
  # Optional half-open TCP idle timeout override.
  # flow_incomplete_tcp_idle_timeout_secs: 300
  flow_incomplete_tcp_syn_sent_idle_timeout_secs: 3
  syn_only_enabled: false
  detailed_observability: false
  admission:
    max_active_flows: 24576
    max_active_nat_entries: 24576
    max_pending_tls_flows: 2048
    # Omit to leave per-source-group admission disabled.
    # max_active_flows_per_source_group: 16384

dpdk:
  # Set all four static_* keys together if you need static DPDK addressing.
  # static_ip: 10.0.1.10
  # static_prefix_len: 24
  # static_gateway: 10.0.1.1
  # static_mac: 02:00:00:00:00:42
  # Either auto or an explicit worker count.
  workers: auto
  # Optional explicit EAL core pinning.
  core_ids: [0, 1]
  allow_azure_multiworker: false
  single_queue_mode: demux
  perf_mode: standard
  force_shared_rx_demux: false
  pin_https_demux_owner: false
  disable_service_lane: false
  lockless_queue_per_worker: false
  shared_rx_owner_only: true
  housekeeping_interval_packets: 64
  housekeeping_interval_us: 250
  pin_state_shard_guard: false
  pin_state_shard_burst: 64
  # Optional explicit shard count; defaults to worker count.
  # state_shards: 2
  disable_in_memory: false
  # Optional IOVA mode override: va or pa.
  # iova_mode: va
  force_netvsc: false
  gcp_auto_probe: false
  # Extra DPDK PMD/bus libraries to preload.
  driver_preload: []
  skip_bus_pci_preload: false
  prefer_pci: false
  # Optional queue capability override.
  # queue_override: 4
  # Optional MTU override for the DPDK port.
  # port_mtu: 1500
  # Optional mbuf tuning.
  # mbuf_data_room: 2176
  # mbuf_pool_size: 65535
  rx_ring_size: 1024
  tx_ring_size: 1024
  # Optional checksum offload override.
  # tx_checksum_offload: true
  allow_retaless_multi_queue: false
  service_lane:
    interface: svc0
    intercept_service_ip: 169.254.255.1
    intercept_service_port: 15443
    multi_queue: true
  intercept_demux:
    gc_interval_ms: 1000
    max_entries: 65536
    shard_count: 64
    host_frame_queue_max: 8192
    pending_arp_queue_max: 4096
  # Optional trust pins for gateway and DHCP learning.
  # gateway_mac: aa:bb:cc:dd:ee:ff
  # dhcp_server_ip: 10.0.1.1
  # dhcp_server_mac: aa:bb:cc:dd:ee:01
  overlay:
    swap_tunnels: false
    force_tunnel_src_port: false
    debug: false
    health_probe_debug: false
```

## Quick Reference

### Required Bootstrap And DNS

| Path | Default | When To Touch |
| --- | --- | --- |
| `version` | required: `1` | Only when Neuwerk ships a future schema version |
| `bootstrap.management_interface` | required; packaged image seeds `eth0` | Management NIC name differs on your platform |
| `bootstrap.data_interface` | required; packaged image seeds `eth1` | Dataplane NIC name differs on your platform |
| `bootstrap.cloud_provider` | required; packaged image seeds `none` | Pin cloud-specific behavior to `aws`, `azure`, or `gcp` |
| `bootstrap.data_plane_mode` | required; packaged image seeds `dpdk` | Switch to `tun` or `tap` instead of DPDK |
| `dns.target_ips` | required | Pin the local IPs Neuwerk should answer DNS on |
| `dns.upstreams` | required | Set the upstream resolvers reachable from the management network |

### Runtime, Policy, HTTP, And Metrics

| Path | Default | When To Touch |
| --- | --- | --- |
| `runtime.controlplane_worker_threads` | `4` | DNS/control-plane Tokio runtime needs a different worker count |
| `runtime.http_worker_threads` | `2` | HTTP API runtime needs a different worker count |
| `runtime.kubernetes.reconcile_interval_secs` | `5` | Kubernetes integration cadence must change |
| `runtime.kubernetes.stale_grace_secs` | `300` | Stale Kubernetes state needs a longer or shorter grace window |
| `policy.default` | `deny` | You need a different startup policy baseline |
| `policy.internal_cidr` | `unset` | DHCP-derived internal-network detection is wrong |
| `http.bind` | derived: `<management-ip>:8443` | API/UI bind address must move |
| `http.advertise` | derived: `http.bind` | Advertised control-plane address differs from bind address |
| `http.external_url` | `unset` | Reverse proxy or external URL must be explicit |
| `http.tls_dir` | `/var/lib/neuwerk/http-tls` | HTTP TLS material must live elsewhere |
| `http.cert_path` | `unset` | Use an explicit server certificate path |
| `http.key_path` | `unset` | Use an explicit server private-key path |
| `http.ca_path` | `unset` | Use an explicit client-CA path |
| `http.tls_san` | empty list | Add extra SANs for generated or validated HTTP certs |
| `metrics.bind` | derived: `<management-ip>:8080` | Metrics bind must move or narrow |
| `metrics.allow_public_bind` | `false` | You intentionally expose metrics on a public address |

### Cluster And Cloud Integration

| Path | Default | When To Touch |
| --- | --- | --- |
| `cluster.bind` | `127.0.0.1:9600` | Enable cluster mode and change the local bind |
| `cluster.join_bind` | derived: `cluster.bind + 1` | The join listener must move |
| `cluster.advertise` | derived: `cluster.bind` | Peers must use a different advertised address |
| `cluster.join_seed` | `unset` | Join an existing cluster instead of starting standalone |
| `cluster.data_dir` | `/var/lib/neuwerk/cluster` | Cluster state must live elsewhere |
| `cluster.node_id_path` | `/var/lib/neuwerk/node_id` | Node ID file must move |
| `cluster.token_path` | `/var/lib/neuwerk/bootstrap-token` | Bootstrap token file must move |
| `cluster.migrate_from_local` | `false` | Seed cluster-backed state from local disk |
| `cluster.migrate_force` | `false` | Force a migration that would otherwise stop |
| `cluster.migrate_verify` | `false` | Run migration verification checks |
| `integration.mode` | `none` | Enable `azure-vmss`, `aws-asg`, or `gcp-mig` integration |
| `integration.route_name` | `neuwerk-default` | Provider route object name must change |
| `integration.cluster_name` | `neuwerk` | Shared integration naming must be pinned |
| `integration.drain_timeout_secs` | `300` | Instances need a different drain grace period |
| `integration.reconcile_interval_secs` | `15` | Provider reconciliation is too slow or too chatty |
| `integration.aws.region` | `unset` | Required for `integration.mode: aws-asg` |
| `integration.aws.vpc_id` | `unset` | Required for `integration.mode: aws-asg` |
| `integration.aws.asg_name` | `unset` | Required for `integration.mode: aws-asg` |
| `integration.azure.subscription_id` | `unset` | Required for `integration.mode: azure-vmss` |
| `integration.azure.resource_group` | `unset` | Required for `integration.mode: azure-vmss` |
| `integration.azure.vmss_name` | `unset` | Required for `integration.mode: azure-vmss` |
| `integration.gcp.project` | `unset` | Required for `integration.mode: gcp-mig` |
| `integration.gcp.region` | `unset` | Required for `integration.mode: gcp-mig` |
| `integration.gcp.ig_name` | `unset` | Required for `integration.mode: gcp-mig` |

### TLS Intercept

The `tls_intercept` section is absent by default. Add it only when you enable TLS interception features.

| Path | Default | When To Touch |
| --- | --- | --- |
| `tls_intercept.upstream_verify` | `strict` | Relax upstream cert verification for a lab or broken upstream |
| `tls_intercept.io_timeout_secs` | `3` | Upstream TLS handshakes or reads need more time |
| `tls_intercept.listen_backlog` | `1024` | TLS intercept accept backlog must change |
| `tls_intercept.h2.body_timeout_secs` | `10` | HTTP/2 body streams need a different idle timeout |
| `tls_intercept.h2.max_concurrent_streams` | `64` | HTTP/2 connection concurrency needs to change |
| `tls_intercept.h2.max_requests_per_connection` | `800` | HTTP/2 reuse policy needs to change |
| `tls_intercept.h2.pool_shards` | `1` | HTTP/2 upstream pooling needs sharding |
| `tls_intercept.h2.detailed_metrics` | `false` | You need per-H2-path metrics despite higher cardinality |
| `tls_intercept.h2.selection_inflight_weight` | `128` | H2 upstream selection bias must change |
| `tls_intercept.h2.reconnect_backoff_base_ms` | `5` | H2 reconnect backoff must start higher or lower |
| `tls_intercept.h2.reconnect_backoff_max_ms` | `250` | H2 reconnect backoff cap must change |

### Dataplane

| Path | Default | When To Touch |
| --- | --- | --- |
| `dataplane.idle_timeout_secs` | `300` | Baseline flow idle timeout must change |
| `dataplane.dns_allowlist_idle_secs` | `idle_timeout_secs + 120` | DNS-derived allowlist entries are too sticky or too short |
| `dataplane.dns_allowlist_gc_interval_secs` | `30` | DNS allowlist cleanup cadence must change |
| `dataplane.dhcp_timeout_secs` | `5` | DHCP bootstrap waits must change |
| `dataplane.dhcp_retry_max` | `5` | DHCP retry budget must change |
| `dataplane.dhcp_lease_min_secs` | `60` | Short DHCP leases need a different floor |
| `dataplane.snat` | `auto` | Use `none` or pin a static SNAT IP |
| `dataplane.encap_mode` | `none` | Enable `vxlan` or `geneve` encapsulation |
| `dataplane.encap_vni` | `unset` | Set a shared VXLAN VNI |
| `dataplane.encap_vni_internal` | `unset` | Split internal VXLAN VNI |
| `dataplane.encap_vni_external` | `unset` | Split external VXLAN VNI |
| `dataplane.encap_udp_port` | protocol default | Override encapsulation UDP port |
| `dataplane.encap_udp_port_internal` | `unset` | Override internal encapsulation UDP port |
| `dataplane.encap_udp_port_external` | `unset` | Override external encapsulation UDP port |
| `dataplane.encap_mtu` | `1500` | Adjust encapsulated path MTU |
| `dataplane.flow_table_capacity` | `32768` | Baseline flow-table capacity must change |
| `dataplane.nat_table_capacity` | `32768` | Baseline NAT-table capacity must change |
| `dataplane.flow_incomplete_tcp_idle_timeout_secs` | `unset` | Half-open TCP tracking is too sticky or too short |
| `dataplane.flow_incomplete_tcp_syn_sent_idle_timeout_secs` | `3` | SYN-sent cleanup needs tuning |
| `dataplane.syn_only_enabled` | `false` | Enable the SYN-only flow table path |
| `dataplane.detailed_observability` | `false` | You need deeper lock/shard visibility while debugging |
| `dataplane.admission.max_active_flows` | `24576` | Global flow admission must be tighter or looser |
| `dataplane.admission.max_active_nat_entries` | `24576` | Global NAT admission must be tighter or looser |
| `dataplane.admission.max_pending_tls_flows` | `2048` | Pending TLS intercept admission must change |
| `dataplane.admission.max_active_flows_per_source_group` | `unset` | Noisy source groups need local blast-radius control |

### DPDK Worker Model And Queueing

The `dpdk` section applies only when `bootstrap.data_plane_mode: dpdk`.

| Path | Default | When To Touch |
| --- | --- | --- |
| `dpdk.workers` | `auto` | Worker count must be pinned |
| `dpdk.core_ids` | contiguous `0..workers-1` | EAL core affinity must be pinned explicitly |
| `dpdk.allow_azure_multiworker` | `false` | Override the Azure reliability guard and allow multiple workers |
| `dpdk.single_queue_mode` | `demux` | Collapse single-queue devices to one worker instead of shared demux |
| `dpdk.perf_mode` | `standard` | Favor more aggressive dataplane worker behavior |
| `dpdk.force_shared_rx_demux` | `false` | Force shared-RX demux instead of queue-per-worker |
| `dpdk.shared_rx_owner_only` | `true` | Override shared-RX owner-only polling behavior |
| `dpdk.pin_https_demux_owner` | `false` | Pin HTTPS flows to worker 0 in shared demux mode |
| `dpdk.disable_service_lane` | `false` | Bypass service-lane steering entirely |
| `dpdk.lockless_queue_per_worker` | `false` | Enable lockless queue-per-worker mode |
| `dpdk.housekeeping_interval_packets` | `64` | Housekeeping packet cadence must change |
| `dpdk.housekeeping_interval_us` | `250` | Housekeeping wall-clock cadence must change |
| `dpdk.pin_state_shard_guard` | `false` | Enable extra state-shard ownership guard rails |
| `dpdk.pin_state_shard_burst` | `64` | Change the state-shard guard burst size |
| `dpdk.state_shards` | worker count | Shared-state sharding count must be pinned |
| `dpdk.disable_in_memory` | `false` | Omit `--in-memory` from DPDK EAL init |
| `dpdk.iova_mode` | `auto` | Force `va` or `pa` IOVA mode |
| `dpdk.force_netvsc` | `false` | Force Azure NetVSC/vdev selection |
| `dpdk.gcp_auto_probe` | `false` | Let GCP probe the dataplane NIC instead of honoring explicit selection |
| `dpdk.driver_preload` | empty list | Add extra PMD or bus libraries to preload |
| `dpdk.skip_bus_pci_preload` | `false` | Skip automatic `librte_bus_pci.so` preload |
| `dpdk.prefer_pci` | `false` | Prefer PCI-backed devices over other matches |
| `dpdk.queue_override` | `unset` | Override unreliable NIC queue-cap reporting |
| `dpdk.port_mtu` | `unset` | Port MTU must be pinned or clamped |
| `dpdk.mbuf_data_room` | DPDK default | Payload headroom must change |
| `dpdk.mbuf_pool_size` | `auto` | Mbuf pool sizing needs manual override |
| `dpdk.rx_ring_size` | `1024` | RX descriptor ring must change |
| `dpdk.tx_ring_size` | `1024` | TX descriptor ring must change |
| `dpdk.tx_checksum_offload` | `auto` | Force TX checksum offload on or off |
| `dpdk.allow_retaless_multi_queue` | `false` | Allow multi-queue operation on NICs without RETA |

### DPDK Addressing, Trust, And Service Lane

| Path | Default | When To Touch |
| --- | --- | --- |
| `dpdk.static_ip` | `unset` | Pin the DPDK dataplane IP instead of using DHCP or metadata discovery |
| `dpdk.static_prefix_len` | `unset` | Required with `dpdk.static_ip` |
| `dpdk.static_gateway` | `unset` | Required with `dpdk.static_ip` |
| `dpdk.static_mac` | `unset` | Required with `dpdk.static_ip` |
| `dpdk.gateway_mac` | `unset` | Pin the trusted gateway MAC explicitly |
| `dpdk.dhcp_server_ip` | `unset` | Pin the trusted DHCP server IP explicitly |
| `dpdk.dhcp_server_mac` | `unset` | Pin the trusted DHCP server MAC explicitly |
| `dpdk.service_lane.interface` | `svc0` | Service-lane TAP interface name must change |
| `dpdk.service_lane.intercept_service_ip` | `169.254.255.1` | Override the intercept service VIP used by DPDK steering |
| `dpdk.service_lane.intercept_service_port` | `15443` | Override the intercept service TCP port used by DPDK steering |
| `dpdk.service_lane.multi_queue` | `true` | Disable multiqueue on the service-lane TAP |
| `dpdk.intercept_demux.gc_interval_ms` | `1000` | Change intercept demux GC frequency |
| `dpdk.intercept_demux.max_entries` | `65536` | Cap intercept demux state growth |
| `dpdk.intercept_demux.shard_count` | `64` | Change shared intercept demux sharding |
| `dpdk.intercept_demux.host_frame_queue_max` | `8192` | Cap queued service-lane host frames |
| `dpdk.intercept_demux.pending_arp_queue_max` | `4096` | Cap queued ARP-dependent frames |
| `dpdk.overlay.swap_tunnels` | `false` | Preserve dual-tunnel directionality expected by some GWLB paths |
| `dpdk.overlay.force_tunnel_src_port` | `false` | Force overlay reply source port to the tunnel port |
| `dpdk.overlay.debug` | `false` | Enable verbose overlay debug logging |
| `dpdk.overlay.health_probe_debug` | `false` | Enable verbose health-probe debug logging |

## Detailed Notes

### File Contract And Validation

Neuwerk loads `/etc/neuwerk/config.yaml` directly. There is no supported appliance env-to-CLI bootstrap layer anymore.

- `version` must be `1`
- unknown YAML keys are rejected
- only the sections you need must be present beyond required `bootstrap` and `dns`
- cluster mode stays disabled unless you set at least one `cluster.*` bind, seed, or path override

### Public Metrics Bind Safety

Neuwerk treats a public metrics listener as a guardrailed configuration. Set `metrics.allow_public_bind: true` before using a non-private, non-loopback, non-link-local `metrics.bind`.

Recommended practice:

- keep `metrics.bind` on a management or other private address
- expose metrics through your normal scraping plane or reverse proxy instead of opening them directly to the Internet
- on Azure DPDK, avoid `0.0.0.0` binds unless you intentionally want Neuwerk to pin the effective bind back to the management IP

### Dataplane SNAT And Overlay Rules

`dataplane.snat` accepts either a scalar or a structured form:

```yaml
dataplane:
  snat: auto
```

```yaml
dataplane:
  snat:
    mode: static
    ip: 198.51.100.20
```

Semantic rules to keep in mind:

- if you enable encapsulation and omit `dataplane.snat`, Neuwerk derives effective SNAT mode `none`
- `dataplane.encap_mode: vxlan` requires either `dataplane.encap_vni` or both `dataplane.encap_vni_internal` and `dataplane.encap_vni_external`
- `dataplane.encap_vni` cannot be combined with the split internal/external VNI pair
- `dataplane.encap_mode: geneve` does not accept `dataplane.encap_vni*`

### DPDK Static Addressing

If you set any static DPDK address key, you must set all four together:

- `dpdk.static_ip`
- `dpdk.static_prefix_len`
- `dpdk.static_gateway`
- `dpdk.static_mac`

Use those keys only when DHCP or metadata-based dataplane bootstrap is unavailable or incorrect.

Most DPDK deployments should start with defaults and only move a few knobs:

- `dpdk.workers`
- `dpdk.single_queue_mode`
- `dpdk.perf_mode`
- `dpdk.port_mtu`
- `dpdk.rx_ring_size`
- `dpdk.tx_ring_size`

The rest are mostly platform or troubleshooting flags. If you need to set many of them in production, document why in your deployment repo.

### Gateway And DHCP Trust Pins

`dpdk.gateway_mac`, `dpdk.dhcp_server_ip`, and `dpdk.dhcp_server_mac` harden gateway and DHCP learning on the DPDK dataplane.

Recommended practice:

- set explicit trust pins when the deployment topology is stable enough to know them
- otherwise rely on Neuwerk's anti-churn behavior and monitor rejections
- treat unexpected gateway or DHCP churn as a topology event worth investigating, not as harmless background noise

### Service Lane Steering And Intercept Endpoint

The service lane is how DPDK hands selected TLS-intercept traffic to the host-side intercept path. Most deployments should leave these at default:

- `dpdk.service_lane.interface`
- `dpdk.service_lane.multi_queue`
- `dpdk.service_lane.intercept_service_ip`
- `dpdk.service_lane.intercept_service_port`

Only change them when:

- the TAP interface name collides with a local naming convention
- multiqueue TAP behavior is broken on the target kernel or environment
- the intercept VIP or port conflicts with a local routing or service assumption

`dpdk.disable_service_lane: true` is a real behavior change, not a tuning hint. It bypasses TLS intercept steering from DPDK.

### TLS Upstream Verification

`tls_intercept.upstream_verify` accepts:

- `strict`
- `insecure`

`strict` is the default and should remain the production setting unless you are intentionally testing against broken upstream certificates in a lab.

`insecure` disables upstream certificate verification for the TLS intercept client path. That is useful for temporary diagnostics, but it removes an important authenticity check and should not be normalized into standard production configuration.

### Overlay And GWLB Compatibility Flags

`dpdk.overlay.swap_tunnels` and `dpdk.overlay.force_tunnel_src_port` exist for overlay compatibility quirks, especially around dual-tunnel reply behavior and UDP source-port expectations.

Leave them off unless you have confirmed that the surrounding appliance or cloud GWLB path expects the non-default behavior. These flags are compatibility shims, not generic performance tuning controls.
