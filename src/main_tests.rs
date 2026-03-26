use super::*;

fn build_test_tcp_packet(src_port: u16, dst_port: u16) -> Packet {
    const ETH_HDR_LEN: usize = 14;
    let total_len = 20 + 20;
    let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&[0; 6]);
    buf[6..12].copy_from_slice(&[1; 6]);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip_off = ETH_HDR_LEN;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 6;
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 10).octets());
    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = 0x18;
    let mut pkt = Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt
}

fn runtime_cli_config(extra_yaml: &str) -> runtime::cli::CliConfig {
    let raw = format!(
        r#"
version: 1
bootstrap:
  management_interface: mgmt0
  data_interface: data0
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 1.1.1.1:53
{extra_yaml}
"#
    );
    let derived =
        runtime::config::derive_runtime_config(runtime::config::load_config_str(&raw).unwrap())
            .unwrap();
    runtime::bootstrap::startup::build_runtime_cli_config(&derived).unwrap()
}

fn metric_value_with_labels(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> f64 {
    rendered
        .lines()
        .find_map(|line| {
            if !line.starts_with(metric) {
                return None;
            }
            let name = line.split_whitespace().next()?;
            for (key, value) in labels {
                let needle = format!(r#"{key}="{value}""#);
                if !name.contains(&needle) {
                    return None;
                }
            }
            line.split_whitespace().last()?.parse::<f64>().ok()
        })
        .unwrap_or(0.0)
}

#[cfg(target_os = "linux")]
#[test]
fn read_cpu_list_from_status_parses_allowed_list() {
    let status = "\
Name:\tfirewall
State:\tR (running)
Cpus_allowed:\tff
Cpus_allowed_list:\t0-1,4
";
    let cpus = runtime::dpdk::affinity::read_cpu_list_from_status(status).expect("cpu list");
    assert_eq!(cpus, vec![0, 1, 4]);
}

#[cfg(target_os = "linux")]
#[test]
fn collect_cpu_ids_from_status_blobs_unions_threads() {
    let statuses = [
        "Name:\tt0\nCpus_allowed_list:\t0\n",
        "Name:\tt1\nCpus_allowed_list:\t1,3\n",
        "Name:\tt2\nCpus_allowed_list:\t2-3\n",
    ];
    let cpus = runtime::dpdk::affinity::collect_cpu_ids_from_status_blobs(statuses.iter().copied());
    assert_eq!(cpus, vec![0, 1, 2, 3]);
}

#[test]
fn choose_dpdk_worker_plan_prefers_queue_per_worker_when_available() {
    let plan = choose_dpdk_worker_plan(4, 8, 4, DpdkSingleQueueStrategy::SharedDemux)
        .expect("worker plan");
    assert_eq!(plan.worker_count, 4);
    assert_eq!(plan.mode, DpdkWorkerMode::QueuePerWorker);
}

#[test]
fn choose_dpdk_worker_plan_uses_shared_demux_on_single_queue() {
    let plan = choose_dpdk_worker_plan(4, 8, 1, DpdkSingleQueueStrategy::SharedDemux)
        .expect("worker plan");
    assert_eq!(plan.worker_count, 4);
    assert_eq!(plan.mode, DpdkWorkerMode::SharedRxDemux);
}

#[test]
fn choose_dpdk_worker_plan_uses_single_worker_on_single_queue_when_forced() {
    let plan = choose_dpdk_worker_plan(4, 8, 1, DpdkSingleQueueStrategy::SingleWorker)
        .expect("worker plan");
    assert_eq!(plan.worker_count, 1);
    assert_eq!(plan.mode, DpdkWorkerMode::Single);
}

#[test]
fn choose_dpdk_worker_plan_reduces_to_effective_queue_count() {
    let plan = choose_dpdk_worker_plan(8, 8, 2, DpdkSingleQueueStrategy::SharedDemux)
        .expect("worker plan");
    assert_eq!(plan.worker_count, 2);
    assert_eq!(plan.mode, DpdkWorkerMode::QueuePerWorker);
}

#[test]
fn choose_dpdk_worker_plan_rejects_zero_effective_queues() {
    let err = choose_dpdk_worker_plan(2, 8, 0, DpdkSingleQueueStrategy::SharedDemux)
        .expect_err("expected queue error");
    assert!(err.contains("no usable queues"));
}

#[test]
fn parse_truthy_flag_accepts_common_values() {
    for raw in ["1", "true", "TRUE", " yes ", "On"] {
        assert!(parse_truthy_flag(raw), "expected truthy parse for '{raw}'");
    }
    for raw in ["", "0", "false", "no", "off", "random"] {
        assert!(!parse_truthy_flag(raw), "expected falsey parse for '{raw}'");
    }
}

#[test]
fn service_lane_stays_enabled_in_aggressive_mode_unless_overridden() {
    assert!(service_lane_enabled_with_override(
        DpdkPerfMode::Aggressive,
        false
    ));
    assert!(service_lane_enabled_with_override(
        DpdkPerfMode::Standard,
        false
    ));
    assert!(!service_lane_enabled_with_override(
        DpdkPerfMode::Aggressive,
        true
    ));
}

#[test]
fn shared_demux_owner_pins_https_to_worker_zero() {
    let pkt = build_test_tcp_packet(40000, 443);
    let owner = shared_demux_owner_for_packet_with_policy(&pkt, 4, 2, true);
    assert_eq!(owner, 0);
}

#[test]
fn shared_demux_owner_hashes_non_https_flows() {
    let pkt = build_test_tcp_packet(40000, 5201);
    let owner = shared_demux_owner_for_packet(&pkt, 4, 2);
    assert!(owner < 2);
}

#[test]
fn shared_demux_owner_https_pin_can_be_disabled() {
    let mut saw_non_zero_owner = false;
    for src_port in 40000..40128 {
        let pkt = build_test_tcp_packet(src_port, 443);
        let pinned_owner = shared_demux_owner_for_packet_with_policy(&pkt, 4, 4, true);
        let unpinned_owner = shared_demux_owner_for_packet_with_policy(&pkt, 4, 4, false);
        assert_eq!(pinned_owner, 0);
        if unpinned_owner != 0 {
            saw_non_zero_owner = true;
            break;
        }
    }
    assert!(
        saw_non_zero_owner,
        "expected unpinned HTTPS flows to hash beyond worker 0"
    );
}

#[test]
fn flow_steer_payload_copies_owned_packet_and_preserves_capacity_for_reuse() {
    let payload = vec![1u8, 2, 3, 4];
    let capacity = payload.capacity();
    let ptr = payload.as_ptr();
    let mut pkt = Packet::new(payload);
    let steered = flow_steer_payload(&mut pkt);
    assert_eq!(steered, vec![1u8, 2, 3, 4]);
    assert_ne!(steered.as_ptr(), ptr);
    assert!(pkt.buffer().is_empty());
    let reusable = pkt.into_vec();
    assert_eq!(reusable.len(), 0);
    assert!(reusable.capacity() >= capacity);
}

#[test]
fn flow_steer_payload_copies_borrowed_packet() {
    let mut backing = vec![9u8, 8, 7, 6];
    let mut pkt =
        unsafe { Packet::from_borrowed_mut(backing.as_mut_ptr(), backing.len()) }.unwrap();
    let steered = flow_steer_payload(&mut pkt);
    assert_eq!(steered, backing);
    assert_ne!(steered.as_ptr(), backing.as_ptr());
    assert!(pkt.is_borrowed());
}

#[test]
fn runtime_cli_config_maps_typed_runtime_knobs() {
    let cfg = runtime_cli_config(
        r#"
runtime:
  controlplane_worker_threads: 7
  http_worker_threads: 3
  kubernetes:
    reconcile_interval_secs: 9
    stale_grace_secs: 301
metrics:
  bind: 0.0.0.0:8080
  allow_public_bind: true
tls_intercept:
  upstream_verify: insecure
  io_timeout_secs: 9
  listen_backlog: 4096
  h2:
    body_timeout_secs: 12
    max_concurrent_streams: 48
dataplane:
  flow_table_capacity: 8192
  nat_table_capacity: 16384
  flow_incomplete_tcp_idle_timeout_secs: 21
  flow_incomplete_tcp_syn_sent_idle_timeout_secs: 6
  syn_only_enabled: true
  detailed_observability: true
  admission:
    max_active_flows: 111
    max_active_nat_entries: 222
    max_pending_tls_flows: 333
    max_active_flows_per_source_group: 44
dpdk:
  workers: 5
  core_ids: [1, 3, 5]
  allow_azure_multiworker: true
  single_queue_mode: single
  perf_mode: aggressive
  force_shared_rx_demux: true
  pin_https_demux_owner: true
  disable_service_lane: true
  lockless_queue_per_worker: true
  shared_rx_owner_only: true
  housekeeping_interval_packets: 128
  housekeeping_interval_us: 400
  pin_state_shard_guard: true
  pin_state_shard_burst: 96
  state_shards: 6
  disable_in_memory: true
  iova_mode: va
  force_netvsc: true
  gcp_auto_probe: true
  driver_preload:
    - /opt/neuwerk/lib/custom-pmd.so
  skip_bus_pci_preload: true
  prefer_pci: true
  queue_override: 7
  port_mtu: 1600
  mbuf_data_room: 4096
  mbuf_pool_size: 16384
  rx_ring_size: 2048
  tx_ring_size: 4096
  tx_checksum_offload: false
  allow_retaless_multi_queue: true
  service_lane:
    interface: svc9
    intercept_service_ip: 169.254.200.10
    intercept_service_port: 16443
    multi_queue: true
  intercept_demux:
    gc_interval_ms: 2000
    max_entries: 1234
    shard_count: 16
    host_frame_queue_max: 456
    pending_arp_queue_max: 78
  gateway_mac: aa:bb:cc:dd:ee:ff
  dhcp_server_ip: 169.254.10.20
  dhcp_server_mac: 00:11:22:33:44:55
  overlay:
    swap_tunnels: true
    force_tunnel_src_port: true
    debug: true
    health_probe_debug: true
"#,
    );

    assert!(cfg.allow_public_metrics_bind);
    assert_eq!(cfg.runtime.controlplane_worker_threads, 7);
    assert_eq!(cfg.runtime.http_worker_threads, 3);
    assert_eq!(cfg.runtime.kubernetes.reconcile_interval_secs, 9);
    assert_eq!(cfg.runtime.kubernetes.stale_grace_secs, 301);
    assert!(matches!(
        cfg.tls_intercept.upstream_verify,
        neuwerk::controlplane::trafficd::UpstreamTlsVerificationMode::Insecure
    ));
    assert_eq!(cfg.tls_intercept.io_timeout, std::time::Duration::from_secs(9));
    assert_eq!(cfg.tls_intercept.listen_backlog, 4096);
    assert_eq!(
        cfg.tls_intercept.h2.body_timeout,
        std::time::Duration::from_secs(12)
    );
    assert_eq!(cfg.tls_intercept.h2.max_concurrent_streams, 48);
    assert_eq!(cfg.engine_runtime.flow_table_capacity, 8192);
    assert_eq!(cfg.engine_runtime.nat_table_capacity, 16384);
    assert_eq!(cfg.engine_runtime.flow_incomplete_tcp_idle_timeout_secs, Some(21));
    assert_eq!(cfg.engine_runtime.flow_incomplete_tcp_syn_sent_idle_timeout_secs, 6);
    assert!(cfg.engine_runtime.syn_only_enabled);
    assert!(cfg.engine_runtime.detailed_observability);
    assert_eq!(cfg.engine_runtime.admission.max_active_flows, Some(111));
    assert_eq!(cfg.engine_runtime.admission.max_active_nat_entries, Some(222));
    assert_eq!(cfg.engine_runtime.admission.max_pending_tls_flows, Some(333));
    assert_eq!(
        cfg.engine_runtime.admission.max_active_flows_per_source_group,
        Some(44)
    );
    assert_eq!(cfg.dpdk.workers, Some(5));
    assert_eq!(cfg.dpdk.core_ids, vec![1, 3, 5]);
    assert!(cfg.dpdk.allow_azure_multiworker);
    assert_eq!(
        cfg.dpdk.single_queue_mode,
        runtime::cli::DpdkSingleQueueMode::SingleWorker
    );
    assert_eq!(cfg.dpdk.perf_mode, runtime::cli::DpdkPerfMode::Aggressive);
    assert!(cfg.dpdk.force_shared_rx_demux);
    assert!(cfg.dpdk.pin_https_demux_owner);
    assert!(cfg.dpdk.disable_service_lane);
    assert!(cfg.dpdk.lockless_queue_per_worker);
    assert!(cfg.dpdk.shared_rx_owner_only);
    assert_eq!(cfg.dpdk.housekeeping_interval_packets, 128);
    assert_eq!(cfg.dpdk.housekeeping_interval_us, 400);
    assert!(cfg.dpdk.pin_state_shard_guard);
    assert_eq!(cfg.dpdk.pin_state_shard_burst, 96);
    assert_eq!(cfg.dpdk.state_shards, Some(6));
    assert!(cfg.dpdk.disable_in_memory);
    assert_eq!(cfg.dpdk.iova_mode, Some(runtime::cli::DpdkIovaMode::Va));
    assert!(cfg.dpdk.force_netvsc);
    assert!(cfg.dpdk.gcp_auto_probe);
    assert_eq!(
        cfg.dpdk.driver_preload,
        vec!["/opt/neuwerk/lib/custom-pmd.so".to_string()]
    );
    assert!(cfg.dpdk.skip_bus_pci_preload);
    assert!(cfg.dpdk.prefer_pci);
    assert_eq!(cfg.dpdk.queue_override, Some(7));
    assert_eq!(cfg.dpdk.port_mtu, Some(1600));
    assert_eq!(cfg.dpdk.mbuf_data_room, Some(4096));
    assert_eq!(cfg.dpdk.mbuf_pool_size, Some(16384));
    assert_eq!(cfg.dpdk.rx_ring_size, 2048);
    assert_eq!(cfg.dpdk.tx_ring_size, 4096);
    assert_eq!(cfg.dpdk.tx_checksum_offload, Some(false));
    assert!(cfg.dpdk.allow_retaless_multi_queue);
    assert_eq!(cfg.dpdk.service_lane.interface, "svc9");
    assert_eq!(
        cfg.dpdk.service_lane.intercept_service_ip,
        Ipv4Addr::new(169, 254, 200, 10)
    );
    assert_eq!(cfg.dpdk.service_lane.intercept_service_port, 16443);
    assert!(cfg.dpdk.service_lane.multi_queue);
    assert_eq!(cfg.dpdk.intercept_demux.gc_interval_ms, 2000);
    assert_eq!(cfg.dpdk.intercept_demux.max_entries, 1234);
    assert_eq!(cfg.dpdk.intercept_demux.shard_count, 16);
    assert_eq!(cfg.dpdk.intercept_demux.host_frame_queue_max, 456);
    assert_eq!(cfg.dpdk.intercept_demux.pending_arp_queue_max, 78);
    assert_eq!(
        cfg.dpdk.gateway_mac.as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(cfg.dpdk.dhcp_server_ip, Some(Ipv4Addr::new(169, 254, 10, 20)));
    assert_eq!(
        cfg.dpdk.dhcp_server_mac.as_deref(),
        Some("00:11:22:33:44:55")
    );
    assert!(cfg.dpdk.overlay.swap_tunnels);
    assert!(cfg.dpdk.overlay.force_tunnel_src_port);
    assert!(cfg.dpdk.overlay.debug);
    assert!(cfg.dpdk.overlay.health_probe_debug);
}

#[test]
fn dpdk_shared_demux_observability_metrics_render() {
    let metrics = neuwerk::metrics::Metrics::new().expect("metrics");
    metrics.inc_dpdk_shared_io_lock_contended();
    metrics.observe_dpdk_shared_io_lock_wait(std::time::Duration::from_micros(50));
    metrics.inc_dpdk_flow_steer_dispatch(1, 3);
    metrics.add_dpdk_flow_steer_bytes(1, 3, 1500);
    metrics.observe_dpdk_flow_steer_queue_wait(3, std::time::Duration::from_micros(75));
    metrics.set_dpdk_flow_steer_queue_depth(3, 7);
    metrics.inc_dpdk_flow_steer_fail_open_event(1, "dispatch_failed");
    metrics.inc_dpdk_service_lane_forward(2);
    metrics.add_dpdk_service_lane_forward_bytes(2, 512);
    metrics.observe_dpdk_service_lane_forward_queue_wait(2, std::time::Duration::from_micros(80));
    metrics.set_dpdk_service_lane_forward_queue_depth(5);

    let rendered = metrics.render().expect("render metrics");
    assert_eq!(
        metric_value_with_labels(&rendered, "dpdk_shared_io_lock_contended_total", &[]),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(&rendered, "dpdk_shared_io_lock_wait_seconds_count", &[]),
        2.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_flow_steer_dispatch_packets_total",
            &[("from_worker", "1"), ("to_worker", "3")]
        ),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_flow_steer_dispatch_bytes_total",
            &[("from_worker", "1"), ("to_worker", "3")]
        ),
        1500.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_flow_steer_queue_wait_seconds_count",
            &[("to_worker", "3")]
        ),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_flow_steer_queue_depth",
            &[("to_worker", "3")]
        ),
        7.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_flow_steer_fail_open_events_total",
            &[("worker", "1"), ("event", "dispatch_failed")]
        ),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_service_lane_forward_packets_total",
            &[("from_worker", "2")]
        ),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_service_lane_forward_bytes_total",
            &[("from_worker", "2")]
        ),
        512.0
    );
    assert_eq!(
        metric_value_with_labels(
            &rendered,
            "dpdk_service_lane_forward_queue_wait_seconds_count",
            &[("from_worker", "2")]
        ),
        1.0
    );
    assert_eq!(
        metric_value_with_labels(&rendered, "dpdk_service_lane_forward_queue_depth", &[]),
        5.0
    );
}

#[test]
fn dataplane_runtime_network_config_uses_safe_defaults() {
    let cfg = runtime_cli_config("");

    let network = runtime::bootstrap::startup::build_dataplane_runtime_network_config(&cfg);

    assert_eq!(network.internal_net, Ipv4Addr::UNSPECIFIED);
    assert_eq!(network.internal_prefix, 32);
    assert_eq!(network.public_ip, Ipv4Addr::UNSPECIFIED);
    assert_eq!(network.data_port, 0);
    assert_eq!(network.overlay.mode, neuwerk::dataplane::EncapMode::None);
    assert_eq!(network.overlay.udp_port, 0);
    assert_eq!(network.overlay.vni, None);
}

#[test]
fn dataplane_runtime_network_config_preserves_cli_overrides() {
    let cfg = runtime_cli_config(
        r#"
policy:
  internal_cidr: 10.42.0.0/16
dataplane:
  snat: 203.0.113.10
  encap_mode: vxlan
  encap_vni: 4242
"#,
    );

    let network = runtime::bootstrap::startup::build_dataplane_runtime_network_config(&cfg);

    assert_eq!(network.internal_net, Ipv4Addr::new(10, 42, 0, 0));
    assert_eq!(network.internal_prefix, 16);
    assert_eq!(network.public_ip, Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(network.data_port, 0);
    assert_eq!(network.overlay.mode, neuwerk::dataplane::EncapMode::Vxlan);
    assert_eq!(network.overlay.udp_port, 10800);
    assert_eq!(network.overlay.vni, Some(4242));
}
