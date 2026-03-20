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

fn base_args() -> Vec<String> {
    vec![
        "--management-interface".to_string(),
        "mgmt0".to_string(),
        "--data-plane-interface".to_string(),
        "data0".to_string(),
    ]
}

fn required_runtime_args() -> Vec<String> {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ip".to_string(),
        "10.0.0.53".to_string(),
        "--dns-upstream".to_string(),
        "1.1.1.1:53".to_string(),
    ]);
    args
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

#[test]
fn parse_args_accepts_repeated_dns_flags() {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ip".to_string(),
        "10.0.0.1".to_string(),
        "--dns-target-ip".to_string(),
        "10.0.0.2".to_string(),
        "--dns-upstream".to_string(),
        "1.1.1.1:53".to_string(),
        "--dns-upstream".to_string(),
        "8.8.8.8:53".to_string(),
    ]);
    let cfg = parse_args("neuwerk", args).expect("parse args");
    assert_eq!(cfg.dns_target_ips.len(), 2);
    assert_eq!(cfg.dns_upstreams.len(), 2);
}

#[test]
fn parse_args_accepts_csv_dns_flags() {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ips".to_string(),
        "10.0.0.1,10.0.0.2".to_string(),
        "--dns-upstreams".to_string(),
        "1.1.1.1:53,8.8.8.8:53".to_string(),
    ]);
    let cfg = parse_args("neuwerk", args).expect("parse args");
    assert_eq!(cfg.dns_target_ips.len(), 2);
    assert_eq!(cfg.dns_upstreams.len(), 2);
}

#[test]
fn parse_args_rejects_mixed_dns_target_forms() {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ip".to_string(),
        "10.0.0.1".to_string(),
        "--dns-target-ips".to_string(),
        "10.0.0.2".to_string(),
        "--dns-upstream".to_string(),
        "1.1.1.1:53".to_string(),
    ]);
    let err = parse_args("neuwerk", args).expect_err("expected parse failure");
    assert!(err.contains("cannot combine repeated --dns-target-ip"));
}

#[test]
fn parse_args_rejects_mixed_dns_upstream_forms() {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ip".to_string(),
        "10.0.0.1".to_string(),
        "--dns-upstream".to_string(),
        "1.1.1.1:53".to_string(),
        "--dns-upstreams".to_string(),
        "8.8.8.8:53".to_string(),
    ]);
    let err = parse_args("neuwerk", args).expect_err("expected parse failure");
    assert!(err.contains("cannot combine repeated --dns-upstream"));
}

#[test]
fn parse_args_rejects_removed_dns_listen_flag() {
    let mut args = base_args();
    args.extend_from_slice(&[
        "--dns-target-ip".to_string(),
        "10.0.0.1".to_string(),
        "--dns-upstream".to_string(),
        "1.1.1.1:53".to_string(),
        "--dns-listen".to_string(),
        "10.0.0.1:53".to_string(),
    ]);
    let err = parse_args("neuwerk", args).expect_err("expected parse failure");
    assert!(err.contains("--dns-listen has been removed"));
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
fn dpdk_shared_demux_observability_metrics_render() {
    let metrics = controlplane::metrics::Metrics::new().expect("metrics");
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
    let cfg = parse_args("neuwerk", required_runtime_args()).expect("parse args");

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
    let mut args = required_runtime_args();
    args.extend_from_slice(&[
        "--internal-cidr".to_string(),
        "10.42.0.0/16".to_string(),
        "--snat".to_string(),
        "203.0.113.10".to_string(),
        "--encap".to_string(),
        "vxlan".to_string(),
        "--encap-vni".to_string(),
        "4242".to_string(),
    ]);
    let cfg = parse_args("neuwerk", args).expect("parse args");

    let network = runtime::bootstrap::startup::build_dataplane_runtime_network_config(&cfg);

    assert_eq!(network.internal_net, Ipv4Addr::new(10, 42, 0, 0));
    assert_eq!(network.internal_prefix, 16);
    assert_eq!(network.public_ip, Ipv4Addr::new(203, 0, 113, 10));
    assert_eq!(network.data_port, 0);
    assert_eq!(network.overlay.mode, neuwerk::dataplane::EncapMode::Vxlan);
    assert_eq!(network.overlay.udp_port, 10800);
    assert_eq!(network.overlay.vni, Some(4242));
}
