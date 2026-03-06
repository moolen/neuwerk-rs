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
    let cfg = parse_args("firewall", args).expect("parse args");
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
    let cfg = parse_args("firewall", args).expect("parse args");
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
    let err = parse_args("firewall", args).expect_err("expected parse failure");
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
    let err = parse_args("firewall", args).expect_err("expected parse failure");
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
    let err = parse_args("firewall", args).expect_err("expected parse failure");
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
fn shared_demux_owner_pins_https_to_worker_zero() {
    let pkt = build_test_tcp_packet(40000, 443);
    let owner = shared_demux_owner_for_packet(&pkt, 4, 2);
    assert_eq!(owner, 0);
}

#[test]
fn shared_demux_owner_hashes_non_https_flows() {
    let pkt = build_test_tcp_packet(40000, 5201);
    let owner = shared_demux_owner_for_packet(&pkt, 4, 2);
    assert!(owner < 2);
}

#[test]
fn flow_steer_payload_moves_owned_packet_without_copy() {
    let payload = vec![1u8, 2, 3, 4];
    let ptr = payload.as_ptr();
    let mut pkt = Packet::new(payload);
    let steered = flow_steer_payload(&mut pkt);
    assert_eq!(steered, vec![1u8, 2, 3, 4]);
    assert_eq!(steered.as_ptr(), ptr);
    assert!(pkt.buffer().is_empty());
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
