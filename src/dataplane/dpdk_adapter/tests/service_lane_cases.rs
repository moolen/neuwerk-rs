#[test]
fn process_service_lane_egress_restores_intercept_tuple_and_rewrites_l2() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        adapter.set_mac(fw_mac);
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        adapter.insert_arp(client_ip, client_mac);

        let mut state = EngineState::new(
            Arc::new(RwLock::new(intercept_policy_snapshot())),
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );
        let out = adapter.process_frame(&outbound, &mut state);
        assert!(
            out.is_none(),
            "intercept packet should steer to service lane"
        );
        let _ = adapter
            .next_host_frame()
            .expect("expected queued service-lane frame");

        let egress = build_tcp_syn_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            INTERCEPT_SERVICE_IP_DEFAULT,
            client_ip,
            INTERCEPT_SERVICE_PORT_DEFAULT,
            40000,
        );
        let forwarded = adapter
            .process_service_lane_egress_frame(&egress, &state)
            .expect("service-lane return frame should forward");
        assert_eq!(&forwarded[0..6], &client_mac);
        assert_eq!(&forwarded[6..12], &fw_mac);
        let ipv4 = parse_ipv4(&forwarded, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&forwarded, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(tcp.src_port, 443);
    });
}

#[test]
fn drain_service_lane_egress_reads_tap_rewrites_intercept_tuple_and_sends_dpdk_frame() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        adapter.set_mac(fw_mac);
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        adapter.insert_arp(client_ip, client_mac);

        let mut state = EngineState::new(
            Arc::new(RwLock::new(intercept_policy_snapshot())),
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );
        let out = adapter.process_frame(&outbound, &mut state);
        assert!(
            out.is_none(),
            "intercept packet should steer to service lane"
        );
        let _ = adapter
            .next_host_frame()
            .expect("expected queued service-lane frame");

        let egress = build_tcp_syn_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            INTERCEPT_SERVICE_IP_DEFAULT,
            client_ip,
            INTERCEPT_SERVICE_PORT_DEFAULT,
            40000,
        );

        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe setup failed");
        let mut writer = unsafe { File::from_raw_fd(fds[1]) };
        let reader = unsafe { File::from_raw_fd(fds[0]) };
        super::service_lane::set_file_nonblocking(&reader).expect("set nonblocking");
        adapter.service_lane_tap = Some(reader);

        writer
            .write_all(&egress)
            .expect("write service-lane egress frame");

        let mut io = RecordingIo::default();
        adapter
            .drain_service_lane_egress(&state, &mut io)
            .expect("drain service lane egress");

        assert_eq!(io.sent.len(), 1);
        assert_eq!(&io.sent[0][0..6], &client_mac);
        assert_eq!(&io.sent[0][6..12], &fw_mac);
        let ipv4 = parse_ipv4(&io.sent[0], ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&io.sent[0], ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(tcp.src_port, 443);
    });
}

#[test]
fn shared_intercept_demux_gc_is_amortized_between_lookups() {
    with_default_intercept_env(|| {
        let demux = SharedInterceptDemuxState::default();
        let stale_key = InterceptDemuxKey {
            client_ip: Ipv4Addr::new(10, 0, 0, 10),
            client_port: 40000,
        };
        let fresh_key = InterceptDemuxKey {
            client_ip: Ipv4Addr::new(10, 0, 0, 11),
            client_port: 40001,
        };
        demux.test_insert_with_last_seen(
            stale_key.client_ip,
            stale_key.client_port,
            Ipv4Addr::new(198, 51, 100, 10),
            443,
            Instant::now() - Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS + 1),
        );
        demux.test_insert_with_last_seen(
            fresh_key.client_ip,
            fresh_key.client_port,
            Ipv4Addr::new(198, 51, 100, 11),
            443,
            Instant::now(),
        );

        demux.test_set_last_gc_all(Instant::now());
        assert_eq!(
            demux.lookup(fresh_key.client_ip, fresh_key.client_port),
            Some((Ipv4Addr::new(198, 51, 100, 11), 443))
        );
        assert!(
            demux.test_contains(stale_key.client_ip, stale_key.client_port),
            "stale entries should not be swept on every fast-path lookup"
        );

        demux.test_set_last_gc_all(
            Instant::now() - intercept_demux_gc_interval() - Duration::from_millis(1),
        );
        assert_eq!(
            demux.lookup(fresh_key.client_ip, fresh_key.client_port),
            Some((Ipv4Addr::new(198, 51, 100, 11), 443))
        );
        assert!(
            !demux.test_contains(stale_key.client_ip, stale_key.client_port),
            "stale entries should still be collected after the gc interval elapses"
        );
    });
}

#[test]
fn flush_host_frames_writes_all_pending_frames_to_service_lane_tap() {
    with_default_intercept_env(|| {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe setup failed");
        let mut reader = unsafe { File::from_raw_fd(fds[0]) };
        let writer = unsafe { File::from_raw_fd(fds[1]) };
        adapter.service_lane_tap = Some(writer);

        let frame_a = vec![0x11; 64];
        let frame_b = vec![0x22; 96];
        adapter.enqueue_host_frame(frame_a.clone());
        adapter.enqueue_host_frame(frame_b.clone());

        let mut io = RecordingIo::default();
        adapter
            .flush_host_frames(&mut io)
            .expect("flush service-lane host frames");
        assert!(adapter.next_host_frame().is_none());

        let mut observed = vec![0u8; frame_a.len() + frame_b.len()];
        std::io::Read::read_exact(&mut reader, &mut observed).expect("read flushed bytes");
        assert_eq!(&observed[..frame_a.len()], frame_a.as_slice());
        assert_eq!(&observed[frame_a.len()..], frame_b.as_slice());
    });
}

#[test]
fn process_service_lane_egress_uses_shared_intercept_demux_across_adapters() {
    with_default_intercept_env(|| {
        let shared = Arc::new(SharedInterceptDemuxState::default());
        let mut ingress = DpdkAdapter::new("data0".to_string()).unwrap();
        let mut egress = DpdkAdapter::new("data0".to_string()).unwrap();
        ingress.set_shared_intercept_demux(shared.clone());
        egress.set_shared_intercept_demux(shared);

        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        ingress.set_mac(fw_mac);
        egress.set_mac(fw_mac);

        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        egress.insert_arp(client_ip, client_mac);

        let mut state = EngineState::new(
            Arc::new(RwLock::new(intercept_policy_snapshot())),
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(1)));
        state.set_intercept_to_host_steering(true);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );
        assert!(
            ingress.process_frame(&outbound, &mut state).is_none(),
            "intercept packet should steer to service lane"
        );
        let _ = ingress
            .next_host_frame()
            .expect("expected queued service-lane frame");

        let egress_frame = build_tcp_syn_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01],
            INTERCEPT_SERVICE_IP_DEFAULT,
            client_ip,
            INTERCEPT_SERVICE_PORT_DEFAULT,
            40000,
        );
        let forwarded = egress
            .process_service_lane_egress_frame(&egress_frame, &state)
            .expect("service-lane return frame should forward");
        let ipv4 = parse_ipv4(&forwarded, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&forwarded, ipv4.l4_offset).expect("tcp");
        assert_eq!(ipv4.src, Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(tcp.src_port, 443);
    });
}

fn with_intercept_cap_env<R>(
    demux_max: Option<&str>,
    host_queue_max: Option<&str>,
    arp_queue_max: Option<&str>,
    f: impl FnOnce() -> R,
) -> R {
    let _env_guard = ENV_LOCK.lock().expect("env lock");
    let old_demux_max = std::env::var("NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES").ok();
    let old_host_queue_max = std::env::var("NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX").ok();
    let old_arp_queue_max = std::env::var("NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX").ok();

    match demux_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES", value),
        None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES"),
    }
    match host_queue_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX", value),
        None => std::env::remove_var("NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX"),
    }
    match arp_queue_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX", value),
        None => std::env::remove_var("NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX"),
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

    match old_demux_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES", value),
        None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES"),
    }
    match old_host_queue_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX", value),
        None => std::env::remove_var("NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX"),
    }
    match old_arp_queue_max {
        Some(value) => std::env::set_var("NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX", value),
        None => std::env::remove_var("NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX"),
    }

    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[test]
fn intercept_demux_rejects_new_entries_when_cap_is_reached() {
    with_intercept_cap_env(Some("1"), None, None, || {
        let demux = SharedInterceptDemuxState::default();
        demux.upsert(
            Ipv4Addr::new(10, 0, 0, 10),
            40000,
            Ipv4Addr::new(198, 51, 100, 10),
            443,
        );
        demux.upsert(
            Ipv4Addr::new(10, 0, 0, 11),
            40001,
            Ipv4Addr::new(198, 51, 100, 11),
            443,
        );

        assert_eq!(
            demux.lookup(Ipv4Addr::new(10, 0, 0, 10), 40000),
            Some((Ipv4Addr::new(198, 51, 100, 10), 443))
        );
        assert_eq!(demux.lookup(Ipv4Addr::new(10, 0, 0, 11), 40001), None);
    });
}

#[test]
fn host_frame_queue_drops_or_sheds_when_queue_cap_is_reached() {
    with_intercept_cap_env(None, Some("1"), None, || {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let frame_a = vec![0x11; 64];
        let frame_b = vec![0x22; 64];
        adapter.enqueue_host_frame(frame_a);
        adapter.enqueue_host_frame(frame_b.clone());

        assert_eq!(adapter.next_host_frame(), Some(frame_b));
        assert!(adapter.next_host_frame().is_none());
    });
}
