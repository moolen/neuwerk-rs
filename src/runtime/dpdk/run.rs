use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use firewall::controlplane;
use firewall::dataplane::policy::{DynamicIpSetV4, PolicySnapshot};
use firewall::dataplane::{
    AuditEmitter, DataplaneConfigStore, DhcpRx, DhcpTx, DpdkAdapter, DpdkIo, DrainControl,
    EngineState, FrameIo, FrameOut, OverlayConfig, Packet, SharedArpState,
    SharedInterceptDemuxState, SnatMode, SoftAdapter, WiretapEmitter,
};
use tokio::sync::{mpsc, watch};

use crate::runtime::cli::DataPlaneMode;

use super::affinity::{choose_dpdk_worker_core_ids, cpu_core_count, pin_thread_to_core};
use super::worker_plan::{
    choose_dpdk_worker_plan, dpdk_force_shared_rx_demux, dpdk_lockless_queue_per_worker_enabled,
    flow_steer_payload, shard_index_for_packet, shared_demux_owner_for_packet, DpdkPerfMode,
    DpdkSingleQueueStrategy, DpdkWorkerMode,
};

fn run_dpdk_housekeeping(
    worker_id: usize,
    force: bool,
    service_lane_enabled: bool,
    housekeeping_shard_idx: usize,
    shared_state: Option<&std::sync::Arc<Vec<std::sync::Mutex<EngineState>>>>,
    local_state: Option<&mut EngineState>,
    adapter: &mut DpdkAdapter,
    io: &mut DpdkWorkerIo,
) -> Result<(), String> {
    if worker_id != 0 {
        return Ok(());
    }
    if let Some(shared) = shared_state {
        let shard = shared
            .get(housekeeping_shard_idx)
            .ok_or_else(|| "dpdk: state shard missing".to_string())?;
        let mut guard = if force {
            shard
                .lock()
                .map_err(|_| "dpdk: state lock poisoned".to_string())?
        } else {
            match shard.try_lock() {
                Ok(guard) => guard,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err("dpdk: state lock poisoned".to_string());
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    return Ok(());
                }
            }
        };
        if service_lane_enabled {
            adapter.drain_service_lane_egress(&guard, io)?;
        }
        while let Some(out) = adapter.next_dhcp_frame(&mut guard) {
            io.send_frame(&out)?;
        }
        return Ok(());
    }
    let local = local_state.ok_or_else(|| "dpdk: local state missing".to_string())?;
    if service_lane_enabled {
        adapter.drain_service_lane_egress(local, io)?;
    }
    while let Some(out) = adapter.next_dhcp_frame(local) {
        io.send_frame(&out)?;
    }
    Ok(())
}

enum DpdkWorkerIo {
    Dedicated(DpdkIo),
    Shared(Arc<Mutex<DpdkIo>>),
}

impl DpdkWorkerIo {
    fn mac(&self) -> Option<[u8; 6]> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.mac(),
            DpdkWorkerIo::Shared(io) => io.lock().ok().and_then(|guard| guard.mac()),
        }
    }
}

impl FrameIo for DpdkWorkerIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.recv_frame(buf),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .recv_frame(buf),
        }
    }

    fn recv_packet(&mut self, pkt: &mut Packet) -> Result<usize, String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.recv_packet(pkt),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .recv_packet(pkt),
        }
    }

    fn finish_rx_packet(&mut self) {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.finish_rx_packet(),
            DpdkWorkerIo::Shared(io) => {
                if let Ok(mut guard) = io.lock() {
                    guard.finish_rx_packet();
                }
            }
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.send_frame(frame),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .send_frame(frame),
        }
    }

    fn send_borrowed_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.send_borrowed_frame(frame),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .send_borrowed_frame(frame),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.flush(),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .flush(),
        }
    }
}

pub fn run_dataplane(
    data_plane_iface: String,
    data_plane_mode: DataPlaneMode,
    idle_timeout_secs: u64,
    policy: Arc<RwLock<PolicySnapshot>>,
    policy_applied_generation: Arc<AtomicU64>,
    service_policy_applied_generation: Arc<AtomicU64>,
    dns_allowlist: DynamicIpSetV4,
    dns_target_ips: Vec<Ipv4Addr>,
    wiretap_emitter: Option<WiretapEmitter>,
    audit_emitter: Option<AuditEmitter>,
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    public_ip: Ipv4Addr,
    snat_mode: SnatMode,
    overlay: OverlayConfig,
    data_port: u16,
    dataplane_config: DataplaneConfigStore,
    drain_control: Option<DrainControl>,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    shared_intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    metrics: controlplane::metrics::Metrics,
) -> Result<(), String> {
    let observer_policy = policy.clone();
    let observer_applied = policy_applied_generation.clone();
    std::thread::Builder::new()
        .name("policy-generation-observer".to_string())
        .spawn(move || {
            let mut last = observer_applied.load(Ordering::Acquire);
            loop {
                let generation = match observer_policy.read() {
                    Ok(lock) => lock.generation(),
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                if generation != last {
                    observer_applied.store(generation, Ordering::Release);
                    last = generation;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
        .map_err(|err| format!("policy observer start failed: {err}"))?;
    let mut state = EngineState::new_with_idle_timeout(
        policy,
        internal_net,
        internal_prefix,
        public_ip,
        data_port,
        idle_timeout_secs,
    );
    state.set_snat_mode(snat_mode);
    state.set_overlay_config(overlay);
    state.set_dns_allowlist(dns_allowlist);
    state.set_dns_target_ips(dns_target_ips);
    state.set_dataplane_config(dataplane_config);
    state.set_policy_applied_generation(policy_applied_generation.clone());
    state.set_service_policy_applied_generation(service_policy_applied_generation);
    if let Some(control) = drain_control {
        state.set_drain_control(control);
    }
    let dpdk_perf_mode = if matches!(data_plane_mode, DataPlaneMode::Dpdk) {
        DpdkPerfMode::from_env()
    } else {
        DpdkPerfMode::Standard
    };
    let perf_aggressive = matches!(dpdk_perf_mode, DpdkPerfMode::Aggressive);
    if perf_aggressive {
        eprintln!(
            "dpdk: perf mode aggressive enabled; disabling dataplane state metrics/audit/wiretap"
        );
    } else {
        state.set_metrics(metrics.clone());
        if let Some(emitter) = wiretap_emitter {
            state.set_wiretap_emitter(emitter);
        }
        if let Some(emitter) = audit_emitter {
            state.set_audit_emitter(emitter);
        }
    }

    match data_plane_mode {
        DataPlaneMode::Soft(mode) => {
            let mut adapter = SoftAdapter::new(data_plane_iface, mode)?;
            adapter.run(&mut state)
        }
        DataPlaneMode::Dpdk => {
            eprintln!("dpdk: perf mode {:?}", dpdk_perf_mode);
            let max_workers = cpu_core_count();
            let requested_workers_raw = std::env::var("NEUWERK_DPDK_WORKERS")
                .ok()
                .and_then(|val| val.parse::<usize>().ok());
            let requested_workers_target = match requested_workers_raw {
                Some(0) => max_workers.max(1),
                Some(n) => n.max(1),
                None => 1,
            };
            let mut worker_core_ids =
                choose_dpdk_worker_core_ids(requested_workers_target, max_workers.max(1));
            if worker_core_ids.is_empty() {
                worker_core_ids.push(0);
            }
            let mut requested_workers = requested_workers_target.min(worker_core_ids.len()).max(1);
            let azure_reliability_guard = matches!(
                std::env::var("NEUWERK_CLOUD_PROVIDER")
                    .ok()
                    .as_deref()
                    .map(|v| v.to_ascii_lowercase()),
                Some(ref v) if v == "azure"
            ) && requested_workers > 1
                && std::env::var("NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER")
                    .ok()
                    .as_deref()
                    != Some("1");
            if azure_reliability_guard {
                eprintln!(
                    "dpdk: azure reliability guard active; forcing single worker (set NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=1 to override)"
                );
                requested_workers = 1;
            }
            worker_core_ids.truncate(requested_workers);
            let worker_core_list = worker_core_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            std::env::set_var("NEUWERK_DPDK_CORE_IDS", &worker_core_list);
            if requested_workers_target > requested_workers {
                eprintln!(
                    "dpdk: cpuset limits requested workers {} -> {}",
                    requested_workers_target, requested_workers
                );
            }
            eprintln!(
                "dpdk: worker config requested={}, cpu_cores={}, using={}, core_ids={}",
                std::env::var("NEUWERK_DPDK_WORKERS").unwrap_or_else(|_| "unset".to_string()),
                max_workers,
                requested_workers,
                worker_core_list
            );
            let force_shared_rx_demux = dpdk_force_shared_rx_demux();
            if force_shared_rx_demux && requested_workers > 1 {
                eprintln!(
                    "dpdk: NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX enabled; skipping queue probe and forcing single shared rx queue"
                );
            }
            let effective_queues = if requested_workers > 1 {
                if force_shared_rx_demux {
                    1
                } else {
                    match DpdkIo::effective_queue_count(&data_plane_iface, requested_workers as u16)
                    {
                        Ok(effective) => effective as usize,
                        Err(err) => {
                            metrics.set_dpdk_init_ok(false);
                            metrics.inc_dpdk_init_failure();
                            return Err(err);
                        }
                    }
                }
            } else {
                1
            };
            let single_queue_strategy = DpdkSingleQueueStrategy::from_env();
            let plan = match choose_dpdk_worker_plan(
                requested_workers,
                max_workers,
                effective_queues,
                single_queue_strategy,
            ) {
                Ok(plan) => plan,
                Err(err) => {
                    metrics.set_dpdk_init_ok(false);
                    metrics.inc_dpdk_init_failure();
                    return Err(err);
                }
            };
            if effective_queues == 1 && requested_workers > 1 {
                let strategy_label = match single_queue_strategy {
                    DpdkSingleQueueStrategy::SharedDemux => "demux",
                    DpdkSingleQueueStrategy::SingleWorker => "single",
                };
                eprintln!(
                    "dpdk: single-queue strategy={} (requested_workers={}, worker_count={})",
                    strategy_label, requested_workers, plan.worker_count
                );
            }
            if plan.worker_count < plan.requested {
                eprintln!(
                    "dpdk: reducing worker threads to {} (device queue limit)",
                    plan.worker_count
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::SharedRxDemux) {
                eprintln!(
                    "dpdk: single rx queue detected (effective_queues={}), enabling shared-rx software demux across {} workers",
                    plan.effective_queues, plan.worker_count
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::Single) {
                let iface = data_plane_iface.clone();
                let core_id = worker_core_ids.first().copied().unwrap_or(0);
                if let Err(err) = pin_thread_to_core(core_id) {
                    eprintln!(
                        "dpdk: single worker failed to pin to core {}: {}",
                        core_id, err
                    );
                } else {
                    eprintln!("dpdk: single worker pinned to core {}", core_id);
                }
                let mut adapter = DpdkAdapter::new(data_plane_iface)?;
                if let Some(publisher) = mac_publisher {
                    adapter.set_mac_publisher(publisher);
                }
                if let Some(tx) = dhcp_tx {
                    adapter.set_dhcp_tx(tx);
                }
                if let Some(rx) = dhcp_rx {
                    adapter.set_dhcp_rx(rx);
                }
                adapter.set_shared_intercept_demux(shared_intercept_demux);
                let mut io = match DpdkIo::new(&iface, Some(metrics.clone())) {
                    Ok(io) => {
                        metrics.set_dpdk_init_ok(true);
                        io
                    }
                    Err(err) => {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                };
                adapter.run_with_io(&mut state, &mut io)
            } else {
                let worker_count = plan.worker_count;
                let queue_per_worker = matches!(plan.mode, DpdkWorkerMode::QueuePerWorker);
                let shared_rx_demux = matches!(plan.mode, DpdkWorkerMode::SharedRxDemux);
                let service_lane_enabled = !perf_aggressive;
                let lockless_qpw =
                    perf_aggressive && queue_per_worker && dpdk_lockless_queue_per_worker_enabled();
                eprintln!(
                    "dpdk: starting {} worker threads (mode={:?})",
                    worker_count, plan.mode
                );
                if !service_lane_enabled {
                    eprintln!("dpdk: perf mode disables service-lane steering/drain");
                }
                if lockless_qpw {
                    eprintln!("dpdk: lockless queue-per-worker enabled (per-worker owned state)");
                }
                let housekeeping_interval_packets =
                    std::env::var("NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS")
                        .ok()
                        .and_then(|val| val.parse::<u64>().ok())
                        .filter(|val| *val > 0)
                        .unwrap_or(64);
                let housekeeping_interval_us =
                    std::env::var("NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US")
                        .ok()
                        .and_then(|val| val.parse::<u64>().ok())
                        .filter(|val| *val > 0)
                        .unwrap_or(250);
                let housekeeping_interval = Duration::from_micros(housekeeping_interval_us);
                eprintln!(
                    "dpdk: housekeeping interval packets={} time_us={}",
                    housekeeping_interval_packets, housekeeping_interval_us
                );
                let pin_state_shard_guard = std::env::var("NEUWERK_DPDK_PIN_STATE_SHARD_GUARD")
                    .map(|val| !matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
                    .unwrap_or(false);
                let pin_state_shard_burst = std::env::var("NEUWERK_DPDK_PIN_STATE_SHARD_BURST")
                    .ok()
                    .and_then(|val| val.parse::<u32>().ok())
                    .filter(|val| *val > 0)
                    .unwrap_or(64);
                eprintln!(
                    "dpdk: state shard guard pinning={} burst={}",
                    pin_state_shard_guard, pin_state_shard_burst
                );
                let shard_count = if lockless_qpw {
                    worker_count
                } else {
                    std::env::var("NEUWERK_DPDK_STATE_SHARDS")
                        .ok()
                        .and_then(|val| val.parse::<usize>().ok())
                        .unwrap_or(worker_count)
                        .max(1)
                };
                eprintln!("dpdk: state shards={}", shard_count);
                let base_state = state;
                let (shared_state, mut worker_local_states): (
                    Option<std::sync::Arc<Vec<std::sync::Mutex<EngineState>>>>,
                    Option<Vec<Option<EngineState>>>,
                ) = if lockless_qpw {
                    let mut states = Vec::with_capacity(worker_count);
                    for worker_id in 0..worker_count {
                        let mut local = base_state.clone_for_shard();
                        local.set_shard_id(worker_id);
                        states.push(Some(local));
                    }
                    (None, Some(states))
                } else {
                    let mut shard_states = Vec::with_capacity(shard_count);
                    for shard_id in 0..shard_count {
                        let mut shard = base_state.clone_for_shard();
                        shard.set_shard_id(shard_id);
                        shard_states.push(std::sync::Mutex::new(shard));
                    }
                    (Some(std::sync::Arc::new(shard_states)), None)
                };
                let shared_arp = Arc::new(Mutex::new(SharedArpState::default()));
                let mut dhcp_rx = dhcp_rx;
                let shared_io = if queue_per_worker {
                    None
                } else {
                    Some(Arc::new(Mutex::new(DpdkIo::new_with_queue(
                        &data_plane_iface,
                        0,
                        plan.effective_queues as u16,
                        Some(metrics.clone()),
                    )?)))
                };
                let enable_flow_steer = shared_rx_demux;
                let (flow_steer_txs, mut flow_steer_rxs) = if enable_flow_steer {
                    let mut txs = Vec::with_capacity(worker_count);
                    let mut rxs = Vec::with_capacity(worker_count);
                    for _ in 0..worker_count {
                        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
                        txs.push(tx);
                        rxs.push(Some(rx));
                    }
                    (Some(Arc::new(txs)), Some(rxs))
                } else {
                    (None, None)
                };
                let service_lane_ready_shared = Arc::new(AtomicBool::new(false));
                let mut handles = Vec::with_capacity(worker_count);
                for worker_id in 0..worker_count {
                    let iface = data_plane_iface.clone();
                    let metrics = metrics.clone();
                    let shared_state = shared_state.as_ref().map(std::sync::Arc::clone);
                    let mut local_state = worker_local_states
                        .as_mut()
                        .and_then(|states| states.get_mut(worker_id))
                        .and_then(Option::take);
                    let shared_arp = Arc::clone(&shared_arp);
                    let shared_intercept_demux = Arc::clone(&shared_intercept_demux);
                    let dhcp_tx = dhcp_tx.clone();
                    let dhcp_rx = if worker_id == 0 { dhcp_rx.take() } else { None };
                    let shared_io = shared_io.clone();
                    let flow_steer_tx = flow_steer_txs.clone();
                    let flow_steer_rx = flow_steer_rxs
                        .as_mut()
                        .and_then(|rxs| rxs.get_mut(worker_id))
                        .and_then(Option::take);
                    let housekeeping_interval_packets = housekeeping_interval_packets;
                    let housekeeping_interval = housekeeping_interval;
                    let pin_state_shard_guard = pin_state_shard_guard;
                    let pin_state_shard_burst = pin_state_shard_burst;
                    let lockless_qpw = lockless_qpw;
                    let service_lane_enabled = service_lane_enabled;
                    let shard_count = shard_count;
                    let service_lane_ready_shared = service_lane_ready_shared.clone();
                    let mac_publisher = if worker_id == 0 {
                        mac_publisher.clone()
                    } else {
                        None
                    };
                    let core_id = worker_core_ids
                        .get(worker_id)
                        .copied()
                        .unwrap_or(worker_id % max_workers.max(1));
                    let handle = std::thread::Builder::new()
                        .name(format!("dpdk-worker-{worker_id}"))
                        .spawn(move || -> Result<(), String> {
                            let housekeeping_shard_idx = shared_state
                                .as_ref()
                                .map(|s| worker_id % s.len())
                                .unwrap_or(0);
                            if let Err(err) = pin_thread_to_core(core_id) {
                                eprintln!(
                                    "dpdk: worker {} failed to pin to core {}: {}",
                                    worker_id, core_id, err
                                );
                            } else {
                                eprintln!("dpdk: worker {} pinned to core {}", worker_id, core_id);
                            }
                            let mut adapter = DpdkAdapter::new(iface.clone())?;
                            if let Some(publisher) = mac_publisher {
                                adapter.set_mac_publisher(publisher);
                            }
                            adapter.set_shared_arp(shared_arp);
                            adapter.set_shared_intercept_demux(shared_intercept_demux);
                            if let Some(tx) = dhcp_tx {
                                adapter.set_dhcp_tx(tx);
                            }
                            if let Some(rx) = dhcp_rx {
                                adapter.set_dhcp_rx(rx);
                            }
                            let mut io = if let Some(shared) = shared_io {
                                DpdkWorkerIo::Shared(shared)
                            } else {
                                DpdkWorkerIo::Dedicated(DpdkIo::new_with_queue(
                                    &iface,
                                    worker_id as u16,
                                    worker_count as u16,
                                    Some(metrics.clone()),
                                )?)
                            };
                            if let Some(mac) = io.mac() {
                                adapter.set_mac(mac);
                            }
                            let mut pkt = Packet::new(vec![0u8; 65536]);
                            let mut pinned_shard_idx: Option<usize> = None;
                            let mut pinned_shard_run_len: u32 = 0;
                            let mut pinned_shard_guard: Option<std::sync::MutexGuard<EngineState>> =
                                None;
                            let mut packets_since_housekeeping = 0u64;
                            let mut next_housekeeping_at = Instant::now() + housekeeping_interval;
                            loop {
                                let service_lane_ready = if !service_lane_enabled {
                                    false
                                } else {
                                    if worker_id == 0 {
                                        let ready = adapter.service_lane_ready();
                                        service_lane_ready_shared.store(ready, Ordering::Release);
                                        ready
                                    } else {
                                        service_lane_ready_shared.load(Ordering::Acquire)
                                    }
                                };
                                let mut from_steer_queue = false;
                                if let Some(rx) = flow_steer_rx.as_ref() {
                                    match rx.try_recv() {
                                        Ok(frame) => {
                                            pkt = Packet::new(frame);
                                            from_steer_queue = true;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            return Err(
                                                "dpdk: flow steer channel disconnected".to_string()
                                            );
                                        }
                                    }
                                }
                                if !from_steer_queue {
                                    let n = io.recv_packet(&mut pkt)?;
                                    if n == 0 {
                                        pinned_shard_guard = None;
                                        pinned_shard_idx = None;
                                        pinned_shard_run_len = 0;
                                        io.finish_rx_packet();
                                        io.flush()?;
                                        run_dpdk_housekeeping(
                                            worker_id,
                                            true,
                                            service_lane_enabled,
                                            housekeeping_shard_idx,
                                            shared_state.as_ref(),
                                            local_state.as_mut(),
                                            &mut adapter,
                                            &mut io,
                                        )?;
                                        if service_lane_enabled {
                                            adapter.flush_host_frames(&mut io)?;
                                        }
                                        packets_since_housekeeping = 0;
                                        next_housekeeping_at =
                                            Instant::now() + housekeeping_interval;
                                        continue;
                                    }
                                    if flow_steer_tx.is_some() {
                                        let owner = shared_demux_owner_for_packet(
                                            &pkt,
                                            shard_count,
                                            worker_count,
                                        );
                                        if owner != worker_id {
                                            let payload = flow_steer_payload(&mut pkt);
                                            flow_steer_tx
                                                .as_ref()
                                                .ok_or_else(|| {
                                                    "dpdk: flow steer tx missing".to_string()
                                                })?
                                                .get(owner)
                                                .ok_or_else(|| {
                                                    "dpdk: flow steer worker missing".to_string()
                                                })?
                                                .send(payload)
                                                .map_err(|_| {
                                                    "dpdk: flow steer dispatch failed".to_string()
                                                })?;
                                            io.finish_rx_packet();
                                            continue;
                                        }
                                    }
                                }
                                let step_result = (|| -> Result<(), String> {
                                    packets_since_housekeeping =
                                        packets_since_housekeeping.saturating_add(1);
                                    if let Some(out) = {
                                        if lockless_qpw {
                                            let local = local_state.as_mut().ok_or_else(|| {
                                                "dpdk: local state missing".to_string()
                                            })?;
                                            local
                                                .set_intercept_to_host_steering(service_lane_ready);
                                            adapter.process_packet_in_place(&mut pkt, local)
                                        } else {
                                            let shared =
                                                shared_state.as_ref().ok_or_else(|| {
                                                    "dpdk: shared state missing".to_string()
                                                })?;
                                            let shard_idx =
                                                shard_index_for_packet(&pkt, shared.len());
                                            if pin_state_shard_guard {
                                                if pinned_shard_idx != Some(shard_idx) {
                                                    pinned_shard_guard = None;
                                                    pinned_shard_idx = None;
                                                    pinned_shard_run_len = 0;
                                                    let shard =
                                                        shared.get(shard_idx).ok_or_else(|| {
                                                            "dpdk: state shard missing".to_string()
                                                        })?;
                                                    let guard = match shard.try_lock() {
                                                        Ok(guard) => guard,
                                                        Err(std::sync::TryLockError::Poisoned(
                                                            _,
                                                        )) => {
                                                            return Err(
                                                                "dpdk: state lock poisoned"
                                                                    .to_string(),
                                                            );
                                                        }
                                                        Err(
                                                            std::sync::TryLockError::WouldBlock,
                                                        ) => {
                                                            metrics.inc_dp_state_lock_contended();
                                                            let start = Instant::now();
                                                            let guard =
                                                                shard.lock().map_err(|_| {
                                                                    "dpdk: state lock poisoned"
                                                                        .to_string()
                                                                })?;
                                                            metrics.observe_dp_state_lock_wait(
                                                                start.elapsed(),
                                                            );
                                                            guard
                                                        }
                                                    };
                                                    pinned_shard_idx = Some(shard_idx);
                                                    pinned_shard_guard = Some(guard);
                                                }
                                                let guard = pinned_shard_guard
                                                    .as_mut()
                                                    .ok_or_else(|| {
                                                        "dpdk: pinned state shard missing"
                                                            .to_string()
                                                    })?;
                                                guard.set_intercept_to_host_steering(
                                                    service_lane_ready,
                                                );
                                                let out = adapter
                                                    .process_packet_in_place(&mut pkt, guard);
                                                pinned_shard_run_len =
                                                    pinned_shard_run_len.saturating_add(1);
                                                if pinned_shard_run_len >= pin_state_shard_burst {
                                                    pinned_shard_guard = None;
                                                    pinned_shard_idx = None;
                                                    pinned_shard_run_len = 0;
                                                }
                                                out
                                            } else {
                                                let shard =
                                                    shared.get(shard_idx).ok_or_else(|| {
                                                        "dpdk: state shard missing".to_string()
                                                    })?;
                                                let mut guard = match shard.try_lock() {
                                                    Ok(guard) => guard,
                                                    Err(std::sync::TryLockError::Poisoned(_)) => {
                                                        return Err(
                                                            "dpdk: state lock poisoned".to_string()
                                                        );
                                                    }
                                                    Err(std::sync::TryLockError::WouldBlock) => {
                                                        metrics.inc_dp_state_lock_contended();
                                                        let start = Instant::now();
                                                        let guard = shard.lock().map_err(|_| {
                                                            "dpdk: state lock poisoned".to_string()
                                                        })?;
                                                        metrics.observe_dp_state_lock_wait(
                                                            start.elapsed(),
                                                        );
                                                        guard
                                                    }
                                                };
                                                guard.set_intercept_to_host_steering(
                                                    service_lane_ready,
                                                );
                                                adapter
                                                    .process_packet_in_place(&mut pkt, &mut guard)
                                            }
                                        }
                                    } {
                                        match out {
                                            FrameOut::Borrowed(frame) => {
                                                io.send_borrowed_frame(frame)?
                                            }
                                            FrameOut::Owned(frame) => io.send_frame(&frame)?,
                                        }
                                    }
                                    if service_lane_enabled {
                                        adapter.flush_host_frames(&mut io)?;
                                    }
                                    let now = Instant::now();
                                    if packets_since_housekeeping >= housekeeping_interval_packets
                                        || now >= next_housekeeping_at
                                    {
                                        run_dpdk_housekeeping(
                                            worker_id,
                                            false,
                                            service_lane_enabled,
                                            housekeeping_shard_idx,
                                            shared_state.as_ref(),
                                            local_state.as_mut(),
                                            &mut adapter,
                                            &mut io,
                                        )?;
                                        packets_since_housekeeping = 0;
                                        next_housekeeping_at = now + housekeeping_interval;
                                    }
                                    Ok(())
                                })();
                                io.finish_rx_packet();
                                step_result?;
                            }
                        })
                        .map_err(|err| format!("dpdk worker start failed: {err}"))?;
                    handles.push(handle);
                }
                metrics.set_dpdk_init_ok(true);
                for handle in handles {
                    if let Err(err) = handle
                        .join()
                        .map_err(|_| "dpdk worker panicked".to_string())?
                    {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                }
                Ok(())
            }
        }
    }
}
