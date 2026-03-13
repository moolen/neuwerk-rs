use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
use tracing::{info, warn};

use crate::runtime::cli::DataPlaneMode;

use super::affinity::{choose_dpdk_worker_core_ids, cpu_core_count, pin_thread_to_core};
use super::worker_plan::{
    choose_dpdk_worker_plan, dpdk_force_shared_rx_demux, dpdk_lockless_queue_per_worker_enabled,
    dpdk_pin_https_demux_owner, dpdk_service_lane_enabled, env_flag_enabled, flow_steer_payload,
    shard_index_for_packet, shared_demux_owner_for_packet_with_policy, DpdkPerfMode,
    DpdkSingleQueueStrategy, DpdkWorkerMode,
};

#[allow(clippy::too_many_arguments)]
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
    let emit_dhcp = worker_emits_dhcp_housekeeping(worker_id);
    if let Some(shared) = shared_state {
        let shard = shared
            .get(housekeeping_shard_idx)
            .ok_or_else(|| "dpdk: state shard missing".to_string())?;
        let guard = if force {
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
        if emit_dhcp {
            while let Some(out) = adapter.next_dhcp_frame(&guard) {
                io.send_frame(&out)?;
            }
        }
        return Ok(());
    }
    let local = local_state.ok_or_else(|| "dpdk: local state missing".to_string())?;
    if service_lane_enabled {
        adapter.drain_service_lane_egress(local, io)?;
    }
    if emit_dhcp {
        while let Some(out) = adapter.next_dhcp_frame(local) {
            io.send_frame(&out)?;
        }
    }
    Ok(())
}

fn increment_queue_depth(depth: &AtomicUsize) -> usize {
    depth.fetch_add(1, Ordering::AcqRel) + 1
}

fn decrement_queue_depth(depth: &AtomicUsize) -> usize {
    let mut current = depth.load(Ordering::Acquire);
    loop {
        if current == 0 {
            return 0;
        }
        match depth.compare_exchange(current, current - 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return current - 1,
            Err(next) => current = next,
        }
    }
}

fn worker_emits_dhcp_housekeeping(worker_id: usize) -> bool {
    worker_id == 0
}

fn direct_rx_poll_enabled(shared_rx_owner_only: bool, worker_id: usize) -> bool {
    !shared_rx_owner_only || worker_id == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowSteerDispatchResult {
    Dispatched,
    ProcessLocally,
}

fn dispatch_flow_steer_packet(
    flow_steer_tx: Option<&Arc<Vec<std::sync::mpsc::SyncSender<Vec<u8>>>>>,
    owner: usize,
    payload: Vec<u8>,
    worker_id: usize,
    metrics: &controlplane::metrics::Metrics,
    queue_depth: Option<&Arc<AtomicUsize>>,
    dispatch_enabled: &mut bool,
) -> FlowSteerDispatchResult {
    if !*dispatch_enabled {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            metrics.set_dpdk_flow_steer_queue_depth(owner, depth);
        }
        return FlowSteerDispatchResult::ProcessLocally;
    }

    let Some(flow_steer_tx) = flow_steer_tx else {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            metrics.set_dpdk_flow_steer_queue_depth(owner, depth);
        }
        *dispatch_enabled = false;
        metrics.inc_dpdk_flow_steer_fail_open_event(worker_id, "tx_missing");
        warn!(
            worker_id,
            owner, "dpdk flow steer tx missing; disabling dispatch and failing open"
        );
        return FlowSteerDispatchResult::ProcessLocally;
    };
    let Some(tx) = flow_steer_tx.get(owner) else {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            metrics.set_dpdk_flow_steer_queue_depth(owner, depth);
        }
        *dispatch_enabled = false;
        metrics.inc_dpdk_flow_steer_fail_open_event(worker_id, "owner_missing");
        warn!(
            worker_id,
            owner, "dpdk flow steer owner sender missing; disabling dispatch and failing open"
        );
        return FlowSteerDispatchResult::ProcessLocally;
    };

    let payload_len = payload.len();
    let wait_start = Instant::now();
    if tx.send(payload).is_err() {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            metrics.set_dpdk_flow_steer_queue_depth(owner, depth);
        }
        *dispatch_enabled = false;
        metrics.inc_dpdk_flow_steer_fail_open_event(worker_id, "dispatch_failed");
        warn!(
            worker_id,
            owner, "dpdk flow steer dispatch failed; disabling dispatch and failing open"
        );
        return FlowSteerDispatchResult::ProcessLocally;
    }

    metrics.observe_dpdk_flow_steer_queue_wait(owner, wait_start.elapsed());
    metrics.inc_dpdk_flow_steer_dispatch(worker_id, owner);
    metrics.add_dpdk_flow_steer_bytes(worker_id, owner, payload_len);
    FlowSteerDispatchResult::Dispatched
}

struct SharedDpdkIo {
    io: Arc<Mutex<DpdkIo>>,
    metrics: controlplane::metrics::Metrics,
}

impl SharedDpdkIo {
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, DpdkIo>, String> {
        match self.io.try_lock() {
            Ok(guard) => Ok(guard),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err("dpdk: shared io lock poisoned".to_string())
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                self.metrics.inc_dpdk_shared_io_lock_contended();
                let start = Instant::now();
                let guard = self
                    .io
                    .lock()
                    .map_err(|_| "dpdk: shared io lock poisoned".to_string())?;
                self.metrics
                    .observe_dpdk_shared_io_lock_wait(start.elapsed());
                Ok(guard)
            }
        }
    }
}

enum DpdkWorkerIo {
    Dedicated(DpdkIo),
    Shared(SharedDpdkIo),
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

#[allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::redundant_locals
)]
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
    shared_intercept_demux: Arc<SharedInterceptDemuxState>,
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
        info!("dpdk perf mode aggressive enabled; disabling dataplane state metrics/audit/wiretap");
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
            info!(perf_mode = ?dpdk_perf_mode, "dpdk perf mode selected");
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
                && !env_flag_enabled("NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER");
            if azure_reliability_guard {
                warn!(
                    requested_workers,
                    "dpdk azure reliability guard active; forcing single worker (set NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=1 to override)"
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
                info!(
                    requested_workers_target,
                    requested_workers, "dpdk cpuset limited requested workers"
                );
            }
            info!(
                requested_workers_raw = %std::env::var("NEUWERK_DPDK_WORKERS")
                    .unwrap_or_else(|_| "unset".to_string()),
                cpu_cores = max_workers,
                requested_workers,
                core_ids = %worker_core_list,
                "dpdk worker configuration"
            );
            let force_shared_rx_demux = dpdk_force_shared_rx_demux();
            if force_shared_rx_demux && requested_workers > 1 {
                info!(
                    "dpdk shared rx demux forced; skipping queue probe and using a single shared rx queue"
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
                info!(
                    strategy = strategy_label,
                    requested_workers,
                    worker_count = plan.worker_count,
                    "dpdk single-queue strategy selected"
                );
            }
            if plan.worker_count < plan.requested {
                info!(
                    worker_count = plan.worker_count,
                    requested_workers = plan.requested,
                    "dpdk reducing worker threads due to device queue limit"
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::SharedRxDemux) {
                info!(
                    effective_queues = plan.effective_queues,
                    worker_count = plan.worker_count,
                    "dpdk single rx queue detected; enabling shared-rx software demux"
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::Single) {
                let iface = data_plane_iface.clone();
                let core_id = worker_core_ids.first().copied().unwrap_or(0);
                if let Err(err) = pin_thread_to_core(core_id) {
                    warn!(core_id, error = %err, "dpdk single worker core pin failed");
                } else {
                    info!(core_id, "dpdk single worker pinned to core");
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
                let pin_https_demux_owner = dpdk_pin_https_demux_owner();
                let service_lane_enabled = dpdk_service_lane_enabled(dpdk_perf_mode);
                let lockless_qpw =
                    perf_aggressive && queue_per_worker && dpdk_lockless_queue_per_worker_enabled();
                info!(worker_count, mode = ?plan.mode, "dpdk starting worker threads");
                if shared_rx_demux {
                    info!(
                        pin_https_demux_owner,
                        "dpdk shared demux HTTPS owner pin configuration"
                    );
                }
                if !service_lane_enabled {
                    warn!(
                        "dpdk service lane disabled via NEUWERK_DPDK_DISABLE_SERVICE_LANE; TLS intercept steering is bypassed"
                    );
                }
                if lockless_qpw {
                    info!("dpdk lockless queue-per-worker enabled");
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
                info!(
                    housekeeping_interval_packets,
                    housekeeping_interval_us, "dpdk housekeeping interval configured"
                );
                let pin_state_shard_guard = std::env::var("NEUWERK_DPDK_PIN_STATE_SHARD_GUARD")
                    .map(|val| !matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
                    .unwrap_or(false);
                let pin_state_shard_burst = std::env::var("NEUWERK_DPDK_PIN_STATE_SHARD_BURST")
                    .ok()
                    .and_then(|val| val.parse::<u32>().ok())
                    .filter(|val| *val > 0)
                    .unwrap_or(64);
                info!(
                    pin_state_shard_guard,
                    pin_state_shard_burst, "dpdk state shard guard configuration"
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
                info!(shard_count, "dpdk state shard count");
                let base_state = state;
                let (shared_state, mut worker_local_states) = if lockless_qpw {
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
                // Optional owner-only RX polling for shared-demux + shared-IO mode.
                // Disabled by default; enable with NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=true.
                let shared_rx_owner_only = shared_io.is_some()
                    && shared_rx_demux
                    && env_flag_enabled("NEUWERK_DPDK_SHARED_RX_OWNER_ONLY");
                info!(shared_rx_owner_only, "dpdk shared rx owner-only polling");
                let enable_flow_steer = shared_rx_demux;
                let (flow_steer_txs, mut flow_steer_rxs, flow_steer_depths) = if enable_flow_steer {
                    let mut txs = Vec::with_capacity(worker_count);
                    let mut rxs = Vec::with_capacity(worker_count);
                    let mut depths = Vec::with_capacity(worker_count);
                    for _ in 0..worker_count {
                        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
                        txs.push(tx);
                        rxs.push(Some(rx));
                        depths.push(Arc::new(AtomicUsize::new(0)));
                    }
                    (Some(Arc::new(txs)), Some(rxs), Some(Arc::new(depths)))
                } else {
                    (None, None, None)
                };
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
                    let flow_steer_depth = flow_steer_depths
                        .as_ref()
                        .and_then(|depths| depths.get(worker_id))
                        .cloned();
                    let mut flow_steer_rx = flow_steer_rxs
                        .as_mut()
                        .and_then(|rxs| rxs.get_mut(worker_id))
                        .and_then(Option::take);
                    let flow_steer_depths = flow_steer_depths.clone();
                    let housekeeping_interval_packets = housekeeping_interval_packets;
                    let housekeeping_interval = housekeeping_interval;
                    let pin_state_shard_guard = pin_state_shard_guard;
                    let pin_state_shard_burst = pin_state_shard_burst;
                    let lockless_qpw = lockless_qpw;
                    let service_lane_enabled = service_lane_enabled;
                    let shard_count = shard_count;
                    let pin_https_demux_owner = pin_https_demux_owner;
                    let allow_direct_rx = direct_rx_poll_enabled(shared_rx_owner_only, worker_id);
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
                                warn!(worker_id, core_id, error = %err, "dpdk worker core pin failed");
                            } else {
                                info!(worker_id, core_id, "dpdk worker pinned to core");
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
                                DpdkWorkerIo::Shared(SharedDpdkIo {
                                    io: shared,
                                    metrics: metrics.clone(),
                                })
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
                            let mut flow_steer_dispatch_enabled = flow_steer_tx.is_some();
                            let mut packets_since_housekeeping = 0u64;
                            let mut next_housekeeping_at = Instant::now() + housekeeping_interval;
                            loop {
                                let service_lane_ready = if !service_lane_enabled {
                                    false
                                } else {
                                    adapter.service_lane_ready()
                                };
                                let mut from_steer_queue = false;
                                let mut received_from_io = false;
                                if let Some(rx) = flow_steer_rx.as_ref() {
                                    match rx.try_recv() {
                                        Ok(frame) => {
                                            if let Some(queue_depth) = flow_steer_depth.as_ref() {
                                                let depth = decrement_queue_depth(queue_depth);
                                                metrics.set_dpdk_flow_steer_queue_depth(
                                                    worker_id,
                                                    depth,
                                                );
                                            }
                                            pkt = Packet::new(frame);
                                            from_steer_queue = true;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            flow_steer_rx = None;
                                            metrics.inc_dpdk_flow_steer_fail_open_event(
                                                worker_id,
                                                "rx_disconnected",
                                            );
                                            warn!(
                                                worker_id,
                                                "dpdk flow steer rx disconnected; failing open to local processing"
                                            );
                                        }
                                    }
                                }
                                if !from_steer_queue {
                                    if !allow_direct_rx {
                                        io.flush()?;
                                        if service_lane_ready {
                                            adapter.flush_host_frames(&mut io)?;
                                        }
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
                                        std::thread::yield_now();
                                        continue;
                                    }
                                    let n = io.recv_packet(&mut pkt).map_err(|err| {
                                        format!("dpdk worker {worker_id} recv failed: {err}")
                                    })?;
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
                                        if service_lane_ready {
                                            adapter.flush_host_frames(&mut io)?;
                                        }
                                        packets_since_housekeeping = 0;
                                        next_housekeeping_at =
                                            Instant::now() + housekeeping_interval;
                                        continue;
                                    }
                                    received_from_io = true;
                                    if flow_steer_tx.is_some() {
                                        let owner = shared_demux_owner_for_packet_with_policy(
                                            &pkt,
                                            shard_count,
                                            worker_count,
                                            pin_https_demux_owner,
                                        );
                                        if owner != worker_id && flow_steer_dispatch_enabled {
                                            let payload = flow_steer_payload(&mut pkt);
                                            let flow_steer_queue_depth = flow_steer_depths
                                                .as_ref()
                                                .and_then(|depths| depths.get(owner))
                                                .cloned();
                                            if let Some(queue_depth) =
                                                flow_steer_queue_depth.as_ref()
                                            {
                                                let depth = increment_queue_depth(queue_depth);
                                                metrics.set_dpdk_flow_steer_queue_depth(
                                                    owner,
                                                    depth,
                                                );
                                            }
                                            if matches!(
                                                dispatch_flow_steer_packet(
                                                    flow_steer_tx.as_ref(),
                                                    owner,
                                                    payload,
                                                    worker_id,
                                                    &metrics,
                                                    flow_steer_queue_depth.as_ref(),
                                                    &mut flow_steer_dispatch_enabled,
                                                ),
                                                FlowSteerDispatchResult::Dispatched
                                            ) {
                                                io.finish_rx_packet();
                                                continue;
                                            }
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
                                    if service_lane_ready {
                                        adapter.flush_host_frames(&mut io)?;
                                    }
                                    if !allow_direct_rx {
                                        io.flush()?;
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
                                if received_from_io {
                                    io.finish_rx_packet();
                                }
                                if let Err(err) = step_result {
                                    warn!(worker_id, error = %err, "dpdk worker exiting on error");
                                    return Err(err);
                                }
                            }
                        })
                        .map_err(|err| format!("dpdk worker start failed: {err}"))?;
                    handles.push(handle);
                }
                metrics.set_dpdk_init_ok(true);
                for (worker_id, handle) in handles.into_iter().enumerate() {
                    if let Err(err) = handle
                        .join()
                        .map_err(|_| "dpdk worker panicked".to_string())?
                    {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(format!("dpdk worker {worker_id} failed: {err}"));
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dispatch_flow_steer_packet_success_keeps_dispatch_enabled() {
        let metrics = controlplane::metrics::Metrics::new().expect("metrics");
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
        let txs = Arc::new(vec![tx]);
        let queue_depth = Arc::new(AtomicUsize::new(1));
        let mut dispatch_enabled = true;

        let result = dispatch_flow_steer_packet(
            Some(&txs),
            0,
            vec![1, 2, 3],
            1,
            &metrics,
            Some(&queue_depth),
            &mut dispatch_enabled,
        );

        assert_eq!(result, FlowSteerDispatchResult::Dispatched);
        assert!(dispatch_enabled);
        assert_eq!(queue_depth.load(Ordering::Acquire), 1);
        assert_eq!(rx.recv().expect("steered payload"), vec![1, 2, 3]);
    }

    #[test]
    fn dispatch_flow_steer_packet_send_failure_fails_open() {
        let metrics = controlplane::metrics::Metrics::new().expect("metrics");
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(8);
        drop(rx);
        let txs = Arc::new(vec![tx]);
        let queue_depth = Arc::new(AtomicUsize::new(1));
        let mut dispatch_enabled = true;

        let result = dispatch_flow_steer_packet(
            Some(&txs),
            0,
            vec![9, 8, 7],
            2,
            &metrics,
            Some(&queue_depth),
            &mut dispatch_enabled,
        );

        assert_eq!(result, FlowSteerDispatchResult::ProcessLocally);
        assert!(!dispatch_enabled);
        assert_eq!(queue_depth.load(Ordering::Acquire), 0);

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "dpdk_flow_steer_fail_open_events_total",
                &[("worker", "2"), ("event", "dispatch_failed")]
            ),
            1.0
        );
    }

    #[test]
    fn direct_rx_poll_enabled_owner_only_allows_only_worker_zero() {
        assert!(direct_rx_poll_enabled(true, 0));
        assert!(!direct_rx_poll_enabled(true, 1));
        assert!(!direct_rx_poll_enabled(true, 2));
        assert!(direct_rx_poll_enabled(false, 0));
        assert!(direct_rx_poll_enabled(false, 1));
    }

    #[test]
    fn worker_emits_dhcp_housekeeping_only_on_worker_zero() {
        assert!(worker_emits_dhcp_housekeeping(0));
        assert!(!worker_emits_dhcp_housekeeping(1));
        assert!(!worker_emits_dhcp_housekeeping(2));
    }
}
