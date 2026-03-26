use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crossbeam_queue::ArrayQueue;
use neuwerk::dataplane::policy::{
    PolicySnapshot, SharedExactSourceGroupIndex, SharedPolicySnapshot,
};
#[cfg(feature = "dpdk")]
use neuwerk::dataplane::DpdkTransferredRxPacket;
use neuwerk::dataplane::engine::EngineRuntimeConfig;
use neuwerk::dataplane::{
    AuditEmitter, DataplaneConfigStore, DhcpRx, DhcpTx, DpdkAdapter, DpdkIo, DrainControl,
    EngineState, FrameIo, FrameOut, OverlayConfig, Packet, SharedArpState,
    SharedInterceptDemuxState, SnatMode, SoftAdapter, WiretapEmitter,
};
use neuwerk::metrics::{
    current_dpdk_worker_id, set_current_dpdk_worker_id, DpdkFlowSteerMetricHandles, Metrics,
};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use crate::runtime::cli::DataPlaneMode;
use crate::runtime::config::{RuntimeDpdkConfig, RuntimeDpdkPerfMode, RuntimeDpdkSingleQueueMode};
use neuwerk::support::runtime_knobs::{current_runtime_knobs, CloudProvider};

use super::affinity::{choose_dpdk_worker_core_ids, cpu_core_count, pin_thread_to_core};
use super::worker_plan::{
    choose_dpdk_worker_plan, flow_steer_payload, service_lane_enabled_with_override,
    shard_index_for_packet, shared_demux_owner_for_packet_with_policy, DpdkPerfMode,
    DpdkSingleQueueStrategy, DpdkWorkerMode,
};

#[allow(clippy::too_many_arguments)]
fn run_dpdk_housekeeping(
    worker_id: usize,
    force: bool,
    service_lane_enabled: bool,
    housekeeping_shard_idx: usize,
    metrics: &Metrics,
    detailed_lock_observability: bool,
    shared_state: Option<&std::sync::Arc<Vec<std::sync::Mutex<EngineState>>>>,
    local_state: Option<&mut EngineState>,
    adapter: &mut DpdkAdapter,
    io: &mut impl FrameIo,
) -> Result<(), String> {
    let emit_dhcp = worker_emits_dhcp_housekeeping(worker_id);
    if let Some(shared) = shared_state {
        let shard = shared
            .get(housekeeping_shard_idx)
            .ok_or_else(|| "dpdk: state shard missing".to_string())?;
        let guard = if force {
            lock_state_shard_blocking(
                shard,
                worker_id,
                housekeeping_shard_idx,
                metrics,
                detailed_lock_observability,
            )?
        } else {
            match try_lock_state_shard(
                shard,
                worker_id,
                housekeeping_shard_idx,
                metrics,
                detailed_lock_observability,
            )? {
                Some(guard) => guard,
                None => return Ok(()),
            }
        };
        let mut guard = guard;
        guard.run_housekeeping();
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
    local.run_housekeeping();
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

struct ObservedStateGuard<'a> {
    guard: std::sync::MutexGuard<'a, EngineState>,
    metrics: Metrics,
    worker_id: usize,
    shard_id: usize,
    acquired_at: Option<Instant>,
    detailed_lock_observability: bool,
}

impl std::ops::Deref for ObservedStateGuard<'_> {
    type Target = EngineState;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl std::ops::DerefMut for ObservedStateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for ObservedStateGuard<'_> {
    fn drop(&mut self) {
        if self.detailed_lock_observability {
            let Some(acquired_at) = self.acquired_at else {
                return;
            };
            self.metrics.observe_dp_state_lock_hold_detailed(
                self.worker_id,
                self.shard_id,
                acquired_at.elapsed(),
            );
        }
    }
}

fn observed_state_guard<'a>(
    guard: std::sync::MutexGuard<'a, EngineState>,
    worker_id: usize,
    shard_id: usize,
    metrics: &Metrics,
    detailed_lock_observability: bool,
) -> ObservedStateGuard<'a> {
    ObservedStateGuard {
        guard,
        metrics: metrics.clone(),
        worker_id,
        shard_id,
        acquired_at: detailed_lock_observability.then(Instant::now),
        detailed_lock_observability,
    }
}

fn try_lock_state_shard<'a>(
    shard: &'a std::sync::Mutex<EngineState>,
    worker_id: usize,
    shard_id: usize,
    metrics: &Metrics,
    detailed_lock_observability: bool,
) -> Result<Option<ObservedStateGuard<'a>>, String> {
    match shard.try_lock() {
        Ok(guard) => Ok(Some(observed_state_guard(
            guard,
            worker_id,
            shard_id,
            metrics,
            detailed_lock_observability,
        ))),
        Err(std::sync::TryLockError::Poisoned(_)) => Err("dpdk: state lock poisoned".to_string()),
        Err(std::sync::TryLockError::WouldBlock) => Ok(None),
    }
}

fn lock_state_shard_blocking<'a>(
    shard: &'a std::sync::Mutex<EngineState>,
    worker_id: usize,
    shard_id: usize,
    metrics: &Metrics,
    detailed_lock_observability: bool,
) -> Result<ObservedStateGuard<'a>, String> {
    match shard.try_lock() {
        Ok(guard) => Ok(observed_state_guard(
            guard,
            worker_id,
            shard_id,
            metrics,
            detailed_lock_observability,
        )),
        Err(std::sync::TryLockError::Poisoned(_)) => Err("dpdk: state lock poisoned".to_string()),
        Err(std::sync::TryLockError::WouldBlock) => {
            metrics.inc_dp_state_lock_contended();
            if detailed_lock_observability {
                metrics.inc_dp_state_lock_contended_detailed(worker_id, shard_id);
            }
            let start = Instant::now();
            let guard = shard
                .lock()
                .map_err(|_| "dpdk: state lock poisoned".to_string())?;
            let wait = start.elapsed();
            metrics.observe_dp_state_lock_wait(wait);
            if detailed_lock_observability {
                metrics.observe_dp_state_lock_wait_detailed(worker_id, shard_id, wait);
            }
            Ok(observed_state_guard(
                guard,
                worker_id,
                shard_id,
                metrics,
                detailed_lock_observability,
            ))
        }
    }
}

fn direct_rx_poll_enabled(shared_rx_owner_only: bool, worker_id: usize) -> bool {
    !shared_rx_owner_only || worker_id == 0
}

fn shared_rx_owner_only_enabled(
    shared_io_present: bool,
    shared_rx_demux: bool,
    configured: bool,
) -> bool {
    if !shared_io_present || !shared_rx_demux {
        return false;
    }
    configured
}

fn requested_dpdk_workers_target(max_workers: usize, configured: Option<usize>) -> usize {
    let max_workers = max_workers.max(1);
    if let Some(value) = configured {
        return value.max(1).min(max_workers);
    }
    if max_workers <= 2 {
        max_workers
    } else {
        max_workers - 1
    }
}

#[derive(Debug)]
enum FlowSteerDispatchResult {
    Dispatched,
    ProcessLocally(FlowSteerPayload),
}

#[derive(Debug)]
enum FlowSteerPayload {
    Bytes(Vec<u8>),
    #[cfg(feature = "dpdk")]
    DpdkRx(DpdkTransferredRxPacket),
}

impl FlowSteerPayload {
    fn len(&self) -> usize {
        match self {
            FlowSteerPayload::Bytes(frame) => frame.len(),
            #[cfg(feature = "dpdk")]
            FlowSteerPayload::DpdkRx(packet) => packet.len(),
        }
    }
}

type FlowSteerQueue = Arc<ArrayQueue<FlowSteerPayload>>;
type FlowSteerQueues = Arc<Vec<FlowSteerQueue>>;

fn dispatch_flow_steer_packet(
    flow_steer_queues: Option<&FlowSteerQueues>,
    owner: usize,
    payload: FlowSteerPayload,
    worker_id: usize,
    queue_depth: Option<&Arc<AtomicUsize>>,
    flow_steer_metrics: Option<&DpdkFlowSteerMetricHandles>,
    dispatch_enabled: &mut bool,
) -> FlowSteerDispatchResult {
    if !*dispatch_enabled {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            if let Some(metrics) = flow_steer_metrics {
                metrics.set_queue_depth(owner, depth);
            }
        }
        return FlowSteerDispatchResult::ProcessLocally(payload);
    }

    let Some(flow_steer_queues) = flow_steer_queues else {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            if let Some(metrics) = flow_steer_metrics {
                metrics.set_queue_depth(owner, depth);
            }
        }
        *dispatch_enabled = false;
        if let Some(metrics) = flow_steer_metrics {
            metrics.inc_fail_open_tx_missing(worker_id);
        }
        warn!(
            worker_id,
            owner, "dpdk flow steer tx missing; disabling dispatch and failing open"
        );
        return FlowSteerDispatchResult::ProcessLocally(payload);
    };
    let Some(queue) = flow_steer_queues.get(owner) else {
        if let Some(queue_depth) = queue_depth {
            let depth = decrement_queue_depth(queue_depth);
            if let Some(metrics) = flow_steer_metrics {
                metrics.set_queue_depth(owner, depth);
            }
        }
        *dispatch_enabled = false;
        if let Some(metrics) = flow_steer_metrics {
            metrics.inc_fail_open_owner_missing(worker_id);
        }
        warn!(
            worker_id,
            owner, "dpdk flow steer owner sender missing; disabling dispatch and failing open"
        );
        return FlowSteerDispatchResult::ProcessLocally(payload);
    };

    let payload_len = payload.len();
    let wait_start = Instant::now();
    let mut payload = payload;
    loop {
        match queue.push(payload) {
            Ok(()) => break,
            Err(returned) => {
                payload = returned;
                std::hint::spin_loop();
                std::thread::yield_now();
            }
        }
    }

    if let Some(metrics) = flow_steer_metrics {
        metrics.observe_dispatch(worker_id, owner, payload_len, wait_start.elapsed());
    }
    FlowSteerDispatchResult::Dispatched
}

struct SharedDpdkIo {
    io: Arc<Mutex<DpdkIo>>,
    metrics: Metrics,
}

struct ObservedSharedDpdkIoGuard<'a> {
    guard: std::sync::MutexGuard<'a, DpdkIo>,
    metrics: Metrics,
    worker_id: Option<usize>,
    acquired_at: Instant,
}

impl std::ops::Deref for ObservedSharedDpdkIoGuard<'_> {
    type Target = DpdkIo;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl std::ops::DerefMut for ObservedSharedDpdkIoGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for ObservedSharedDpdkIoGuard<'_> {
    fn drop(&mut self) {
        if let Some(worker_id) = self.worker_id {
            self.metrics
                .observe_dpdk_shared_io_lock_hold_worker(worker_id, self.acquired_at.elapsed());
        }
    }
}

impl SharedDpdkIo {
    fn lock(&self) -> Result<ObservedSharedDpdkIoGuard<'_>, String> {
        let worker_id = current_dpdk_worker_id();
        match self.io.try_lock() {
            Ok(guard) => Ok(ObservedSharedDpdkIoGuard {
                guard,
                metrics: self.metrics.clone(),
                worker_id,
                acquired_at: Instant::now(),
            }),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err("dpdk: shared io lock poisoned".to_string())
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if let Some(worker_id) = worker_id {
                    self.metrics
                        .inc_dpdk_shared_io_lock_contended_worker(worker_id);
                } else {
                    self.metrics.inc_dpdk_shared_io_lock_contended();
                }
                let start = Instant::now();
                let guard = self
                    .io
                    .lock()
                    .map_err(|_| "dpdk: shared io lock poisoned".to_string())?;
                if let Some(worker_id) = worker_id {
                    self.metrics
                        .observe_dpdk_shared_io_lock_wait_worker(worker_id, start.elapsed());
                } else {
                    self.metrics
                        .observe_dpdk_shared_io_lock_wait(start.elapsed());
                }
                Ok(ObservedSharedDpdkIoGuard {
                    guard,
                    metrics: self.metrics.clone(),
                    worker_id,
                    acquired_at: Instant::now(),
                })
            }
        }
    }
}

enum LockedDpdkWorkerIo<'a> {
    Dedicated(&'a mut DpdkIo),
    Shared(ObservedSharedDpdkIoGuard<'a>),
}

impl FrameIo for LockedDpdkWorkerIo<'_> {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.recv_frame(buf),
            LockedDpdkWorkerIo::Shared(io) => io.recv_frame(buf),
        }
    }

    fn recv_packet(&mut self, pkt: &mut Packet) -> Result<usize, String> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.recv_packet(pkt),
            LockedDpdkWorkerIo::Shared(io) => io.recv_packet(pkt),
        }
    }

    fn finish_rx_packet(&mut self) {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.finish_rx_packet(),
            LockedDpdkWorkerIo::Shared(io) => io.finish_rx_packet(),
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.send_frame(frame),
            LockedDpdkWorkerIo::Shared(io) => io.send_frame(frame),
        }
    }

    fn send_borrowed_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.send_borrowed_frame(frame),
            LockedDpdkWorkerIo::Shared(io) => io.send_borrowed_frame(frame),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.flush(),
            LockedDpdkWorkerIo::Shared(io) => io.flush(),
        }
    }

    fn mac(&self) -> Option<[u8; 6]> {
        match self {
            LockedDpdkWorkerIo::Dedicated(io) => io.mac(),
            LockedDpdkWorkerIo::Shared(io) => io.mac(),
        }
    }
}

impl LockedDpdkWorkerIo<'_> {
    fn take_flow_steer_payload(&mut self, pkt: &mut Packet) -> FlowSteerPayload {
        #[cfg(feature = "dpdk")]
        {
            let transferred = match self {
                LockedDpdkWorkerIo::Dedicated(io) => io.take_rx_packet_for_transfer(pkt),
                LockedDpdkWorkerIo::Shared(io) => io.take_rx_packet_for_transfer(pkt),
            };
            if let Some(packet) = transferred {
                return FlowSteerPayload::DpdkRx(packet);
            }
        }
        FlowSteerPayload::Bytes(flow_steer_payload(pkt))
    }

    fn restore_flow_steer_payload(&mut self, payload: FlowSteerPayload) -> Result<Packet, String> {
        match payload {
            FlowSteerPayload::Bytes(frame) => Ok(Packet::new(frame)),
            #[cfg(feature = "dpdk")]
            FlowSteerPayload::DpdkRx(packet) => match self {
                LockedDpdkWorkerIo::Dedicated(io) => io.adopt_transferred_rx_packet(packet),
                LockedDpdkWorkerIo::Shared(io) => io.adopt_transferred_rx_packet(packet),
            },
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

    fn lock_io(&mut self) -> Result<LockedDpdkWorkerIo<'_>, String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => Ok(LockedDpdkWorkerIo::Dedicated(io)),
            DpdkWorkerIo::Shared(io) => io.lock().map(LockedDpdkWorkerIo::Shared),
        }
    }
}

impl FrameIo for DpdkWorkerIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        self.lock_io()?.recv_frame(buf)
    }

    fn recv_packet(&mut self, pkt: &mut Packet) -> Result<usize, String> {
        self.lock_io()?.recv_packet(pkt)
    }

    fn finish_rx_packet(&mut self) {
        if let Ok(mut io) = self.lock_io() {
            io.finish_rx_packet();
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.lock_io()?.send_frame(frame)
    }

    fn send_borrowed_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.lock_io()?.send_borrowed_frame(frame)
    }

    fn flush(&mut self) -> Result<(), String> {
        self.lock_io()?.flush()
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
    dpdk: RuntimeDpdkConfig,
    idle_timeout_secs: u64,
    engine_runtime: EngineRuntimeConfig,
    policy: Arc<RwLock<PolicySnapshot>>,
    policy_snapshot: SharedPolicySnapshot,
    exact_source_group_index: SharedExactSourceGroupIndex,
    policy_applied_generation: Arc<AtomicU64>,
    service_policy_applied_generation: Arc<AtomicU64>,
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
    metrics: Metrics,
) -> Result<(), String> {
    let detailed_lock_observability = engine_runtime.detailed_observability;
    let observer_policy = policy_snapshot.clone();
    let observer_applied = policy_applied_generation.clone();
    std::thread::Builder::new()
        .name("policy-generation-observer".to_string())
        .spawn(move || {
            let mut last = observer_applied.load(Ordering::Acquire);
            loop {
                let generation = observer_policy.load().generation();
                if generation != last {
                    observer_applied.store(generation, Ordering::Release);
                    last = generation;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
        .map_err(|err| format!("policy observer start failed: {err}"))?;
    let mut state = EngineState::new_with_idle_timeout_and_config(
        policy,
        internal_net,
        internal_prefix,
        public_ip,
        data_port,
        idle_timeout_secs,
        engine_runtime,
    );
    state.set_policy_snapshot(policy_snapshot);
    state.set_exact_source_policy_index(exact_source_group_index);
    state.set_snat_mode(snat_mode);
    state.set_overlay_config(overlay);
    state.set_dns_target_ips(dns_target_ips);
    state.set_dataplane_config(dataplane_config);
    state.set_policy_applied_generation(policy_applied_generation.clone());
    state.set_service_policy_applied_generation(service_policy_applied_generation);
    if let Some(control) = drain_control {
        state.set_drain_control(control);
    }
    let dpdk_perf_mode = if matches!(data_plane_mode, DataPlaneMode::Dpdk) {
        match dpdk.perf_mode {
            RuntimeDpdkPerfMode::Standard => DpdkPerfMode::Standard,
            RuntimeDpdkPerfMode::Aggressive => DpdkPerfMode::Aggressive,
        }
    } else {
        DpdkPerfMode::Standard
    };
    let perf_aggressive = matches!(dpdk_perf_mode, DpdkPerfMode::Aggressive);
    state.set_metrics(metrics.clone());
    if perf_aggressive {
        info!("dpdk perf mode aggressive enabled; disabling dataplane audit/wiretap");
    } else {
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
            let requested_workers_target = requested_dpdk_workers_target(max_workers, dpdk.workers);
            let requested_workers_raw = dpdk
                .workers
                .map(|value| value.to_string())
                .unwrap_or_else(|| "auto".to_string());
            let mut worker_core_ids = if dpdk.core_ids.is_empty() {
                choose_dpdk_worker_core_ids(requested_workers_target, max_workers.max(1))
            } else {
                let mut ids = dpdk.core_ids.clone();
                ids.truncate(requested_workers_target);
                ids
            };
            if worker_core_ids.is_empty() {
                worker_core_ids.push(0);
            }
            let mut requested_workers = requested_workers_target.min(worker_core_ids.len()).max(1);
            let running_on_azure = current_runtime_knobs().cloud_provider == CloudProvider::Azure;
            let azure_reliability_guard = running_on_azure
                && requested_workers > 1
                && !dpdk.allow_azure_multiworker;
            if azure_reliability_guard {
                warn!(
                    requested_workers,
                    "dpdk azure reliability guard active; forcing single worker"
                );
                requested_workers = 1;
            }
            // Azure D8-class failsafe/tap datapaths still crash during startup once the worker
            // count rises above 4. Keep the default below that cliff on 8-vCPU Azure shapes unless
            // the user explicitly pins a lower value.
            if running_on_azure && max_workers == 8 && requested_workers > 4 {
                warn!(
                    requested_workers,
                    capped_workers = 4,
                    "dpdk azure D8 worker cap active; limiting worker count to avoid known startup crash"
                );
                requested_workers = 4;
            }
            worker_core_ids.truncate(requested_workers);
            let worker_core_list = worker_core_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(",");
            if requested_workers_target > requested_workers {
                info!(
                    requested_workers_target,
                    requested_workers, "dpdk cpuset limited requested workers"
                );
            }
            info!(
                requested_workers_raw,
                cpu_cores = max_workers,
                requested_workers,
                core_ids = %worker_core_list,
                "dpdk worker configuration"
            );
            let force_shared_rx_demux = dpdk.force_shared_rx_demux;
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
            let single_queue_strategy = match dpdk.single_queue_mode {
                RuntimeDpdkSingleQueueMode::Demux => DpdkSingleQueueStrategy::SharedDemux,
                RuntimeDpdkSingleQueueMode::SingleWorker => DpdkSingleQueueStrategy::SingleWorker,
            };
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
                set_current_dpdk_worker_id(Some(0));
                adapter.run_with_io(&mut state, &mut io)
            } else {
                let worker_count = plan.worker_count;
                let queue_per_worker = matches!(plan.mode, DpdkWorkerMode::QueuePerWorker);
                let shared_rx_demux = matches!(plan.mode, DpdkWorkerMode::SharedRxDemux);
                let pin_https_demux_owner = dpdk.pin_https_demux_owner;
                let service_lane_enabled =
                    service_lane_enabled_with_override(dpdk_perf_mode, dpdk.disable_service_lane);
                let lockless_qpw =
                    perf_aggressive && queue_per_worker && dpdk.lockless_queue_per_worker;
                info!(worker_count, mode = ?plan.mode, "dpdk starting worker threads");
                if shared_rx_demux {
                    info!(
                        pin_https_demux_owner,
                        "dpdk shared demux HTTPS owner pin configuration"
                    );
                }
                if !service_lane_enabled {
                    warn!(
                        "dpdk service lane disabled; TLS intercept steering is bypassed"
                    );
                }
                if lockless_qpw {
                    info!("dpdk lockless queue-per-worker enabled");
                }
                let housekeeping_interval_packets = dpdk.housekeeping_interval_packets;
                let housekeeping_interval_us = dpdk.housekeeping_interval_us;
                let housekeeping_interval = Duration::from_micros(housekeeping_interval_us);
                info!(
                    housekeeping_interval_packets,
                    housekeeping_interval_us, "dpdk housekeeping interval configured"
                );
                let pin_state_shard_guard = dpdk.pin_state_shard_guard;
                let pin_state_shard_burst = dpdk.pin_state_shard_burst;
                info!(
                    pin_state_shard_guard,
                    pin_state_shard_burst, "dpdk state shard guard configuration"
                );
                info!(
                    detailed_lock_observability,
                    "dpdk detailed lock observability configuration"
                );
                let owner_local_state = lockless_qpw || shared_rx_demux;
                let shard_count = if owner_local_state {
                    worker_count
                } else {
                    dpdk.state_shards.unwrap_or(worker_count).max(1)
                };
                info!(shard_count, "dpdk state shard count");
                let base_state = state;
                let (shared_state, mut worker_local_states) = if owner_local_state {
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
                // Shared-I/O plus software demux contends heavily if every worker polls RX.
                let shared_rx_owner_only = shared_rx_owner_only_enabled(
                    shared_io.is_some(),
                    shared_rx_demux,
                    dpdk.shared_rx_owner_only,
                );
                info!(shared_rx_owner_only, "dpdk shared rx owner-only polling");
                let enable_flow_steer = shared_rx_demux;
                let (flow_steer_queues, flow_steer_depths) = if enable_flow_steer {
                    let mut queues = Vec::with_capacity(worker_count);
                    let mut depths = Vec::with_capacity(worker_count);
                    for _ in 0..worker_count {
                        queues.push(Arc::new(ArrayQueue::new(1024)));
                        depths.push(Arc::new(AtomicUsize::new(0)));
                    }
                    (Some(Arc::new(queues)), Some(Arc::new(depths)))
                } else {
                    (None, None)
                };
                let flow_steer_metrics = if enable_flow_steer {
                    Some(Arc::new(metrics.bind_dpdk_flow_steer_metrics(worker_count)))
                } else {
                    None
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
                    let flow_steer_queues = flow_steer_queues.clone();
                    let flow_steer_depth = flow_steer_depths
                        .as_ref()
                        .and_then(|depths| depths.get(worker_id))
                        .cloned();
                    let flow_steer_queue = flow_steer_queues
                        .as_ref()
                        .and_then(|queues| queues.get(worker_id))
                        .cloned();
                    let flow_steer_depths = flow_steer_depths.clone();
                    let flow_steer_metrics = flow_steer_metrics.clone();
                    let housekeeping_interval_packets = housekeeping_interval_packets;
                    let housekeeping_interval = housekeeping_interval;
                    let pin_state_shard_guard = pin_state_shard_guard;
                    let pin_state_shard_burst = pin_state_shard_burst;
                    let detailed_lock_observability = detailed_lock_observability;
                    let owner_local_state = owner_local_state;
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
                            set_current_dpdk_worker_id(Some(worker_id));
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
                            let mut pinned_shard_guard = None;
                            let mut flow_steer_dispatch_enabled = flow_steer_queues.is_some();
                            let mut packets_since_housekeeping = 0u64;
                            let mut next_housekeeping_at = Instant::now() + housekeeping_interval;
                            loop {
                                let service_lane_ready = if !service_lane_enabled {
                                    false
                                } else {
                                    adapter.service_lane_ready()
                                };
                                let mut from_steer_queue = false;
                                let mut steered_payload = None;
                                if let Some(queue) = flow_steer_queue.as_ref() {
                                    if let Some(payload) = queue.pop() {
                                        if let Some(queue_depth) = flow_steer_depth.as_ref() {
                                            let depth = decrement_queue_depth(queue_depth);
                                            if let Some(flow_steer_metrics) =
                                                flow_steer_metrics.as_deref()
                                            {
                                                flow_steer_metrics
                                                    .set_queue_depth(worker_id, depth);
                                            }
                                        }
                                        steered_payload = Some(payload);
                                        from_steer_queue = true;
                                    }
                                }
                                if !from_steer_queue {
                                    if !allow_direct_rx {
                                        let mut locked_io = io.lock_io()?;
                                        locked_io.flush()?;
                                        if service_lane_ready {
                                            adapter.flush_host_frames(&mut locked_io)?;
                                        }
                                        run_dpdk_housekeeping(
                                            worker_id,
                                            false,
                                            service_lane_enabled,
                                            housekeeping_shard_idx,
                                            &metrics,
                                            detailed_lock_observability,
                                            shared_state.as_ref(),
                                            local_state.as_mut(),
                                            &mut adapter,
                                            &mut locked_io,
                                        )?;
                                        std::thread::yield_now();
                                        continue;
                                    }
                                    let mut locked_io = io.lock_io()?;
                                    let n = locked_io.recv_packet(&mut pkt).map_err(|err| {
                                        format!("dpdk worker {worker_id} recv failed: {err}")
                                    })?;
                                    if n == 0 {
                                        pinned_shard_guard = None;
                                        pinned_shard_idx = None;
                                        pinned_shard_run_len = 0;
                                        locked_io.finish_rx_packet();
                                        locked_io.flush()?;
                                        run_dpdk_housekeeping(
                                            worker_id,
                                            true,
                                            service_lane_enabled,
                                            housekeeping_shard_idx,
                                            &metrics,
                                            detailed_lock_observability,
                                            shared_state.as_ref(),
                                            local_state.as_mut(),
                                            &mut adapter,
                                            &mut locked_io,
                                        )?;
                                        if service_lane_ready {
                                            adapter.flush_host_frames(&mut locked_io)?;
                                        }
                                        packets_since_housekeeping = 0;
                                        next_housekeeping_at =
                                            Instant::now() + housekeeping_interval;
                                        continue;
                                    }
                                    if flow_steer_queues.is_some() {
                                        let owner = shared_demux_owner_for_packet_with_policy(
                                            &pkt,
                                            shard_count,
                                            worker_count,
                                            pin_https_demux_owner,
                                        );
                                        if owner != worker_id && flow_steer_dispatch_enabled {
                                            let payload = locked_io.take_flow_steer_payload(&mut pkt);
                                            let flow_steer_queue_depth = flow_steer_depths
                                                .as_ref()
                                                .and_then(|depths| depths.get(owner))
                                                .cloned();
                                            if let Some(queue_depth) =
                                                flow_steer_queue_depth.as_ref()
                                            {
                                                let depth = increment_queue_depth(queue_depth);
                                                if let Some(flow_steer_metrics) =
                                                    flow_steer_metrics.as_deref()
                                                {
                                                    flow_steer_metrics
                                                        .set_queue_depth(owner, depth);
                                                }
                                            }
                                            match dispatch_flow_steer_packet(
                                                flow_steer_queues.as_ref(),
                                                owner,
                                                payload,
                                                worker_id,
                                                flow_steer_queue_depth.as_ref(),
                                                flow_steer_metrics.as_deref(),
                                                &mut flow_steer_dispatch_enabled,
                                            ) {
                                                FlowSteerDispatchResult::Dispatched => {
                                                    locked_io.finish_rx_packet();
                                                    continue;
                                                }
                                                FlowSteerDispatchResult::ProcessLocally(payload) => {
                                                    if owner_local_state {
                                                        locked_io.finish_rx_packet();
                                                        return Err(format!(
                                                            "dpdk flow steer dispatch failed for owner {owner} in owner-local state mode"
                                                        ));
                                                    }
                                                    pkt = locked_io
                                                        .restore_flow_steer_payload(payload)?;
                                                }
                                            }
                                        }
                                    }
                                    let step_result = (|| -> Result<(), String> {
                                        packets_since_housekeeping =
                                            packets_since_housekeeping.saturating_add(1);
                                        if let Some(out) = {
                                            if owner_local_state {
                                                let local = local_state.as_mut().ok_or_else(|| {
                                                    "dpdk: local state missing".to_string()
                                                })?;
                                                local.set_intercept_to_host_steering(
                                                    service_lane_ready,
                                                );
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
                                                        let shard = shared
                                                            .get(shard_idx)
                                                            .ok_or_else(|| {
                                                                "dpdk: state shard missing"
                                                                    .to_string()
                                                            })?;
                                                        let guard = lock_state_shard_blocking(
                                                            shard,
                                                            worker_id,
                                                            shard_idx,
                                                            &metrics,
                                                            detailed_lock_observability,
                                                        )?;
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
                                                    if pinned_shard_run_len
                                                        >= pin_state_shard_burst
                                                    {
                                                        pinned_shard_guard = None;
                                                        pinned_shard_idx = None;
                                                        pinned_shard_run_len = 0;
                                                    }
                                                    out
                                                } else {
                                                    let shard = shared.get(shard_idx).ok_or_else(
                                                        || "dpdk: state shard missing".to_string(),
                                                    )?;
                                                    let mut guard = lock_state_shard_blocking(
                                                        shard,
                                                        worker_id,
                                                        shard_idx,
                                                        &metrics,
                                                        detailed_lock_observability,
                                                    )?;
                                                    guard.set_intercept_to_host_steering(
                                                        service_lane_ready,
                                                    );
                                                    adapter.process_packet_in_place(
                                                        &mut pkt,
                                                        &mut guard,
                                                    )
                                                }
                                            }
                                        } {
                                            match out {
                                                FrameOut::Borrowed(frame) => {
                                                    locked_io.send_borrowed_frame(frame)?
                                                }
                                                FrameOut::Owned(frame) => {
                                                    locked_io.send_frame(&frame)?
                                                }
                                            }
                                        }
                                        if service_lane_ready {
                                            adapter.flush_host_frames(&mut locked_io)?;
                                        }
                                        if !allow_direct_rx {
                                            locked_io.flush()?;
                                        }
                                        let now = Instant::now();
                                        if packets_since_housekeeping
                                            >= housekeeping_interval_packets
                                            || now >= next_housekeeping_at
                                        {
                                            run_dpdk_housekeeping(
                                                worker_id,
                                                false,
                                                service_lane_enabled,
                                                housekeeping_shard_idx,
                                                &metrics,
                                                detailed_lock_observability,
                                                shared_state.as_ref(),
                                                local_state.as_mut(),
                                                &mut adapter,
                                                &mut locked_io,
                                            )?;
                                            packets_since_housekeeping = 0;
                                            next_housekeeping_at = now + housekeeping_interval;
                                        }
                                        Ok(())
                                    })();
                                    locked_io.finish_rx_packet();
                                    if let Err(err) = step_result {
                                        warn!(
                                            worker_id,
                                            error = %err,
                                            "dpdk worker exiting on error"
                                        );
                                        return Err(err);
                                    }
                                    continue;
                                }
                                let mut locked_io = io.lock_io()?;
                                if let Some(payload) = steered_payload.take() {
                                    pkt = locked_io.restore_flow_steer_payload(payload)?;
                                }
                                let step_result = (|| -> Result<(), String> {
                                    packets_since_housekeeping =
                                        packets_since_housekeeping.saturating_add(1);
                                    if let Some(out) = {
                                        if owner_local_state {
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
                                                    let guard = lock_state_shard_blocking(
                                                        shard,
                                                        worker_id,
                                                        shard_idx,
                                                        &metrics,
                                                        detailed_lock_observability,
                                                    )?;
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
                                                let out =
                                                    adapter.process_packet_in_place(&mut pkt, guard);
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
                                                let mut guard = lock_state_shard_blocking(
                                                    shard,
                                                        worker_id,
                                                        shard_idx,
                                                        &metrics,
                                                        detailed_lock_observability,
                                                    )?;
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
                                                locked_io.send_borrowed_frame(frame)?
                                            }
                                            FrameOut::Owned(frame) => locked_io.send_frame(&frame)?,
                                        }
                                    }
                                    if service_lane_ready {
                                        adapter.flush_host_frames(&mut locked_io)?;
                                    }
                                    if !allow_direct_rx {
                                        locked_io.flush()?;
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
                                            &metrics,
                                            detailed_lock_observability,
                                            shared_state.as_ref(),
                                            local_state.as_mut(),
                                            &mut adapter,
                                            &mut locked_io,
                                        )?;
                                        packets_since_housekeeping = 0;
                                        next_housekeeping_at = now + housekeeping_interval;
                                    }
                                    Ok(())
                                })();
                                locked_io.finish_rx_packet();
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
        let metrics = Metrics::new().expect("metrics");
        let flow_steer_metrics = metrics.bind_dpdk_flow_steer_metrics(2);
        let queues = Arc::new(vec![Arc::new(ArrayQueue::new(8))]);
        let queue_depth = Arc::new(AtomicUsize::new(1));
        let mut dispatch_enabled = true;

        let result = dispatch_flow_steer_packet(
            Some(&queues),
            0,
            FlowSteerPayload::Bytes(vec![1, 2, 3]),
            1,
            Some(&queue_depth),
            Some(&flow_steer_metrics),
            &mut dispatch_enabled,
        );

        assert!(matches!(result, FlowSteerDispatchResult::Dispatched));
        assert!(dispatch_enabled);
        assert_eq!(queue_depth.load(Ordering::Acquire), 1);
        match queues[0].pop() {
            Some(FlowSteerPayload::Bytes(frame)) => assert_eq!(frame, vec![1, 2, 3]),
            other => panic!("unexpected queue payload: {other:?}"),
        }
    }

    #[test]
    fn dispatch_flow_steer_packet_missing_owner_fails_open() {
        let metrics = Metrics::new().expect("metrics");
        let flow_steer_metrics = metrics.bind_dpdk_flow_steer_metrics(3);
        let queues = Arc::new(Vec::new());
        let queue_depth = Arc::new(AtomicUsize::new(1));
        let mut dispatch_enabled = true;

        let result = dispatch_flow_steer_packet(
            Some(&queues),
            0,
            FlowSteerPayload::Bytes(vec![9, 8, 7]),
            2,
            Some(&queue_depth),
            Some(&flow_steer_metrics),
            &mut dispatch_enabled,
        );

        match result {
            FlowSteerDispatchResult::ProcessLocally(FlowSteerPayload::Bytes(frame)) => {
                assert_eq!(frame, vec![9, 8, 7]);
            }
            other => panic!("unexpected dispatch result: {other:?}"),
        }
        assert!(!dispatch_enabled);
        assert_eq!(queue_depth.load(Ordering::Acquire), 0);

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "dpdk_flow_steer_fail_open_events_total",
                &[("worker", "2"), ("event", "owner_missing")]
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
    fn shared_rx_owner_only_defaults_on_for_shared_io_demux() {
        assert!(shared_rx_owner_only_enabled(true, true, true));
        assert!(!shared_rx_owner_only_enabled(false, true, true));
        assert!(!shared_rx_owner_only_enabled(true, false, true));
    }

    #[test]
    fn shared_rx_owner_only_honors_typed_override() {
        assert!(!shared_rx_owner_only_enabled(true, true, false));
        assert!(shared_rx_owner_only_enabled(true, true, true));
    }

    #[test]
    fn worker_emits_dhcp_housekeeping_only_on_worker_zero() {
        assert!(worker_emits_dhcp_housekeeping(0));
        assert!(!worker_emits_dhcp_housekeeping(1));
        assert!(!worker_emits_dhcp_housekeeping(2));
    }

    #[test]
    fn requested_dpdk_workers_target_defaults_to_auto_core_count() {
        assert_eq!(requested_dpdk_workers_target(8, None), 7);
    }

    #[test]
    fn requested_dpdk_workers_target_keeps_full_cores_for_tiny_nodes() {
        assert_eq!(requested_dpdk_workers_target(1, None), 1);
        assert_eq!(requested_dpdk_workers_target(2, None), 2);
    }

    #[test]
    fn requested_dpdk_workers_target_respects_valid_override() {
        assert_eq!(requested_dpdk_workers_target(8, Some(1)), 1);
        assert_eq!(requested_dpdk_workers_target(8, Some(6)), 6);
        assert_eq!(requested_dpdk_workers_target(8, Some(99)), 8);
    }
}
