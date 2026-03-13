use firewall::dataplane::Packet;
use tracing::warn;

pub fn parse_truthy_flag(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

pub fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|raw| parse_truthy_flag(&raw))
        .unwrap_or(false)
}

pub fn shard_index_for_packet(pkt: &Packet, shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let src_ip = match pkt.src_ip() {
        Some(ip) => ip,
        None => return 0,
    };
    let dst_ip = match pkt.dst_ip() {
        Some(ip) => ip,
        None => return 0,
    };
    let proto = pkt.protocol().unwrap_or(0);
    let (src_port, dst_port) = pkt.ports().unwrap_or((0, 0));
    let src_u = u32::from(src_ip);
    let dst_u = u32::from(dst_ip);
    let forward = ((src_u as u64) << 32) | dst_u as u64;
    let reverse = ((dst_u as u64) << 32) | src_u as u64;
    let forward_ports = ((src_port as u64) << 16) | dst_port as u64;
    let reverse_ports = ((dst_port as u64) << 16) | src_port as u64;
    let (a, b) = if (forward, forward_ports) <= (reverse, reverse_ports) {
        (forward, forward_ports)
    } else {
        (reverse, reverse_ports)
    };
    // Fast, deterministic symmetric flow hash for hot-path sharding.
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    x ^= a.wrapping_mul(0x9ddf_ea08_eb38_2d69);
    x ^= b.wrapping_mul(0xc2b2_ae35);
    x ^= (proto as u64).wrapping_mul(0x1656_67b1);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    (x as usize) % shard_count
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkWorkerMode {
    Single,
    QueuePerWorker,
    SharedRxDemux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkSingleQueueStrategy {
    SharedDemux,
    SingleWorker,
}

impl DpdkSingleQueueStrategy {
    pub fn from_env() -> Self {
        let Ok(raw) = std::env::var("NEUWERK_DPDK_SINGLE_QUEUE_MODE") else {
            return Self::SharedDemux;
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "demux" | "shared-demux" | "shared_rx_demux" => Self::SharedDemux,
            "single" | "single-worker" | "single_worker" => Self::SingleWorker,
            _ => {
                warn!(
                    raw = %raw,
                    "unknown NEUWERK_DPDK_SINGLE_QUEUE_MODE (expected demux|single); defaulting to demux"
                );
                Self::SharedDemux
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DpdkWorkerPlan {
    pub requested: usize,
    pub effective_queues: usize,
    pub worker_count: usize,
    pub mode: DpdkWorkerMode,
}

pub fn choose_dpdk_worker_plan(
    requested: usize,
    max_workers: usize,
    effective_queues: usize,
    single_queue_strategy: DpdkSingleQueueStrategy,
) -> Result<DpdkWorkerPlan, String> {
    let requested = requested.max(1).min(max_workers.max(1));
    if effective_queues == 0 {
        return Err("dpdk: no usable queues available".to_string());
    }
    if requested == 1 {
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: 1,
            mode: DpdkWorkerMode::Single,
        });
    }
    if effective_queues >= requested {
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: requested,
            mode: DpdkWorkerMode::QueuePerWorker,
        });
    }
    if effective_queues == 1 {
        if matches!(single_queue_strategy, DpdkSingleQueueStrategy::SingleWorker) {
            return Ok(DpdkWorkerPlan {
                requested,
                effective_queues,
                worker_count: 1,
                mode: DpdkWorkerMode::Single,
            });
        }
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: requested,
            mode: DpdkWorkerMode::SharedRxDemux,
        });
    }
    Ok(DpdkWorkerPlan {
        requested,
        effective_queues,
        worker_count: effective_queues,
        mode: DpdkWorkerMode::QueuePerWorker,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkPerfMode {
    Standard,
    Aggressive,
}

impl DpdkPerfMode {
    pub fn from_env() -> Self {
        let Ok(raw) = std::env::var("NEUWERK_DPDK_PERF_MODE") else {
            return Self::Standard;
        };
        match raw.trim().to_ascii_lowercase().as_str() {
            "" | "standard" | "default" | "off" => Self::Standard,
            "aggressive" | "on" | "1" | "true" | "yes" => Self::Aggressive,
            _ => {
                warn!(
                    raw = %raw,
                    "unknown NEUWERK_DPDK_PERF_MODE (expected standard|aggressive); defaulting to standard"
                );
                Self::Standard
            }
        }
    }
}

pub fn dpdk_force_shared_rx_demux() -> bool {
    env_flag_enabled("NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX")
}

pub fn dpdk_pin_https_demux_owner() -> bool {
    std::env::var("NEUWERK_DPDK_PIN_HTTPS_OWNER")
        .map(|raw| parse_truthy_flag(&raw))
        .unwrap_or(true)
}

pub fn service_lane_enabled_with_override(
    perf_mode: DpdkPerfMode,
    disable_service_lane: bool,
) -> bool {
    // Keep service-lane steering active by default even in aggressive mode.
    // TLS intercept relies on this path.
    let _ = perf_mode;
    !disable_service_lane
}

pub fn dpdk_service_lane_enabled(perf_mode: DpdkPerfMode) -> bool {
    service_lane_enabled_with_override(
        perf_mode,
        env_flag_enabled("NEUWERK_DPDK_DISABLE_SERVICE_LANE"),
    )
}

pub fn dpdk_lockless_queue_per_worker_enabled() -> bool {
    std::env::var("NEUWERK_DPDK_LOCKLESS_QPW")
        .map(|val| !matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
        .unwrap_or(false)
}

pub fn shared_demux_owner_for_packet(
    pkt: &Packet,
    shard_count: usize,
    worker_count: usize,
) -> usize {
    shared_demux_owner_for_packet_with_policy(pkt, shard_count, worker_count, true)
}

pub fn shared_demux_owner_for_packet_with_policy(
    pkt: &Packet,
    shard_count: usize,
    worker_count: usize,
    pin_https_owner: bool,
) -> usize {
    if worker_count <= 1 {
        return 0;
    }
    if pin_https_owner {
        if let Some((src_port, dst_port)) = pkt.ports() {
            // Keep HTTPS/TLS flows on worker 0, which owns service-lane flush.
            if src_port == 443 || dst_port == 443 {
                return 0;
            }
        }
    }
    let shard_idx = shard_index_for_packet(pkt, shard_count);
    shard_idx % worker_count
}

pub fn flow_steer_payload(pkt: &mut Packet) -> Vec<u8> {
    if pkt.is_borrowed() {
        pkt.buffer().to_vec()
    } else {
        std::mem::replace(pkt, Packet::new(Vec::new())).into_vec()
    }
}
