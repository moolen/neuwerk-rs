use super::{FrameIo, Packet};
use crate::controlplane::metrics::Metrics;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dpdk_sys::*;

unsafe extern "C" {
    fn rust_rte_prepare_ipv4_l4_checksum_offload(
        m: *mut rte_mbuf,
        ol_flags: u64,
        l2_len: u16,
        l3_len: u16,
    ) -> c_int;
}

const RX_RING_SIZE: u16 = 1024;
const TX_RING_SIZE: u16 = 1024;
const MBUF_CACHE_SIZE: u32 = 250;
const MBUF_PER_POOL: u32 = 8191;
const RX_BURST_SIZE: usize = 32;
const TX_BURST_SIZE: usize = 32;
const METRICS_FLUSH_PACKET_THRESHOLD: u64 = 128;
const MTU_FRAME_OVERHEAD: u32 = 18; // Ethernet header + FCS.
const MIN_VALID_MTU: u16 = 576;
const ENA_XSTATS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const ENA_ALLOWANCE_XSTATS: &[&str] = &[
    "bw_in_allowance_exceeded",
    "bw_out_allowance_exceeded",
    "pps_allowance_exceeded",
    "conntrack_allowance_exceeded",
    "conntrack_allowance_available",
    "linklocal_allowance_exceeded",
];

static EAL_INIT: OnceLock<Result<(), String>> = OnceLock::new();
static PORT_INIT: OnceLock<Result<PortSetup, String>> = OnceLock::new();

struct PortInfo {
    id: u16,
    mac: [u8; 6],
    name: Option<String>,
}

struct PortSetup {
    port_id: u16,
    mempool: *mut rte_mempool,
    mac: [u8; 6],
    queue_count: u16,
    tx_csum_offload: TxChecksumOffloadCaps,
    ena_xstat_ids: Vec<EnaXstatId>,
}

// Safety: DPDK mempools are designed for concurrent access across threads.
// We only store a pointer and use it for allocation/free, which is thread-safe.
unsafe impl Send for PortSetup {}
unsafe impl Sync for PortSetup {}

pub struct DpdkIo {
    port_id: u16,
    queue_id: u16,
    queue_label: String,
    mempool: *mut rte_mempool,
    mac: [u8; 6],
    tx_csum_offload: TxChecksumOffloadCaps,
    metrics: Option<Metrics>,
    rx_bufs: [*mut rte_mbuf; RX_BURST_SIZE],
    rx_count: u16,
    rx_index: u16,
    held_rx_mbuf: *mut rte_mbuf,
    tx_bufs: [*mut rte_mbuf; TX_BURST_SIZE],
    tx_lens: [u32; TX_BURST_SIZE],
    tx_count: u16,
    metric_batch: IoMetricBatch,
    ena_xstat_ids: Vec<EnaXstatId>,
    ena_xstat_values: Vec<u64>,
    ena_xstats_last_poll: Instant,
}

// Safety: `DpdkIo` owns raw DPDK pointers that are thread-compatible but not
// intrinsically synchronized. We only move `DpdkIo` across threads and use
// shared instances behind `Mutex` in the software-demux path.
unsafe impl Send for DpdkIo {}

static DPDK_RX_LOGGED: AtomicBool = AtomicBool::new(false);
static DPDK_RX_OVERSIZE_LOGS: AtomicU32 = AtomicU32::new(0);
static DPDK_TX_CSUM_PREP_FAIL_LOGS: AtomicU32 = AtomicU32::new(0);
static DPDK_XSTATS_LOGS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
struct EnaXstatId {
    label: String,
    id: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct IoMetricBatch {
    rx_packets: u64,
    rx_bytes: u64,
    rx_dropped: u64,
    tx_packets: u64,
    tx_bytes: u64,
    tx_dropped: u64,
}

impl IoMetricBatch {
    fn pending_packets(self) -> u64 {
        self.rx_packets + self.rx_dropped + self.tx_packets + self.tx_dropped
    }

    fn is_empty(self) -> bool {
        self.rx_packets == 0
            && self.rx_bytes == 0
            && self.rx_dropped == 0
            && self.tx_packets == 0
            && self.tx_bytes == 0
            && self.tx_dropped == 0
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct TxChecksumOffloadCaps {
    ipv4: bool,
    tcp: bool,
    udp: bool,
}

impl TxChecksumOffloadCaps {
    fn any(self) -> bool {
        self.ipv4 || self.tcp || self.udp
    }
}

#[derive(Clone, Debug, Default)]
struct DeviceInfoCaps {
    driver_name: Option<String>,
    max_rx_queues: u16,
    max_tx_queues: u16,
    reta_size: u16,
    flow_type_rss_offloads: u64,
    tx_offload_capa: u64,
    rx_offload_capa: u64,
    max_rx_pktlen: u32,
}

fn preferred_rss_hf(supported: u64) -> u64 {
    let preferred = (ETH_RSS_NONFRAG_IPV4_TCP as u64)
        | (ETH_RSS_NONFRAG_IPV4_UDP as u64)
        | (ETH_RSS_NONFRAG_IPV6_TCP as u64)
        | (ETH_RSS_NONFRAG_IPV6_UDP as u64)
        | (ETH_RSS_IPV4 as u64)
        | (ETH_RSS_IPV6 as u64);
    let selected = supported & preferred;
    if selected != 0 {
        selected
    } else {
        supported
    }
}

fn fallback_rss_hf() -> u64 {
    (ETH_RSS_NONFRAG_IPV4_TCP as u64) | (ETH_RSS_NONFRAG_IPV4_UDP as u64) | (ETH_RSS_IPV4 as u64)
}

fn driver_name_from_ptr(driver_name: *const c_char) -> Option<String> {
    if driver_name.is_null() {
        return None;
    }
    // Safety: DPDK returns a static null-terminated driver string.
    unsafe { CStr::from_ptr(driver_name) }
        .to_str()
        .ok()
        .map(ToOwned::to_owned)
}

fn read_device_info_caps(port_id: u16) -> Result<DeviceInfoCaps, String> {
    let mut max_rx_queues = 0u16;
    let mut max_tx_queues = 0u16;
    let mut reta_size = 0u16;
    let mut flow_type_rss_offloads = 0u64;
    let mut tx_offload_capa = 0u64;
    let mut rx_offload_capa = 0u64;
    let mut max_rx_pktlen = 0u32;
    let mut driver_name_ptr: *const c_char = ptr::null();
    let ret = unsafe {
        rust_rte_eth_dev_info_caps_get(
            port_id,
            &mut max_rx_queues,
            &mut max_tx_queues,
            &mut reta_size,
            &mut flow_type_rss_offloads,
            &mut tx_offload_capa,
            &mut rx_offload_capa,
            &mut max_rx_pktlen,
            &mut driver_name_ptr,
        )
    };
    if ret < 0 {
        return Err(format!("dpdk: failed to read device info caps ({ret})"));
    }
    Ok(DeviceInfoCaps {
        driver_name: driver_name_from_ptr(driver_name_ptr),
        max_rx_queues,
        max_tx_queues,
        reta_size,
        flow_type_rss_offloads,
        tx_offload_capa,
        rx_offload_capa,
        max_rx_pktlen,
    })
}

fn should_use_pmd_default_rss_hf(driver_name: Option<&str>, supported_hf: u64) -> bool {
    let Some(name) = driver_name else {
        return false;
    };
    if !name.to_ascii_lowercase().contains("ena") {
        return false;
    }
    // ENA can report only IP-level RSS bits while still supporting queue spread
    // with PMD defaults; forcing custom rss_hf can fail port configuration.
    (supported_hf & fallback_rss_hf()) == 0
}

fn queue_caps_look_unreliable(max_rx: u16, max_tx: u16) -> bool {
    // Some distro/runtime ABI mixes can surface implausible queue counts
    // (for example very large max_rx with max_tx=0). Treat those values as
    // unreliable and probe queue setup directly.
    max_rx == 0 || max_tx == 0 || max_rx > 4096 || max_tx > 4096
}

fn parse_mbuf_data_room_size() -> u16 {
    let default_size = RTE_MBUF_DEFAULT_BUF_SIZE as u16;
    let Some(raw) = std::env::var("NEUWERK_DPDK_MBUF_DATA_ROOM").ok() else {
        return default_size;
    };
    let parsed = match raw.trim().parse::<u32>() {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!(
                raw = %raw,
                default_size,
                "dpdk invalid NEUWERK_DPDK_MBUF_DATA_ROOM; using default"
            );
            return default_size;
        }
    };
    let min_size = (RTE_PKTMBUF_HEADROOM as u32).saturating_add(256);
    let bounded_u32 = parsed.max(min_size).min(u16::MAX as u32);
    let bounded = bounded_u32 as u16;
    if bounded_u32 != parsed {
        tracing::warn!(parsed, bounded, "dpdk clamped NEUWERK_DPDK_MBUF_DATA_ROOM");
    }
    bounded
}

fn parse_u16_env(name: &str) -> Option<u16> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().parse::<u16>() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!(env_var = %name, raw = %raw, "dpdk invalid numeric env override; ignoring");
            None
        }
    }
}

fn parse_queue_cap_override() -> Option<u16> {
    let value = parse_u16_env("NEUWERK_DPDK_QUEUE_OVERRIDE")?;
    if value == 0 {
        tracing::warn!("dpdk NEUWERK_DPDK_QUEUE_OVERRIDE=0; ignoring");
        return None;
    }
    Some(value)
}

fn parse_port_mtu_override() -> Option<u16> {
    let value = parse_u16_env("NEUWERK_DPDK_PORT_MTU")?;
    if value < MIN_VALID_MTU {
        tracing::warn!(
            value,
            minimum = MIN_VALID_MTU,
            "dpdk NEUWERK_DPDK_PORT_MTU below minimum; ignoring"
        );
        return None;
    }
    Some(value)
}

fn discover_ena_allowance_xstats(port_id: u16) -> Vec<EnaXstatId> {
    let mut out = Vec::new();
    for name in ENA_ALLOWANCE_XSTATS {
        let cname = match CString::new(*name) {
            Ok(cname) => cname,
            Err(_) => continue,
        };
        let mut id = 0u64;
        let ret = unsafe { rte_eth_xstats_get_id_by_name(port_id, cname.as_ptr(), &mut id) };
        if ret >= 0 {
            out.push(EnaXstatId {
                label: (*name).to_string(),
                id,
            });
        }
    }
    if !out.is_empty() {
        let labels = out
            .iter()
            .map(|x| x.label.as_str())
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(labels = %labels, "dpdk ENA allowance xstats enabled");
        return out;
    }

    let name_count = unsafe { rte_eth_xstats_get_names(port_id, std::ptr::null_mut(), 0) };
    if name_count <= 0 {
        return Vec::new();
    }
    let mut names = (0..name_count as usize)
        .map(|_| rte_eth_xstat_name::default())
        .collect::<Vec<_>>();
    let got = unsafe { rte_eth_xstats_get_names(port_id, names.as_mut_ptr(), name_count as u32) };
    if got <= 0 {
        return Vec::new();
    }
    for entry in names.into_iter().take(got as usize) {
        let raw_ptr = entry.name.as_ptr();
        if raw_ptr.is_null() {
            continue;
        }
        let raw_name = unsafe { CStr::from_ptr(raw_ptr) };
        let Ok(name) = raw_name.to_str() else {
            continue;
        };
        if !name.contains("allowance") {
            continue;
        }
        let cname = match CString::new(name) {
            Ok(cname) => cname,
            Err(_) => continue,
        };
        let mut id = 0u64;
        let ret = unsafe { rte_eth_xstats_get_id_by_name(port_id, cname.as_ptr(), &mut id) };
        if ret < 0 {
            continue;
        }
        out.push(EnaXstatId {
            label: name.to_string(),
            id,
        });
    }
    if !out.is_empty() {
        let labels = out
            .iter()
            .map(|x| x.label.as_str())
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(labels = %labels, "dpdk discovered allowance-like xstats");
    }
    out
}

fn create_mempool(pool_name: &CString, socket_id: i32) -> Result<*mut rte_mempool, String> {
    let candidates = [MBUF_PER_POOL, 4095, 2047, 1023];
    let mut last_errno = 0;
    let data_room_size = parse_mbuf_data_room_size();
    for count in candidates {
        if count <= MBUF_CACHE_SIZE + 1 {
            continue;
        }
        let mempool = unsafe {
            rte_pktmbuf_pool_create(
                pool_name.as_ptr(),
                count,
                MBUF_CACHE_SIZE,
                0,
                data_room_size,
                socket_id,
            )
        };
        if !mempool.is_null() {
            if count != MBUF_PER_POOL {
                tracing::warn!(count, "dpdk mempool fallback size applied");
            }
            tracing::info!(data_room_size, "dpdk mbuf data room size");
            return Ok(mempool);
        }
        last_errno = unsafe { rust_rte_errno() };
        tracing::warn!(
            count,
            data_room_size,
            rte_errno = last_errno,
            "dpdk mempool create failed"
        );
    }
    Err(format!(
        "dpdk: failed to create mempool (rte_errno={})",
        last_errno
    ))
}

fn configure_rss_reta(
    port_id: u16,
    queue_count: u16,
    reported_reta_size: u16,
) -> Result<u16, String> {
    if queue_count <= 1 {
        return Ok(0);
    }

    let mut candidates = Vec::with_capacity(5);
    if reported_reta_size >= 64 && reported_reta_size <= 4096 && reported_reta_size % 64 == 0 {
        candidates.push(reported_reta_size);
    }
    // Keep a short fallback probe list for environments where `reta_size` is
    // missing or unreliable.
    for size in [128u16, 64u16, 256u16, 512u16] {
        if !candidates.contains(&size) {
            candidates.push(size);
        }
    }

    let mut last_ret = 0;
    for reta_size in candidates {
        let groups = ((reta_size as usize) + 63) / 64;
        let mut reta = Vec::with_capacity(groups);
        for _ in 0..groups {
            reta.push(rte_eth_rss_reta_entry64::default());
        }
        for idx in 0..(reta_size as usize) {
            let group = idx / 64;
            let offset = idx % 64;
            reta[group].mask |= 1u64 << offset;
            reta[group].reta[offset] = (idx % queue_count as usize) as u16;
        }
        let ret = unsafe { rte_eth_dev_rss_reta_update(port_id, reta.as_mut_ptr(), reta_size) };
        if ret == 0 {
            return Ok(reta_size);
        }
        last_ret = ret;
    }

    Err(format!(
            "dpdk: rss reta update failed for candidate sizes (reported_reta_size={}, queues={}, last_ret={})",
            reported_reta_size, queue_count, last_ret
        ))
}

fn parse_core_id_list(raw: &str) -> Vec<usize> {
    let mut ids = Vec::new();
    for token in raw.trim().split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((start, end)) = token.split_once('-') {
            let Ok(start) = start.trim().parse::<usize>() else {
                continue;
            };
            let Ok(end) = end.trim().parse::<usize>() else {
                continue;
            };
            if start <= end {
                for id in start..=end {
                    ids.push(id);
                }
            } else {
                for id in end..=start {
                    ids.push(id);
                }
            }
        } else if let Ok(id) = token.parse::<usize>() {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

include!("io/init_port.rs");
include!("io/runtime.rs");
include!("io/eal_port_select.rs");
include!("io/tx_checksum.rs");
