use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(test)]
use std::os::fd::FromRawFd;

use tokio::sync::{mpsc, watch};

use crate::dataplane::dhcp::{DhcpRx, DhcpTx, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::dataplane::engine::{Action, EngineState};
use crate::dataplane::overlay::{self, EncapMode};
use crate::dataplane::packet::Packet;

mod debug_flags;
mod frame_codec;
mod io_api;
mod service_lane;
use debug_flags::{
    azure_gateway_mac, health_probe_debug_enabled, overlay_debug_enabled,
    overlay_force_tunnel_src_port, overlay_swap_tunnels, ARP_LOGS, HEALTH_PROBE_DEBUG_LOGS,
    HEALTH_PROBE_LOGGED, OVERLAY_ACTION_LOGS, OVERLAY_ENCAP_LOGS, OVERLAY_INTERNAL_LOGS,
    OVERLAY_PARSE_LOGS, OVERLAY_SAMPLE_LOGS, OVERLAY_TUNNEL_LOGS,
};
use frame_codec::{
    build_arp_reply, build_arp_request, build_tcp_control, build_udp_frame, parse_arp_reply,
    parse_arp_request, parse_eth, parse_ipv4, parse_tcp, parse_udp,
};
pub use io_api::{FrameIo, UnwiredDpdkIo};
use service_lane::{
    intercept_service_ip, intercept_service_port, open_tap, read_interface_mac, select_mac,
};

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;
const HEALTH_PROBE_PORT: u16 = 8080;
const GCP_BACKEND_HEALTH_PROBE_PORT: u16 = 80;
const TCP_FLAG_FIN: u8 = 0x01;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const ARP_CACHE_TTL_SECS: u64 = 120;
const ARP_REQUEST_COOLDOWN_MS: u64 = 500;
const INTERCEPT_DEMUX_IDLE_SECS: u64 = 300;
const INTERCEPT_DEMUX_GC_INTERVAL_MS_DEFAULT: u64 = 1_000;
const INTERCEPT_DEMUX_MAX_ENTRIES_DEFAULT: usize = 65_536;
const HOST_FRAME_QUEUE_MAX_DEFAULT: usize = 8_192;
const PENDING_ARP_QUEUE_MAX_DEFAULT: usize = 4_096;
const SERVICE_LANE_TAP_RETRY_MS: u64 = 1_000;
const INTERCEPT_SERVICE_IP_DEFAULT: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 1);
const INTERCEPT_SERVICE_PORT_DEFAULT: u16 = 15443;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
#[derive(Debug, Clone, Copy)]
struct DhcpServerHint {
    ip: Ipv4Addr,
    mac: [u8; 6],
}

#[derive(Debug, Clone, Copy)]
struct ArpEntry {
    mac: [u8; 6],
    last_seen: Instant,
}

#[derive(Debug, Default)]
pub struct SharedArpState {
    cache: HashMap<Ipv4Addr, ArpEntry>,
    last_request: HashMap<Ipv4Addr, Instant>,
}

fn intercept_demux_gc_interval() -> Duration {
    static INTERVAL: OnceLock<Duration> = OnceLock::new();

    *INTERVAL.get_or_init(|| {
        let interval_ms = std::env::var("NEUWERK_DPDK_INTERCEPT_DEMUX_GC_INTERVAL_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(INTERCEPT_DEMUX_GC_INTERVAL_MS_DEFAULT);
        tracing::info!(interval_ms, "dpdk intercept demux gc interval configured");
        Duration::from_millis(interval_ms)
    })
}

fn parse_env_usize_gt_zero(var_name: &str, default: usize) -> usize {
    std::env::var(var_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn intercept_demux_max_entries() -> usize {
    parse_env_usize_gt_zero(
        "NEUWERK_DPDK_INTERCEPT_DEMUX_MAX_ENTRIES",
        INTERCEPT_DEMUX_MAX_ENTRIES_DEFAULT,
    )
}

fn host_frame_queue_max() -> usize {
    parse_env_usize_gt_zero(
        "NEUWERK_DPDK_HOST_FRAME_QUEUE_MAX",
        HOST_FRAME_QUEUE_MAX_DEFAULT,
    )
}

fn pending_arp_queue_max() -> usize {
    parse_env_usize_gt_zero(
        "NEUWERK_DPDK_PENDING_ARP_QUEUE_MAX",
        PENDING_ARP_QUEUE_MAX_DEFAULT,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InterceptDemuxKey {
    client_ip: Ipv4Addr,
    client_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct InterceptDemuxEntry {
    upstream_ip: Ipv4Addr,
    upstream_port: u16,
    last_seen: Instant,
}

#[derive(Debug)]
struct InterceptDemuxShard {
    map: HashMap<InterceptDemuxKey, InterceptDemuxEntry>,
    last_gc: Instant,
}

impl Default for InterceptDemuxShard {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            last_gc: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct SharedInterceptDemuxState {
    shards: Vec<Mutex<InterceptDemuxShard>>,
    size: AtomicUsize,
}

impl Default for SharedInterceptDemuxState {
    fn default() -> Self {
        const DEFAULT_SHARD_COUNT: usize = 64;
        let shard_count = std::env::var("NEUWERK_DPDK_INTERCEPT_DEMUX_SHARDS")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .filter(|count| *count > 0)
            .unwrap_or(DEFAULT_SHARD_COUNT);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(Mutex::new(InterceptDemuxShard::default()));
        }
        Self {
            shards,
            size: AtomicUsize::new(0),
        }
    }
}

impl SharedInterceptDemuxState {
    fn dec_size(&self, count: usize) {
        if count == 0 {
            return;
        }
        let _ = self
            .size
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(count))
            });
    }

    fn shard_index(&self, client_ip: Ipv4Addr, client_port: u16) -> usize {
        if self.shards.len() <= 1 {
            return 0;
        }
        let src_u = u32::from(client_ip) as u64;
        let mut x = (src_u << 16) ^ (client_port as u64);
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^= x >> 33;
        (x as usize) % self.shards.len()
    }

    fn gc_expired(shard: &mut InterceptDemuxShard, now: Instant) -> usize {
        let before = shard.map.len();
        shard.map.retain(|_, entry| {
            now.duration_since(entry.last_seen) <= Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS)
        });
        shard.last_gc = now;
        before.saturating_sub(shard.map.len())
    }

    fn maybe_gc(shard: &mut InterceptDemuxShard) -> usize {
        if shard.last_gc.elapsed() < intercept_demux_gc_interval() {
            return 0;
        }
        Self::gc_expired(shard, Instant::now())
    }

    pub fn upsert(
        &self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
    ) -> bool {
        let idx = self.shard_index(client_ip, client_port);
        let mut shard = self.shards[idx]
            .lock()
            .expect("shared intercept demux shard lock poisoned");
        let gc_removed = Self::maybe_gc(&mut shard);
        self.dec_size(gc_removed);
        let key = InterceptDemuxKey {
            client_ip,
            client_port,
        };
        if let Some(entry) = shard.map.get_mut(&key) {
            *entry = InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen: Instant::now(),
            };
            return true;
        }
        let max_entries = intercept_demux_max_entries();
        loop {
            let current = self.size.load(Ordering::Relaxed);
            if current >= max_entries {
                return false;
            }
            if self
                .size
                .compare_exchange(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        shard.map.insert(
            key,
            InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen: Instant::now(),
            },
        );
        true
    }

    pub fn remove(&self, client_ip: Ipv4Addr, client_port: u16) {
        let idx = self.shard_index(client_ip, client_port);
        let mut shard = self.shards[idx]
            .lock()
            .expect("shared intercept demux shard lock poisoned");
        if shard
            .map
            .remove(&InterceptDemuxKey {
                client_ip,
                client_port,
            })
            .is_some()
        {
            self.dec_size(1);
        }
    }

    pub fn lookup(&self, client_ip: Ipv4Addr, client_port: u16) -> Option<(Ipv4Addr, u16)> {
        let idx = self.shard_index(client_ip, client_port);
        let mut shard = self.shards[idx]
            .lock()
            .expect("shared intercept demux shard lock poisoned");
        let gc_removed = Self::maybe_gc(&mut shard);
        self.dec_size(gc_removed);
        let key = InterceptDemuxKey {
            client_ip,
            client_port,
        };
        if let Some(entry) = shard.map.get_mut(&key) {
            entry.last_seen = Instant::now();
            return Some((entry.upstream_ip, entry.upstream_port));
        }
        None
    }

    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn test_insert_with_last_seen(
        &self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
        last_seen: Instant,
    ) {
        let idx = self.shard_index(client_ip, client_port);
        let mut shard = self.shards[idx]
            .lock()
            .expect("shared intercept demux shard lock poisoned");
        if !shard.map.contains_key(&InterceptDemuxKey {
            client_ip,
            client_port,
        }) {
            self.size.fetch_add(1, Ordering::Relaxed);
        }
        shard.map.insert(
            InterceptDemuxKey {
                client_ip,
                client_port,
            },
            InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen,
            },
        );
    }

    #[cfg(test)]
    pub(crate) fn test_contains(&self, client_ip: Ipv4Addr, client_port: u16) -> bool {
        let idx = self.shard_index(client_ip, client_port);
        let shard = self.shards[idx]
            .lock()
            .expect("shared intercept demux shard lock poisoned");
        shard.map.contains_key(&InterceptDemuxKey {
            client_ip,
            client_port,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_set_last_gc_all(&self, last_gc: Instant) {
        for shard in &self.shards {
            let mut lock = shard
                .lock()
                .expect("shared intercept demux shard lock poisoned");
            lock.last_gc = last_gc;
        }
    }
}

#[derive(Debug)]
pub struct DpdkAdapter {
    data_iface: String,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    metrics: Option<crate::metrics::Metrics>,
    mac: [u8; 6],
    dhcp_server_hint: Option<DhcpServerHint>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    shared_arp: Option<Arc<Mutex<SharedArpState>>>,
    shared_intercept_demux: Option<Arc<SharedInterceptDemuxState>>,
    intercept_demux: HashMap<InterceptDemuxKey, InterceptDemuxEntry>,
    intercept_demux_last_gc: Instant,
    arp_cache: HashMap<Ipv4Addr, ArpEntry>,
    arp_last_request: HashMap<Ipv4Addr, Instant>,
    pending_frames: VecDeque<Vec<u8>>,
    pending_host_frames: VecDeque<Vec<u8>>,
    service_lane_tap: Option<File>,
    service_lane_mac: Option<[u8; 6]>,
    service_lane_tap_last_attempt: Option<Instant>,
}

pub enum FrameOut<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DpdkAdapter {
    pub fn new(data_iface: String) -> Result<Self, String> {
        if data_iface.trim().is_empty() {
            return Err("data-plane-interface cannot be empty".to_string());
        }
        Ok(Self {
            data_iface: data_iface.trim().to_string(),
            dhcp_tx: None,
            dhcp_rx: None,
            metrics: None,
            mac: [0; 6],
            dhcp_server_hint: None,
            mac_publisher: None,
            shared_arp: None,
            shared_intercept_demux: None,
            intercept_demux: HashMap::new(),
            intercept_demux_last_gc: Instant::now(),
            arp_cache: HashMap::new(),
            arp_last_request: HashMap::new(),
            pending_frames: VecDeque::new(),
            pending_host_frames: VecDeque::new(),
            service_lane_tap: None,
            service_lane_mac: None,
            service_lane_tap_last_attempt: None,
        })
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
        if let Some(publisher) = &self.mac_publisher {
            let _ = publisher.send(mac);
        }
    }

    pub fn set_mac_publisher(&mut self, publisher: watch::Sender<[u8; 6]>) {
        self.mac_publisher = Some(publisher);
    }

    pub fn set_shared_arp(&mut self, shared: Arc<Mutex<SharedArpState>>) {
        self.shared_arp = Some(shared);
    }

    pub fn set_shared_intercept_demux(&mut self, shared: Arc<SharedInterceptDemuxState>) {
        self.shared_intercept_demux = Some(shared);
    }

    fn set_runtime_metrics(&mut self, metrics: Option<&crate::metrics::Metrics>) {
        self.metrics = metrics.cloned();
    }

    fn runtime_metrics(&self) -> Option<&crate::metrics::Metrics> {
        self.metrics.as_ref()
    }

    pub fn set_dhcp_channels(&mut self, tx: mpsc::Sender<DhcpRx>, rx: mpsc::Receiver<DhcpTx>) {
        self.dhcp_tx = Some(tx);
        self.dhcp_rx = Some(rx);
    }

    pub fn set_dhcp_tx(&mut self, tx: mpsc::Sender<DhcpRx>) {
        self.dhcp_tx = Some(tx);
    }

    pub fn set_dhcp_rx(&mut self, rx: mpsc::Receiver<DhcpTx>) {
        self.dhcp_rx = Some(rx);
    }
}
include!("dpdk_adapter/service_lane_runtime.rs");
include!("dpdk_adapter/frame_runtime.rs");

fn ipv4_in_subnet(ip: Ipv4Addr, base: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix >= 32 {
        return ip == base;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(base) & mask)
}

#[cfg(not(feature = "dpdk"))]
pub fn preinit_dpdk_eal(_iface: &str) -> Result<(), String> {
    Err("dpdk io backend not available (build with --features dpdk and install DPDK)".to_string())
}

#[cfg(feature = "dpdk")]
mod io;

#[cfg(feature = "dpdk")]
pub fn preinit_dpdk_eal(iface: &str) -> Result<(), String> {
    io::init_eal(iface)
}

#[cfg(feature = "dpdk")]
pub use io::DpdkIo;
#[cfg(feature = "dpdk")]
pub use io::DpdkTransferredRxPacket;
#[cfg(not(feature = "dpdk"))]
pub use io_api::UnwiredDpdkIo as DpdkIo;

#[cfg(test)]
mod tests;
