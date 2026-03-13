use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
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
pub struct SharedInterceptDemuxState {
    map: HashMap<InterceptDemuxKey, InterceptDemuxEntry>,
    last_gc: Instant,
}

impl Default for SharedInterceptDemuxState {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            last_gc: Instant::now(),
        }
    }
}

impl SharedInterceptDemuxState {
    fn gc_expired(&mut self, now: Instant) {
        self.map.retain(|_, entry| {
            now.duration_since(entry.last_seen) <= Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS)
        });
        self.last_gc = now;
    }

    fn maybe_gc(&mut self) {
        if self.last_gc.elapsed() < intercept_demux_gc_interval() {
            return;
        }
        self.gc_expired(Instant::now());
    }

    pub fn upsert(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
    ) {
        self.maybe_gc();
        self.map.insert(
            InterceptDemuxKey {
                client_ip,
                client_port,
            },
            InterceptDemuxEntry {
                upstream_ip,
                upstream_port,
                last_seen: Instant::now(),
            },
        );
    }

    pub fn remove(&mut self, client_ip: Ipv4Addr, client_port: u16) {
        self.map.remove(&InterceptDemuxKey {
            client_ip,
            client_port,
        });
    }

    pub fn lookup(&mut self, client_ip: Ipv4Addr, client_port: u16) -> Option<(Ipv4Addr, u16)> {
        self.maybe_gc();
        let key = InterceptDemuxKey {
            client_ip,
            client_port,
        };
        if let Some(entry) = self.map.get_mut(&key) {
            entry.last_seen = Instant::now();
            return Some((entry.upstream_ip, entry.upstream_port));
        }
        None
    }
}

#[derive(Debug)]
pub struct DpdkAdapter {
    data_iface: String,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac: [u8; 6],
    dhcp_server_hint: Option<DhcpServerHint>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    shared_arp: Option<Arc<Mutex<SharedArpState>>>,
    shared_intercept_demux: Option<Arc<Mutex<SharedInterceptDemuxState>>>,
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

    pub fn set_shared_intercept_demux(&mut self, shared: Arc<Mutex<SharedInterceptDemuxState>>) {
        self.shared_intercept_demux = Some(shared);
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
#[cfg(not(feature = "dpdk"))]
pub use io_api::UnwiredDpdkIo as DpdkIo;

#[cfg(test)]
mod tests;
