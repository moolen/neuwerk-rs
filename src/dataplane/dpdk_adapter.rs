use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, watch};

use crate::dataplane::dhcp::{DhcpRx, DhcpTx, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::dataplane::engine::{Action, EngineState};
use crate::dataplane::overlay::{self, EncapMode};
use crate::dataplane::packet::Packet;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;
const HEALTH_PROBE_PORT: u16 = 8080;
const ARP_CACHE_TTL_SECS: u64 = 120;
const ARP_REQUEST_COOLDOWN_MS: u64 = 500;
const INTERCEPT_DEMUX_IDLE_SECS: u64 = 300;
const SERVICE_LANE_TAP_RETRY_MS: u64 = 1_000;
const INTERCEPT_SERVICE_IP_DEFAULT: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 1);
const INTERCEPT_SERVICE_PORT_DEFAULT: u16 = 15443;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
static HEALTH_PROBE_LOGGED: AtomicBool = AtomicBool::new(false);
static OVERLAY_PARSE_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_SAMPLE_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_TUNNEL_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_INTERNAL_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_ACTION_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_ENCAP_LOGS: AtomicUsize = AtomicUsize::new(0);
static ARP_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_SWAP_TUNNELS: OnceLock<bool> = OnceLock::new();
static OVERLAY_TUNNEL_SRC_PORT: OnceLock<bool> = OnceLock::new();

fn overlay_swap_tunnels() -> bool {
    *OVERLAY_SWAP_TUNNELS.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_GWLB_SWAP_TUNNELS")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        eprintln!("dpdk: overlay tunnel swap enabled={}", enabled);
        enabled
    })
}

fn overlay_force_tunnel_src_port() -> bool {
    *OVERLAY_TUNNEL_SRC_PORT.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_GWLB_TUNNEL_SRC_PORT")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if enabled {
            eprintln!("dpdk: overlay tunnel src port forced to tunnel port");
        }
        enabled
    })
}

fn azure_gateway_mac() -> Option<[u8; 6]> {
    let provider = std::env::var("NEUWERK_CLOUD_PROVIDER").ok()?;
    if !provider.eq_ignore_ascii_case("azure") {
        return None;
    }
    let mac = match std::env::var("NEUWERK_AZURE_GATEWAY_MAC") {
        Ok(value) => value,
        Err(_) => return None,
    };
    parse_mac_addr(&mac).ok()
}

fn intercept_service_ip() -> Ipv4Addr {
    std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP")
        .ok()
        .and_then(|raw| raw.parse::<Ipv4Addr>().ok())
        .unwrap_or(INTERCEPT_SERVICE_IP_DEFAULT)
}

fn intercept_service_port() -> u16 {
    std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(INTERCEPT_SERVICE_PORT_DEFAULT)
}

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

#[derive(Debug, Default)]
pub struct SharedInterceptDemuxState {
    map: HashMap<InterceptDemuxKey, InterceptDemuxEntry>,
}

impl SharedInterceptDemuxState {
    fn gc(&mut self) {
        let now = Instant::now();
        self.map.retain(|_, entry| {
            now.duration_since(entry.last_seen) <= Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS)
        });
    }

    pub fn upsert(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
    ) {
        self.gc();
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
        self.gc();
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

    pub fn service_lane_ready(&mut self) -> bool {
        if self.service_lane_tap.is_some() {
            return true;
        }
        if let Some(last_attempt) = self.service_lane_tap_last_attempt {
            if last_attempt.elapsed() < Duration::from_millis(SERVICE_LANE_TAP_RETRY_MS) {
                return false;
            }
        }
        self.service_lane_tap_last_attempt = Some(Instant::now());
        let iface = std::env::var("NEUWERK_DPDK_SERVICE_LANE_IFACE")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "svc0".to_string());
        match open_tap(&iface) {
            Ok(file) => {
                match read_interface_mac(&iface) {
                    Ok(mac) => self.service_lane_mac = Some(mac),
                    Err(err) => eprintln!("dpdk: service lane mac unavailable on {iface}: {err}"),
                }
                self.service_lane_tap = Some(file);
                true
            }
            Err(err) => {
                eprintln!("dpdk: service lane tap unavailable on {iface}: {err}");
                false
            }
        }
    }

    pub fn refresh_service_lane_steering(&mut self, state: &mut EngineState) {
        state.set_intercept_to_host_steering(self.service_lane_ready());
    }

    fn queue_host_frame(&mut self, frame: &[u8]) {
        if frame.len() < ETH_HDR_LEN {
            return;
        }
        let mut host_frame = frame.to_vec();
        host_frame[0..6].copy_from_slice(
            &self
                .service_lane_mac
                .unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        );
        self.pending_host_frames.push_back(host_frame);
    }

    fn with_intercept_demux_map<R>(
        &mut self,
        f: impl FnOnce(&mut HashMap<InterceptDemuxKey, InterceptDemuxEntry>) -> R,
    ) -> R {
        if let Some(shared) = &self.shared_intercept_demux {
            if let Ok(mut lock) = shared.lock() {
                return f(&mut lock.map);
            }
        }
        f(&mut self.intercept_demux)
    }

    fn gc_intercept_demux_map(map: &mut HashMap<InterceptDemuxKey, InterceptDemuxEntry>) {
        let now = Instant::now();
        map.retain(|_, entry| {
            now.duration_since(entry.last_seen) <= Duration::from_secs(INTERCEPT_DEMUX_IDLE_SECS)
        });
    }

    fn upsert_intercept_demux_entry(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
        upstream_ip: Ipv4Addr,
        upstream_port: u16,
    ) {
        if let Some(shared) = &self.shared_intercept_demux {
            if let Ok(mut lock) = shared.lock() {
                lock.upsert(client_ip, client_port, upstream_ip, upstream_port);
                return;
            }
        }
        self.with_intercept_demux_map(|map| {
            Self::gc_intercept_demux_map(map);
            map.insert(
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
        });
    }

    fn remove_intercept_demux_entry(&mut self, client_ip: Ipv4Addr, client_port: u16) {
        if let Some(shared) = &self.shared_intercept_demux {
            if let Ok(mut lock) = shared.lock() {
                lock.remove(client_ip, client_port);
                return;
            }
        }
        self.with_intercept_demux_map(|map| {
            map.remove(&InterceptDemuxKey {
                client_ip,
                client_port,
            });
        });
    }

    fn lookup_intercept_demux_entry(
        &mut self,
        client_ip: Ipv4Addr,
        client_port: u16,
    ) -> Option<InterceptDemuxEntry> {
        if let Some(shared) = &self.shared_intercept_demux {
            if let Ok(mut lock) = shared.lock() {
                return lock
                    .lookup(client_ip, client_port)
                    .map(|(upstream_ip, upstream_port)| InterceptDemuxEntry {
                        upstream_ip,
                        upstream_port,
                        last_seen: Instant::now(),
                    });
            }
        }
        self.with_intercept_demux_map(|map| {
            Self::gc_intercept_demux_map(map);
            let key = InterceptDemuxKey {
                client_ip,
                client_port,
            };
            if let Some(entry) = map.get_mut(&key) {
                entry.last_seen = Instant::now();
                Some(*entry)
            } else {
                None
            }
        })
    }

    fn queue_intercept_host_frame(&mut self, frame: &[u8]) {
        if frame.len() < ETH_HDR_LEN {
            return;
        }
        let mut pkt = Packet::from_bytes(frame);
        let (src_port, dst_port) = match pkt.ports() {
            Some(ports) => ports,
            None => {
                self.queue_host_frame(frame);
                return;
            }
        };
        let src_ip = match pkt.src_ip() {
            Some(ip) => ip,
            None => {
                self.queue_host_frame(frame);
                return;
            }
        };
        let dst_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => {
                self.queue_host_frame(frame);
                return;
            }
        };
        if pkt.protocol() != Some(6) {
            self.queue_host_frame(frame);
            return;
        }

        self.upsert_intercept_demux_entry(src_ip, src_port, dst_ip, dst_port);
        if !pkt.set_dst_ip(intercept_service_ip())
            || !pkt.set_dst_port(intercept_service_port())
            || !pkt.recalc_checksums()
        {
            return;
        }
        if let Some(flags) = pkt.tcp_flags() {
            if flags & (0x01 | 0x04) != 0 {
                self.remove_intercept_demux_entry(src_ip, src_port);
            }
        }
        self.queue_host_frame(pkt.buffer());
    }

    fn rewrite_intercept_service_lane_egress(&mut self, pkt: &mut Packet) {
        if pkt.protocol() != Some(6) {
            return;
        }
        let (src_port, dst_port) = match pkt.ports() {
            Some(ports) => ports,
            None => return,
        };
        if src_port != intercept_service_port() {
            return;
        }
        let src_ip = match pkt.src_ip() {
            Some(ip) => ip,
            None => return,
        };
        if src_ip != intercept_service_ip() {
            return;
        }
        let client_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => return,
        };
        let Some(entry) = self.lookup_intercept_demux_entry(client_ip, dst_port) else {
            return;
        };

        if !pkt.set_src_ip(entry.upstream_ip)
            || !pkt.set_src_port(entry.upstream_port)
            || !pkt.recalc_checksums()
        {
            return;
        }
        if let Some(flags) = pkt.tcp_flags() {
            if flags & (0x01 | 0x04) != 0 {
                self.remove_intercept_demux_entry(client_ip, dst_port);
            }
        }
    }

    pub fn next_host_frame(&mut self) -> Option<Vec<u8>> {
        self.pending_host_frames.pop_front()
    }

    pub fn flush_host_frames<I: FrameIo>(&mut self, io: &mut I) -> Result<(), String> {
        if self.pending_host_frames.is_empty() {
            return Ok(());
        }
        let Some(tap) = self.service_lane_tap.as_mut() else {
            return Err("dpdk: service lane steering unavailable".to_string());
        };
        while let Some(frame) = self.pending_host_frames.pop_front() {
            tap.write_all(&frame)
                .map_err(|err| format!("dpdk: service lane write failed: {err}"))?;
        }
        io.flush()
    }

    pub fn process_service_lane_egress_frame(
        &mut self,
        frame: &[u8],
        state: &EngineState,
    ) -> Option<Vec<u8>> {
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let mut pkt = Packet::from_bytes(frame);
        self.rewrite_intercept_service_lane_egress(&mut pkt);
        self.rewrite_l2_for_forward(&mut pkt, state)
    }

    pub fn drain_service_lane_egress<I: FrameIo>(
        &mut self,
        state: &EngineState,
        io: &mut I,
    ) -> Result<(), String> {
        if self.service_lane_tap.is_none() {
            return Ok(());
        }
        let mut buf = [0u8; 65536];
        loop {
            let readable = {
                let tap = self
                    .service_lane_tap
                    .as_ref()
                    .ok_or_else(|| "dpdk: service lane tap unavailable".to_string())?;
                service_lane_tap_readable(tap)?
            };
            if !readable {
                break;
            }
            let n = {
                let tap = self
                    .service_lane_tap
                    .as_mut()
                    .ok_or_else(|| "dpdk: service lane tap unavailable".to_string())?;
                tap.read(&mut buf)
                    .map_err(|err| format!("dpdk: service lane read failed: {err}"))?
            };
            if n == 0 {
                break;
            }
            if let Some(frame) = self.process_service_lane_egress_frame(&buf[..n], state) {
                io.send_frame(&frame)?;
            }
        }
        Ok(())
    }

    pub fn process_frame(&mut self, frame: &[u8], state: &mut EngineState) -> Option<Vec<u8>> {
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETH_TYPE_ARP => return self.handle_arp(frame, state),
            ETH_TYPE_IPV4 => {}
            _ => return None,
        }

        if let Some(resp) = self.handle_health_probe(frame, state) {
            return Some(resp);
        }

        if self.handle_dhcp(frame) {
            return None;
        }

        if state.overlay.mode != EncapMode::None {
            let metrics = state.metrics().cloned();
            let overlay_pkt = match overlay::decap(frame, &state.overlay, metrics.as_ref()) {
                Ok(pkt) => pkt,
                Err(_) => return None,
            };
            let mut inner = overlay_pkt.inner;
            if inner.src_ip().is_none() || inner.dst_ip().is_none() {
                if OVERLAY_PARSE_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                    let buf = inner.buffer();
                    let ethertype = if buf.len() >= ETH_HDR_LEN {
                        u16::from_be_bytes([buf[12], buf[13]])
                    } else {
                        0
                    };
                    let head_len = buf.len().min(32);
                    eprintln!(
                        "dpdk: overlay inner parse failed (len={}, ethertype=0x{:04x}, head={:02x?}, meta={:?})",
                        buf.len(),
                        ethertype,
                        &buf[..head_len],
                        overlay_pkt.meta
                    );
                }
            }
            if OVERLAY_SAMPLE_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                let src = inner.src_ip();
                let dst = inner.dst_ip();
                let proto = inner.protocol();
                eprintln!(
                    "dpdk: overlay inner sample src={:?} dst={:?} proto={:?} len={} meta={:?}",
                    src,
                    dst,
                    proto,
                    inner.len(),
                    overlay_pkt.meta
                );
            }
            if OVERLAY_INTERNAL_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                if let (Some(src), Some(dst)) = (inner.src_ip(), inner.dst_ip()) {
                    if state.is_internal(src) || state.is_internal(dst) {
                        eprintln!(
                            "dpdk: overlay internal flow src={} dst={} proto={:?} meta={:?}",
                            src,
                            dst,
                            inner.protocol(),
                            overlay_pkt.meta
                        );
                    }
                }
            }
            overlay::maybe_clamp_mss(&mut inner, &state.overlay, &overlay_pkt.meta);
            let swap_tunnel = overlay_swap_tunnels();
            let mut out_meta = overlay::reply_meta(&overlay_pkt.meta, &state.overlay, swap_tunnel);
            if overlay_force_tunnel_src_port() {
                let port = out_meta.udp_port(&state.overlay);
                out_meta.set_outer_src_port(port);
            }
            if overlay_pkt.meta.tunnel_label() != out_meta.tunnel_label()
                && OVERLAY_TUNNEL_LOGS.fetch_add(1, Ordering::Relaxed) < 10
            {
                eprintln!(
                    "dpdk: overlay tunnel swap {} -> {}",
                    overlay_pkt.meta.tunnel_label(),
                    out_meta.tunnel_label()
                );
            }
            let action = crate::dataplane::engine::handle_packet(&mut inner, state);
            if OVERLAY_ACTION_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                let ports = inner.ports();
                eprintln!(
                    "dpdk: overlay action={:?} src={:?} dst={:?} ports={:?} meta={:?}",
                    action,
                    inner.src_ip(),
                    inner.dst_ip(),
                    ports,
                    &out_meta
                );
            }
            return match action {
                Action::Forward { .. } | Action::ToHost => {
                    match overlay::encap(&inner, &out_meta, &state.overlay, metrics.as_ref()) {
                        Ok(frame) => Some(frame),
                        Err(err) => {
                            if OVERLAY_ENCAP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                                eprintln!(
                                    "dpdk: overlay encap failed err={:?} src={:?} dst={:?} meta={:?}",
                                    err,
                                    inner.src_ip(),
                                    inner.dst_ip(),
                                    &out_meta
                                );
                            }
                            None
                        }
                    }
                }
                Action::Drop => None,
            };
        }

        let mut pkt = Packet::from_bytes(frame);
        match crate::dataplane::engine::handle_packet(&mut pkt, state) {
            Action::Forward { .. } => self.rewrite_l2_for_forward(&mut pkt, state),
            Action::ToHost => {
                self.queue_intercept_host_frame(pkt.buffer());
                None
            }
            Action::Drop => None,
        }
    }

    pub fn process_packet_in_place<'a>(
        &'a mut self,
        pkt: &'a mut Packet,
        state: &mut EngineState,
    ) -> Option<FrameOut<'a>> {
        let frame = pkt.buffer();
        if frame.len() < ETH_HDR_LEN {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        match ethertype {
            ETH_TYPE_ARP => return self.handle_arp(frame, state).map(FrameOut::Owned),
            ETH_TYPE_IPV4 => {}
            _ => return None,
        }

        if let Some(resp) = self.handle_health_probe(frame, state) {
            return Some(FrameOut::Owned(resp));
        }

        if self.handle_dhcp(frame) {
            return None;
        }

        if state.overlay.mode != EncapMode::None {
            return self.process_frame(frame, state).map(FrameOut::Owned);
        }

        match crate::dataplane::engine::handle_packet(pkt, state) {
            Action::Forward { .. } => {
                if self.rewrite_l2_for_forward_in_place(pkt, state) {
                    Some(FrameOut::Borrowed(pkt.buffer()))
                } else {
                    None
                }
            }
            Action::ToHost => {
                self.queue_intercept_host_frame(pkt.buffer());
                None
            }
            Action::Drop => None,
        }
    }

    pub fn next_dhcp_frame(&mut self, state: &EngineState) -> Option<Vec<u8>> {
        if let Some(frame) = self.pending_frames.pop_front() {
            return Some(frame);
        }
        let rx = self.dhcp_rx.as_mut()?;
        let msg = match rx.try_recv() {
            Ok(msg) => msg,
            Err(_) => return None,
        };
        let frame = self.build_dhcp_frame(state, msg)?;
        eprintln!("dpdk: sending dhcp frame len={}", frame.len());
        Some(frame)
    }

    pub fn run(&mut self, _state: &mut EngineState) -> Result<(), String> {
        println!(
            "dataplane started (dpdk), data-plane-interface={}",
            self.data_iface
        );
        Err("dpdk adapter io not wired".to_string())
    }

    pub fn run_with_io<I: FrameIo>(
        &mut self,
        state: &mut EngineState,
        io: &mut I,
    ) -> Result<(), String> {
        println!(
            "dataplane started (dpdk), data-plane-interface={}",
            self.data_iface
        );
        if let Some(mac) = io.mac() {
            self.set_mac(mac);
        }
        let mut pkt = Packet::new(vec![0u8; 65536]);
        loop {
            self.refresh_service_lane_steering(state);
            pkt.prepare_for_rx(65536);
            let n = io.recv_frame(pkt.buffer_mut())?;
            if n == 0 {
                io.flush()?;
                self.drain_service_lane_egress(state, io)?;
                self.flush_host_frames(io)?;
                while let Some(out) = self.next_dhcp_frame(state) {
                    io.send_frame(&out)?;
                }
                continue;
            }
            pkt.truncate(n);
            if let Some(out) = self.process_packet_in_place(&mut pkt, state) {
                match out {
                    FrameOut::Borrowed(frame) => io.send_frame(frame)?,
                    FrameOut::Owned(frame) => io.send_frame(&frame)?,
                }
            }
            self.drain_service_lane_egress(state, io)?;
            self.flush_host_frames(io)?;
            while let Some(out) = self.next_dhcp_frame(state) {
                io.send_frame(&out)?;
            }
        }
    }

    fn handle_dhcp(&mut self, frame: &[u8]) -> bool {
        let eth = match parse_eth(frame) {
            Some(eth) => eth,
            None => return false,
        };
        let ipv4 = match parse_ipv4(frame, eth.payload_offset) {
            Some(ipv4) => ipv4,
            None => return false,
        };
        if ipv4.proto != 17 {
            return false;
        }
        let udp = match parse_udp(frame, ipv4.l4_offset) {
            Some(udp) => udp,
            None => return false,
        };
        if udp.dst_port != DHCP_CLIENT_PORT || udp.src_port != DHCP_SERVER_PORT {
            return false;
        }
        let payload = match frame.get(udp.payload_offset..udp.payload_offset + udp.payload_len) {
            Some(payload) => payload.to_vec(),
            None => return false,
        };
        if let Some(tx) = &self.dhcp_tx {
            let _ = tx.try_send(DhcpRx {
                src_ip: ipv4.src,
                payload,
            });
        }
        // DHCP replies come from a valid L2 peer; seed ARP for the sender so
        // early forwarded traffic after lease acquisition can resolve gateway MAC.
        self.insert_arp(ipv4.src, eth.src_mac);
        eprintln!("dpdk: received dhcp frame from {}", ipv4.src);
        self.dhcp_server_hint = Some(DhcpServerHint {
            ip: ipv4.src,
            mac: eth.src_mac,
        });
        true
    }

    fn handle_arp(&mut self, frame: &[u8], state: &EngineState) -> Option<Vec<u8>> {
        if let Some(reply) = parse_arp_reply(frame) {
            self.insert_arp(reply.sender_ip, reply.sender_mac);
            if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                eprintln!(
                    "dpdk: arp reply sender_ip={} sender_mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    reply.sender_ip,
                    reply.sender_mac[0],
                    reply.sender_mac[1],
                    reply.sender_mac[2],
                    reply.sender_mac[3],
                    reply.sender_mac[4],
                    reply.sender_mac[5]
                );
            }
            return None;
        }

        let cfg = state.dataplane_config.get()?;
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return None;
        }
        parse_arp_request(frame, cfg.ip).map(|req| {
            self.insert_arp(req.sender_ip, req.sender_mac);
            state.inc_dp_arp_handled();
            build_arp_reply(req.sender_mac, req.sender_ip, cfg.mac, cfg.ip)
        })
    }

    fn insert_arp(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        if mac == [0; 6] || ip == Ipv4Addr::UNSPECIFIED {
            return;
        }
        let entry = ArpEntry {
            mac,
            last_seen: Instant::now(),
        };
        self.arp_cache.insert(ip, entry);
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                guard.cache.insert(ip, entry);
            }
        }
    }

    fn lookup_arp(&mut self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        if let Some(entry) = self.arp_cache.get(&ip).copied() {
            if entry.last_seen.elapsed() <= Duration::from_secs(ARP_CACHE_TTL_SECS) {
                return Some(entry.mac);
            }
            self.arp_cache.remove(&ip);
        }
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                if let Some(entry) = guard.cache.get(&ip).copied() {
                    if entry.last_seen.elapsed() <= Duration::from_secs(ARP_CACHE_TTL_SECS) {
                        self.arp_cache.insert(ip, entry);
                        return Some(entry.mac);
                    }
                    guard.cache.remove(&ip);
                }
            }
        }
        None
    }

    fn maybe_queue_arp_request(&mut self, src_mac: [u8; 6], src_ip: Ipv4Addr, target_ip: Ipv4Addr) {
        let now = Instant::now();
        let mut should_send = match self.arp_last_request.get(&target_ip) {
            Some(last) => {
                now.duration_since(*last) >= Duration::from_millis(ARP_REQUEST_COOLDOWN_MS)
            }
            None => true,
        };
        if let Some(shared) = &self.shared_arp {
            if let Ok(mut guard) = shared.lock() {
                let shared_ok = match guard.last_request.get(&target_ip) {
                    Some(last) => {
                        now.duration_since(*last) >= Duration::from_millis(ARP_REQUEST_COOLDOWN_MS)
                    }
                    None => true,
                };
                should_send &= shared_ok;
                if should_send {
                    guard.last_request.insert(target_ip, now);
                }
            }
        }
        if !should_send {
            return;
        }
        self.arp_last_request.insert(target_ip, now);
        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
            eprintln!(
                "dpdk: arp request src_ip={} target_ip={}",
                src_ip, target_ip
            );
        }
        let frame = build_arp_request(src_mac, src_ip, target_ip);
        self.pending_frames.push_back(frame);
    }

    fn rewrite_l2_for_forward(&mut self, pkt: &mut Packet, state: &EngineState) -> Option<Vec<u8>> {
        if self.rewrite_l2_for_forward_in_place(pkt, state) {
            return Some(pkt.buffer().to_vec());
        }
        None
    }

    fn rewrite_l2_for_forward_in_place(&mut self, pkt: &mut Packet, state: &EngineState) -> bool {
        let cfg = match state.dataplane_config.get() {
            Some(cfg) => cfg,
            None => return false,
        };
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return false;
        }
        let dst_ip = match pkt.dst_ip() {
            Some(ip) => ip,
            None => return false,
        };
        let buf = pkt.buffer_mut();
        if buf.len() < ETH_HDR_LEN {
            return false;
        }
        if u16::from_be_bytes([buf[12], buf[13]]) != ETH_TYPE_IPV4 {
            return true;
        }

        let next_hop = if cfg.gateway != Ipv4Addr::UNSPECIFIED
            && !ipv4_in_subnet(dst_ip, cfg.ip, cfg.prefix)
        {
            cfg.gateway
        } else {
            dst_ip
        };

        let src_mac = select_mac(self.mac, Some(cfg.mac));
        let dst_mac = match self.lookup_arp(next_hop) {
            Some(mac) => mac,
            None => {
                if next_hop == cfg.gateway {
                    if let Some(mac) = azure_gateway_mac() {
                        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 5 {
                            eprintln!(
                                "dpdk: using azure gateway mac for next_hop={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                next_hop,
                                mac[0],
                                mac[1],
                                mac[2],
                                mac[3],
                                mac[4],
                                mac[5]
                            );
                        }
                        self.insert_arp(next_hop, mac);
                        if let Some(mac) = self.lookup_arp(next_hop) {
                            mac
                        } else {
                            return false;
                        }
                    } else {
                        if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                            eprintln!(
                                "dpdk: arp miss next_hop={} src_ip={} dst_ip={}",
                                next_hop, cfg.ip, dst_ip
                            );
                        }
                        self.maybe_queue_arp_request(src_mac, cfg.ip, next_hop);
                        return false;
                    }
                } else {
                    if ARP_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                        eprintln!(
                            "dpdk: arp miss next_hop={} src_ip={} dst_ip={}",
                            next_hop, cfg.ip, dst_ip
                        );
                    }
                    self.maybe_queue_arp_request(src_mac, cfg.ip, next_hop);
                    return false;
                }
            }
        };

        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        true
    }

    fn build_dhcp_frame(&self, state: &EngineState, msg: DhcpTx) -> Option<Vec<u8>> {
        let cfg = state.dataplane_config.get();
        let src_mac = select_mac(self.mac, cfg.map(|c| c.mac));
        let (dst_ip, src_ip, payload, dst_mac) = match msg {
            DhcpTx::Broadcast { payload } => (
                Ipv4Addr::BROADCAST,
                Ipv4Addr::UNSPECIFIED,
                payload,
                [0xff; 6],
            ),
            DhcpTx::Unicast { payload, dst_ip } => {
                let src_ip = cfg.map(|c| c.ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
                let dst_mac = self
                    .dhcp_server_hint
                    .filter(|hint| hint.ip == dst_ip)
                    .map(|hint| hint.mac)
                    .unwrap_or([0xff; 6]);
                (dst_ip, src_ip, payload, dst_mac)
            }
        };
        Some(build_udp_frame(
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            DHCP_CLIENT_PORT,
            DHCP_SERVER_PORT,
            &payload,
        ))
    }

    fn handle_health_probe(&self, frame: &[u8], state: &EngineState) -> Option<Vec<u8>> {
        let cfg = state.dataplane_config.get()?;
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return None;
        }
        let eth = parse_eth(frame)?;
        let ipv4 = parse_ipv4(frame, eth.payload_offset)?;
        if ipv4.proto != 6 || ipv4.dst != cfg.ip {
            return None;
        }
        let tcp = parse_tcp(frame, ipv4.l4_offset)?;
        if tcp.dst_port != HEALTH_PROBE_PORT {
            return None;
        }
        if tcp.flags & 0x02 == 0 {
            return None;
        }
        let ack = tcp.seq.wrapping_add(1);
        if !HEALTH_PROBE_LOGGED.swap(true, Ordering::Relaxed) {
            eprintln!(
                "dpdk: health probe response src={} dst={} port={}",
                ipv4.src, cfg.ip, tcp.dst_port
            );
        }
        Some(build_tcp_synack(
            cfg.mac,
            eth.src_mac,
            cfg.ip,
            ipv4.src,
            HEALTH_PROBE_PORT,
            tcp.src_port,
            0,
            ack,
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct EthHeader {
    src_mac: [u8; 6],
    payload_offset: usize,
}

fn parse_eth(frame: &[u8]) -> Option<EthHeader> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Some(EthHeader {
        src_mac,
        payload_offset: ETH_HDR_LEN,
    })
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Header {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    l4_offset: usize,
}

fn parse_ipv4(frame: &[u8], ip_off: usize) -> Option<Ipv4Header> {
    if frame.len() < ip_off + 20 {
        return None;
    }
    let ver = frame[ip_off] >> 4;
    if ver != 4 {
        return None;
    }
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl {
        return None;
    }
    let proto = frame[ip_off + 9];
    let src = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    Some(Ipv4Header {
        src,
        dst,
        proto,
        l4_offset: ip_off + ihl,
    })
}

#[derive(Debug, Clone, Copy)]
struct UdpHeader {
    src_port: u16,
    dst_port: u16,
    payload_offset: usize,
    payload_len: usize,
}

fn parse_udp(frame: &[u8], l4_off: usize) -> Option<UdpHeader> {
    if frame.len() < l4_off + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
    let len = u16::from_be_bytes([frame[l4_off + 4], frame[l4_off + 5]]) as usize;
    if len < 8 {
        return None;
    }
    let payload_len = len - 8;
    let payload_offset = l4_off + 8;
    if frame.len() < payload_offset + payload_len {
        return None;
    }
    Some(UdpHeader {
        src_port,
        dst_port,
        payload_offset,
        payload_len,
    })
}

#[derive(Debug, Clone, Copy)]
struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: u8,
}

fn parse_tcp(frame: &[u8], l4_off: usize) -> Option<TcpHeader> {
    if frame.len() < l4_off + 20 {
        return None;
    }
    let src_port = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
    let seq = u32::from_be_bytes([
        frame[l4_off + 4],
        frame[l4_off + 5],
        frame[l4_off + 6],
        frame[l4_off + 7],
    ]);
    let data_offset = (frame[l4_off + 12] >> 4) as usize * 4;
    if data_offset < 20 || frame.len() < l4_off + data_offset {
        return None;
    }
    let flags = frame[l4_off + 13];
    Some(TcpHeader {
        src_port,
        dst_port,
        seq,
        flags,
    })
}

fn build_tcp_synack(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let total_len = 20 + 20;
    let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_off = ETH_HDR_LEN;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 6;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = 0x12;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64240u16.to_be_bytes());
    buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&0u16.to_be_bytes());
    buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&0u16.to_be_bytes());

    let mut pkt = Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

struct ArpRequest {
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
}

struct ArpReply {
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
}

fn parse_arp_request(frame: &[u8], target_ip: Ipv4Addr) -> Option<ArpRequest> {
    if frame.len() < 42 {
        return None;
    }
    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if htype != 1 || ptype != ETH_TYPE_IPV4 || hlen != 6 || plen != 4 || op != 1 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    let target = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    if target != target_ip {
        return None;
    }
    Some(ArpRequest {
        sender_mac,
        sender_ip,
    })
}

fn parse_arp_reply(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < 42 {
        return None;
    }
    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if htype != 1 || ptype != ETH_TYPE_IPV4 || hlen != 6 || plen != 4 || op != 2 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&frame[22..28]);
    let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    Some(ArpReply {
        sender_mac,
        sender_ip,
    })
}

fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

fn build_arp_reply(
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&2u16.to_be_bytes());
    buf[22..28].copy_from_slice(&src_mac);
    buf[28..32].copy_from_slice(&src_ip.octets());
    buf[32..38].copy_from_slice(&dst_mac);
    buf[38..42].copy_from_slice(&dst_ip.octets());
    buf
}

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

fn build_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_off = ETH_HDR_LEN;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 17;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
}

fn open_tap(name: &str) -> Result<File, String> {
    if name.is_empty() {
        return Err("dpdk: service lane interface cannot be empty".to_string());
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(format!(
            "dpdk: service lane interface name too long (max {})",
            libc::IFNAMSIZ - 1
        ));
    }
    let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "dpdk: open /dev/net/tun failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut ifr = IfReq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_flags: IFF_TAP | IFF_NO_PI,
    };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("dpdk: TUNSETIFF {name} failed: {err}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_interface_mac(iface: &str) -> Result<[u8; 6], String> {
    let path = format!("/sys/class/net/{iface}/address");
    let value =
        std::fs::read_to_string(&path).map_err(|err| format!("read {path} failed: {err}"))?;
    parse_mac_addr(value.trim())
}

fn parse_mac_addr(value: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid mac address '{value}'"));
    }
    let mut bytes = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("invalid mac address '{value}'"));
        }
        bytes[idx] = u8::from_str_radix(part, 16)
            .map_err(|err| format!("invalid mac address '{value}': {err}"))?;
    }
    Ok(bytes)
}

fn service_lane_tap_readable(tap: &File) -> Result<bool, String> {
    let fd = tap.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(format!("dpdk: service lane poll failed: {}", err));
    }
    if rc == 0 {
        return Ok(false);
    }
    if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(format!(
            "dpdk: service lane poll error revents=0x{:x}",
            pfd.revents
        ));
    }
    Ok(pfd.revents & libc::POLLIN != 0)
}

fn select_mac(fallback: [u8; 6], candidate: Option<[u8; 6]>) -> [u8; 6] {
    if let Some(mac) = candidate {
        if mac != [0; 6] {
            return mac;
        }
    }
    fallback
}

pub trait FrameIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String>;
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String>;
    fn flush(&mut self) -> Result<(), String> {
        Ok(())
    }
    fn mac(&self) -> Option<[u8; 6]> {
        None
    }
}

pub struct UnwiredDpdkIo;

impl UnwiredDpdkIo {
    pub fn new(
        _iface: &str,
        _metrics: Option<crate::controlplane::metrics::Metrics>,
    ) -> Result<Self, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }

    pub fn new_with_queue(
        _iface: &str,
        _queue_id: u16,
        _queue_count: u16,
        _metrics: Option<crate::controlplane::metrics::Metrics>,
    ) -> Result<Self, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }

    pub fn effective_queue_count(_iface: &str, _queue_count: u16) -> Result<u16, String> {
        Err(
            "dpdk io backend not available (build with --features dpdk and install DPDK)"
                .to_string(),
        )
    }
}

impl FrameIo for UnwiredDpdkIo {
    fn recv_frame(&mut self, _buf: &mut [u8]) -> Result<usize, String> {
        Err("dpdk io backend not implemented".to_string())
    }

    fn send_frame(&mut self, _frame: &[u8]) -> Result<(), String> {
        Err("dpdk io backend not implemented".to_string())
    }
}

#[cfg(not(feature = "dpdk"))]
pub fn preinit_dpdk_eal(_iface: &str) -> Result<(), String> {
    Err("dpdk io backend not available (build with --features dpdk and install DPDK)".to_string())
}

#[cfg(feature = "dpdk")]
mod dpdk_io {
    use super::FrameIo;
    use crate::controlplane::metrics::Metrics;
    use std::ffi::CString;
    use std::fs;
    use std::os::raw::c_char;
    use std::path::Path;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::OnceLock;

    use dpdk_sys::*;

    const RX_RING_SIZE: u16 = 1024;
    const TX_RING_SIZE: u16 = 1024;
    const MBUF_CACHE_SIZE: u32 = 250;
    const MBUF_PER_POOL: u32 = 8191;
    const RX_BURST_SIZE: usize = 32;
    const TX_BURST_SIZE: usize = 32;
    const METRICS_FLUSH_PACKET_THRESHOLD: u64 = 128;

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
        tx_bufs: [*mut rte_mbuf; TX_BURST_SIZE],
        tx_lens: [u32; TX_BURST_SIZE],
        tx_count: u16,
        metric_batch: IoMetricBatch,
    }

    // Safety: `DpdkIo` owns raw DPDK pointers that are thread-compatible but not
    // intrinsically synchronized. We only move `DpdkIo` across threads and use
    // shared instances behind `Mutex` in the software-demux path.
    unsafe impl Send for DpdkIo {}

    static DPDK_RX_LOGGED: AtomicBool = AtomicBool::new(false);
    static DPDK_RX_OVERSIZE_LOGS: AtomicU32 = AtomicU32::new(0);
    static DPDK_IPV4_LOGS: AtomicUsize = AtomicUsize::new(0);

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

    fn create_mempool(pool_name: &CString, socket_id: i32) -> Result<*mut rte_mempool, String> {
        let candidates = [MBUF_PER_POOL, 4095, 2047, 1023];
        let mut last_errno = 0;
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
                    RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                    socket_id,
                )
            };
            if !mempool.is_null() {
                if count != MBUF_PER_POOL {
                    eprintln!("dpdk: mempool fallback size {}", count);
                }
                return Ok(mempool);
            }
            last_errno = unsafe { rust_rte_errno() };
            eprintln!(
                "dpdk: mempool create failed (size={}, rte_errno={})",
                count, last_errno
            );
        }
        Err(format!(
            "dpdk: failed to create mempool (rte_errno={})",
            last_errno
        ))
    }

    fn configure_rss_reta(port_id: u16, queue_count: u16, reta_size: u16) -> Result<(), String> {
        if queue_count <= 1 || reta_size == 0 {
            return Ok(());
        }
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
        if ret < 0 {
            return Err(format!(
                "dpdk: rss reta update failed (reta_size={}, queues={}, ret={})",
                reta_size, queue_count, ret
            ));
        }
        Ok(())
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

    fn init_port(iface: &str, queue_count: u16) -> Result<PortSetup, String> {
        let cached = PORT_INIT.get_or_init(|| {
            let mut queue_count = queue_count.max(1);
            let ports = available_ports();
            if ports.is_empty() {
                return Err("dpdk: no ethernet ports available".to_string());
            }
            eprintln!("dpdk: {} ports available", ports.len());
            for port in ports.iter() {
                eprintln!(
                    "dpdk: port {} mac {}{}",
                    port.id,
                    format_mac(port.mac),
                    port.name
                        .as_deref()
                        .map(|name| format!(" name={}", name))
                        .unwrap_or_default()
                );
            }
            let port_id = match port_id_for_iface_or_pci(iface, &ports) {
                Ok(id) => id,
                Err(err) => return Err(err),
            };
            eprintln!("dpdk: selected port {}", port_id);

            let mut dev_info: rte_eth_dev_info = unsafe {
                let mut info = std::mem::MaybeUninit::<rte_eth_dev_info>::uninit();
                std::ptr::write_bytes(info.as_mut_ptr(), 0, 1);
                info.assume_init()
            };
            unsafe {
                rte_eth_dev_info_get(port_id, &mut dev_info);
            }
            let mut max_rx = dev_info.max_rx_queues;
            let mut max_tx = dev_info.max_tx_queues;
            let is_gcp = std::env::var("NEUWERK_CLOUD_PROVIDER")
                .map(|provider| provider.eq_ignore_ascii_case("gcp"))
                .unwrap_or(false);
            if is_gcp && (max_rx == 0 || max_tx == 0) {
                eprintln!(
                    "dpdk: gcp reported max_rx={} max_tx={}; forcing single queue",
                    max_rx, max_tx
                );
                queue_count = 1;
                max_rx = max_rx.max(1);
                max_tx = max_tx.max(1);
            } else {
                if max_rx == 0 {
                    eprintln!(
                        "dpdk: max_rx_queues reported 0; assuming at least {}",
                        queue_count
                    );
                    max_rx = queue_count;
                }
                if max_tx == 0 {
                    eprintln!(
                        "dpdk: max_tx_queues reported 0; assuming at least {}",
                        queue_count
                    );
                    max_tx = queue_count;
                }
            }
            let max_supported = max_rx.min(max_tx).max(1);
            if queue_count > max_supported {
                eprintln!(
                    "dpdk: requested {} queues, but device supports rx={} tx={}, clamping to {}",
                    queue_count, max_rx, max_tx, max_supported
                );
                queue_count = max_supported;
            }

            let socket_id_raw = unsafe { rte_eth_dev_socket_id(port_id as u16) };
            let socket_id = if socket_id_raw < 0 {
                0i32
            } else {
                socket_id_raw
            };
            let socket_id_u32 = socket_id as u32;
            let pool_name = CString::new("mbuf_pool").unwrap();
            let mempool = create_mempool(&pool_name, socket_id)?;

            let mut rss_hf = 0u64;
            let tx_csum_env_enabled = std::env::var("NEUWERK_DPDK_TX_CSUM_OFFLOAD")
                .map(|val| !matches!(val.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
                .unwrap_or(true);
            let mut tx_csum_offload = TxChecksumOffloadCaps::default();
            if tx_csum_env_enabled {
                tx_csum_offload.ipv4 =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_IPV4_CKSUM as u64)) != 0;
                tx_csum_offload.tcp =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_TCP_CKSUM as u64)) != 0;
                tx_csum_offload.udp =
                    (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_UDP_CKSUM as u64)) != 0;
            }
            let mut tx_offloads = 0u64;
            if tx_csum_offload.ipv4 {
                tx_offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM as u64;
            }
            if tx_csum_offload.tcp {
                tx_offloads |= DEV_TX_OFFLOAD_TCP_CKSUM as u64;
            }
            if tx_csum_offload.udp {
                tx_offloads |= DEV_TX_OFFLOAD_UDP_CKSUM as u64;
            }
            if (dev_info.tx_offload_capa & (DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64)) != 0 {
                tx_offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE as u64;
            }
            eprintln!(
                "dpdk: tx offload capa=0x{:x} enabled=0x{:x} (ipv4={}, tcp={}, udp={})",
                dev_info.tx_offload_capa,
                tx_offloads,
                tx_csum_offload.ipv4,
                tx_csum_offload.tcp,
                tx_csum_offload.udp
            );
            if queue_count > 1 {
                rss_hf = preferred_rss_hf(dev_info.flow_type_rss_offloads);
                if rss_hf == 0 {
                    eprintln!(
                        "dpdk: rss unsupported (supported_hf=0x{:x}); forcing single queue",
                        dev_info.flow_type_rss_offloads
                    );
                    queue_count = 1;
                }
            }

            let mut port_conf: rte_eth_conf = unsafe {
                let mut conf = std::mem::MaybeUninit::<rte_eth_conf>::uninit();
                std::ptr::write_bytes(conf.as_mut_ptr(), 0, 1);
                conf.assume_init()
            };
            if queue_count > 1 {
                eprintln!(
                    "dpdk: rss supported_hf=0x{:x} selected_hf=0x{:x} reta_size={}",
                    dev_info.flow_type_rss_offloads, rss_hf, dev_info.reta_size
                );
                port_conf.rxmode.mq_mode = rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
                port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
                port_conf.rx_adv_conf.rss_conf.rss_key = std::ptr::null_mut();
                port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            }
            port_conf.txmode.offloads = tx_offloads;
            let ret =
                unsafe { rte_eth_dev_configure(port_id, queue_count, queue_count, &mut port_conf) };
            if ret < 0 {
                return Err(format!("dpdk: port configure failed ({ret})"));
            }

            for queue_id in 0..queue_count {
                let ret = unsafe {
                    rte_eth_rx_queue_setup(
                        port_id,
                        queue_id,
                        RX_RING_SIZE,
                        socket_id_u32,
                        ptr::null(),
                        mempool,
                    )
                };
                if ret < 0 {
                    return Err(format!("dpdk: rx queue {} setup failed ({ret})", queue_id));
                }

                let ret = unsafe {
                    let mut tx_conf = dev_info.default_txconf;
                    tx_conf.offloads = tx_offloads;
                    rte_eth_tx_queue_setup(port_id, queue_id, TX_RING_SIZE, socket_id_u32, &tx_conf)
                };
                if ret < 0 {
                    return Err(format!("dpdk: tx queue {} setup failed ({ret})", queue_id));
                }
            }

            let ret = unsafe { rte_eth_dev_start(port_id) };
            if ret < 0 {
                return Err(format!("dpdk: port start failed ({ret})"));
            }

            unsafe {
                rte_eth_promiscuous_enable(port_id);
            }
            if queue_count > 1 {
                if let Err(err) = configure_rss_reta(port_id, queue_count, dev_info.reta_size) {
                    eprintln!("{err}");
                    eprintln!("dpdk: rss reta unavailable; forcing single worker");
                    queue_count = 1;
                }
            }

            let mut addr: ether_addr = unsafe { std::mem::zeroed() };
            unsafe {
                rte_eth_macaddr_get(port_id, &mut addr);
            }
            let mac = addr.addr_bytes;

            Ok(PortSetup {
                port_id,
                mempool,
                mac,
                queue_count,
                tx_csum_offload,
            })
        });

        match cached {
            Ok(setup) => {
                if setup.queue_count != queue_count {
                    eprintln!(
                        "dpdk: port already initialized with {} queues (requested {}), using {}",
                        setup.queue_count, queue_count, setup.queue_count
                    );
                }
                Ok(PortSetup {
                    port_id: setup.port_id,
                    mempool: setup.mempool,
                    mac: setup.mac,
                    queue_count: setup.queue_count,
                    tx_csum_offload: setup.tx_csum_offload,
                })
            }
            Err(err) => Err(err.clone()),
        }
    }

    impl DpdkIo {
        pub fn effective_queue_count(iface: &str, queue_count: u16) -> Result<u16, String> {
            init_eal(iface)?;
            let setup = init_port(iface, queue_count)?;
            Ok(setup.queue_count.max(1))
        }

        pub fn new(iface: &str, metrics: Option<Metrics>) -> Result<Self, String> {
            Self::new_with_queue(iface, 0, 1, metrics)
        }

        pub fn new_with_queue(
            iface: &str,
            queue_id: u16,
            queue_count: u16,
            metrics: Option<Metrics>,
        ) -> Result<Self, String> {
            init_eal(iface)?;
            let setup = init_port(iface, queue_count)?;
            if queue_id >= setup.queue_count {
                return Err(format!(
                    "dpdk: queue_id {} out of range (queue_count={})",
                    queue_id, setup.queue_count
                ));
            }
            Ok(Self {
                port_id: setup.port_id,
                queue_id,
                queue_label: queue_id.to_string(),
                mempool: setup.mempool,
                mac: setup.mac,
                tx_csum_offload: setup.tx_csum_offload,
                metrics,
                rx_bufs: [ptr::null_mut(); RX_BURST_SIZE],
                rx_count: 0,
                rx_index: 0,
                tx_bufs: [ptr::null_mut(); TX_BURST_SIZE],
                tx_lens: [0; TX_BURST_SIZE],
                tx_count: 0,
                metric_batch: IoMetricBatch::default(),
            })
        }

        fn record_rx_packet(&mut self, bytes: u64) {
            self.metric_batch.rx_packets = self.metric_batch.rx_packets.saturating_add(1);
            self.metric_batch.rx_bytes = self.metric_batch.rx_bytes.saturating_add(bytes);
            self.flush_metrics_if_needed(false);
        }

        fn record_rx_dropped(&mut self, count: u64) {
            self.metric_batch.rx_dropped = self.metric_batch.rx_dropped.saturating_add(count);
            self.flush_metrics_if_needed(false);
        }

        fn record_tx_packet(&mut self, count: u64, bytes: u64) {
            self.metric_batch.tx_packets = self.metric_batch.tx_packets.saturating_add(count);
            self.metric_batch.tx_bytes = self.metric_batch.tx_bytes.saturating_add(bytes);
            self.flush_metrics_if_needed(false);
        }

        fn record_tx_dropped(&mut self, count: u64) {
            self.metric_batch.tx_dropped = self.metric_batch.tx_dropped.saturating_add(count);
            self.flush_metrics_if_needed(false);
        }

        fn flush_metrics_if_needed(&mut self, force: bool) {
            if self.metrics.is_none() {
                self.metric_batch = IoMetricBatch::default();
                return;
            }
            if !force && self.metric_batch.pending_packets() < METRICS_FLUSH_PACKET_THRESHOLD {
                return;
            }
            if self.metric_batch.is_empty() {
                return;
            }
            let Some(metrics) = &self.metrics else {
                return;
            };
            if self.metric_batch.rx_packets > 0 {
                metrics.inc_dpdk_rx_packets(self.metric_batch.rx_packets);
                metrics.inc_dpdk_rx_packets_queue(&self.queue_label, self.metric_batch.rx_packets);
            }
            if self.metric_batch.rx_bytes > 0 {
                metrics.add_dpdk_rx_bytes(self.metric_batch.rx_bytes);
                metrics.add_dpdk_rx_bytes_queue(&self.queue_label, self.metric_batch.rx_bytes);
            }
            if self.metric_batch.rx_dropped > 0 {
                metrics.inc_dpdk_rx_dropped(self.metric_batch.rx_dropped);
                metrics.inc_dpdk_rx_dropped_queue(&self.queue_label, self.metric_batch.rx_dropped);
            }
            if self.metric_batch.tx_packets > 0 {
                metrics.inc_dpdk_tx_packets(self.metric_batch.tx_packets);
                metrics.inc_dpdk_tx_packets_queue(&self.queue_label, self.metric_batch.tx_packets);
            }
            if self.metric_batch.tx_bytes > 0 {
                metrics.add_dpdk_tx_bytes(self.metric_batch.tx_bytes);
                metrics.add_dpdk_tx_bytes_queue(&self.queue_label, self.metric_batch.tx_bytes);
            }
            if self.metric_batch.tx_dropped > 0 {
                metrics.inc_dpdk_tx_dropped(self.metric_batch.tx_dropped);
                metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, self.metric_batch.tx_dropped);
            }
            self.metric_batch = IoMetricBatch::default();
        }

        fn flush_tx(&mut self) -> Result<(), String> {
            if self.tx_count == 0 {
                return Ok(());
            }
            let sent = unsafe {
                rust_rte_eth_tx_burst(
                    self.port_id,
                    self.queue_id,
                    self.tx_bufs.as_mut_ptr(),
                    self.tx_count,
                )
            };
            let sent_usize = sent as usize;
            let mut bytes = 0u64;
            for len in self.tx_lens.iter().take(sent_usize) {
                bytes += *len as u64;
            }
            self.record_tx_packet(sent as u64, bytes);
            if sent_usize < self.tx_count as usize {
                let dropped = (self.tx_count as usize).saturating_sub(sent_usize);
                for idx in sent_usize..self.tx_count as usize {
                    let mbuf = self.tx_bufs[idx];
                    if !mbuf.is_null() {
                        unsafe { rust_rte_pktmbuf_free(mbuf) };
                    }
                }
                self.record_tx_dropped(dropped as u64);
            }
            self.tx_count = 0;
            Ok(())
        }
    }

    impl FrameIo for DpdkIo {
        fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
            let mbuf = loop {
                if self.rx_index >= self.rx_count {
                    let received = unsafe {
                        rust_rte_eth_rx_burst(
                            self.port_id,
                            self.queue_id,
                            self.rx_bufs.as_mut_ptr(),
                            RX_BURST_SIZE as u16,
                        )
                    };
                    if received == 0 {
                        self.flush_metrics_if_needed(true);
                        return Ok(0);
                    }
                    self.rx_count = received;
                    self.rx_index = 0;
                    let first = self.rx_bufs[0];
                    if !first.is_null() {
                        unsafe { rust_rte_mbuf_prefetch_part1(first) };
                    }
                }
                let mbuf = self.rx_bufs[self.rx_index as usize];
                self.rx_index += 1;
                if !mbuf.is_null() {
                    unsafe {
                        rust_rte_mbuf_prefetch_part1(mbuf);
                        rust_rte_mbuf_prefetch_part2(mbuf);
                    }
                    if self.rx_index < self.rx_count {
                        let next = self.rx_bufs[self.rx_index as usize];
                        if !next.is_null() {
                            unsafe { rust_rte_mbuf_prefetch_part1(next) };
                        }
                    }
                    break mbuf;
                }
                self.record_rx_dropped(1);
                if self.rx_index >= self.rx_count {
                    return Ok(0);
                }
            };

            let pkt_len = unsafe { rust_rte_pktmbuf_pkt_len(mbuf) as usize };
            let data_len = unsafe { rust_rte_pktmbuf_data_len(mbuf) as usize };
            let nb_segs = unsafe { rust_rte_pktmbuf_nb_segs(mbuf) };
            let data_off = unsafe { rust_rte_pktmbuf_headroom(mbuf) };

            if pkt_len > buf.len() {
                if DPDK_RX_OVERSIZE_LOGS.fetch_add(1, Ordering::Relaxed) < 10 {
                    eprintln!(
                        "dpdk: rx frame too large (pkt_len={}, buf_len={}, nb_segs={}, data_len={})",
                        pkt_len,
                        buf.len(),
                        nb_segs,
                        data_len
                    );
                }
                unsafe { rust_rte_pktmbuf_free(mbuf) };
                self.record_rx_dropped(1);
                return Ok(0);
            }

            let mut offset = 0usize;
            let mut copy_len = if pkt_len == 0 { data_len } else { pkt_len };
            copy_len = copy_len.min(buf.len());
            if copy_len > 0 {
                let out = unsafe {
                    rust_rte_pktmbuf_read(mbuf, 0, copy_len as u32, buf.as_mut_ptr() as *mut _)
                };
                if out.is_null() {
                    let data_ptr = unsafe { rust_rte_pktmbuf_mtod(mbuf) };
                    let fallback_len = data_len.min(buf.len());
                    if !data_ptr.is_null() && fallback_len > 0 {
                        unsafe {
                            ptr::copy_nonoverlapping(
                                data_ptr as *const u8,
                                buf.as_mut_ptr(),
                                fallback_len,
                            )
                        };
                        offset = fallback_len;
                    } else {
                        eprintln!(
                            "dpdk: rte_pktmbuf_read returned null (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                            pkt_len, data_len, nb_segs, data_off
                        );
                    }
                } else {
                    if out != buf.as_ptr() as *const _ {
                        unsafe {
                            ptr::copy_nonoverlapping(out as *const u8, buf.as_mut_ptr(), copy_len)
                        };
                    }
                    offset = copy_len;
                }
            }

            unsafe { rust_rte_pktmbuf_free(mbuf) };
            if offset == 0 {
                eprintln!(
                    "dpdk: rx mbuf had zero-length payload (pkt_len={}, data_len={}, nb_segs={}, data_off={})",
                    pkt_len, data_len, nb_segs, data_off
                );
                self.record_rx_dropped(1);
            }
            if offset > 0 && !DPDK_RX_LOGGED.swap(true, Ordering::Relaxed) {
                let head_len = offset.min(32);
                let mut hex = String::new();
                for byte in buf.iter().take(head_len) {
                    use std::fmt::Write;
                    let _ = write!(&mut hex, "{:02x} ", byte);
                }
                eprintln!(
                    "dpdk: first rx frame len={} head={}",
                    offset,
                    hex.trim_end()
                );
            }
            if offset > 0 {
                self.record_rx_packet(offset as u64);
            }
            Ok(offset)
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let mbuf = unsafe { rust_rte_pktmbuf_alloc(self.mempool) };
            if mbuf.is_null() {
                self.record_tx_dropped(1);
                return Err("dpdk: failed to allocate mbuf".to_string());
            }
            if frame.len() > u16::MAX as usize {
                unsafe { rust_rte_pktmbuf_free(mbuf) };
                self.record_tx_dropped(1);
                return Err("dpdk: frame exceeds mbuf max length".to_string());
            }
            let dst = unsafe { rust_rte_pktmbuf_append(mbuf, frame.len() as u16) };
            if dst.is_null() {
                unsafe { rust_rte_pktmbuf_free(mbuf) };
                self.record_tx_dropped(1);
                return Err("dpdk: frame exceeds mbuf tailroom".to_string());
            }
            unsafe {
                ptr::copy_nonoverlapping(frame.as_ptr(), dst as *mut u8, frame.len());
            }
            maybe_prepare_tx_checksum_offload(mbuf, frame, self.tx_csum_offload);
            let idx = self.tx_count as usize;
            if idx >= TX_BURST_SIZE {
                self.flush_tx()?;
            }
            let idx = self.tx_count as usize;
            self.tx_bufs[idx] = mbuf;
            self.tx_lens[idx] = frame.len() as u32;
            self.tx_count += 1;
            if self.tx_count as usize >= TX_BURST_SIZE {
                self.flush_tx()?;
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), String> {
            self.flush_tx()?;
            self.flush_metrics_if_needed(true);
            Ok(())
        }

        fn mac(&self) -> Option<[u8; 6]> {
            Some(self.mac)
        }
    }

    pub(super) fn init_eal(iface: &str) -> Result<(), String> {
        let cached = EAL_INIT.get_or_init(|| {
            let max_cores = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
                .max(1);
            let requested = std::env::var("NEUWERK_DPDK_WORKERS")
                .ok()
                .and_then(|val| val.parse::<usize>().ok())
                .unwrap_or(max_cores)
                .max(1);
            let requested = requested.min(max_cores);
            let core_ids = std::env::var("NEUWERK_DPDK_CORE_IDS")
                .ok()
                .map(|raw| parse_core_id_list(&raw))
                .filter(|ids| !ids.is_empty())
                .map(|mut ids| {
                    ids.truncate(requested);
                    ids
                })
                .unwrap_or_else(|| (0..requested).collect());
            let core_list = if core_ids.is_empty() {
                "0".to_string()
            } else {
                core_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            eprintln!("dpdk: eal lcore list={}", core_list);
            let mut args = vec![
                "firewall".to_string(),
                "-l".to_string(),
                core_list,
                "-n".to_string(),
                "4".to_string(),
                "--proc-type=primary".to_string(),
                "--file-prefix=neuwerk".to_string(),
                "--no-telemetry".to_string(),
                "--in-memory".to_string(),
            ];
            let cloud_provider = std::env::var("NEUWERK_CLOUD_PROVIDER")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let iova_override = std::env::var("NEUWERK_DPDK_IOVA").ok();
            if let Some(mode) = iova_override.as_deref() {
                let mode = mode.trim().to_ascii_lowercase();
                if mode == "va" || mode == "pa" {
                    args.push(format!("--iova-mode={}", mode));
                } else {
                    eprintln!("dpdk: invalid NEUWERK_DPDK_IOVA={}, ignoring", mode);
                }
            } else if !iommu_groups_present() {
                args.push("--iova-mode=va".to_string());
                eprintln!("dpdk: no iommu groups detected; forcing iova=va");
            }
            let force_netvsc = std::env::var("NEUWERK_DPDK_NETVSC")
                .ok()
                .as_deref()
                == Some("1");
            let allow_azure_pmds = cloud_provider == "azure";
            let allow_gcp_autoprobe = cloud_provider == "gcp"
                && std::env::var("NEUWERK_GCP_DPDK_AUTOPROBE")
                    .ok()
                    .as_deref()
                    == Some("1");
            if allow_gcp_autoprobe {
                eprintln!("dpdk: gcp auto-probe override enabled");
            }
            if let Some(pci) = normalize_pci_arg(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    eprintln!(
                        "dpdk: gcp auto-probe enabled; ignoring explicit pci selector {}",
                        pci
                    );
                }
            } else if let Ok(pci) = pci_addr_for_iface(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    eprintln!(
                        "dpdk: gcp auto-probe enabled; ignoring iface-derived pci selector {}",
                        pci
                    );
                }
            } else if let Some(mac) = normalize_mac_arg(iface) {
                let mac_str = format_mac(mac);
                if allow_azure_pmds {
                    if let Some(pci) = mana_pci_for_mac(mac) {
                        args.push("-a".to_string());
                        args.push(format!("{},mac={}", pci, format_mac(mac)));
                    } else if let Some(netvsc_iface) = netvsc_iface_for_mac(mac) {
                        args.push("--vdev".to_string());
                        args.push(format!(
                            "net_vdev_netvsc,iface={},force=1",
                            netvsc_iface
                        ));
                    } else if let Some(pci) = pci_addr_for_mac(mac) {
                        args.push("-a".to_string());
                        args.push(pci);
                    } else if force_netvsc {
                        args.push("--vdev".to_string());
                        args.push(format!("net_vdev_netvsc,iface=data0,force=1"));
                    } else {
                        args.push("--vdev".to_string());
                        args.push(format!("net_mana,mac={}", mac_str));
                    }
                } else if allow_gcp_autoprobe {
                    eprintln!(
                        "dpdk: gcp auto-probe enabled; using mac selector {} after probe",
                        mac_str
                    );
                } else if let Some(pci) = pci_addr_for_mac(mac) {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    return Err(format!(
                        "dpdk: mac selector {} did not resolve to PCI; use --data-plane-interface pci:<addr> or set --cloud-provider azure",
                        mac_str
                    ));
                }
            }
            eprintln!("dpdk: eal args: {}", args.join(" "));
            let cstrings: Vec<CString> = args
                .iter()
                .map(|arg| CString::new(arg.as_str()).unwrap())
                .collect();
            let mut argv: Vec<*mut c_char> =
                cstrings.iter().map(|s| s.as_ptr() as *mut c_char).collect();
            let argc = argv.len() as i32;
            let ret = unsafe { rte_eal_init(argc, argv.as_mut_ptr()) };
            if ret < 0 {
                return Err(format!("dpdk: rte_eal_init failed (rte_errno={})", unsafe {
                    rust_rte_errno()
                }));
            }
            Ok(())
        });
        cached.clone()
    }

    fn iommu_groups_present() -> bool {
        let Ok(entries) = fs::read_dir("/sys/kernel/iommu_groups") else {
            return false;
        };
        entries.flatten().next().is_some()
    }

    fn pci_addr_for_iface(iface: &str) -> Result<String, String> {
        let path = format!("/sys/class/net/{iface}/device");
        let target = fs::read_link(Path::new(&path))
            .map_err(|err| format!("dpdk: read_link {path} failed: {err}"))?;
        let name = target
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "dpdk: invalid pci device name".to_string())?;
        Ok(name.to_string())
    }

    fn port_id_for_iface_or_pci(iface: &str, ports: &[PortInfo]) -> Result<u16, String> {
        if let Some(mac) = normalize_mac_arg(iface) {
            match port_id_for_mac(mac, ports) {
                Ok(port) => return Ok(port),
                Err(err) => {
                    if ports.len() == 1 {
                        eprintln!(
                            "dpdk: {} (single port available, falling back to port {})",
                            err, ports[0].id
                        );
                        return Ok(ports[0].id);
                    }
                    return Err(err);
                }
            }
        }
        if let Some(pci) = normalize_pci_arg(iface) {
            return port_id_for_name(&pci);
        }
        if let Ok(pci) = pci_addr_for_iface(iface) {
            if let Ok(port) = port_id_for_name(&pci) {
                return Ok(port);
            }
        }
        if ports.len() == 1 {
            return Ok(ports[0].id);
        }
        Err(format!(
            "dpdk: multiple ports available ({}), unable to map interface or pci {iface}",
            ports.len()
        ))
    }

    fn port_id_for_name(name: &str) -> Result<u16, String> {
        let cname = CString::new(name).map_err(|_| "dpdk: invalid device name".to_string())?;
        let mut port_id: u16 = 0;
        let ret = unsafe { rte_eth_dev_get_port_by_name(cname.as_ptr(), &mut port_id) };
        if ret != 0 {
            return Err(format!("dpdk: rte_eth_dev_get_port_by_name failed ({ret})"));
        }
        Ok(port_id)
    }

    fn port_id_for_mac(mac: [u8; 6], ports: &[PortInfo]) -> Result<u16, String> {
        let matches: Vec<&PortInfo> = ports.iter().filter(|port| port.mac == mac).collect();
        if matches.is_empty() {
            return Err(format!("dpdk: no port found with mac {}", format_mac(mac)));
        }
        if matches.len() == 1 {
            return Ok(matches[0].id);
        }
        let prefer_pci = std::env::var("NEUWERK_DPDK_PREFER_PCI").ok().as_deref() == Some("1");
        if prefer_pci {
            if let Some(port) = matches
                .iter()
                .find(|port| port_name_is_pci(port.name.as_deref()))
            {
                eprintln!(
                    "dpdk: NEUWERK_DPDK_PREFER_PCI=1 selecting pci port {}",
                    port.id
                );
                return Ok(port.id);
            }
        }
        if let Some(port) = matches
            .iter()
            .find(|port| port_name_is_netvsc(port.name.as_deref()))
        {
            return Ok(port.id);
        }
        if let Some(port) = matches
            .iter()
            .find(|port| port_name_is_failsafe(port.name.as_deref()))
        {
            return Ok(port.id);
        }
        if let Some(port) = matches
            .iter()
            .find(|port| port_name_is_tap(port.name.as_deref()))
        {
            return Ok(port.id);
        }
        Ok(matches[0].id)
    }

    fn port_name_is_failsafe(name: Option<&str>) -> bool {
        name.map(|name| name.contains("failsafe")).unwrap_or(false)
    }

    fn port_name_is_netvsc(name: Option<&str>) -> bool {
        name.map(|name| {
            let name = name.to_ascii_lowercase();
            if name.contains("failsafe") || name.contains("tap") {
                return false;
            }
            name.contains("netvsc") || name.contains("net_vdev_netvsc")
        })
        .unwrap_or(false)
    }

    fn port_name_is_tap(name: Option<&str>) -> bool {
        name.map(|name| name.contains("tap")).unwrap_or(false)
    }

    fn port_name_is_pci(name: Option<&str>) -> bool {
        name.map(|name| is_pci_addr(name)).unwrap_or(false)
    }

    fn normalize_pci_arg(value: &str) -> Option<String> {
        let value = value.trim();
        let value = value.strip_prefix("pci:").unwrap_or(value);
        if is_pci_addr(value) {
            Some(value.to_string())
        } else {
            None
        }
    }

    fn normalize_mac_arg(value: &str) -> Option<[u8; 6]> {
        let value = value.trim();
        let value = value.strip_prefix("mac:").unwrap_or(value);
        parse_mac(value)
    }

    fn parse_mac(value: &str) -> Option<[u8; 6]> {
        let mut bytes = [0u8; 6];
        let parts: Vec<&str> = value.split(|c| c == ':' || c == '-').collect();
        if parts.len() != 6 {
            return None;
        }
        for (idx, part) in parts.iter().enumerate() {
            if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let parsed = u8::from_str_radix(part, 16).ok()?;
            bytes[idx] = parsed;
        }
        Some(bytes)
    }

    fn format_mac(mac: [u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    fn pci_addr_for_mac(mac: [u8; 6]) -> Option<String> {
        let target = format_mac(mac);
        let entries = fs::read_dir("/sys/class/net").ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lo" {
                continue;
            }
            let addr_path = format!("/sys/class/net/{}/address", name);
            let addr = fs::read_to_string(addr_path).ok()?;
            if addr.trim().eq_ignore_ascii_case(&target) {
                if let Ok(pci) = pci_addr_for_iface(&name) {
                    if is_pci_addr(&pci) {
                        return Some(pci);
                    }
                }
            }
        }
        None
    }

    fn netvsc_iface_for_mac(mac: [u8; 6]) -> Option<String> {
        let target = format_mac(mac);
        let entries = fs::read_dir("/sys/class/net").ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lo" {
                continue;
            }
            let addr_path = format!("/sys/class/net/{}/address", name);
            let addr = fs::read_to_string(addr_path).ok()?;
            if !addr.trim().eq_ignore_ascii_case(&target) {
                continue;
            }
            let driver_path = format!("/sys/class/net/{}/device/driver", name);
            let driver = fs::read_link(driver_path).ok()?;
            let driver_name = driver.file_name()?.to_string_lossy();
            if driver_name == "hv_netvsc" {
                return Some(name.to_string());
            }
        }
        None
    }

    fn mana_pci_for_mac(mac: [u8; 6]) -> Option<String> {
        let target = format_mac(mac);
        let entries = fs::read_dir("/sys/class/net").ok()?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lo" {
                continue;
            }
            let addr_path = format!("/sys/class/net/{}/address", name);
            let addr = fs::read_to_string(addr_path).ok()?;
            if !addr.trim().eq_ignore_ascii_case(&target) {
                continue;
            }
            let driver_path = format!("/sys/class/net/{}/device/driver", name);
            let driver = fs::read_link(driver_path).ok()?;
            let driver_name = driver.file_name()?.to_string_lossy();
            if driver_name == "mana" {
                if let Ok(pci) = pci_addr_for_iface(&name) {
                    if is_pci_addr(&pci) {
                        return Some(pci);
                    }
                }
            }
        }
        None
    }

    fn is_pci_addr(value: &str) -> bool {
        let parts: Vec<&str> = value.split(':').collect();
        if parts.len() != 2 && parts.len() != 3 {
            return false;
        }
        let (domain, bus, devfn) = if parts.len() == 3 {
            (Some(parts[0]), parts[1], parts[2])
        } else {
            (None, parts[0], parts[1])
        };
        if let Some(domain) = domain {
            if !is_hex_len(domain, 4) {
                return false;
            }
        }
        if !is_hex_len(bus, 2) {
            return false;
        }
        let mut devfn_parts = devfn.split('.');
        let dev = match devfn_parts.next() {
            Some(dev) => dev,
            None => return false,
        };
        let func = match devfn_parts.next() {
            Some(func) => func,
            None => return false,
        };
        if devfn_parts.next().is_some() {
            return false;
        }
        is_hex_len(dev, 2) && is_hex_len(func, 1)
    }

    fn available_ports() -> Vec<PortInfo> {
        let mut ports = Vec::new();
        for port in 0..dpdk_sys::RTE_MAX_ETHPORTS {
            let port = port as u16;
            let valid = unsafe { rte_eth_dev_is_valid_port(port) };
            if valid == 0 {
                continue;
            }
            let mut addr: ether_addr = unsafe { std::mem::zeroed() };
            unsafe { rte_eth_macaddr_get(port, &mut addr) };
            let name = port_name(port);
            ports.push(PortInfo {
                id: port,
                mac: addr.addr_bytes,
                name,
            });
        }
        ports
    }

    fn port_name(port_id: u16) -> Option<String> {
        let mut buf = vec![0u8; dpdk_sys::RTE_ETH_NAME_MAX_LEN as usize];
        let ret = unsafe { rte_eth_dev_get_name_by_port(port_id, buf.as_mut_ptr() as *mut c_char) };
        if ret != 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).ok()
    }

    fn is_hex_len(value: &str, len: usize) -> bool {
        value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
    }

    fn maybe_prepare_tx_checksum_offload(
        mbuf: *mut rte_mbuf,
        frame: &[u8],
        caps: TxChecksumOffloadCaps,
    ) {
        if mbuf.is_null() || !caps.any() {
            return;
        }
        if frame.len() < super::ETH_HDR_LEN + 20 {
            return;
        }
        let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
        if ether_type != super::ETH_TYPE_IPV4 {
            return;
        }
        let ip_off = super::ETH_HDR_LEN;
        let ver_ihl = frame[ip_off];
        if (ver_ihl >> 4) != 4 {
            return;
        }
        let ihl = ((ver_ihl & 0x0f) as usize) * 4;
        if ihl < 20 || frame.len() < ip_off + ihl {
            return;
        }
        let proto = frame[ip_off + 9];
        let l4_off = ip_off + ihl;
        let mut ol_flags = PKT_TX_IPV4;
        if caps.ipv4 {
            ol_flags |= PKT_TX_IP_CKSUM;
        }
        let l4_cksum_ptr = match proto {
            6 if caps.tcp => {
                if frame.len() < l4_off + 20 {
                    return;
                }
                ol_flags |= PKT_TX_TCP_CKSUM;
                (l4_off + 16) as u16
            }
            17 if caps.udp => {
                if frame.len() < l4_off + 8 {
                    return;
                }
                if frame[l4_off + 6] == 0 && frame[l4_off + 7] == 0 {
                    return;
                }
                ol_flags |= PKT_TX_UDP_CKSUM;
                (l4_off + 6) as u16
            }
            _ => return,
        };
        unsafe {
            let ip_hdr = rust_rte_pktmbuf_mtod_offset(mbuf, ip_off as u16) as *mut ipv4_hdr;
            if ip_hdr.is_null() {
                return;
            }
            if (ol_flags & PKT_TX_IP_CKSUM) != 0 {
                std::ptr::write_unaligned(std::ptr::addr_of_mut!((*ip_hdr).hdr_checksum), 0);
            }
            let pseudo = rust_rte_ipv4_phdr_cksum(ip_hdr, ol_flags);
            let l4_cksum = rust_rte_pktmbuf_mtod_offset(mbuf, l4_cksum_ptr) as *mut u16;
            if l4_cksum.is_null() {
                return;
            }
            std::ptr::write_unaligned(l4_cksum, pseudo);

            let m = &mut *mbuf;
            m.ol_flags = ol_flags;
            let tx_offload = m._5._1.as_mut();
            tx_offload.set_l2_len(super::ETH_HDR_LEN as u64);
            tx_offload.set_l3_len(ihl as u64);
            tx_offload.set_l4_len(0);
            tx_offload.set_tso_segsz(0);
            tx_offload.set_outer_l2_len(0);
            tx_offload.set_outer_l3_len(0);
        }
    }
}

#[cfg(feature = "dpdk")]
pub fn preinit_dpdk_eal(iface: &str) -> Result<(), String> {
    dpdk_io::init_eal(iface)
}

#[cfg(feature = "dpdk")]
pub use dpdk_io::DpdkIo;
#[cfg(not(feature = "dpdk"))]
pub use UnwiredDpdkIo as DpdkIo;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::metrics::Metrics;
    use crate::dataplane::config::DataplaneConfig;
    use crate::dataplane::policy::{
        CidrV4, DefaultPolicy, IpSetV4, PolicySnapshot, Proto, Rule, RuleAction, RuleMatch,
        SourceGroup, Tls13Uninspectable, TlsMatch, TlsMode,
    };
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, RwLock};
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Default)]
    struct RecordingIo {
        sent: Vec<Vec<u8>>,
    }

    impl FrameIo for RecordingIo {
        fn recv_frame(&mut self, _buf: &mut [u8]) -> Result<usize, String> {
            Ok(0)
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            self.sent.push(frame.to_vec());
            Ok(())
        }
    }

    fn metric_value(rendered: &str, name: &str) -> Option<f64> {
        for line in rendered.lines() {
            if line.starts_with('#') || !line.starts_with(name) {
                continue;
            }
            if line.contains('{') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let metric = parts.next()?;
            if metric != name {
                continue;
            }
            let value = parts.next()?;
            if let Ok(parsed) = value.parse::<f64>() {
                return Some(parsed);
            }
        }
        None
    }

    fn with_intercept_env<R>(ip: Option<&str>, port: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let old_ip = std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP").ok();
        let old_port = std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT").ok();

        match ip {
            Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP", value),
            None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP"),
        }
        match port {
            Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT", value),
            None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT"),
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        match old_ip {
            Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP", value),
            None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP"),
        }
        match old_port {
            Some(value) => std::env::set_var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT", value),
            None => std::env::remove_var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT"),
        }

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    fn with_default_intercept_env<R>(f: impl FnOnce() -> R) -> R {
        with_intercept_env(None, None, f)
    }

    fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
        let mut buf = vec![0u8; 42];
        buf[0..6].copy_from_slice(&[0xff; 6]);
        buf[6..12].copy_from_slice(&sender_mac);
        buf[12..14].copy_from_slice(&ETH_TYPE_ARP.to_be_bytes());
        buf[14..16].copy_from_slice(&1u16.to_be_bytes());
        buf[16..18].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        buf[18] = 6;
        buf[19] = 4;
        buf[20..22].copy_from_slice(&1u16.to_be_bytes());
        buf[22..28].copy_from_slice(&sender_mac);
        buf[28..32].copy_from_slice(&sender_ip.octets());
        buf[32..38].copy_from_slice(&[0u8; 6]);
        buf[38..42].copy_from_slice(&target_ip.octets());
        buf
    }

    fn build_udp_ipv4_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        build_udp_frame(
            src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload,
        )
    }

    fn build_tcp_syn_ipv4_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        build_tcp_ipv4_frame_with_flags(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, 0x02)
    }

    fn build_tcp_ipv4_frame_with_flags(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
    ) -> Vec<u8> {
        let total_len = 20 + 20;
        let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

        let ip_off = ETH_HDR_LEN;
        buf[ip_off] = 0x45;
        buf[ip_off + 1] = 0;
        buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_off + 8] = 64;
        buf[ip_off + 9] = 6;
        buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
        buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

        let tcp_off = ip_off + 20;
        buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&1u32.to_be_bytes());
        buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&0u32.to_be_bytes());
        buf[tcp_off + 12] = 0x50;
        buf[tcp_off + 13] = flags;
        buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64240u16.to_be_bytes());
        buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&0u16.to_be_bytes());
        buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&0u16.to_be_bytes());

        let mut pkt = Packet::new(buf);
        let _ = pkt.recalc_checksums();
        pkt.buffer().to_vec()
    }

    fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 8 + inner.len()];
        buf[0] = 0x08;
        buf[4] = ((vni >> 16) & 0xff) as u8;
        buf[5] = ((vni >> 8) & 0xff) as u8;
        buf[6] = (vni & 0xff) as u8;
        buf[8..].copy_from_slice(inner);
        buf
    }

    fn parse_vxlan_outer_udp(frame: &[u8]) -> Result<(u16, u16, u32), String> {
        if frame.len() < ETH_HDR_LEN + 20 + 8 + 8 {
            return Err("frame too short".to_string());
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != ETH_TYPE_IPV4 {
            return Err("not ipv4 ethernet frame".to_string());
        }
        let ipv4 = parse_ipv4(frame, ETH_HDR_LEN).ok_or_else(|| "parse ipv4 failed".to_string())?;
        if ipv4.proto != 17 {
            return Err("not udp".to_string());
        }
        let udp = parse_udp(frame, ipv4.l4_offset).ok_or_else(|| "parse udp failed".to_string())?;
        if udp.payload_len < 8 {
            return Err("vxlan payload too short".to_string());
        }
        let payload = &frame[udp.payload_offset..udp.payload_offset + udp.payload_len];
        if payload[0] & 0x08 == 0 {
            return Err("vxlan I-bit not set".to_string());
        }
        let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
        Ok((udp.src_port, udp.dst_port, vni))
    }

    fn intercept_policy_snapshot() -> PolicySnapshot {
        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        let rule = Rule {
            id: "tls-intercept".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: None,
                proto: Proto::Tcp,
                src_ports: Vec::new(),
                dst_ports: vec![crate::dataplane::policy::PortRange {
                    start: 443,
                    end: 443,
                }],
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: Some(TlsMatch {
                    mode: TlsMode::Intercept,
                    sni: None,
                    server_san: None,
                    server_cn: None,
                    fingerprints_sha256: Vec::new(),
                    trust_anchors: Vec::new(),
                    tls13_uninspectable: Tls13Uninspectable::Deny,
                    intercept_http: None,
                }),
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };
        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };
        PolicySnapshot::new_with_generation(DefaultPolicy::Deny, vec![group], 1)
    }

    #[test]
    fn process_frame_replies_to_arp_for_dataplane_ip() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let metrics = Metrics::new().unwrap();
        let mut state =
            EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
        state.set_metrics(metrics.clone());
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: Ipv4Addr::new(10, 0, 0, 2),
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                lease_expiry: None,
            });
            store
        });

        let req = build_arp_request(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let reply = adapter.process_frame(&req, &mut state).expect("arp reply");
        assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&reply[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 2);

        let rendered = metrics.render().unwrap();
        let value = metric_value(&rendered, "dp_arp_handled_total").unwrap_or(0.0);
        assert!(value >= 1.0, "metrics:\n{rendered}");
    }

    #[test]
    fn process_frame_sends_dhcp_payload_to_control_plane() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        adapter.set_dhcp_tx(tx);
        let mut state = EngineState::new(
            Arc::new(RwLock::new(PolicySnapshot::new(
                DefaultPolicy::Deny,
                Vec::new(),
            ))),
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::UNSPECIFIED,
            0,
        );

        let payload = b"dhcp-test";
        let frame = build_udp_ipv4_frame(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0xff; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
            payload,
        );
        assert!(adapter.process_frame(&frame, &mut state).is_none());
        let msg = rx.try_recv().expect("dhcp rx");
        assert_eq!(msg.src_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn process_frame_learns_arp_from_dhcp_server_frame() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let mut state = EngineState::new(
            Arc::new(RwLock::new(PolicySnapshot::new(
                DefaultPolicy::Deny,
                Vec::new(),
            ))),
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        let server_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let frame = build_udp_ipv4_frame(
            server_mac,
            [0xff; 6],
            server_ip,
            Ipv4Addr::BROADCAST,
            DHCP_SERVER_PORT,
            DHCP_CLIENT_PORT,
            b"dhcp-test",
        );

        assert!(adapter.process_frame(&frame, &mut state).is_none());
        assert_eq!(adapter.lookup_arp(server_ip), Some(server_mac));
    }

    #[test]
    fn next_dhcp_frame_builds_broadcast_frame() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

        let (tx, rx) = mpsc::channel(1);
        adapter.set_dhcp_rx(rx);
        tx.try_send(DhcpTx::Broadcast {
            payload: b"hello".to_vec(),
        })
        .unwrap();

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
        let frame = adapter.next_dhcp_frame(&state).expect("dhcp frame");
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_TYPE_IPV4);
        let udp_off = ETH_HDR_LEN + 20;
        assert_eq!(
            u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]),
            DHCP_CLIENT_PORT
        );
        assert_eq!(
            u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]),
            DHCP_SERVER_PORT
        );
    }

    #[test]
    fn process_packet_in_place_forward_returns_borrowed_and_rewrites_l2() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let gw_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let gw_ip = Ipv4Addr::new(10, 20, 2, 1);
        let fw_ip = Ipv4Addr::new(10, 20, 2, 4);
        adapter.set_mac(fw_mac);
        adapter.insert_arp(gw_ip, gw_mac);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Allow,
            Vec::new(),
        )));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 20, 3, 0),
            24,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: fw_ip,
                prefix: 24,
                gateway: gw_ip,
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let frame = build_udp_ipv4_frame(
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            fw_mac,
            Ipv4Addr::new(10, 20, 3, 4),
            Ipv4Addr::new(10, 20, 4, 4),
            12345,
            80,
            b"hello",
        );
        let mut pkt = Packet::new(frame);

        match adapter.process_packet_in_place(&mut pkt, &mut state) {
            Some(FrameOut::Borrowed(out)) => {
                assert_eq!(out.as_ptr(), pkt.buffer().as_ptr());
                assert_eq!(&pkt.buffer()[0..6], &gw_mac);
                assert_eq!(&pkt.buffer()[6..12], &fw_mac);
            }
            Some(FrameOut::Owned(_)) => panic!("expected borrowed frame for forward path"),
            None => panic!("expected forwarded frame"),
        }
    }

    #[test]
    fn process_packet_in_place_arp_returns_owned() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let mut state =
            EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: fw_ip,
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let req = build_arp_request(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            Ipv4Addr::new(10, 0, 0, 1),
            fw_ip,
        );
        let mut pkt = Packet::new(req);
        match adapter.process_packet_in_place(&mut pkt, &mut state) {
            Some(FrameOut::Owned(reply)) => {
                assert_eq!(&reply[0..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
                assert_eq!(&reply[6..12], &fw_mac);
                assert_eq!(u16::from_be_bytes([reply[20], reply[21]]), 2);
            }
            Some(FrameOut::Borrowed(_)) => panic!("expected owned reply for arp path"),
            None => panic!("expected arp reply"),
        }
    }

    #[test]
    fn process_packet_in_place_health_probe_returns_owned() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
        let client_ip = Ipv4Addr::new(10, 0, 0, 99);
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: fw_ip,
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let syn = build_tcp_syn_ipv4_frame(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            fw_mac,
            client_ip,
            fw_ip,
            40000,
            HEALTH_PROBE_PORT,
        );
        let mut pkt = Packet::new(syn);
        match adapter.process_packet_in_place(&mut pkt, &mut state) {
            Some(FrameOut::Owned(reply)) => {
                let ipv4 = parse_ipv4(&reply, ETH_HDR_LEN).expect("ipv4");
                let tcp = parse_tcp(&reply, ipv4.l4_offset).expect("tcp");
                assert_eq!(ipv4.src, fw_ip);
                assert_eq!(ipv4.dst, client_ip);
                assert_eq!(tcp.src_port, HEALTH_PROBE_PORT);
                assert_eq!(tcp.dst_port, 40000);
                assert_eq!(tcp.flags & 0x12, 0x12);
            }
            Some(FrameOut::Borrowed(_)) => panic!("expected owned reply for health probe path"),
            None => panic!("expected health probe synack"),
        }
    }

    #[test]
    fn process_frame_health_probe_non_syn_is_ignored() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        state.set_dataplane_config({
            let store = crate::dataplane::config::DataplaneConfigStore::new();
            store.set(DataplaneConfig {
                ip: fw_ip,
                prefix: 24,
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                mac: fw_mac,
                lease_expiry: None,
            });
            store
        });

        let ack = build_tcp_ipv4_frame_with_flags(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            fw_mac,
            Ipv4Addr::new(10, 0, 0, 99),
            fw_ip,
            40000,
            HEALTH_PROBE_PORT,
            0x10,
        );
        assert!(
            adapter.process_frame(&ack, &mut state).is_none(),
            "non-SYN packet to health probe port should not trigger SYN-ACK"
        );
    }

    #[test]
    fn build_dhcp_frame_unicast_uses_server_hint_when_ip_matches() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        adapter.set_mac(fw_mac);
        adapter.dhcp_server_hint = Some(DhcpServerHint {
            ip: server_ip,
            mac: server_mac,
        });

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
        state.dataplane_config.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });

        let frame = adapter
            .build_dhcp_frame(
                &state,
                DhcpTx::Unicast {
                    payload: b"renew".to_vec(),
                    dst_ip: server_ip,
                },
            )
            .expect("dhcp unicast frame");
        assert_eq!(&frame[0..6], &server_mac);
        assert_eq!(&frame[6..12], &fw_mac);
        let ipv4 = parse_ipv4(&frame, ETH_HDR_LEN).expect("ipv4");
        let udp = parse_udp(&frame, ipv4.l4_offset).expect("udp");
        assert_eq!(ipv4.src, fw_ip);
        assert_eq!(ipv4.dst, server_ip);
        assert_eq!(udp.src_port, DHCP_CLIENT_PORT);
        assert_eq!(udp.dst_port, DHCP_SERVER_PORT);
    }

    #[test]
    fn build_dhcp_frame_unicast_falls_back_to_broadcast_mac_on_hint_miss() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let fw_ip = Ipv4Addr::new(10, 0, 0, 2);
        adapter.set_mac(fw_mac);
        adapter.dhcp_server_hint = Some(DhcpServerHint {
            ip: Ipv4Addr::new(10, 0, 0, 254),
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        });

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Deny,
            Vec::new(),
        )));
        let state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
        state.dataplane_config.set(DataplaneConfig {
            ip: fw_ip,
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: fw_mac,
            lease_expiry: None,
        });

        let dst_ip = Ipv4Addr::new(10, 0, 0, 200);
        let frame = adapter
            .build_dhcp_frame(
                &state,
                DhcpTx::Unicast {
                    payload: b"renew".to_vec(),
                    dst_ip,
                },
            )
            .expect("dhcp unicast frame");
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &fw_mac);
        let ipv4 = parse_ipv4(&frame, ETH_HDR_LEN).expect("ipv4");
        assert_eq!(ipv4.src, fw_ip);
        assert_eq!(ipv4.dst, dst_ip);
    }

    #[test]
    fn shared_arp_cooldown_prevents_duplicate_arp_requests_across_adapters() {
        let shared = Arc::new(Mutex::new(SharedArpState::default()));
        let mut a = DpdkAdapter::new("data0".to_string()).unwrap();
        let mut b = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        a.set_mac(fw_mac);
        b.set_mac(fw_mac);
        a.set_shared_arp(shared.clone());
        b.set_shared_arp(shared);

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(
            DefaultPolicy::Allow,
            Vec::new(),
        )));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        state.dataplane_config.set(DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 1),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 254),
            mac: fw_mac,
            lease_expiry: None,
        });

        let frame = build_udp_ipv4_frame(
            [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
            fw_mac,
            Ipv4Addr::new(10, 0, 0, 42),
            Ipv4Addr::new(198, 51, 100, 10),
            12345,
            80,
            b"hello",
        );
        assert!(a.process_frame(&frame, &mut state).is_none());
        assert!(b.process_frame(&frame, &mut state).is_none());

        assert!(
            a.next_dhcp_frame(&state).is_some(),
            "first adapter should queue ARP request"
        );
        assert!(
            b.next_dhcp_frame(&state).is_none(),
            "shared cooldown should suppress duplicate ARP request"
        );
    }

    #[test]
    fn lookup_arp_evicts_stale_entries_and_falls_back_to_fresh_shared_cache() {
        let shared = Arc::new(Mutex::new(SharedArpState::default()));
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        adapter.set_shared_arp(shared.clone());

        let stale_ip = Ipv4Addr::new(10, 0, 0, 99);
        let stale_mac = [0x00, 0x10, 0x20, 0x30, 0x40, 0x50];
        adapter.insert_arp(stale_ip, stale_mac);

        let stale_seen = Instant::now() - Duration::from_secs(ARP_CACHE_TTL_SECS + 1);
        adapter.arp_cache.insert(
            stale_ip,
            ArpEntry {
                mac: stale_mac,
                last_seen: stale_seen,
            },
        );
        {
            let mut guard = shared.lock().expect("shared arp lock");
            guard.cache.insert(
                stale_ip,
                ArpEntry {
                    mac: stale_mac,
                    last_seen: stale_seen,
                },
            );
        }

        assert_eq!(adapter.lookup_arp(stale_ip), None);
        assert!(
            !adapter.arp_cache.contains_key(&stale_ip),
            "stale local ARP entry should be removed"
        );
        assert!(
            !shared
                .lock()
                .expect("shared arp lock")
                .cache
                .contains_key(&stale_ip),
            "stale shared ARP entry should be removed"
        );

        let fresh_ip = Ipv4Addr::new(10, 0, 0, 100);
        let stale_local_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01];
        let fresh_shared_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02];
        adapter.arp_cache.insert(
            fresh_ip,
            ArpEntry {
                mac: stale_local_mac,
                last_seen: stale_seen,
            },
        );
        {
            let mut guard = shared.lock().expect("shared arp lock");
            guard.cache.insert(
                fresh_ip,
                ArpEntry {
                    mac: fresh_shared_mac,
                    last_seen: Instant::now(),
                },
            );
        }

        assert_eq!(adapter.lookup_arp(fresh_ip), Some(fresh_shared_mac));
        assert_eq!(
            adapter.arp_cache.get(&fresh_ip).map(|entry| entry.mac),
            Some(fresh_shared_mac),
            "lookup should refresh local cache from shared cache"
        );
    }

    #[test]
    fn process_frame_intercept_uses_env_overridden_service_endpoint() {
        with_intercept_env(Some("169.254.200.9"), Some("18080"), || {
            let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
            let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            adapter.set_mac(fw_mac);

            let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
            let mut state = EngineState::new(
                policy,
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
                [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
                fw_mac,
                Ipv4Addr::new(10, 0, 0, 42),
                Ipv4Addr::new(198, 51, 100, 10),
                40000,
                443,
            );
            assert!(adapter.process_frame(&outbound, &mut state).is_none());
            let host_frame = adapter.next_host_frame().expect("expected host frame");
            let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
            let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
            assert_eq!(ipv4.dst, Ipv4Addr::new(169, 254, 200, 9));
            assert_eq!(tcp.dst_port, 18080);
        })
    }

    #[test]
    fn intercept_demux_removed_on_client_fin_prevents_tuple_restore() {
        with_default_intercept_env(|| {
            let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
            let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let client_ip = Ipv4Addr::new(10, 0, 0, 42);
            let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
            adapter.set_mac(fw_mac);
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

            let syn = build_tcp_syn_ipv4_frame(
                client_mac,
                fw_mac,
                client_ip,
                Ipv4Addr::new(198, 51, 100, 10),
                40000,
                443,
            );
            assert!(adapter.process_frame(&syn, &mut state).is_none());
            let _ = adapter
                .next_host_frame()
                .expect("expected initial host frame");

            let fin = build_tcp_ipv4_frame_with_flags(
                client_mac,
                fw_mac,
                client_ip,
                Ipv4Addr::new(198, 51, 100, 10),
                40000,
                443,
                0x11,
            );
            assert!(adapter.process_frame(&fin, &mut state).is_none());
            let _ = adapter.next_host_frame().expect("expected fin host frame");

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
                .expect("service-lane frame should still forward");
            let ipv4 = parse_ipv4(&forwarded, ETH_HDR_LEN).expect("ipv4");
            let tcp = parse_tcp(&forwarded, ipv4.l4_offset).expect("tcp");
            assert_eq!(ipv4.src, INTERCEPT_SERVICE_IP_DEFAULT);
            assert_eq!(tcp.src_port, INTERCEPT_SERVICE_PORT_DEFAULT);
        });
    }

    #[test]
    fn process_frame_overlay_dual_tunnel_swaps_and_forces_src_port() {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let old_swap = std::env::var("NEUWERK_GWLB_SWAP_TUNNELS").ok();
        let old_force = std::env::var("NEUWERK_GWLB_TUNNEL_SRC_PORT").ok();
        std::env::set_var("NEUWERK_GWLB_SWAP_TUNNELS", "1");
        std::env::set_var("NEUWERK_GWLB_TUNNEL_SRC_PORT", "1");

        let result = (|| {
            let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
            adapter.set_mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);

            let policy = Arc::new(RwLock::new(PolicySnapshot::new(
                DefaultPolicy::Allow,
                Vec::new(),
            )));
            let mut state = EngineState::new(
                policy,
                Ipv4Addr::new(10, 0, 0, 0),
                24,
                Ipv4Addr::UNSPECIFIED,
                0,
            );
            state.set_snat_mode(crate::dataplane::overlay::SnatMode::None);
            state.set_overlay_config(crate::dataplane::overlay::OverlayConfig {
                mode: EncapMode::Vxlan,
                udp_port: 0,
                udp_port_internal: Some(10800),
                udp_port_external: Some(10801),
                vni: None,
                vni_internal: Some(800),
                vni_external: Some(801),
                mtu: 1500,
            });

            let inner = build_udp_ipv4_frame(
                [0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
                [0x20, 0x21, 0x22, 0x23, 0x24, 0x25],
                Ipv4Addr::new(10, 0, 0, 42),
                Ipv4Addr::new(198, 51, 100, 10),
                40000,
                80,
                b"hello",
            );
            let payload = build_vxlan_payload(&inner, 800);
            let outer = build_udp_ipv4_frame(
                [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                Ipv4Addr::new(192, 0, 2, 10),
                Ipv4Addr::new(192, 0, 2, 11),
                5555,
                10800,
                &payload,
            );

            let out = adapter
                .process_frame(&outer, &mut state)
                .expect("overlay frame should forward");
            let (src_port, dst_port, vni) =
                parse_vxlan_outer_udp(&out).expect("parse output vxlan");
            assert_eq!(dst_port, 10801, "reply should switch to external tunnel");
            assert_eq!(vni, 801, "reply should switch to external vni");
            assert_eq!(
                src_port, 10801,
                "outer src port should be forced to tunnel port"
            );
        })();

        match old_swap {
            Some(value) => std::env::set_var("NEUWERK_GWLB_SWAP_TUNNELS", value),
            None => std::env::remove_var("NEUWERK_GWLB_SWAP_TUNNELS"),
        }
        match old_force {
            Some(value) => std::env::set_var("NEUWERK_GWLB_TUNNEL_SRC_PORT", value),
            None => std::env::remove_var("NEUWERK_GWLB_TUNNEL_SRC_PORT"),
        }

        result
    }

    #[test]
    fn process_frame_intercept_fail_closed_returns_rst() {
        let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        adapter.set_mac(fw_mac);

        let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            Ipv4Addr::new(203, 0, 113, 1),
            0,
        );
        state.set_service_policy_applied_generation(Arc::new(AtomicU64::new(0)));
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

        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        adapter.insert_arp(client_ip, client_mac);
        let outbound = build_tcp_syn_ipv4_frame(
            client_mac,
            fw_mac,
            client_ip,
            Ipv4Addr::new(198, 51, 100, 10),
            40000,
            443,
        );

        let rst = adapter
            .process_frame(&outbound, &mut state)
            .expect("expected fail-closed rst frame");
        assert_eq!(&rst[0..6], &client_mac);
        assert_eq!(&rst[6..12], &fw_mac);
        let ipv4 = parse_ipv4(&rst, ETH_HDR_LEN).expect("ipv4");
        let tcp = parse_tcp(&rst, ipv4.l4_offset).expect("tcp");
        assert!(
            tcp.flags & 0x04 != 0,
            "tcp rst flag missing: {:02x}",
            tcp.flags
        );
        assert_eq!(ipv4.src, Ipv4Addr::new(198, 51, 100, 10));
        assert_eq!(ipv4.dst, client_ip);
    }

    #[test]
    fn process_frame_intercept_ready_queues_service_lane_frame() {
        with_default_intercept_env(|| {
            let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
            let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            adapter.set_mac(fw_mac);

            let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
            let mut state = EngineState::new(
                policy,
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

            let client_ip = Ipv4Addr::new(10, 0, 0, 42);
            let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
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
                "intercept-eligible flow should not egress dataplane directly"
            );
            let host_frame = adapter
                .next_host_frame()
                .expect("expected service-lane frame");
            assert_eq!(host_frame.len(), outbound.len());
            assert_eq!(&host_frame[0..6], &[0xff; 6]);
            assert_eq!(
                u16::from_be_bytes([host_frame[12], host_frame[13]]),
                ETH_TYPE_IPV4
            );
            let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
            let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
            assert_eq!(ipv4.src, client_ip);
            assert_eq!(ipv4.dst, INTERCEPT_SERVICE_IP_DEFAULT);
            assert_eq!(tcp.dst_port, INTERCEPT_SERVICE_PORT_DEFAULT);
        });
    }

    #[test]
    fn process_frame_intercept_ready_targets_service_lane_mac_when_known() {
        with_default_intercept_env(|| {
            let mut adapter = DpdkAdapter::new("data0".to_string()).unwrap();
            let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let svc_mac = [0x4a, 0x0e, 0x7b, 0x9e, 0x36, 0x7d];
            adapter.set_mac(fw_mac);
            adapter.service_lane_mac = Some(svc_mac);

            let policy = Arc::new(RwLock::new(intercept_policy_snapshot()));
            let mut state = EngineState::new(
                policy,
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

            let client_ip = Ipv4Addr::new(10, 0, 0, 42);
            let client_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
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
                "intercept-eligible flow should not egress dataplane directly"
            );
            let host_frame = adapter
                .next_host_frame()
                .expect("expected service-lane frame");
            assert_eq!(host_frame.len(), outbound.len());
            assert_eq!(&host_frame[0..6], &svc_mac);
            let ipv4 = parse_ipv4(&host_frame, ETH_HDR_LEN).expect("ipv4");
            let tcp = parse_tcp(&host_frame, ipv4.l4_offset).expect("tcp");
            assert_eq!(ipv4.src, client_ip);
            assert_eq!(ipv4.dst, INTERCEPT_SERVICE_IP_DEFAULT);
            assert_eq!(tcp.dst_port, INTERCEPT_SERVICE_PORT_DEFAULT);
        });
    }

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
            adapter.service_lane_tap = Some(unsafe { File::from_raw_fd(fds[0]) });

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
    fn process_service_lane_egress_uses_shared_intercept_demux_across_adapters() {
        with_default_intercept_env(|| {
            let shared = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));
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
}
