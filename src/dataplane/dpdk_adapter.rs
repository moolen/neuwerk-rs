use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
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
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return None;
        }
        bytes[idx] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
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

#[derive(Debug)]
pub struct DpdkAdapter {
    data_iface: String,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac: [u8; 6],
    dhcp_server_hint: Option<DhcpServerHint>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    shared_arp: Option<Arc<Mutex<SharedArpState>>>,
    arp_cache: HashMap<Ipv4Addr, ArpEntry>,
    arp_last_request: HashMap<Ipv4Addr, Instant>,
    pending_frames: VecDeque<Vec<u8>>,
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
            arp_cache: HashMap::new(),
            arp_last_request: HashMap::new(),
            pending_frames: VecDeque::new(),
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
            Action::Drop | Action::ToHost => None,
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
            Action::Drop | Action::ToHost => None,
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
            pkt.prepare_for_rx(65536);
            let n = io.recv_frame(pkt.buffer_mut())?;
            if n == 0 {
                io.flush()?;
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
    const MBUF_PER_POOL: u32 = 8192;
    const RX_BURST_SIZE: usize = 32;
    const TX_BURST_SIZE: usize = 32;

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
        metrics: Option<Metrics>,
        rx_bufs: [*mut rte_mbuf; RX_BURST_SIZE],
        rx_count: u16,
        rx_index: u16,
        tx_bufs: [*mut rte_mbuf; TX_BURST_SIZE],
        tx_lens: [u32; TX_BURST_SIZE],
        tx_count: u16,
    }

    static DPDK_RX_LOGGED: AtomicBool = AtomicBool::new(false);
    static DPDK_RX_OVERSIZE_LOGS: AtomicU32 = AtomicU32::new(0);
    static DPDK_IPV4_LOGS: AtomicUsize = AtomicUsize::new(0);

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
            let mempool = unsafe {
                rte_pktmbuf_pool_create(
                    pool_name.as_ptr(),
                    MBUF_PER_POOL,
                    MBUF_CACHE_SIZE,
                    0,
                    RTE_MBUF_DEFAULT_BUF_SIZE as u16,
                    socket_id,
                )
            };
            if mempool.is_null() {
                return Err(format!(
                    "dpdk: failed to create mempool (rte_errno={})",
                    unsafe { rust_rte_errno() }
                ));
            }

            let mut port_conf: rte_eth_conf = unsafe {
                let mut conf = std::mem::MaybeUninit::<rte_eth_conf>::uninit();
                std::ptr::write_bytes(conf.as_mut_ptr(), 0, 1);
                conf.assume_init()
            };
            if queue_count > 1 {
                port_conf.rxmode.mq_mode = rte_eth_rx_mq_mode::ETH_MQ_RX_RSS;
                port_conf.rx_adv_conf.rss_conf.rss_hf = dev_info.flow_type_rss_offloads;
                port_conf.rx_adv_conf.rss_conf.rss_key = std::ptr::null_mut();
                port_conf.rx_adv_conf.rss_conf.rss_key_len = 0;
            }
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
                    rte_eth_tx_queue_setup(
                        port_id,
                        queue_id,
                        TX_RING_SIZE,
                        socket_id_u32,
                        ptr::null(),
                    )
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
                metrics,
                rx_bufs: [ptr::null_mut(); RX_BURST_SIZE],
                rx_count: 0,
                rx_index: 0,
                tx_bufs: [ptr::null_mut(); TX_BURST_SIZE],
                tx_lens: [0; TX_BURST_SIZE],
                tx_count: 0,
            })
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
            if let Some(metrics) = &self.metrics {
                metrics.inc_dpdk_tx_packets(sent as u64);
                let mut bytes = 0u64;
                for len in self.tx_lens.iter().take(sent_usize) {
                    bytes += *len as u64;
                }
                if bytes > 0 {
                    metrics.add_dpdk_tx_bytes(bytes);
                    metrics.add_dpdk_tx_bytes_queue(&self.queue_label, bytes);
                }
                metrics.inc_dpdk_tx_packets_queue(&self.queue_label, sent as u64);
            }
            if sent_usize < self.tx_count as usize {
                let dropped = (self.tx_count as usize).saturating_sub(sent_usize);
                for idx in sent_usize..self.tx_count as usize {
                    let mbuf = self.tx_bufs[idx];
                    if !mbuf.is_null() {
                        unsafe { rust_rte_pktmbuf_free(mbuf) };
                    }
                }
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_tx_dropped(dropped as u64);
                    metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, dropped as u64);
                }
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
                        return Ok(0);
                    }
                    self.rx_count = received;
                    self.rx_index = 0;
                }
                let mbuf = self.rx_bufs[self.rx_index as usize];
                self.rx_index += 1;
                if !mbuf.is_null() {
                    break mbuf;
                }
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_rx_dropped(1);
                    metrics.inc_dpdk_rx_dropped_queue(&self.queue_label, 1);
                }
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
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_rx_dropped(1);
                    metrics.inc_dpdk_rx_dropped_queue(&self.queue_label, 1);
                }
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
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_rx_dropped(1);
                    metrics.inc_dpdk_rx_dropped_queue(&self.queue_label, 1);
                }
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
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_rx_packets(1);
                    metrics.add_dpdk_rx_bytes(offset as u64);
                    metrics.inc_dpdk_rx_packets_queue(&self.queue_label, 1);
                    metrics.add_dpdk_rx_bytes_queue(&self.queue_label, offset as u64);
                }
            }
            Ok(offset)
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let mbuf = unsafe { rust_rte_pktmbuf_alloc(self.mempool) };
            if mbuf.is_null() {
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_tx_dropped(1);
                    metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, 1);
                }
                return Err("dpdk: failed to allocate mbuf".to_string());
            }
            if frame.len() > u16::MAX as usize {
                unsafe { rust_rte_pktmbuf_free(mbuf) };
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_tx_dropped(1);
                    metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, 1);
                }
                return Err("dpdk: frame exceeds mbuf max length".to_string());
            }
            let dst = unsafe { rust_rte_pktmbuf_append(mbuf, frame.len() as u16) };
            if dst.is_null() {
                unsafe { rust_rte_pktmbuf_free(mbuf) };
                if let Some(metrics) = &self.metrics {
                    metrics.inc_dpdk_tx_dropped(1);
                    metrics.inc_dpdk_tx_dropped_queue(&self.queue_label, 1);
                }
                return Err("dpdk: frame exceeds mbuf tailroom".to_string());
            }
            unsafe {
                ptr::copy_nonoverlapping(frame.as_ptr(), dst as *mut u8, frame.len());
            }
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
            self.flush_tx()
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
            let core_count = requested.min(max_cores);
            let core_list = if core_count <= 1 {
                "0".to_string()
            } else {
                format!("0-{}", core_count - 1)
            };
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
            let cloud_provider = std::env::var("NEUWERK_CLOUD_PROVIDER")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let allow_azure_pmds = cloud_provider == "azure";
            if let Some(pci) = normalize_pci_arg(iface) {
                args.push("-a".to_string());
                args.push(pci);
            } else if let Ok(pci) = pci_addr_for_iface(iface) {
                args.push("-a".to_string());
                args.push(pci);
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
    use crate::dataplane::policy::DefaultPolicy;
    use crate::dataplane::policy::PolicySnapshot;
    use std::sync::{Arc, RwLock};

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
}
