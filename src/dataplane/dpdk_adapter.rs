use std::net::Ipv4Addr;

use tokio::sync::{mpsc, watch};

use crate::dataplane::dhcp::{DhcpRx, DhcpTx, DHCP_CLIENT_PORT, DHCP_SERVER_PORT};
use crate::dataplane::engine::{Action, EngineState};
use crate::dataplane::packet::Packet;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const ETH_TYPE_ARP: u16 = 0x0806;

#[derive(Debug, Clone, Copy)]
struct DhcpServerHint {
    ip: Ipv4Addr,
    mac: [u8; 6],
}

#[derive(Debug)]
pub struct DpdkAdapter {
    data_iface: String,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac: [u8; 6],
    dhcp_server_hint: Option<DhcpServerHint>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
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

        if self.handle_dhcp(frame) {
            return None;
        }

        let mut pkt = Packet::from_bytes(frame);
        match crate::dataplane::engine::handle_packet(&mut pkt, state) {
            Action::Forward { .. } => Some(pkt.buffer().to_vec()),
            Action::Drop | Action::ToHost => None,
        }
    }

    pub fn next_dhcp_frame(&mut self, state: &EngineState) -> Option<Vec<u8>> {
        let rx = self.dhcp_rx.as_mut()?;
        let msg = match rx.try_recv() {
            Ok(msg) => msg,
            Err(_) => return None,
        };
        self.build_dhcp_frame(state, msg)
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
        let mut buf = vec![0u8; 2048];
        loop {
            let n = io.recv_frame(&mut buf)?;
            if n == 0 {
                continue;
            }
            if let Some(out) = self.process_frame(&buf[..n], state) {
                io.send_frame(&out)?;
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
        self.dhcp_server_hint = Some(DhcpServerHint {
            ip: ipv4.src,
            mac: eth.src_mac,
        });
        true
    }

    fn handle_arp(&self, frame: &[u8], state: &EngineState) -> Option<Vec<u8>> {
        let cfg = state.dataplane_config.get()?;
        if cfg.ip == Ipv4Addr::UNSPECIFIED || cfg.mac == [0; 6] {
            return None;
        }
        parse_arp_request(frame, cfg.ip).map(|req| {
            state.inc_dp_arp_handled();
            build_arp_reply(req.sender_mac, req.sender_ip, cfg.mac, cfg.ip)
        })
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
    Some(Ipv4Header {
        src,
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

struct ArpRequest {
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
    fn mac(&self) -> Option<[u8; 6]> {
        None
    }
}

pub struct UnwiredDpdkIo;

impl UnwiredDpdkIo {
    pub fn new(_iface: &str) -> Result<Self, String> {
        Err("dpdk io backend not available (build with --features dpdk and install DPDK)".to_string())
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

#[cfg(feature = "dpdk")]
mod dpdk_io {
    use super::FrameIo;
    use std::ffi::CString;
    use std::fs;
    use std::os::raw::c_char;
    use std::path::Path;
    use std::ptr;
    use std::sync::OnceLock;

    use dpdk_sys::*;

    const RX_RING_SIZE: u16 = 1024;
    const TX_RING_SIZE: u16 = 1024;
    const MBUF_CACHE_SIZE: u32 = 250;
    const MBUF_PER_POOL: u32 = 8192;

    static EAL_INIT: OnceLock<Result<(), String>> = OnceLock::new();

    pub struct DpdkIo {
        port_id: u16,
        mempool: *mut rte_mempool,
        mac: [u8; 6],
    }

    impl DpdkIo {
        pub fn new(iface: &str) -> Result<Self, String> {
            init_eal(iface)?;

            let count = unsafe { rte_eth_dev_count_avail() } as u16;
            if count == 0 {
                return Err("dpdk: no ethernet ports available".to_string());
            }
            let port_id = port_id_for_iface(iface, count)?;

            let socket_id = unsafe { rte_eth_dev_socket_id(port_id as u16) };
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
                    unsafe { rte_errno }
                ));
            }

            let mut port_conf: rte_eth_conf = unsafe { std::mem::zeroed() };
            let ret = unsafe { rte_eth_dev_configure(port_id, 1, 1, &mut port_conf) };
            if ret < 0 {
                return Err(format!("dpdk: port configure failed ({ret})"));
            }

            let ret = unsafe {
                rte_eth_rx_queue_setup(
                    port_id,
                    0,
                    RX_RING_SIZE,
                    socket_id,
                    ptr::null(),
                    mempool,
                )
            };
            if ret < 0 {
                return Err(format!("dpdk: rx queue setup failed ({ret})"));
            }

            let ret = unsafe {
                rte_eth_tx_queue_setup(
                    port_id,
                    0,
                    TX_RING_SIZE,
                    socket_id,
                    ptr::null(),
                )
            };
            if ret < 0 {
                return Err(format!("dpdk: tx queue setup failed ({ret})"));
            }

            let ret = unsafe { rte_eth_dev_start(port_id) };
            if ret < 0 {
                return Err(format!("dpdk: port start failed ({ret})"));
            }

            unsafe {
                rte_eth_promiscuous_enable(port_id);
            }

            let mut addr: rte_ether_addr = unsafe { std::mem::zeroed() };
            unsafe {
                rte_eth_macaddr_get(port_id, &mut addr);
            }
            let mac = addr.addr_bytes;

            Ok(Self {
                port_id,
                mempool,
                mac,
            })
        }
    }

    impl FrameIo for DpdkIo {
        fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
            let mut mbuf: *mut rte_mbuf = ptr::null_mut();
            let received = unsafe { rte_eth_rx_burst(self.port_id, 0, &mut mbuf, 1) };
            if received == 0 {
                return Ok(0);
            }
            if mbuf.is_null() {
                return Ok(0);
            }

            let mut offset = 0usize;
            let mut seg = mbuf;
            while !seg.is_null() {
                let data_len = unsafe { (*seg).data_len as usize };
                let data_off = unsafe { (*seg).data_off as usize };
                let addr = unsafe { (*seg).buf_addr as *const u8 };
                let start = unsafe { addr.add(data_off) };
                let chunk = unsafe { std::slice::from_raw_parts(start, data_len) };
                let copy_len = data_len.min(buf.len().saturating_sub(offset));
                if copy_len == 0 {
                    break;
                }
                buf[offset..offset + copy_len].copy_from_slice(&chunk[..copy_len]);
                offset += copy_len;
                seg = unsafe { (*seg).next };
            }

            unsafe { rte_pktmbuf_free(mbuf) };
            Ok(offset)
        }

        fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
            let mbuf = unsafe { rte_pktmbuf_alloc(self.mempool) };
            if mbuf.is_null() {
                return Err("dpdk: failed to allocate mbuf".to_string());
            }
            unsafe {
                let data_off = (*mbuf).data_off as usize;
                let tailroom = RTE_MBUF_DEFAULT_BUF_SIZE as usize - data_off;
                if frame.len() > tailroom {
                    rte_pktmbuf_free(mbuf);
                    return Err("dpdk: frame exceeds mbuf tailroom".to_string());
                }
                (*mbuf).pkt_len = frame.len() as u32;
                (*mbuf).data_len = frame.len() as u16;
                (*mbuf).nb_segs = 1;
                (*mbuf).next = ptr::null_mut();
                let dst = (*mbuf).buf_addr as *mut u8;
                ptr::copy_nonoverlapping(frame.as_ptr(), dst.add(data_off), frame.len());
            }
            let mut tx = mbuf;
            let sent = unsafe { rte_eth_tx_burst(self.port_id, 0, &mut tx, 1) };
            if sent == 0 {
                unsafe { rte_pktmbuf_free(mbuf) };
            }
            Ok(())
        }

        fn mac(&self) -> Option<[u8; 6]> {
            Some(self.mac)
        }
    }

    fn init_eal(iface: &str) -> Result<(), String> {
        let cached = EAL_INIT.get_or_init(|| {
            let mut args = vec![
                "firewall".to_string(),
                "-l".to_string(),
                "0".to_string(),
                "-n".to_string(),
                "4".to_string(),
                "--proc-type=auto".to_string(),
                "--file-prefix=neuwerk".to_string(),
            ];
            if let Ok(pci) = pci_addr_for_iface(iface) {
                args.push("-a".to_string());
                args.push(pci);
            }
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
                    rte_errno
                }));
            }
            Ok(())
        });
        cached.clone()
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

    fn port_id_for_iface(iface: &str, count: u16) -> Result<u16, String> {
        if let Ok(pci) = pci_addr_for_iface(iface) {
            if let Ok(port) = port_id_for_name(&pci) {
                return Ok(port);
            }
        }
        if count == 1 {
            return Ok(0);
        }
        Err(format!(
            "dpdk: multiple ports available ({count}), unable to map interface {iface}"
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
    use crate::dataplane::policy::PolicySnapshot;
    use crate::dataplane::policy::DefaultPolicy;
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

    fn build_arp_request(
        sender_mac: [u8; 6],
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> Vec<u8> {
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
            src_mac,
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            payload,
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
        let mut state = EngineState::new(policy, Ipv4Addr::UNSPECIFIED, 0, Ipv4Addr::UNSPECIFIED, 0);
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
            Arc::new(RwLock::new(PolicySnapshot::new(DefaultPolicy::Deny, Vec::new()))),
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

        let policy = Arc::new(RwLock::new(PolicySnapshot::new(DefaultPolicy::Deny, Vec::new())));
        let mut state = EngineState::new(
            policy,
            Ipv4Addr::UNSPECIFIED,
            0,
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let frame = adapter.next_dhcp_frame(&state).expect("dhcp frame");
        assert_eq!(&frame[0..6], &[0xff; 6]);
        assert_eq!(&frame[6..12], &[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETH_TYPE_IPV4);
        let udp_off = ETH_HDR_LEN + 20;
        assert_eq!(u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]), DHCP_CLIENT_PORT);
        assert_eq!(u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]), DHCP_SERVER_PORT);
    }
}
