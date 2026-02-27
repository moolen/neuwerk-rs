use std::net::Ipv4Addr;

use crate::controlplane::metrics::Metrics;
use crate::dataplane::packet::Packet;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const VXLAN_HDR_LEN: usize = 8;
const GENEVE_BASE_LEN: usize = 8;
const GENEVE_PROTO_ETHERNET: u16 = 0x6558;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncapMode {
    None,
    Vxlan,
    Geneve,
}

impl EncapMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" | "NONE" => Ok(EncapMode::None),
            "vxlan" | "VXLAN" => Ok(EncapMode::Vxlan),
            "geneve" | "GENEVE" => Ok(EncapMode::Geneve),
            _ => Err(format!(
                "unknown encap mode: {value} (expected none, vxlan, or geneve)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnatMode {
    None,
    Auto,
    Static(Ipv4Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelKind {
    Default,
    Internal,
    External,
}

#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub mode: EncapMode,
    pub udp_port: u16,
    pub udp_port_internal: Option<u16>,
    pub udp_port_external: Option<u16>,
    pub vni: Option<u32>,
    pub vni_internal: Option<u32>,
    pub vni_external: Option<u32>,
    pub mtu: u16,
}

impl OverlayConfig {
    pub fn none() -> Self {
        Self {
            mode: EncapMode::None,
            udp_port: 0,
            udp_port_internal: None,
            udp_port_external: None,
            vni: None,
            vni_internal: None,
            vni_external: None,
            mtu: 1500,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self.mode {
            EncapMode::None => Ok(()),
            EncapMode::Vxlan => {
                if self.udp_port == 0
                    && self.udp_port_internal.is_none()
                    && self.udp_port_external.is_none()
                {
                    return Err("--encap-udp-port is required for vxlan mode".to_string());
                }
                if self.vni.is_none() && self.vni_internal.is_none() && self.vni_external.is_none()
                {
                    return Err("--encap-vni is required for vxlan mode".to_string());
                }
                Ok(())
            }
            EncapMode::Geneve => {
                if self.udp_port == 0 {
                    return Err("--encap-udp-port is required for geneve mode".to_string());
                }
                Ok(())
            }
        }
    }

    pub fn has_dual_tunnel(&self) -> bool {
        let has_internal = self.udp_port_internal.is_some() || self.vni_internal.is_some();
        let has_external = self.udp_port_external.is_some() || self.vni_external.is_some();
        has_internal && has_external
    }

    fn resolve_udp_port(&self, tunnel: TunnelKind) -> u16 {
        match tunnel {
            TunnelKind::Internal => self.udp_port_internal.unwrap_or_else(|| self.udp_port),
            TunnelKind::External => self.udp_port_external.unwrap_or_else(|| self.udp_port),
            TunnelKind::Default => self.udp_port,
        }
    }
}

#[derive(Debug, Clone)]
struct GeneveMeta {
    flags: u8,
    protocol: u16,
    options: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct OverlayMeta {
    mode: EncapMode,
    outer_src_ip: Ipv4Addr,
    outer_dst_ip: Ipv4Addr,
    outer_src_port: u16,
    outer_src_mac: Option<[u8; 6]>,
    outer_dst_mac: Option<[u8; 6]>,
    tunnel: TunnelKind,
    vni: u32,
    geneve: Option<GeneveMeta>,
}

impl OverlayMeta {
    pub fn tunnel_label(&self) -> &'static str {
        match self.tunnel {
            TunnelKind::Internal => "internal",
            TunnelKind::External => "external",
            TunnelKind::Default => "default",
        }
    }

    pub fn udp_port(&self, cfg: &OverlayConfig) -> u16 {
        cfg.resolve_udp_port(self.tunnel)
    }

    pub fn set_outer_src_port(&mut self, port: u16) {
        self.outer_src_port = port;
    }
}

#[derive(Debug)]
pub struct OverlayPacket {
    pub meta: OverlayMeta,
    pub inner: Packet,
}

#[derive(Debug)]
struct OuterParsed {
    outer_src_ip: Ipv4Addr,
    outer_dst_ip: Ipv4Addr,
    outer_src_port: u16,
    outer_dst_port: u16,
    outer_src_mac: Option<[u8; 6]>,
    outer_dst_mac: Option<[u8; 6]>,
    udp_payload_offset: usize,
    udp_payload_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayError {
    Parse,
    Unsupported,
    Mtu,
}

pub fn reply_meta(meta: &OverlayMeta, cfg: &OverlayConfig, swap_tunnel: bool) -> OverlayMeta {
    let mut out = meta.clone();
    if !cfg.has_dual_tunnel() || !swap_tunnel {
        return out;
    }
    let next = match meta.tunnel {
        TunnelKind::Internal => TunnelKind::External,
        TunnelKind::External => TunnelKind::Internal,
        TunnelKind::Default => TunnelKind::Default,
    };
    if next == meta.tunnel {
        return out;
    }
    out.tunnel = next;
    out.vni = vni_for_tunnel(cfg, next).unwrap_or(out.vni);
    out
}

pub fn decap(
    frame: &[u8],
    cfg: &OverlayConfig,
    metrics: Option<&Metrics>,
) -> Result<OverlayPacket, OverlayError> {
    let parsed = match parse_outer_udp(frame) {
        Some(parsed) => parsed,
        None => {
            if let Some(metrics) = metrics {
                metrics.inc_overlay_decap_error();
            }
            return Err(OverlayError::Parse);
        }
    };

    let payload = match frame
        .get(parsed.udp_payload_offset..parsed.udp_payload_offset + parsed.udp_payload_len)
    {
        Some(payload) => payload,
        None => {
            if let Some(metrics) = metrics {
                metrics.inc_overlay_decap_error();
            }
            return Err(OverlayError::Parse);
        }
    };

    let (meta, inner_payload) = match cfg.mode {
        EncapMode::Vxlan => decap_vxlan(payload, parsed, cfg, metrics)?,
        EncapMode::Geneve => decap_geneve(payload, parsed, cfg, metrics)?,
        EncapMode::None => {
            if let Some(metrics) = metrics {
                metrics.inc_overlay_decap_error();
            }
            return Err(OverlayError::Unsupported);
        }
    };

    if let Some(metrics) = metrics {
        metrics.observe_overlay_packet(mode_label(cfg.mode), "in");
    }

    Ok(OverlayPacket {
        meta,
        inner: Packet::from_bytes(inner_payload),
    })
}

pub fn encap(
    inner: &Packet,
    meta: &OverlayMeta,
    cfg: &OverlayConfig,
    metrics: Option<&Metrics>,
) -> Result<Vec<u8>, OverlayError> {
    let payload = match meta.mode {
        EncapMode::Vxlan => build_vxlan_payload(inner.buffer(), meta.vni),
        EncapMode::Geneve => build_geneve_payload(inner.buffer(), meta)?,
        EncapMode::None => {
            if let Some(metrics) = metrics {
                metrics.inc_overlay_encap_error();
            }
            return Err(OverlayError::Unsupported);
        }
    };

    let outer_len = 20 + 8 + payload.len();
    if cfg.mtu > 0 && outer_len > cfg.mtu as usize {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_mtu_drop();
        }
        return Err(OverlayError::Mtu);
    }

    let (src_ip, dst_ip) = (meta.outer_dst_ip, meta.outer_src_ip);
    let src_port = meta.outer_src_port;
    let dst_port = cfg.resolve_udp_port(meta.tunnel);
    let has_eth = meta.outer_src_mac.is_some() && meta.outer_dst_mac.is_some();
    let frame = build_udp_frame(
        meta.outer_dst_mac,
        meta.outer_src_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        &payload,
        has_eth,
    );

    if let Some(metrics) = metrics {
        metrics.observe_overlay_packet(mode_label(meta.mode), "out");
    }

    Ok(frame)
}

pub fn maybe_clamp_mss(pkt: &mut Packet, cfg: &OverlayConfig, meta: &OverlayMeta) {
    let max = match compute_mss_max(cfg, meta) {
        Some(max) => max,
        None => return,
    };
    if pkt.clamp_tcp_mss(max) {
        let _ = pkt.recalc_checksums();
    }
}

fn mode_label(mode: EncapMode) -> &'static str {
    match mode {
        EncapMode::None => "none",
        EncapMode::Vxlan => "vxlan",
        EncapMode::Geneve => "geneve",
    }
}

fn parse_outer_udp(frame: &[u8]) -> Option<OuterParsed> {
    let (ip_off, src_mac, dst_mac) = if frame.len() >= ETH_HDR_LEN {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == ETH_TYPE_IPV4 {
            let mut src = [0u8; 6];
            let mut dst = [0u8; 6];
            src.copy_from_slice(&frame[6..12]);
            dst.copy_from_slice(&frame[0..6]);
            (ETH_HDR_LEN, Some(src), Some(dst))
        } else {
            (0, None, None)
        }
    } else {
        (0, None, None)
    };

    if frame.len() < ip_off + 20 {
        return None;
    }
    if (frame[ip_off] >> 4) != 4 {
        return None;
    }
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl {
        return None;
    }
    if frame[ip_off + 9] != IPPROTO_UDP {
        return None;
    }
    let src_ip = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst_ip = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    let udp_off = ip_off + ihl;
    if frame.len() < udp_off + 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
    let udp_len = u16::from_be_bytes([frame[udp_off + 4], frame[udp_off + 5]]) as usize;
    if udp_len < 8 || frame.len() < udp_off + udp_len {
        return None;
    }
    let payload_offset = udp_off + 8;
    let payload_len = udp_len - 8;
    Some(OuterParsed {
        outer_src_ip: src_ip,
        outer_dst_ip: dst_ip,
        outer_src_port: src_port,
        outer_dst_port: dst_port,
        outer_src_mac: src_mac,
        outer_dst_mac: dst_mac,
        udp_payload_offset: payload_offset,
        udp_payload_len: payload_len,
    })
}

fn decap_vxlan<'a>(
    payload: &'a [u8],
    parsed: OuterParsed,
    cfg: &OverlayConfig,
    metrics: Option<&Metrics>,
) -> Result<(OverlayMeta, &'a [u8]), OverlayError> {
    if payload.len() < VXLAN_HDR_LEN {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let flags = payload[0];
    if flags & 0x08 == 0 {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;

    let tunnel = match resolve_tunnel(cfg, vni, parsed.outer_dst_port) {
        Some(tunnel) => tunnel,
        None => {
            if let Some(metrics) = metrics {
                metrics.inc_overlay_decap_error();
            }
            return Err(OverlayError::Parse);
        }
    };

    let meta = OverlayMeta {
        mode: EncapMode::Vxlan,
        outer_src_ip: parsed.outer_src_ip,
        outer_dst_ip: parsed.outer_dst_ip,
        outer_src_port: parsed.outer_src_port,
        outer_src_mac: parsed.outer_src_mac,
        outer_dst_mac: parsed.outer_dst_mac,
        tunnel,
        vni,
        geneve: None,
    };

    Ok((meta, &payload[VXLAN_HDR_LEN..]))
}

fn decap_geneve<'a>(
    payload: &'a [u8],
    parsed: OuterParsed,
    cfg: &OverlayConfig,
    metrics: Option<&Metrics>,
) -> Result<(OverlayMeta, &'a [u8]), OverlayError> {
    if parsed.outer_dst_port != cfg.udp_port {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    if payload.len() < GENEVE_BASE_LEN {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let ver = payload[0] >> 6;
    if ver != 0 {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let opt_len_words = (payload[0] & 0x3f) as usize;
    let opt_len = opt_len_words * 4;
    let header_len = GENEVE_BASE_LEN + opt_len;
    if payload.len() < header_len {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let flags = payload[1];
    let protocol = u16::from_be_bytes([payload[2], payload[3]]);
    if protocol != GENEVE_PROTO_ETHERNET {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Unsupported);
    }
    let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;
    if !vni_matches(cfg, vni) {
        if let Some(metrics) = metrics {
            metrics.inc_overlay_decap_error();
        }
        return Err(OverlayError::Parse);
    }
    let options = payload[GENEVE_BASE_LEN..header_len].to_vec();

    let meta = OverlayMeta {
        mode: EncapMode::Geneve,
        outer_src_ip: parsed.outer_src_ip,
        outer_dst_ip: parsed.outer_dst_ip,
        outer_src_port: parsed.outer_src_port,
        outer_src_mac: parsed.outer_src_mac,
        outer_dst_mac: parsed.outer_dst_mac,
        tunnel: TunnelKind::Default,
        vni,
        geneve: Some(GeneveMeta {
            flags,
            protocol,
            options,
        }),
    };

    Ok((meta, &payload[header_len..]))
}

fn resolve_tunnel(cfg: &OverlayConfig, vni: u32, udp_port: u16) -> Option<TunnelKind> {
    let mut tunnel = None;
    if let Some(port) = cfg.udp_port_internal {
        if udp_port == port {
            tunnel = Some(TunnelKind::Internal);
        }
    }
    if let Some(port) = cfg.udp_port_external {
        if udp_port == port {
            tunnel = Some(TunnelKind::External);
        }
    }
    if tunnel.is_none() && udp_port == cfg.udp_port {
        tunnel = Some(TunnelKind::Default);
    }

    if tunnel.is_none() {
        if cfg.udp_port_internal.is_none() && cfg.udp_port_external.is_none() {
            if let Some(internal) = cfg.vni_internal {
                if vni == internal {
                    tunnel = Some(TunnelKind::Internal);
                }
            }
            if let Some(external) = cfg.vni_external {
                if vni == external {
                    tunnel = Some(TunnelKind::External);
                }
            }
        }
    }

    let Some(tunnel) = tunnel else {
        return None;
    };

    if !vni_matches_tunnel(cfg, vni, tunnel) {
        return None;
    }
    Some(tunnel)
}

fn vni_matches_tunnel(cfg: &OverlayConfig, vni: u32, tunnel: TunnelKind) -> bool {
    match tunnel {
        TunnelKind::Internal => cfg
            .vni_internal
            .map(|expected| expected == vni)
            .unwrap_or_else(|| cfg.vni.map(|expected| expected == vni).unwrap_or(true)),
        TunnelKind::External => cfg
            .vni_external
            .map(|expected| expected == vni)
            .unwrap_or_else(|| cfg.vni.map(|expected| expected == vni).unwrap_or(true)),
        TunnelKind::Default => vni_matches(cfg, vni),
    }
}

fn vni_for_tunnel(cfg: &OverlayConfig, tunnel: TunnelKind) -> Option<u32> {
    match tunnel {
        TunnelKind::Internal => cfg.vni_internal.or(cfg.vni),
        TunnelKind::External => cfg.vni_external.or(cfg.vni),
        TunnelKind::Default => cfg.vni,
    }
}

fn vni_matches(cfg: &OverlayConfig, vni: u32) -> bool {
    if let Some(expected) = cfg.vni {
        return vni == expected;
    }
    if let Some(expected) = cfg.vni_internal {
        if vni == expected {
            return true;
        }
    }
    if let Some(expected) = cfg.vni_external {
        if vni == expected {
            return true;
        }
    }
    true
}

fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
    let mut buf = vec![0u8; VXLAN_HDR_LEN + inner.len()];
    buf[0] = 0x08;
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[VXLAN_HDR_LEN..].copy_from_slice(inner);
    buf
}

fn build_geneve_payload(inner: &[u8], meta: &OverlayMeta) -> Result<Vec<u8>, OverlayError> {
    let geneve = match &meta.geneve {
        Some(geneve) => geneve,
        None => return Err(OverlayError::Parse),
    };
    if geneve.options.len() % 4 != 0 {
        return Err(OverlayError::Parse);
    }
    let opt_len_words = (geneve.options.len() / 4) as u8;
    let header_len = GENEVE_BASE_LEN + geneve.options.len();
    let mut buf = vec![0u8; header_len + inner.len()];
    buf[0] = opt_len_words & 0x3f;
    buf[1] = geneve.flags;
    buf[2..4].copy_from_slice(&geneve.protocol.to_be_bytes());
    buf[4] = ((meta.vni >> 16) & 0xff) as u8;
    buf[5] = ((meta.vni >> 8) & 0xff) as u8;
    buf[6] = (meta.vni & 0xff) as u8;
    buf[7] = 0;
    buf[GENEVE_BASE_LEN..header_len].copy_from_slice(&geneve.options);
    buf[header_len..].copy_from_slice(inner);
    Ok(buf)
}

fn build_udp_frame(
    src_mac: Option<[u8; 6]>,
    dst_mac: Option<[u8; 6]>,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    include_eth: bool,
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let eth_len = if include_eth { ETH_HDR_LEN } else { 0 };
    let mut buf = vec![0u8; eth_len + total_len];
    if include_eth {
        let src_mac = src_mac.unwrap_or([0u8; 6]);
        let dst_mac = dst_mac.unwrap_or([0u8; 6]);
        buf[0..6].copy_from_slice(&dst_mac);
        buf[6..12].copy_from_slice(&src_mac);
        buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    }

    let ip_off = eth_len;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = IPPROTO_UDP;
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

fn compute_mss_max(cfg: &OverlayConfig, meta: &OverlayMeta) -> Option<u16> {
    if cfg.mtu == 0 {
        return None;
    }
    let overlay_len = match meta.mode {
        EncapMode::Vxlan => VXLAN_HDR_LEN,
        EncapMode::Geneve => {
            let opts = meta.geneve.as_ref().map(|g| g.options.len()).unwrap_or(0);
            GENEVE_BASE_LEN + opts
        }
        EncapMode::None => 0,
    };
    let overhead = 20 + 8 + overlay_len + ETH_HDR_LEN + 20 + 20;
    if (cfg.mtu as usize) <= overhead {
        return None;
    }
    let max = (cfg.mtu as usize).saturating_sub(overhead);
    if max == 0 {
        None
    } else if max > u16::MAX as usize {
        Some(u16::MAX)
    } else {
        Some(max as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_inner() -> Vec<u8> {
        let mut buf = vec![0u8; 14 + 20 + 8];
        buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        buf[14] = 0x45;
        buf[14 + 9] = 17;
        buf[14 + 2..14 + 4].copy_from_slice(&28u16.to_be_bytes());
        buf
    }

    #[test]
    fn vxlan_round_trip_preserves_vni() {
        let cfg = OverlayConfig {
            mode: EncapMode::Vxlan,
            udp_port: 10800,
            udp_port_internal: None,
            udp_port_external: None,
            vni: Some(800),
            vni_internal: None,
            vni_external: None,
            mtu: 1500,
        };
        let inner = build_inner();
        let meta = OverlayMeta {
            mode: EncapMode::Vxlan,
            outer_src_ip: Ipv4Addr::new(10, 0, 0, 2),
            outer_dst_ip: Ipv4Addr::new(10, 0, 0, 1),
            outer_src_port: 1234,
            outer_src_mac: None,
            outer_dst_mac: None,
            tunnel: TunnelKind::Default,
            vni: 800,
            geneve: None,
        };
        let pkt = Packet::from_bytes(&inner);
        let out = encap(&pkt, &meta, &cfg, None).expect("encap");
        let decap = decap(&out, &cfg, None).expect("decap");
        assert_eq!(decap.meta.vni, 800);
        assert_eq!(decap.inner.buffer().len(), inner.len());
    }

    #[test]
    fn geneve_preserves_options() {
        let cfg = OverlayConfig {
            mode: EncapMode::Geneve,
            udp_port: 6081,
            udp_port_internal: None,
            udp_port_external: None,
            vni: None,
            vni_internal: None,
            vni_external: None,
            mtu: 1500,
        };
        let inner = build_inner();
        let options = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let meta = OverlayMeta {
            mode: EncapMode::Geneve,
            outer_src_ip: Ipv4Addr::new(10, 0, 0, 2),
            outer_dst_ip: Ipv4Addr::new(10, 0, 0, 1),
            outer_src_port: 1234,
            outer_src_mac: None,
            outer_dst_mac: None,
            tunnel: TunnelKind::Default,
            vni: 99,
            geneve: Some(GeneveMeta {
                flags: 0,
                protocol: GENEVE_PROTO_ETHERNET,
                options: options.clone(),
            }),
        };
        let pkt = Packet::from_bytes(&inner);
        let out = encap(&pkt, &meta, &cfg, None).expect("encap");
        let decap = decap(&out, &cfg, None).expect("decap");
        let got = decap.meta.geneve.expect("geneve");
        assert_eq!(got.options, options);
    }

    #[test]
    fn reply_meta_swaps_dual_tunnel() {
        let cfg = OverlayConfig {
            mode: EncapMode::Vxlan,
            udp_port: 0,
            udp_port_internal: Some(10800),
            udp_port_external: Some(10801),
            vni: None,
            vni_internal: Some(800),
            vni_external: Some(801),
            mtu: 1500,
        };
        let meta = OverlayMeta {
            mode: EncapMode::Vxlan,
            outer_src_ip: Ipv4Addr::new(10, 0, 0, 2),
            outer_dst_ip: Ipv4Addr::new(10, 0, 0, 1),
            outer_src_port: 4242,
            outer_src_mac: None,
            outer_dst_mac: None,
            tunnel: TunnelKind::Internal,
            vni: 800,
            geneve: None,
        };
        let out = reply_meta(&meta, &cfg, true);
        assert_eq!(out.tunnel_label(), "external");
        assert_eq!(out.vni, 801);
    }

    #[test]
    fn reply_meta_no_swap_keeps_tunnel() {
        let cfg = OverlayConfig {
            mode: EncapMode::Vxlan,
            udp_port: 0,
            udp_port_internal: Some(10800),
            udp_port_external: Some(10801),
            vni: None,
            vni_internal: Some(800),
            vni_external: Some(801),
            mtu: 1500,
        };
        let meta = OverlayMeta {
            mode: EncapMode::Vxlan,
            outer_src_ip: Ipv4Addr::new(10, 0, 0, 2),
            outer_dst_ip: Ipv4Addr::new(10, 0, 0, 1),
            outer_src_port: 4242,
            outer_src_mac: None,
            outer_dst_mac: None,
            tunnel: TunnelKind::Internal,
            vni: 800,
            geneve: None,
        };
        let out = reply_meta(&meta, &cfg, false);
        assert_eq!(out.tunnel_label(), "internal");
        assert_eq!(out.vni, 800);
    }
}
