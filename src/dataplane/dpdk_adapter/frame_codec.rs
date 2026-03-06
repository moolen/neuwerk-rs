use std::net::Ipv4Addr;

use crate::dataplane::packet::Packet;

#[derive(Debug, Clone, Copy)]
pub(super) struct EthHeader {
    pub(super) src_mac: [u8; 6],
    pub(super) payload_offset: usize,
}

pub(super) fn parse_eth(frame: &[u8]) -> Option<EthHeader> {
    if frame.len() < super::ETH_HDR_LEN {
        return None;
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Some(EthHeader {
        src_mac,
        payload_offset: super::ETH_HDR_LEN,
    })
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Ipv4Header {
    pub(super) src: Ipv4Addr,
    pub(super) dst: Ipv4Addr,
    pub(super) proto: u8,
    pub(super) l4_offset: usize,
}

pub(super) fn parse_ipv4(frame: &[u8], ip_off: usize) -> Option<Ipv4Header> {
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
pub(super) struct UdpHeader {
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) payload_offset: usize,
    pub(super) payload_len: usize,
}

pub(super) fn parse_udp(frame: &[u8], l4_off: usize) -> Option<UdpHeader> {
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
pub(super) struct TcpHeader {
    pub(super) src_port: u16,
    pub(super) dst_port: u16,
    pub(super) seq: u32,
    pub(super) ack: u32,
    pub(super) flags: u8,
}

pub(super) fn parse_tcp(frame: &[u8], l4_off: usize) -> Option<TcpHeader> {
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
    let ack = u32::from_be_bytes([
        frame[l4_off + 8],
        frame[l4_off + 9],
        frame[l4_off + 10],
        frame[l4_off + 11],
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
        ack,
        flags,
    })
}

pub(super) fn build_tcp_control(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let total_len = 20 + 20;
    let mut buf = vec![0u8; super::ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&super::ETH_TYPE_IPV4.to_be_bytes());

    let ip_off = super::ETH_HDR_LEN;
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
    buf[tcp_off + 13] = flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64240u16.to_be_bytes());
    buf[tcp_off + 16..tcp_off + 18].copy_from_slice(&0u16.to_be_bytes());
    buf[tcp_off + 18..tcp_off + 20].copy_from_slice(&0u16.to_be_bytes());

    let mut pkt = Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

pub(super) struct ArpRequest {
    pub(super) sender_mac: [u8; 6],
    pub(super) sender_ip: Ipv4Addr,
}

pub(super) struct ArpReply {
    pub(super) sender_mac: [u8; 6],
    pub(super) sender_ip: Ipv4Addr,
}

pub(super) fn parse_arp_request(frame: &[u8], target_ip: Ipv4Addr) -> Option<ArpRequest> {
    if frame.len() < 42 {
        return None;
    }
    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if htype != 1 || ptype != super::ETH_TYPE_IPV4 || hlen != 6 || plen != 4 || op != 1 {
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

pub(super) fn parse_arp_reply(frame: &[u8]) -> Option<ArpReply> {
    if frame.len() < 42 {
        return None;
    }
    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if htype != 1 || ptype != super::ETH_TYPE_IPV4 || hlen != 6 || plen != 4 || op != 2 {
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

pub(super) fn build_arp_request(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&super::ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&super::ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

pub(super) fn build_arp_reply(
    dst_mac: [u8; 6],
    dst_ip: Ipv4Addr,
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&super::ETH_TYPE_ARP.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&super::ETH_TYPE_IPV4.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&2u16.to_be_bytes());
    buf[22..28].copy_from_slice(&src_mac);
    buf[28..32].copy_from_slice(&src_ip.octets());
    buf[32..38].copy_from_slice(&dst_mac);
    buf[38..42].copy_from_slice(&dst_ip.octets());
    buf
}

pub(super) fn build_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; super::ETH_HDR_LEN + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&super::ETH_TYPE_IPV4.to_be_bytes());

    let ip_off = super::ETH_HDR_LEN;
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
