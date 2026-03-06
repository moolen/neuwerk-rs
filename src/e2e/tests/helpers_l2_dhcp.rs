use super::*;
pub(in crate::e2e::tests) struct DhcpTestServer {
    pub(in crate::e2e::tests) server_ip: Ipv4Addr,
    pub(in crate::e2e::tests) server_mac: [u8; 6],
    pub(in crate::e2e::tests) lease_ip: Ipv4Addr,
    pub(in crate::e2e::tests) lease_time_secs: u32,
}

impl DhcpTestServer {
    pub(in crate::e2e::tests) fn new(
        server_ip: Ipv4Addr,
        server_mac: [u8; 6],
        lease_ip: Ipv4Addr,
        lease_time_secs: u32,
    ) -> Self {
        Self {
            server_ip,
            server_mac,
            lease_ip,
            lease_time_secs,
        }
    }

    pub(in crate::e2e::tests) fn handle_client_frame(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (_src_mac, payload) = parse_eth_ipv4_udp_payload(frame)?;
        let dhcp = parse_dhcp_message(payload)?;
        let reply_type = match dhcp.msg_type {
            1 => 2,
            3 => 5,
            _ => return None,
        };
        let reply = build_dhcp_reply(
            reply_type,
            dhcp.xid,
            dhcp.chaddr,
            self.lease_ip,
            self.server_ip,
            self.lease_time_secs,
            Ipv4Addr::new(255, 255, 255, 0),
            self.server_ip,
        );
        let mut frame = build_ipv4_udp_frame(
            self.server_mac,
            [0xff; 6],
            self.server_ip,
            Ipv4Addr::BROADCAST,
            67,
            68,
            &reply,
        );
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&self.server_mac);
        Some(frame)
    }
}

pub(in crate::e2e::tests) struct DhcpMessage {
    msg_type: u8,
    xid: u32,
    chaddr: [u8; 6],
}

pub(in crate::e2e::tests) fn parse_eth_ipv4_udp_payload(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    let ihl = (frame[14] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < 14 + ihl + 8 {
        return None;
    }
    let udp_off = 14 + ihl;
    let len = u16::from_be_bytes([frame[udp_off + 4], frame[udp_off + 5]]) as usize;
    if len < 8 || frame.len() < udp_off + len {
        return None;
    }
    let payload_off = udp_off + 8;
    let payload_len = len - 8;
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Some((src_mac, &frame[payload_off..payload_off + payload_len]))
}

pub(in crate::e2e::tests) fn parse_dhcp_message(buf: &[u8]) -> Option<DhcpMessage> {
    if buf.len() < 240 {
        return None;
    }
    if buf[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&buf[28..34]);
    let mut idx = 240;
    let mut msg_type = None;
    while idx < buf.len() {
        let code = buf[idx];
        idx += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if idx >= buf.len() {
            return None;
        }
        let len = buf[idx] as usize;
        idx += 1;
        if idx + len > buf.len() {
            return None;
        }
        if code == 53 && len == 1 {
            msg_type = Some(buf[idx]);
        }
        idx += len;
    }
    Some(DhcpMessage {
        msg_type: msg_type?,
        xid,
        chaddr,
    })
}

pub(in crate::e2e::tests) fn build_dhcp_reply(
    msg_type: u8,
    xid: u32,
    chaddr: [u8; 6],
    yiaddr: Ipv4Addr,
    server_ip: Ipv4Addr,
    lease_time: u32,
    subnet: Ipv4Addr,
    router: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    buf[3] = 0;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&yiaddr.octets());
    buf[28..34].copy_from_slice(&chaddr);
    buf[236..240].copy_from_slice(&[99, 130, 83, 99]);
    push_option(&mut buf, 53, &[msg_type]);
    push_option(&mut buf, 1, &subnet.octets());
    push_option(&mut buf, 3, &router.octets());
    push_option(&mut buf, 51, &lease_time.to_be_bytes());
    push_option(&mut buf, 54, &server_ip.octets());
    buf.push(255);
    buf
}

pub(in crate::e2e::tests) fn push_option(buf: &mut Vec<u8>, code: u8, data: &[u8]) {
    buf.push(code);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

pub(in crate::e2e::tests) fn build_ipv4_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; 14 + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip_off = 14;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 17;
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());
    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);
    buf
}

pub(in crate::e2e::tests) fn build_ipv4_tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 20 + payload.len();
    let mut buf = vec![0u8; 14 + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip_off = 14;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 6;
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64_240u16.to_be_bytes());
    buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

    let mut pkt = crate::dataplane::packet::Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

pub(in crate::e2e::tests) fn parse_ipv4_udp(
    frame: &[u8],
) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16), String> {
    if frame.len() < 14 + 20 + 8 {
        return Err("frame too short".to_string());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err("not ipv4".to_string());
    }
    let ihl = (frame[14] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < 14 + ihl + 8 {
        return Err("invalid ipv4 header".to_string());
    }
    let src = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
    let dst = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
    let udp_off = 14 + ihl;
    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
    Ok((src, dst, src_port, dst_port))
}

pub(in crate::e2e::tests) fn parse_ipv4_tcp(
    frame: &[u8],
) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16), String> {
    if frame.len() < 14 + 20 + 20 {
        return Err("frame too short".to_string());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err("not ipv4".to_string());
    }
    let ip_off = 14;
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl + 20 {
        return Err("invalid ipv4 header".to_string());
    }
    if frame[ip_off + 9] != 6 {
        return Err("not tcp".to_string());
    }
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
    let tcp_off = ip_off + ihl;
    let src_port = u16::from_be_bytes([frame[tcp_off], frame[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[tcp_off + 2], frame[tcp_off + 3]]);
    Ok((src, dst, src_port, dst_port))
}

pub(in crate::e2e::tests) fn build_arp_request(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

pub(in crate::e2e::tests) fn assert_arp_reply(
    frame: &[u8],
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Result<(), String> {
    if frame.len() < 42 {
        return Err("arp reply too short".to_string());
    }
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if op != 2 {
        return Err("not an arp reply".to_string());
    }
    if frame[22..28] != target_mac {
        return Err("arp reply sender mac mismatch".to_string());
    }
    let reply_sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if reply_sender_ip != target_ip {
        return Err("arp reply sender ip mismatch".to_string());
    }
    if frame[32..38] != sender_mac {
        return Err("arp reply target mac mismatch".to_string());
    }
    let reply_target_ip = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    if reply_target_ip != sender_ip {
        return Err("arp reply target ip mismatch".to_string());
    }
    Ok(())
}
