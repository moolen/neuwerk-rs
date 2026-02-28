use std::net::Ipv4Addr;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_IPV4: u16 = 0x0800;

#[derive(Debug, Clone)]
pub struct Packet {
    buf: Vec<u8>,
}

impl Packet {
    pub fn new(buf: Vec<u8>) -> Self {
        Self { buf }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            buf: bytes.to_vec(),
        }
    }

    pub fn truncate(&mut self, len: usize) {
        self.buf.truncate(len);
    }

    pub fn prepare_for_rx(&mut self, len: usize) {
        if self.buf.capacity() < len {
            self.buf.reserve(len - self.buf.capacity());
        }
        // Safety: the caller will immediately fill the buffer before reading.
        unsafe {
            self.buf.set_len(len);
        }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    pub fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    fn ipv4_offset(&self) -> Option<usize> {
        if self.buf.len() >= ETH_HDR_LEN + 20 {
            let ethertype = u16::from_be_bytes([self.buf[12], self.buf[13]]);
            if ethertype == ETH_TYPE_IPV4 {
                if (self.buf[ETH_HDR_LEN] >> 4) == 4 {
                    return Some(ETH_HDR_LEN);
                }
            }
        }

        if self.buf.len() >= 20 && (self.buf[0] >> 4) == 4 {
            return Some(0);
        }

        None
    }

    fn ipv4_header_len(&self, ip_off: usize) -> Option<usize> {
        if ip_off + 1 > self.buf.len() {
            return None;
        }
        let ihl = (self.buf[ip_off] & 0x0f) as usize * 4;
        if ihl < 20 || ip_off + ihl > self.buf.len() {
            return None;
        }
        Some(ihl)
    }

    fn ipv4_total_len(&self, ip_off: usize) -> Option<usize> {
        if ip_off + 4 > self.buf.len() {
            return None;
        }
        let total_len = u16::from_be_bytes([self.buf[ip_off + 2], self.buf[ip_off + 3]]) as usize;
        if total_len < 20 || ip_off + total_len > self.buf.len() {
            return None;
        }
        Some(total_len)
    }

    pub fn protocol(&self) -> Option<u8> {
        let ip_off = self.ipv4_offset()?;
        if ip_off + 10 > self.buf.len() {
            return None;
        }
        Some(self.buf[ip_off + 9])
    }

    pub fn icmp_type_code(&self) -> Option<(u8, u8)> {
        let ip_off = self.ipv4_offset()?;
        let ihl = self.ipv4_header_len(ip_off)?;
        if self.buf[ip_off + 9] != 1 {
            return None;
        }
        let icmp_off = ip_off + ihl;
        if icmp_off + 2 > self.buf.len() {
            return None;
        }
        Some((self.buf[icmp_off], self.buf[icmp_off + 1]))
    }

    pub fn icmp_identifier(&self) -> Option<u16> {
        let ip_off = self.ipv4_offset()?;
        let ihl = self.ipv4_header_len(ip_off)?;
        if self.buf[ip_off + 9] != 1 {
            return None;
        }
        let icmp_off = ip_off + ihl;
        if icmp_off + 6 > self.buf.len() {
            return None;
        }
        Some(u16::from_be_bytes([
            self.buf[icmp_off + 4],
            self.buf[icmp_off + 5],
        ]))
    }

    pub fn set_icmp_identifier(&mut self, id: u16) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        if self.buf[ip_off + 9] != 1 {
            return false;
        }
        let icmp_off = ip_off + ihl;
        if icmp_off + 6 > self.buf.len() {
            return false;
        }
        self.buf[icmp_off + 4..icmp_off + 6].copy_from_slice(&id.to_be_bytes());
        true
    }

    pub fn ipv4_ttl(&self) -> Option<u8> {
        let ip_off = self.ipv4_offset()?;
        if ip_off + 9 > self.buf.len() {
            return None;
        }
        Some(self.buf[ip_off + 8])
    }

    pub fn set_ipv4_ttl(&mut self, ttl: u8) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        if ip_off + 9 > self.buf.len() {
            return false;
        }
        self.buf[ip_off + 8] = ttl;
        true
    }

    pub fn is_ipv4_fragment(&self) -> Option<bool> {
        let ip_off = self.ipv4_offset()?;
        if ip_off + 8 > self.buf.len() {
            return None;
        }
        let flags = u16::from_be_bytes([self.buf[ip_off + 6], self.buf[ip_off + 7]]);
        let more_fragments = (flags & 0x2000) != 0;
        let offset = flags & 0x1fff;
        Some(more_fragments || offset != 0)
    }

    pub fn icmp_inner_tuple(&self) -> Option<IcmpInnerTuple> {
        let ip_off = self.ipv4_offset()?;
        let ihl = self.ipv4_header_len(ip_off)?;
        if self.buf[ip_off + 9] != 1 {
            return None;
        }
        let icmp_off = ip_off + ihl;
        let inner_ip_off = icmp_off + 8;
        if self.buf.len() < inner_ip_off + 20 {
            return None;
        }
        let ver = self.buf[inner_ip_off] >> 4;
        if ver != 4 {
            return None;
        }
        let inner_ihl = (self.buf[inner_ip_off] & 0x0f) as usize * 4;
        if inner_ihl < 20 || self.buf.len() < inner_ip_off + inner_ihl {
            return None;
        }
        let proto = self.buf[inner_ip_off + 9];
        let src_ip = Ipv4Addr::new(
            self.buf[inner_ip_off + 12],
            self.buf[inner_ip_off + 13],
            self.buf[inner_ip_off + 14],
            self.buf[inner_ip_off + 15],
        );
        let dst_ip = Ipv4Addr::new(
            self.buf[inner_ip_off + 16],
            self.buf[inner_ip_off + 17],
            self.buf[inner_ip_off + 18],
            self.buf[inner_ip_off + 19],
        );
        let l4_off = inner_ip_off + inner_ihl;
        if self.buf.len() < l4_off + 8 {
            return None;
        }
        let (src_port, dst_port, icmp_identifier) = match proto {
            6 | 17 => {
                if self.buf.len() < l4_off + 4 {
                    return None;
                }
                let src_port = u16::from_be_bytes([self.buf[l4_off], self.buf[l4_off + 1]]);
                let dst_port = u16::from_be_bytes([self.buf[l4_off + 2], self.buf[l4_off + 3]]);
                (src_port, dst_port, None)
            }
            1 => {
                if self.buf.len() < l4_off + 6 {
                    return None;
                }
                let identifier = u16::from_be_bytes([self.buf[l4_off + 4], self.buf[l4_off + 5]]);
                (identifier, 0, Some(identifier))
            }
            _ => return None,
        };
        Some(IcmpInnerTuple {
            ip_offset: inner_ip_off,
            ihl: inner_ihl,
            l4_offset: l4_off,
            proto,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            icmp_identifier,
        })
    }

    pub fn set_icmp_inner_src_ip(&mut self, inner: &IcmpInnerTuple, ip: Ipv4Addr) -> bool {
        if self.buf.len() < inner.ip_offset + 20 {
            return false;
        }
        self.buf[inner.ip_offset + 12..inner.ip_offset + 16].copy_from_slice(&ip.octets());
        recalc_ipv4_header_checksum(&mut self.buf, inner.ip_offset, inner.ihl)
    }

    pub fn set_icmp_inner_src_port(&mut self, inner: &IcmpInnerTuple, port: u16) -> bool {
        if self.buf.len() < inner.l4_offset + 6 {
            return false;
        }
        match inner.proto {
            6 | 17 => {
                self.buf[inner.l4_offset..inner.l4_offset + 2].copy_from_slice(&port.to_be_bytes());
                true
            }
            1 => {
                self.buf[inner.l4_offset + 4..inner.l4_offset + 6]
                    .copy_from_slice(&port.to_be_bytes());
                true
            }
            _ => false,
        }
    }

    pub fn set_icmp_inner_dst_ip(&mut self, inner: &IcmpInnerTuple, ip: Ipv4Addr) -> bool {
        if self.buf.len() < inner.ip_offset + 20 {
            return false;
        }
        self.buf[inner.ip_offset + 16..inner.ip_offset + 20].copy_from_slice(&ip.octets());
        recalc_ipv4_header_checksum(&mut self.buf, inner.ip_offset, inner.ihl)
    }

    pub fn set_icmp_inner_dst_port(&mut self, inner: &IcmpInnerTuple, port: u16) -> bool {
        if self.buf.len() < inner.l4_offset + 4 {
            return false;
        }
        match inner.proto {
            6 | 17 => {
                self.buf[inner.l4_offset + 2..inner.l4_offset + 4]
                    .copy_from_slice(&port.to_be_bytes());
                true
            }
            _ => false,
        }
    }

    pub fn src_ip(&self) -> Option<Ipv4Addr> {
        let ip_off = self.ipv4_offset()?;
        if ip_off + 16 > self.buf.len() {
            return None;
        }
        Some(Ipv4Addr::new(
            self.buf[ip_off + 12],
            self.buf[ip_off + 13],
            self.buf[ip_off + 14],
            self.buf[ip_off + 15],
        ))
    }

    pub fn dst_ip(&self) -> Option<Ipv4Addr> {
        let ip_off = self.ipv4_offset()?;
        if ip_off + 20 > self.buf.len() {
            return None;
        }
        Some(Ipv4Addr::new(
            self.buf[ip_off + 16],
            self.buf[ip_off + 17],
            self.buf[ip_off + 18],
            self.buf[ip_off + 19],
        ))
    }

    pub fn set_src_ip(&mut self, ip: Ipv4Addr) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        if ip_off + 16 > self.buf.len() {
            return false;
        }
        self.buf[ip_off + 12..ip_off + 16].copy_from_slice(&ip.octets());
        true
    }

    pub fn set_dst_ip(&mut self, ip: Ipv4Addr) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        if ip_off + 20 > self.buf.len() {
            return false;
        }
        self.buf[ip_off + 16..ip_off + 20].copy_from_slice(&ip.octets());
        true
    }

    pub fn ports(&self) -> Option<(u16, u16)> {
        let ip_off = self.ipv4_offset()?;
        let ihl = self.ipv4_header_len(ip_off)?;
        let proto = self.protocol()?;
        if proto != 6 && proto != 17 {
            return None;
        }
        let l4_off = ip_off + ihl;
        if l4_off + 4 > self.buf.len() {
            return None;
        }
        let src = u16::from_be_bytes([self.buf[l4_off], self.buf[l4_off + 1]]);
        let dst = u16::from_be_bytes([self.buf[l4_off + 2], self.buf[l4_off + 3]]);
        Some((src, dst))
    }

    pub fn tcp_seq(&self) -> Option<u32> {
        let (l4_off, _) = self.tcp_offsets()?;
        if l4_off + 8 > self.buf.len() {
            return None;
        }
        Some(u32::from_be_bytes([
            self.buf[l4_off + 4],
            self.buf[l4_off + 5],
            self.buf[l4_off + 6],
            self.buf[l4_off + 7],
        ]))
    }

    pub fn tcp_ack(&self) -> Option<u32> {
        let (l4_off, _) = self.tcp_offsets()?;
        if l4_off + 12 > self.buf.len() {
            return None;
        }
        Some(u32::from_be_bytes([
            self.buf[l4_off + 8],
            self.buf[l4_off + 9],
            self.buf[l4_off + 10],
            self.buf[l4_off + 11],
        ]))
    }

    pub fn tcp_flags(&self) -> Option<u8> {
        let (l4_off, _) = self.tcp_offsets()?;
        if l4_off + 14 > self.buf.len() {
            return None;
        }
        Some(self.buf[l4_off + 13])
    }

    pub fn tcp_payload(&self) -> Option<&[u8]> {
        let (l4_off, data_off) = self.tcp_offsets()?;
        let ip_off = self.ipv4_offset()?;
        let total_len = self.ipv4_total_len(ip_off)?;
        let start = l4_off + data_off;
        let end = ip_off + total_len;
        if start > end || end > self.buf.len() {
            return None;
        }
        Some(&self.buf[start..end])
    }

    fn tcp_offsets(&self) -> Option<(usize, usize)> {
        let ip_off = self.ipv4_offset()?;
        let ihl = self.ipv4_header_len(ip_off)?;
        let proto = self.protocol()?;
        if proto != 6 {
            return None;
        }
        let l4_off = ip_off + ihl;
        if l4_off + 13 > self.buf.len() {
            return None;
        }
        let data_off = ((self.buf[l4_off + 12] >> 4) as usize) * 4;
        if data_off < 20 || l4_off + data_off > self.buf.len() {
            return None;
        }
        Some((l4_off, data_off))
    }

    pub fn set_src_port(&mut self, port: u16) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        let proto = match self.protocol() {
            Some(p) => p,
            None => return false,
        };
        if proto != 6 && proto != 17 {
            return false;
        }
        let l4_off = ip_off + ihl;
        if l4_off + 2 > self.buf.len() {
            return false;
        }
        self.buf[l4_off..l4_off + 2].copy_from_slice(&port.to_be_bytes());
        true
    }

    pub fn set_dst_port(&mut self, port: u16) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        let proto = match self.protocol() {
            Some(p) => p,
            None => return false,
        };
        if proto != 6 && proto != 17 {
            return false;
        }
        let l4_off = ip_off + ihl;
        if l4_off + 4 > self.buf.len() {
            return false;
        }
        self.buf[l4_off + 2..l4_off + 4].copy_from_slice(&port.to_be_bytes());
        true
    }

    pub fn rewrite_as_tcp_rst_reply(&mut self) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        let total_len = match self.ipv4_total_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        if self.protocol() != Some(6) {
            return false;
        }
        let (src_ip, dst_ip) = match (self.src_ip(), self.dst_ip()) {
            (Some(src), Some(dst)) => (src, dst),
            _ => return false,
        };
        let (src_port, dst_port) = match self.ports() {
            Some(ports) => ports,
            None => return false,
        };
        let seq = match self.tcp_seq() {
            Some(seq) => seq,
            None => return false,
        };
        let ack = match self.tcp_ack() {
            Some(ack) => ack,
            None => return false,
        };
        let flags = match self.tcp_flags() {
            Some(flags) => flags,
            None => return false,
        };

        let l4_off = ip_off + ihl;
        if l4_off + 20 > self.buf.len() {
            return false;
        }
        let data_off = ((self.buf[l4_off + 12] >> 4) as usize) * 4;
        if data_off < 20 || l4_off + data_off > self.buf.len() {
            return false;
        }
        let tcp_len = match total_len.checked_sub(ihl) {
            Some(len) => len,
            None => return false,
        };
        if tcp_len < data_off {
            return false;
        }
        let payload_len = tcp_len - data_off;
        let syn = flags & 0x02 != 0;
        let fin = flags & 0x01 != 0;
        let ack_set = flags & 0x10 != 0;
        let ack_inc = payload_len as u32 + if syn { 1 } else { 0 } + if fin { 1 } else { 0 };
        let rst_seq = if ack_set { ack } else { 0 };
        let rst_ack = seq.wrapping_add(ack_inc);

        if !self.set_src_ip(dst_ip) || !self.set_dst_ip(src_ip) {
            return false;
        }
        if !self.set_src_port(dst_port) || !self.set_dst_port(src_port) {
            return false;
        }

        self.buf[l4_off + 4..l4_off + 8].copy_from_slice(&rst_seq.to_be_bytes());
        self.buf[l4_off + 8..l4_off + 12].copy_from_slice(&rst_ack.to_be_bytes());
        self.buf[l4_off + 13] = 0x14; // RST + ACK
        self.buf[l4_off + 14..l4_off + 16].copy_from_slice(&0u16.to_be_bytes()); // window
        self.buf[l4_off + 18..l4_off + 20].copy_from_slice(&0u16.to_be_bytes()); // urgent ptr

        let new_total_len = ihl + data_off;
        self.buf[ip_off + 2..ip_off + 4].copy_from_slice(&(new_total_len as u16).to_be_bytes());
        let new_frame_len = ip_off + new_total_len;
        if self.buf.len() < new_frame_len {
            return false;
        }
        self.buf.truncate(new_frame_len);

        self.recalc_checksums()
    }

    pub fn recalc_checksums(&mut self) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        let total_len = match self.ipv4_total_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        if ip_off + ihl > self.buf.len() {
            return false;
        }

        self.buf[ip_off + 10] = 0;
        self.buf[ip_off + 11] = 0;
        let header = &self.buf[ip_off..ip_off + ihl];
        let checksum = checksum_finalize(checksum_sum(header));
        self.buf[ip_off + 10..ip_off + 12].copy_from_slice(&checksum.to_be_bytes());

        let proto = self.buf[ip_off + 9];
        if proto == 1 {
            let l4_off = ip_off + ihl;
            let l4_len = total_len - ihl;
            if l4_off + l4_len > self.buf.len() || l4_len < 8 {
                return false;
            }
            self.buf[l4_off + 2] = 0;
            self.buf[l4_off + 3] = 0;
            let checksum = checksum_finalize(checksum_sum(&self.buf[l4_off..l4_off + l4_len]));
            self.buf[l4_off + 2..l4_off + 4].copy_from_slice(&checksum.to_be_bytes());
            return true;
        }
        if proto != 6 && proto != 17 {
            return true;
        }
        let l4_off = ip_off + ihl;
        let l4_len = total_len - ihl;
        if l4_off + l4_len > self.buf.len() {
            return false;
        }
        let src = Ipv4Addr::new(
            self.buf[ip_off + 12],
            self.buf[ip_off + 13],
            self.buf[ip_off + 14],
            self.buf[ip_off + 15],
        );
        let dst = Ipv4Addr::new(
            self.buf[ip_off + 16],
            self.buf[ip_off + 17],
            self.buf[ip_off + 18],
            self.buf[ip_off + 19],
        );

        let (checksum_off, payload) = if proto == 6 {
            if l4_len < 20 || l4_off + 20 > self.buf.len() {
                return false;
            }
            (l4_off + 16, &mut self.buf[l4_off..l4_off + l4_len])
        } else {
            if l4_len < 8 || l4_off + 8 > self.buf.len() {
                return false;
            }
            (l4_off + 6, &mut self.buf[l4_off..l4_off + l4_len])
        };

        payload[checksum_off - l4_off] = 0;
        payload[checksum_off - l4_off + 1] = 0;

        let checksum = transport_checksum(src, dst, proto, payload);
        payload[checksum_off - l4_off..checksum_off - l4_off + 2]
            .copy_from_slice(&checksum.to_be_bytes());

        true
    }

    pub fn rewrite_as_icmp_time_exceeded(&mut self, src_ip: Ipv4Addr) -> bool {
        let ip_off = match self.ipv4_offset() {
            Some(off) => off,
            None => return false,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return false,
        };
        if ip_off + ihl + 8 > self.buf.len() {
            return false;
        }
        let dst_ip = match self.src_ip() {
            Some(ip) => ip,
            None => return false,
        };

        let has_eth = ip_off == ETH_HDR_LEN;
        let mut eth_dst = [0u8; 6];
        let mut eth_src = [0u8; 6];
        if has_eth {
            if self.buf.len() < ETH_HDR_LEN {
                return false;
            }
            eth_dst.copy_from_slice(&self.buf[0..6]);
            eth_src.copy_from_slice(&self.buf[6..12]);
        }

        let icmp_payload_len = ihl + 8;
        let icmp_len = 8 + icmp_payload_len;
        let total_len = 20 + icmp_len;
        let eth_len = if has_eth { ETH_HDR_LEN } else { 0 };
        let mut buf = vec![0u8; eth_len + total_len];

        if has_eth {
            buf[0..6].copy_from_slice(&eth_src);
            buf[6..12].copy_from_slice(&eth_dst);
            buf[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
        }

        let ip_out = eth_len;
        buf[ip_out] = 0x45;
        buf[ip_out + 1] = 0;
        buf[ip_out + 2..ip_out + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[ip_out + 4..ip_out + 6].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_out + 6..ip_out + 8].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_out + 8] = 64;
        buf[ip_out + 9] = 1;
        buf[ip_out + 10..ip_out + 12].copy_from_slice(&0u16.to_be_bytes());
        buf[ip_out + 12..ip_out + 16].copy_from_slice(&src_ip.octets());
        buf[ip_out + 16..ip_out + 20].copy_from_slice(&dst_ip.octets());

        let icmp_off = ip_out + 20;
        buf[icmp_off] = 11;
        buf[icmp_off + 1] = 0;
        buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&0u16.to_be_bytes());
        buf[icmp_off + 4..icmp_off + 8].copy_from_slice(&0u32.to_be_bytes());
        buf[icmp_off + 8..icmp_off + 8 + ihl].copy_from_slice(&self.buf[ip_off..ip_off + ihl]);
        buf[icmp_off + 8 + ihl..icmp_off + 8 + ihl + 8]
            .copy_from_slice(&self.buf[ip_off + ihl..ip_off + ihl + 8]);

        let checksum = checksum_finalize(checksum_sum(&buf[icmp_off..icmp_off + icmp_len]));
        buf[icmp_off + 2..icmp_off + 4].copy_from_slice(&checksum.to_be_bytes());

        self.buf = buf;
        self.recalc_checksums()
    }

    pub fn clamp_tcp_mss(&mut self, max_mss: u16) -> bool {
        let (l4_off, data_off) = match self.tcp_offsets() {
            Some(offsets) => offsets,
            None => return false,
        };
        if self.buf.len() < l4_off + data_off {
            return false;
        }
        let flags = self.buf[l4_off + 13];
        if flags & 0x02 == 0 {
            return false;
        }
        let mut idx = l4_off + 20;
        let end = l4_off + data_off;
        let mut changed = false;
        while idx + 2 <= end {
            let kind = self.buf[idx];
            if kind == 0 {
                break;
            }
            if kind == 1 {
                idx += 1;
                continue;
            }
            if idx + 2 > end {
                break;
            }
            let len = self.buf[idx + 1] as usize;
            if len < 2 || idx + len > end {
                break;
            }
            if kind == 2 && len == 4 {
                let current = u16::from_be_bytes([self.buf[idx + 2], self.buf[idx + 3]]);
                if current > max_mss {
                    self.buf[idx + 2..idx + 4].copy_from_slice(&max_mss.to_be_bytes());
                    changed = true;
                }
                break;
            }
            idx += len;
        }
        changed
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IcmpInnerTuple {
    pub ip_offset: usize,
    pub ihl: usize,
    pub l4_offset: usize,
    pub proto: u8,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_identifier: Option<u16>,
}

fn recalc_ipv4_header_checksum(buf: &mut [u8], ip_off: usize, ihl: usize) -> bool {
    if ip_off + ihl > buf.len() || ihl < 20 {
        return false;
    }
    buf[ip_off + 10] = 0;
    buf[ip_off + 11] = 0;
    let checksum = checksum_finalize(checksum_sum(&buf[ip_off..ip_off + ihl]));
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&checksum.to_be_bytes());
    true
}

fn checksum_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += (rem as u32) << 8;
    }
    sum
}

fn checksum_finalize(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum += checksum_sum(&src.octets());
    sum += checksum_sum(&dst.octets());
    sum += proto as u32;
    sum += payload.len() as u32;
    sum += checksum_sum(payload);
    checksum_finalize(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_helpers_smoke() {
        let data = [0x00u8, 0x01, 0xf2, 0x03];
        let sum = checksum_sum(&data);
        let checksum = checksum_finalize(sum);
        assert_ne!(checksum, 0);
    }
}
