impl Packet {
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
        let old = u32::from_be_bytes([
            self.buf[ip_off + 12],
            self.buf[ip_off + 13],
            self.buf[ip_off + 14],
            self.buf[ip_off + 15],
        ]);
        let new = u32::from(ip);
        self.buf[ip_off + 12..ip_off + 16].copy_from_slice(&ip.octets());
        self.update_ipv4_header_checksum_u32(ip_off, old, new);
        self.update_transport_pseudo_checksum_u32(ip_off, old, new);
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
        let old = u32::from_be_bytes([
            self.buf[ip_off + 16],
            self.buf[ip_off + 17],
            self.buf[ip_off + 18],
            self.buf[ip_off + 19],
        ]);
        let new = u32::from(ip);
        self.buf[ip_off + 16..ip_off + 20].copy_from_slice(&ip.octets());
        self.update_ipv4_header_checksum_u32(ip_off, old, new);
        self.update_transport_pseudo_checksum_u32(ip_off, old, new);
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
        if !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, 4) {
            return None;
        }
        let src = u16::from_be_bytes([self.buf[l4_off], self.buf[l4_off + 1]]);
        let dst = u16::from_be_bytes([self.buf[l4_off + 2], self.buf[l4_off + 3]]);
        Some((src, dst))
    }

    pub fn tcp_seq(&self) -> Option<u32> {
        let ip_off = self.ipv4_offset()?;
        let (l4_off, _) = self.tcp_offsets()?;
        if !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, 8) {
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
        let ip_off = self.ipv4_offset()?;
        let (l4_off, _) = self.tcp_offsets()?;
        if !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, 12) {
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
        let ip_off = self.ipv4_offset()?;
        let (l4_off, _) = self.tcp_offsets()?;
        if !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, 14) {
            return None;
        }
        Some(self.buf[l4_off + 13])
    }

    pub fn tcp_payload(&self) -> Option<&[u8]> {
        let (l4_off, data_off) = self.tcp_offsets()?;
        let ip_off = self.ipv4_offset()?;
        let start = l4_off + data_off;
        let end = self.ipv4_logical_end(ip_off)?;
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
        if !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, 13) {
            return None;
        }
        let data_off = ((self.buf[l4_off + 12] >> 4) as usize) * 4;
        if data_off < 20 || !self.ipv4_range_within(ip_off, self.buf.len(), l4_off, data_off) {
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
        let old = u16::from_be_bytes([self.buf[l4_off], self.buf[l4_off + 1]]);
        self.buf[l4_off..l4_off + 2].copy_from_slice(&port.to_be_bytes());
        self.update_transport_checksum_u16(ip_off, l4_off, proto, old, port);
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
        let old = u16::from_be_bytes([self.buf[l4_off + 2], self.buf[l4_off + 3]]);
        self.buf[l4_off + 2..l4_off + 4].copy_from_slice(&port.to_be_bytes());
        self.update_transport_checksum_u16(ip_off, l4_off, proto, old, port);
        true
    }
}
