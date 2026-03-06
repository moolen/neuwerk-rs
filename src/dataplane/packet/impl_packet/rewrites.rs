impl Packet {
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
        let l4_len = match total_len.checked_sub(ihl) {
            Some(len) => len,
            None => return false,
        };
        if proto == 1 {
            let l4_off = ip_off + ihl;
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

        self.buf = PacketBuf::owned(buf);
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
