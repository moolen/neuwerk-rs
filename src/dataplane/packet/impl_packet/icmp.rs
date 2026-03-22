impl Packet {
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
        if ip_off + 12 > self.buf.len() {
            return false;
        }
        let old_word = u16::from_be_bytes([self.buf[ip_off + 8], self.buf[ip_off + 9]]);
        self.buf[ip_off + 8] = ttl;
        let new_word = u16::from_be_bytes([self.buf[ip_off + 8], self.buf[ip_off + 9]]);
        let old_csum = u16::from_be_bytes([self.buf[ip_off + 10], self.buf[ip_off + 11]]);
        let new_csum = checksum_update_u16(old_csum, old_word, new_word);
        self.buf[ip_off + 10..ip_off + 12].copy_from_slice(&new_csum.to_be_bytes());
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
        let outer_end = self.ipv4_logical_end(ip_off)?;
        let icmp_off = ip_off + ihl;
        let inner_ip_off = icmp_off + 8;
        if outer_end < inner_ip_off + 20 {
            return None;
        }
        let ver = self.buf[inner_ip_off] >> 4;
        if ver != 4 {
            return None;
        }
        let inner_ihl = self.ipv4_header_len_within(inner_ip_off, outer_end)?;
        let inner_total_len =
            u16::from_be_bytes([self.buf[inner_ip_off + 2], self.buf[inner_ip_off + 3]]) as usize;
        if inner_total_len < inner_ihl {
            return None;
        }
        let inner_logical_end = inner_ip_off.checked_add(inner_total_len)?;
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
        let (src_port, dst_port, icmp_identifier) = match proto {
            6 | 17 => {
                if outer_end < l4_off + 4 || inner_logical_end < l4_off + 4 {
                    return None;
                }
                let src_port = u16::from_be_bytes([self.buf[l4_off], self.buf[l4_off + 1]]);
                let dst_port = u16::from_be_bytes([self.buf[l4_off + 2], self.buf[l4_off + 3]]);
                (src_port, dst_port, None)
            }
            1 => {
                if outer_end < l4_off + 6 || inner_logical_end < l4_off + 6 {
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
}
