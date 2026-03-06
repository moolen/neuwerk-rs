impl Packet {
    fn update_ipv4_header_checksum_u32(&mut self, ip_off: usize, old: u32, new: u32) {
        if ip_off + 12 > self.buf.len() {
            return;
        }
        let old_csum = u16::from_be_bytes([self.buf[ip_off + 10], self.buf[ip_off + 11]]);
        let new_csum = checksum_update_u32(old_csum, old, new);
        self.buf[ip_off + 10..ip_off + 12].copy_from_slice(&new_csum.to_be_bytes());
    }

    fn update_transport_pseudo_checksum_u32(&mut self, ip_off: usize, old: u32, new: u32) {
        let proto = match self.protocol() {
            Some(p) => p,
            None => return,
        };
        if proto != 6 && proto != 17 {
            return;
        }
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return,
        };
        let l4_off = ip_off + ihl;
        self.update_transport_checksum_u32(ip_off, l4_off, proto, old, new);
    }

    fn update_transport_checksum_u16(
        &mut self,
        ip_off: usize,
        l4_off: usize,
        proto: u8,
        old: u16,
        new: u16,
    ) {
        let total_len = match self.ipv4_total_len(ip_off) {
            Some(len) => len,
            None => return,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return,
        };
        let l4_len = total_len.saturating_sub(ihl);
        let checksum_off = match proto {
            6 => {
                if l4_len < 20 || l4_off + 18 > self.buf.len() {
                    return;
                }
                l4_off + 16
            }
            17 => {
                if l4_len < 8 || l4_off + 8 > self.buf.len() {
                    return;
                }
                l4_off + 6
            }
            _ => return,
        };
        let old_csum = u16::from_be_bytes([self.buf[checksum_off], self.buf[checksum_off + 1]]);
        if proto == 17 && old_csum == 0 {
            return;
        }
        let new_csum = checksum_update_u16(old_csum, old, new);
        self.buf[checksum_off..checksum_off + 2].copy_from_slice(&new_csum.to_be_bytes());
    }

    fn update_transport_checksum_u32(
        &mut self,
        ip_off: usize,
        l4_off: usize,
        proto: u8,
        old: u32,
        new: u32,
    ) {
        let total_len = match self.ipv4_total_len(ip_off) {
            Some(len) => len,
            None => return,
        };
        let ihl = match self.ipv4_header_len(ip_off) {
            Some(len) => len,
            None => return,
        };
        let l4_len = total_len.saturating_sub(ihl);
        let checksum_off = match proto {
            6 => {
                if l4_len < 20 || l4_off + 18 > self.buf.len() {
                    return;
                }
                l4_off + 16
            }
            17 => {
                if l4_len < 8 || l4_off + 8 > self.buf.len() {
                    return;
                }
                l4_off + 6
            }
            _ => return,
        };
        let old_csum = u16::from_be_bytes([self.buf[checksum_off], self.buf[checksum_off + 1]]);
        if proto == 17 && old_csum == 0 {
            return;
        }
        let new_csum = checksum_update_u32(old_csum, old, new);
        self.buf[checksum_off..checksum_off + 2].copy_from_slice(&new_csum.to_be_bytes());
    }
}
