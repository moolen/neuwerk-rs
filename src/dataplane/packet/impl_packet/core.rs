impl Packet {
    pub fn new(buf: Vec<u8>) -> Self {
        Self {
            buf: PacketBuf::owned(buf),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            buf: PacketBuf::owned(bytes.to_vec()),
        }
    }

    // Safety: caller must ensure the pointer remains valid and uniquely writable while
    // the returned packet is used.
    pub unsafe fn from_borrowed_mut(ptr: *mut u8, len: usize) -> Option<Self> {
        Some(Self {
            buf: PacketBuf::borrowed(ptr, len)?,
        })
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

    pub fn into_vec(self) -> Vec<u8> {
        self.buf.into_vec()
    }

    pub fn is_borrowed(&self) -> bool {
        self.buf.is_borrowed()
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

}
