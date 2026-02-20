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
        Self { buf: bytes.to_vec() }
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
