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

fn checksum_update_u16(checksum: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!checksum as u32) + ((!old as u32) & 0xffff) + (new as u32);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_update_u32(checksum: u16, old: u32, new: u32) -> u16 {
    let old_hi = (old >> 16) as u16;
    let old_lo = (old & 0xffff) as u16;
    let new_hi = (new >> 16) as u16;
    let new_lo = (new & 0xffff) as u16;
    let csum = checksum_update_u16(checksum, old_hi, new_hi);
    checksum_update_u16(csum, old_lo, new_lo)
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

