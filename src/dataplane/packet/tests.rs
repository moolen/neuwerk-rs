use super::*;

#[test]
fn checksum_helpers_smoke() {
    let data = [0x00u8, 0x01, 0xf2, 0x03];
    let sum = checksum_sum(&data);
    let checksum = checksum_finalize(sum);
    assert_ne!(checksum, 0);
}

#[test]
fn incremental_l3_l4_checksum_matches_full_recalc() {
    let mut base = Packet::new(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64,
        17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1, 156, 64, 0, 53, 0, 12, 0, 0, b't', b'e', b's', b't',
    ]);
    assert!(base.recalc_checksums());
    let mut inc = base.clone();
    let mut full = base.clone();

    assert!(inc.set_ipv4_ttl(63));
    assert!(inc.set_src_ip(Ipv4Addr::new(10, 0, 0, 99)));
    assert!(inc.set_dst_ip(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(inc.set_src_port(40123));
    assert!(inc.set_dst_port(5300));

    assert!(full.set_ipv4_ttl(63));
    assert!(full.set_src_ip(Ipv4Addr::new(10, 0, 0, 99)));
    assert!(full.set_dst_ip(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(full.set_src_port(40123));
    assert!(full.set_dst_port(5300));
    assert!(full.recalc_checksums());

    assert_eq!(inc.buffer(), full.buffer());
}

#[test]
fn udp_zero_checksum_stays_zero_on_rewrite() {
    let mut pkt = Packet::new(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0x00, 0x00, 0x1c, 0, 0, 0, 0, 64,
        17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1, 156, 64, 0, 53, 0, 8, 0, 0,
    ]);
    assert!(pkt.recalc_checksums());
    pkt.buffer_mut()[40] = 0;
    pkt.buffer_mut()[41] = 0;
    assert!(pkt.set_src_ip(Ipv4Addr::new(10, 0, 0, 99)));
    assert!(pkt.set_src_port(40123));
    assert_eq!(pkt.buffer()[40], 0);
    assert_eq!(pkt.buffer()[41], 0);
}

#[test]
fn recalc_checksums_rejects_malformed_ipv4_total_len_smaller_than_ihl() {
    // IPv4 version=4, IHL=13 (52 bytes), total_len=40 -> invalid and should not panic.
    let mut pkt = Packet::new(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x4d, 0x00, 0x00, 0x28, 0x00, 0x02, 0x00,
        0x00, 0x40, 0x06, 0xf9, 0x77, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0x90, 0x90,
    ]);
    assert!(!pkt.recalc_checksums());
}

#[test]
fn take_transfer_bytes_compacts_payload_and_preserves_owned_capacity_for_reuse() {
    let mut pkt = Packet::new(vec![0u8; 65_536]);
    pkt.truncate(64);

    let payload = pkt.take_transfer_bytes();
    assert_eq!(payload.len(), 64);
    assert_eq!(pkt.len(), 0);

    let reusable = pkt.into_vec();
    assert_eq!(reusable.len(), 0);
    assert!(reusable.capacity() >= 65_536);
}
