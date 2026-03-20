#![no_main]

use neuwerk::dataplane::packet::Packet;
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;

fuzz_target!(|data: &[u8]| {
    let mut packet = Packet::from_bytes(data);

    let _ = packet.len();
    let _ = packet.protocol();
    let _ = packet.icmp_type_code();
    let _ = packet.icmp_identifier();
    let _ = packet.src_ip();
    let _ = packet.dst_ip();
    let _ = packet.ports();
    let _ = packet.tcp_seq();
    let _ = packet.tcp_ack();
    let _ = packet.tcp_flags();
    let _ = packet.tcp_payload();
    let _ = packet.is_ipv4_fragment();
    let _ = packet.icmp_inner_tuple();

    if let Some(ttl) = packet.ipv4_ttl() {
        let _ = packet.set_ipv4_ttl(ttl.saturating_sub(1));
    }
    if let Some(src) = packet.src_ip() {
        let _ = packet.set_src_ip(src);
    }
    if let Some(dst) = packet.dst_ip() {
        let _ = packet.set_dst_ip(dst);
    }
    if let Some((src, dst)) = packet.ports() {
        let _ = packet.set_src_port(dst);
        let _ = packet.set_dst_port(src);
    }

    let _ = packet.clamp_tcp_mss(1200);
    let _ = packet.recalc_checksums();
    let _ = packet.rewrite_as_tcp_rst_reply();
    let _ = packet.rewrite_as_icmp_time_exceeded(Ipv4Addr::new(1, 1, 1, 1));
});
