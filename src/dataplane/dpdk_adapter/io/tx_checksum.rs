fn maybe_prepare_tx_checksum_offload(
    mbuf: *mut rte_mbuf,
    frame: &[u8],
    caps: TxChecksumOffloadCaps,
) -> bool {
    if mbuf.is_null() || !caps.any() {
        return false;
    }
    if frame.len() < super::ETH_HDR_LEN + 20 {
        return false;
    }
    let ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    if ether_type != super::ETH_TYPE_IPV4 {
        return false;
    }
    let ip_off = super::ETH_HDR_LEN;
    let ver_ihl = frame[ip_off];
    if (ver_ihl >> 4) != 4 {
        return false;
    }
    let ihl = ((ver_ihl & 0x0f) as usize) * 4;
    if ihl < 20 || frame.len() < ip_off + ihl {
        return false;
    }
    let proto = frame[ip_off + 9];
    let l4_off = ip_off + ihl;
    let mut ol_flags = PKT_TX_IPV4;
    if caps.ipv4 {
        ol_flags |= PKT_TX_IP_CKSUM;
    }
    let l4_cksum_ptr = match proto {
        6 if caps.tcp => {
            if frame.len() < l4_off + 20 {
                return false;
            }
            ol_flags |= PKT_TX_TCP_CKSUM;
            (l4_off + 16) as u16
        }
        17 if caps.udp => {
            if frame.len() < l4_off + 8 {
                return false;
            }
            let src_port = u16::from_be_bytes([frame[l4_off], frame[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([frame[l4_off + 2], frame[l4_off + 3]]);
            // DHCP/BOOTP (67/68) frames have shown unstable behavior with ENA
            // UDP checksum offload in this bench; keep them in software-checksum
            // mode and offload all other UDP traffic.
            if (src_port == crate::dataplane::dhcp::DHCP_CLIENT_PORT
                && dst_port == crate::dataplane::dhcp::DHCP_SERVER_PORT)
                || (src_port == crate::dataplane::dhcp::DHCP_SERVER_PORT
                    && dst_port == crate::dataplane::dhcp::DHCP_CLIENT_PORT)
            {
                return false;
            }
            if frame[l4_off + 6] == 0 && frame[l4_off + 7] == 0 {
                return false;
            }
            ol_flags |= PKT_TX_UDP_CKSUM;
            (l4_off + 6) as u16
        }
        _ => return false,
    };
    unsafe {
        let ret = rust_rte_prepare_ipv4_l4_checksum_offload(
            mbuf,
            ol_flags,
            super::ETH_HDR_LEN as u16,
            ihl as u16,
        );
        if ret == 0 {
            return true;
        }
        let m = &mut *mbuf;
        m.ol_flags = 0;
        *m._5.tx_offload.as_mut() = 0;
        if DPDK_TX_CSUM_PREP_FAIL_LOGS.fetch_add(1, Ordering::Relaxed) < 16 {
            tracing::warn!(
                ret,
                proto,
                l3_len = ihl,
                l4_cksum_off = l4_cksum_ptr,
                "dpdk tx checksum offload prep failed; falling back to software checksum"
            );
        }
    }
    false
}
