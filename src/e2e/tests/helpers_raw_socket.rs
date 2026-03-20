use super::*;

static NEXT_ICMP_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

pub(in crate::e2e::tests) fn icmp_echo(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        bind_raw_socket(fd, bind_ip)?;
        set_socket_timeout(fd, timeout)?;

        let id = NEXT_ICMP_ID
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add((unsafe { libc::getpid() } as u16) ^ 0x1234);
        let seq = 1u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(b"ping");
        let mut pkt = vec![0u8; 8 + payload.len()];
        pkt[0] = 8;
        pkt[1] = 0;
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..].copy_from_slice(&payload);
        let checksum = checksum16(&pkt);
        pkt[2..4].copy_from_slice(&checksum.to_be_bytes());

        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const _,
                pkt.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }

        let mut buf = vec![0u8; 2048];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut
                {
                    return Err("icmp echo timed out".to_string());
                }
                return Err(err.to_string());
            }
            let n = n as usize;
            if let Some((ihl, proto, _src, _dst)) = parse_ipv4_header(&buf[..n]) {
                if proto != 1 || n < ihl + 8 {
                    continue;
                }
                let icmp_off = ihl;
                let icmp_type = buf[icmp_off];
                let icmp_code = buf[icmp_off + 1];
                if icmp_type != 0 || icmp_code != 0 {
                    continue;
                }
                let recv_id = u16::from_be_bytes([buf[icmp_off + 4], buf[icmp_off + 5]]);
                let recv_seq = u16::from_be_bytes([buf[icmp_off + 6], buf[icmp_off + 7]]);
                if recv_id == id && recv_seq == seq {
                    return Ok(());
                }
            } else if n >= 8 {
                let icmp_type = buf[0];
                let icmp_code = buf[1];
                if icmp_type != 0 || icmp_code != 0 {
                    continue;
                }
                let recv_id = u16::from_be_bytes([buf[4], buf[5]]);
                let recv_seq = u16::from_be_bytes([buf[6], buf[7]]);
                if recv_id == id && recv_seq == seq {
                    return Ok(());
                }
            }
        }
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

pub(in crate::e2e::tests) fn open_icmp_socket(
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

pub(in crate::e2e::tests) struct UdpPacketInfo {
    pub(in crate::e2e::tests) src_port: u16,
    pub(in crate::e2e::tests) payload: Vec<u8>,
}

pub(in crate::e2e::tests) fn open_tcp_raw_socket(
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

pub(in crate::e2e::tests) fn open_udp_raw_socket(
    bind_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

pub(in crate::e2e::tests) fn wait_for_udp_packet_on_fd(
    fd: i32,
    expected_src: Ipv4Addr,
    expected_dst: Ipv4Addr,
    expected_dst_port: u16,
    payload_prefix: Option<&[u8]>,
    timeout: Duration,
) -> Result<UdpPacketInfo, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err("udp capture timed out".to_string());
        }
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (ihl, proto, src, dst) = match parse_ipv4_header(&buf[..n]) {
            Some(values) => values,
            None => continue,
        };
        if proto != 17 {
            continue;
        }
        if src != expected_src || dst != expected_dst {
            continue;
        }
        if n < 9 {
            continue;
        }
        let udp_off = ihl;
        if n < udp_off + 8 {
            continue;
        }
        let src_port = u16::from_be_bytes([buf[udp_off], buf[udp_off + 1]]);
        let dst_port = u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
        if dst_port != expected_dst_port {
            continue;
        }
        let payload = buf[udp_off + 8..n].to_vec();
        if let Some(prefix) = payload_prefix {
            if !payload.starts_with(prefix) {
                continue;
            }
        }
        return Ok(UdpPacketInfo { src_port, payload });
    }
}

pub(in crate::e2e::tests) fn wait_for_tcp_rst_on_fd(
    fd: i32,
    expected_src: Ipv4Addr,
    expected_dst: Ipv4Addr,
    expected_src_port: Option<u16>,
    expected_dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    let mut last_non_rst: Option<(u8, u16, u16)> = None;
    loop {
        if Instant::now() >= deadline {
            return Err(match last_non_rst {
                Some((flags, src_port, dst_port)) => format!(
                    "tcp rst capture timed out (last flags=0x{flags:02x}, src_port={src_port}, dst_port={dst_port})"
                ),
                None => "tcp rst capture timed out".to_string(),
            });
        }
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (ihl, proto, src, dst) = match parse_ipv4_header(&buf[..n]) {
            Some(values) => values,
            None => continue,
        };
        if proto != 6 || src != expected_src || dst != expected_dst {
            continue;
        }
        if n < ihl + 20 {
            continue;
        }
        let tcp_off = ihl;
        let data_offset = ((buf[tcp_off + 12] >> 4) as usize) * 4;
        if data_offset < 20 || n < tcp_off + data_offset {
            continue;
        }
        let src_port = u16::from_be_bytes([buf[tcp_off], buf[tcp_off + 1]]);
        let dst_port = u16::from_be_bytes([buf[tcp_off + 2], buf[tcp_off + 3]]);
        if let Some(port) = expected_src_port {
            if src_port != port {
                continue;
            }
        }
        if let Some(port) = expected_dst_port {
            if dst_port != port {
                continue;
            }
        }
        let flags = buf[tcp_off + 13];
        if (flags & 0x04) != 0 {
            return Ok(());
        }
        last_non_rst = Some((flags, src_port, dst_port));
    }
}

pub(in crate::e2e::tests) fn wait_for_icmp_time_exceeded_on_fd(
    fd: i32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    expected_outer_src: Option<Ipv4Addr>,
) -> Result<(), String> {
    let mut buf = vec![0u8; 2048];
    let mut last_unexpected: Option<(Ipv4Addr, Ipv4Addr)> = None;
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                return Err(match last_unexpected {
                    Some((src, dst)) => format!(
                        "icmp time exceeded timed out (last outer src={}, dst={})",
                        src, dst
                    ),
                    None => "icmp time exceeded timed out".to_string(),
                });
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (icmp_off, inner_off, outer_src, outer_dst) =
            if let Some((ihl, proto, src, dst)) = parse_ipv4_header(&buf[..n]) {
                if proto != 1 || n < ihl + 8 {
                    continue;
                }
                (ihl, ihl + 8, Some(src), Some(dst))
            } else {
                if n < 8 {
                    continue;
                }
                (0usize, 8usize, None, None)
            };
        let icmp_type = buf[icmp_off];
        let icmp_code = buf[icmp_off + 1];
        if icmp_type != 11 || icmp_code != 0 {
            continue;
        }
        if n < inner_off + 20 {
            continue;
        }
        let inner_ihl = ((buf[inner_off] & 0x0f) as usize) * 4;
        if inner_ihl < 20 || n < inner_off + inner_ihl + 8 {
            continue;
        }
        let inner_proto = buf[inner_off + 9];
        if inner_proto != 17 {
            continue;
        }
        let inner_src = Ipv4Addr::new(
            buf[inner_off + 12],
            buf[inner_off + 13],
            buf[inner_off + 14],
            buf[inner_off + 15],
        );
        let inner_dst = Ipv4Addr::new(
            buf[inner_off + 16],
            buf[inner_off + 17],
            buf[inner_off + 18],
            buf[inner_off + 19],
        );
        if inner_src != src_ip || inner_dst != dst_ip {
            continue;
        }
        let udp_off = inner_off + inner_ihl;
        let inner_src_port = u16::from_be_bytes([buf[udp_off], buf[udp_off + 1]]);
        let inner_dst_port = u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
        if inner_src_port == src_port && inner_dst_port == dst_port {
            if let (Some(expected), Some(actual_src), Some(actual_dst)) =
                (expected_outer_src, outer_src, outer_dst)
            {
                if actual_src != expected {
                    last_unexpected = Some((actual_src, actual_dst));
                    continue;
                }
            }
            return Ok(());
        }
    }
}

pub(in crate::e2e::tests) fn send_ipv4_udp_fragment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        let hdrincl: libc::c_int = 1;
        let opt = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &hdrincl as *const _ as *const _,
                mem::size_of::<libc::c_int>() as u32,
            )
        };
        if opt < 0 {
            return Err(io::Error::last_os_error().to_string());
        }

        let total_len = 20 + 8 + payload.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        buf[8] = 64;
        buf[9] = 17;
        buf[10..12].copy_from_slice(&0u16.to_be_bytes());
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());
        let checksum = checksum16(&buf[..20]);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());

        let udp_off = 20;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
        buf[udp_off + 8..].copy_from_slice(payload);

        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const _,
                buf.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

pub(in crate::e2e::tests) fn build_icmp_time_exceeded(
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_src_port: u16,
    inner_dst_port: u16,
) -> Vec<u8> {
    let inner_len = 20 + 8;
    let mut buf = vec![0u8; 8 + inner_len];
    buf[0] = 11;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&0u32.to_be_bytes());

    let ip_off = 8;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(inner_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 1;
    buf[ip_off + 9] = 17;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&inner_src.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&inner_dst.octets());

    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&inner_src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&inner_dst_port.to_be_bytes());
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&8u16.to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());

    let checksum = checksum16(&buf);
    buf[2..4].copy_from_slice(&checksum.to_be_bytes());
    buf
}

pub(in crate::e2e::tests) fn send_icmp_time_exceeded(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_src_port: u16,
    inner_dst_port: u16,
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        bind_raw_socket(fd, bind_ip)?;
        let pkt = build_icmp_time_exceeded(inner_src, inner_dst, inner_src_port, inner_dst_port);
        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const _,
                pkt.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

pub(in crate::e2e::tests) fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(value);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(in crate::e2e::tests) fn parse_ipv4_header(
    buf: &[u8],
) -> Option<(usize, u8, Ipv4Addr, Ipv4Addr)> {
    if buf.len() < 20 {
        return None;
    }
    if (buf[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let proto = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some((ihl, proto, src, dst))
}

pub(in crate::e2e::tests) fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

pub(in crate::e2e::tests) fn bind_raw_socket(fd: i32, ip: Ipv4Addr) -> Result<(), String> {
    let addr = sockaddr_in(ip, 0);
    let res = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(in crate::e2e::tests) fn set_socket_timeout(fd: i32, timeout: Duration) -> Result<(), String> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const _,
            mem::size_of::<libc::timeval>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(in crate::e2e::tests) fn enable_ip_recv_ttl(fd: i32) -> Result<(), String> {
    let opt: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &opt as *const _ as *const _,
            mem::size_of::<libc::c_int>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(in crate::e2e::tests) fn recv_udp_ttl(fd: i32, timeout: Duration) -> Result<u8, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    let mut cmsg_buf = [0u8; 64];
    loop {
        if Instant::now() >= deadline {
            return Err("udp ttl timed out".to_string());
        }
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len();
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let cmsg_ref = unsafe { &*cmsg };
            if cmsg_ref.cmsg_level == libc::IPPROTO_IP && cmsg_ref.cmsg_type == libc::IP_TTL {
                let data = unsafe { libc::CMSG_DATA(cmsg) as *const u8 };
                let ttl = unsafe { *data };
                return Ok(ttl);
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        return Err("udp ttl missing".to_string());
    }
}
