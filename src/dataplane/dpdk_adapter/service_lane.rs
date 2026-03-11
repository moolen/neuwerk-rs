use std::fs::File;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd};

pub(super) fn intercept_service_ip() -> Ipv4Addr {
    std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_IP")
        .ok()
        .and_then(|raw| raw.parse::<Ipv4Addr>().ok())
        .unwrap_or(super::INTERCEPT_SERVICE_IP_DEFAULT)
}

pub(super) fn intercept_service_port() -> u16 {
    std::env::var("NEUWERK_DPDK_INTERCEPT_SERVICE_PORT")
        .ok()
        .and_then(|raw| raw.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(super::INTERCEPT_SERVICE_PORT_DEFAULT)
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
}

pub(super) fn open_tap(name: &str) -> Result<File, String> {
    if name.is_empty() {
        return Err("dpdk: service lane interface cannot be empty".to_string());
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(format!(
            "dpdk: service lane interface name too long (max {})",
            libc::IFNAMSIZ - 1
        ));
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "dpdk: open /dev/net/tun failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut ifr = IfReq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_flags: super::IFF_TAP | super::IFF_NO_PI,
    };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }
    let rc = unsafe { libc::ioctl(fd, super::TUNSETIFF, &ifr) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("dpdk: TUNSETIFF {name} failed: {err}"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn read_interface_mac(iface: &str) -> Result<[u8; 6], String> {
    let path = format!("/sys/class/net/{iface}/address");
    let value =
        std::fs::read_to_string(&path).map_err(|err| format!("read {path} failed: {err}"))?;
    parse_mac_addr(value.trim())
}

pub(super) fn parse_mac_addr(value: &str) -> Result<[u8; 6], String> {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 6 {
        return Err(format!("invalid mac address '{value}'"));
    }
    let mut bytes = [0u8; 6];
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 {
            return Err(format!("invalid mac address '{value}'"));
        }
        bytes[idx] = u8::from_str_radix(part, 16)
            .map_err(|err| format!("invalid mac address '{value}': {err}"))?;
    }
    Ok(bytes)
}

pub(super) fn service_lane_tap_readable(tap: &File) -> Result<bool, String> {
    let fd = tap.as_raw_fd();
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 0) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(format!("dpdk: service lane poll failed: {}", err));
    }
    if rc == 0 {
        return Ok(false);
    }
    if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(format!(
            "dpdk: service lane poll error revents=0x{:x}",
            pfd.revents
        ));
    }
    Ok(pfd.revents & libc::POLLIN != 0)
}

pub(super) fn select_mac(fallback: [u8; 6], candidate: Option<[u8; 6]>) -> [u8; 6] {
    if let Some(mac) = candidate {
        if mac != [0; 6] {
            return mac;
        }
    }
    fallback
}
