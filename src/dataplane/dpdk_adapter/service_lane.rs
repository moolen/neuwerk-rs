use std::fs::File;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd};

use crate::support::runtime_knobs::current_runtime_knobs;

pub(super) fn intercept_service_ip() -> Ipv4Addr {
    current_runtime_knobs().dpdk.service_lane_intercept_service_ip
}

pub(super) fn intercept_service_port() -> u16 {
    current_runtime_knobs().dpdk.service_lane_intercept_service_port
}

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
}

fn tap_ifreq_flags() -> libc::c_short {
    let mut flags = super::IFF_TAP | super::IFF_NO_PI;
    if current_runtime_knobs().dpdk.service_lane_multi_queue {
        flags |= libc::IFF_MULTI_QUEUE as libc::c_short;
    }
    flags
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
        ifr_flags: tap_ifreq_flags(),
    };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }
    let mut rc = unsafe { libc::ioctl(fd, super::TUNSETIFF, &ifr) };
    if rc < 0 && (ifr.ifr_flags & libc::IFF_MULTI_QUEUE as libc::c_short) != 0 {
        let first_err = std::io::Error::last_os_error();
        ifr.ifr_flags &= !(libc::IFF_MULTI_QUEUE as libc::c_short);
        rc = unsafe { libc::ioctl(fd, super::TUNSETIFF, &ifr) };
        if rc < 0 {
            let fallback_err = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(format!(
                "dpdk: TUNSETIFF {name} failed with multiqueue ({first_err}); fallback failed: {fallback_err}"
            ));
        }
    } else if rc < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("dpdk: TUNSETIFF {name} failed: {err}"));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    set_file_nonblocking(&file)?;
    Ok(file)
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

pub(super) fn set_file_nonblocking(file: &File) -> Result<(), String> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "dpdk: get nonblocking flags failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if flags & libc::O_NONBLOCK != 0 {
        return Ok(());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "dpdk: set nonblocking failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

pub(super) fn select_mac(fallback: [u8; 6], candidate: Option<[u8; 6]>) -> [u8; 6] {
    if let Some(mac) = candidate {
        if mac != [0; 6] {
            return mac;
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::runtime_knobs::{with_runtime_knobs, RuntimeKnobs};

    #[test]
    fn tap_ifreq_flags_enables_multiqueue_by_default() {
        with_runtime_knobs(RuntimeKnobs::default(), || {
            let flags = tap_ifreq_flags();
            assert_ne!(flags & libc::IFF_MULTI_QUEUE as libc::c_short, 0);
        });
    }

    #[test]
    fn tap_ifreq_flags_honors_multiqueue_disable_override() {
        let mut knobs = RuntimeKnobs::default();
        knobs.dpdk.service_lane_multi_queue = false;
        with_runtime_knobs(knobs, || {
            let flags = tap_ifreq_flags();
            assert_eq!(flags & libc::IFF_MULTI_QUEUE as libc::c_short, 0);
        });
    }
}
