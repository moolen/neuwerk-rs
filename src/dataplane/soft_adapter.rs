use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::sync::OnceLock;

use crate::dataplane::engine::{Action, EngineState};
use crate::dataplane::overlay::{self, EncapMode};
use crate::dataplane::packet::Packet;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
static OVERLAY_SWAP_TUNNELS: OnceLock<bool> = OnceLock::new();

#[repr(C)]
struct IfReq {
    ifr_name: [libc::c_char; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftMode {
    Tun,
    Tap,
}

impl SoftMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "tun" | "TUN" => Ok(SoftMode::Tun),
            "tap" | "TAP" => Ok(SoftMode::Tap),
            _ => Err(format!(
                "unknown data-plane mode: {value} (expected tun or tap)"
            )),
        }
    }
}

#[derive(Debug)]
pub struct SoftAdapter {
    iface: String,
    mode: SoftMode,
    file: File,
}

impl SoftAdapter {
    pub fn new(iface: String, mode: SoftMode) -> Result<Self, String> {
        let iface = iface.trim().to_string();
        if iface.is_empty() {
            return Err("data-plane-interface cannot be empty".to_string());
        }
        if iface.len() >= libc::IFNAMSIZ {
            return Err(format!(
                "data-plane-interface name too long (max {} chars)",
                libc::IFNAMSIZ - 1
            ));
        }
        let file = open_tun_tap(&iface, mode)?;
        Ok(Self { iface, mode, file })
    }

    pub fn run(&mut self, state: &mut EngineState) -> Result<(), String> {
        println!(
            "dataplane started (software), mode={:?}, data-plane-interface={}",
            self.mode, self.iface
        );
        let mut buf = vec![0u8; 65535];
        loop {
            let n = self
                .file
                .read(&mut buf)
                .map_err(|err| format!("dataplane read failed: {err}"))?;
            if n == 0 {
                continue;
            }

            if state.overlay.mode == EncapMode::None {
                let mut pkt = Packet::from_bytes(&buf[..n]);
                match crate::dataplane::engine::handle_packet(&mut pkt, state) {
                    Action::Drop => {}
                    Action::Forward { .. } | Action::ToHost => {
                        self.file
                            .write_all(pkt.buffer())
                            .map_err(|err| format!("dataplane write failed: {err}"))?;
                    }
                }
                continue;
            }

            let overlay_pkt = match overlay::decap(&buf[..n], &state.overlay, state.metrics()) {
                Ok(pkt) => pkt,
                Err(_) => continue,
            };
            let mut inner = overlay_pkt.inner;
            overlay::maybe_clamp_mss(&mut inner, &state.overlay, &overlay_pkt.meta);
            match crate::dataplane::engine::handle_packet(&mut inner, state) {
                Action::Drop => {}
                Action::Forward { .. } | Action::ToHost => {
                    let out_meta = overlay::reply_meta(
                        &overlay_pkt.meta,
                        &state.overlay,
                        overlay_swap_tunnels(),
                    );
                    let out =
                        match overlay::encap(&inner, &out_meta, &state.overlay, state.metrics()) {
                            Ok(frame) => frame,
                            Err(_) => continue,
                        };
                    self.file
                        .write_all(&out)
                        .map_err(|err| format!("dataplane write failed: {err}"))?;
                }
            }
        }
    }
}

fn overlay_swap_tunnels() -> bool {
    *OVERLAY_SWAP_TUNNELS.get_or_init(|| {
        std::env::var("NEUWERK_GWLB_SWAP_TUNNELS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

fn open_tun_tap(name: &str, mode: SoftMode) -> Result<File, String> {
    let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR) };
    if fd < 0 {
        return Err(format!(
            "failed to open /dev/net/tun: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ifr = IfReq {
        ifr_name: [0; libc::IFNAMSIZ],
        ifr_flags: match mode {
            SoftMode::Tun => IFF_TUN,
            SoftMode::Tap => IFF_TAP,
        } | IFF_NO_PI,
    };

    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes().iter()) {
        *dst = *src as libc::c_char;
    }

    let res = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
    if res < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(format!("TUNSETIFF failed for {name}: {err}"));
    }

    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
}
