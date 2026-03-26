use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::time::{Duration, Instant};

use crate::dataplane::engine::{Action, EngineState};
use crate::dataplane::overlay::{self, EncapMode};
use crate::dataplane::packet::Packet;
use crate::support::runtime_knobs::current_runtime_knobs;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;
const SOFT_HOUSEKEEPING_INTERVAL_PACKETS: u64 = 64;
const SOFT_HOUSEKEEPING_INTERVAL: Duration = Duration::from_micros(250);

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
    overlay_swap_tunnels: bool,
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
        let overlay_swap_tunnels = current_runtime_knobs().dpdk.overlay_swap_tunnels;
        Ok(Self {
            iface,
            mode,
            file,
            overlay_swap_tunnels,
        })
    }

    pub fn run(&mut self, state: &mut EngineState) -> Result<(), String> {
        tracing::info!(
            mode = ?self.mode,
            data_plane_interface = %self.iface,
            "dataplane started (software)"
        );
        let mut buf = vec![0u8; 65535];
        let mut packets_since_housekeeping = 0u64;
        let mut next_housekeeping_at = Instant::now() + SOFT_HOUSEKEEPING_INTERVAL;
        loop {
            let n = self
                .file
                .read(&mut buf)
                .map_err(|err| format!("dataplane read failed: {err}"))?;
            if n == 0 {
                continue;
            }
            packets_since_housekeeping = packets_since_housekeeping.saturating_add(1);

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
                let now = Instant::now();
                if packets_since_housekeeping >= SOFT_HOUSEKEEPING_INTERVAL_PACKETS
                    || now >= next_housekeeping_at
                {
                    state.run_housekeeping();
                    packets_since_housekeeping = 0;
                    next_housekeeping_at = now + SOFT_HOUSEKEEPING_INTERVAL;
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
                        self.overlay_swap_tunnels,
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
            let now = Instant::now();
            if packets_since_housekeeping >= SOFT_HOUSEKEEPING_INTERVAL_PACKETS
                || now >= next_housekeeping_at
            {
                state.run_housekeeping();
                packets_since_housekeeping = 0;
                next_housekeeping_at = now + SOFT_HOUSEKEEPING_INTERVAL;
            }
        }
    }
}

fn open_tun_tap(name: &str, mode: SoftMode) -> Result<File, String> {
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
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
