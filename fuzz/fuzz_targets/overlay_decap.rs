#![no_main]

use neuwerk::dataplane::overlay::{decap, encap, EncapMode, OverlayConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 6 {
        return;
    }

    let mode = match data[0] % 3 {
        0 => EncapMode::None,
        1 => EncapMode::Vxlan,
        _ => EncapMode::Geneve,
    };
    let udp_port = u16::from_be_bytes([data[1], data[2]]).max(1);
    let vni = u32::from_be_bytes([0, data[3], data[4], data[5]]);

    let cfg = OverlayConfig {
        mode,
        udp_port,
        udp_port_internal: None,
        udp_port_external: None,
        vni: Some(vni),
        vni_internal: None,
        vni_external: None,
        mtu: 1500,
    };

    let frame = &data[6..];
    if let Ok(parsed) = decap(frame, &cfg, None) {
        let _ = encap(&parsed.inner, &parsed.meta, &cfg, None);
    }
});
