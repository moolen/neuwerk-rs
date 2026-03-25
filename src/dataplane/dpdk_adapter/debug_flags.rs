use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::OnceLock;

use super::service_lane::parse_mac_addr;

pub(super) static HEALTH_PROBE_LOGGED: AtomicBool = AtomicBool::new(false);
pub(super) static OVERLAY_PARSE_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_SAMPLE_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_TUNNEL_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_INTERNAL_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_ACTION_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_ENCAP_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static ARP_LOGS: AtomicUsize = AtomicUsize::new(0);
static OVERLAY_SWAP_TUNNELS: OnceLock<bool> = OnceLock::new();
static OVERLAY_TUNNEL_SRC_PORT: OnceLock<bool> = OnceLock::new();
static OVERLAY_DEBUG_ENABLED: OnceLock<bool> = OnceLock::new();
static HEALTH_PROBE_DEBUG_ENABLED: OnceLock<bool> = OnceLock::new();
pub(super) static HEALTH_PROBE_DEBUG_LOGS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn overlay_swap_tunnels() -> bool {
    *OVERLAY_SWAP_TUNNELS.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_GWLB_SWAP_TUNNELS")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        tracing::info!(enabled, "dpdk overlay tunnel swap configured");
        enabled
    })
}

pub(super) fn overlay_force_tunnel_src_port() -> bool {
    *OVERLAY_TUNNEL_SRC_PORT.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_GWLB_TUNNEL_SRC_PORT")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if enabled {
            tracing::info!("dpdk overlay tunnel source port forced to tunnel port");
        }
        enabled
    })
}

pub(super) fn overlay_debug_enabled() -> bool {
    *OVERLAY_DEBUG_ENABLED.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_DPDK_OVERLAY_DEBUG")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if enabled {
            tracing::info!("dpdk overlay debug logging enabled");
        }
        enabled
    })
}

pub(super) fn health_probe_debug_enabled() -> bool {
    *HEALTH_PROBE_DEBUG_ENABLED.get_or_init(|| {
        let enabled = std::env::var("NEUWERK_DPDK_HEALTH_PROBE_DEBUG")
            .map(|val| matches!(val.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        if enabled {
            tracing::info!("dpdk health probe debug logging enabled");
        }
        enabled
    })
}

pub(super) fn azure_gateway_mac() -> Option<[u8; 6]> {
    let provider = std::env::var("NEUWERK_CLOUD_PROVIDER").ok()?;
    if !provider.eq_ignore_ascii_case("azure") {
        return None;
    }
    let mac = match std::env::var("NEUWERK_AZURE_GATEWAY_MAC") {
        Ok(value) => value,
        Err(_) => return None,
    };
    parse_mac_addr(&mac).ok()
}

pub(super) fn configured_gateway_mac() -> Option<[u8; 6]> {
    std::env::var("NEUWERK_DPDK_GATEWAY_MAC")
        .ok()
        .and_then(|value| parse_mac_addr(value.trim()).ok())
        .or_else(azure_gateway_mac)
}

pub(super) fn configured_dhcp_server_ip() -> Option<Ipv4Addr> {
    std::env::var("NEUWERK_DPDK_DHCP_SERVER_IP")
        .ok()
        .and_then(|value| value.trim().parse::<Ipv4Addr>().ok())
}

pub(super) fn configured_dhcp_server_mac() -> Option<[u8; 6]> {
    std::env::var("NEUWERK_DPDK_DHCP_SERVER_MAC")
        .ok()
        .and_then(|value| parse_mac_addr(value.trim()).ok())
}
