use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use super::service_lane::parse_mac_addr;
use crate::support::runtime_knobs::{current_runtime_knobs, CloudProvider};

pub(super) static HEALTH_PROBE_LOGGED: AtomicBool = AtomicBool::new(false);
pub(super) static OVERLAY_PARSE_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_SAMPLE_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_TUNNEL_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_INTERNAL_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_ACTION_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static OVERLAY_ENCAP_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static ARP_LOGS: AtomicUsize = AtomicUsize::new(0);
pub(super) static HEALTH_PROBE_DEBUG_LOGS: AtomicUsize = AtomicUsize::new(0);

pub(super) fn overlay_swap_tunnels() -> bool {
    let enabled = current_runtime_knobs().dpdk.overlay_swap_tunnels;
    tracing::info!(enabled, "dpdk overlay tunnel swap configured");
    enabled
}

pub(super) fn overlay_force_tunnel_src_port() -> bool {
    let enabled = current_runtime_knobs().dpdk.overlay_force_tunnel_src_port;
    if enabled {
        tracing::info!("dpdk overlay tunnel source port forced to tunnel port");
    }
    enabled
}

pub(super) fn overlay_debug_enabled() -> bool {
    let enabled = current_runtime_knobs().dpdk.overlay_debug;
    if enabled {
        tracing::info!("dpdk overlay debug logging enabled");
    }
    enabled
}

pub(super) fn health_probe_debug_enabled() -> bool {
    let enabled = current_runtime_knobs().dpdk.health_probe_debug;
    if enabled {
        tracing::info!("dpdk health probe debug logging enabled");
    }
    enabled
}

pub(super) fn azure_gateway_mac() -> Option<[u8; 6]> {
    if current_runtime_knobs().cloud_provider != CloudProvider::Azure {
        return None;
    }
    None
}

pub(super) fn configured_gateway_mac() -> Option<[u8; 6]> {
    current_runtime_knobs()
        .dpdk
        .gateway_mac
        .as_deref()
        .and_then(|value| parse_mac_addr(value.trim()).ok())
        .or_else(azure_gateway_mac)
}

pub(super) fn configured_dhcp_server_ip() -> Option<Ipv4Addr> {
    current_runtime_knobs().dpdk.dhcp_server_ip
}

pub(super) fn configured_dhcp_server_mac() -> Option<[u8; 6]> {
    current_runtime_knobs()
        .dpdk
        .dhcp_server_mac
        .as_deref()
        .and_then(|value| parse_mac_addr(value.trim()).ok())
}
