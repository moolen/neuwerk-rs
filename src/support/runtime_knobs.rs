use std::net::Ipv4Addr;
use std::sync::{OnceLock, RwLock};

#[cfg(test)]
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CloudProvider {
    #[default]
    None,
    Azure,
    Aws,
    Gcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpdkIovaMode {
    Va,
    Pa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpdkRuntimeKnobs {
    pub workers: Option<usize>,
    pub core_ids: Vec<usize>,
    pub disable_in_memory: bool,
    pub iova_mode: Option<DpdkIovaMode>,
    pub force_netvsc: bool,
    pub gcp_auto_probe: bool,
    pub driver_preload: Vec<String>,
    pub skip_bus_pci_preload: bool,
    pub prefer_pci: bool,
    pub queue_override: Option<u16>,
    pub port_mtu: Option<u16>,
    pub mbuf_data_room: Option<u16>,
    pub mbuf_pool_size: Option<u32>,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub tx_checksum_offload: Option<bool>,
    pub allow_retaless_multi_queue: bool,
    pub service_lane_interface: String,
    pub service_lane_intercept_service_ip: Ipv4Addr,
    pub service_lane_intercept_service_port: u16,
    pub service_lane_multi_queue: bool,
    pub intercept_demux_gc_interval_ms: u64,
    pub intercept_demux_max_entries: usize,
    pub intercept_demux_shard_count: usize,
    pub host_frame_queue_max: usize,
    pub pending_arp_queue_max: usize,
    pub overlay_swap_tunnels: bool,
    pub overlay_force_tunnel_src_port: bool,
    pub overlay_debug: bool,
    pub health_probe_debug: bool,
    pub gateway_mac: Option<String>,
    pub dhcp_server_ip: Option<Ipv4Addr>,
    pub dhcp_server_mac: Option<String>,
}

impl Default for DpdkRuntimeKnobs {
    fn default() -> Self {
        Self {
            workers: None,
            core_ids: Vec::new(),
            disable_in_memory: false,
            iova_mode: None,
            force_netvsc: false,
            gcp_auto_probe: false,
            driver_preload: Vec::new(),
            skip_bus_pci_preload: false,
            prefer_pci: false,
            queue_override: None,
            port_mtu: None,
            mbuf_data_room: None,
            mbuf_pool_size: None,
            rx_ring_size: 1024,
            tx_ring_size: 1024,
            tx_checksum_offload: None,
            allow_retaless_multi_queue: false,
            service_lane_interface: "svc0".to_string(),
            service_lane_intercept_service_ip: Ipv4Addr::new(169, 254, 255, 1),
            service_lane_intercept_service_port: 15443,
            service_lane_multi_queue: true,
            intercept_demux_gc_interval_ms: 1_000,
            intercept_demux_max_entries: 65_536,
            intercept_demux_shard_count: 64,
            host_frame_queue_max: 8_192,
            pending_arp_queue_max: 4_096,
            overlay_swap_tunnels: false,
            overlay_force_tunnel_src_port: false,
            overlay_debug: false,
            health_probe_debug: false,
            gateway_mac: None,
            dhcp_server_ip: None,
            dhcp_server_mac: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RuntimeKnobs {
    pub cloud_provider: CloudProvider,
    pub dpdk: DpdkRuntimeKnobs,
}

fn state() -> &'static RwLock<RuntimeKnobs> {
    static STATE: OnceLock<RwLock<RuntimeKnobs>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(RuntimeKnobs::default()))
}

pub fn current_runtime_knobs() -> RuntimeKnobs {
    state()
        .read()
        .expect("runtime knob lock poisoned")
        .clone()
}

pub fn install_runtime_knobs(knobs: RuntimeKnobs) {
    *state().write().expect("runtime knob lock poisoned") = knobs;
}

#[cfg(test)]
pub fn with_runtime_knobs<T>(knobs: RuntimeKnobs, f: impl FnOnce() -> T) -> T {
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    let _guard = TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let old = current_runtime_knobs();
    install_runtime_knobs(knobs);
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    install_runtime_knobs(old);
    match out {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}
