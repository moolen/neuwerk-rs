use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, RwLock};

use neuwerk::dataplane::policy::{
    DynamicIpSetV4, PolicySnapshot, SharedExactSourceGroupIndex, SharedPolicySnapshot,
};
use neuwerk::dataplane::{
    AuditEmitter, DataplaneConfigStore, DhcpRx, DhcpTx, DrainControl, OverlayConfig,
    SharedInterceptDemuxState, SnatMode, WiretapEmitter,
};
use neuwerk::metrics::Metrics;
use tokio::sync::{mpsc, oneshot, watch};

use crate::runtime::cli::DataPlaneMode;
use crate::runtime::dpdk::run::run_dataplane;

pub struct DataplaneRuntimeConfig {
    pub data_plane_iface: String,
    pub data_plane_mode: DataPlaneMode,
    pub idle_timeout_secs: u64,
    pub policy: Arc<RwLock<PolicySnapshot>>,
    pub policy_snapshot: SharedPolicySnapshot,
    pub exact_source_group_index: SharedExactSourceGroupIndex,
    pub policy_applied_generation: Arc<AtomicU64>,
    pub service_policy_applied_generation: Arc<AtomicU64>,
    pub dns_allowlist: DynamicIpSetV4,
    pub dns_target_ips: Vec<Ipv4Addr>,
    pub wiretap_emitter: Option<WiretapEmitter>,
    pub audit_emitter: Option<AuditEmitter>,
    pub internal_net: Ipv4Addr,
    pub internal_prefix: u8,
    pub public_ip: Ipv4Addr,
    pub snat_mode: SnatMode,
    pub overlay: OverlayConfig,
    pub data_port: u16,
    pub dataplane_config: DataplaneConfigStore,
    pub drain_control: Option<DrainControl>,
    pub dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    pub dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    pub mac_tx: Option<watch::Sender<[u8; 6]>>,
    pub shared_intercept_demux: Arc<SharedInterceptDemuxState>,
    pub metrics: Metrics,
}

pub fn spawn_dataplane_runtime_thread(
    cfg: DataplaneRuntimeConfig,
) -> Result<oneshot::Receiver<Result<(), String>>, String> {
    let (dataplane_tx, dataplane_rx) = oneshot::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("dataplane-runtime".to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run_dataplane(
                    cfg.data_plane_iface,
                    cfg.data_plane_mode,
                    cfg.idle_timeout_secs,
                    cfg.policy,
                    cfg.policy_snapshot,
                    cfg.exact_source_group_index,
                    cfg.policy_applied_generation,
                    cfg.service_policy_applied_generation,
                    cfg.dns_allowlist,
                    cfg.dns_target_ips,
                    cfg.wiretap_emitter,
                    cfg.audit_emitter,
                    cfg.internal_net,
                    cfg.internal_prefix,
                    cfg.public_ip,
                    cfg.snat_mode,
                    cfg.overlay,
                    cfg.data_port,
                    cfg.dataplane_config,
                    cfg.drain_control,
                    cfg.dhcp_tx,
                    cfg.dhcp_rx,
                    cfg.mac_tx,
                    cfg.shared_intercept_demux,
                    cfg.metrics,
                )
                .map_err(|err| format!("dataplane failed: {err}"))
            }))
            .unwrap_or_else(|_| Err("dataplane thread panicked".to_string()));
            let _ = dataplane_tx.send(result);
        })
        .map_err(|_| "dataplane: failed to spawn runtime thread".to_string())?;
    Ok(dataplane_rx)
}
