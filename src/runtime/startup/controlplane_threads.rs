use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use neuwerk::controlplane;
use neuwerk::controlplane::audit::AuditStore;
use neuwerk::controlplane::policy_repository::PolicyDiskStore;
use neuwerk::controlplane::policy_telemetry::PolicyTelemetryStore;
use neuwerk::controlplane::ready::ReadinessState;
use neuwerk::controlplane::threat_intel::store::ThreatStore;
use neuwerk::controlplane::wiretap::{DnsMap, WiretapHub};
use neuwerk::controlplane::PolicyStore;
use neuwerk::metrics::Metrics;
use tokio::sync::oneshot;

pub struct HttpRuntimeThreadConfig {
    pub cfg: controlplane::http_api::HttpApiConfig,
    pub policy_store: PolicyStore,
    pub local_store: PolicyDiskStore,
    pub cluster: Option<controlplane::http_api::HttpApiCluster>,
    pub audit_store: Option<AuditStore>,
    pub policy_telemetry_store: Option<PolicyTelemetryStore>,
    pub threat_store: Option<ThreatStore>,
    pub wiretap_hub: Option<WiretapHub>,
    pub dns_map: Option<DnsMap>,
    pub readiness: Option<ReadinessState>,
    pub metrics: Metrics,
    pub shutdown: controlplane::http_api::HttpApiShutdown,
    pub leader_local_policy_apply_count: Option<Arc<AtomicU64>>,
}

#[allow(clippy::type_complexity)]
pub fn spawn_dns_runtime_thread(
    mut cfg: controlplane::trafficd::TrafficdConfig,
    worker_threads: usize,
) -> Result<
    (
        oneshot::Receiver<Result<(), String>>,
        oneshot::Receiver<Result<(), String>>,
    ),
    String,
> {
    let (dns_tx, dns_rx) = oneshot::channel::<Result<(), String>>();
    let (startup_tx, startup_rx) = oneshot::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("dns-runtime".to_string())
        .spawn(move || {
            let mut startup_tx = Some(startup_tx);
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(worker_threads)
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let msg = format!("dns runtime build failed: {err}");
                    if let Some(tx) = startup_tx.take() {
                        let _ = tx.send(Err(msg.clone()));
                    }
                    let _ = dns_tx.send(Err(msg));
                    return;
                }
            };
            cfg.startup_status_tx = startup_tx.take();
            let res = rt.block_on(async { controlplane::trafficd::run(cfg).await });
            let _ = dns_tx.send(res);
        })
        .map_err(|err| format!("dns proxy: failed to spawn runtime thread: {err}"))?;
    Ok((dns_rx, startup_rx))
}

pub fn spawn_http_runtime_thread(
    cfg: HttpRuntimeThreadConfig,
    worker_threads: usize,
) -> Result<oneshot::Receiver<Result<(), String>>, String> {
    let (http_tx, http_rx) = oneshot::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("http-runtime".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(worker_threads)
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = http_tx.send(Err(format!("http runtime build failed: {err}")));
                    return;
                }
            };
            let res = rt.block_on(async {
                controlplane::http_api::run_http_api_with_shutdown_and_threat_store_with_local_apply_guard(
                    cfg.cfg,
                    cfg.policy_store,
                    cfg.local_store,
                    cfg.cluster,
                    cfg.audit_store,
                    cfg.policy_telemetry_store,
                    cfg.threat_store,
                    cfg.wiretap_hub,
                    cfg.dns_map,
                    cfg.readiness,
                    cfg.metrics,
                    cfg.shutdown,
                    cfg.leader_local_policy_apply_count,
                )
                .await
                .map_err(|err| format!("http api failed: {err}"))
            });
            let _ = http_tx.send(res);
        })
        .map_err(|err| format!("http api: failed to spawn runtime thread: {err}"))?;
    Ok(http_rx)
}
