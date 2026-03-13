use firewall::controlplane;
use firewall::controlplane::audit::AuditStore;
use firewall::controlplane::metrics::Metrics;
use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::wiretap::{DnsMap, WiretapHub};
use firewall::controlplane::PolicyStore;
use tokio::sync::oneshot;

fn runtime_worker_threads(env_name: &str, default_threads: usize) -> usize {
    std::env::var(env_name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|threads| *threads > 0)
        .unwrap_or(default_threads)
}

fn controlplane_worker_threads() -> usize {
    runtime_worker_threads("NEUWERK_CONTROLPLANE_WORKER_THREADS", 4)
}

fn http_runtime_worker_threads() -> usize {
    runtime_worker_threads("NEUWERK_HTTP_RUNTIME_WORKER_THREADS", 2)
}

pub struct HttpRuntimeThreadConfig {
    pub cfg: controlplane::http_api::HttpApiConfig,
    pub policy_store: PolicyStore,
    pub local_store: PolicyDiskStore,
    pub cluster: Option<controlplane::http_api::HttpApiCluster>,
    pub audit_store: Option<AuditStore>,
    pub wiretap_hub: Option<WiretapHub>,
    pub dns_map: Option<DnsMap>,
    pub readiness: Option<ReadinessState>,
    pub metrics: Metrics,
    pub shutdown: controlplane::http_api::HttpApiShutdown,
}

#[allow(clippy::type_complexity)]
pub fn spawn_dns_runtime_thread(
    mut cfg: controlplane::trafficd::TrafficdConfig,
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
                .worker_threads(controlplane_worker_threads())
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
) -> Result<oneshot::Receiver<Result<(), String>>, String> {
    let (http_tx, http_rx) = oneshot::channel::<Result<(), String>>();
    std::thread::Builder::new()
        .name("http-runtime".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(http_runtime_worker_threads())
                .build()
            {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = http_tx.send(Err(format!("http runtime build failed: {err}")));
                    return;
                }
            };
            let res = rt.block_on(async {
                controlplane::http_api::run_http_api_with_shutdown(
                    cfg.cfg,
                    cfg.policy_store,
                    cfg.local_store,
                    cfg.cluster,
                    cfg.audit_store,
                    cfg.wiretap_hub,
                    cfg.dns_map,
                    cfg.readiness,
                    cfg.metrics,
                    cfg.shutdown,
                )
                .await
                .map_err(|err| format!("http api failed: {err}"))
            });
            let _ = http_tx.send(res);
        })
        .map_err(|err| format!("http api: failed to spawn runtime thread: {err}"))?;
    Ok(http_rx)
}
