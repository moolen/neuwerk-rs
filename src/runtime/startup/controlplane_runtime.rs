use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use firewall::controlplane;
use firewall::controlplane::audit::{AuditStore, DEFAULT_AUDIT_STORE_MAX_BYTES};
use firewall::controlplane::cluster::ClusterRuntime;
use firewall::controlplane::integrations::IntegrationStore;
use firewall::controlplane::metrics::Metrics;
use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::wiretap::{DnsMap, WiretapHub};
use firewall::controlplane::PolicyStore;
use firewall::dataplane::{
    AuditEmitter, SharedInterceptDemuxState, WiretapEmitter, DEFAULT_AUDIT_REPORT_INTERVAL_SECS,
    DEFAULT_WIRETAP_REPORT_INTERVAL_SECS,
};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::runtime::bootstrap::policy_state::local_controlplane_data_root;
use crate::runtime::cli::CliConfig;
use crate::runtime::startup::bridges::spawn_event_bridges;
use crate::runtime::startup::controlplane_threads::{
    spawn_dns_runtime_thread, spawn_http_runtime_thread, HttpRuntimeThreadConfig,
};

const KUBERNETES_RECONCILE_INTERVAL_SECS: u64 = 5;
const KUBERNETES_STALE_GRACE_SECS: u64 = 300;

pub struct ControlplaneRuntimeHandles {
    pub dns_task: oneshot::Receiver<Result<(), String>>,
    pub http_task: oneshot::Receiver<Result<(), String>>,
    pub http_shutdown: controlplane::http_api::HttpApiShutdown,
    pub wiretap_emitter: WiretapEmitter,
    pub audit_emitter: AuditEmitter,
    pub shared_intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
}

fn env_u64_with_default(name: &str, default: u64) -> u64 {
    match env::var(name) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(0) => {
                warn!(env_var = %name, value = 0, default, "invalid zero value; using default");
                default
            }
            Ok(value) => value,
            Err(_) => {
                warn!(env_var = %name, raw = %raw, default, "invalid numeric value; using default");
                default
            }
        },
        Err(_) => default,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn start_controlplane_runtime(
    cfg: &CliConfig,
    management_ip: Ipv4Addr,
    http_bind: SocketAddr,
    http_advertise: SocketAddr,
    metrics_bind: SocketAddr,
    policy_store: PolicyStore,
    local_policy_store: PolicyDiskStore,
    local_integrations_dir: PathBuf,
    cluster_runtime: Option<&ClusterRuntime>,
    readiness: ReadinessState,
    metrics: Metrics,
    dpdk_enabled: bool,
    node_id: String,
    wiretap_hub: WiretapHub,
) -> Result<ControlplaneRuntimeHandles, String> {
    let dns_allowlist = policy_store.dns_allowlist();
    let dns_policy = policy_store.dns_policy();
    let dns_allowlist_for_dns = dns_allowlist.clone();
    let dns_allowlist_for_gc = dns_allowlist.clone();
    let dns_upstreams = cfg.dns_upstreams.clone();
    let dns_listen = SocketAddr::new(IpAddr::V4(management_ip), 53);
    let service_lane_iface = "svc0".to_string();
    let service_lane_ip = Ipv4Addr::new(169, 254, 255, 1);
    let service_lane_prefix = 30u8;
    let service_policy_snapshot = policy_store.snapshot();
    let service_policy_applied_generation = policy_store.service_policy_applied_tracker();
    let dns_map = DnsMap::new();
    let dns_map_for_dns = dns_map.clone();
    let dns_map_for_gc = dns_map.clone();
    let dns_map_for_http = dns_map.clone();
    let audit_store = AuditStore::new(
        local_controlplane_data_root().join("audit-store"),
        DEFAULT_AUDIT_STORE_MAX_BYTES,
    );
    let (wiretap_tx, wiretap_rx) = mpsc::channel(1024);
    let (audit_tx, audit_rx) = mpsc::channel(4096);
    let wiretap_emitter = WiretapEmitter::new(wiretap_tx, DEFAULT_WIRETAP_REPORT_INTERVAL_SECS);
    let audit_emitter = AuditEmitter::new(audit_tx, DEFAULT_AUDIT_REPORT_INTERVAL_SECS);

    spawn_event_bridges(
        wiretap_rx,
        audit_rx,
        wiretap_hub.clone(),
        dns_map.clone(),
        audit_store.clone(),
        policy_store.clone(),
        node_id.clone(),
    )?;

    if let Some(runtime) = cluster_runtime {
        let store = runtime.store.clone();
        let raft = runtime.raft.clone();
        let policy_store = policy_store.clone();
        let local_policy_store = local_policy_store.clone();
        let readiness_for_replication = readiness.clone();
        tokio::spawn(async move {
            controlplane::policy_replication::run_policy_replication(
                store,
                raft,
                policy_store,
                local_policy_store,
                Some(readiness_for_replication),
                Duration::from_secs(1),
            )
            .await;
        });
    }

    let kubernetes_integration_store = match cluster_runtime {
        Some(runtime) => IntegrationStore::cluster(
            runtime.raft.clone(),
            runtime.store.clone(),
            cfg.cluster.token_path.clone(),
        ),
        None => IntegrationStore::local(local_integrations_dir.clone()),
    };
    let kubernetes_reconcile_interval_secs = env_u64_with_default(
        "NEUWERK_KUBERNETES_RECONCILE_INTERVAL_SECS",
        KUBERNETES_RECONCILE_INTERVAL_SECS,
    );
    let kubernetes_stale_grace_secs = env_u64_with_default(
        "NEUWERK_KUBERNETES_STALE_GRACE_SECS",
        KUBERNETES_STALE_GRACE_SECS,
    );
    {
        let policy_store = policy_store.clone();
        let integration_store = kubernetes_integration_store.clone();
        tokio::spawn(async move {
            controlplane::kubernetes::run_kubernetes_resolver(
                policy_store,
                integration_store,
                Duration::from_secs(kubernetes_stale_grace_secs),
                Duration::from_secs(kubernetes_reconcile_interval_secs),
            )
            .await;
        });
    }

    let tls_intercept_ca_present = controlplane::intercept_tls::has_intercept_ca_material(
        &cfg.http_tls_dir,
        cluster_runtime.map(|runtime| &runtime.store),
    )?;
    let tls_intercept_ca_ready = Arc::new(AtomicBool::new(tls_intercept_ca_present));
    let tls_intercept_ca_generation = Arc::new(AtomicU64::new(0));
    let tls_intercept_ca_source = if let Some(runtime) = cluster_runtime {
        controlplane::intercept_tls::InterceptCaSource::Cluster {
            store: runtime.store.clone(),
            token_path: cfg.cluster.token_path.clone(),
        }
    } else {
        controlplane::intercept_tls::InterceptCaSource::Local {
            tls_dir: cfg.http_tls_dir.clone(),
        }
    };
    let tls_intercept_listen_port = 15443u16;
    let shared_intercept_demux = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));

    let dns_cfg = controlplane::trafficd::TrafficdConfig {
        dns_bind: dns_listen,
        dns_upstreams,
        dns_allowlist: dns_allowlist_for_dns,
        dns_policy,
        dns_map: dns_map_for_dns,
        metrics: metrics.clone(),
        policy_snapshot: service_policy_snapshot,
        service_policy_applied_generation: service_policy_applied_generation.clone(),
        tls_intercept_ca_ready: tls_intercept_ca_ready.clone(),
        tls_intercept_ca_generation: tls_intercept_ca_generation.clone(),
        tls_intercept_ca_source: tls_intercept_ca_source.clone(),
        tls_intercept_listen_port,
        enable_kernel_intercept_steering: !dpdk_enabled,
        service_lane_iface: service_lane_iface.clone(),
        service_lane_ip,
        service_lane_prefix,
        intercept_demux: shared_intercept_demux.clone(),
        policy_store: policy_store.clone(),
        audit_store: Some(audit_store.clone()),
        node_id: node_id.clone(),
        startup_status_tx: None,
    };
    let (dns_task, dns_startup_rx) = spawn_dns_runtime_thread(dns_cfg)?;
    match tokio::time::timeout(Duration::from_secs(2), dns_startup_rx).await {
        Ok(Ok(Ok(()))) => {
            readiness.set_dns_ready(true);
            readiness.set_service_plane_ready(true);
        }
        Ok(Ok(Err(err))) => return Err(format!("dns proxy: startup failed: {err}")),
        Ok(Err(_)) => return Err("dns proxy: startup channel dropped".to_string()),
        Err(_) => return Err("dns proxy: startup timed out after 2s".to_string()),
    }

    let dns_allowlist_idle_secs = cfg.dns_allowlist_idle_secs;
    let dns_allowlist_gc_interval_secs = cfg.dns_allowlist_gc_interval_secs;
    tokio::spawn(async move {
        controlplane::allowlist_gc::run_allowlist_gc(
            dns_allowlist_for_gc,
            dns_allowlist_idle_secs,
            dns_allowlist_gc_interval_secs,
            Some(dns_map_for_gc),
        )
        .await;
    });

    let http_cluster = cluster_runtime.map(|runtime| controlplane::http_api::HttpApiCluster {
        raft: runtime.raft.clone(),
        store: runtime.store.clone(),
    });
    let http_cfg = controlplane::http_api::HttpApiConfig {
        bind_addr: http_bind,
        advertise_addr: http_advertise,
        metrics_bind,
        tls_dir: cfg.http_tls_dir.clone(),
        cert_path: cfg.http_cert_path.clone(),
        key_path: cfg.http_key_path.clone(),
        ca_path: cfg.http_ca_path.clone(),
        san_entries: cfg.http_tls_san.clone(),
        management_ip: IpAddr::V4(management_ip),
        token_path: cfg.cluster.token_path.clone(),
        external_url: cfg.http_external_url.clone(),
        cluster_tls_dir: if cfg.cluster.enabled {
            Some(cfg.cluster.data_dir.join("tls"))
        } else {
            None
        },
        tls_intercept_ca_ready: Some(tls_intercept_ca_ready),
        tls_intercept_ca_generation: Some(tls_intercept_ca_generation),
    };
    let http_shutdown = controlplane::http_api::HttpApiShutdown::new();
    let http_task = spawn_http_runtime_thread(HttpRuntimeThreadConfig {
        cfg: http_cfg,
        policy_store,
        local_store: local_policy_store,
        cluster: http_cluster,
        audit_store: Some(audit_store),
        wiretap_hub: Some(wiretap_hub),
        dns_map: Some(dns_map_for_http),
        readiness: Some(readiness),
        metrics,
        shutdown: http_shutdown.clone(),
    })?;

    Ok(ControlplaneRuntimeHandles {
        dns_task,
        http_task,
        http_shutdown,
        wiretap_emitter,
        audit_emitter,
        shared_intercept_demux,
    })
}
