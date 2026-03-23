use std::env;
#[cfg(test)]
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use neuwerk::controlplane;
use neuwerk::controlplane::audit::{AuditStore, DEFAULT_AUDIT_STORE_MAX_BYTES};
use neuwerk::controlplane::cluster::ClusterRuntime;
use neuwerk::controlplane::integrations::IntegrationStore;
use neuwerk::controlplane::policy_repository::PolicyDiskStore;
use neuwerk::controlplane::ready::ReadinessState;
use neuwerk::controlplane::threat_intel::feeds::ThreatSnapshot;
#[cfg(test)]
use neuwerk::controlplane::threat_intel::manager::local_snapshot_path;
use neuwerk::controlplane::threat_intel::manager::{
    load_effective_snapshot, load_local_runtime_state, persist_local_runtime_state,
    spawn_refresh_loop, ThreatManagerCluster, ThreatManagerConfig, ThreatRefreshOutcome,
};
use neuwerk::controlplane::threat_intel::runtime::{
    backfill_audit_findings, ThreatRuntimeConfig, ThreatRuntimeHandle, ThreatRuntimeSlot,
};
use neuwerk::controlplane::threat_intel::settings::{load_settings, ThreatIntelSettings};
use neuwerk::controlplane::threat_intel::silences::{load_silences, ThreatSilenceList};
use neuwerk::controlplane::threat_intel::store::ThreatStore;
use neuwerk::controlplane::threat_intel::types::ThreatSeverity;
use neuwerk::controlplane::wiretap::{DnsMap, WiretapHub};
use neuwerk::controlplane::PolicyStore;
use neuwerk::dataplane::{
    AuditEmitter, SharedInterceptDemuxState, WiretapEmitter, DEFAULT_AUDIT_REPORT_INTERVAL_SECS,
    DEFAULT_WIRETAP_REPORT_INTERVAL_SECS,
};
use neuwerk::metrics::Metrics;
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
const THREAT_RUNTIME_RELOAD_INTERVAL_SECS: u64 = 5;

pub struct ControlplaneRuntimeHandles {
    pub dns_task: oneshot::Receiver<Result<(), String>>,
    pub http_task: oneshot::Receiver<Result<(), String>>,
    pub http_shutdown: controlplane::http_api::HttpApiShutdown,
    pub wiretap_emitter: WiretapEmitter,
    pub audit_emitter: AuditEmitter,
    pub shared_intercept_demux: Arc<SharedInterceptDemuxState>,
}

#[cfg(test)]
fn threat_snapshot_path(local_data_root: &Path) -> PathBuf {
    local_snapshot_path(local_data_root)
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

#[cfg(test)]
fn load_startup_threat_snapshot(local_data_root: &Path) -> Result<Option<ThreatSnapshot>, String> {
    let path = local_snapshot_path(local_data_root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read threat snapshot: {err}")),
    };
    let snapshot =
        serde_json::from_slice(&bytes).map_err(|err| format!("parse threat snapshot: {err}"))?;
    Ok(Some(snapshot))
}

#[cfg(test)]
fn load_runtime_threat_snapshot(local_data_root: &Path) -> Option<ThreatSnapshot> {
    match load_startup_threat_snapshot(local_data_root) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            warn!(error = %err, "threat intel snapshot load failed");
            None
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn maybe_backfill_snapshot(
    local_data_root: &Path,
    settings: &ThreatIntelSettings,
    snapshot: &ThreatSnapshot,
    silences: &ThreatSilenceList,
    audit_store: &AuditStore,
    threat_store: &ThreatStore,
    metrics: &Metrics,
) -> Result<(), String> {
    if !settings.enabled {
        return Ok(());
    }
    let mut state = load_local_runtime_state(local_data_root)?.unwrap_or_default();
    if state.last_backfill_snapshot_version == Some(snapshot.version) {
        return Ok(());
    }

    state.last_backfill_started_at = Some(unix_now());
    persist_local_runtime_state(local_data_root, &state)?;

    let started = Instant::now();
    match backfill_audit_findings(snapshot, silences, audit_store, threat_store, metrics) {
        Ok(_) => {
            state.last_backfill_snapshot_version = Some(snapshot.version);
            state.last_backfill_completed_at = Some(unix_now());
            state.last_backfill_outcome = Some(ThreatRefreshOutcome::Success);
            persist_local_runtime_state(local_data_root, &state)?;
            metrics.inc_threat_backfill_run("success");
            metrics.observe_threat_backfill_duration(started.elapsed());
            Ok(())
        }
        Err(err) => {
            state.last_backfill_completed_at = Some(unix_now());
            state.last_backfill_outcome = Some(ThreatRefreshOutcome::Failed);
            persist_local_runtime_state(local_data_root, &state)?;
            metrics.inc_threat_backfill_run("failed");
            metrics.observe_threat_backfill_duration(started.elapsed());
            Err(err)
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ThreatRuntimeState {
    Disabled {
        settings: ThreatIntelSettings,
        silences: ThreatSilenceList,
    },
    AwaitingSnapshot {
        settings: ThreatIntelSettings,
        silences: ThreatSilenceList,
    },
    Enabled {
        settings: ThreatIntelSettings,
        snapshot: ThreatSnapshot,
        silences: ThreatSilenceList,
    },
}

fn runtime_state_from_inputs(
    settings: &ThreatIntelSettings,
    snapshot: Option<ThreatSnapshot>,
    silences: &ThreatSilenceList,
) -> ThreatRuntimeState {
    if !settings.enabled {
        return ThreatRuntimeState::Disabled {
            settings: settings.clone(),
            silences: silences.clone(),
        };
    }
    match snapshot {
        Some(snapshot) => ThreatRuntimeState::Enabled {
            settings: settings.clone(),
            snapshot,
            silences: silences.clone(),
        },
        None => ThreatRuntimeState::AwaitingSnapshot {
            settings: settings.clone(),
            silences: silences.clone(),
        },
    }
}

fn apply_threat_runtime_state(
    slot: &ThreatRuntimeSlot,
    store: &ThreatStore,
    metrics: &Metrics,
    state: &ThreatRuntimeState,
) -> Result<(), String> {
    match state {
        ThreatRuntimeState::Disabled { settings, .. } => {
            store.reconcile_alertable_threshold(settings.alert_threshold)?;
            slot.replace(None)?;
            refresh_threat_active_metrics(metrics, store)?;
            metrics.set_threat_cluster_snapshot_version(0);
        }
        ThreatRuntimeState::AwaitingSnapshot { settings, .. } => {
            store.reconcile_alertable_threshold(settings.alert_threshold)?;
            slot.replace(None)?;
            refresh_threat_active_metrics(metrics, store)?;
            metrics.set_threat_cluster_snapshot_version(0);
        }
        ThreatRuntimeState::Enabled {
            settings,
            snapshot,
            silences,
        } => {
            store.reconcile_alertable_threshold(settings.alert_threshold)?;
            let handle = ThreatRuntimeHandle::spawn(ThreatRuntimeConfig {
                snapshot: snapshot.clone(),
                silences: silences.clone(),
                store: store.clone(),
                metrics: metrics.clone(),
                queue_capacity: 4096,
            });
            slot.replace(Some(handle))?;
        }
    }
    Ok(())
}

fn refresh_threat_active_metrics(metrics: &Metrics, store: &ThreatStore) -> Result<(), String> {
    let counts = store.active_counts_by_severity()?;
    for severity in [
        ThreatSeverity::Low,
        ThreatSeverity::Medium,
        ThreatSeverity::High,
        ThreatSeverity::Critical,
    ] {
        metrics.set_threat_findings_active(
            match severity {
                ThreatSeverity::Low => "low",
                ThreatSeverity::Medium => "medium",
                ThreatSeverity::High => "high",
                ThreatSeverity::Critical => "critical",
            },
            counts.get(&severity).copied().unwrap_or(0),
        );
    }
    Ok(())
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
    let dns_policy = policy_store.dns_policy();
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
    let local_data_root = local_controlplane_data_root();
    let audit_store = AuditStore::new(
        local_data_root.join("audit-store"),
        DEFAULT_AUDIT_STORE_MAX_BYTES,
    );
    let threat_store = ThreatStore::new(local_data_root.join("threat-store"), 1024 * 1024)?;
    let (threat_settings, _) = load_settings(
        cluster_runtime.map(|runtime| &runtime.store),
        &local_data_root,
    )
    .map_err(|err| format!("load threat intel settings: {err}"))?;
    let (threat_silences, _) = load_silences(
        cluster_runtime.map(|runtime| &runtime.store),
        &local_data_root,
    )
    .map_err(|err| format!("load threat silences: {err}"))?;
    let threat_runtime = ThreatRuntimeSlot::new(None, Some(metrics.clone()));
    let threat_cluster_store = cluster_runtime.map(|runtime| runtime.store.clone());
    let initial_snapshot = load_effective_snapshot(threat_cluster_store.as_ref(), &local_data_root)
        .unwrap_or_else(|err| {
            warn!(error = %err, "threat intel snapshot load failed");
            None
        });
    let initial_state =
        runtime_state_from_inputs(&threat_settings, initial_snapshot, &threat_silences);
    if matches!(initial_state, ThreatRuntimeState::AwaitingSnapshot { .. }) {
        warn!("threat intel enabled but no local snapshot is available yet");
    }
    apply_threat_runtime_state(&threat_runtime, &threat_store, &metrics, &initial_state)?;
    let threat_manager_cluster = cluster_runtime.map(|runtime| ThreatManagerCluster {
        raft: runtime.raft.clone(),
        store: runtime.store.clone(),
    });
    spawn_refresh_loop(ThreatManagerConfig::new(
        local_data_root.clone(),
        threat_manager_cluster,
        metrics.clone(),
    ));
    if let ThreatRuntimeState::Enabled {
        snapshot, silences, ..
    } = &initial_state
    {
        if let Err(err) = maybe_backfill_snapshot(
            &local_data_root,
            &threat_settings,
            snapshot,
            silences,
            &audit_store,
            &threat_store,
            &metrics,
        ) {
            warn!(error = %err, "initial threat backfill failed");
        }
    }
    {
        let threat_runtime = threat_runtime.clone();
        let threat_store = threat_store.clone();
        let audit_store = audit_store.clone();
        let metrics = metrics.clone();
        let local_data_root = local_data_root.clone();
        tokio::spawn(async move {
            let mut applied_state = initial_state;
            let mut interval =
                tokio::time::interval(Duration::from_secs(THREAT_RUNTIME_RELOAD_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let settings = match load_settings(threat_cluster_store.as_ref(), &local_data_root)
                {
                    Ok((settings, _)) => settings,
                    Err(err) => {
                        warn!(error = %err, "threat intel settings reload failed");
                        continue;
                    }
                };
                let silences = match load_silences(threat_cluster_store.as_ref(), &local_data_root)
                {
                    Ok((silences, _)) => silences,
                    Err(err) => {
                        warn!(error = %err, "threat intel silences reload failed");
                        continue;
                    }
                };
                let snapshot = match load_effective_snapshot(
                    threat_cluster_store.as_ref(),
                    &local_data_root,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        warn!(error = %err, "threat intel snapshot reload failed");
                        None
                    }
                };
                let state = runtime_state_from_inputs(&settings, snapshot, &silences);
                if applied_state != state {
                    if matches!(state, ThreatRuntimeState::AwaitingSnapshot { .. }) {
                        warn!("threat intel enabled but no local snapshot is available yet");
                    }
                    if let Err(err) =
                        apply_threat_runtime_state(&threat_runtime, &threat_store, &metrics, &state)
                    {
                        warn!(error = %err, "threat runtime reload failed");
                        continue;
                    }
                    applied_state = state.clone();
                }
                if let ThreatRuntimeState::Enabled {
                    snapshot, silences, ..
                } = &state
                {
                    if let Err(err) = maybe_backfill_snapshot(
                        &local_data_root,
                        &settings,
                        snapshot,
                        silences,
                        &audit_store,
                        &threat_store,
                        &metrics,
                    ) {
                        warn!(error = %err, "threat backfill failed");
                    }
                }
            }
        });
    }
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
        Some(threat_runtime.clone()),
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
    let shared_intercept_demux = Arc::new(SharedInterceptDemuxState::default());

    let dns_cfg = controlplane::trafficd::TrafficdConfig {
        dns_bind: dns_listen,
        dns_upstreams,
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
        threat_runtime: Some(threat_runtime),
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
    let policy_store_for_gc = policy_store.clone();
    tokio::spawn(async move {
        controlplane::allowlist_gc::run_allowlist_gc(
            policy_store_for_gc,
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
        threat_store: Some(threat_store),
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

#[cfg(test)]
mod tests {
    use super::{
        apply_threat_runtime_state, load_runtime_threat_snapshot, load_startup_threat_snapshot,
        maybe_backfill_snapshot, runtime_state_from_inputs, threat_snapshot_path,
        ThreatRuntimeState,
    };
    use crate::controlplane::audit::{
        AuditEvent as StoredAuditEvent, AuditFindingType, AuditStore, DEFAULT_AUDIT_STORE_MAX_BYTES,
    };
    use crate::controlplane::threat_intel::feeds::{ThreatIndicatorSnapshotItem, ThreatSnapshot};
    use crate::controlplane::threat_intel::runtime::ThreatRuntimeSlot;
    use crate::controlplane::threat_intel::settings::ThreatIntelSettings;
    use crate::controlplane::threat_intel::silences::ThreatSilenceList;
    use crate::controlplane::threat_intel::store::{
        ThreatEnrichmentStatus, ThreatFeedHit, ThreatFinding, ThreatMatchSource, ThreatStore,
    };
    use crate::controlplane::threat_intel::types::{ThreatIndicatorType, ThreatSeverity};
    use neuwerk::metrics::Metrics;
    use uuid::Uuid;

    #[test]
    fn load_startup_threat_snapshot_reads_persisted_snapshot() {
        let dir = std::env::temp_dir().join(format!("threat-startup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("threat-intel")).expect("mkdir");
        let snapshot = ThreatSnapshot::new(
            3,
            10,
            vec![ThreatIndicatorSnapshotItem {
                indicator: "bad.example.com".to_string(),
                indicator_type: ThreatIndicatorType::Hostname,
                feed: "threatfox".to_string(),
                severity: ThreatSeverity::High,
                confidence: Some(80),
                tags: Vec::new(),
                reference_url: None,
                feed_first_seen: Some(1),
                feed_last_seen: Some(2),
                expires_at: None,
            }],
        );
        std::fs::write(
            threat_snapshot_path(&dir),
            serde_json::to_vec(&snapshot).expect("serialize"),
        )
        .expect("write snapshot");

        let loaded = load_startup_threat_snapshot(&dir)
            .expect("load snapshot")
            .expect("snapshot");
        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn load_startup_threat_snapshot_returns_none_when_missing() {
        let dir = std::env::temp_dir().join(format!("threat-startup-{}", Uuid::new_v4()));
        let loaded = load_startup_threat_snapshot(&dir).expect("load snapshot");
        assert!(loaded.is_none());
    }

    #[test]
    fn load_runtime_threat_snapshot_returns_none_when_corrupt() {
        let dir = std::env::temp_dir().join(format!("threat-startup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(dir.join("threat-intel")).expect("mkdir");
        std::fs::write(threat_snapshot_path(&dir), b"{not-json").expect("write snapshot");

        let loaded = load_runtime_threat_snapshot(&dir);
        assert!(loaded.is_none());
    }

    #[test]
    fn runtime_state_waits_for_snapshot_when_enabled() {
        let settings = ThreatIntelSettings {
            enabled: true,
            alert_threshold: ThreatSeverity::Critical,
            ..ThreatIntelSettings::default()
        };

        let state = runtime_state_from_inputs(&settings, None, &ThreatSilenceList::default());

        assert!(matches!(
            state,
            ThreatRuntimeState::AwaitingSnapshot {
                settings: ThreatIntelSettings {
                    enabled: true,
                    alert_threshold: ThreatSeverity::Critical,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn apply_threat_runtime_state_refreshes_active_metrics_without_runtime_handle() {
        let metrics = Metrics::new().expect("metrics");
        let store = ThreatStore::new(temp_store_dir(), 1024 * 1024).expect("store");
        store
            .upsert_finding(sample_finding("bad.example.com", ThreatSeverity::High))
            .expect("upsert finding");
        let slot = ThreatRuntimeSlot::new(None, Some(metrics.clone()));
        let state = ThreatRuntimeState::AwaitingSnapshot {
            settings: ThreatIntelSettings {
                enabled: true,
                alert_threshold: ThreatSeverity::High,
                ..ThreatIntelSettings::default()
            },
            silences: ThreatSilenceList::default(),
        };

        apply_threat_runtime_state(&slot, &store, &metrics, &state).expect("apply state");

        let rendered = metrics.render().expect("render metrics");
        assert_eq!(
            metric_value_with_labels(
                &rendered,
                "neuwerk_threat_findings_active",
                &[("severity", "high")]
            ),
            1.0
        );
    }

    #[test]
    fn threat_disabled_backfill_skips_persisting_findings() {
        let metrics = Metrics::new().expect("metrics");
        let root = temp_store_dir();
        let audit_store = AuditStore::new(root.join("audit"), DEFAULT_AUDIT_STORE_MAX_BYTES);
        audit_store.ingest(
            StoredAuditEvent {
                finding_type: AuditFindingType::DnsDeny,
                source_group: "apps".to_string(),
                hostname: Some("bad.example.com".to_string()),
                dst_ip: None,
                dst_port: None,
                proto: None,
                fqdn: None,
                sni: None,
                icmp_type: None,
                icmp_code: None,
                query_type: Some(1),
                observed_at: 123,
            },
            None,
            "node-a",
        );
        let store = ThreatStore::new(root.join("threat-store"), 1024 * 1024).expect("store");

        maybe_backfill_snapshot(
            &root,
            &ThreatIntelSettings {
                enabled: false,
                ..ThreatIntelSettings::default()
            },
            &ThreatSnapshot::new(
                3,
                10,
                vec![ThreatIndicatorSnapshotItem {
                    indicator: "bad.example.com".to_string(),
                    indicator_type: ThreatIndicatorType::Hostname,
                    feed: "threatfox".to_string(),
                    severity: ThreatSeverity::High,
                    confidence: Some(80),
                    tags: Vec::new(),
                    reference_url: None,
                    feed_first_seen: Some(1),
                    feed_last_seen: Some(2),
                    expires_at: None,
                }],
            ),
            &ThreatSilenceList::default(),
            &audit_store,
            &store,
            &metrics,
        )
        .expect("backfill");

        let items = store.query(&Default::default()).expect("query");
        assert!(items.is_empty());
    }

    fn sample_finding(indicator: &str, severity: ThreatSeverity) -> ThreatFinding {
        ThreatFinding {
            indicator: indicator.to_string(),
            indicator_type: ThreatIndicatorType::Hostname,
            observation_layer:
                crate::controlplane::threat_intel::types::ThreatObservationLayer::Dns,
            match_source: ThreatMatchSource::Stream,
            source_group: "apps".to_string(),
            severity,
            confidence: Some(90),
            feed_hits: vec![ThreatFeedHit {
                feed: "threatfox".to_string(),
                severity,
                confidence: Some(90),
                reference_url: None,
                tags: Vec::new(),
            }],
            first_seen: 10,
            last_seen: 10,
            count: 1,
            sample_node_ids: vec!["node-a".to_string()],
            alertable: true,
            audit_links: Vec::new(),
            enrichment_status: ThreatEnrichmentStatus::NotRequested,
        }
    }

    fn temp_store_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("threat-runtime-startup-{}", Uuid::new_v4()))
    }

    fn metric_value_with_labels(rendered: &str, metric: &str, labels: &[(&str, &str)]) -> f64 {
        rendered
            .lines()
            .find_map(|line| {
                if !line.starts_with(metric) {
                    return None;
                }
                let name = line.split_whitespace().next()?;
                for (key, value) in labels {
                    let needle = format!(r#"{key}="{value}""#);
                    if !name.contains(&needle) {
                        return None;
                    }
                }
                line.split_whitespace().last()?.parse::<f64>().ok()
            })
            .unwrap_or(0.0)
    }
}
