use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use crate::controlplane::audit::AuditStore;
use crate::controlplane::dns_proxy;
use crate::controlplane::intercept_tls::{load_intercept_ca_signer, InterceptCaSource};
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::DnsPolicy;
use crate::controlplane::wiretap::DnsMap;
use crate::controlplane::PolicyStore;
#[cfg(test)]
use crate::dataplane::policy::HttpHeadersMatcher;
use crate::dataplane::policy::{
    CidrV4, DynamicIpSetV4, PacketMeta, PolicySnapshot, PortRange, Proto, RuleAction, RuleMode,
    TlsInterceptHttpPolicy, TlsMode,
};
use crate::dataplane::SharedInterceptDemuxState;
use axum::http::Response;
use bytes::Bytes;
use futures::FutureExt;
use h2::{client, server};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, warn};

const TLS_IO_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_H2_BODY_IDLE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(10);
const TLS_H2_MAX_CONCURRENT_STREAMS_DEFAULT: u32 = 64;
const INTERCEPT_LEAF_CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const INTERCEPT_LEAF_CACHE_MAX_ENTRIES: usize = 1024;
const INTERCEPT_CHAIN: &str = "NEUWERK_TLS_INTERCEPT";
const INTERCEPT_REPLY_CHAIN: &str = "NEUWERK_TLS_INTERCEPT_REPLY";
const SO_ORIGINAL_DST: i32 = 80;
const SERVICE_LANE_LOCAL_TABLE: u32 = 190;
const SERVICE_LANE_REPLY_TABLE: u32 = 191;
const SERVICE_LANE_LOCAL_RULE_PREF: u32 = 10940;
const SERVICE_LANE_REPLY_RULE_PREF: u32 = 10941;
const SERVICE_LANE_REPLY_MARK_RULE_PREF: u32 = 10942;
const SERVICE_LANE_TPROXY_FWMARK: u32 = 0x1;
const SERVICE_LANE_REPLY_FWMARK: u32 = 0x2;
const SERVICE_LANE_PEER_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 255, 2);
const SERVICE_LANE_PEER_MAC: &str = "02:00:00:00:00:02";

fn tls_h2_body_idle_timeout() -> Duration {
    static H2_BODY_IDLE_TIMEOUT: OnceLock<Duration> = OnceLock::new();
    *H2_BODY_IDLE_TIMEOUT.get_or_init(|| {
        let secs = std::env::var("NEUWERK_TLS_H2_BODY_TIMEOUT_SECS")
            .ok()
            .and_then(|raw| raw.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(TLS_H2_BODY_IDLE_TIMEOUT_DEFAULT.as_secs());
        Duration::from_secs(secs)
    })
}

fn tls_h2_max_concurrent_streams() -> u32 {
    static H2_MAX_CONCURRENT_STREAMS: OnceLock<u32> = OnceLock::new();
    *H2_MAX_CONCURRENT_STREAMS.get_or_init(|| {
        std::env::var("NEUWERK_TLS_H2_MAX_CONCURRENT_STREAMS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(TLS_H2_MAX_CONCURRENT_STREAMS_DEFAULT)
    })
}

mod certs;
mod http_match;
mod service_lane;
mod upstream_tls;

use certs::build_tls_intercept_acceptor;
#[cfg(test)]
use certs::{build_tls_acceptor, InterceptLeafCertResolver};
#[cfg(test)]
use service_lane::{intercept_reply_mark_rule_args, intercept_tproxy_rule_args, rule_line_matches};

pub struct TrafficdConfig {
    pub dns_bind: std::net::SocketAddr,
    pub dns_upstreams: Vec<std::net::SocketAddr>,
    pub dns_allowlist: DynamicIpSetV4,
    pub dns_policy: Arc<RwLock<DnsPolicy>>,
    pub dns_map: DnsMap,
    pub metrics: Metrics,
    pub policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    pub service_policy_applied_generation: Arc<AtomicU64>,
    pub tls_intercept_ca_ready: Arc<AtomicBool>,
    pub tls_intercept_ca_generation: Arc<AtomicU64>,
    pub tls_intercept_ca_source: InterceptCaSource,
    pub tls_intercept_listen_port: u16,
    pub enable_kernel_intercept_steering: bool,
    pub service_lane_iface: String,
    pub service_lane_ip: Ipv4Addr,
    pub service_lane_prefix: u8,
    pub intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    pub policy_store: PolicyStore,
    pub audit_store: Option<AuditStore>,
    pub node_id: String,
    pub startup_status_tx: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

#[derive(Debug)]
pub struct TlsInterceptRuntimeConfig {
    pub bind_addr: std::net::SocketAddr,
    pub upstream_override: Option<std::net::SocketAddr>,
    pub upstream_tls_insecure: bool,
    pub intercept_ca_cert_pem: Vec<u8>,
    pub intercept_ca_key_der: Vec<u8>,
    pub metrics: Metrics,
    pub policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    pub intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    pub startup_status_tx: Option<oneshot::Sender<Result<(), String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterceptSteeringRule {
    src_cidr: CidrV4,
    dst_cidr: Option<CidrV4>,
    dst_port: Option<PortRange>,
}

#[derive(Debug, Clone)]
struct MatchedTlsInterceptPolicy {
    http_policy: Option<TlsInterceptHttpPolicy>,
    enforce_http_policy: bool,
}

include!("trafficd/intercept_runtime.rs");

fn policy_has_tls_intercept(snapshot: &PolicySnapshot) -> bool {
    snapshot.groups.iter().any(|group| {
        group.rules.iter().any(|rule| {
            matches!(
                rule.matcher.tls.as_ref().map(|tls| tls.mode),
                Some(TlsMode::Intercept)
            )
        })
    })
}

fn compile_intercept_steering_rules(snapshot: &PolicySnapshot) -> Vec<InterceptSteeringRule> {
    let mut out = Vec::new();
    for group in &snapshot.groups {
        if group.sources.has_dynamic() || group.sources.cidrs().is_empty() {
            continue;
        }
        for rule in &group.rules {
            if rule.action != RuleAction::Allow {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if !matches!(rule.matcher.proto, Proto::Tcp | Proto::Any) {
                continue;
            }
            let dst_cidrs = rule
                .matcher
                .dst_ips
                .as_ref()
                .map(|set| set.cidrs().to_vec())
                .unwrap_or_default();
            let dst_ports = if rule.matcher.dst_ports.is_empty() {
                vec![None]
            } else {
                rule.matcher.dst_ports.iter().copied().map(Some).collect()
            };
            let dst_targets = if dst_cidrs.is_empty() {
                vec![None]
            } else {
                dst_cidrs.into_iter().map(Some).collect()
            };
            for src_cidr in group.sources.cidrs() {
                for dst_cidr in &dst_targets {
                    for dst_port in &dst_ports {
                        out.push(InterceptSteeringRule {
                            src_cidr: *src_cidr,
                            dst_cidr: *dst_cidr,
                            dst_port: *dst_port,
                        });
                    }
                }
            }
        }
    }
    out
}

fn find_intercept_http_policy(
    snapshot: &PolicySnapshot,
    meta: &PacketMeta,
) -> Option<MatchedTlsInterceptPolicy> {
    for group in &snapshot.groups {
        if !group.sources.contains(meta.src_ip) {
            continue;
        }
        for rule in &group.rules {
            if !rule_matches_meta(rule, meta) {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if rule.action != RuleAction::Allow {
                return None;
            }
            return Some(MatchedTlsInterceptPolicy {
                http_policy: tls.intercept_http.clone(),
                enforce_http_policy: snapshot.enforcement_mode()
                    == crate::dataplane::policy::EnforcementMode::Enforce
                    && rule.mode == RuleMode::Enforce,
            });
        }
    }
    None
}

fn lookup_intercept_demux_original_dst(
    demux: &Arc<Mutex<SharedInterceptDemuxState>>,
    src_ip: Ipv4Addr,
    src_port: u16,
) -> Option<SocketAddr> {
    let mut lock = demux.lock().ok()?;
    let (upstream_ip, upstream_port) = lock.lookup(src_ip, src_port)?;
    Some(SocketAddr::new(IpAddr::V4(upstream_ip), upstream_port))
}

fn infer_intercept_original_dst(snapshot: &PolicySnapshot, src_ip: Ipv4Addr) -> Option<SocketAddr> {
    let mut inferred: Option<SocketAddr> = None;
    for group in &snapshot.groups {
        if !group.sources.contains(src_ip) {
            continue;
        }
        for rule in &group.rules {
            if rule.action != RuleAction::Allow {
                continue;
            }
            let Some(tls) = rule.matcher.tls.as_ref() else {
                continue;
            };
            if !matches!(tls.mode, TlsMode::Intercept) {
                continue;
            }
            if !matches!(rule.matcher.proto, Proto::Tcp | Proto::Any) {
                continue;
            }

            let Some(dst_ips) = &rule.matcher.dst_ips else {
                continue;
            };
            let cidrs = dst_ips.cidrs();
            if cidrs.len() != 1 || cidrs[0].prefix() != 32 {
                continue;
            }
            let dst_ip = cidrs[0].addr();

            let dst_port = match rule.matcher.dst_ports.as_slice() {
                [range] if range.start == range.end => range.start,
                _ => continue,
            };

            let candidate = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
            match inferred {
                None => inferred = Some(candidate),
                Some(current) if current == candidate => {}
                Some(_) => return None,
            }
        }
    }
    inferred
}

fn rule_matches_meta(rule: &crate::dataplane::policy::Rule, meta: &PacketMeta) -> bool {
    if let Some(dst_ips) = &rule.matcher.dst_ips {
        if !dst_ips.contains(meta.dst_ip) {
            return false;
        }
    }
    if !rule.matcher.proto.matches(meta.proto) {
        return false;
    }
    if !port_matches(&rule.matcher.src_ports, meta.src_port) {
        return false;
    }
    if !port_matches(&rule.matcher.dst_ports, meta.dst_port) {
        return false;
    }
    true
}

fn port_matches(ranges: &[PortRange], port: u16) -> bool {
    if ranges.is_empty() {
        return true;
    }
    ranges.iter().any(|range| range.contains(port))
}

fn original_dst_addr(stream: &TcpStream) -> Result<SocketAddr, String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(format!(
                "tls intercept: SO_ORIGINAL_DST lookup failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::new(IpAddr::V4(ip), port));
    }
    #[allow(unreachable_code)]
    Err("tls intercept: SO_ORIGINAL_DST unsupported on this platform".to_string())
}

fn spawn_service_policy_observer(
    observer_policy: Arc<RwLock<PolicySnapshot>>,
    observer_applied: Arc<AtomicU64>,
    tls_intercept_ca_ready: Arc<AtomicBool>,
    intercept_ready: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut last = observer_applied.load(Ordering::Acquire);
        loop {
            let snapshot = {
                match observer_policy.read() {
                    Ok(lock) => Some(lock.clone()),
                    Err(_) => None,
                }
            };
            let Some(snapshot) = snapshot else {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            };
            let generation = snapshot.generation();
            if policy_has_tls_intercept(&snapshot)
                && (!tls_intercept_ca_ready.load(Ordering::Acquire)
                    || !intercept_ready.load(Ordering::Acquire))
            {
                let blocked_generation = generation.saturating_sub(1);
                if blocked_generation != last {
                    observer_applied.store(blocked_generation, Ordering::Release);
                    last = blocked_generation;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            if generation != last {
                observer_applied.store(generation, Ordering::Release);
                last = generation;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_tls_intercept_supervisor(
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    tls_intercept_ca_ready: Arc<AtomicBool>,
    tls_intercept_ca_generation: Arc<AtomicU64>,
    tls_intercept_ca_source: InterceptCaSource,
    intercept_ready: Arc<AtomicBool>,
    listen_addr: SocketAddr,
    enable_kernel_intercept_steering: bool,
    service_lane_iface: String,
    intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    metrics: Metrics,
) {
    tokio::spawn(async move {
        let verify_mode = upstream_tls::upstream_tls_verify_mode_from_env();
        let mut runtime_task: Option<tokio::task::JoinHandle<Result<(), String>>> = None;
        let mut runtime_ca_generation: Option<u64> = None;
        let mut applied_steering_rules: Option<Vec<InterceptSteeringRule>> = None;
        loop {
            let desired_ca_generation = tls_intercept_ca_generation.load(Ordering::Acquire);
            if let Some(task) = runtime_task.as_ref() {
                if task.is_finished() {
                    if let Some(task) = runtime_task.take() {
                        let _ = task.await;
                    }
                    intercept_ready.store(false, Ordering::Release);
                    runtime_ca_generation = None;
                } else if runtime_ca_generation != Some(desired_ca_generation) {
                    if let Some(task) = runtime_task.take() {
                        task.abort();
                        let _ = task.await;
                    }
                    intercept_ready.store(false, Ordering::Release);
                    runtime_ca_generation = None;
                }
            }

            let snapshot = {
                match policy_snapshot.read() {
                    Ok(lock) => Some(lock.clone()),
                    Err(_) => None,
                }
            };
            let Some(snapshot) = snapshot else {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    service_lane::clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            };

            let has_intercept_policy = policy_has_tls_intercept(&snapshot);
            if !has_intercept_policy {
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    service_lane::clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                intercept_ready.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let ca_ready = tls_intercept_ca_ready.load(Ordering::Acquire);
            if !ca_ready {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    service_lane::clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if runtime_task.is_none() {
                let signer = match load_intercept_ca_signer(&tls_intercept_ca_source) {
                    Ok(signer) => signer,
                    Err(err) => {
                        warn!(error = %err, "trafficd intercept ca load failed");
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let (startup_tx, startup_rx) = oneshot::channel();
                let task = tokio::spawn(run_tls_intercept_runtime(TlsInterceptRuntimeConfig {
                    bind_addr: listen_addr,
                    upstream_override: None,
                    upstream_tls_insecure: verify_mode
                        == upstream_tls::UpstreamTlsVerificationMode::Insecure,
                    intercept_ca_cert_pem: signer.cert_pem().to_vec(),
                    intercept_ca_key_der: signer.key_der().to_vec(),
                    metrics: metrics.clone(),
                    policy_snapshot: policy_snapshot.clone(),
                    intercept_demux: intercept_demux.clone(),
                    startup_status_tx: Some(startup_tx),
                }));
                match tokio::time::timeout(Duration::from_secs(2), startup_rx).await {
                    Ok(Ok(Ok(()))) => {
                        runtime_task = Some(task);
                        runtime_ca_generation = Some(desired_ca_generation);
                    }
                    Ok(Ok(Err(err))) => {
                        error!(error = %err, "trafficd tls intercept runtime startup failed");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Ok(Err(_)) => {
                        error!("trafficd tls intercept runtime startup channel dropped");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    Err(_) => {
                        error!("trafficd tls intercept runtime startup timed out");
                        task.abort();
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            }

            let rules = compile_intercept_steering_rules(&snapshot);
            if rules.is_empty() {
                intercept_ready.store(false, Ordering::Release);
                if enable_kernel_intercept_steering && applied_steering_rules.is_some() {
                    service_lane::clear_intercept_steering_rules(&service_lane_iface);
                    applied_steering_rules = None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            if enable_kernel_intercept_steering {
                let rules_changed = applied_steering_rules
                    .as_ref()
                    .map(|current| current != &rules)
                    .unwrap_or(true);
                if rules_changed {
                    if let Err(err) = service_lane::apply_intercept_steering_rules(
                        &rules,
                        listen_addr,
                        &service_lane_iface,
                    ) {
                        error!(error = %err, "trafficd intercept steering apply failed");
                        service_lane::clear_intercept_steering_rules(&service_lane_iface);
                        applied_steering_rules = None;
                        intercept_ready.store(false, Ordering::Release);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    applied_steering_rules = Some(rules);
                }
            }
            intercept_ready.store(true, Ordering::Release);

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
}

pub async fn run(cfg: TrafficdConfig) -> Result<(), String> {
    if cfg.dns_upstreams.is_empty() {
        return Err("trafficd: at least one dns upstream is required".to_string());
    }
    service_lane::ensure_service_lane_interface(
        &cfg.service_lane_iface,
        cfg.service_lane_ip,
        cfg.service_lane_prefix,
    )?;
    service_lane::ensure_service_lane_routing(&cfg.service_lane_iface, cfg.service_lane_ip)?;

    let intercept_listen_ip = if cfg.enable_kernel_intercept_steering {
        Ipv4Addr::UNSPECIFIED
    } else {
        cfg.service_lane_ip
    };
    let intercept_listen_addr = SocketAddr::new(
        IpAddr::V4(intercept_listen_ip),
        cfg.tls_intercept_listen_port,
    );

    let intercept_ready = Arc::new(AtomicBool::new(false));
    spawn_tls_intercept_supervisor(
        cfg.policy_snapshot.clone(),
        cfg.tls_intercept_ca_ready.clone(),
        cfg.tls_intercept_ca_generation.clone(),
        cfg.tls_intercept_ca_source.clone(),
        intercept_ready.clone(),
        intercept_listen_addr,
        cfg.enable_kernel_intercept_steering,
        cfg.service_lane_iface.clone(),
        cfg.intercept_demux.clone(),
        cfg.metrics.clone(),
    );

    spawn_service_policy_observer(
        cfg.policy_snapshot.clone(),
        cfg.service_policy_applied_generation.clone(),
        cfg.tls_intercept_ca_ready.clone(),
        intercept_ready,
    );

    dns_proxy::run_dns_proxy(
        cfg.dns_bind,
        cfg.dns_upstreams,
        cfg.dns_allowlist,
        cfg.dns_policy,
        cfg.dns_map,
        cfg.metrics,
        Some(cfg.policy_store),
        cfg.audit_store,
        cfg.node_id,
        cfg.startup_status_tx,
    )
    .await
    .map_err(|err| format!("trafficd dns runtime failed: {err}"))
}

#[cfg(test)]
mod tests;
