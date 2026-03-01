use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use firewall::controlplane::api_auth::DEFAULT_TTL_SECS;
use firewall::controlplane::audit::{
    AuditEvent as ControlplaneAuditEvent, AuditFindingType, AuditStore,
    DEFAULT_AUDIT_STORE_MAX_BYTES,
};
use firewall::controlplane::cloud::provider::CloudProvider as CloudProviderTrait;
use firewall::controlplane::cloud::providers::{
    aws::AwsProvider, azure::AzureProvider, gcp::GcpProvider,
};
use firewall::controlplane::cloud::types::{DiscoveryFilter, IntegrationConfig, IntegrationMode};
use firewall::controlplane::cloud::{self, IntegrationManager, ReadyChecker, ReadyClient};
use firewall::controlplane::cluster::migration;
use firewall::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};
use firewall::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::wiretap::{load_or_create_node_id, DnsMap, WiretapHub};
use firewall::controlplane::{self, PolicyStore};
use firewall::dataplane::policy::{DefaultPolicy, DynamicIpSetV4, PolicySnapshot};
use firewall::dataplane::{
    AuditEmitter, AuditEventType, DataplaneConfigStore, DhcpRx, DhcpTx, DpdkAdapter, DpdkIo,
    DrainControl, EncapMode, EngineState, FrameIo, FrameOut, OverlayConfig, Packet, SharedArpState,
    SharedInterceptDemuxState, SnatMode, SoftAdapter, SoftMode, WiretapEmitter,
    DEFAULT_AUDIT_REPORT_INTERVAL_SECS, DEFAULT_IDLE_TIMEOUT_SECS,
    DEFAULT_WIRETAP_REPORT_INTERVAL_SECS,
};
use futures::stream::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::new_connection;
use serde::Deserialize;
use std::collections::HashMap;
use tokio::sync::{mpsc, oneshot, watch};

const DNS_ALLOWLIST_IDLE_SLACK_SECS: u64 = 120;
const DNS_ALLOWLIST_GC_INTERVAL_SECS: u64 = 30;
const DHCP_TIMEOUT_SECS: u64 = 5;
const DHCP_RETRY_MAX: u32 = 5;
const DHCP_LEASE_MIN_SECS: u64 = 60;

#[cfg(target_os = "linux")]
fn cpu_core_count() -> usize {
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 {
        return count as usize;
    }
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
}

#[cfg(not(target_os = "linux"))]
fn cpu_core_count() -> usize {
    std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(1)
}

fn shard_index_for_packet(pkt: &Packet, shard_count: usize) -> usize {
    if shard_count <= 1 {
        return 0;
    }
    let src_ip = match pkt.src_ip() {
        Some(ip) => ip,
        None => return 0,
    };
    let dst_ip = match pkt.dst_ip() {
        Some(ip) => ip,
        None => return 0,
    };
    let proto = pkt.protocol().unwrap_or(0);
    let (src_port, dst_port) = pkt.ports().unwrap_or((0, 0));
    let src_u = u32::from(src_ip);
    let dst_u = u32::from(dst_ip);
    let forward = (src_u, dst_u, src_port, dst_port);
    let reverse = (dst_u, src_u, dst_port, src_port);
    let key = if forward <= reverse { forward } else { reverse };
    let mut hasher = DefaultHasher::new();
    proto.hash(&mut hasher);
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

#[cfg(target_os = "linux")]
fn pin_thread_to_core(core_id: usize) -> Result<(), String> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
        let rc = libc::pthread_setaffinity_np(
            libc::pthread_self(),
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        if rc != 0 {
            return Err(format!("pthread_setaffinity_np failed: {rc}"));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn pin_thread_to_core(_core_id: usize) -> Result<(), String> {
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DpdkWorkerMode {
    Single,
    QueuePerWorker,
    SharedRxDemux,
}

#[derive(Debug, Clone, Copy)]
struct DpdkWorkerPlan {
    requested: usize,
    effective_queues: usize,
    worker_count: usize,
    mode: DpdkWorkerMode,
}

fn choose_dpdk_worker_plan(
    requested: usize,
    max_workers: usize,
    effective_queues: usize,
) -> Result<DpdkWorkerPlan, String> {
    let requested = requested.max(1).min(max_workers.max(1));
    if effective_queues == 0 {
        return Err("dpdk: no usable queues available".to_string());
    }
    if requested == 1 {
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: 1,
            mode: DpdkWorkerMode::Single,
        });
    }
    if effective_queues >= requested {
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: requested,
            mode: DpdkWorkerMode::QueuePerWorker,
        });
    }
    if effective_queues == 1 {
        return Ok(DpdkWorkerPlan {
            requested,
            effective_queues,
            worker_count: requested,
            mode: DpdkWorkerMode::SharedRxDemux,
        });
    }
    Ok(DpdkWorkerPlan {
        requested,
        effective_queues,
        worker_count: effective_queues,
        mode: DpdkWorkerMode::QueuePerWorker,
    })
}

fn shared_demux_owner_for_packet(pkt: &Packet, shard_count: usize, worker_count: usize) -> usize {
    if worker_count <= 1 {
        return 0;
    }
    if let Some((src_port, dst_port)) = pkt.ports() {
        // Route common HTTPS flows to worker 0 so service-lane intercept is
        // handled by the worker that owns the service-lane TAP attachment.
        if src_port == 443 || dst_port == 443 {
            return 0;
        }
    }
    let shard_idx = shard_index_for_packet(pkt, shard_count);
    shard_idx % worker_count
}

enum DpdkWorkerIo {
    Dedicated(DpdkIo),
    Shared(Arc<Mutex<DpdkIo>>),
}

impl DpdkWorkerIo {
    fn mac(&self) -> Option<[u8; 6]> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.mac(),
            DpdkWorkerIo::Shared(io) => io.lock().ok().and_then(|guard| guard.mac()),
        }
    }
}

impl FrameIo for DpdkWorkerIo {
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.recv_frame(buf),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .recv_frame(buf),
        }
    }

    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.send_frame(frame),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .send_frame(frame),
        }
    }

    fn flush(&mut self) -> Result<(), String> {
        match self {
            DpdkWorkerIo::Dedicated(io) => io.flush(),
            DpdkWorkerIo::Shared(io) => io
                .lock()
                .map_err(|_| "dpdk: shared io lock poisoned".to_string())?
                .flush(),
        }
    }
}

const INTEGRATION_ROUTE_NAME: &str = "neuwerk-default";
const INTEGRATION_DRAIN_TIMEOUT_SECS: u64 = 300;
const INTEGRATION_RECONCILE_INTERVAL_SECS: u64 = 15;
const INTEGRATION_CLUSTER_NAME: &str = "neuwerk";
const IMDS_NETWORK_URL: &str =
    "http://169.254.169.254/metadata/instance/network/interface?api-version=2021-02-01";

#[derive(Debug)]
struct CliConfig {
    management_iface: String,
    data_plane_iface: String,
    dns_target_ips: Vec<Ipv4Addr>,
    dns_upstreams: Vec<SocketAddr>,
    data_plane_mode: DataPlaneMode,
    idle_timeout_secs: u64,
    dns_allowlist_idle_secs: u64,
    dns_allowlist_gc_interval_secs: u64,
    default_policy: DefaultPolicy,
    dhcp_timeout_secs: u64,
    dhcp_retry_max: u32,
    dhcp_lease_min_secs: u64,
    internal_cidr: Option<(Ipv4Addr, u8)>,
    snat_mode: SnatMode,
    encap_mode: EncapMode,
    encap_vni: Option<u32>,
    encap_vni_internal: Option<u32>,
    encap_vni_external: Option<u32>,
    encap_udp_port: Option<u16>,
    encap_udp_port_internal: Option<u16>,
    encap_udp_port_external: Option<u16>,
    encap_mtu: u16,
    http_bind: Option<SocketAddr>,
    http_advertise: Option<SocketAddr>,
    http_tls_dir: PathBuf,
    http_cert_path: Option<PathBuf>,
    http_key_path: Option<PathBuf>,
    http_ca_path: Option<PathBuf>,
    http_tls_san: Vec<String>,
    metrics_bind: Option<SocketAddr>,
    cloud_provider: CloudProviderKind,
    cluster: controlplane::cluster::config::ClusterConfig,
    cluster_migrate_from_local: bool,
    cluster_migrate_force: bool,
    cluster_migrate_verify: bool,
    integration_mode: controlplane::cloud::types::IntegrationMode,
    integration_route_name: String,
    integration_drain_timeout_secs: u64,
    integration_reconcile_interval_secs: u64,
    integration_cluster_name: String,
    azure_subscription_id: Option<String>,
    azure_resource_group: Option<String>,
    azure_vmss_name: Option<String>,
    aws_region: Option<String>,
    aws_vpc_id: Option<String>,
    aws_asg_name: Option<String>,
    gcp_project: Option<String>,
    gcp_region: Option<String>,
    gcp_ig_name: Option<String>,
}

#[derive(Debug)]
enum AuthCommand {
    KeyRotate {
        addr: SocketAddr,
        tls_dir: PathBuf,
    },
    KeyList {
        addr: SocketAddr,
        tls_dir: PathBuf,
    },
    KeyRetire {
        addr: SocketAddr,
        tls_dir: PathBuf,
        kid: String,
    },
    TokenMint {
        addr: SocketAddr,
        tls_dir: PathBuf,
        sub: String,
        ttl_secs: Option<i64>,
        kid: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataPlaneMode {
    Soft(SoftMode),
    Dpdk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloudProviderKind {
    None,
    Azure,
    Aws,
    Gcp,
}

impl CloudProviderKind {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "none" | "NONE" => Ok(CloudProviderKind::None),
            "azure" | "AZURE" => Ok(CloudProviderKind::Azure),
            "aws" | "AWS" => Ok(CloudProviderKind::Aws),
            "gcp" | "GCP" => Ok(CloudProviderKind::Gcp),
            _ => Err(format!(
                "--cloud-provider must be azure, aws, gcp, or none, got {value}"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            CloudProviderKind::None => "none",
            CloudProviderKind::Azure => "azure",
            CloudProviderKind::Aws => "aws",
            CloudProviderKind::Gcp => "gcp",
        }
    }
}

impl DataPlaneMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "dpdk" | "DPDK" => Ok(DataPlaneMode::Dpdk),
            _ => Ok(DataPlaneMode::Soft(SoftMode::parse(value)?)),
        }
    }
}

fn usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} --management-interface <iface> --data-plane-interface <iface|pci|mac> --dns-target-ip <ipv4> --dns-upstream <ip:port> [--data-plane-mode tun|tap|dpdk] [--idle-timeout-secs <secs>] [--dns-allowlist-idle-secs <secs>] [--dns-allowlist-gc-interval-secs <secs>] [--default-policy allow|deny] [--dhcp-timeout-secs <secs>] [--dhcp-retry-max <count>] [--dhcp-lease-min-secs <secs>] [--internal-cidr <cidr>] [--snat none|auto|<ipv4>] [--encap none|vxlan|geneve] [--encap-vni <id>] [--encap-udp-port <port>] [--encap-vni-internal <id>] [--encap-vni-external <id>] [--encap-udp-port-internal <port>] [--encap-udp-port-external <port>] [--encap-mtu <bytes>]\n  {bin} [cluster flags]\n  {bin} auth <command>\n\nFlags:\n  --management-interface <iface>\n  --data-plane-interface <iface|pci|mac> (dpdk accepts pci:0000:00:00.0 or mac:aa:bb:cc:dd:ee:ff)\n  --dns-target-ip <ipv4> (repeatable)\n  --dns-target-ips <csv IPv4 list>\n  --dns-upstream <ip:port> (repeatable)\n  --dns-upstreams <csv ip:port list>\n  --data-plane-mode tun|tap|dpdk (default: tun)\n  --idle-timeout-secs <secs> (default: 300)\n  --dns-allowlist-idle-secs <secs> (default: idle-timeout + 120)\n  --dns-allowlist-gc-interval-secs <secs> (default: 30)\n  --default-policy allow|deny (default: deny)\n  --dhcp-timeout-secs <secs> (default: 5)\n  --dhcp-retry-max <count> (default: 5)\n  --dhcp-lease-min-secs <secs> (default: 60)\n  --internal-cidr <cidr> (overrides DHCP-derived internal network)\n  --snat none|auto|<ipv4>\n  --encap none|vxlan|geneve (default: none)\n  --encap-vni <id>\n  --encap-vni-internal <id>\n  --encap-vni-external <id>\n  --encap-udp-port <port> (default: 10800 for vxlan, 6081 for geneve)\n  --encap-udp-port-internal <port> (default: 10800 when --encap-vni-internal is set)\n  --encap-udp-port-external <port> (default: 10801 when --encap-vni-external is set)\n  --encap-mtu <bytes> (default: 1500)\n  --http-bind <ip:port> (default: <management-ip>:8443)\n  --http-advertise <ip:port> (default: http-bind)\n  --http-tls-dir <path> (default: /var/lib/neuwerk/http-tls)\n  --http-cert-path <path>\n  --http-key-path <path>\n  --http-ca-path <path>\n  --http-tls-san <comma-separated>\n  --metrics-bind <ip:port> (default: <management-ip>:8080)\n  --cloud-provider azure|aws|gcp|none (default: none)\n  --integration azure-vmss|aws-asg|gcp-mig|none (default: none)\n  --integration-route-name <name> (default: neuwerk-default)\n  --integration-drain-timeout-secs <secs> (default: 300)\n  --integration-reconcile-interval-secs <secs> (default: 15)\n  --integration-cluster-name <name> (default: neuwerk)\n  --azure-subscription-id <id>\n  --azure-resource-group <name>\n  --azure-vmss-name <name>\n  --aws-region <region>\n  --aws-vpc-id <id>\n  --aws-asg-name <name>\n  --gcp-project <id>\n  --gcp-region <region>\n  --gcp-ig-name <name>\n  --cluster-migrate-from-local\n  --cluster-migrate-force\n  --cluster-migrate-verify\n  --cluster-bind <ip:port>\n  --cluster-join-bind <ip:port> (default: cluster-bind + 1)\n  --cluster-advertise <ip:port> (default: cluster-bind)\n  --join <ip:port>\n  --cluster-data-dir <path> (default: /var/lib/neuwerk/cluster)\n  --node-id-path <path> (default: /var/lib/neuwerk/node_id)\n  --bootstrap-token-path <path> (default: /var/lib/neuwerk/bootstrap-token)\n  -h, --help\n\nAuth Commands:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n"
    )
}

fn auth_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n"
    )
}

fn looks_like_pci(value: &str) -> bool {
    let value = value.trim();
    let value = value.strip_prefix("pci:").unwrap_or(value);
    is_pci_addr(value)
}

fn looks_like_mac(value: &str) -> bool {
    let value = value.trim();
    let value = value.strip_prefix("mac:").unwrap_or(value);
    parse_mac(value).is_some()
}

fn is_pci_addr(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 2 && parts.len() != 3 {
        return false;
    }
    let (domain, bus, devfn) = if parts.len() == 3 {
        (Some(parts[0]), parts[1], parts[2])
    } else {
        (None, parts[0], parts[1])
    };
    if let Some(domain) = domain {
        if !is_hex_len(domain, 4) {
            return false;
        }
    }
    if !is_hex_len(bus, 2) {
        return false;
    }
    let mut devfn_parts = devfn.split('.');
    let dev = match devfn_parts.next() {
        Some(dev) => dev,
        None => return false,
    };
    let func = match devfn_parts.next() {
        Some(func) => func,
        None => return false,
    };
    if devfn_parts.next().is_some() {
        return false;
    }
    is_hex_len(dev, 2) && is_hex_len(func, 1)
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = value.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let parsed = u8::from_str_radix(part, 16).ok()?;
        bytes[idx] = parsed;
    }
    Some(bytes)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsNetworkInterface {
    mac_address: String,
    ipv4: Option<ImdsIpv4>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsIpv4 {
    ip_address: Vec<ImdsIpAddress>,
    subnet: Vec<ImdsSubnet>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsIpAddress {
    private_ip_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsSubnet {
    prefix: String,
}

async fn imds_dataplane_config(mac: [u8; 6]) -> Result<(Ipv4Addr, u8, Ipv4Addr), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(IMDS_NETWORK_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|err| format!("imds request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("imds request failed: {}", response.status()));
    }
    let payload: Vec<ImdsNetworkInterface> = response
        .json()
        .await
        .map_err(|err| format!("imds decode failed: {err}"))?;
    let target = format_mac_no_sep(mac);
    for nic in payload {
        if normalize_imds_mac(&nic.mac_address) != target {
            continue;
        }
        let Some(ipv4) = nic.ipv4 else {
            continue;
        };
        let ip = ipv4
            .ip_address
            .first()
            .and_then(|addr| addr.private_ip_address.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| "imds missing dataplane ip".to_string())?;
        let prefix = ipv4
            .subnet
            .first()
            .and_then(|subnet| subnet.prefix.parse::<u8>().ok())
            .ok_or_else(|| "imds missing subnet prefix".to_string())?;
        let gateway = subnet_gateway(ip, prefix)?;
        return Ok((ip, prefix, gateway));
    }
    Err("imds dataplane nic not found for mac".to_string())
}

async fn imds_dataplane_from_mgmt_ip(
    mgmt_ip: Ipv4Addr,
) -> Result<(Ipv4Addr, u8, Ipv4Addr, [u8; 6]), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(IMDS_NETWORK_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|err| format!("imds request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("imds request failed: {}", response.status()));
    }
    let payload: Vec<ImdsNetworkInterface> = response
        .json()
        .await
        .map_err(|err| format!("imds decode failed: {err}"))?;
    let mut dataplane: Option<(Ipv4Addr, u8, Ipv4Addr, [u8; 6])> = None;
    for nic in payload {
        let Some(ipv4) = nic.ipv4 else {
            continue;
        };
        let ip = ipv4
            .ip_address
            .first()
            .and_then(|addr| addr.private_ip_address.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| "imds missing ip address".to_string())?;
        if ip == mgmt_ip {
            continue;
        }
        let prefix = ipv4
            .subnet
            .first()
            .and_then(|subnet| subnet.prefix.parse::<u8>().ok())
            .ok_or_else(|| "imds missing subnet prefix".to_string())?;
        let gateway = subnet_gateway(ip, prefix)?;
        let mac = parse_imds_mac(&nic.mac_address)?;
        dataplane = Some((ip, prefix, gateway, mac));
        break;
    }
    dataplane.ok_or_else(|| "imds dataplane nic not found".to_string())
}

fn subnet_gateway(ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Addr, String> {
    if prefix == 0 || prefix > 32 {
        return Err(format!("invalid subnet prefix {prefix}"));
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(ip) & mask;
    let gateway = network.saturating_add(1);
    Ok(Ipv4Addr::from(gateway))
}

fn normalize_imds_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([':', '-'], "")
}

fn format_mac_no_sep(mac: [u8; 6]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn parse_imds_mac(value: &str) -> Result<[u8; 6], String> {
    let raw = normalize_imds_mac(value);
    if raw.len() != 12 {
        return Err("invalid imds mac".to_string());
    }
    let mut bytes = [0u8; 6];
    for idx in 0..6 {
        let start = idx * 2;
        let part = &raw[start..start + 2];
        bytes[idx] = u8::from_str_radix(part, 16).map_err(|_| "invalid imds mac".to_string())?;
    }
    Ok(bytes)
}

fn take_flag_value(
    flag: &str,
    arg: &str,
    args: &mut impl Iterator<Item = String>,
) -> Result<String, String> {
    let prefix = format!("{flag}=");
    if let Some(rest) = arg.strip_prefix(&prefix) {
        if rest.is_empty() {
            return Err(format!("{flag} requires a value"));
        }
        return Ok(rest.to_string());
    }
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_socket(flag: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be a socket address in the form ip:port, got {value}"))
}

fn parse_ipv4(flag: &str, value: &str) -> Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be an IPv4 address, got {value}"))
}

fn parse_csv_ipv4_list(flag: &str, value: &str) -> Result<Vec<Ipv4Addr>, String> {
    let mut parsed = Vec::new();
    for part in value.split(',') {
        let entry = part.trim();
        if entry.is_empty() {
            continue;
        }
        parsed.push(parse_ipv4(flag, entry)?);
    }
    if parsed.is_empty() {
        return Err(format!("{flag} requires at least one IPv4 address"));
    }
    Ok(parsed)
}

fn parse_csv_socket_list(flag: &str, value: &str) -> Result<Vec<SocketAddr>, String> {
    let mut parsed = Vec::new();
    for part in value.split(',') {
        let entry = part.trim();
        if entry.is_empty() {
            continue;
        }
        parsed.push(parse_socket(flag, entry)?);
    }
    if parsed.is_empty() {
        return Err(format!("{flag} requires at least one ip:port"));
    }
    Ok(parsed)
}

fn parse_port(flag: &str, value: &str) -> Result<u16, String> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be a valid UDP port, got {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be between 1 and 65535, got {value}"));
    }
    Ok(parsed)
}

fn parse_vni(flag: &str, value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be a number, got {value}"))?;
    if parsed > 0x00ff_ffff {
        return Err(format!("{flag} must be <= 16777215, got {value}"));
    }
    Ok(parsed)
}

fn parse_cidr(flag: &str, value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (addr, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("{flag} must be in CIDR form (e.g. 10.0.0.0/24), got {value}"))?;
    let ip = addr
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("{flag} must be a valid IPv4 CIDR, got {value}"))?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| format!("{flag} must be a valid IPv4 CIDR, got {value}"))?;
    if prefix > 32 {
        return Err(format!("{flag} must be <= 32, got {prefix}"));
    }
    Ok((ip, prefix))
}

fn parse_default_policy(value: &str) -> Result<DefaultPolicy, String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok(DefaultPolicy::Allow),
        "deny" => Ok(DefaultPolicy::Deny),
        _ => Err(format!(
            "--default-policy must be allow or deny, got {value}"
        )),
    }
}

fn parse_integration_mode(value: &str) -> Result<IntegrationMode, String> {
    match value.to_ascii_lowercase().as_str() {
        "none" => Ok(IntegrationMode::None),
        "azure-vmss" => Ok(IntegrationMode::AzureVmss),
        "aws-asg" => Ok(IntegrationMode::AwsAsg),
        "gcp-mig" => Ok(IntegrationMode::GcpMig),
        _ => Err(format!(
            "--integration must be azure-vmss, aws-asg, gcp-mig, or none, got {value}"
        )),
    }
}

fn build_integration_provider(cfg: &CliConfig) -> Option<Arc<dyn CloudProviderTrait>> {
    match cfg.integration_mode {
        IntegrationMode::AzureVmss => Some(
            AzureProvider::new(
                cfg.azure_subscription_id.clone().unwrap_or_default(),
                cfg.azure_resource_group.clone().unwrap_or_default(),
                cfg.azure_vmss_name.clone().unwrap_or_default(),
            )
            .shared(),
        ),
        IntegrationMode::AwsAsg => Some(
            AwsProvider::new(
                cfg.aws_region.clone().unwrap_or_default(),
                cfg.aws_vpc_id.clone().unwrap_or_default(),
                cfg.aws_asg_name.clone().unwrap_or_default(),
            )
            .shared(),
        ),
        IntegrationMode::GcpMig => Some(
            GcpProvider::new(
                cfg.gcp_project.clone().unwrap_or_default(),
                cfg.gcp_region.clone().unwrap_or_default(),
                cfg.gcp_ig_name.clone().unwrap_or_default(),
            )
            .shared(),
        ),
        IntegrationMode::None => None,
    }
}

fn integration_tag_filter(cfg: &CliConfig) -> DiscoveryFilter {
    let mut tags = std::collections::HashMap::new();
    tags.insert(
        "neuwerk.io/cluster".to_string(),
        cfg.integration_cluster_name.clone(),
    );
    tags.insert("neuwerk.io/role".to_string(), "dataplane".to_string());
    DiscoveryFilter { tags }
}

async fn select_integration_seed(
    provider: Arc<dyn CloudProviderTrait>,
    filter: &DiscoveryFilter,
    cluster_port: u16,
) -> Result<Option<SocketAddr>, String> {
    let instances = provider
        .discover_instances(filter)
        .await
        .map_err(|err| format!("discover instances failed: {err}"))?;
    let seed = cloud::select_seed_instance(&instances);
    let Some(seed) = seed else {
        return Ok(None);
    };
    let self_ref = provider
        .self_identity()
        .await
        .map_err(|err| format!("self identity failed: {err}"))?;
    if seed.id == self_ref.id {
        return Ok(None);
    }
    Ok(Some(SocketAddr::new(seed.mgmt_ip, cluster_port)))
}

fn load_http_ca(cfg: &CliConfig) -> Option<Vec<u8>> {
    let path = cfg
        .http_ca_path
        .clone()
        .unwrap_or_else(|| cfg.http_tls_dir.join("ca.crt"));
    std::fs::read(path).ok()
}

fn parse_args(bin: &str, args: Vec<String>) -> Result<CliConfig, String> {
    let mut management_iface = None;
    let mut data_plane_iface = None;
    let mut dns_target_ips: Vec<Ipv4Addr> = Vec::new();
    let mut dns_target_ips_csv: Option<Vec<Ipv4Addr>> = None;
    let mut dns_upstreams: Vec<SocketAddr> = Vec::new();
    let mut dns_upstreams_csv: Option<Vec<SocketAddr>> = None;
    let mut data_plane_mode = DataPlaneMode::Soft(SoftMode::Tun);
    let mut idle_timeout_secs = DEFAULT_IDLE_TIMEOUT_SECS;
    let mut dns_allowlist_idle_secs = None;
    let mut dns_allowlist_gc_interval_secs = None;
    let mut default_policy = DefaultPolicy::Deny;
    let mut dhcp_timeout_secs = DHCP_TIMEOUT_SECS;
    let mut dhcp_retry_max = DHCP_RETRY_MAX;
    let mut dhcp_lease_min_secs = DHCP_LEASE_MIN_SECS;
    let mut internal_cidr = None;
    let mut http_bind = None;
    let mut http_advertise = None;
    let mut http_tls_dir = PathBuf::from("/var/lib/neuwerk/http-tls");
    let mut http_cert_path = None;
    let mut http_key_path = None;
    let mut http_ca_path = None;
    let mut http_tls_san: Vec<String> = Vec::new();
    let mut metrics_bind = None;
    let mut cloud_provider = CloudProviderKind::None;
    let mut snat_mode = SnatMode::Auto;
    let mut encap_mode = EncapMode::None;
    let mut encap_vni = None;
    let mut encap_vni_internal = None;
    let mut encap_vni_external = None;
    let mut encap_udp_port = None;
    let mut encap_udp_port_internal = None;
    let mut encap_udp_port_external = None;
    let mut encap_mtu: u16 = 1500;
    let mut snat_set = false;
    let mut cluster_bind = None;
    let mut cluster_join_bind = None;
    let mut cluster_advertise = None;
    let mut cluster_join = None;
    let mut cluster_data_dir = None;
    let mut node_id_path = None;
    let mut bootstrap_token_path = None;
    let mut cluster_migrate_from_local = false;
    let mut cluster_migrate_force = false;
    let mut cluster_migrate_verify = false;
    let mut integration_mode = IntegrationMode::None;
    let mut integration_route_name = INTEGRATION_ROUTE_NAME.to_string();
    let mut integration_drain_timeout_secs = INTEGRATION_DRAIN_TIMEOUT_SECS;
    let mut integration_reconcile_interval_secs = INTEGRATION_RECONCILE_INTERVAL_SECS;
    let mut integration_cluster_name = INTEGRATION_CLUSTER_NAME.to_string();
    let mut azure_subscription_id = None;
    let mut azure_resource_group = None;
    let mut azure_vmss_name = None;
    let mut aws_region = None;
    let mut aws_vpc_id = None;
    let mut aws_asg_name = None;
    let mut gcp_project = None;
    let mut gcp_region = None;
    let mut gcp_ig_name = None;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", usage(bin));
                std::process::exit(0);
            }
            _ => {}
        }

        if arg == "--management-interface" || arg.starts_with("--management-interface=") {
            let value = take_flag_value("--management-interface", &arg, &mut args)?;
            management_iface = Some(value);
            continue;
        }
        if arg == "--data-plane-interface" || arg.starts_with("--data-plane-interface=") {
            let value = take_flag_value("--data-plane-interface", &arg, &mut args)?;
            data_plane_iface = Some(value);
            continue;
        }
        if arg == "--dns-target-ip" || arg.starts_with("--dns-target-ip=") {
            let value = take_flag_value("--dns-target-ip", &arg, &mut args)?;
            dns_target_ips.push(parse_ipv4("--dns-target-ip", &value)?);
            continue;
        }
        if arg == "--dns-target-ips" || arg.starts_with("--dns-target-ips=") {
            let value = take_flag_value("--dns-target-ips", &arg, &mut args)?;
            dns_target_ips_csv = Some(parse_csv_ipv4_list("--dns-target-ips", &value)?);
            continue;
        }
        if arg == "--dns-upstream" || arg.starts_with("--dns-upstream=") {
            let value = take_flag_value("--dns-upstream", &arg, &mut args)?;
            dns_upstreams.push(parse_socket("--dns-upstream", &value)?);
            continue;
        }
        if arg == "--dns-upstreams" || arg.starts_with("--dns-upstreams=") {
            let value = take_flag_value("--dns-upstreams", &arg, &mut args)?;
            dns_upstreams_csv = Some(parse_csv_socket_list("--dns-upstreams", &value)?);
            continue;
        }
        if arg == "--dns-listen" || arg.starts_with("--dns-listen=") {
            return Err(
                "--dns-listen has been removed; DNS interception now binds on management-ip:53"
                    .to_string(),
            );
        }
        if arg == "--data-plane-mode" || arg.starts_with("--data-plane-mode=") {
            let value = take_flag_value("--data-plane-mode", &arg, &mut args)?;
            data_plane_mode = DataPlaneMode::parse(&value)?;
            continue;
        }
        if arg == "--idle-timeout-secs" || arg.starts_with("--idle-timeout-secs=") {
            let value = take_flag_value("--idle-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--idle-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--idle-timeout-secs must be >= 1".to_string());
            }
            idle_timeout_secs = parsed;
            continue;
        }
        if arg == "--dns-allowlist-idle-secs" || arg.starts_with("--dns-allowlist-idle-secs=") {
            let value = take_flag_value("--dns-allowlist-idle-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dns-allowlist-idle-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dns-allowlist-idle-secs must be >= 1".to_string());
            }
            dns_allowlist_idle_secs = Some(parsed);
            continue;
        }
        if arg == "--dns-allowlist-gc-interval-secs"
            || arg.starts_with("--dns-allowlist-gc-interval-secs=")
        {
            let value = take_flag_value("--dns-allowlist-gc-interval-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dns-allowlist-gc-interval-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dns-allowlist-gc-interval-secs must be >= 1".to_string());
            }
            dns_allowlist_gc_interval_secs = Some(parsed);
            continue;
        }
        if arg == "--default-policy" || arg.starts_with("--default-policy=") {
            let value = take_flag_value("--default-policy", &arg, &mut args)?;
            default_policy = parse_default_policy(&value)?;
            continue;
        }
        if arg == "--dhcp-timeout-secs" || arg.starts_with("--dhcp-timeout-secs=") {
            let value = take_flag_value("--dhcp-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dhcp-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dhcp-timeout-secs must be >= 1".to_string());
            }
            dhcp_timeout_secs = parsed;
            continue;
        }
        if arg == "--dhcp-retry-max" || arg.starts_with("--dhcp-retry-max=") {
            let value = take_flag_value("--dhcp-retry-max", &arg, &mut args)?;
            let parsed = value
                .parse::<u32>()
                .map_err(|_| format!("--dhcp-retry-max must be a positive integer, got {value}"))?;
            if parsed == 0 {
                return Err("--dhcp-retry-max must be >= 1".to_string());
            }
            dhcp_retry_max = parsed;
            continue;
        }
        if arg == "--dhcp-lease-min-secs" || arg.starts_with("--dhcp-lease-min-secs=") {
            let value = take_flag_value("--dhcp-lease-min-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dhcp-lease-min-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dhcp-lease-min-secs must be >= 1".to_string());
            }
            dhcp_lease_min_secs = parsed;
            continue;
        }
        if arg == "--internal-cidr" || arg.starts_with("--internal-cidr=") {
            let value = take_flag_value("--internal-cidr", &arg, &mut args)?;
            internal_cidr = Some(parse_cidr("--internal-cidr", &value)?);
            continue;
        }
        if arg == "--snat" || arg.starts_with("--snat=") {
            let value = take_flag_value("--snat", &arg, &mut args)?;
            snat_mode = match value.as_str() {
                "none" | "NONE" => SnatMode::None,
                "auto" | "AUTO" => SnatMode::Auto,
                _ => {
                    let parsed = value.parse::<Ipv4Addr>().map_err(|_| {
                        format!("--snat must be none, auto, or an IPv4 address, got {value}")
                    })?;
                    SnatMode::Static(parsed)
                }
            };
            snat_set = true;
            continue;
        }
        if arg == "--encap" || arg.starts_with("--encap=") {
            let value = take_flag_value("--encap", &arg, &mut args)?;
            encap_mode = EncapMode::parse(&value)?;
            continue;
        }
        if arg == "--encap-vni" || arg.starts_with("--encap-vni=") {
            let value = take_flag_value("--encap-vni", &arg, &mut args)?;
            encap_vni = Some(parse_vni("--encap-vni", &value)?);
            continue;
        }
        if arg == "--encap-vni-internal" || arg.starts_with("--encap-vni-internal=") {
            let value = take_flag_value("--encap-vni-internal", &arg, &mut args)?;
            encap_vni_internal = Some(parse_vni("--encap-vni-internal", &value)?);
            continue;
        }
        if arg == "--encap-vni-external" || arg.starts_with("--encap-vni-external=") {
            let value = take_flag_value("--encap-vni-external", &arg, &mut args)?;
            encap_vni_external = Some(parse_vni("--encap-vni-external", &value)?);
            continue;
        }
        if arg == "--encap-udp-port" || arg.starts_with("--encap-udp-port=") {
            let value = take_flag_value("--encap-udp-port", &arg, &mut args)?;
            encap_udp_port = Some(parse_port("--encap-udp-port", &value)?);
            continue;
        }
        if arg == "--encap-udp-port-internal" || arg.starts_with("--encap-udp-port-internal=") {
            let value = take_flag_value("--encap-udp-port-internal", &arg, &mut args)?;
            encap_udp_port_internal = Some(parse_port("--encap-udp-port-internal", &value)?);
            continue;
        }
        if arg == "--encap-udp-port-external" || arg.starts_with("--encap-udp-port-external=") {
            let value = take_flag_value("--encap-udp-port-external", &arg, &mut args)?;
            encap_udp_port_external = Some(parse_port("--encap-udp-port-external", &value)?);
            continue;
        }
        if arg == "--encap-mtu" || arg.starts_with("--encap-mtu=") {
            let value = take_flag_value("--encap-mtu", &arg, &mut args)?;
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("--encap-mtu must be a positive integer, got {value}"))?;
            if parsed == 0 {
                return Err("--encap-mtu must be >= 1".to_string());
            }
            encap_mtu = parsed;
            continue;
        }
        if arg == "--http-bind" || arg.starts_with("--http-bind=") {
            let value = take_flag_value("--http-bind", &arg, &mut args)?;
            http_bind = Some(parse_socket("--http-bind", &value)?);
            continue;
        }
        if arg == "--http-advertise" || arg.starts_with("--http-advertise=") {
            let value = take_flag_value("--http-advertise", &arg, &mut args)?;
            http_advertise = Some(parse_socket("--http-advertise", &value)?);
            continue;
        }
        if arg == "--http-tls-dir" || arg.starts_with("--http-tls-dir=") {
            let value = take_flag_value("--http-tls-dir", &arg, &mut args)?;
            http_tls_dir = PathBuf::from(value);
            continue;
        }
        if arg == "--http-cert-path" || arg.starts_with("--http-cert-path=") {
            let value = take_flag_value("--http-cert-path", &arg, &mut args)?;
            http_cert_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-key-path" || arg.starts_with("--http-key-path=") {
            let value = take_flag_value("--http-key-path", &arg, &mut args)?;
            http_key_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-ca-path" || arg.starts_with("--http-ca-path=") {
            let value = take_flag_value("--http-ca-path", &arg, &mut args)?;
            http_ca_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-tls-san" || arg.starts_with("--http-tls-san=") {
            let value = take_flag_value("--http-tls-san", &arg, &mut args)?;
            for entry in value.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    http_tls_san.push(entry.to_string());
                }
            }
            continue;
        }
        if arg == "--metrics-bind" || arg.starts_with("--metrics-bind=") {
            let value = take_flag_value("--metrics-bind", &arg, &mut args)?;
            metrics_bind = Some(parse_socket("--metrics-bind", &value)?);
            continue;
        }
        if arg == "--cloud-provider" || arg.starts_with("--cloud-provider=") {
            let value = take_flag_value("--cloud-provider", &arg, &mut args)?;
            cloud_provider = CloudProviderKind::parse(&value)?;
            continue;
        }
        if arg == "--integration" || arg.starts_with("--integration=") {
            let value = take_flag_value("--integration", &arg, &mut args)?;
            integration_mode = parse_integration_mode(&value)?;
            continue;
        }
        if arg == "--integration-route-name" || arg.starts_with("--integration-route-name=") {
            let value = take_flag_value("--integration-route-name", &arg, &mut args)?;
            integration_route_name = value;
            continue;
        }
        if arg == "--integration-drain-timeout-secs"
            || arg.starts_with("--integration-drain-timeout-secs=")
        {
            let value = take_flag_value("--integration-drain-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--integration-drain-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--integration-drain-timeout-secs must be >= 1".to_string());
            }
            integration_drain_timeout_secs = parsed;
            continue;
        }
        if arg == "--integration-reconcile-interval-secs"
            || arg.starts_with("--integration-reconcile-interval-secs=")
        {
            let value = take_flag_value("--integration-reconcile-interval-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!(
                    "--integration-reconcile-interval-secs must be a positive integer, got {value}"
                )
            })?;
            if parsed == 0 {
                return Err("--integration-reconcile-interval-secs must be >= 1".to_string());
            }
            integration_reconcile_interval_secs = parsed;
            continue;
        }
        if arg == "--integration-cluster-name" || arg.starts_with("--integration-cluster-name=") {
            let value = take_flag_value("--integration-cluster-name", &arg, &mut args)?;
            if value.trim().is_empty() {
                return Err("--integration-cluster-name must not be empty".to_string());
            }
            integration_cluster_name = value;
            continue;
        }
        if arg == "--azure-subscription-id" || arg.starts_with("--azure-subscription-id=") {
            let value = take_flag_value("--azure-subscription-id", &arg, &mut args)?;
            azure_subscription_id = Some(value);
            continue;
        }
        if arg == "--azure-resource-group" || arg.starts_with("--azure-resource-group=") {
            let value = take_flag_value("--azure-resource-group", &arg, &mut args)?;
            azure_resource_group = Some(value);
            continue;
        }
        if arg == "--azure-vmss-name" || arg.starts_with("--azure-vmss-name=") {
            let value = take_flag_value("--azure-vmss-name", &arg, &mut args)?;
            azure_vmss_name = Some(value);
            continue;
        }
        if arg == "--aws-region" || arg.starts_with("--aws-region=") {
            let value = take_flag_value("--aws-region", &arg, &mut args)?;
            aws_region = Some(value);
            continue;
        }
        if arg == "--aws-vpc-id" || arg.starts_with("--aws-vpc-id=") {
            let value = take_flag_value("--aws-vpc-id", &arg, &mut args)?;
            aws_vpc_id = Some(value);
            continue;
        }
        if arg == "--aws-asg-name" || arg.starts_with("--aws-asg-name=") {
            let value = take_flag_value("--aws-asg-name", &arg, &mut args)?;
            aws_asg_name = Some(value);
            continue;
        }
        if arg == "--gcp-project" || arg.starts_with("--gcp-project=") {
            let value = take_flag_value("--gcp-project", &arg, &mut args)?;
            gcp_project = Some(value);
            continue;
        }
        if arg == "--gcp-region" || arg.starts_with("--gcp-region=") {
            let value = take_flag_value("--gcp-region", &arg, &mut args)?;
            gcp_region = Some(value);
            continue;
        }
        if arg == "--gcp-ig-name" || arg.starts_with("--gcp-ig-name=") {
            let value = take_flag_value("--gcp-ig-name", &arg, &mut args)?;
            gcp_ig_name = Some(value);
            continue;
        }
        if arg == "--cluster-migrate-from-local" {
            cluster_migrate_from_local = true;
            continue;
        }
        if arg == "--cluster-migrate-force" {
            cluster_migrate_force = true;
            continue;
        }
        if arg == "--cluster-migrate-verify" {
            cluster_migrate_verify = true;
            continue;
        }
        if arg == "--cluster-bind" || arg.starts_with("--cluster-bind=") {
            let value = take_flag_value("--cluster-bind", &arg, &mut args)?;
            cluster_bind = Some(parse_socket("--cluster-bind", &value)?);
            continue;
        }
        if arg == "--cluster-join-bind" || arg.starts_with("--cluster-join-bind=") {
            let value = take_flag_value("--cluster-join-bind", &arg, &mut args)?;
            cluster_join_bind = Some(parse_socket("--cluster-join-bind", &value)?);
            continue;
        }
        if arg == "--cluster-advertise" || arg.starts_with("--cluster-advertise=") {
            let value = take_flag_value("--cluster-advertise", &arg, &mut args)?;
            cluster_advertise = Some(parse_socket("--cluster-advertise", &value)?);
            continue;
        }
        if arg == "--join" || arg.starts_with("--join=") {
            let value = take_flag_value("--join", &arg, &mut args)?;
            cluster_join = Some(parse_socket("--join", &value)?);
            continue;
        }
        if arg == "--cluster-data-dir" || arg.starts_with("--cluster-data-dir=") {
            let value = take_flag_value("--cluster-data-dir", &arg, &mut args)?;
            cluster_data_dir = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--node-id-path" || arg.starts_with("--node-id-path=") {
            let value = take_flag_value("--node-id-path", &arg, &mut args)?;
            node_id_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--bootstrap-token-path" || arg.starts_with("--bootstrap-token-path=") {
            let value = take_flag_value("--bootstrap-token-path", &arg, &mut args)?;
            bootstrap_token_path = Some(PathBuf::from(value));
            continue;
        }

        return Err(format!("unknown flag: {arg}"));
    }

    if let Ok(value) = env::var("NEUWERK_CLUSTER_MIGRATE") {
        if matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES") {
            cluster_migrate_from_local = true;
        }
    }

    let mut missing = Vec::new();
    if dns_target_ips_csv.is_some() && !dns_target_ips.is_empty() {
        return Err(
            "cannot combine repeated --dns-target-ip with --dns-target-ips csv form".to_string(),
        );
    }
    if dns_upstreams_csv.is_some() && !dns_upstreams.is_empty() {
        return Err(
            "cannot combine repeated --dns-upstream with --dns-upstreams csv form".to_string(),
        );
    }
    if let Some(list) = dns_target_ips_csv.take() {
        dns_target_ips = list;
    }
    if let Some(list) = dns_upstreams_csv.take() {
        dns_upstreams = list;
    }
    if management_iface.is_none() {
        missing.push("--management-interface");
    }
    if data_plane_iface.is_none() {
        missing.push("--data-plane-interface");
    }
    if dns_target_ips.is_empty() {
        missing.push("--dns-target-ip");
    }
    if dns_upstreams.is_empty() {
        missing.push("--dns-upstream");
    }

    if !missing.is_empty() {
        return Err(format!("missing required flags: {}", missing.join(", ")));
    }

    if matches!(data_plane_mode, DataPlaneMode::Soft(_)) {
        let iface = data_plane_iface.as_deref().unwrap();
        if looks_like_pci(iface) || looks_like_mac(iface) {
            return Err(
                "--data-plane-interface must be a netdev when --data-plane-mode is tun or tap"
                    .to_string(),
            );
        }
    }

    match integration_mode {
        IntegrationMode::AzureVmss => {
            if azure_subscription_id.is_none() {
                return Err(
                    "--azure-subscription-id is required for --integration azure-vmss".to_string(),
                );
            }
            if azure_resource_group.is_none() {
                return Err(
                    "--azure-resource-group is required for --integration azure-vmss".to_string(),
                );
            }
            if azure_vmss_name.is_none() {
                return Err(
                    "--azure-vmss-name is required for --integration azure-vmss".to_string()
                );
            }
        }
        IntegrationMode::AwsAsg => {
            if aws_region.is_none() {
                return Err("--aws-region is required for --integration aws-asg".to_string());
            }
            if aws_vpc_id.is_none() {
                return Err("--aws-vpc-id is required for --integration aws-asg".to_string());
            }
            if aws_asg_name.is_none() {
                return Err("--aws-asg-name is required for --integration aws-asg".to_string());
            }
        }
        IntegrationMode::GcpMig => {
            if gcp_project.is_none() {
                return Err("--gcp-project is required for --integration gcp-mig".to_string());
            }
            if gcp_region.is_none() {
                return Err("--gcp-region is required for --integration gcp-mig".to_string());
            }
            if gcp_ig_name.is_none() {
                return Err("--gcp-ig-name is required for --integration gcp-mig".to_string());
            }
        }
        IntegrationMode::None => {}
    }
    if management_iface == data_plane_iface {
        return Err(
            "--management-interface and --data-plane-interface must be different".to_string(),
        );
    }

    if !snat_set && encap_mode != EncapMode::None {
        snat_mode = SnatMode::None;
    }

    let encap_udp_port_set = encap_udp_port.is_some();
    if encap_mode == EncapMode::Vxlan && !encap_udp_port_set {
        if encap_vni_internal.is_some() && encap_udp_port_internal.is_none() {
            encap_udp_port_internal = Some(10800);
        }
        if encap_vni_external.is_some() && encap_udp_port_external.is_none() {
            encap_udp_port_external = Some(10801);
        }
    }

    let encap_udp_port = encap_udp_port.unwrap_or_else(|| match encap_mode {
        EncapMode::Geneve => 6081,
        EncapMode::Vxlan => 10800,
        EncapMode::None => 0,
    });

    let overlay = OverlayConfig {
        mode: encap_mode,
        udp_port: encap_udp_port,
        udp_port_internal: encap_udp_port_internal,
        udp_port_external: encap_udp_port_external,
        vni: encap_vni,
        vni_internal: encap_vni_internal,
        vni_external: encap_vni_external,
        mtu: encap_mtu,
    };
    overlay.validate()?;

    let dns_allowlist_idle_secs =
        dns_allowlist_idle_secs.unwrap_or(idle_timeout_secs + DNS_ALLOWLIST_IDLE_SLACK_SECS);
    let dns_allowlist_gc_interval_secs =
        dns_allowlist_gc_interval_secs.unwrap_or(DNS_ALLOWLIST_GC_INTERVAL_SECS);

    Ok(CliConfig {
        management_iface: management_iface.unwrap(),
        data_plane_iface: data_plane_iface.unwrap(),
        dns_target_ips,
        dns_upstreams,
        data_plane_mode,
        idle_timeout_secs,
        dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs,
        default_policy,
        dhcp_timeout_secs,
        dhcp_retry_max,
        dhcp_lease_min_secs,
        internal_cidr,
        snat_mode,
        encap_mode,
        encap_vni,
        encap_vni_internal,
        encap_vni_external,
        encap_udp_port: Some(encap_udp_port),
        encap_udp_port_internal,
        encap_udp_port_external,
        encap_mtu,
        http_bind,
        http_advertise,
        http_tls_dir,
        http_cert_path,
        http_key_path,
        http_ca_path,
        http_tls_san,
        metrics_bind,
        cloud_provider,
        cluster: build_cluster_config(
            cluster_bind,
            cluster_join_bind,
            cluster_advertise,
            cluster_join,
            cluster_data_dir,
            node_id_path,
            bootstrap_token_path,
        )?,
        cluster_migrate_from_local,
        cluster_migrate_force,
        cluster_migrate_verify,
        integration_mode,
        integration_route_name,
        integration_drain_timeout_secs,
        integration_reconcile_interval_secs,
        integration_cluster_name,
        azure_subscription_id,
        azure_resource_group,
        azure_vmss_name,
        aws_region,
        aws_vpc_id,
        aws_asg_name,
        gcp_project,
        gcp_region,
        gcp_ig_name,
    })
}

fn parse_duration_secs(value: &str) -> Result<i64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("ttl value is empty".to_string());
    }
    let (num, unit) = value.split_at(value.len() - 1);
    let (num, multiplier) = if num.chars().all(|c| c.is_ascii_digit()) {
        let multiplier = match unit {
            "s" | "S" => 1,
            "m" | "M" => 60,
            "h" | "H" => 60 * 60,
            "d" | "D" => 24 * 60 * 60,
            _ => {
                return value
                    .parse::<i64>()
                    .map_err(|_| format!("invalid ttl duration: {value}"));
            }
        };
        (num, multiplier)
    } else {
        return value
            .parse::<i64>()
            .map_err(|_| format!("invalid ttl duration: {value}"));
    };
    let num = num
        .parse::<i64>()
        .map_err(|_| format!("invalid ttl duration: {value}"))?;
    if num <= 0 {
        return Err("ttl must be positive".to_string());
    }
    Ok(num * multiplier)
}

fn parse_auth_args(bin: &str, args: &[String]) -> Result<AuthCommand, String> {
    let mut args = args.iter().cloned();
    let Some(section) = args.next() else {
        return Err(auth_usage(bin));
    };
    let mut cluster_addr = None;
    let mut cluster_tls_dir = None;

    let mut kid = None;
    let mut sub = None;
    let mut ttl_secs = None;

    let (mode, action) = match section.as_str() {
        "key" => (section, args.next()),
        "token" => (section, args.next()),
        _ => return Err(format!("unknown auth command: {section}")),
    };

    let action = action.ok_or_else(|| "missing auth action".to_string())?;
    let mut action_arg: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(auth_usage(bin)),
            _ => {}
        }
        if arg == "--cluster-addr" || arg.starts_with("--cluster-addr=") {
            let value = take_flag_value("--cluster-addr", &arg, &mut args)?;
            cluster_addr = Some(parse_socket("--cluster-addr", &value)?);
            continue;
        }
        if arg == "--cluster-tls-dir" || arg.starts_with("--cluster-tls-dir=") {
            let value = take_flag_value("--cluster-tls-dir", &arg, &mut args)?;
            cluster_tls_dir = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--sub" || arg.starts_with("--sub=") {
            let value = take_flag_value("--sub", &arg, &mut args)?;
            sub = Some(value);
            continue;
        }
        if arg == "--ttl" || arg.starts_with("--ttl=") {
            let value = take_flag_value("--ttl", &arg, &mut args)?;
            ttl_secs = Some(parse_duration_secs(&value)?);
            continue;
        }
        if arg == "--kid" || arg.starts_with("--kid=") {
            let value = take_flag_value("--kid", &arg, &mut args)?;
            kid = Some(value);
            continue;
        }
        if action_arg.is_none() {
            action_arg = Some(arg);
            continue;
        }
        return Err(format!("unknown auth flag: {arg}"));
    }

    let addr = cluster_addr.ok_or_else(|| "missing --cluster-addr".to_string())?;
    let tls_dir = cluster_tls_dir.unwrap_or_else(|| PathBuf::from("/var/lib/neuwerk/cluster/tls"));

    match mode.as_str() {
        "key" => match action.as_str() {
            "rotate" => Ok(AuthCommand::KeyRotate { addr, tls_dir }),
            "list" => Ok(AuthCommand::KeyList { addr, tls_dir }),
            "retire" => {
                let kid = action_arg.ok_or_else(|| "missing kid".to_string())?;
                Ok(AuthCommand::KeyRetire { addr, tls_dir, kid })
            }
            _ => Err(format!("unknown auth key action: {action}")),
        },
        "token" => match action.as_str() {
            "mint" => {
                let sub = sub.ok_or_else(|| "missing --sub".to_string())?;
                Ok(AuthCommand::TokenMint {
                    addr,
                    tls_dir,
                    sub,
                    ttl_secs,
                    kid,
                })
            }
            _ => Err(format!("unknown auth token action: {action}")),
        },
        _ => Err(format!("unknown auth command: {mode}")),
    }
}

async fn run_auth_command(cmd: AuthCommand) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, tls_dir) = match &cmd {
        AuthCommand::KeyRotate { addr, tls_dir }
        | AuthCommand::KeyList { addr, tls_dir }
        | AuthCommand::KeyRetire { addr, tls_dir, .. }
        | AuthCommand::TokenMint { addr, tls_dir, .. } => (addr, tls_dir),
    };
    let tls = RaftTlsConfig::load(tls_dir.clone())?;
    let mut client = AuthClient::connect(*addr, tls).await?;

    match cmd {
        AuthCommand::KeyRotate { .. } => {
            let key = client.rotate_key().await?;
            println!(
                "rotated key: {} (created {}, status {:?})",
                key.kid, key.created_at, key.status
            );
        }
        AuthCommand::KeyList { .. } => {
            let (active_kid, keys) = client.list_keys().await?;
            println!("active kid: {active_kid}");
            for key in keys {
                let active = if key.signing { "signing" } else { "" };
                println!(
                    "kid: {} status: {:?} created: {} {}",
                    key.kid, key.status, key.created_at, active
                );
            }
        }
        AuthCommand::KeyRetire { kid, .. } => {
            client.retire_key(&kid).await?;
            println!("retired key: {kid}");
        }
        AuthCommand::TokenMint {
            sub, ttl_secs, kid, ..
        } => {
            let ttl = ttl_secs.or(Some(DEFAULT_TTL_SECS));
            let (token, _kid, _exp) = client.mint_token(&sub, ttl, kid.as_deref()).await?;
            println!("{token}");
        }
    }
    Ok(())
}

fn build_cluster_config(
    bind: Option<SocketAddr>,
    join_bind: Option<SocketAddr>,
    advertise: Option<SocketAddr>,
    join: Option<SocketAddr>,
    data_dir: Option<PathBuf>,
    node_id_path: Option<PathBuf>,
    token_path: Option<PathBuf>,
) -> Result<controlplane::cluster::config::ClusterConfig, String> {
    let enabled = bind.is_some()
        || join_bind.is_some()
        || advertise.is_some()
        || join.is_some()
        || data_dir.is_some()
        || node_id_path.is_some()
        || token_path.is_some();

    if !enabled {
        return Ok(controlplane::cluster::config::ClusterConfig::disabled());
    }

    let mut cfg = controlplane::cluster::config::ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.bind_addr = bind.unwrap_or(cfg.bind_addr);
    cfg.join_bind_addr = join_bind
        .unwrap_or_else(|| controlplane::cluster::config::default_join_bind(cfg.bind_addr));
    cfg.advertise_addr = advertise.unwrap_or(cfg.bind_addr);
    cfg.join_seed = join;
    cfg.data_dir = data_dir.unwrap_or(cfg.data_dir);
    cfg.node_id_path = node_id_path.unwrap_or(cfg.node_id_path);
    cfg.token_path = token_path.unwrap_or(cfg.token_path);
    Ok(cfg)
}

async fn management_ipv4(iface: &str) -> Result<Ipv4Addr, String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);
    let index = get_link_index(&handle, iface).await?;
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr lookup {iface} failed: {err}"))?
    {
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        task.abort();
                        return Ok(v4);
                    }
                }
                _ => {}
            }
        }
    }
    task.abort();
    Err(format!("no IPv4 address for interface {iface}"))
}

async fn dataplane_ipv4_config(iface: &str) -> Result<(Ipv4Addr, u8, [u8; 6]), String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);
    let index = get_link_index(&handle, iface).await?;

    let mut mac = [0u8; 6];
    let mut links = handle.link().get().match_index(index).execute();
    if let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link lookup {iface} failed: {err}"))?
    {
        for nla in msg.attributes {
            if let LinkAttribute::Address(addr) = nla {
                if addr.len() >= 6 {
                    mac.copy_from_slice(&addr[..6]);
                }
            }
        }
    }

    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr lookup {iface} failed: {err}"))?
    {
        let prefix = msg.header.prefix_len;
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        task.abort();
                        return Ok((v4, prefix, mac));
                    }
                }
                _ => {}
            }
        }
    }
    task.abort();
    Err(format!("no IPv4 address for interface {iface}"))
}

async fn internal_ipv4_config(
    management_iface: &str,
    data_plane_iface: &str,
) -> Result<(Ipv4Addr, u8), String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);

    let mut link_names: HashMap<u32, String> = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link list failed: {err}"))?
    {
        let mut name = None;
        for nla in msg.attributes {
            if let LinkAttribute::IfName(value) = nla {
                name = Some(value);
                break;
            }
        }
        if let Some(name) = name {
            link_names.insert(msg.header.index, name);
        }
    }

    let mut candidates: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr list failed: {err}"))?
    {
        let ifname = match link_names.get(&msg.header.index) {
            Some(name) => name.as_str(),
            None => continue,
        };
        if ifname == "lo" || ifname == management_iface || ifname == data_plane_iface {
            continue;
        }
        if ifname.contains("mgmt") {
            continue;
        }
        let prefix = msg.header.prefix_len;
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        if is_private_ipv4(v4) {
                            candidates.push((v4, prefix));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    task.abort();

    if let Some(choice) = pick_private_candidate(&candidates) {
        return Ok(choice);
    }

    Err("no private IPv4 address found for internal network".to_string())
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets {
        [10, ..] => true,
        [172, b, ..] if (16..=31).contains(&b) => true,
        [192, 168, ..] => true,
        _ => false,
    }
}

fn pick_private_candidate(candidates: &[(Ipv4Addr, u8)]) -> Option<(Ipv4Addr, u8)> {
    for (ip, prefix) in candidates {
        if ip.octets()[0] == 10 {
            return Some((*ip, *prefix));
        }
    }
    for (ip, prefix) in candidates {
        let [a, b, ..] = ip.octets();
        if a == 172 && (16..=31).contains(&b) {
            return Some((*ip, *prefix));
        }
    }
    for (ip, prefix) in candidates {
        let [a, b, ..] = ip.octets();
        if a == 192 && b == 168 {
            return Some((*ip, *prefix));
        }
    }
    None
}

async fn get_link_index(handle: &rtnetlink::Handle, link_name: &str) -> Result<u32, String> {
    let mut links = handle
        .link()
        .get()
        .match_name(link_name.to_string())
        .execute();
    if let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link lookup {link_name} failed: {err}"))?
    {
        return Ok(msg.header.index);
    }
    Err(format!("link not found: {link_name}"))
}

fn run_dataplane(
    data_plane_iface: String,
    data_plane_mode: DataPlaneMode,
    idle_timeout_secs: u64,
    policy: Arc<RwLock<PolicySnapshot>>,
    policy_applied_generation: Arc<AtomicU64>,
    service_policy_applied_generation: Arc<AtomicU64>,
    dns_allowlist: DynamicIpSetV4,
    dns_target_ips: Vec<Ipv4Addr>,
    wiretap_emitter: Option<WiretapEmitter>,
    audit_emitter: Option<AuditEmitter>,
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    public_ip: Ipv4Addr,
    snat_mode: SnatMode,
    overlay: OverlayConfig,
    data_port: u16,
    dataplane_config: DataplaneConfigStore,
    drain_control: Option<DrainControl>,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    shared_intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    metrics: controlplane::metrics::Metrics,
) -> Result<(), String> {
    let observer_policy = policy.clone();
    let observer_applied = policy_applied_generation.clone();
    std::thread::Builder::new()
        .name("policy-generation-observer".to_string())
        .spawn(move || {
            let mut last = observer_applied.load(Ordering::Acquire);
            loop {
                let generation = match observer_policy.read() {
                    Ok(lock) => lock.generation(),
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };
                if generation != last {
                    observer_applied.store(generation, Ordering::Release);
                    last = generation;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })
        .map_err(|err| format!("policy observer start failed: {err}"))?;
    let mut state = EngineState::new_with_idle_timeout(
        policy,
        internal_net,
        internal_prefix,
        public_ip,
        data_port,
        idle_timeout_secs,
    );
    state.set_snat_mode(snat_mode);
    state.set_overlay_config(overlay);
    state.set_dns_allowlist(dns_allowlist);
    state.set_dns_target_ips(dns_target_ips);
    state.set_dataplane_config(dataplane_config);
    state.set_service_policy_applied_generation(service_policy_applied_generation);
    if let Some(control) = drain_control {
        state.set_drain_control(control);
    }
    let metrics_for_state = metrics.clone();
    state.set_metrics(metrics_for_state);
    if let Some(emitter) = wiretap_emitter {
        state.set_wiretap_emitter(emitter);
    }
    if let Some(emitter) = audit_emitter {
        state.set_audit_emitter(emitter);
    }

    match data_plane_mode {
        DataPlaneMode::Soft(mode) => {
            let mut adapter = SoftAdapter::new(data_plane_iface, mode)?;
            adapter.run(&mut state)
        }
        DataPlaneMode::Dpdk => {
            let requested_workers = std::env::var("NEUWERK_DPDK_WORKERS")
                .ok()
                .and_then(|val| val.parse::<usize>().ok())
                .unwrap_or(1)
                .max(1);
            let max_workers = cpu_core_count();
            let requested_workers = requested_workers.min(max_workers);
            eprintln!(
                "dpdk: worker config requested={}, cpu_cores={}, using={}",
                std::env::var("NEUWERK_DPDK_WORKERS").unwrap_or_else(|_| "unset".to_string()),
                max_workers,
                requested_workers
            );
            let effective_queues = if requested_workers > 1 {
                match DpdkIo::effective_queue_count(&data_plane_iface, requested_workers as u16) {
                    Ok(effective) => effective as usize,
                    Err(err) => {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                }
            } else {
                1
            };
            let plan =
                match choose_dpdk_worker_plan(requested_workers, max_workers, effective_queues) {
                    Ok(plan) => plan,
                    Err(err) => {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                };
            if plan.worker_count < plan.requested {
                eprintln!(
                    "dpdk: reducing worker threads to {} (device queue limit)",
                    plan.worker_count
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::SharedRxDemux) {
                eprintln!(
                    "dpdk: single rx queue detected (effective_queues={}), enabling shared-rx software demux across {} workers",
                    plan.effective_queues, plan.worker_count
                );
            }
            if matches!(plan.mode, DpdkWorkerMode::Single) {
                let iface = data_plane_iface.clone();
                let mut adapter = DpdkAdapter::new(data_plane_iface)?;
                if let Some(publisher) = mac_publisher {
                    adapter.set_mac_publisher(publisher);
                }
                if let Some(tx) = dhcp_tx {
                    adapter.set_dhcp_tx(tx);
                }
                if let Some(rx) = dhcp_rx {
                    adapter.set_dhcp_rx(rx);
                }
                adapter.set_shared_intercept_demux(shared_intercept_demux);
                let mut io = match DpdkIo::new(&iface, Some(metrics.clone())) {
                    Ok(io) => {
                        metrics.set_dpdk_init_ok(true);
                        io
                    }
                    Err(err) => {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                };
                adapter.run_with_io(&mut state, &mut io)
            } else {
                let worker_count = plan.worker_count;
                let queue_per_worker = matches!(plan.mode, DpdkWorkerMode::QueuePerWorker);
                let shared_rx_demux = matches!(plan.mode, DpdkWorkerMode::SharedRxDemux);
                eprintln!(
                    "dpdk: starting {} worker threads (mode={:?})",
                    worker_count, plan.mode
                );
                let shard_count = std::env::var("NEUWERK_DPDK_STATE_SHARDS")
                    .ok()
                    .and_then(|val| val.parse::<usize>().ok())
                    .unwrap_or(worker_count)
                    .max(1);
                eprintln!("dpdk: state shards={}", shard_count);
                let base_state = state;
                let mut shard_states = Vec::with_capacity(shard_count);
                for shard_id in 0..shard_count {
                    let mut shard = base_state.clone_for_shard();
                    shard.set_shard_id(shard_id);
                    shard_states.push(std::sync::Mutex::new(shard));
                }
                let state = std::sync::Arc::new(shard_states);
                let shared_arp = Arc::new(Mutex::new(SharedArpState::default()));
                let mut dhcp_rx = dhcp_rx;
                let shared_io = if queue_per_worker {
                    None
                } else {
                    Some(Arc::new(Mutex::new(DpdkIo::new_with_queue(
                        &data_plane_iface,
                        0,
                        plan.effective_queues as u16,
                        Some(metrics.clone()),
                    )?)))
                };
                let (flow_steer_txs, mut flow_steer_rxs) = if shared_rx_demux {
                    let mut txs = Vec::with_capacity(worker_count);
                    let mut rxs = Vec::with_capacity(worker_count);
                    for _ in 0..worker_count {
                        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1024);
                        txs.push(tx);
                        rxs.push(Some(rx));
                    }
                    (Some(Arc::new(txs)), Some(rxs))
                } else {
                    (None, None)
                };
                let service_lane_ready_shared = Arc::new(AtomicBool::new(false));
                let mut handles = Vec::with_capacity(worker_count);
                for worker_id in 0..worker_count {
                    let iface = data_plane_iface.clone();
                    let metrics = metrics.clone();
                    let state = std::sync::Arc::clone(&state);
                    let shared_arp = Arc::clone(&shared_arp);
                    let shared_intercept_demux = Arc::clone(&shared_intercept_demux);
                    let dhcp_tx = dhcp_tx.clone();
                    let dhcp_rx = if worker_id == 0 { dhcp_rx.take() } else { None };
                    let shared_io = shared_io.clone();
                    let flow_steer_tx = flow_steer_txs.clone();
                    let flow_steer_rx = flow_steer_rxs
                        .as_mut()
                        .and_then(|rxs| rxs.get_mut(worker_id))
                        .and_then(Option::take);
                    let service_lane_ready_shared = service_lane_ready_shared.clone();
                    let mac_publisher = if worker_id == 0 {
                        mac_publisher.clone()
                    } else {
                        None
                    };
                    let core_count = max_workers.max(1);
                    let core_id = worker_id % core_count;
                    let handle = std::thread::Builder::new()
                        .name(format!("dpdk-worker-{worker_id}"))
                        .spawn(move || -> Result<(), String> {
                            let housekeeping_shard_idx = worker_id % state.len();
                            if let Err(err) = pin_thread_to_core(core_id) {
                                eprintln!(
                                    "dpdk: worker {} failed to pin to core {}: {}",
                                    worker_id, core_id, err
                                );
                            } else {
                                eprintln!("dpdk: worker {} pinned to core {}", worker_id, core_id);
                            }
                            let mut adapter = DpdkAdapter::new(iface.clone())?;
                            if let Some(publisher) = mac_publisher {
                                adapter.set_mac_publisher(publisher);
                            }
                            adapter.set_shared_arp(shared_arp);
                            adapter.set_shared_intercept_demux(shared_intercept_demux);
                            if let Some(tx) = dhcp_tx {
                                adapter.set_dhcp_tx(tx);
                            }
                            if let Some(rx) = dhcp_rx {
                                adapter.set_dhcp_rx(rx);
                            }
                            let mut io = if let Some(shared) = shared_io {
                                DpdkWorkerIo::Shared(shared)
                            } else {
                                DpdkWorkerIo::Dedicated(DpdkIo::new_with_queue(
                                    &iface,
                                    worker_id as u16,
                                    worker_count as u16,
                                    Some(metrics.clone()),
                                )?)
                            };
                            if let Some(mac) = io.mac() {
                                adapter.set_mac(mac);
                            }
                            let mut pkt = Packet::new(vec![0u8; 65536]);
                            loop {
                                let service_lane_ready = if worker_id == 0 {
                                    let ready = adapter.service_lane_ready();
                                    service_lane_ready_shared.store(ready, Ordering::Release);
                                    ready
                                } else {
                                    service_lane_ready_shared.load(Ordering::Acquire)
                                };
                                let mut from_steer_queue = false;
                                if let Some(rx) = flow_steer_rx.as_ref() {
                                    match rx.try_recv() {
                                        Ok(frame) => {
                                            pkt = Packet::from_bytes(&frame);
                                            from_steer_queue = true;
                                        }
                                        Err(std::sync::mpsc::TryRecvError::Empty) => {}
                                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                            return Err(
                                                "dpdk: flow steer channel disconnected".to_string()
                                            );
                                        }
                                    }
                                }
                                if !from_steer_queue {
                                    pkt.prepare_for_rx(65536);
                                    let n = io.recv_frame(pkt.buffer_mut())?;
                                    if n == 0 {
                                        io.flush()?;
                                        if worker_id == 0 {
                                            let guard =
                                                state.get(housekeeping_shard_idx).ok_or_else(
                                                    || "dpdk: state shard missing".to_string(),
                                                )?;
                                            let guard = guard.lock().map_err(|_| {
                                                "dpdk: state lock poisoned".to_string()
                                            })?;
                                            adapter.drain_service_lane_egress(&guard, &mut io)?;
                                        }
                                        adapter.flush_host_frames(&mut io)?;
                                        if worker_id == 0 {
                                            while let Some(out) = {
                                                let guard =
                                                    state.get(housekeeping_shard_idx).ok_or_else(
                                                        || "dpdk: state shard missing".to_string(),
                                                    )?;
                                                let mut guard = guard.lock().map_err(|_| {
                                                    "dpdk: state lock poisoned".to_string()
                                                })?;
                                                adapter.next_dhcp_frame(&mut guard)
                                            } {
                                                io.send_frame(&out)?;
                                            }
                                        }
                                        continue;
                                    }
                                    pkt.truncate(n);
                                    if flow_steer_tx.is_some() {
                                        let owner = shared_demux_owner_for_packet(
                                            &pkt,
                                            state.len(),
                                            worker_count,
                                        );
                                        if owner != worker_id {
                                            let payload = pkt.buffer().to_vec();
                                            flow_steer_tx
                                                .as_ref()
                                                .ok_or_else(|| {
                                                    "dpdk: flow steer tx missing".to_string()
                                                })?
                                                .get(owner)
                                                .ok_or_else(|| {
                                                    "dpdk: flow steer worker missing".to_string()
                                                })?
                                                .send(payload)
                                                .map_err(|_| {
                                                    "dpdk: flow steer dispatch failed".to_string()
                                                })?;
                                            continue;
                                        }
                                    }
                                }
                                if let Some(out) = {
                                    let shard_idx = shard_index_for_packet(&pkt, state.len());
                                    let shard = state
                                        .get(shard_idx)
                                        .ok_or_else(|| "dpdk: state shard missing".to_string())?;
                                    let mut guard = match shard.try_lock() {
                                        Ok(guard) => guard,
                                        Err(std::sync::TryLockError::Poisoned(_)) => {
                                            return Err("dpdk: state lock poisoned".to_string());
                                        }
                                        Err(std::sync::TryLockError::WouldBlock) => {
                                            metrics.inc_dp_state_lock_contended();
                                            let start = Instant::now();
                                            let guard = shard.lock().map_err(|_| {
                                                "dpdk: state lock poisoned".to_string()
                                            })?;
                                            metrics.observe_dp_state_lock_wait(start.elapsed());
                                            guard
                                        }
                                    };
                                    guard.set_intercept_to_host_steering(service_lane_ready);
                                    adapter.process_packet_in_place(&mut pkt, &mut guard)
                                } {
                                    match out {
                                        FrameOut::Borrowed(frame) => io.send_frame(frame)?,
                                        FrameOut::Owned(frame) => io.send_frame(&frame)?,
                                    }
                                }
                                if worker_id == 0 {
                                    let guard = state
                                        .get(housekeeping_shard_idx)
                                        .ok_or_else(|| "dpdk: state shard missing".to_string())?;
                                    let guard = guard
                                        .lock()
                                        .map_err(|_| "dpdk: state lock poisoned".to_string())?;
                                    adapter.drain_service_lane_egress(&guard, &mut io)?;
                                }
                                adapter.flush_host_frames(&mut io)?;
                                if worker_id == 0 {
                                    while let Some(out) = {
                                        let guard =
                                            state.get(housekeeping_shard_idx).ok_or_else(|| {
                                                "dpdk: state shard missing".to_string()
                                            })?;
                                        let mut guard = guard
                                            .lock()
                                            .map_err(|_| "dpdk: state lock poisoned".to_string())?;
                                        adapter.next_dhcp_frame(&mut guard)
                                    } {
                                        io.send_frame(&out)?;
                                    }
                                }
                            }
                        })
                        .map_err(|err| format!("dpdk worker start failed: {err}"))?;
                    handles.push(handle);
                }
                metrics.set_dpdk_init_ok(true);
                for handle in handles {
                    if let Err(err) = handle
                        .join()
                        .map_err(|_| "dpdk worker panicked".to_string())?
                    {
                        metrics.set_dpdk_init_ok(false);
                        metrics.inc_dpdk_init_failure();
                        return Err(err);
                    }
                }
                Ok(())
            }
        }
    }
}

fn boxed_error(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::Other, msg.into()).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = env::args().next().unwrap_or_else(|| "firewall".to_string());
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(|arg| arg.as_str()) == Some("auth") {
        let cmd = match parse_auth_args(&bin, &args[1..]) {
            Ok(cmd) => cmd,
            Err(err) => {
                eprintln!("{err}\n\n{}", auth_usage(&bin));
                std::process::exit(2);
            }
        };
        if let Err(err) = run_auth_command(cmd).await {
            eprintln!("{err}");
            std::process::exit(2);
        }
        return Ok(());
    }

    let mut cfg = match parse_args(&bin, args) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}\n\n{}", usage(&bin));
            std::process::exit(2);
        }
    };
    if cfg.cloud_provider != CloudProviderKind::None {
        std::env::set_var("NEUWERK_CLOUD_PROVIDER", cfg.cloud_provider.as_str());
    }

    let integration_provider = build_integration_provider(&cfg);
    if cfg.integration_mode != IntegrationMode::None
        && cfg.cluster.enabled
        && cfg.cluster.join_seed.is_none()
    {
        if let Some(provider) = integration_provider.clone() {
            let filter = integration_tag_filter(&cfg);
            match select_integration_seed(provider, &filter, cfg.cluster.bind_addr.port()).await {
                Ok(seed) => {
                    if let Some(seed) = seed {
                        cfg.cluster.join_seed = Some(seed);
                    }
                }
                Err(err) => {
                    eprintln!("integration seed selection failed: {err}");
                }
            }
        }
    }

    println!("firewall starting");
    println!("management interface: {}", cfg.management_iface);
    println!("data plane interface: {}", cfg.data_plane_iface);
    println!("data plane mode: {:?}", cfg.data_plane_mode);
    println!("idle timeout (secs): {}", cfg.idle_timeout_secs);
    println!("dns allowlist idle (secs): {}", cfg.dns_allowlist_idle_secs);
    println!(
        "dns allowlist gc interval (secs): {}",
        cfg.dns_allowlist_gc_interval_secs
    );
    println!("default policy: {:?}", cfg.default_policy);
    println!("dns targets: {:?}", cfg.dns_target_ips);
    println!("dns upstreams: {:?}", cfg.dns_upstreams);
    println!("cloud provider: {:?}", cfg.cloud_provider);
    if cfg.cluster.enabled {
        println!("cluster bind: {}", cfg.cluster.bind_addr);
        println!("cluster join bind: {}", cfg.cluster.join_bind_addr);
        println!("cluster advertise: {}", cfg.cluster.advertise_addr);
        if let Some(seed) = cfg.cluster.join_seed {
            println!("cluster join seed: {seed}");
        }
    }
    println!("integration mode: {:?}", cfg.integration_mode);
    if cfg.integration_mode != IntegrationMode::None {
        println!("integration route name: {}", cfg.integration_route_name);
        println!(
            "integration drain timeout (secs): {}",
            cfg.integration_drain_timeout_secs
        );
        println!(
            "integration reconcile interval (secs): {}",
            cfg.integration_reconcile_interval_secs
        );
        println!("integration cluster name: {}", cfg.integration_cluster_name);
    }
    println!("snat mode: {:?}", cfg.snat_mode);
    if cfg.encap_mode != EncapMode::None {
        println!("encap mode: {:?}", cfg.encap_mode);
        if let Some(vni) = cfg.encap_vni {
            println!("encap vni: {vni}");
        }
        if let Some(vni) = cfg.encap_vni_internal {
            println!("encap vni internal: {vni}");
        }
        if let Some(vni) = cfg.encap_vni_external {
            println!("encap vni external: {vni}");
        }
        if let Some(port) = cfg.encap_udp_port {
            println!("encap udp port: {port}");
        }
        if let Some(port) = cfg.encap_udp_port_internal {
            println!("encap udp port internal: {port}");
        }
        if let Some(port) = cfg.encap_udp_port_external {
            println!("encap udp port external: {port}");
        }
        println!("encap mtu: {}", cfg.encap_mtu);
    }
    if let Some((net, prefix)) = cfg.internal_cidr {
        println!("internal cidr: {net}/{prefix}");
    }

    let dpdk_enabled = matches!(cfg.data_plane_mode, DataPlaneMode::Dpdk);
    if dpdk_enabled && matches!(cfg.snat_mode, SnatMode::Static(_)) {
        eprintln!("--snat <ipv4> is only supported in software dataplane mode");
        std::process::exit(2);
    }
    let soft_dp_config = if dpdk_enabled || matches!(cfg.snat_mode, SnatMode::Static(_)) {
        None
    } else {
        dataplane_ipv4_config(&cfg.data_plane_iface).await.ok()
    };

    let management_ip = match management_ipv4(&cfg.management_iface).await {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("management interface ip error: {err}");
            std::process::exit(2);
        }
    };
    let http_bind = cfg
        .http_bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(management_ip), 8443));
    let http_advertise = cfg.http_advertise.unwrap_or(http_bind);
    let metrics_bind = cfg
        .metrics_bind
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(management_ip), 8080));

    println!("http bind: {http_bind}");
    println!("http advertise: {http_advertise}");
    println!("metrics bind: {metrics_bind}");

    // TODO: wire dataplane network parameters via CLI or config.
    let (internal_net, internal_prefix) = cfg.internal_cidr.unwrap_or((Ipv4Addr::UNSPECIFIED, 32));
    let public_ip = match cfg.snat_mode {
        SnatMode::Static(ip) => ip,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let data_port = 0;
    let overlay = OverlayConfig {
        mode: cfg.encap_mode,
        udp_port: cfg.encap_udp_port.unwrap_or(0),
        udp_port_internal: cfg.encap_udp_port_internal,
        udp_port_external: cfg.encap_udp_port_external,
        vni: cfg.encap_vni,
        vni_internal: cfg.encap_vni_internal,
        vni_external: cfg.encap_vni_external,
        mtu: cfg.encap_mtu,
    };

    let dataplane_config = DataplaneConfigStore::new();
    let policy_store = PolicyStore::new_with_config(
        cfg.default_policy,
        internal_net,
        internal_prefix,
        dataplane_config.clone(),
    );
    if let Some((ip, prefix, mac)) = soft_dp_config {
        dataplane_config.set(firewall::dataplane::DataplaneConfig {
            ip,
            prefix,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac,
            lease_expiry: None,
        });
    }

    if dpdk_enabled && dataplane_config.get().is_none() {
        match imds_dataplane_from_mgmt_ip(management_ip).await {
            Ok((ip, prefix, gateway, mac)) => {
                dataplane_config.set(firewall::dataplane::DataplaneConfig {
                    ip,
                    prefix,
                    gateway,
                    mac,
                    lease_expiry: None,
                });
                eprintln!(
                    "dpdk imds bootstrap: set dataplane config ip={}, prefix={}, gateway={}",
                    ip, prefix, gateway
                );
            }
            Err(err) => {
                eprintln!("dpdk imds bootstrap failed: {err}");
            }
        }
    }

    if !dpdk_enabled && cfg.internal_cidr.is_none() {
        if let Ok((ip, prefix)) =
            internal_ipv4_config(&cfg.management_iface, &cfg.data_plane_iface).await
        {
            let _ = policy_store.update_internal_cidr(ip, prefix);
        } else {
            eprintln!("warning: internal CIDR not detected; rely on policy source groups");
        }
    }

    if !dpdk_enabled && soft_dp_config.is_none() && matches!(cfg.snat_mode, SnatMode::Auto) {
        let iface = cfg.data_plane_iface.clone();
        let dataplane_config = dataplane_config.clone();
        tokio::spawn(async move {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match dataplane_ipv4_config(&iface).await {
                    Ok((ip, prefix, mac)) => {
                        dataplane_config.set(firewall::dataplane::DataplaneConfig {
                            ip,
                            prefix,
                            gateway: Ipv4Addr::UNSPECIFIED,
                            mac,
                            lease_expiry: None,
                        });
                        break;
                    }
                    Err(err) => {
                        if Instant::now() >= deadline {
                            eprintln!("dataplane interface ip error: {err}");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
    let local_policy_store =
        PolicyDiskStore::new(PathBuf::from("/var/lib/neuwerk/local-policy-store"));
    let local_service_accounts_dir = PathBuf::from("/var/lib/neuwerk/service-accounts");
    if !cfg.cluster.enabled {
        if let Ok(Some(active_id)) = local_policy_store.active_id() {
            match local_policy_store.read_record(active_id) {
                Ok(Some(record)) if record.mode.is_active() => {
                    if let Err(err) =
                        policy_store.rebuild_from_config_with_mode(record.policy, record.mode)
                    {
                        eprintln!("local policy error: {err}");
                        std::process::exit(2);
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    eprintln!("local policy read error: {err}");
                    std::process::exit(2);
                }
            }
        }
    }
    let dns_allowlist = policy_store.dns_allowlist();
    let dns_policy = policy_store.dns_policy();
    let dns_allowlist_for_dns = dns_allowlist.clone();
    let dns_allowlist_for_gc = dns_allowlist.clone();
    let dns_allowlist_for_dp = dns_allowlist.clone();
    let dns_upstreams = cfg.dns_upstreams.clone();
    let dns_listen = SocketAddr::new(IpAddr::V4(management_ip), 53);
    let service_lane_iface = "svc0".to_string();
    let service_lane_ip = Ipv4Addr::new(169, 254, 255, 1);
    let service_lane_prefix = 30u8;
    let policy_applied_generation = policy_store.policy_applied_tracker();
    let service_policy_snapshot = policy_store.snapshot();
    let service_policy_applied_generation = policy_store.service_policy_applied_tracker();
    let dns_map = DnsMap::new();
    let wiretap_hub = WiretapHub::new(1024);
    let metrics = match controlplane::metrics::Metrics::new() {
        Ok(metrics) => metrics,
        Err(err) => {
            eprintln!("metrics init error: {err}");
            std::process::exit(2);
        }
    };
    if dpdk_enabled {
        match firewall::dataplane::preinit_dpdk_eal(&cfg.data_plane_iface) {
            Ok(()) => {
                metrics.set_dpdk_init_ok(true);
            }
            Err(err) => {
                metrics.set_dpdk_init_ok(false);
                metrics.inc_dpdk_init_failure();
                eprintln!("dpdk preinit failed: {err}");
                std::process::exit(2);
            }
        }
    }
    let node_id = match load_or_create_node_id(&cfg.cluster.node_id_path) {
        Ok(node_id) => node_id,
        Err(err) => {
            eprintln!("node id error: {err}");
            std::process::exit(2);
        }
    };
    let node_uuid = match uuid::Uuid::parse_str(node_id.trim()) {
        Ok(node_id) => node_id,
        Err(err) => {
            eprintln!("node id error: {err}");
            std::process::exit(2);
        }
    };
    let audit_store = AuditStore::new(
        PathBuf::from("/var/lib/neuwerk/audit-store"),
        DEFAULT_AUDIT_STORE_MAX_BYTES,
    );
    let (wiretap_tx, mut wiretap_rx) = tokio::sync::mpsc::channel(1024);
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(4096);
    let wiretap_emitter = WiretapEmitter::new(wiretap_tx, DEFAULT_WIRETAP_REPORT_INTERVAL_SECS);
    let audit_emitter = AuditEmitter::new(audit_tx, DEFAULT_AUDIT_REPORT_INTERVAL_SECS);
    let hub_for_wiretap = wiretap_hub.clone();
    let dns_map_for_wiretap = dns_map.clone();
    let dns_map_for_dns = dns_map.clone();
    let dns_map_for_gc = dns_map.clone();
    let dns_map_for_http = dns_map.clone();
    let dns_map_for_audit = dns_map.clone();
    let audit_store_for_events = audit_store.clone();
    let policy_store_for_audit = policy_store.clone();
    let node_id_for_wiretap = node_id.clone();
    let node_id_for_audit = node_id.clone();
    let _wiretap_task = std::thread::Builder::new()
        .name("wiretap-bridge".to_string())
        .spawn(move || {
            while let Some(event) = wiretap_rx.blocking_recv() {
                let hostname = dns_map_for_wiretap.lookup(event.dst_ip);
                let enriched = controlplane::wiretap::WiretapEvent::from_dataplane(
                    event,
                    hostname,
                    &node_id_for_wiretap,
                );
                hub_for_wiretap.publish(enriched);
            }
            eprintln!("wiretap: bridge stopped (all senders dropped)");
        })
        .map_err(|err| boxed_error(format!("wiretap bridge thread failed to start: {err}")))?;
    let _audit_task = std::thread::Builder::new()
        .name("audit-bridge".to_string())
        .spawn(move || {
            while let Some(event) = audit_rx.blocking_recv() {
                let fqdn = dns_map_for_audit.lookup(event.dst_ip);
                let finding_type = match event.event_type {
                    AuditEventType::L4Deny => AuditFindingType::L4Deny,
                    AuditEventType::TlsDeny => AuditFindingType::TlsDeny,
                    AuditEventType::IcmpDeny => AuditFindingType::IcmpDeny,
                };
                let enriched = ControlplaneAuditEvent {
                    finding_type,
                    source_group: event.source_group,
                    hostname: None,
                    dst_ip: Some(event.dst_ip),
                    dst_port: Some(event.dst_port),
                    proto: Some(event.proto),
                    fqdn,
                    sni: event.sni,
                    icmp_type: event.icmp_type,
                    icmp_code: event.icmp_code,
                    query_type: None,
                    observed_at: event.observed_at,
                };
                audit_store_for_events.ingest(
                    enriched,
                    policy_store_for_audit.active_policy_id(),
                    &node_id_for_audit,
                );
            }
            eprintln!("audit: bridge stopped (all senders dropped)");
        })
        .map_err(|err| boxed_error(format!("audit bridge thread failed to start: {err}")))?;

    let cluster_metrics = metrics.clone();
    let cluster_runtime = if cfg.cluster.enabled {
        match controlplane::cluster::run_cluster_tasks(
            cfg.cluster.clone(),
            Some(wiretap_hub.clone()),
            Some(cluster_metrics),
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("cluster error: {err}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    if cfg.cluster_migrate_from_local || cfg.cluster_migrate_verify {
        if !cfg.cluster.enabled {
            eprintln!("cluster migration requested but cluster mode is disabled");
            std::process::exit(2);
        }
        if cfg.cluster.join_seed.is_some() {
            eprintln!("cluster migration requested but --join is set; run migration only on the seed node");
            std::process::exit(2);
        }
        let Some(runtime) = cluster_runtime.as_ref() else {
            eprintln!("cluster migration requested but cluster runtime is unavailable");
            std::process::exit(2);
        };
        let migrate_cfg = migration::MigrationConfig {
            enabled: cfg.cluster_migrate_from_local,
            force: cfg.cluster_migrate_force,
            verify: cfg.cluster_migrate_verify,
            http_tls_dir: cfg.http_tls_dir.clone(),
            local_policy_store: local_policy_store.clone(),
            local_service_accounts_dir: local_service_accounts_dir.clone(),
            cluster_data_dir: cfg.cluster.data_dir.clone(),
            token_path: cfg.cluster.token_path.clone(),
            node_id: node_uuid,
        };
        match migration::run(&runtime.raft, &runtime.store, migrate_cfg).await {
            Ok(report) => {
                if report.migrated {
                    eprintln!(
                        "cluster migration complete: policies={}, service_accounts={}, tokens={}, api_keyset={}",
                        report.policies_seeded,
                        report.service_accounts_seeded,
                        report.tokens_seeded,
                        report
                            .api_keyset_source
                            .unwrap_or_else(|| "unknown".to_string())
                    );
                } else if let Some(reason) = report.skipped_reason {
                    eprintln!("cluster migration skipped: {reason}");
                }
            }
            Err(err) => {
                eprintln!("cluster migration failed: {err}");
                std::process::exit(2);
            }
        }
    }

    let readiness = ReadinessState::new(
        dataplane_config.clone(),
        policy_store.clone(),
        cluster_runtime
            .as_ref()
            .map(|runtime| runtime.store.clone()),
        cluster_runtime.as_ref().map(|runtime| runtime.raft.clone()),
    );
    readiness.set_policy_ready(true);

    if let Some(runtime) = cluster_runtime.as_ref() {
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
                std::time::Duration::from_secs(1),
            )
            .await;
        });
    }

    let tls_intercept_ca_present = match controlplane::intercept_tls::has_intercept_ca_material(
        &cfg.http_tls_dir,
        cluster_runtime.as_ref().map(|runtime| &runtime.store),
    ) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("tls intercept ca check failed: {err}");
            std::process::exit(2);
        }
    };
    let tls_intercept_ca_ready = Arc::new(AtomicBool::new(tls_intercept_ca_present));
    let tls_intercept_ca_generation = Arc::new(AtomicU64::new(0));
    let tls_intercept_ca_source = if let Some(runtime) = cluster_runtime.as_ref() {
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

    let metrics_for_dns = metrics.clone();
    let (dns_tx, dns_rx) = oneshot::channel::<Result<(), String>>();
    let (dns_startup_tx, dns_startup_rx) = oneshot::channel::<Result<(), String>>();
    let tls_intercept_ca_ready_for_dns = tls_intercept_ca_ready.clone();
    let tls_intercept_ca_generation_for_dns = tls_intercept_ca_generation.clone();
    let tls_intercept_ca_source_for_dns = tls_intercept_ca_source.clone();
    let service_policy_applied_generation_for_dns = service_policy_applied_generation.clone();
    let service_lane_iface_for_dns = service_lane_iface.clone();
    let shared_intercept_demux_for_dns = shared_intercept_demux.clone();
    let policy_store_for_dns = policy_store.clone();
    let audit_store_for_dns = audit_store.clone();
    let node_id_for_dns = node_id.clone();
    let dns_thread = std::thread::Builder::new()
        .name("dns-runtime".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("dns runtime");
            let res = rt.block_on(async {
                controlplane::trafficd::run(controlplane::trafficd::TrafficdConfig {
                    dns_bind: dns_listen,
                    dns_upstreams,
                    dns_allowlist: dns_allowlist_for_dns,
                    dns_policy,
                    dns_map: dns_map_for_dns,
                    metrics: metrics_for_dns,
                    policy_snapshot: service_policy_snapshot,
                    service_policy_applied_generation: service_policy_applied_generation_for_dns,
                    tls_intercept_ca_ready: tls_intercept_ca_ready_for_dns,
                    tls_intercept_ca_generation: tls_intercept_ca_generation_for_dns,
                    tls_intercept_ca_source: tls_intercept_ca_source_for_dns,
                    tls_intercept_listen_port,
                    enable_kernel_intercept_steering: !dpdk_enabled,
                    service_lane_iface: service_lane_iface_for_dns,
                    service_lane_ip,
                    service_lane_prefix,
                    intercept_demux: shared_intercept_demux_for_dns,
                    policy_store: policy_store_for_dns.clone(),
                    audit_store: Some(audit_store_for_dns),
                    node_id: node_id_for_dns,
                    startup_status_tx: Some(dns_startup_tx),
                })
                .await
            });
            let _ = dns_tx.send(res);
        });
    if dns_thread.is_err() {
        eprintln!("dns proxy: failed to spawn runtime thread");
        std::process::exit(2);
    }
    let dns_task = dns_rx;
    match tokio::time::timeout(Duration::from_secs(2), dns_startup_rx).await {
        Ok(Ok(Ok(()))) => {
            readiness.set_dns_ready(true);
            readiness.set_service_plane_ready(true);
        }
        Ok(Ok(Err(err))) => {
            eprintln!("dns proxy: startup failed: {err}");
            std::process::exit(2);
        }
        Ok(Err(_)) => {
            eprintln!("dns proxy: startup channel dropped");
            std::process::exit(2);
        }
        Err(_) => {
            eprintln!("dns proxy: startup timed out after 2s");
            std::process::exit(2);
        }
    }

    let dns_allowlist_idle_secs = cfg.dns_allowlist_idle_secs;
    let dns_allowlist_gc_interval_secs = cfg.dns_allowlist_gc_interval_secs;
    let _allowlist_gc_task = tokio::spawn(async move {
        controlplane::allowlist_gc::run_allowlist_gc(
            dns_allowlist_for_gc,
            dns_allowlist_idle_secs,
            dns_allowlist_gc_interval_secs,
            Some(dns_map_for_gc),
        )
        .await;
    });

    let http_cluster =
        cluster_runtime
            .as_ref()
            .map(|runtime| controlplane::http_api::HttpApiCluster {
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
        cluster_tls_dir: if cfg.cluster.enabled {
            Some(cfg.cluster.data_dir.join("tls"))
        } else {
            None
        },
        tls_intercept_ca_ready: Some(tls_intercept_ca_ready.clone()),
        tls_intercept_ca_generation: Some(tls_intercept_ca_generation.clone()),
    };
    let http_policy_store = policy_store.clone();
    let http_local_store = local_policy_store.clone();
    let metrics_for_http = metrics.clone();
    let readiness_for_http = readiness.clone();
    let (http_tx, http_rx) = oneshot::channel::<Result<(), String>>();
    let http_thread = std::thread::Builder::new()
        .name("http-runtime".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .expect("http runtime");
            let res = rt.block_on(async {
                controlplane::http_api::run_http_api(
                    http_cfg,
                    http_policy_store,
                    http_local_store,
                    http_cluster,
                    Some(audit_store.clone()),
                    Some(wiretap_hub.clone()),
                    Some(dns_map_for_http),
                    Some(readiness_for_http),
                    metrics_for_http,
                )
                .await
                .map_err(|err| format!("http api failed: {err}"))
            });
            let _ = http_tx.send(res);
        });
    if http_thread.is_err() {
        eprintln!("http api: failed to spawn runtime thread");
        std::process::exit(2);
    }
    let http_task = http_rx;

    let drain_control = DrainControl::new();
    let drain_control_for_dp = drain_control.clone();
    let _integration_task = if cfg.integration_mode != IntegrationMode::None {
        if let Some(provider) = integration_provider.clone() {
            let integration_cfg = IntegrationConfig {
                cluster_name: cfg.integration_cluster_name.clone(),
                route_name: cfg.integration_route_name.clone(),
                drain_timeout_secs: cfg.integration_drain_timeout_secs,
                reconcile_interval_secs: cfg.integration_reconcile_interval_secs,
                tag_filter: integration_tag_filter(&cfg),
                http_ready_port: http_advertise.port(),
                cluster_tls_dir: if cfg.cluster.enabled {
                    Some(cfg.cluster.data_dir.join("tls"))
                } else {
                    None
                },
            };
            let ready_client = match ReadyClient::new(http_advertise.port(), load_http_ca(&cfg)) {
                Ok(client) => Arc::new(client) as Arc<dyn ReadyChecker>,
                Err(err) => {
                    eprintln!("integration ready client error: {err}");
                    Arc::new(
                        ReadyClient::new(http_advertise.port(), None)
                            .expect("ready client fallback"),
                    ) as Arc<dyn ReadyChecker>
                }
            };
            let metrics_for_integration = metrics.clone();
            let drain_for_integration = drain_control.clone();
            let store_for_integration = cluster_runtime
                .as_ref()
                .map(|runtime| runtime.store.clone());
            let raft_for_integration = cluster_runtime.as_ref().map(|runtime| runtime.raft.clone());
            Some(tokio::spawn(async move {
                match IntegrationManager::new(
                    integration_cfg,
                    provider,
                    store_for_integration,
                    raft_for_integration,
                    metrics_for_integration,
                    drain_for_integration,
                    ready_client,
                )
                .await
                {
                    Ok(manager) => manager.run(cfg.integration_mode).await,
                    Err(err) => eprintln!("integration init error: {err}"),
                }
            }))
        } else {
            None
        }
    } else {
        None
    };

    let data_plane_iface = cfg.data_plane_iface;
    let data_plane_mode = cfg.data_plane_mode;
    let idle_timeout_secs = cfg.idle_timeout_secs;
    let policy = policy_store.snapshot();
    let metrics_for_dataplane = metrics.clone();
    let dataplane_config_for_dp = dataplane_config.clone();
    let shared_intercept_demux_for_dp = shared_intercept_demux.clone();

    let (dp_to_cp_tx, dp_to_cp_rx) = if dpdk_enabled {
        let (tx, rx) = mpsc::channel::<DhcpRx>(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (cp_to_dp_tx, cp_to_dp_rx) = if dpdk_enabled {
        let (tx, rx) = mpsc::channel::<DhcpTx>(128);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (mac_tx, mac_rx) = if dpdk_enabled {
        let (tx, rx) = watch::channel([0u8; 6]);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let dhcp_task = if dpdk_enabled {
        let mac_rx = mac_rx.as_ref().expect("mac receiver").clone();
        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_secs(cfg.dhcp_timeout_secs),
                retry_max: cfg.dhcp_retry_max,
                lease_min_secs: cfg.dhcp_lease_min_secs,
                hostname: None,
                update_internal_cidr: cfg.internal_cidr.is_none(),
                allow_router_fallback_from_subnet: cfg.cloud_provider == CloudProviderKind::Azure,
            },
            mac_rx,
            rx: dp_to_cp_rx.expect("dhcp rx"),
            tx: cp_to_dp_tx.expect("dhcp tx"),
            dataplane_config: dataplane_config.clone(),
            policy_store: policy_store.clone(),
            metrics: Some(metrics.clone()),
        };
        Some(tokio::spawn(async move {
            dhcp_client
                .run()
                .await
                .map_err(|err| format!("dhcp client failed: {err}"))
        }))
    } else {
        None
    };

    if dpdk_enabled {
        let dataplane_config = dataplane_config.clone();
        let mut mac_rx = mac_rx.expect("mac receiver");
        tokio::spawn(async move {
            let mac = loop {
                let current = *mac_rx.borrow();
                if current != [0u8; 6] {
                    break current;
                }
                if mac_rx.changed().await.is_err() {
                    eprintln!("dpdk imds fallback: mac channel closed");
                    return;
                }
            };
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if dataplane_config.get().is_some() {
                    return;
                }
                if Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if dataplane_config.get().is_some() {
                return;
            }
            match imds_dataplane_config(mac).await {
                Ok((ip, prefix, gateway)) => {
                    dataplane_config.set(firewall::dataplane::DataplaneConfig {
                        ip,
                        prefix,
                        gateway,
                        mac,
                        lease_expiry: None,
                    });
                    eprintln!(
                        "dpdk imds fallback: set dataplane config ip={}, prefix={}, gateway={}",
                        ip, prefix, gateway
                    );
                }
                Err(err) => {
                    eprintln!("dpdk imds fallback failed: {err}");
                }
            }
        });
    }

    readiness.set_dataplane_running(true);
    let dataplane_task = tokio::task::spawn_blocking(move || {
        run_dataplane(
            data_plane_iface,
            data_plane_mode,
            idle_timeout_secs,
            policy,
            policy_applied_generation,
            service_policy_applied_generation,
            dns_allowlist_for_dp,
            cfg.dns_target_ips.clone(),
            Some(wiretap_emitter),
            Some(audit_emitter),
            internal_net,
            internal_prefix,
            public_ip,
            cfg.snat_mode,
            overlay.clone(),
            data_port,
            dataplane_config_for_dp,
            Some(drain_control_for_dp),
            dp_to_cp_tx,
            cp_to_dp_rx,
            mac_tx,
            shared_intercept_demux_for_dp,
            metrics_for_dataplane,
        )
        .map_err(|err| format!("dataplane failed: {err}"))
    });

    if let Some(mut dhcp_task) = dhcp_task {
        tokio::select! {
            res = http_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("http api exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("http api thread failed: {err}"))),
                }
            }
            res = dns_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("dns proxy exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("dns proxy task failed: {err}"))),
                }
            }
            res = dataplane_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("dataplane exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("dataplane task failed: {err}"))),
                }
            }
            res = &mut dhcp_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("dhcp task exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("dhcp task failed: {err}"))),
                }
            }
        }
    } else {
        tokio::select! {
            res = http_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("http api exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("http api thread failed: {err}"))),
                }
            }
            res = dns_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("dns proxy exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("dns proxy task failed: {err}"))),
                }
            }
            res = dataplane_task => {
                match res {
                    Ok(Ok(())) => Err(boxed_error("dataplane exited unexpectedly")),
                    Ok(Err(err)) => Err(boxed_error(err)),
                    Err(err) => Err(boxed_error(format!("dataplane task failed: {err}"))),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_tcp_packet(src_port: u16, dst_port: u16) -> Packet {
        const ETH_HDR_LEN: usize = 14;
        let total_len = 20 + 20;
        let mut buf = vec![0u8; ETH_HDR_LEN + total_len];
        buf[0..6].copy_from_slice(&[0; 6]);
        buf[6..12].copy_from_slice(&[1; 6]);
        buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip_off = ETH_HDR_LEN;
        buf[ip_off] = 0x45;
        buf[ip_off + 1] = 0;
        buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[ip_off + 8] = 64;
        buf[ip_off + 9] = 6;
        buf[ip_off + 12..ip_off + 16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
        buf[ip_off + 16..ip_off + 20].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 10).octets());
        let tcp_off = ip_off + 20;
        buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        buf[tcp_off + 12] = 0x50;
        buf[tcp_off + 13] = 0x18;
        let mut pkt = Packet::new(buf);
        let _ = pkt.recalc_checksums();
        pkt
    }

    fn base_args() -> Vec<String> {
        vec![
            "--management-interface".to_string(),
            "mgmt0".to_string(),
            "--data-plane-interface".to_string(),
            "data0".to_string(),
        ]
    }

    #[test]
    fn parse_args_accepts_repeated_dns_flags() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--dns-target-ip".to_string(),
            "10.0.0.1".to_string(),
            "--dns-target-ip".to_string(),
            "10.0.0.2".to_string(),
            "--dns-upstream".to_string(),
            "1.1.1.1:53".to_string(),
            "--dns-upstream".to_string(),
            "8.8.8.8:53".to_string(),
        ]);
        let cfg = parse_args("firewall", args).expect("parse args");
        assert_eq!(cfg.dns_target_ips.len(), 2);
        assert_eq!(cfg.dns_upstreams.len(), 2);
    }

    #[test]
    fn parse_args_accepts_csv_dns_flags() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--dns-target-ips".to_string(),
            "10.0.0.1,10.0.0.2".to_string(),
            "--dns-upstreams".to_string(),
            "1.1.1.1:53,8.8.8.8:53".to_string(),
        ]);
        let cfg = parse_args("firewall", args).expect("parse args");
        assert_eq!(cfg.dns_target_ips.len(), 2);
        assert_eq!(cfg.dns_upstreams.len(), 2);
    }

    #[test]
    fn parse_args_rejects_mixed_dns_target_forms() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--dns-target-ip".to_string(),
            "10.0.0.1".to_string(),
            "--dns-target-ips".to_string(),
            "10.0.0.2".to_string(),
            "--dns-upstream".to_string(),
            "1.1.1.1:53".to_string(),
        ]);
        let err = parse_args("firewall", args).expect_err("expected parse failure");
        assert!(err.contains("cannot combine repeated --dns-target-ip"));
    }

    #[test]
    fn parse_args_rejects_mixed_dns_upstream_forms() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--dns-target-ip".to_string(),
            "10.0.0.1".to_string(),
            "--dns-upstream".to_string(),
            "1.1.1.1:53".to_string(),
            "--dns-upstreams".to_string(),
            "8.8.8.8:53".to_string(),
        ]);
        let err = parse_args("firewall", args).expect_err("expected parse failure");
        assert!(err.contains("cannot combine repeated --dns-upstream"));
    }

    #[test]
    fn parse_args_rejects_removed_dns_listen_flag() {
        let mut args = base_args();
        args.extend_from_slice(&[
            "--dns-target-ip".to_string(),
            "10.0.0.1".to_string(),
            "--dns-upstream".to_string(),
            "1.1.1.1:53".to_string(),
            "--dns-listen".to_string(),
            "10.0.0.1:53".to_string(),
        ]);
        let err = parse_args("firewall", args).expect_err("expected parse failure");
        assert!(err.contains("--dns-listen has been removed"));
    }

    #[test]
    fn choose_dpdk_worker_plan_prefers_queue_per_worker_when_available() {
        let plan = choose_dpdk_worker_plan(4, 8, 4).expect("worker plan");
        assert_eq!(plan.worker_count, 4);
        assert_eq!(plan.mode, DpdkWorkerMode::QueuePerWorker);
    }

    #[test]
    fn choose_dpdk_worker_plan_uses_shared_demux_on_single_queue() {
        let plan = choose_dpdk_worker_plan(4, 8, 1).expect("worker plan");
        assert_eq!(plan.worker_count, 4);
        assert_eq!(plan.mode, DpdkWorkerMode::SharedRxDemux);
    }

    #[test]
    fn choose_dpdk_worker_plan_reduces_to_effective_queue_count() {
        let plan = choose_dpdk_worker_plan(8, 8, 2).expect("worker plan");
        assert_eq!(plan.worker_count, 2);
        assert_eq!(plan.mode, DpdkWorkerMode::QueuePerWorker);
    }

    #[test]
    fn choose_dpdk_worker_plan_rejects_zero_effective_queues() {
        let err = choose_dpdk_worker_plan(2, 8, 0).expect_err("expected queue error");
        assert!(err.contains("no usable queues"));
    }

    #[test]
    fn shared_demux_owner_pins_https_to_worker_zero() {
        let pkt = build_test_tcp_packet(40000, 443);
        let owner = shared_demux_owner_for_packet(&pkt, 4, 2);
        assert_eq!(owner, 0);
    }

    #[test]
    fn shared_demux_owner_hashes_non_https_flows() {
        let pkt = build_test_tcp_packet(40000, 5201);
        let owner = shared_demux_owner_for_packet(&pkt, 4, 2);
        assert!(owner < 2);
    }
}
