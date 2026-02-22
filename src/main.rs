use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use firewall::controlplane::policy_config::PolicyMode;
use firewall::controlplane::policy_repository::PolicyDiskStore;
use firewall::controlplane::{self, PolicyStore};
use firewall::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use firewall::controlplane::wiretap::{DnsMap, WiretapHub, load_or_create_node_id};
use firewall::dataplane::policy::{DefaultPolicy, DynamicIpSetV4, PolicySnapshot};
use firewall::dataplane::{
    DataplaneConfigStore, DhcpRx, DhcpTx, DpdkAdapter, DpdkIo, EngineState, SoftAdapter, SoftMode,
    DEFAULT_IDLE_TIMEOUT_SECS, WiretapEmitter,
    DEFAULT_WIRETAP_REPORT_INTERVAL_SECS,
};
use firewall::controlplane::api_auth::DEFAULT_TTL_SECS;
use firewall::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};
use futures::stream::TryStreamExt;
use tokio::sync::{mpsc, watch};
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::new_connection;
use std::collections::HashMap;

const DNS_ALLOWLIST_IDLE_SLACK_SECS: u64 = 120;
const DNS_ALLOWLIST_GC_INTERVAL_SECS: u64 = 30;
const DHCP_TIMEOUT_SECS: u64 = 5;
const DHCP_RETRY_MAX: u32 = 5;
const DHCP_LEASE_MIN_SECS: u64 = 60;

#[derive(Debug)]
struct CliConfig {
    management_iface: String,
    data_plane_iface: String,
    dns_listen: SocketAddr,
    dns_upstream: SocketAddr,
    data_plane_mode: DataPlaneMode,
    idle_timeout_secs: u64,
    dns_allowlist_idle_secs: u64,
    dns_allowlist_gc_interval_secs: u64,
    default_policy: DefaultPolicy,
    dhcp_timeout_secs: u64,
    dhcp_retry_max: u32,
    dhcp_lease_min_secs: u64,
    snat_ip: Option<Ipv4Addr>,
    http_bind: Option<SocketAddr>,
    http_advertise: Option<SocketAddr>,
    http_tls_dir: PathBuf,
    http_cert_path: Option<PathBuf>,
    http_key_path: Option<PathBuf>,
    http_ca_path: Option<PathBuf>,
    http_tls_san: Vec<String>,
    metrics_bind: Option<SocketAddr>,
    cluster: controlplane::cluster::config::ClusterConfig,
}

#[derive(Debug)]
enum AuthCommand {
    KeyRotate { addr: SocketAddr, tls_dir: PathBuf },
    KeyList { addr: SocketAddr, tls_dir: PathBuf },
    KeyRetire { addr: SocketAddr, tls_dir: PathBuf, kid: String },
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
        "Usage:\n  {bin} --management-interface <iface> --data-plane-interface <iface> --dns-upstream <ip:port> --dns-listen <ip:port> [--data-plane-mode tun|tap|dpdk] [--idle-timeout-secs <secs>] [--dns-allowlist-idle-secs <secs>] [--dns-allowlist-gc-interval-secs <secs>] [--default-policy allow|deny] [--dhcp-timeout-secs <secs>] [--dhcp-retry-max <count>] [--dhcp-lease-min-secs <secs>] [--snat-ip <ipv4>]\n  {bin} [cluster flags]\n  {bin} auth <command>\n\nFlags:\n  --management-interface <iface>\n  --data-plane-interface <iface>\n  --dns-upstream <ip:port>\n  --dns-listen <ip:port>\n  --data-plane-mode tun|tap|dpdk (default: tun)\n  --idle-timeout-secs <secs> (default: 300)\n  --dns-allowlist-idle-secs <secs> (default: idle-timeout + 120)\n  --dns-allowlist-gc-interval-secs <secs> (default: 30)\n  --default-policy allow|deny (default: deny)\n  --dhcp-timeout-secs <secs> (default: 5)\n  --dhcp-retry-max <count> (default: 5)\n  --dhcp-lease-min-secs <secs> (default: 60)\n  --snat-ip <ipv4> (software dataplane only)\n  --http-bind <ip:port> (default: <management-ip>:8443)\n  --http-advertise <ip:port> (default: http-bind)\n  --http-tls-dir <path> (default: /var/lib/neuwerk/http-tls)\n  --http-cert-path <path>\n  --http-key-path <path>\n  --http-ca-path <path>\n  --http-tls-san <comma-separated>\n  --metrics-bind <ip:port> (default: <management-ip>:8080)\n  --cluster-bind <ip:port>\n  --cluster-join-bind <ip:port> (default: cluster-bind + 1)\n  --cluster-advertise <ip:port> (default: cluster-bind)\n  --join <ip:port>\n  --cluster-data-dir <path> (default: /var/lib/neuwerk/cluster)\n  --node-id-path <path> (default: /var/lib/neuwerk/node_id)\n  --bootstrap-token-path <path> (default: /var/lib/neuwerk/bootstrap-token)\n  -h, --help\n\nAuth Commands:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n"
    )
}

fn auth_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n"
    )
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

fn parse_default_policy(value: &str) -> Result<DefaultPolicy, String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok(DefaultPolicy::Allow),
        "deny" => Ok(DefaultPolicy::Deny),
        _ => Err(format!(
            "--default-policy must be allow or deny, got {value}"
        )),
    }
}

fn parse_args(bin: &str, args: Vec<String>) -> Result<CliConfig, String> {
    let mut management_iface = None;
    let mut data_plane_iface = None;
    let mut dns_listen = None;
    let mut dns_upstream = None;
    let mut data_plane_mode = DataPlaneMode::Soft(SoftMode::Tun);
    let mut idle_timeout_secs = DEFAULT_IDLE_TIMEOUT_SECS;
    let mut dns_allowlist_idle_secs = None;
    let mut dns_allowlist_gc_interval_secs = None;
    let mut default_policy = DefaultPolicy::Deny;
    let mut dhcp_timeout_secs = DHCP_TIMEOUT_SECS;
    let mut dhcp_retry_max = DHCP_RETRY_MAX;
    let mut dhcp_lease_min_secs = DHCP_LEASE_MIN_SECS;
    let mut http_bind = None;
    let mut http_advertise = None;
    let mut http_tls_dir = PathBuf::from("/var/lib/neuwerk/http-tls");
    let mut http_cert_path = None;
    let mut http_key_path = None;
    let mut http_ca_path = None;
    let mut http_tls_san: Vec<String> = Vec::new();
    let mut metrics_bind = None;
    let mut snat_ip = None;
    let mut cluster_bind = None;
    let mut cluster_join_bind = None;
    let mut cluster_advertise = None;
    let mut cluster_join = None;
    let mut cluster_data_dir = None;
    let mut node_id_path = None;
    let mut bootstrap_token_path = None;

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
        if arg == "--dns-upstream" || arg.starts_with("--dns-upstream=") {
            let value = take_flag_value("--dns-upstream", &arg, &mut args)?;
            dns_upstream = Some(parse_socket("--dns-upstream", &value)?);
            continue;
        }
        if arg == "--dns-listen" || arg.starts_with("--dns-listen=") {
            let value = take_flag_value("--dns-listen", &arg, &mut args)?;
            dns_listen = Some(parse_socket("--dns-listen", &value)?);
            continue;
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
            let parsed = value.parse::<u32>().map_err(|_| {
                format!("--dhcp-retry-max must be a positive integer, got {value}")
            })?;
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
        if arg == "--snat-ip" || arg.starts_with("--snat-ip=") {
            let value = take_flag_value("--snat-ip", &arg, &mut args)?;
            let parsed = value
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("--snat-ip must be an IPv4 address, got {value}"))?;
            snat_ip = Some(parsed);
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

    let mut missing = Vec::new();
    if management_iface.is_none() {
        missing.push("--management-interface");
    }
    if data_plane_iface.is_none() {
        missing.push("--data-plane-interface");
    }
    if dns_upstream.is_none() {
        missing.push("--dns-upstream");
    }
    if dns_listen.is_none() {
        missing.push("--dns-listen");
    }

    if !missing.is_empty() {
        return Err(format!("missing required flags: {}", missing.join(", ")));
    }
    if management_iface == data_plane_iface {
        return Err("--management-interface and --data-plane-interface must be different".to_string());
    }

    let dns_allowlist_idle_secs =
        dns_allowlist_idle_secs.unwrap_or(idle_timeout_secs + DNS_ALLOWLIST_IDLE_SLACK_SECS);
    let dns_allowlist_gc_interval_secs =
        dns_allowlist_gc_interval_secs.unwrap_or(DNS_ALLOWLIST_GC_INTERVAL_SECS);

    Ok(CliConfig {
        management_iface: management_iface.unwrap(),
        data_plane_iface: data_plane_iface.unwrap(),
        dns_listen: dns_listen.unwrap(),
        dns_upstream: dns_upstream.unwrap(),
        data_plane_mode,
        idle_timeout_secs,
        dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs,
        default_policy,
        dhcp_timeout_secs,
        dhcp_retry_max,
        dhcp_lease_min_secs,
        snat_ip,
        http_bind,
        http_advertise,
        http_tls_dir,
        http_cert_path,
        http_key_path,
        http_ca_path,
        http_tls_san,
        metrics_bind,
        cluster: build_cluster_config(
            cluster_bind,
            cluster_join_bind,
            cluster_advertise,
            cluster_join,
            cluster_data_dir,
            node_id_path,
            bootstrap_token_path,
        )?,
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
            println!("rotated key: {} (created {}, status {:?})", key.kid, key.created_at, key.status);
        }
        AuthCommand::KeyList { .. } => {
            let (active_kid, keys) = client.list_keys().await?;
            println!("active kid: {active_kid}");
            for key in keys {
                let active = if key.signing { "signing" } else { "" };
                println!("kid: {} status: {:?} created: {} {}", key.kid, key.status, key.created_at, active);
            }
        }
        AuthCommand::KeyRetire { kid, .. } => {
            client.retire_key(&kid).await?;
            println!("retired key: {kid}");
        }
        AuthCommand::TokenMint { sub, ttl_secs, kid, .. } => {
            let ttl = ttl_secs.or(Some(DEFAULT_TTL_SECS));
            let (token, _kid, _exp) = client
                .mint_token(&sub, ttl, kid.as_deref())
                .await?;
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
    dns_allowlist: DynamicIpSetV4,
    wiretap_emitter: Option<WiretapEmitter>,
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    public_ip: Ipv4Addr,
    data_port: u16,
    dataplane_config: DataplaneConfigStore,
    dhcp_tx: Option<mpsc::Sender<DhcpRx>>,
    dhcp_rx: Option<mpsc::Receiver<DhcpTx>>,
    mac_publisher: Option<watch::Sender<[u8; 6]>>,
    metrics: controlplane::metrics::Metrics,
) -> Result<(), String> {
    let mut state = EngineState::new_with_idle_timeout(
        policy,
        internal_net,
        internal_prefix,
        public_ip,
        data_port,
        idle_timeout_secs,
    );
    state.set_dns_allowlist(dns_allowlist);
    state.set_dataplane_config(dataplane_config);
    let metrics_for_state = metrics.clone();
    state.set_metrics(metrics_for_state);
    if let Some(emitter) = wiretap_emitter {
        state.set_wiretap_emitter(emitter);
    }

    match data_plane_mode {
        DataPlaneMode::Soft(mode) => {
            let mut adapter = SoftAdapter::new(data_plane_iface, mode)?;
            adapter.run(&mut state)
        }
        DataPlaneMode::Dpdk => {
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
            let mut io = match DpdkIo::new(&iface) {
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

    let cfg = match parse_args(&bin, args) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}\n\n{}", usage(&bin));
            std::process::exit(2);
        }
    };

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
    println!("dns listen: {}", cfg.dns_listen);
    println!("dns upstream: {}", cfg.dns_upstream);
    if cfg.cluster.enabled {
        println!("cluster bind: {}", cfg.cluster.bind_addr);
        println!("cluster join bind: {}", cfg.cluster.join_bind_addr);
        println!("cluster advertise: {}", cfg.cluster.advertise_addr);
        if let Some(seed) = cfg.cluster.join_seed {
            println!("cluster join seed: {seed}");
        }
    }

    let dpdk_enabled = matches!(cfg.data_plane_mode, DataPlaneMode::Dpdk);
    if dpdk_enabled && cfg.snat_ip.is_some() {
        eprintln!("--snat-ip is only supported in software dataplane mode");
        std::process::exit(2);
    }
    let soft_dp_config = if dpdk_enabled || cfg.snat_ip.is_some() {
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
    let internal_net = Ipv4Addr::UNSPECIFIED;
    let internal_prefix = 32;
    let public_ip = cfg.snat_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let data_port = 0;

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

    if !dpdk_enabled {
        if let Ok((ip, prefix)) =
            internal_ipv4_config(&cfg.management_iface, &cfg.data_plane_iface).await
        {
            let _ = policy_store.update_internal_cidr(ip, prefix);
        } else {
            eprintln!("warning: internal CIDR not detected; rely on policy source groups");
        }
    }

    if !dpdk_enabled && soft_dp_config.is_none() && cfg.snat_ip.is_none() {
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
    if !cfg.cluster.enabled {
        if let Ok(Some(active_id)) = local_policy_store.active_id() {
            match local_policy_store.read_record(active_id) {
                Ok(Some(record)) if record.mode == PolicyMode::Enforce => {
                    if let Err(err) = policy_store.rebuild_from_config(record.policy) {
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
    let dns_listen = cfg.dns_listen;
    let dns_upstream = cfg.dns_upstream;
    let dns_map = DnsMap::new();
    let wiretap_hub = WiretapHub::new(1024);
    let metrics = match controlplane::metrics::Metrics::new() {
        Ok(metrics) => metrics,
        Err(err) => {
            eprintln!("metrics init error: {err}");
            std::process::exit(2);
        }
    };
    let node_id = match load_or_create_node_id(&cfg.cluster.node_id_path) {
        Ok(node_id) => node_id,
        Err(err) => {
            eprintln!("node id error: {err}");
            std::process::exit(2);
        }
    };
    let (wiretap_tx, mut wiretap_rx) = tokio::sync::mpsc::channel(1024);
    let wiretap_emitter =
        WiretapEmitter::new(wiretap_tx, DEFAULT_WIRETAP_REPORT_INTERVAL_SECS);
    let hub_for_wiretap = wiretap_hub.clone();
    let dns_map_for_wiretap = dns_map.clone();
    let dns_map_for_dns = dns_map.clone();
    let dns_map_for_gc = dns_map.clone();
    let dns_map_for_http = dns_map.clone();
    let node_id_for_wiretap = node_id.clone();
    let _wiretap_task = tokio::spawn(async move {
        while let Some(event) = wiretap_rx.recv().await {
            let hostname = dns_map_for_wiretap.lookup(event.dst_ip);
            let enriched =
                controlplane::wiretap::WiretapEvent::from_dataplane(event, hostname, &node_id_for_wiretap);
            hub_for_wiretap.publish(enriched);
        }
    });

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

    if let Some(runtime) = cluster_runtime.as_ref() {
        let store = runtime.store.clone();
        let policy_store = policy_store.clone();
        let local_policy_store = local_policy_store.clone();
        tokio::spawn(async move {
            controlplane::policy_replication::run_policy_replication(
                store,
                policy_store,
                local_policy_store,
                std::time::Duration::from_secs(1),
            )
            .await;
        });
    }

    let metrics_for_dns = metrics.clone();
    let dns_task = tokio::spawn(async move {
        controlplane::dns_proxy::run_dns_proxy(
            dns_listen,
            dns_upstream,
            dns_allowlist_for_dns,
            dns_policy,
            dns_map_for_dns,
            metrics_for_dns,
        )
        .await
        .map_err(|err| format!("dns proxy failed: {err}"))
    });

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
    };
    let http_policy_store = policy_store.clone();
    let http_local_store = local_policy_store.clone();
    let metrics_for_http = metrics.clone();
    let http_task = tokio::spawn(async move {
        controlplane::http_api::run_http_api(
            http_cfg,
            http_policy_store,
            http_local_store,
            http_cluster,
            Some(wiretap_hub.clone()),
            Some(dns_map_for_http),
            metrics_for_http,
        )
        .await
        .map_err(|err| format!("http api failed: {err}"))
    });

    let data_plane_iface = cfg.data_plane_iface;
    let data_plane_mode = cfg.data_plane_mode;
    let idle_timeout_secs = cfg.idle_timeout_secs;
    let policy = policy_store.snapshot();
    let metrics_for_dataplane = metrics.clone();
    let dataplane_config_for_dp = dataplane_config.clone();

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
        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_secs(cfg.dhcp_timeout_secs),
                retry_max: cfg.dhcp_retry_max,
                lease_min_secs: cfg.dhcp_lease_min_secs,
                hostname: None,
            },
            mac_rx: mac_rx.expect("mac receiver"),
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

    let dataplane_task = tokio::task::spawn_blocking(move || {
        run_dataplane(
            data_plane_iface,
            data_plane_mode,
            idle_timeout_secs,
            policy,
            dns_allowlist_for_dp,
            Some(wiretap_emitter),
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
            dataplane_config_for_dp,
            dp_to_cp_tx,
            cp_to_dp_rx,
            mac_tx,
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
                    Err(err) => Err(boxed_error(format!("http api task failed: {err}"))),
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
                    Err(err) => Err(boxed_error(format!("http api task failed: {err}"))),
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
