use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use firewall::controlplane::{self, PolicyStore};
use firewall::dataplane::policy::{DefaultPolicy, PolicySnapshot};
use firewall::dataplane::{EngineState, SoftAdapter, SoftMode, DEFAULT_IDLE_TIMEOUT_SECS};

#[derive(Debug)]
struct CliConfig {
    management_iface: String,
    data_plane_iface: String,
    dns_listen: SocketAddr,
    dns_upstream: SocketAddr,
    data_plane_mode: SoftMode,
    idle_timeout_secs: u64,
    default_policy: DefaultPolicy,
    policy_config: Option<PathBuf>,
}

fn usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} --management-interface <iface> --data-plane-interface <iface> --dns-upstream <ip:port> --dns-listen <ip:port> [--data-plane-mode tun|tap] [--idle-timeout-secs <secs>] [--default-policy allow|deny] [--policy-config <path>]\n\nFlags:\n  --management-interface <iface>\n  --data-plane-interface <iface>\n  --dns-upstream <ip:port>\n  --dns-listen <ip:port>\n  --data-plane-mode tun|tap (default: tun)\n  --idle-timeout-secs <secs> (default: 300)\n  --default-policy allow|deny (default: deny)\n  --policy-config <path>\n  -h, --help\n"
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

fn parse_args(bin: &str) -> Result<CliConfig, String> {
    let mut management_iface = None;
    let mut data_plane_iface = None;
    let mut dns_listen = None;
    let mut dns_upstream = None;
    let mut data_plane_mode = SoftMode::Tun;
    let mut idle_timeout_secs = DEFAULT_IDLE_TIMEOUT_SECS;
    let mut default_policy = DefaultPolicy::Deny;
    let mut policy_config = None;

    let mut args = env::args().skip(1);
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
            data_plane_mode = SoftMode::parse(&value)?;
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
        if arg == "--default-policy" || arg.starts_with("--default-policy=") {
            let value = take_flag_value("--default-policy", &arg, &mut args)?;
            default_policy = parse_default_policy(&value)?;
            continue;
        }
        if arg == "--policy-config" || arg.starts_with("--policy-config=") {
            let value = take_flag_value("--policy-config", &arg, &mut args)?;
            policy_config = Some(PathBuf::from(value));
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

    Ok(CliConfig {
        management_iface: management_iface.unwrap(),
        data_plane_iface: data_plane_iface.unwrap(),
        dns_listen: dns_listen.unwrap(),
        dns_upstream: dns_upstream.unwrap(),
        data_plane_mode,
        idle_timeout_secs,
        default_policy,
        policy_config,
    })
}

fn run_dataplane(
    data_plane_iface: String,
    data_plane_mode: SoftMode,
    idle_timeout_secs: u64,
    policy: Arc<RwLock<PolicySnapshot>>,
    internal_net: Ipv4Addr,
    internal_prefix: u8,
    public_ip: Ipv4Addr,
    data_port: u16,
) -> Result<(), String> {
    let mut state = EngineState::new_with_idle_timeout(
        policy,
        internal_net,
        internal_prefix,
        public_ip,
        data_port,
        idle_timeout_secs,
    );

    let mut adapter = SoftAdapter::new(data_plane_iface, data_plane_mode)?;
    adapter.run(&mut state)
}

fn boxed_error(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::Other, msg.into()).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bin = env::args().next().unwrap_or_else(|| "firewall".to_string());
    let cfg = match parse_args(&bin) {
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
    println!("default policy: {:?}", cfg.default_policy);
    println!("dns listen: {}", cfg.dns_listen);
    println!("dns upstream: {}", cfg.dns_upstream);

    // TODO: wire dataplane network parameters via CLI or config.
    let internal_net = Ipv4Addr::new(10, 0, 0, 0);
    let internal_prefix = 24;
    let public_ip = Ipv4Addr::new(203, 0, 113, 1);
    let data_port = 0;

    let policy_store = PolicyStore::new(cfg.default_policy, internal_net, internal_prefix);
    if let Some(path) = &cfg.policy_config {
        if let Err(err) = policy_store.rebuild_from_yaml_path(path) {
            eprintln!("policy config error: {err}");
            std::process::exit(2);
        }
    }
    let dns_allowlist = policy_store.dns_allowlist();
    let dns_listen = cfg.dns_listen;
    let dns_upstream = cfg.dns_upstream;

    let dns_task = tokio::spawn(async move {
        controlplane::dns_proxy::run_dns_proxy(dns_listen, dns_upstream, dns_allowlist)
            .await
            .map_err(|err| format!("dns proxy failed: {err}"))
    });

    let data_plane_iface = cfg.data_plane_iface;
    let data_plane_mode = cfg.data_plane_mode;
    let idle_timeout_secs = cfg.idle_timeout_secs;
    let policy = policy_store.snapshot();
    let dataplane_task = tokio::task::spawn_blocking(move || {
        run_dataplane(
            data_plane_iface,
            data_plane_mode,
            idle_timeout_secs,
            policy,
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
        )
        .map_err(|err| format!("dataplane failed: {err}"))
    });

    tokio::select! {
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
