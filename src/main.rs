use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

use firewall::controlplane::{self, Allowlist};
use firewall::dataplane::{EngineState, SoftAdapter, SoftMode};

#[derive(Debug)]
struct CliConfig {
    management_iface: String,
    data_plane_iface: String,
    dns_listen: SocketAddr,
    dns_upstream: SocketAddr,
    data_plane_mode: SoftMode,
}

fn usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} --management-interface <iface> --data-plane-interface <iface> --dns-upstream <ip:port> --dns-listen <ip:port> [--data-plane-mode tun|tap]\n\nFlags:\n  --management-interface <iface>\n  --data-plane-interface <iface>\n  --dns-upstream <ip:port>\n  --dns-listen <ip:port>\n  --data-plane-mode tun|tap (default: tun)\n  -h, --help\n"
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
    args.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_socket(flag: &str, value: &str) -> Result<SocketAddr, String> {
    value.parse().map_err(|_| {
        format!(
            "{flag} must be a socket address in the form ip:port, got {value}"
        )
    })
}

fn parse_args(bin: &str) -> Result<CliConfig, String> {
    let mut management_iface = None;
    let mut data_plane_iface = None;
    let mut dns_listen = None;
    let mut dns_upstream = None;
    let mut data_plane_mode = SoftMode::Tun;

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
    })
}

fn run_dataplane(
    data_plane_iface: String,
    data_plane_mode: SoftMode,
    allowlist: Arc<RwLock<Allowlist>>,
) -> Result<(), String> {
    // TODO: wire dataplane network parameters via CLI or config.
    let mut state = EngineState::new(
        allowlist,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
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
    println!("dns listen: {}", cfg.dns_listen);
    println!("dns upstream: {}", cfg.dns_upstream);

    let allowlist = Arc::new(RwLock::new(Allowlist::new()));
    let dns_allowlist = allowlist.clone();
    let dns_listen = cfg.dns_listen;
    let dns_upstream = cfg.dns_upstream;

    let dns_task = tokio::spawn(async move {
        controlplane::dns_proxy::run_dns_proxy(dns_listen, dns_upstream, dns_allowlist)
            .await
            .map_err(|err| format!("dns proxy failed: {err}"))
    });

    let dataplane_allowlist = allowlist.clone();
    let data_plane_iface = cfg.data_plane_iface;
    let data_plane_mode = cfg.data_plane_mode;
    let dataplane_task = tokio::task::spawn_blocking(move || {
        run_dataplane(data_plane_iface, data_plane_mode, dataplane_allowlist)
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
