use std::net::SocketAddr;
use std::path::PathBuf;

use firewall::controlplane::api_auth::DEFAULT_TTL_SECS;
use firewall::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};

use crate::runtime::cli::{parse_socket, take_flag_value};

#[derive(Debug)]
pub enum AuthCommand {
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
        roles: Option<Vec<String>>,
    },
}

pub fn auth_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] [--roles <csv>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n"
    )
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

pub fn parse_auth_args(bin: &str, args: &[String]) -> Result<AuthCommand, String> {
    let mut args = args.iter().cloned();
    let Some(section) = args.next() else {
        return Err(auth_usage(bin));
    };
    let mut cluster_addr = None;
    let mut cluster_tls_dir = None;

    let mut kid = None;
    let mut sub = None;
    let mut ttl_secs = None;
    let mut roles: Option<Vec<String>> = None;

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
        if arg == "--roles" || arg.starts_with("--roles=") {
            let value = take_flag_value("--roles", &arg, &mut args)?;
            let parsed: Vec<String> = value
                .split(',')
                .map(|entry| entry.trim().to_ascii_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect();
            roles = if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            };
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
                    roles,
                })
            }
            _ => Err(format!("unknown auth token action: {action}")),
        },
        _ => Err(format!("unknown auth command: {mode}")),
    }
}

pub async fn run_auth_command(cmd: AuthCommand) -> Result<(), String> {
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
            sub,
            ttl_secs,
            kid,
            roles,
            ..
        } => {
            let ttl = ttl_secs.or(Some(DEFAULT_TTL_SECS));
            let (token, _kid, _exp) = client.mint_token(&sub, ttl, kid.as_deref(), roles).await?;
            println!("{token}");
        }
    }
    Ok(())
}
