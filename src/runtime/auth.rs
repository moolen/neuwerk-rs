use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use neuwerk::controlplane::api_auth::{self, ApiKeySet, DEFAULT_TTL_SECS};
use neuwerk::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};
use neuwerk::controlplane::cluster::store::ClusterStore;

use crate::runtime::cli::{parse_socket, take_flag_value};

#[derive(Debug, Clone)]
pub(crate) enum AuthTarget {
    Cluster { addr: SocketAddr, tls_dir: PathBuf },
    Local { tls_dir: PathBuf },
}

#[derive(Debug, Clone)]
pub enum AuthCommand {
    KeyRotate {
        target: AuthTarget,
    },
    KeyList {
        target: AuthTarget,
    },
    KeyRetire {
        target: AuthTarget,
        kid: String,
    },
    TokenMint {
        target: AuthTarget,
        sub: String,
        ttl_secs: Option<i64>,
        kid: Option<String>,
        roles: Option<Vec<String>>,
    },
}

pub fn auth_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key rotate --http-tls-dir <path>\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --http-tls-dir <path>\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --http-tls-dir <path>\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] [--roles <csv>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] [--roles <csv>] --http-tls-dir <path>\n"
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
    let mut http_tls_dir = None;

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
        if arg == "--http-tls-dir" || arg.starts_with("--http-tls-dir=") {
            let value = take_flag_value("--http-tls-dir", &arg, &mut args)?;
            http_tls_dir = Some(PathBuf::from(value));
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

    let target = match (cluster_addr, http_tls_dir) {
        (Some(addr), None) => AuthTarget::Cluster {
            addr,
            tls_dir: cluster_tls_dir
                .unwrap_or_else(|| PathBuf::from("/var/lib/neuwerk/cluster/tls")),
        },
        (None, Some(tls_dir)) => AuthTarget::Local { tls_dir },
        (Some(_), Some(_)) => {
            return Err(
                "choose either cluster auth (--cluster-addr) or local auth (--http-tls-dir), not both"
                    .to_string(),
            )
        }
        (None, None) => {
            return Err(
                "missing auth target: pass --cluster-addr for cluster mode or --http-tls-dir for local mode"
                    .to_string(),
            )
        }
    };

    match mode.as_str() {
        "key" => match action.as_str() {
            "rotate" => Ok(AuthCommand::KeyRotate { target }),
            "list" => Ok(AuthCommand::KeyList { target }),
            "retire" => {
                let kid = action_arg.ok_or_else(|| "missing kid".to_string())?;
                Ok(AuthCommand::KeyRetire { target, kid })
            }
            _ => Err(format!("unknown auth key action: {action}")),
        },
        "token" => match action.as_str() {
            "mint" => {
                let sub = sub.ok_or_else(|| "missing --sub".to_string())?;
                Ok(AuthCommand::TokenMint {
                    target,
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

async fn execute_cluster_command(
    target: AuthTarget,
    cmd: AuthCommand,
) -> Result<Vec<String>, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (addr, tls_dir) = match target {
        AuthTarget::Cluster { addr, tls_dir } => (addr, tls_dir),
        AuthTarget::Local { .. } => {
            return Err("local auth target passed to cluster command handler".to_string())
        }
    };
    let tls = RaftTlsConfig::load(tls_dir)?;
    let mut client = AuthClient::connect(addr, tls).await?;

    match cmd {
        AuthCommand::KeyRotate { .. } => {
            let key = client.rotate_key().await?;
            Ok(vec![format!(
                "rotated key: {} (created {}, status {:?})",
                key.kid, key.created_at, key.status
            )])
        }
        AuthCommand::KeyList { .. } => {
            let (active_kid, keys) = client.list_keys().await?;
            let mut lines = vec![format!("active kid: {active_kid}")];
            for key in keys {
                let active = if key.signing { "signing" } else { "" };
                lines.push(format!(
                    "kid: {} status: {:?} created: {} {}",
                    key.kid, key.status, key.created_at, active
                ));
            }
            Ok(lines)
        }
        AuthCommand::KeyRetire { kid, .. } => {
            client.retire_key(&kid).await?;
            Ok(vec![format!("retired key: {kid}")])
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
            Ok(vec![token])
        }
    }
}

fn ensure_local_keyset(tls_dir: &Path) -> Result<(PathBuf, ApiKeySet), String> {
    let keyset = api_auth::ensure_local_keyset(tls_dir)?;
    Ok((api_auth::local_keyset_path(tls_dir), keyset))
}

fn load_cluster_keyset_for_local_target(tls_dir: &Path) -> Result<Option<ApiKeySet>, String> {
    let Some(local_root) = tls_dir.parent() else {
        return Ok(None);
    };
    let cluster_raft_dir = local_root.join("cluster").join("raft");
    if !cluster_raft_dir.exists() {
        return Ok(None);
    }
    let store = ClusterStore::open_read_only(cluster_raft_dir).map_err(|err| err.to_string())?;
    let Some(keyset) = api_auth::load_keyset_from_store(&store)? else {
        return Ok(None);
    };
    api_auth::persist_keyset_to_file(&api_auth::local_keyset_path(tls_dir), &keyset)?;
    Ok(Some(keyset))
}

fn execute_local_command(target: AuthTarget, cmd: AuthCommand) -> Result<Vec<String>, String> {
    let tls_dir = match target {
        AuthTarget::Local { tls_dir } => tls_dir,
        AuthTarget::Cluster { .. } => {
            return Err("cluster auth target passed to local command handler".to_string())
        }
    };
    let (path, mut keyset) = ensure_local_keyset(&tls_dir)?;
    let cluster_keyset = load_cluster_keyset_for_local_target(&tls_dir)?;

    match cmd {
        AuthCommand::KeyRotate { .. } => {
            if cluster_keyset.is_some() {
                return Err(
                    "clustered node detected; use --cluster-addr/--cluster-tls-dir for auth key rotation"
                        .to_string(),
                );
            }
            let key = api_auth::rotate_key(&mut keyset)?;
            api_auth::persist_keyset_to_file(&path, &keyset)?;
            Ok(vec![format!(
                "rotated key: {} (created {}, status {:?})",
                key.kid, key.created_at, key.status
            )])
        }
        AuthCommand::KeyList { .. } => {
            let keyset = cluster_keyset.as_ref().unwrap_or(&keyset);
            let mut lines = vec![format!("active kid: {}", keyset.active_kid)];
            for key in api_auth::list_summaries(&keyset) {
                let active = if key.signing { "signing" } else { "" };
                lines.push(format!(
                    "kid: {} status: {:?} created: {} {}",
                    key.kid, key.status, key.created_at, active
                ));
            }
            Ok(lines)
        }
        AuthCommand::KeyRetire { kid, .. } => {
            if cluster_keyset.is_some() {
                return Err(
                    "clustered node detected; use --cluster-addr/--cluster-tls-dir for auth key retirement"
                        .to_string(),
                );
            }
            api_auth::retire_key(&mut keyset, &kid)?;
            api_auth::persist_keyset_to_file(&path, &keyset)?;
            Ok(vec![format!("retired key: {kid}")])
        }
        AuthCommand::TokenMint {
            sub,
            ttl_secs,
            kid,
            roles,
            ..
        } => {
            let ttl = ttl_secs.or(Some(DEFAULT_TTL_SECS));
            let keyset = cluster_keyset.as_ref().unwrap_or(&keyset);
            let token =
                api_auth::mint_token_with_roles(&keyset, &sub, ttl, kid.as_deref(), roles)?.token;
            Ok(vec![token])
        }
    }
}

async fn execute_auth_command(cmd: AuthCommand) -> Result<Vec<String>, String> {
    let target = match &cmd {
        AuthCommand::KeyRotate { target }
        | AuthCommand::KeyList { target }
        | AuthCommand::KeyRetire { target, .. }
        | AuthCommand::TokenMint { target, .. } => target.clone(),
    };

    match target {
        AuthTarget::Cluster { .. } => execute_cluster_command(target, cmd).await,
        AuthTarget::Local { .. } => execute_local_command(target, cmd),
    }
}

pub async fn run_auth_command(cmd: AuthCommand) -> Result<(), String> {
    for line in execute_auth_command(cmd).await? {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use neuwerk::controlplane::api_auth::API_KEYS_KEY;
    use neuwerk::controlplane::cluster::store::ClusterStore;
    use neuwerk::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
    use openraft::entry::EntryPayload;
    use openraft::storage::RaftStateMachine;
    use openraft::{CommittedLeaderId, Entry, LogId};
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn parse_auth_args_accepts_local_token_mint() {
        let args = vec![
            "token".to_string(),
            "mint".to_string(),
            "--sub".to_string(),
            "demo-admin".to_string(),
            "--roles".to_string(),
            "admin,viewer".to_string(),
            "--http-tls-dir".to_string(),
            "/tmp/http-tls".to_string(),
        ];
        let cmd = parse_auth_args("neuwerk", &args).expect("parse auth args");
        match cmd {
            AuthCommand::TokenMint {
                target: AuthTarget::Local { tls_dir },
                sub,
                roles,
                ..
            } => {
                assert_eq!(tls_dir, PathBuf::from("/tmp/http-tls"));
                assert_eq!(sub, "demo-admin");
                assert_eq!(roles, Some(vec!["admin".to_string(), "viewer".to_string()]));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parse_auth_args_rejects_mixed_cluster_and_local_targets() {
        let args = vec![
            "token".to_string(),
            "mint".to_string(),
            "--sub".to_string(),
            "demo-admin".to_string(),
            "--cluster-addr".to_string(),
            "127.0.0.1:9600".to_string(),
            "--http-tls-dir".to_string(),
            "/tmp/http-tls".to_string(),
        ];
        let err = parse_auth_args("neuwerk", &args).expect_err("expected mixed target error");
        assert!(err.contains("choose either cluster auth"));
    }

    #[tokio::test]
    async fn execute_auth_command_mints_local_token() {
        let tempdir = TempDir::new().expect("tempdir");
        let tls_dir = tempdir.path().join("http-tls");
        let output = execute_auth_command(AuthCommand::TokenMint {
            target: AuthTarget::Local {
                tls_dir: tls_dir.clone(),
            },
            sub: "demo-admin".to_string(),
            ttl_secs: Some(300),
            kid: None,
            roles: Some(vec!["admin".to_string()]),
        })
        .await
        .expect("mint token");
        assert_eq!(output.len(), 1);

        let keyset_path = api_auth::local_keyset_path(&tls_dir);
        let keyset = api_auth::load_keyset_from_file(&keyset_path)
            .expect("load keyset")
            .expect("missing keyset");
        let claims = api_auth::validate_token(&output[0], &keyset).expect("validate token");
        assert_eq!(claims.sub, "demo-admin");
        assert_eq!(claims.roles, Some(vec!["admin".to_string()]));
    }

    #[tokio::test]
    async fn execute_auth_command_prefers_cluster_keyset_when_present() {
        let tempdir = TempDir::new().expect("tempdir");
        let tls_dir = tempdir.path().join("http-tls");
        std::fs::create_dir_all(&tls_dir).expect("mkdir http tls");
        let local_keyset = api_auth::ensure_local_keyset(&tls_dir).expect("local keyset");

        let seed_tls_dir = tempdir.path().join("seed-http-tls");
        std::fs::create_dir_all(&seed_tls_dir).expect("mkdir seed tls");
        api_auth::ensure_local_keyset(&seed_tls_dir).expect("seed keyset");
        let cluster_keyset =
            api_auth::load_keyset_from_file(&api_auth::local_keyset_path(&seed_tls_dir))
                .expect("load seed keyset")
                .expect("missing seed keyset");
        assert_ne!(local_keyset.active_kid, cluster_keyset.active_kid);

        let mut store = ClusterStore::open(tempdir.path().join("cluster").join("raft")).unwrap();
        store
            .apply([Entry::<ClusterTypeConfig> {
                log_id: LogId::new(CommittedLeaderId::new(1, 1), 1),
                payload: EntryPayload::Normal(ClusterCommand::Put {
                    key: API_KEYS_KEY.to_vec(),
                    value: serde_json::to_vec(&cluster_keyset).expect("serialize keyset"),
                }),
            }])
            .await
            .expect("apply cluster keyset");

        let output = execute_auth_command(AuthCommand::TokenMint {
            target: AuthTarget::Local {
                tls_dir: tls_dir.clone(),
            },
            sub: "cluster-admin".to_string(),
            ttl_secs: Some(300),
            kid: None,
            roles: Some(vec!["admin".to_string()]),
        })
        .await
        .expect("mint token");

        let claims = api_auth::validate_token(&output[0], &cluster_keyset).expect("validate token");
        assert_eq!(claims.sub, "cluster-admin");
        assert_eq!(claims.roles, Some(vec!["admin".to_string()]));
    }
}
