#[cfg(test)]
use super::{usage, CliConfig};

pub const RUNTIME_STARTUP_UNSUPPORTED_MESSAGE: &str =
    "runtime startup no longer accepts CLI flags; configure /etc/neuwerk/config.yaml instead";

#[cfg(test)]
fn parse_args(bin: &str, args: Vec<String>) -> Result<CliConfig, String> {
    if args.iter().any(|arg| matches!(arg.as_str(), "-h" | "--help")) {
        return Err(usage(bin));
    }

    Err(RUNTIME_STARTUP_UNSUPPORTED_MESSAGE.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::{parse_args, RUNTIME_STARTUP_UNSUPPORTED_MESSAGE};
    use crate::runtime::auth::{parse_auth_args, AuthCommand, AuthTarget};
    use crate::runtime::cluster::{parse_cluster_args, ClusterCommand};
    use crate::runtime::cli::usage;
    use crate::runtime::sysdump::parse_sysdump_args;

    #[test]
    fn parse_args_rejects_legacy_runtime_flags() {
        let err = parse_args(
            "neuwerk",
            vec![
                "--management-interface".to_string(),
                "mgmt0".to_string(),
                "--data-plane-interface".to_string(),
                "data0".to_string(),
            ],
        )
            .expect_err("legacy runtime flags must be rejected");

        assert_eq!(err, RUNTIME_STARTUP_UNSUPPORTED_MESSAGE);
    }

    #[test]
    fn runtime_usage_points_to_config_yaml() {
        let text = usage("neuwerk");

        assert!(text.contains("/etc/neuwerk/config.yaml"));
        assert!(!text.contains("--management-interface"));
    }

    #[test]
    fn auth_cluster_flow_still_parses() {
        let args = vec![
            "key".to_string(),
            "list".to_string(),
            "--cluster-addr".to_string(),
            "127.0.0.1:7000".to_string(),
        ];

        let cmd = parse_auth_args("neuwerk", &args).expect("auth command");

        match cmd {
            AuthCommand::KeyList {
                target:
                    AuthTarget::Cluster { addr, tls_dir },
            } => {
                assert_eq!(
                    addr,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7000)
                );
                assert_eq!(tls_dir, PathBuf::from("/var/lib/neuwerk/cluster/tls"));
            }
            other => panic!("unexpected auth command: {other:?}"),
        }
    }

    #[test]
    fn sysdump_flow_still_parses() {
        let args = vec![
            "--output".to_string(),
            "/tmp/neuwerk-sysdump.tar.gz".to_string(),
        ];

        let parsed = parse_sysdump_args("neuwerk", &args).expect("sysdump args");

        assert_eq!(
            parsed.output,
            Some(PathBuf::from("/tmp/neuwerk-sysdump.tar.gz"))
        );
    }

    #[test]
    fn cluster_members_remove_flow_parses() {
        let args = vec![
            "members".to_string(),
            "remove".to_string(),
            "42".to_string(),
            "--http-addr".to_string(),
            "127.0.0.1:8443".to_string(),
            "--token".to_string(),
            "jwt".to_string(),
            "--force".to_string(),
        ];

        let cmd = parse_cluster_args("neuwerk", &args).expect("cluster args");

        assert!(matches!(
            cmd,
            ClusterCommand::MemberRemove {
                node_id: 42,
                force: true,
                ..
            }
        ));
    }

    #[test]
    fn top_level_usage_mentions_cluster_commands() {
        let text = usage("neuwerk");

        assert!(text.contains("neuwerk cluster members list"));
        assert!(text.contains("neuwerk cluster voters set"));
    }
}
