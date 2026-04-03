use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use neuwerk::controlplane::cluster::types::NodeId;
use reqwest::{Client, Method};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::runtime::cli::{parse_socket, take_flag_value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterCommand {
    MembersList {
        http_addr: SocketAddr,
        token: String,
        ca: Option<PathBuf>,
    },
    MemberRemove {
        http_addr: SocketAddr,
        token: String,
        ca: Option<PathBuf>,
        node_id: NodeId,
        force: bool,
    },
    VotersSet {
        http_addr: SocketAddr,
        token: String,
        ca: Option<PathBuf>,
        ids: Vec<NodeId>,
        force: bool,
    },
}

pub fn cluster_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} cluster members list --http-addr <ip:port> --token <jwt> [--ca <path>]\n  {bin} cluster members remove <node-id> --http-addr <ip:port> --token <jwt> [--ca <path>] [--force]\n  {bin} cluster voters set --ids <csv> --http-addr <ip:port> --token <jwt> [--ca <path>] [--force]\n"
    )
}

pub fn parse_cluster_args(bin: &str, args: &[String]) -> Result<ClusterCommand, String> {
    let mut args = args.iter().cloned();
    let Some(section) = args.next() else {
        return Err(cluster_usage(bin));
    };
    let Some(action) = args.next() else {
        return Err("missing cluster action".to_string());
    };

    let mut http_addr = None;
    let mut token = None;
    let mut ca = None;
    let mut ids = None;
    let mut force = false;
    let mut positionals = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Err(cluster_usage(bin)),
            "--force" => {
                force = true;
                continue;
            }
            _ => {}
        }
        if arg == "--http-addr" || arg.starts_with("--http-addr=") {
            let value = take_flag_value("--http-addr", &arg, &mut args)?;
            http_addr = Some(parse_socket("--http-addr", &value)?);
            continue;
        }
        if arg == "--token" || arg.starts_with("--token=") {
            token = Some(take_flag_value("--token", &arg, &mut args)?);
            continue;
        }
        if arg == "--ca" || arg.starts_with("--ca=") {
            ca = Some(PathBuf::from(take_flag_value("--ca", &arg, &mut args)?));
            continue;
        }
        if arg == "--ids" || arg.starts_with("--ids=") {
            let value = take_flag_value("--ids", &arg, &mut args)?;
            ids = Some(parse_node_ids_csv(&value)?);
            continue;
        }
        positionals.push(arg);
    }

    let http_addr = http_addr.ok_or_else(|| "missing --http-addr".to_string())?;
    let token = token.ok_or_else(|| "missing --token".to_string())?;

    match (section.as_str(), action.as_str()) {
        ("members", "list") => {
            if force {
                return Err("--force is only valid for mutating cluster commands".to_string());
            }
            if ids.is_some() {
                return Err("--ids is only valid for voters set".to_string());
            }
            if !positionals.is_empty() {
                return Err(format!("unexpected positional arguments: {}", positionals.join(" ")));
            }
            Ok(ClusterCommand::MembersList {
                http_addr,
                token,
                ca,
            })
        }
        ("members", "remove") => {
            if positionals.len() != 1 {
                return Err("members remove requires <node-id>".to_string());
            }
            if ids.is_some() {
                return Err("--ids is only valid for voters set".to_string());
            }
            let node_id = parse_node_id(&positionals[0], "<node-id>")?;
            Ok(ClusterCommand::MemberRemove {
                http_addr,
                token,
                ca,
                node_id,
                force,
            })
        }
        ("voters", "set") => {
            if !positionals.is_empty() {
                return Err(format!("unexpected positional arguments: {}", positionals.join(" ")));
            }
            let ids = ids.ok_or_else(|| "missing --ids".to_string())?;
            Ok(ClusterCommand::VotersSet {
                http_addr,
                token,
                ca,
                ids,
                force,
            })
        }
        ("members", other) => Err(format!("unknown cluster members action: {other}")),
        ("voters", other) => Err(format!("unknown cluster voters action: {other}")),
        (other, _) => Err(format!("unknown cluster command: {other}")),
    }
}

pub async fn run_cluster_command(cmd: ClusterCommand) -> Result<(), String> {
    let client = build_http_client(command_ca_path(&cmd))?;

    match cmd {
        ClusterCommand::MembersList {
            http_addr, token, ..
        } => {
            let mut response: ClusterMembersResponse =
                send_request(&client, Method::GET, http_addr, "/api/v1/cluster/members", &token, None)
                    .await?;
            response.members.sort_by(|left, right| {
                let left = left.node_id.parse::<NodeId>().unwrap_or(0);
                let right = right.node_id.parse::<NodeId>().unwrap_or(0);
                left.cmp(&right)
            });
            for line in render_members_lines(&response.members) {
                println!("{line}");
            }
        }
        ClusterCommand::MemberRemove {
            http_addr,
            token,
            node_id,
            force,
            ..
        } => {
            let response: ClusterVotersResponse = send_request(
                &client,
                Method::POST,
                http_addr,
                &format!("/api/v1/cluster/members/{node_id}/remove"),
                &token,
                Some(serde_json::json!({ "force": force })),
            )
            .await?;
            println!("voters: {}", format_voters(&response.voters));
        }
        ClusterCommand::VotersSet {
            http_addr,
            token,
            ids,
            force,
            ..
        } => {
            let response: ClusterVotersResponse = send_request(
                &client,
                Method::PUT,
                http_addr,
                "/api/v1/cluster/members/voters",
                &token,
                Some(serde_json::json!({
                    "ids": ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
                    "force": force,
                })),
            )
            .await?;
            println!("voters: {}", format_voters(&response.voters));
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ClusterMembersResponse {
    members: Vec<ClusterMemberView>,
}

#[derive(Debug, Deserialize)]
struct ClusterMemberView {
    node_id: String,
    addr: String,
    role: String,
    is_voter: bool,
    cloud_status: String,
    drain_state: Option<String>,
    termination_event_id: Option<String>,
    auto_evict_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ClusterVotersResponse {
    voters: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
}

fn command_ca_path(cmd: &ClusterCommand) -> Option<&Path> {
    match cmd {
        ClusterCommand::MembersList { ca, .. }
        | ClusterCommand::MemberRemove { ca, .. }
        | ClusterCommand::VotersSet { ca, .. } => ca.as_deref(),
    }
}

fn parse_node_ids_csv(value: &str) -> Result<Vec<NodeId>, String> {
    let ids = value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(|entry| parse_node_id(entry, "--ids"))
        .collect::<Result<Vec<_>, _>>()?;
    if ids.is_empty() {
        return Err("--ids must not be empty".to_string());
    }
    Ok(ids)
}

fn parse_node_id(value: &str, label: &str) -> Result<NodeId, String> {
    value
        .parse::<NodeId>()
        .map_err(|_| format!("{label} must be a numeric node id, got {value}"))
}

fn build_http_client(ca_path: Option<&Path>) -> Result<Client, String> {
    let mut builder = Client::builder();
    if let Some(ca_path) = ca_path {
        let pem =
            std::fs::read(ca_path).map_err(|err| format!("read ca {}: {err}", ca_path.display()))?;
        let ca = reqwest::Certificate::from_pem(&pem)
            .map_err(|err| format!("invalid ca {}: {err}", ca_path.display()))?;
        builder = builder.add_root_certificate(ca);
    }
    builder
        .build()
        .map_err(|err| format!("http client build failed: {err}"))
}

async fn send_request<T: DeserializeOwned>(
    client: &Client,
    method: Method,
    http_addr: SocketAddr,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> Result<T, String> {
    let mut request = client.request(method, format!("https://{http_addr}{path}"));
    request = request.bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|err| format!("cluster api request failed: {err}"))?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|err| format!("cluster api response read failed: {err}"))?;
    if !status.is_success() {
        if let Ok(error) = serde_json::from_slice::<ErrorBody>(&bytes) {
            return Err(format!("cluster api status {status}: {}", error.error));
        }
        let body = String::from_utf8_lossy(&bytes);
        let body = body.trim();
        if body.is_empty() {
            return Err(format!("cluster api status {status}"));
        }
        return Err(format!("cluster api status {status}: {body}"));
    }
    serde_json::from_slice(&bytes).map_err(|err| format!("cluster api decode failed: {err}"))
}

fn render_members_lines(members: &[ClusterMemberView]) -> Vec<String> {
    members
        .iter()
        .map(|member| {
            let mut line = format!(
                "{} role={} voter={} addr={} cloud={}",
                member.node_id,
                member.role,
                if member.is_voter { "yes" } else { "no" },
                member.addr,
                member.cloud_status
            );
            if let Some(reason) = &member.auto_evict_reason {
                line.push_str(&format!(" auto_evict={reason}"));
            }
            if let Some(state) = &member.drain_state {
                line.push_str(&format!(" drain={state}"));
            }
            if let Some(event_id) = &member.termination_event_id {
                line.push_str(&format!(" termination_event={event_id}"));
            }
            line
        })
        .collect()
}

fn format_voters(voters: &[String]) -> String {
    let mut voters = voters.to_vec();
    voters.sort_by(|left, right| {
        let left = left.parse::<NodeId>().unwrap_or(0);
        let right = right.parse::<NodeId>().unwrap_or(0);
        left.cmp(&right)
    });
    voters.join(",")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::{parse_cluster_args, render_members_lines, ClusterCommand, ClusterMemberView};

    #[test]
    fn cluster_members_list_parses() {
        let args = vec![
            "members".to_string(),
            "list".to_string(),
            "--http-addr".to_string(),
            "127.0.0.1:8443".to_string(),
            "--token".to_string(),
            "jwt".to_string(),
            "--ca".to_string(),
            "/tmp/http-ca.crt".to_string(),
        ];

        let cmd = parse_cluster_args("neuwerk", &args).expect("cluster command");

        assert_eq!(
            cmd,
            ClusterCommand::MembersList {
                http_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
                token: "jwt".to_string(),
                ca: Some(PathBuf::from("/tmp/http-ca.crt")),
            }
        );
    }

    #[test]
    fn cluster_voters_set_parses_force_and_ids() {
        let args = vec![
            "voters".to_string(),
            "set".to_string(),
            "--ids".to_string(),
            "1,2,3".to_string(),
            "--http-addr".to_string(),
            "127.0.0.1:8443".to_string(),
            "--token".to_string(),
            "jwt".to_string(),
            "--force".to_string(),
        ];

        let cmd = parse_cluster_args("neuwerk", &args).expect("cluster command");

        assert_eq!(
            cmd,
            ClusterCommand::VotersSet {
                http_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
                token: "jwt".to_string(),
                ca: None,
                ids: vec![1, 2, 3],
                force: true,
            }
        );
    }

    #[test]
    fn render_members_lines_includes_optional_fields() {
        let lines = render_members_lines(&[ClusterMemberView {
            node_id: "2".to_string(),
            addr: "127.0.0.2:9600".to_string(),
            role: "follower".to_string(),
            is_voter: true,
            cloud_status: "missing_from_discovery".to_string(),
            drain_state: None,
            termination_event_id: Some("evt-2".to_string()),
            auto_evict_reason: Some("missing_from_discovery:42".to_string()),
        }]);

        assert_eq!(
            lines,
            vec![
                "2 role=follower voter=yes addr=127.0.0.2:9600 cloud=missing_from_discovery auto_evict=missing_from_discovery:42 termination_event=evt-2"
                    .to_string()
            ]
        );
    }

    #[test]
    fn cluster_members_list_rejects_mutation_only_flags() {
        let args = vec![
            "members".to_string(),
            "list".to_string(),
            "--http-addr".to_string(),
            "127.0.0.1:8443".to_string(),
            "--token".to_string(),
            "jwt".to_string(),
            "--force".to_string(),
        ];

        let err = parse_cluster_args("neuwerk", &args).expect_err("invalid cluster args");

        assert!(err.contains("--force"));
    }
}
