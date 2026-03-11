#![allow(clippy::format_in_format_args)]

use super::*;

pub(in crate::e2e::tests) fn overlay_policy_allow_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "overlay"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok::<(), String>(())
    })?;
    Ok(())
}

pub(in crate::e2e::tests) fn overlay_metrics_snapshot(metrics_addr: SocketAddr) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match runtime {
        Ok(rt) => rt
            .block_on(async { http_get_path(metrics_addr, "metrics", "/metrics").await })
            .unwrap_or_else(|e| format!("metrics fetch failed: {e}")),
        Err(e) => format!("metrics runtime error: {e}"),
    }
}

pub(in crate::e2e::tests) fn overlay_debug_snapshot(cfg: &TopologyConfig) -> String {
    fn run_cmd(cmd: &str, args: &[&str]) -> String {
        let display = if args.is_empty() {
            cmd.to_string()
        } else {
            format!("{cmd} {}", args.join(" "))
        };
        match Command::new(cmd).args(args).output() {
            Ok(output) => format!(
                "$ {display}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\n",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(err) => format!("$ {display}\nerror: {err}\n"),
        }
    }

    let mut out = String::new();
    let fw_ns = "fw-node";
    let dp0 = cfg.dp_tun_iface.as_str();
    let fw_dp = cfg.fw_dp_iface.as_str();
    let outer_dst = cfg.dp_public_ip.to_string();
    let inner_src = cfg.client_dp_ip.to_string();

    let cmds: Vec<(&str, Vec<&str>)> = vec![
        ("ip", vec!["netns", "exec", fw_ns, "ip", "-4", "rule"]),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "show", "table", "100",
            ],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-4", "route", "show"],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-s", "link", "show", dp0],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-s", "link", "show", fw_dp],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "addr", "show", "dev", dp0,
            ],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "sysctl", "net.ipv4.ip_forward"],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "get", &outer_dst, "iif", fw_dp,
            ],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "get", &inner_src, "iif", dp0,
            ],
        ),
    ];

    for (cmd, args) in cmds {
        out.push_str(&run_cmd(cmd, &args));
    }
    out
}

pub(in crate::e2e::tests) fn netns_read_u64(ns: &str, path: &str) -> Option<u64> {
    let output = Command::new("ip")
        .args(["netns", "exec", ns, "cat", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout);
    value.trim().parse::<u64>().ok()
}

pub(in crate::e2e::tests) fn dp_iface_rx_packets(cfg: &TopologyConfig) -> Option<u64> {
    let path = format!("/sys/class/net/{}/statistics/rx_packets", cfg.dp_tun_iface);
    netns_read_u64("fw-node", &path)
}
