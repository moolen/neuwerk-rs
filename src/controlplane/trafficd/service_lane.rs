use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;

use crate::dataplane::policy::CidrV4;

pub(super) fn clear_intercept_steering_rules(service_lane_iface: &str) {
    clear_table_chain("mangle", super::INTERCEPT_CHAIN, "tcp", service_lane_iface);
    clear_table_chain("nat", super::INTERCEPT_CHAIN, "tcp", service_lane_iface);
    clear_output_table_chain("mangle", super::INTERCEPT_REPLY_CHAIN, "tcp");
}

pub(super) fn apply_intercept_steering_rules(
    rules: &[super::InterceptSteeringRule],
    listen_addr: SocketAddr,
    service_lane_iface: &str,
) -> Result<(), String> {
    let listen_port = listen_addr.port();
    if matches!(listen_addr.ip(), IpAddr::V4(ip) if ip.is_unspecified()) {
        ensure_redirect_chain(super::INTERCEPT_CHAIN, "tcp")?;
        for rule in rules {
            run_iptables(intercept_redirect_rule_args(rule, listen_port))?;
        }
        return Ok(());
    }

    ensure_tproxy_chain(super::INTERCEPT_CHAIN, "tcp", service_lane_iface)?;
    ensure_output_mark_chain(super::INTERCEPT_REPLY_CHAIN, "tcp")?;

    let listen_ip = match listen_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => {
            return Err("trafficd intercept steering requires ipv4 listen addr".to_string());
        }
    };
    for rule in rules {
        run_iptables(intercept_tproxy_rule_args(
            rule,
            listen_ip,
            listen_port,
            super::SERVICE_LANE_TPROXY_FWMARK,
        ))?;
        run_iptables(intercept_reply_mark_rule_args(
            rule,
            super::SERVICE_LANE_REPLY_FWMARK,
        ))?;
    }
    Ok(())
}

pub(super) fn ensure_service_lane_routing(
    iface: &str,
    service_lane_ip: Ipv4Addr,
) -> Result<(), String> {
    ensure_service_lane_rp_filter_loose(iface)?;

    let local_table = super::SERVICE_LANE_LOCAL_TABLE.to_string();
    run_ip(&[
        "-4",
        "route",
        "replace",
        "local",
        "0.0.0.0/0",
        "dev",
        "lo",
        "table",
        &local_table,
    ])?;
    let fwmark_fragment = format!("fwmark 0x{:x}", super::SERVICE_LANE_TPROXY_FWMARK);
    let local_lookup_fragment = format!("lookup {}", super::SERVICE_LANE_LOCAL_TABLE);
    ensure_ip_rule_pref(
        super::SERVICE_LANE_LOCAL_RULE_PREF,
        &[fwmark_fragment.as_str(), local_lookup_fragment.as_str()],
        &[
            "fwmark".to_string(),
            format!(
                "0x{:x}/0x{:x}",
                super::SERVICE_LANE_TPROXY_FWMARK,
                super::SERVICE_LANE_TPROXY_FWMARK
            ),
            "lookup".to_string(),
            local_table.clone(),
        ],
    )?;

    let reply_table = super::SERVICE_LANE_REPLY_TABLE.to_string();
    run_ip(&[
        "-4",
        "neigh",
        "replace",
        super::SERVICE_LANE_PEER_IP.to_string().as_str(),
        "lladdr",
        super::SERVICE_LANE_PEER_MAC,
        "nud",
        "permanent",
        "dev",
        iface,
    ])?;
    run_ip(&[
        "-4",
        "route",
        "replace",
        "default",
        "via",
        super::SERVICE_LANE_PEER_IP.to_string().as_str(),
        "dev",
        iface,
        "table",
        &reply_table,
    ])?;
    let from_cidr = format!("{service_lane_ip}/32");
    let from_fragment = format!("from {service_lane_ip}");
    let reply_lookup_fragment = format!("lookup {}", super::SERVICE_LANE_REPLY_TABLE);
    ensure_ip_rule_pref(
        super::SERVICE_LANE_REPLY_RULE_PREF,
        &[from_fragment.as_str(), reply_lookup_fragment.as_str()],
        &[
            "from".to_string(),
            from_cidr,
            "lookup".to_string(),
            reply_table.clone(),
        ],
    )?;
    let reply_fwmark_fragment = format!("fwmark 0x{:x}", super::SERVICE_LANE_REPLY_FWMARK);
    ensure_ip_rule_pref(
        super::SERVICE_LANE_REPLY_MARK_RULE_PREF,
        &[
            reply_fwmark_fragment.as_str(),
            reply_lookup_fragment.as_str(),
        ],
        &[
            "fwmark".to_string(),
            format!(
                "0x{:x}/0x{:x}",
                super::SERVICE_LANE_REPLY_FWMARK,
                super::SERVICE_LANE_REPLY_FWMARK
            ),
            "lookup".to_string(),
            reply_table,
        ],
    )?;
    Ok(())
}

pub(super) fn ensure_service_lane_interface(
    iface: &str,
    ip: Ipv4Addr,
    prefix: u8,
) -> Result<(), String> {
    let exists = run_ip(&["link", "show", "dev", iface]).is_ok();
    if !exists {
        run_ip(&["tuntap", "add", "dev", iface, "mode", "tap"])?;
    }
    run_ip(&["link", "set", "dev", iface, "up"])?;
    let expected = format!("{}/{}", ip, prefix.min(32));
    let addr_show = run_ip(&["-4", "addr", "show", "dev", iface])?;
    if !addr_show.contains(&expected) {
        let _ = run_ip(&["-4", "addr", "add", &expected, "dev", iface]);
    }
    Ok(())
}

pub(super) fn intercept_tproxy_rule_args(
    rule: &super::InterceptSteeringRule,
    listen_ip: Ipv4Addr,
    listen_port: u16,
    fwmark: u32,
) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-A".to_string(),
        super::INTERCEPT_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-d".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--dport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("TPROXY".to_string());
    args.push("--on-ip".to_string());
    args.push(listen_ip.to_string());
    args.push("--on-port".to_string());
    args.push(listen_port.to_string());
    args.push("--tproxy-mark".to_string());
    args.push(format!("0x{fwmark:x}/0x{fwmark:x}"));
    args
}

pub(super) fn intercept_reply_mark_rule_args(
    rule: &super::InterceptSteeringRule,
    fwmark: u32,
) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-A".to_string(),
        super::INTERCEPT_REPLY_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-d".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-s".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--sport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("MARK".to_string());
    args.push("--set-xmark".to_string());
    args.push(format!("0x{fwmark:x}/0x{fwmark:x}"));
    args
}

pub(super) fn rule_line_matches(line: &str, required_fragments: &[&str]) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && required_fragments
            .iter()
            .all(|fragment| trimmed.contains(fragment))
}

fn run_iptables(args: Vec<String>) -> Result<(), String> {
    let status = Command::new("iptables")
        .args(&args)
        .status()
        .map_err(|err| format!("iptables invocation failed: {err}"))?;
    if status.success() {
        return Ok(());
    }
    Err(format!("iptables {:?} failed with status {}", args, status))
}

fn iptables_check(args: Vec<String>) -> bool {
    Command::new("iptables")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn iptables_chain_exists(table: &str, chain: &str) -> bool {
    iptables_check(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-L".to_string(),
        chain.to_string(),
    ])
}

fn delete_chain_jump(
    table: &str,
    parent_chain: &str,
    chain: &str,
    proto: &str,
    iface: Option<&str>,
) {
    let mut check_args = vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-C".to_string(),
        parent_chain.to_string(),
    ];
    if let Some(iface) = iface {
        check_args.push("-i".to_string());
        check_args.push(iface.to_string());
    }
    check_args.push("-p".to_string());
    check_args.push(proto.to_string());
    check_args.push("-j".to_string());
    check_args.push(chain.to_string());
    let mut delete_args = check_args.clone();
    delete_args[3] = "-D".to_string();
    while iptables_check(check_args.clone()) {
        let _ = run_iptables(delete_args.clone());
    }
}

fn delete_prerouting_jump(table: &str, chain: &str, proto: &str, iface: Option<&str>) {
    delete_chain_jump(table, "PREROUTING", chain, proto, iface);
}

fn delete_output_jump(table: &str, chain: &str, proto: &str) {
    delete_chain_jump(table, "OUTPUT", chain, proto, None);
}

fn clear_table_chain(table: &str, chain: &str, proto: &str, iface: &str) {
    if !iptables_chain_exists(table, chain) {
        return;
    }
    delete_prerouting_jump(table, chain, proto, Some(iface));
    delete_prerouting_jump(table, chain, proto, None);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-F".to_string(),
        chain.to_string(),
    ]);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-X".to_string(),
        chain.to_string(),
    ]);
}

fn clear_output_table_chain(table: &str, chain: &str, proto: &str) {
    if !iptables_chain_exists(table, chain) {
        return;
    }
    delete_output_jump(table, chain, proto);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-F".to_string(),
        chain.to_string(),
    ]);
    let _ = run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        table.to_string(),
        "-X".to_string(),
        chain.to_string(),
    ]);
}

fn ensure_tproxy_chain(chain: &str, proto: &str, iface: &str) -> Result<(), String> {
    if !iptables_chain_exists("mangle", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "mangle".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_prerouting_jump("mangle", chain, proto, Some(iface));
    delete_prerouting_jump("mangle", chain, proto, None);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-I".to_string(),
        "PREROUTING".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn ensure_redirect_chain(chain: &str, proto: &str) -> Result<(), String> {
    if !iptables_chain_exists("nat", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "nat".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_prerouting_jump("nat", chain, proto, None);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-I".to_string(),
        "PREROUTING".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn ensure_output_mark_chain(chain: &str, proto: &str) -> Result<(), String> {
    if !iptables_chain_exists("mangle", chain) {
        run_iptables(vec![
            "-w".to_string(),
            "-t".to_string(),
            "mangle".to_string(),
            "-N".to_string(),
            chain.to_string(),
        ])?;
    }
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-F".to_string(),
        chain.to_string(),
    ])?;
    delete_output_jump("mangle", chain, proto);
    run_iptables(vec![
        "-w".to_string(),
        "-t".to_string(),
        "mangle".to_string(),
        "-I".to_string(),
        "OUTPUT".to_string(),
        "1".to_string(),
        "-p".to_string(),
        proto.to_string(),
        "-j".to_string(),
        chain.to_string(),
    ])?;
    Ok(())
}

fn cidr_to_iptables_arg(cidr: CidrV4) -> String {
    format!("{}/{}", cidr.addr(), cidr.prefix())
}

fn intercept_redirect_rule_args(
    rule: &super::InterceptSteeringRule,
    listen_port: u16,
) -> Vec<String> {
    let mut args = vec![
        "-w".to_string(),
        "-t".to_string(),
        "nat".to_string(),
        "-A".to_string(),
        super::INTERCEPT_CHAIN.to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        cidr_to_iptables_arg(rule.src_cidr),
    ];
    if let Some(dst_cidr) = rule.dst_cidr {
        args.push("-d".to_string());
        args.push(cidr_to_iptables_arg(dst_cidr));
    }
    if let Some(dst_port) = rule.dst_port {
        args.push("-m".to_string());
        args.push("tcp".to_string());
        args.push("--dport".to_string());
        if dst_port.start == dst_port.end {
            args.push(dst_port.start.to_string());
        } else {
            args.push(format!("{}:{}", dst_port.start, dst_port.end));
        }
    }
    args.push("-j".to_string());
    args.push("REDIRECT".to_string());
    args.push("--to-ports".to_string());
    args.push(listen_port.to_string());
    args
}

fn run_ip(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|err| format!("ip invocation failed: {err}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    Err(format!(
        "ip {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn run_ip_owned(args: Vec<String>) -> Result<String, String> {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ip(&refs)
}

fn ensure_ip_rule_pref(
    pref: u32,
    required_fragments: &[&str],
    add_tail_args: &[String],
) -> Result<(), String> {
    let pref_str = pref.to_string();
    let existing = run_ip(&["-4", "rule", "show", "pref", &pref_str])?;
    if rule_line_matches(&existing, required_fragments) {
        return Ok(());
    }
    if !existing.trim().is_empty() {
        run_ip(&["-4", "rule", "del", "pref", &pref_str])?;
    }
    let mut args = vec![
        "-4".to_string(),
        "rule".to_string(),
        "add".to_string(),
        "pref".to_string(),
        pref_str,
    ];
    args.extend_from_slice(add_tail_args);
    run_ip_owned(args)?;
    Ok(())
}

fn ensure_service_lane_rp_filter_loose(iface: &str) -> Result<(), String> {
    let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
    let current = fs::read_to_string(&path)
        .map_err(|err| format!("read {path} failed: {err}"))?
        .trim()
        .parse::<u8>()
        .map_err(|err| format!("parse {path} failed: {err}"))?;
    if current >= 2 {
        return Ok(());
    }
    fs::write(&path, "2").map_err(|err| format!("write {path} failed: {err}"))?;
    Ok(())
}
