use std::net::{Ipv4Addr, SocketAddr};

use firewall::controlplane::cloud::types::IntegrationMode;
use firewall::dataplane::policy::DefaultPolicy;

pub fn looks_like_pci(value: &str) -> bool {
    let value = value.trim();
    let value = value.strip_prefix("pci:").unwrap_or(value);
    is_pci_addr(value)
}

pub fn looks_like_mac(value: &str) -> bool {
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

pub fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = value.split([':', '-']).collect();
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

pub fn take_flag_value(
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

pub fn parse_socket(flag: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be a socket address in the form ip:port, got {value}"))
}

pub fn parse_ipv4(flag: &str, value: &str) -> Result<Ipv4Addr, String> {
    value
        .parse()
        .map_err(|_| format!("{flag} must be an IPv4 address, got {value}"))
}

pub fn parse_csv_ipv4_list(flag: &str, value: &str) -> Result<Vec<Ipv4Addr>, String> {
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

pub fn parse_csv_socket_list(flag: &str, value: &str) -> Result<Vec<SocketAddr>, String> {
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

pub fn parse_port(flag: &str, value: &str) -> Result<u16, String> {
    let parsed = value
        .parse::<u16>()
        .map_err(|_| format!("{flag} must be a valid UDP port, got {value}"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be between 1 and 65535, got {value}"));
    }
    Ok(parsed)
}

pub fn parse_vni(flag: &str, value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| format!("{flag} must be a number, got {value}"))?;
    if parsed > 0x00ff_ffff {
        return Err(format!("{flag} must be <= 16777215, got {value}"));
    }
    Ok(parsed)
}

pub fn parse_cidr(flag: &str, value: &str) -> Result<(Ipv4Addr, u8), String> {
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

pub fn parse_default_policy(value: &str) -> Result<DefaultPolicy, String> {
    match value.to_ascii_lowercase().as_str() {
        "allow" => Ok(DefaultPolicy::Allow),
        "deny" => Ok(DefaultPolicy::Deny),
        _ => Err(format!(
            "--default-policy must be allow or deny, got {value}"
        )),
    }
}

pub fn parse_integration_mode(value: &str) -> Result<IntegrationMode, String> {
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
