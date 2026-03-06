use super::*;

pub(super) fn parse_default_policy(value: PolicyValue) -> Result<DefaultPolicy, String> {
    match value {
        PolicyValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "allow" => Ok(DefaultPolicy::Allow),
            "deny" => Ok(DefaultPolicy::Deny),
            _ => Err(format!("invalid default policy: {value}")),
        },
    }
}

pub(super) fn parse_rule_action(value: PolicyValue) -> Result<RuleAction, String> {
    match value {
        PolicyValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "allow" => Ok(RuleAction::Allow),
            "deny" => Ok(RuleAction::Deny),
            _ => Err(format!("invalid rule action: {value}")),
        },
    }
}

pub(super) fn parse_proto(value: ProtoValue) -> Result<Proto, String> {
    match value {
        ProtoValue::String(value) => match value.to_ascii_lowercase().as_str() {
            "any" => Ok(Proto::Any),
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            "icmp" => Ok(Proto::Icmp),
            other => other
                .parse::<u8>()
                .map(parse_proto_number)
                .map_err(|_| format!("invalid proto value: {value}")),
        },
        ProtoValue::Number(value) => Ok(parse_proto_number(value)),
    }
}

pub(super) fn parse_proto_number(value: u8) -> Proto {
    match value {
        6 => Proto::Tcp,
        17 => Proto::Udp,
        1 => Proto::Icmp,
        _ => Proto::Other(value),
    }
}

pub(super) fn parse_port_range(spec: PortSpec) -> Result<PortRange, String> {
    match spec {
        PortSpec::Number(value) => Ok(PortRange {
            start: value,
            end: value,
        }),
        PortSpec::String(value) => {
            if let Some((start, end)) = value.split_once('-') {
                let start = start
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range start: {value}"))?;
                let end = end
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port range end: {value}"))?;
                if start > end {
                    return Err(format!("invalid port range: {value}"));
                }
                Ok(PortRange { start, end })
            } else {
                let port = value
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("invalid port: {value}"))?;
                Ok(PortRange {
                    start: port,
                    end: port,
                })
            }
        }
    }
}

pub(super) fn parse_cidr_v4(value: &str) -> Result<CidrV4, String> {
    if let Some((addr, prefix)) = value.split_once('/') {
        let addr = parse_ipv4(addr)?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| format!("invalid prefix length: {value}"))?;
        if prefix > 32 {
            return Err(format!("invalid prefix length: {value}"));
        }
        Ok(CidrV4::new(addr, prefix))
    } else {
        let addr = parse_ipv4(value)?;
        Ok(CidrV4::new(addr, 32))
    }
}

pub(super) fn parse_ipv4(value: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address: {value}"))
}

pub(super) fn parse_sha256_fingerprint(value: &str) -> Result<[u8; 32], String> {
    let cleaned: String = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if cleaned.len() != 64 {
        return Err(format!("invalid sha256 fingerprint length: {value}"));
    }
    let bytes = hex::decode(cleaned).map_err(|_| format!("invalid sha256 fingerprint: {value}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(super) fn parse_pem_cert_chain(value: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut input = value.as_bytes();
    let mut certs = Vec::new();
    loop {
        while let Some(b) = input.first() {
            if b.is_ascii_whitespace() {
                input = &input[1..];
            } else {
                break;
            }
        }
        if input.is_empty() {
            break;
        }
        let (rest, pem) =
            parse_x509_pem(input).map_err(|_| "invalid PEM certificate".to_string())?;
        if pem.label != "CERTIFICATE" {
            return Err("unsupported PEM label for trust anchor".to_string());
        }
        certs.push(pem.contents.to_vec());
        input = rest;
    }
    if certs.is_empty() {
        return Err("trust_anchors_pem cannot be empty".to_string());
    }
    Ok(certs)
}

pub(super) fn compile_dns_rule(
    rule_id: &str,
    priority: u32,
    action: RuleAction,
    mode: DataplaneRuleMode,
    hostname: Option<&str>,
) -> Result<Option<DnsRule>, String> {
    let Some(hostname) = hostname else {
        return Ok(None);
    };
    let hostname = hostname.trim();
    if hostname.is_empty() {
        return Err(format!("rule {rule_id}: dns_hostname cannot be empty"));
    }
    let regex = RegexBuilder::new(hostname)
        .case_insensitive(true)
        .build()
        .map_err(|err| format!("rule {rule_id}: invalid dns_hostname regex: {err}"))?;
    Ok(Some(DnsRule {
        id: rule_id.to_string(),
        priority,
        action,
        mode,
        hostname: regex,
    }))
}

pub(super) fn normalize_hostname(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub(super) fn normalize_header_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

pub(super) fn compile_optional_regex(
    pattern: Option<String>,
    rule_id: &str,
    field: &str,
    case_insensitive: bool,
) -> Result<Option<Regex>, String> {
    match pattern {
        Some(pattern) => Ok(Some(compile_regex(
            &pattern,
            rule_id,
            field,
            case_insensitive,
        )?)),
        None => Ok(None),
    }
}

pub(super) fn compile_regex(
    pattern: &str,
    rule_id: &str,
    field: &str,
    case_insensitive: bool,
) -> Result<Regex, String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err(format!("rule {rule_id}: {field} regex cannot be empty"));
    }
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|err| format!("rule {rule_id}: invalid {field} regex: {err}"))
}
