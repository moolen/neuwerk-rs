use std::net::SocketAddr;

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
