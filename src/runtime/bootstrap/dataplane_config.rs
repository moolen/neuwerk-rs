use std::env;
use std::net::Ipv4Addr;
use std::time::Duration;

use serde::Deserialize;

const IMDS_NETWORK_URL: &str =
    "http://169.254.169.254/metadata/instance/network/interface?api-version=2021-02-01";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsNetworkInterface {
    mac_address: String,
    ipv4: Option<ImdsIpv4>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsIpv4 {
    ip_address: Vec<ImdsIpAddress>,
    subnet: Vec<ImdsSubnet>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsIpAddress {
    private_ip_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImdsSubnet {
    prefix: String,
}

pub async fn imds_dataplane_config(mac: [u8; 6]) -> Result<(Ipv4Addr, u8, Ipv4Addr), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(IMDS_NETWORK_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|err| format!("imds request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("imds request failed: {}", response.status()));
    }
    let payload: Vec<ImdsNetworkInterface> = response
        .json()
        .await
        .map_err(|err| format!("imds decode failed: {err}"))?;
    let target = format_mac_no_sep(mac);
    for nic in payload {
        if normalize_imds_mac(&nic.mac_address) != target {
            continue;
        }
        let Some(ipv4) = nic.ipv4 else {
            continue;
        };
        let ip = ipv4
            .ip_address
            .first()
            .and_then(|addr| addr.private_ip_address.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| "imds missing dataplane ip".to_string())?;
        let prefix = ipv4
            .subnet
            .first()
            .and_then(|subnet| subnet.prefix.parse::<u8>().ok())
            .ok_or_else(|| "imds missing subnet prefix".to_string())?;
        let gateway = subnet_gateway(ip, prefix)?;
        return Ok((ip, prefix, gateway));
    }
    Err("imds dataplane nic not found for mac".to_string())
}

pub async fn imds_dataplane_from_mgmt_ip(
    mgmt_ip: Ipv4Addr,
) -> Result<(Ipv4Addr, u8, Ipv4Addr, [u8; 6]), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|err| err.to_string())?;
    let response = client
        .get(IMDS_NETWORK_URL)
        .header("Metadata", "true")
        .send()
        .await
        .map_err(|err| format!("imds request failed: {err}"))?;
    if !response.status().is_success() {
        return Err(format!("imds request failed: {}", response.status()));
    }
    let payload: Vec<ImdsNetworkInterface> = response
        .json()
        .await
        .map_err(|err| format!("imds decode failed: {err}"))?;
    let mut dataplane: Option<(Ipv4Addr, u8, Ipv4Addr, [u8; 6])> = None;
    for nic in payload {
        let Some(ipv4) = nic.ipv4 else {
            continue;
        };
        let ip = ipv4
            .ip_address
            .first()
            .and_then(|addr| addr.private_ip_address.parse::<Ipv4Addr>().ok())
            .ok_or_else(|| "imds missing ip address".to_string())?;
        if ip == mgmt_ip {
            continue;
        }
        let prefix = ipv4
            .subnet
            .first()
            .and_then(|subnet| subnet.prefix.parse::<u8>().ok())
            .ok_or_else(|| "imds missing subnet prefix".to_string())?;
        let gateway = subnet_gateway(ip, prefix)?;
        let mac = parse_imds_mac(&nic.mac_address)?;
        dataplane = Some((ip, prefix, gateway, mac));
        break;
    }
    dataplane.ok_or_else(|| "imds dataplane nic not found".to_string())
}

pub fn dpdk_static_config_from_env() -> Result<Option<firewall::dataplane::DataplaneConfig>, String>
{
    let ip_raw = match env::var("NEUWERK_DPDK_STATIC_IP") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let prefix_raw = env::var("NEUWERK_DPDK_STATIC_PREFIX").map_err(|_| {
        "NEUWERK_DPDK_STATIC_PREFIX is required when NEUWERK_DPDK_STATIC_IP is set".to_string()
    })?;
    let gateway_raw = env::var("NEUWERK_DPDK_STATIC_GATEWAY").map_err(|_| {
        "NEUWERK_DPDK_STATIC_GATEWAY is required when NEUWERK_DPDK_STATIC_IP is set".to_string()
    })?;
    let mac_raw = env::var("NEUWERK_DPDK_STATIC_MAC").map_err(|_| {
        "NEUWERK_DPDK_STATIC_MAC is required when NEUWERK_DPDK_STATIC_IP is set".to_string()
    })?;

    let ip = ip_raw
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid NEUWERK_DPDK_STATIC_IP={ip_raw}"))?;
    let prefix = prefix_raw
        .trim()
        .parse::<u8>()
        .map_err(|_| format!("invalid NEUWERK_DPDK_STATIC_PREFIX={prefix_raw}"))?;
    if prefix == 0 || prefix > 32 {
        return Err(format!("invalid NEUWERK_DPDK_STATIC_PREFIX={prefix_raw}"));
    }
    let gateway = gateway_raw
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid NEUWERK_DPDK_STATIC_GATEWAY={gateway_raw}"))?;
    let mac = crate::runtime::cli::parse_mac(mac_raw.trim())
        .ok_or_else(|| format!("invalid NEUWERK_DPDK_STATIC_MAC={mac_raw}"))?;

    Ok(Some(firewall::dataplane::DataplaneConfig {
        ip,
        prefix,
        gateway,
        mac,
        lease_expiry: None,
    }))
}

fn subnet_gateway(ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Addr, String> {
    if prefix == 0 || prefix > 32 {
        return Err(format!("invalid subnet prefix {prefix}"));
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(ip) & mask;
    let gateway = network.saturating_add(1);
    Ok(Ipv4Addr::from(gateway))
}

fn normalize_imds_mac(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace([':', '-'], "")
}

fn format_mac_no_sep(mac: [u8; 6]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn parse_imds_mac(value: &str) -> Result<[u8; 6], String> {
    let raw = normalize_imds_mac(value);
    if raw.len() != 12 {
        return Err("invalid imds mac".to_string());
    }
    let mut bytes = [0u8; 6];
    for idx in 0..6 {
        let start = idx * 2;
        let part = &raw[start..start + 2];
        bytes[idx] = u8::from_str_radix(part, 16).map_err(|_| "invalid imds mac".to_string())?;
    }
    Ok(bytes)
}
