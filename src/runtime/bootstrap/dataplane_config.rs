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

pub fn dpdk_static_config_from_runtime(
    cfg: &crate::runtime::config::DerivedRuntimeConfig,
) -> Result<Option<neuwerk::dataplane::DataplaneConfig>, String> {
    let Some(dpdk) = cfg.operator.dpdk.as_ref() else {
        return Ok(None);
    };
    let Some(ip) = dpdk.static_ip else {
        return Ok(None);
    };
    let prefix = dpdk.static_prefix_len.ok_or_else(|| {
        "config validation error: dpdk.static_prefix_len is required when dpdk.static_ip is set"
            .to_string()
    })?;
    if prefix == 0 || prefix > 32 {
        return Err(format!("invalid dpdk.static_prefix_len={prefix}"));
    }
    let gateway = dpdk.static_gateway.ok_or_else(|| {
        "config validation error: dpdk.static_gateway is required when dpdk.static_ip is set"
            .to_string()
    })?;
    let mac_raw = dpdk.static_mac.as_deref().ok_or_else(|| {
        "config validation error: dpdk.static_mac is required when dpdk.static_ip is set"
            .to_string()
    })?;
    let mac = crate::runtime::cli::parse_mac(mac_raw.trim())
        .ok_or_else(|| format!("invalid dpdk.static_mac={mac_raw}"))?;

    Ok(Some(neuwerk::dataplane::DataplaneConfig {
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
    for (idx, byte) in bytes.iter_mut().enumerate() {
        let start = idx * 2;
        let part = &raw[start..start + 2];
        *byte = u8::from_str_radix(part, 16).map_err(|_| "invalid imds mac".to_string())?;
    }
    Ok(bytes)
}
