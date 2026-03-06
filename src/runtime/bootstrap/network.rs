use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::link::LinkAttribute;
use rtnetlink::new_connection;

pub async fn management_ipv4(iface: &str) -> Result<Ipv4Addr, String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);
    let index = get_link_index(&handle, iface).await?;
    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr lookup {iface} failed: {err}"))?
    {
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        task.abort();
                        return Ok(v4);
                    }
                }
                _ => {}
            }
        }
    }
    task.abort();
    Err(format!("no IPv4 address for interface {iface}"))
}

pub async fn dataplane_ipv4_config(iface: &str) -> Result<(Ipv4Addr, u8, [u8; 6]), String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);
    let index = get_link_index(&handle, iface).await?;

    let mut mac = [0u8; 6];
    let mut links = handle.link().get().match_index(index).execute();
    if let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link lookup {iface} failed: {err}"))?
    {
        for nla in msg.attributes {
            if let LinkAttribute::Address(addr) = nla {
                if addr.len() >= 6 {
                    mac.copy_from_slice(&addr[..6]);
                }
            }
        }
    }

    let mut addrs = handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr lookup {iface} failed: {err}"))?
    {
        let prefix = msg.header.prefix_len;
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        task.abort();
                        return Ok((v4, prefix, mac));
                    }
                }
                _ => {}
            }
        }
    }
    task.abort();
    Err(format!("no IPv4 address for interface {iface}"))
}

pub async fn internal_ipv4_config(
    management_iface: &str,
    data_plane_iface: &str,
) -> Result<(Ipv4Addr, u8), String> {
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);

    let mut link_names: HashMap<u32, String> = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link list failed: {err}"))?
    {
        let mut name = None;
        for nla in msg.attributes {
            if let LinkAttribute::IfName(value) = nla {
                name = Some(value);
                break;
            }
        }
        if let Some(name) = name {
            link_names.insert(msg.header.index, name);
        }
    }

    let mut candidates: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|err| format!("addr list failed: {err}"))?
    {
        let ifname = match link_names.get(&msg.header.index) {
            Some(name) => name.as_str(),
            None => continue,
        };
        if ifname == "lo" || ifname == management_iface || ifname == data_plane_iface {
            continue;
        }
        if ifname.contains("mgmt") {
            continue;
        }
        let prefix = msg.header.prefix_len;
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    if let IpAddr::V4(v4) = ip {
                        if is_private_ipv4(v4) {
                            candidates.push((v4, prefix));
                        }
                    }
                }
                _ => {}
            }
        }
    }

    task.abort();

    if let Some(choice) = pick_private_candidate(&candidates) {
        return Ok(choice);
    }

    Err("no private IPv4 address found for internal network".to_string())
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    match octets {
        [10, ..] => true,
        [172, b, ..] if (16..=31).contains(&b) => true,
        [192, 168, ..] => true,
        _ => false,
    }
}

fn pick_private_candidate(candidates: &[(Ipv4Addr, u8)]) -> Option<(Ipv4Addr, u8)> {
    for (ip, prefix) in candidates {
        if ip.octets()[0] == 10 {
            return Some((*ip, *prefix));
        }
    }
    for (ip, prefix) in candidates {
        let [a, b, ..] = ip.octets();
        if a == 172 && (16..=31).contains(&b) {
            return Some((*ip, *prefix));
        }
    }
    for (ip, prefix) in candidates {
        let [a, b, ..] = ip.octets();
        if a == 192 && b == 168 {
            return Some((*ip, *prefix));
        }
    }
    None
}

async fn get_link_index(handle: &rtnetlink::Handle, link_name: &str) -> Result<u32, String> {
    let mut links = handle
        .link()
        .get()
        .match_name(link_name.to_string())
        .execute();
    if let Some(msg) = links
        .try_next()
        .await
        .map_err(|err| format!("link lookup {link_name} failed: {err}"))?
    {
        return Ok(msg.header.index);
    }
    Err(format!("link not found: {link_name}"))
}
