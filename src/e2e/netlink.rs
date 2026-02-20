use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::time::Duration;

use futures::stream::TryStreamExt;
use netlink_packet_route::rule::RuleAction;
use rtnetlink::{new_connection, Error as NetlinkError, Handle};
use tokio::time::sleep;

pub async fn with_handle<F, Fut, T>(f: F) -> Result<T, String>
where
    F: FnOnce(Handle) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let (connection, handle, _) =
        new_connection().map_err(|err| format!("netlink connection error: {err}"))?;
    let task = tokio::spawn(connection);
    let result = f(handle).await;
    task.abort();
    result
}

pub async fn create_veth_pair(handle: &Handle, left: &str, right: &str) -> Result<(), String> {
    handle
        .link()
        .add()
        .veth(left.to_string(), right.to_string())
        .execute()
        .await
        .map_err(|err| format!("create veth {left}<->{right} failed: {err}"))
}

pub async fn set_link_namespace(
    handle: &Handle,
    link_name: &str,
    ns_fd: &impl AsRawFd,
) -> Result<(), String> {
    let index = get_link_index(handle, link_name).await?;
    handle
        .link()
        .set(index)
        .setns_by_fd(ns_fd.as_raw_fd())
        .execute()
        .await
        .map_err(|err| format!("move {link_name} to netns failed: {err}"))
}

pub async fn get_link_index(handle: &Handle, link_name: &str) -> Result<u32, String> {
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

pub async fn wait_for_link_index(
    handle: &Handle,
    link_name: &str,
    timeout: Duration,
) -> Result<u32, String> {
    let start = tokio::time::Instant::now();
    loop {
        match get_link_index(handle, link_name).await {
            Ok(idx) => return Ok(idx),
            Err(err) => {
                if start.elapsed() > timeout {
                    return Err(err);
                }
            }
        }
        sleep(Duration::from_millis(50)).await;
    }
}

pub async fn set_link_up(handle: &Handle, index: u32) -> Result<(), String> {
    handle
        .link()
        .set(index)
        .up()
        .execute()
        .await
        .map_err(|err| format!("link up failed: {err}"))
}

pub async fn add_address(
    handle: &Handle,
    index: u32,
    address: IpAddr,
    prefix: u8,
) -> Result<(), String> {
    handle
        .address()
        .add(index, address, prefix)
        .execute()
        .await
        .map_err(|err| format!("addr add failed: {err}"))
}

pub async fn add_route_v4(
    handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix: u8,
    oif: u32,
    table: Option<u32>,
) -> Result<(), String> {
    let mut req = handle.route().add().v4().destination_prefix(dest, prefix);
    req = req.output_interface(oif);
    if let Some(table_id) = table {
        req = req.table_id(table_id);
    }
    req.execute()
        .await
        .map_err(|err| format!("route add failed: {err}"))
}

pub async fn add_gateway_route_v4(
    handle: &Handle,
    dest: std::net::Ipv4Addr,
    prefix: u8,
    gateway: std::net::Ipv4Addr,
    oif: u32,
) -> Result<(), String> {
    handle
        .route()
        .add()
        .v4()
        .destination_prefix(dest, prefix)
        .gateway(gateway)
        .output_interface(oif)
        .execute()
        .await
        .map_err(|err| format!("route add via failed: {err}"))
}

pub async fn add_rule_iif_v4(
    handle: &Handle,
    ifname: &str,
    table: u32,
    priority: Option<u32>,
) -> Result<(), String> {
    let mut req = handle
        .rule()
        .add()
        .v4()
        .input_interface(ifname.to_string())
        .action(RuleAction::ToTable)
        .table_id(table);
    if let Some(prio) = priority {
        req = req.priority(prio);
    }
    req.execute()
        .await
        .map_err(|err| format!("rule add failed: {err}"))
}

pub fn ignore_nl_exists(err: &str) -> bool {
    matches!(
        err,
        _ if err.contains("File exists")
            || err.contains("EEXIST")
            || err.contains("exists")
    )
}

pub fn netlink_error_to_string(err: NetlinkError) -> String {
    format!("{err}")
}
