use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::controlplane::metrics::Metrics;
use crate::controlplane::PolicyStore;
use crate::dataplane::config::{DataplaneConfig, DataplaneConfigStore};
use crate::dataplane::dhcp::{DhcpRx, DhcpTx};

const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug, Clone)]
pub struct DhcpClientConfig {
    pub timeout: Duration,
    pub retry_max: u32,
    pub lease_min_secs: u64,
    pub hostname: Option<String>,
    pub update_internal_cidr: bool,
    pub allow_router_fallback_from_subnet: bool,
}

#[derive(Debug)]
pub struct DhcpClient {
    pub config: DhcpClientConfig,
    pub mac_rx: watch::Receiver<[u8; 6]>,
    pub rx: mpsc::Receiver<DhcpRx>,
    pub tx: mpsc::Sender<DhcpTx>,
    pub dataplane_config: DataplaneConfigStore,
    pub policy_store: PolicyStore,
    pub metrics: Option<Metrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Nak = 6,
}

#[derive(Debug, Clone)]
struct DhcpPacket {
    xid: u32,
    yiaddr: Ipv4Addr,
    chaddr: [u8; 6],
    msg_type: DhcpMessageType,
    options: DhcpOptions,
}

#[derive(Debug, Clone, Default)]
struct DhcpOptions {
    subnet_mask: Option<Ipv4Addr>,
    router: Option<Ipv4Addr>,
    lease_time: Option<u32>,
    server_id: Option<Ipv4Addr>,
    renew_time: Option<u32>,
    rebind_time: Option<u32>,
    requested_ip: Option<Ipv4Addr>,
    msg_type: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub server_id: Ipv4Addr,
    pub lease_time_secs: u64,
    pub renew_time_secs: u64,
    pub rebind_time_secs: u64,
    pub expiry: u64,
}

impl DhcpClient {
    pub async fn run(mut self) -> Result<(), String> {
        info!("dhcp client starting");
        loop {
            self.clear_lease_state();
            let mac = self.await_mac().await?;
            let mut lease = self.acquire_lease(mac).await?;
            loop {
                let renew_at = lease.renew_time_secs;
                if renew_at == 0 {
                    break;
                }
                let deadline = Instant::now() + Duration::from_secs(renew_at);
                tokio::time::sleep_until(deadline).await;
                match self.renew_lease(&lease, mac).await {
                    Ok(updated) => lease = updated,
                    Err(_) => break,
                }
            }
        }
    }

    async fn acquire_lease(&mut self, mac: [u8; 6]) -> Result<DhcpLease, String> {
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            if attempt > self.config.retry_max.max(1) {
                return Err("dhcp discovery retries exceeded".to_string());
            }
            debug!(
                attempt,
                retry_max = self.config.retry_max.max(1),
                "dhcp discover attempt"
            );

            let xid = rand_xid();
            let discover = build_discover(xid, mac, self.config.hostname.as_deref());
            self.send(DhcpTx::Broadcast { payload: discover }).await?;

            let offer = match self.await_message(xid, DhcpMessageType::Offer, mac).await {
                Ok(pkt) => pkt,
                Err(err) => {
                    warn!(error = %err, "dhcp offer wait failed");
                    continue;
                }
            };
            let server_id = match offer.options.server_id {
                Some(value) => value,
                None => continue,
            };
            let requested_ip = offer.yiaddr;
            let request = build_request(
                xid,
                mac,
                requested_ip,
                server_id,
                self.config.hostname.as_deref(),
            );
            self.send(DhcpTx::Broadcast { payload: request }).await?;

            let ack = match self.await_message(xid, DhcpMessageType::Ack, mac).await {
                Ok(pkt) => pkt,
                Err(err) => {
                    warn!(error = %err, "dhcp ack wait failed");
                    continue;
                }
            };
            if ack.yiaddr != requested_ip {
                continue;
            }
            let lease = lease_from_packet(&ack, &self.config, mac)?;
            info!(
                ip = %lease.ip,
                prefix = lease.prefix,
                gateway = %lease.gateway,
                lease_secs = lease.lease_time_secs,
                "dhcp lease acquired"
            );
            self.apply_lease(&lease, mac)?;
            return Ok(lease);
        }
    }

    async fn renew_lease(&mut self, lease: &DhcpLease, mac: [u8; 6]) -> Result<DhcpLease, String> {
        let xid = rand_xid();
        let request = build_request(
            xid,
            mac,
            lease.ip,
            lease.server_id,
            self.config.hostname.as_deref(),
        );
        self.send(DhcpTx::Unicast {
            payload: request,
            dst_ip: lease.server_id,
        })
        .await?;
        let ack = self.await_message(xid, DhcpMessageType::Ack, mac).await?;
        let updated = lease_from_packet(&ack, &self.config, mac)?;
        self.apply_lease(&updated, mac)?;
        Ok(updated)
    }

    fn clear_lease_state(&self) {
        self.dataplane_config.clear();
        if let Some(metrics) = &self.metrics {
            metrics.set_dhcp_lease_active(false);
            metrics.set_dhcp_lease_expiry_epoch(0);
        }
    }

    async fn await_message(
        &mut self,
        xid: u32,
        kind: DhcpMessageType,
        mac: [u8; 6],
    ) -> Result<DhcpPacket, String> {
        let deadline = Instant::now() + self.config.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("dhcp timeout".to_string());
            }
            let pkt = match tokio::time::timeout(remaining, self.rx.recv()).await {
                Ok(Some(msg)) => {
                    let mut pkt = parse_packet(&msg.payload)?;
                    if pkt.options.server_id.is_none() && msg.src_ip != Ipv4Addr::UNSPECIFIED {
                        pkt.options.server_id = Some(msg.src_ip);
                    }
                    pkt
                }
                Ok(None) => return Err("dhcp channel closed".to_string()),
                Err(_) => return Err("dhcp timeout".to_string()),
            };
            if pkt.msg_type != kind {
                if pkt.msg_type == DhcpMessageType::Nak {
                    return Err("dhcp nak".to_string());
                }
                continue;
            }
            if pkt.xid != xid || pkt.chaddr != mac {
                continue;
            }
            return Ok(pkt);
        }
    }

    async fn send(&self, msg: DhcpTx) -> Result<(), String> {
        self.tx
            .send(msg)
            .await
            .map_err(|_| "dhcp tx channel closed".to_string())
    }

    fn apply_lease(&self, lease: &DhcpLease, mac: [u8; 6]) -> Result<(), String> {
        let net = network_addr(lease.ip, lease.prefix);
        if self.config.update_internal_cidr {
            self.policy_store.update_internal_cidr(net, lease.prefix)?;
        }
        self.dataplane_config.set(DataplaneConfig {
            ip: lease.ip,
            prefix: lease.prefix,
            gateway: lease.gateway,
            mac,
            lease_expiry: Some(lease.expiry),
        });
        if let Some(metrics) = &self.metrics {
            metrics.set_dhcp_lease_active(true);
            metrics.set_dhcp_lease_expiry_epoch(lease.expiry);
            metrics.inc_dhcp_lease_change();
        }
        Ok(())
    }

    async fn await_mac(&mut self) -> Result<[u8; 6], String> {
        let mut logged = false;
        loop {
            let mac = *self.mac_rx.borrow();
            if mac != [0; 6] {
                return Ok(mac);
            }
            if !logged {
                debug!("dhcp waiting for dataplane mac");
                logged = true;
            }
            self.mac_rx
                .changed()
                .await
                .map_err(|_| "dhcp mac channel closed".to_string())?;
        }
    }
}

fn lease_from_packet(
    pkt: &DhcpPacket,
    cfg: &DhcpClientConfig,
    mac: [u8; 6],
) -> Result<DhcpLease, String> {
    if pkt.msg_type != DhcpMessageType::Ack {
        return Err("not a dhcp ack".to_string());
    }
    if pkt.chaddr != mac {
        return Err("dhcp ack mac mismatch".to_string());
    }
    let subnet = pkt
        .options
        .subnet_mask
        .ok_or_else(|| "dhcp ack missing subnet mask".to_string())?;
    let prefix = mask_to_prefix(subnet).ok_or_else(|| "invalid subnet mask".to_string())?;
    let gateway = match pkt.options.router {
        Some(router) => router,
        None if cfg.allow_router_fallback_from_subnet => {
            let fallback = subnet_gateway(pkt.yiaddr, prefix)
                .ok_or_else(|| "dhcp ack missing router and gateway fallback failed".to_string())?;
            warn!(
                gateway = %fallback,
                "dhcp ack missing router option; falling back to subnet gateway"
            );
            fallback
        }
        None => return Err("dhcp ack missing router".to_string()),
    };
    let server_id = pkt
        .options
        .server_id
        .ok_or_else(|| "dhcp ack missing server id".to_string())?;
    let lease_time = pkt
        .options
        .lease_time
        .ok_or_else(|| "dhcp ack missing lease time".to_string())?;
    if (lease_time as u64) < cfg.lease_min_secs {
        return Err("dhcp lease below minimum".to_string());
    }
    let renew_time = pkt.options.renew_time.unwrap_or(lease_time / 2);
    let rebind_time = pkt
        .options
        .rebind_time
        .unwrap_or_else(|| lease_time.saturating_mul(7) / 8);

    let now = now_secs();
    let expiry = now.saturating_add(lease_time as u64);
    Ok(DhcpLease {
        ip: pkt.yiaddr,
        prefix,
        gateway,
        server_id,
        lease_time_secs: lease_time as u64,
        renew_time_secs: renew_time as u64,
        rebind_time_secs: rebind_time as u64,
        expiry,
    })
}

fn parse_packet(buf: &[u8]) -> Result<DhcpPacket, String> {
    if buf.len() < 240 {
        return Err("dhcp packet too short".to_string());
    }
    if buf[236..240] != DHCP_COOKIE {
        return Err("dhcp magic cookie missing".to_string());
    }

    let htype = buf[1];
    let hlen = buf[2];
    if htype != 1 || hlen != 6 {
        return Err("unsupported dhcp hardware type".to_string());
    }
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let yiaddr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&buf[28..34]);

    let options = parse_options(&buf[240..])?;
    let msg_type = options
        .msg_type()
        .ok_or_else(|| "dhcp message type missing".to_string())?;

    Ok(DhcpPacket {
        xid,
        yiaddr,
        chaddr,
        msg_type,
        options,
    })
}

fn parse_options(buf: &[u8]) -> Result<DhcpOptions, String> {
    let mut options = DhcpOptions::default();
    let mut idx = 0usize;
    while idx < buf.len() {
        let code = buf[idx];
        idx += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if idx >= buf.len() {
            return Err("dhcp option truncated".to_string());
        }
        let len = buf[idx] as usize;
        idx += 1;
        if idx + len > buf.len() {
            return Err("dhcp option truncated".to_string());
        }
        let data = &buf[idx..idx + len];
        idx += len;
        match code {
            1 if len == 4 => {
                options.subnet_mask = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            3 if len >= 4 => {
                options.router = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            50 if len == 4 => {
                options.requested_ip = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            51 if len == 4 => {
                options.lease_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            53 if len == 1 => {
                options.msg_type = Some(data[0]);
            }
            54 if len == 4 => {
                options.server_id = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            58 if len == 4 => {
                options.renew_time = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            59 if len == 4 => {
                options.rebind_time =
                    Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
            }
            _ => {}
        }
    }
    Ok(options)
}

impl DhcpOptions {
    fn msg_type(&self) -> Option<DhcpMessageType> {
        match self.msg_type? {
            1 => Some(DhcpMessageType::Discover),
            2 => Some(DhcpMessageType::Offer),
            3 => Some(DhcpMessageType::Request),
            5 => Some(DhcpMessageType::Ack),
            6 => Some(DhcpMessageType::Nak),
            _ => None,
        }
    }
}

fn build_discover(xid: u32, mac: [u8; 6], hostname: Option<&str>) -> Vec<u8> {
    let mut buf = build_base(
        1,
        xid,
        mac,
        true,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
    );
    push_option(&mut buf, 53, &[DhcpMessageType::Discover as u8]);
    push_option(&mut buf, 55, &[1, 3, 51, 54, 58, 59]);
    push_client_id(&mut buf, mac);
    if let Some(name) = hostname {
        push_option(&mut buf, 12, name.as_bytes());
    }
    finish_options(&mut buf);
    buf
}

fn build_request(
    xid: u32,
    mac: [u8; 6],
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    hostname: Option<&str>,
) -> Vec<u8> {
    let mut buf = build_base(
        1,
        xid,
        mac,
        true,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
    );
    push_option(&mut buf, 53, &[DhcpMessageType::Request as u8]);
    push_option(&mut buf, 50, &requested_ip.octets());
    push_option(&mut buf, 54, &server_id.octets());
    push_option(&mut buf, 55, &[1, 3, 51, 54, 58, 59]);
    push_client_id(&mut buf, mac);
    if let Some(name) = hostname {
        push_option(&mut buf, 12, name.as_bytes());
    }
    finish_options(&mut buf);
    buf
}

fn build_base(
    op: u8,
    xid: u32,
    mac: [u8; 6],
    broadcast: bool,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = op;
    buf[1] = 1;
    buf[2] = 6;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    if broadcast {
        buf[10] = 0x80;
    }
    buf[12..16].copy_from_slice(&ciaddr.octets());
    buf[16..20].copy_from_slice(&yiaddr.octets());
    buf[28..34].copy_from_slice(&mac);
    buf[236..240].copy_from_slice(&DHCP_COOKIE);
    buf
}

fn push_option(buf: &mut Vec<u8>, code: u8, data: &[u8]) {
    buf.push(code);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

fn push_client_id(buf: &mut Vec<u8>, mac: [u8; 6]) {
    let mut data = [0u8; 7];
    data[0] = 1;
    data[1..7].copy_from_slice(&mac);
    push_option(buf, 61, &data);
}

fn finish_options(buf: &mut Vec<u8>) {
    buf.push(255);
}

fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let mut value = u32::from(mask);
    let mut prefix = 0u8;
    while value & 0x8000_0000 != 0 {
        prefix += 1;
        value <<= 1;
    }
    if value != 0 {
        return None;
    }
    Some(prefix)
}

fn network_addr(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    Ipv4Addr::from(u32::from(ip) & mask)
}

fn subnet_gateway(ip: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    if prefix >= 31 {
        return None;
    }
    let network = u32::from(network_addr(ip, prefix));
    Some(Ipv4Addr::from(network.saturating_add(1)))
}

fn rand_xid() -> u32 {
    let mut rng = rand::thread_rng();
    rng.next_u32()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::metrics::Metrics;
    use crate::controlplane::PolicyStore;
    use crate::dataplane::config::DataplaneConfigStore;
    use crate::dataplane::policy::DefaultPolicy;
    use tokio::sync::{mpsc, watch};

    fn test_client(
        timeout: Duration,
    ) -> (
        DhcpClient,
        mpsc::Sender<DhcpRx>,
        mpsc::Receiver<DhcpTx>,
        DataplaneConfigStore,
    ) {
        let (_mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let (rx_tx, rx) = mpsc::channel(4);
        let (tx, tx_rx) = mpsc::channel(4);
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let client = DhcpClient {
            config: DhcpClientConfig {
                timeout,
                retry_max: 1,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx,
            tx,
            dataplane_config: dataplane_config.clone(),
            policy_store,
            metrics: None,
        };
        (client, rx_tx, tx_rx, dataplane_config)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_reply(
        msg_type: u8,
        xid: u32,
        mac: [u8; 6],
        yiaddr: Ipv4Addr,
        server_id: Ipv4Addr,
        subnet: Ipv4Addr,
        router: Option<Ipv4Addr>,
        lease_time: u32,
    ) -> Vec<u8> {
        let mut buf = build_base(2, xid, mac, true, Ipv4Addr::UNSPECIFIED, yiaddr);
        push_option(&mut buf, 53, &[msg_type]);
        push_option(&mut buf, 54, &server_id.octets());
        push_option(&mut buf, 1, &subnet.octets());
        if let Some(router) = router {
            push_option(&mut buf, 3, &router.octets());
        }
        push_option(&mut buf, 51, &lease_time.to_be_bytes());
        finish_options(&mut buf);
        buf
    }

    #[allow(clippy::too_many_arguments)]
    fn build_reply_with_renew_time(
        msg_type: u8,
        xid: u32,
        mac: [u8; 6],
        yiaddr: Ipv4Addr,
        server_id: Ipv4Addr,
        subnet: Ipv4Addr,
        router: Option<Ipv4Addr>,
        lease_time: u32,
        renew_time: u32,
    ) -> Vec<u8> {
        let mut buf = build_base(2, xid, mac, true, Ipv4Addr::UNSPECIFIED, yiaddr);
        push_option(&mut buf, 53, &[msg_type]);
        push_option(&mut buf, 54, &server_id.octets());
        push_option(&mut buf, 1, &subnet.octets());
        if let Some(router) = router {
            push_option(&mut buf, 3, &router.octets());
        }
        push_option(&mut buf, 51, &lease_time.to_be_bytes());
        push_option(&mut buf, 58, &renew_time.to_be_bytes());
        finish_options(&mut buf);
        buf
    }

    #[test]
    fn mask_to_prefix_handles_valid_and_invalid_masks() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), Some(24));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 0, 0)), Some(16));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
    }

    #[test]
    fn parse_ack_builds_lease() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let xid = 0x12345678;
        let yiaddr = Ipv4Addr::new(10, 0, 0, 10);
        let server_id = Ipv4Addr::new(10, 0, 0, 1);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let router = Ipv4Addr::new(10, 0, 0, 1);
        let lease_time = 600;
        let buf = build_reply(
            DhcpMessageType::Ack as u8,
            xid,
            mac,
            yiaddr,
            server_id,
            subnet,
            Some(router),
            lease_time,
        );
        let pkt = parse_packet(&buf).expect("parse packet");
        let cfg = DhcpClientConfig {
            timeout: Duration::from_secs(5),
            retry_max: 3,
            lease_min_secs: 60,
            hostname: None,
            update_internal_cidr: true,
            allow_router_fallback_from_subnet: false,
        };
        let lease = lease_from_packet(&pkt, &cfg, mac).expect("lease");
        assert_eq!(lease.ip, yiaddr);
        assert_eq!(lease.prefix, 24);
        assert_eq!(lease.gateway, router);
        assert_eq!(lease.server_id, server_id);
        assert_eq!(lease.lease_time_secs, lease_time as u64);
    }

    #[test]
    fn parse_ack_missing_router_fails_when_fallback_disabled() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let xid = 0x12345678;
        let yiaddr = Ipv4Addr::new(10, 20, 2, 9);
        let server_id = Ipv4Addr::new(168, 63, 129, 16);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let lease_time = 600;
        let buf = build_reply(
            DhcpMessageType::Ack as u8,
            xid,
            mac,
            yiaddr,
            server_id,
            subnet,
            None,
            lease_time,
        );
        let pkt = parse_packet(&buf).expect("parse packet");
        let cfg = DhcpClientConfig {
            timeout: Duration::from_secs(5),
            retry_max: 3,
            lease_min_secs: 60,
            hostname: None,
            update_internal_cidr: true,
            allow_router_fallback_from_subnet: false,
        };
        let err = lease_from_packet(&pkt, &cfg, mac).expect_err("expected missing router error");
        assert!(err.contains("missing router"));
    }

    #[test]
    fn parse_ack_missing_router_derives_subnet_gateway_when_enabled() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let xid = 0x12345678;
        let yiaddr = Ipv4Addr::new(10, 20, 2, 9);
        let server_id = Ipv4Addr::new(168, 63, 129, 16);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let lease_time = 600;
        let buf = build_reply(
            DhcpMessageType::Ack as u8,
            xid,
            mac,
            yiaddr,
            server_id,
            subnet,
            None,
            lease_time,
        );
        let pkt = parse_packet(&buf).expect("parse packet");
        let cfg = DhcpClientConfig {
            timeout: Duration::from_secs(5),
            retry_max: 3,
            lease_min_secs: 60,
            hostname: None,
            update_internal_cidr: true,
            allow_router_fallback_from_subnet: true,
        };
        let lease = lease_from_packet(&pkt, &cfg, mac).expect("lease");
        assert_eq!(lease.gateway, Ipv4Addr::new(10, 20, 2, 1));
    }

    fn metric_value(rendered: &str, name: &str) -> Option<f64> {
        for line in rendered.lines() {
            if line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix(name) {
                let value = rest.split_whitespace().next()?;
                return value.parse().ok();
            }
        }
        None
    }

    #[test]
    fn apply_lease_updates_metrics() {
        let metrics = Metrics::new().unwrap();
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
        let dataplane_config = DataplaneConfigStore::new();
        let (_mac_tx, mac_rx) = watch::channel([0u8; 6]);
        let (_tx, rx) = mpsc::channel(1);
        let (tx2, _rx2) = mpsc::channel(1);

        let client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_secs(1),
                retry_max: 1,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx,
            tx: tx2,
            dataplane_config,
            policy_store,
            metrics: Some(metrics.clone()),
        };

        let lease = DhcpLease {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            server_id: Ipv4Addr::new(10, 0, 0, 1),
            lease_time_secs: 3600,
            renew_time_secs: 1800,
            rebind_time_secs: 3150,
            expiry: 12345,
        };

        client
            .apply_lease(&lease, [0x02, 0, 0, 0, 0, 1])
            .expect("apply lease");

        let rendered = metrics.render().unwrap();
        assert_eq!(metric_value(&rendered, "dhcp_lease_active"), Some(1.0));
        assert_eq!(
            metric_value(&rendered, "dhcp_lease_expiry_epoch"),
            Some(12345.0)
        );
        assert_eq!(
            metric_value(&rendered, "dhcp_lease_changes_total"),
            Some(1.0)
        );
    }

    #[tokio::test]
    async fn await_message_times_out_when_no_packets_arrive() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
        let (mut client, _rx_tx, _tx_rx, _dataplane_config) =
            test_client(Duration::from_millis(10));

        let err = client
            .await_message(0x12345678, DhcpMessageType::Ack, mac)
            .await
            .expect_err("timeout");

        assert_eq!(err, "dhcp timeout");
    }

    #[tokio::test]
    async fn await_message_returns_nak_error() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x12];
        let yiaddr = Ipv4Addr::new(10, 0, 0, 10);
        let server_id = Ipv4Addr::new(10, 0, 0, 1);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let xid = 0x22334455;
        let (mut client, rx_tx, _tx_rx, _dataplane_config) = test_client(Duration::from_secs(1));

        rx_tx
            .send(DhcpRx {
                src_ip: server_id,
                payload: build_reply(
                    DhcpMessageType::Nak as u8,
                    xid,
                    mac,
                    yiaddr,
                    server_id,
                    subnet,
                    Some(server_id),
                    600,
                ),
            })
            .await
            .expect("send nak");

        let err = client
            .await_message(xid, DhcpMessageType::Ack, mac)
            .await
            .expect_err("nak");

        assert_eq!(err, "dhcp nak");
    }

    #[tokio::test]
    async fn renew_lease_sends_unicast_request_and_applies_updated_lease() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x13];
        let server_id = Ipv4Addr::new(10, 0, 0, 1);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let initial_ip = Ipv4Addr::new(10, 0, 0, 20);
        let updated_ip = Ipv4Addr::new(10, 0, 0, 21);
        let updated_gateway = Ipv4Addr::new(10, 0, 0, 254);
        let lease = DhcpLease {
            ip: initial_ip,
            prefix: 24,
            gateway: server_id,
            server_id,
            lease_time_secs: 600,
            renew_time_secs: 300,
            rebind_time_secs: 525,
            expiry: 100,
        };
        let (mut client, rx_tx, mut tx_rx, dataplane_config) = test_client(Duration::from_secs(1));

        let renew_task = tokio::spawn(async move { client.renew_lease(&lease, mac).await });

        let outbound = tx_rx.recv().await.expect("renew request");
        let request = match outbound {
            DhcpTx::Unicast { payload, dst_ip } => {
                assert_eq!(dst_ip, server_id);
                let parsed = parse_packet(&payload).expect("parse request");
                assert_eq!(parsed.msg_type, DhcpMessageType::Request);
                assert_eq!(parsed.options.requested_ip, Some(initial_ip));
                assert_eq!(parsed.options.server_id, Some(server_id));
                parsed
            }
            other => panic!("unexpected tx {other:?}"),
        };

        rx_tx
            .send(DhcpRx {
                src_ip: server_id,
                payload: build_reply(
                    DhcpMessageType::Ack as u8,
                    request.xid,
                    mac,
                    updated_ip,
                    server_id,
                    subnet,
                    Some(updated_gateway),
                    900,
                ),
            })
            .await
            .expect("send ack");

        let updated = renew_task.await.expect("renew task").expect("renew lease");
        assert_eq!(updated.ip, updated_ip);
        assert_eq!(updated.gateway, updated_gateway);
        assert_eq!(updated.lease_time_secs, 900);
        assert_eq!(updated.renew_time_secs, 450);
        assert_eq!(
            dataplane_config.get(),
            Some(DataplaneConfig {
                ip: updated_ip,
                prefix: 24,
                gateway: updated_gateway,
                mac,
                lease_expiry: Some(updated.expiry),
            })
        );
    }

    #[tokio::test]
    async fn run_clears_config_and_degrades_readiness_before_reacquire_after_renew_timeout() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x14];
        let yiaddr = Ipv4Addr::new(10, 0, 0, 30);
        let server_id = Ipv4Addr::new(10, 0, 0, 1);
        let subnet = Ipv4Addr::new(255, 255, 255, 0);
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let metrics = Metrics::new().unwrap();
        let (mac_tx, mac_rx) = watch::channel(mac);
        let (rx_tx, rx) = mpsc::channel(8);
        let (tx, mut tx_rx) = mpsc::channel(8);
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::new(10, 0, 0, 0),
            24,
            dataplane_config.clone(),
        );
        let readiness = crate::controlplane::ready::ReadinessState::new(
            dataplane_config.clone(),
            policy_store.clone(),
            None,
            None,
        );
        readiness.set_dataplane_running(true);
        readiness.set_policy_ready(true);
        readiness.set_dns_ready(true);
        readiness.set_service_plane_ready(true);

        let client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(20),
                retry_max: 1,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx,
            tx,
            dataplane_config: dataplane_config.clone(),
            policy_store,
            metrics: Some(metrics.clone()),
        };

        let run_task = tokio::spawn(async move { client.run().await });
        let _mac_tx = mac_tx;

        let discover = tokio::time::timeout(Duration::from_secs(1), tx_rx.recv())
            .await
            .expect("discover timeout")
            .expect("discover message");
        let discover = match discover {
            DhcpTx::Broadcast { payload } => parse_packet(&payload).expect("parse discover"),
            other => panic!("unexpected tx {other:?}"),
        };
        assert_eq!(discover.msg_type, DhcpMessageType::Discover);

        rx_tx
            .send(DhcpRx {
                src_ip: server_id,
                payload: build_reply(
                    DhcpMessageType::Offer as u8,
                    discover.xid,
                    mac,
                    yiaddr,
                    server_id,
                    subnet,
                    Some(gateway),
                    2,
                ),
            })
            .await
            .expect("send offer");

        let request = tokio::time::timeout(Duration::from_secs(1), tx_rx.recv())
            .await
            .expect("request timeout")
            .expect("request message");
        let request = match request {
            DhcpTx::Broadcast { payload } => parse_packet(&payload).expect("parse request"),
            other => panic!("unexpected tx {other:?}"),
        };
        assert_eq!(request.msg_type, DhcpMessageType::Request);
        assert_eq!(request.options.requested_ip, Some(yiaddr));

        rx_tx
            .send(DhcpRx {
                src_ip: server_id,
                payload: build_reply_with_renew_time(
                    DhcpMessageType::Ack as u8,
                    request.xid,
                    mac,
                    yiaddr,
                    server_id,
                    subnet,
                    Some(gateway),
                    2,
                    1,
                ),
            })
            .await
            .expect("send ack");

        tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if dataplane_config.get().is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("lease application timeout");
        assert!(readiness.snapshot().ready);

        let renew_request = tokio::time::timeout(Duration::from_secs(2), tx_rx.recv())
            .await
            .expect("renew timeout")
            .expect("renew message");
        match renew_request {
            DhcpTx::Unicast { payload, dst_ip } => {
                assert_eq!(dst_ip, server_id);
                let renew = parse_packet(&payload).expect("parse renew request");
                assert_eq!(renew.msg_type, DhcpMessageType::Request);
                assert_eq!(renew.options.requested_ip, Some(yiaddr));
            }
            other => panic!("unexpected tx {other:?}"),
        }

        let reacquire = tokio::time::timeout(Duration::from_millis(250), tx_rx.recv())
            .await
            .expect("reacquire discover timeout")
            .expect("reacquire discover message");
        let reacquire = match reacquire {
            DhcpTx::Broadcast { payload } => parse_packet(&payload).expect("parse reacquire"),
            other => panic!("unexpected tx {other:?}"),
        };
        assert_eq!(reacquire.msg_type, DhcpMessageType::Discover);
        assert!(dataplane_config.get().is_none());
        assert!(!readiness.snapshot().ready);

        let rendered = metrics.render().unwrap();
        assert_eq!(metric_value(&rendered, "dhcp_lease_active"), Some(0.0));
        assert_eq!(
            metric_value(&rendered, "dhcp_lease_expiry_epoch"),
            Some(0.0)
        );

        run_task.abort();
    }
}
