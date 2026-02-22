use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::{Arc, RwLock};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::controlplane::cluster::rpc::{self, WiretapHandler, WiretapStream};
use crate::dataplane::policy::{CidrV4, PortRange, Proto};
use crate::dataplane::wiretap as dp_wiretap;

#[derive(Debug, Clone)]
struct DnsEntry {
    hostname: String,
    last_seen: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMap {
    inner: Arc<RwLock<HashMap<Ipv4Addr, DnsEntry>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub ips: Vec<Ipv4Addr>,
    pub last_seen: u64,
}

impl DnsMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_many(&self, hostname: &str, ips: &[Ipv4Addr], now: u64) {
        let hostname = normalize_hostname(hostname);
        if hostname.is_empty() {
            return;
        }
        if let Ok(mut lock) = self.inner.write() {
            for ip in ips {
                lock.insert(
                    *ip,
                    DnsEntry {
                        hostname: hostname.clone(),
                        last_seen: now,
                    },
                );
            }
        }
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        match self.inner.read() {
            Ok(lock) => lock.get(&ip).map(|entry| entry.hostname.clone()),
            Err(_) => None,
        }
    }

    pub fn evict_idle(&self, now: u64, idle_timeout_secs: u64) -> usize {
        match self.inner.write() {
            Ok(mut lock) => {
                let before = lock.len();
                lock.retain(|_, entry| now.saturating_sub(entry.last_seen) <= idle_timeout_secs);
                before - lock.len()
            }
            Err(_) => 0,
        }
    }

    pub fn snapshot_grouped(&self) -> Vec<DnsCacheEntry> {
        let mut grouped: HashMap<String, (Vec<Ipv4Addr>, u64)> = HashMap::new();
        if let Ok(lock) = self.inner.read() {
            for (ip, entry) in lock.iter() {
                let slot = grouped
                    .entry(entry.hostname.clone())
                    .or_insert_with(|| (Vec::new(), 0));
                slot.0.push(*ip);
                slot.1 = slot.1.max(entry.last_seen);
            }
        }
        let mut entries: Vec<DnsCacheEntry> = grouped
            .into_iter()
            .map(|(hostname, (mut ips, last_seen))| {
                ips.sort();
                DnsCacheEntry {
                    hostname,
                    ips,
                    last_seen,
                }
            })
            .collect();
        entries.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        entries
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct WiretapQuery {
    #[serde(default)]
    pub src_cidr: Vec<String>,
    #[serde(default)]
    pub dst_cidr: Vec<String>,
    #[serde(default)]
    pub hostname: Vec<String>,
    #[serde(default)]
    pub proto: Vec<String>,
    #[serde(default)]
    pub src_port: Vec<String>,
    #[serde(default)]
    pub dst_port: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct WiretapFilter {
    src_cidrs: Vec<CidrV4>,
    dst_cidrs: Vec<CidrV4>,
    hostname: Vec<Regex>,
    proto: Vec<Proto>,
    src_ports: Vec<PortRange>,
    dst_ports: Vec<PortRange>,
}

impl WiretapFilter {
    pub fn from_query(query: WiretapQuery) -> Result<Self, String> {
        let mut src_cidrs = Vec::new();
        for value in query.src_cidr {
            src_cidrs.push(parse_cidr_v4(&value)?);
        }

        let mut dst_cidrs = Vec::new();
        for value in query.dst_cidr {
            dst_cidrs.push(parse_cidr_v4(&value)?);
        }

        let mut hostname = Vec::new();
        for value in query.hostname {
            let regex = RegexBuilder::new(value.trim())
                .case_insensitive(true)
                .build()
                .map_err(|err| format!("invalid hostname regex: {err}"))?;
            hostname.push(regex);
        }

        let mut proto = Vec::new();
        for value in query.proto {
            let parsed = parse_proto_value(&value)?;
            if matches!(parsed, Proto::Any) {
                proto.clear();
                break;
            }
            proto.push(parsed);
        }

        let mut src_ports = Vec::new();
        for value in query.src_port {
            src_ports.push(parse_port_range(&value)?);
        }

        let mut dst_ports = Vec::new();
        for value in query.dst_port {
            dst_ports.push(parse_port_range(&value)?);
        }

        Ok(Self {
            src_cidrs,
            dst_cidrs,
            hostname,
            proto,
            src_ports,
            dst_ports,
        })
    }

    pub fn matches(&self, event: &WiretapEvent) -> bool {
        if !self.src_cidrs.is_empty()
            && !self
                .src_cidrs
                .iter()
                .any(|cidr| cidr.contains(event.src_ip))
        {
            return false;
        }

        if !self.dst_cidrs.is_empty()
            && !self
                .dst_cidrs
                .iter()
                .any(|cidr| cidr.contains(event.dst_ip))
        {
            return false;
        }

        if !self.proto.is_empty() && !self.proto.iter().any(|p| p.matches(event.proto)) {
            return false;
        }

        if !self.src_ports.is_empty()
            && !self
                .src_ports
                .iter()
                .any(|range| range.contains(event.src_port))
        {
            return false;
        }

        if !self.dst_ports.is_empty()
            && !self
                .dst_ports
                .iter()
                .any(|range| range.contains(event.dst_port))
        {
            return false;
        }

        if !self.hostname.is_empty() {
            let Some(hostname) = event.hostname.as_deref() else {
                return false;
            };
            if !self.hostname.iter().any(|regex| regex.is_match(hostname)) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct WiretapEvent {
    pub event_type: dp_wiretap::WiretapEventType,
    pub flow_id: String,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets_in: u64,
    pub packets_out: u64,
    pub last_seen: u64,
    pub hostname: Option<String>,
    pub node_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WiretapEventPayload {
    pub flow_id: String,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets_in: u64,
    pub packets_out: u64,
    pub last_seen: u64,
    pub hostname: Option<String>,
    pub node_id: String,
}

impl WiretapEvent {
    pub fn from_dataplane(
        event: dp_wiretap::WiretapEvent,
        hostname: Option<String>,
        node_id: &str,
    ) -> Self {
        Self {
            event_type: event.event_type,
            flow_id: event.flow_id,
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            proto: event.proto,
            packets_in: event.packets_in,
            packets_out: event.packets_out,
            last_seen: event.last_seen,
            hostname,
            node_id: node_id.to_string(),
        }
    }

    pub fn payload(&self) -> WiretapEventPayload {
        WiretapEventPayload {
            flow_id: self.flow_id.clone(),
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            proto: self.proto,
            packets_in: self.packets_in,
            packets_out: self.packets_out,
            last_seen: self.last_seen,
            hostname: self.hostname.clone(),
            node_id: self.node_id.clone(),
        }
    }

    pub fn to_proto(&self) -> rpc::proto::WiretapEvent {
        rpc::proto::WiretapEvent {
            event_type: match self.event_type {
                dp_wiretap::WiretapEventType::Flow => "flow".to_string(),
                dp_wiretap::WiretapEventType::FlowEnd => "flow_end".to_string(),
            },
            flow_id: self.flow_id.clone(),
            src_ip: self.src_ip.to_string(),
            dst_ip: self.dst_ip.to_string(),
            src_port: self.src_port as u32,
            dst_port: self.dst_port as u32,
            proto: self.proto as u32,
            packets_in: self.packets_in,
            packets_out: self.packets_out,
            last_seen: self.last_seen,
            hostname: self.hostname.clone().unwrap_or_default(),
            node_id: self.node_id.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WiretapHub {
    sender: broadcast::Sender<WiretapEvent>,
}

impl WiretapHub {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(1));
        Self { sender }
    }

    pub fn publish(&self, event: WiretapEvent) {
        let _ = self.sender.send(event);
    }

    pub fn subscribe(&self, filter: WiretapFilter) -> WiretapSubscriber {
        WiretapSubscriber {
            filter,
            receiver: self.sender.subscribe(),
        }
    }
}

pub struct WiretapSubscriber {
    filter: WiretapFilter,
    receiver: broadcast::Receiver<WiretapEvent>,
}

impl WiretapSubscriber {
    pub fn into_stream(self) -> impl futures::Stream<Item = WiretapEvent> + Send {
        let filter = self.filter;
        BroadcastStream::new(self.receiver).filter_map(move |event| {
            let event = match event {
                Ok(event) => event,
                Err(_) => return None,
            };
            if filter.matches(&event) {
                Some(event)
            } else {
                None
            }
        })
    }
}

#[derive(Clone)]
pub struct WiretapGrpcService {
    hub: WiretapHub,
}

impl WiretapGrpcService {
    pub fn new(hub: WiretapHub) -> Self {
        Self { hub }
    }
}

#[async_trait::async_trait]
impl WiretapHandler for WiretapGrpcService {
    async fn subscribe(
        &self,
        req: rpc::proto::WiretapSubscribeRequest,
    ) -> Result<WiretapStream, String> {
        let query = WiretapQuery {
            src_cidr: req.src_cidr,
            dst_cidr: req.dst_cidr,
            hostname: req.hostname,
            proto: req.proto,
            src_port: req.src_port,
            dst_port: req.dst_port,
        };
        let filter = WiretapFilter::from_query(query)?;
        let subscriber = self.hub.subscribe(filter);
        let stream = subscriber.into_stream().map(|event| Ok(event.to_proto()));
        Ok(Box::pin(stream))
    }
}

pub fn load_or_create_node_id(path: &Path) -> Result<String, String> {
    if path.exists() {
        let contents = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
        let trimmed = contents.trim();
        let parsed = uuid::Uuid::parse_str(trimmed).map_err(|err| err.to_string())?;
        return Ok(parsed.to_string());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }

    let node_id = uuid::Uuid::new_v4();
    std::fs::write(path, node_id.to_string()).map_err(|err| err.to_string())?;
    Ok(node_id.to_string())
}

fn parse_proto_value(value: &str) -> Result<Proto, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("proto cannot be empty".to_string());
    }
    match value.to_ascii_lowercase().as_str() {
        "any" => Ok(Proto::Any),
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "icmp" => Ok(Proto::Icmp),
        other => other
            .parse::<u8>()
            .map(|value| match value {
                6 => Proto::Tcp,
                17 => Proto::Udp,
                1 => Proto::Icmp,
                _ => Proto::Other(value),
            })
            .map_err(|_| format!("invalid proto value: {value}")),
    }
}

fn parse_port_range(value: &str) -> Result<PortRange, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("port cannot be empty".to_string());
    }
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
            .parse::<u16>()
            .map_err(|_| format!("invalid port: {value}"))?;
        Ok(PortRange {
            start: port,
            end: port,
        })
    }
}

fn parse_cidr_v4(value: &str) -> Result<CidrV4, String> {
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

fn parse_ipv4(value: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid IPv4 address: {value}"))
}

fn normalize_hostname(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiretap_filter_matches_ports_and_proto() {
        let query = WiretapQuery {
            src_port: vec!["1000-2000".to_string()],
            dst_port: vec!["80".to_string()],
            proto: vec!["tcp".to_string()],
            ..WiretapQuery::default()
        };
        let filter = WiretapFilter::from_query(query).unwrap();

        let event = WiretapEvent {
            event_type: dp_wiretap::WiretapEventType::Flow,
            flow_id: "flow".to_string(),
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            src_port: 1500,
            dst_port: 80,
            proto: 6,
            packets_in: 0,
            packets_out: 1,
            last_seen: 1,
            hostname: None,
            node_id: "node".to_string(),
        };

        assert!(filter.matches(&event));
    }

    #[test]
    fn wiretap_filter_hostname_requires_mapping() {
        let query = WiretapQuery {
            hostname: vec!["example\\.com".to_string()],
            ..WiretapQuery::default()
        };
        let filter = WiretapFilter::from_query(query).unwrap();

        let mut event = WiretapEvent {
            event_type: dp_wiretap::WiretapEventType::Flow,
            flow_id: "flow".to_string(),
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(93, 184, 216, 34),
            src_port: 1500,
            dst_port: 443,
            proto: 6,
            packets_in: 0,
            packets_out: 1,
            last_seen: 1,
            hostname: None,
            node_id: "node".to_string(),
        };

        assert!(!filter.matches(&event));

        event.hostname = Some("api.example.com".to_string());
        assert!(filter.matches(&event));
    }

    #[test]
    fn dns_map_normalizes_and_evicts() {
        let map = DnsMap::new();
        let ips = vec![Ipv4Addr::new(198, 51, 100, 10)];
        map.insert_many("Foo.Example.COM.", &ips, 10);
        assert_eq!(map.lookup(ips[0]).unwrap(), "foo.example.com");
        assert_eq!(map.evict_idle(20, 5), 1);
    }

    #[test]
    fn wiretap_event_from_dataplane_includes_hostname() {
        let map = DnsMap::new();
        let ip = Ipv4Addr::new(203, 0, 113, 9);
        map.insert_many("Api.Example.COM.", &[ip], 10);

        let dp_event = dp_wiretap::WiretapEvent {
            event_type: dp_wiretap::WiretapEventType::Flow,
            flow_id: "flow".to_string(),
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: ip,
            src_port: 4444,
            dst_port: 443,
            proto: 6,
            packets_in: 0,
            packets_out: 1,
            last_seen: 10,
        };

        let hostname = map.lookup(ip);
        let event = WiretapEvent::from_dataplane(dp_event, hostname, "node-1");
        assert_eq!(event.hostname.as_deref(), Some("api.example.com"));
        assert_eq!(event.node_id, "node-1");
    }
}
