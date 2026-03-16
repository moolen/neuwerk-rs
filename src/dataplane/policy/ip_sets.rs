use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrV4 {
    addr: Ipv4Addr,
    prefix: u8,
    mask: u32,
    net: u32,
}

impl CidrV4 {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        let net = u32::from(addr) & mask;
        Self {
            addr,
            prefix,
            mask,
            net,
        }
    }

    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let addr = u32::from(ip) & self.mask;
        addr == self.net
    }
}

#[derive(Debug, Clone, Copy)]
struct DynamicIpEntry {
    last_seen: u64,
    active_flows: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DynamicIpSetV4 {
    inner: Arc<RwLock<HashMap<Ipv4Addr, DynamicIpEntry>>>,
}

impl DynamicIpSetV4 {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert(&self, ip: Ipv4Addr) {
        self.insert_at(ip, now_secs());
    }

    pub fn insert_many<I>(&self, ips: I)
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        let now = now_secs();
        if let Ok(mut lock) = self.inner.write() {
            for ip in ips {
                lock.entry(ip)
                    .and_modify(|entry| {
                        entry.last_seen = entry.last_seen.max(now);
                    })
                    .or_insert(DynamicIpEntry {
                        last_seen: now,
                        active_flows: 0,
                    });
            }
        }
    }

    pub fn insert_at(&self, ip: Ipv4Addr, now: u64) {
        if let Ok(mut lock) = self.inner.write() {
            lock.entry(ip)
                .and_modify(|entry| {
                    entry.last_seen = entry.last_seen.max(now);
                })
                .or_insert(DynamicIpEntry {
                    last_seen: now,
                    active_flows: 0,
                });
        }
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        match self.inner.read() {
            Ok(lock) => lock.contains_key(&ip),
            Err(_) => false,
        }
    }

    pub fn flow_open(&self, ip: Ipv4Addr, now: u64) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(entry) = lock.get_mut(&ip) {
                entry.last_seen = entry.last_seen.max(now);
                entry.active_flows = entry.active_flows.saturating_add(1);
            }
        }
    }

    pub fn flow_close(&self, ip: Ipv4Addr, last_seen: u64) {
        if let Ok(mut lock) = self.inner.write() {
            if let Some(entry) = lock.get_mut(&ip) {
                entry.last_seen = entry.last_seen.max(last_seen);
                entry.active_flows = entry.active_flows.saturating_sub(1);
            }
        }
    }

    pub fn evict_idle(&self, now: u64, idle_timeout_secs: u64) -> usize {
        match self.inner.write() {
            Ok(mut lock) => {
                let before = lock.len();
                lock.retain(|_, entry| {
                    if entry.active_flows > 0 {
                        return true;
                    }
                    now.saturating_sub(entry.last_seen) <= idle_timeout_secs
                });
                before - lock.len()
            }
            Err(_) => 0,
        }
    }

    pub fn len(&self) -> usize {
        match self.inner.read() {
            Ok(lock) => lock.len(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn ips(&self) -> Vec<Ipv4Addr> {
        match self.inner.read() {
            Ok(lock) => {
                let mut out = lock.keys().copied().collect::<Vec<_>>();
                out.sort_unstable();
                out
            }
            Err(_) => Vec::new(),
        }
    }

    pub fn clear(&self) {
        if let Ok(mut lock) = self.inner.write() {
            lock.clear();
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Default)]
pub struct IpSetV4 {
    cidrs: Vec<CidrV4>,
    dynamic: Option<DynamicIpSetV4>,
}

impl IpSetV4 {
    pub fn new() -> Self {
        Self {
            cidrs: Vec::new(),
            dynamic: None,
        }
    }

    pub fn with_dynamic(dynamic: DynamicIpSetV4) -> Self {
        Self {
            cidrs: Vec::new(),
            dynamic: Some(dynamic),
        }
    }

    pub fn set_dynamic(&mut self, dynamic: DynamicIpSetV4) {
        self.dynamic = Some(dynamic);
    }

    pub fn add_cidr(&mut self, cidr: CidrV4) {
        self.cidrs.push(cidr);
    }

    pub fn add_ip(&mut self, ip: Ipv4Addr) {
        self.cidrs.push(CidrV4::new(ip, 32));
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty() && self.dynamic.is_none()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        if let Some(dynamic) = &self.dynamic {
            if dynamic.contains(ip) {
                return true;
            }
        }
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }

    pub fn cidrs(&self) -> &[CidrV4] {
        &self.cidrs
    }

    pub fn has_dynamic(&self) -> bool {
        self.dynamic.is_some()
    }

    pub(crate) fn dynamic_set(&self) -> Option<DynamicIpSetV4> {
        self.dynamic.clone()
    }

    pub fn dynamic_ips(&self) -> Vec<Ipv4Addr> {
        self.dynamic
            .as_ref()
            .map(|dynamic| dynamic.ips())
            .unwrap_or_default()
    }
}
