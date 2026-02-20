use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub last_seen: u64,
}

#[derive(Debug, Default)]
pub struct FlowTable {
    map: HashMap<FlowKey, FlowEntry>,
    idle_timeout_secs: u64,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::new_with_timeout(crate::dataplane::DEFAULT_IDLE_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        Self {
            map: HashMap::new(),
            idle_timeout_secs,
        }
    }

    pub fn touch(&mut self, key: FlowKey, now: u64) {
        self.map
            .entry(key)
            .and_modify(|entry| entry.last_seen = now)
            .or_insert(FlowEntry { last_seen: now });
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.map.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn evict_expired(&mut self, now: u64) -> usize {
        let timeout = self.idle_timeout_secs;
        let before = self.map.len();
        self.map
            .retain(|_, entry| now.saturating_sub(entry.last_seen) <= timeout);
        before - self.map.len()
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }
}
