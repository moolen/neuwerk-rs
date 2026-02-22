use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::dataplane::tls::TlsFlowState;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
}

#[derive(Debug)]
pub struct FlowEntry {
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub last_reported: u64,
    pub tls: Option<TlsFlowState>,
    pub source_group: String,
}

impl FlowEntry {
    pub fn new(last_seen: u64) -> Self {
        Self {
            first_seen: last_seen,
            last_seen,
            packets_in: 0,
            packets_out: 0,
            last_reported: 0,
            tls: None,
            source_group: "default".to_string(),
        }
    }

    pub fn with_source_group(last_seen: u64, source_group: String) -> Self {
        Self {
            source_group,
            ..Self::new(last_seen)
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExpiredFlow {
    pub key: FlowKey,
    pub last_seen: u64,
    pub packets_in: u64,
    pub packets_out: u64,
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

    pub fn touch(&mut self, key: FlowKey, now: u64) -> bool {
        match self.map.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().last_seen = now;
                false
            }
            Entry::Vacant(entry) => {
                entry.insert(FlowEntry::new(now));
                true
            }
        }
    }

    pub fn insert(&mut self, key: FlowKey, entry: FlowEntry) {
        self.map.insert(key, entry);
    }

    pub fn get_entry(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.map.get(key)
    }

    pub fn get_entry_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        self.map.get_mut(key)
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.map.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn evict_expired(&mut self, now: u64) -> Vec<ExpiredFlow> {
        let timeout = self.idle_timeout_secs;
        let mut expired = Vec::new();
        for (key, entry) in self.map.iter() {
            if now.saturating_sub(entry.last_seen) > timeout {
                expired.push(ExpiredFlow {
                    key: *key,
                    last_seen: entry.last_seen,
                    packets_in: entry.packets_in,
                    packets_out: entry.packets_out,
                });
            }
        }

        for flow in &expired {
            self.map.remove(&flow.key);
        }

        expired
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }
}
