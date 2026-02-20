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
}

impl FlowTable {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn insert(&mut self, key: FlowKey) {
        self.map.entry(key).or_insert(FlowEntry { last_seen: 0 });
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.map.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
}
