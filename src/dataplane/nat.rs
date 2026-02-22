use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::dataplane::flow::FlowKey;

pub const PORT_MIN: u16 = 40000;
pub const PORT_MAX: u16 = 59999;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatError {
    PortExhausted,
}

#[derive(Debug, Clone)]
pub struct NatEntry {
    pub internal: FlowKey,
    pub external_port: u16,
    pub last_seen: u64,
}

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ReverseKey {
    pub external_port: u16,
    pub remote_ip: Ipv4Addr,
    pub remote_port: u16,
    pub proto: u8,
}

#[derive(Debug, Default)]
pub struct NatTable {
    map: HashMap<FlowKey, NatEntry>,
    reverse: HashMap<ReverseKey, FlowKey>,
    idle_timeout_secs: u64,
}

impl NatTable {
    pub fn new() -> Self {
        Self::new_with_timeout(DEFAULT_IDLE_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        Self {
            map: HashMap::new(),
            reverse: HashMap::new(),
            idle_timeout_secs,
        }
    }

    pub fn get_entry(&self, key: &FlowKey) -> Option<&NatEntry> {
        self.map.get(key)
    }

    pub fn get_or_create(&mut self, key: &FlowKey, now: u64) -> Result<u16, NatError> {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen = now;
            return Ok(entry.external_port);
        }

        let external_port = self.allocate_port(key).ok_or(NatError::PortExhausted)?;
        let entry = NatEntry {
            internal: *key,
            external_port,
            last_seen: now,
        };
        let reverse_key = ReverseKey {
            external_port,
            remote_ip: key.dst_ip,
            remote_port: key.dst_port,
            proto: key.proto,
        };

        self.map.insert(*key, entry);
        self.reverse.insert(reverse_key, *key);

        Ok(external_port)
    }

    pub fn reverse_lookup(&self, key: &ReverseKey) -> Option<FlowKey> {
        self.reverse.get(key).copied()
    }

    pub fn touch(&mut self, key: &FlowKey, now: u64) {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen = now;
        }
    }

    pub fn evict_expired(&mut self, now: u64) -> usize {
        let timeout = self.idle_timeout_secs;
        let mut expired = Vec::new();
        for (key, entry) in self.map.iter() {
            if now.saturating_sub(entry.last_seen) > timeout {
                let reverse_key = ReverseKey {
                    external_port: entry.external_port,
                    remote_ip: key.dst_ip,
                    remote_port: key.dst_port,
                    proto: key.proto,
                };
                expired.push((*key, reverse_key));
            }
        }

        for (key, reverse_key) in &expired {
            self.map.remove(key);
            self.reverse.remove(reverse_key);
        }

        expired.len()
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn port_range_len() -> u32 {
        (PORT_MAX - PORT_MIN + 1) as u32
    }

    fn allocate_port(&self, key: &FlowKey) -> Option<u16> {
        let range = (PORT_MAX - PORT_MIN + 1) as u32;
        let start = flow_hash(key) % range;
        for i in 0..range {
            let offset = (start + i) % range;
            let port = PORT_MIN + offset as u16;
            let reverse_key = ReverseKey {
                external_port: port,
                remote_ip: key.dst_ip,
                remote_port: key.dst_port,
                proto: key.proto,
            };
            if !self.reverse.contains_key(&reverse_key) {
                return Some(port);
            }
        }
        None
    }
}

fn flow_hash(key: &FlowKey) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in key.src_ip.octets() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for byte in key.dst_ip.octets() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for byte in key.src_port.to_be_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for byte in key.dst_port.to_be_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash ^= key.proto as u32;
    hash = hash.wrapping_mul(0x01000193);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_hash_deterministic() {
        let key = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 1234,
            dst_port: 53,
            proto: 17,
        };
        let h1 = flow_hash(&key);
        let h2 = flow_hash(&key);
        assert_eq!(h1, h2);
    }
}
