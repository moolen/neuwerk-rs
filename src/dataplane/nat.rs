use std::net::Ipv4Addr;

use crate::dataplane::flow::FlowKey;

pub const PORT_MIN: u16 = 40000;
pub const PORT_MAX: u16 = 59999;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

const NAT_TABLE_DEFAULT_CAPACITY: usize = 1 << 15;
const NAT_TABLE_MIN_CAPACITY: usize = 1 << 10;
const NAT_TABLE_MAX_CAPACITY: usize = 1 << 26;
const NAT_TABLE_MAX_LOAD_PERCENT: usize = 70;

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

#[derive(Debug)]
enum OpenSlot<K, V> {
    Empty,
    Tombstone,
    Occupied { key: K, value: V },
}

#[derive(Debug)]
struct OpenMap<K, V> {
    slots: Vec<OpenSlot<K, V>>,
    len: usize,
    tombstones: usize,
    hash_fn: fn(&K) -> u32,
}

impl<K: Copy + Eq, V> OpenMap<K, V> {
    fn new_with_capacity(capacity: usize, hash_fn: fn(&K) -> u32) -> Self {
        Self {
            slots: empty_slots(capacity),
            len: 0,
            tombstones: 0,
            hash_fn,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn get(&self, key: &K) -> Option<&V> {
        let idx = self.find_index(key)?;
        match &self.slots[idx] {
            OpenSlot::Occupied { value, .. } => Some(value),
            _ => None,
        }
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let idx = self.find_index(key)?;
        match &mut self.slots[idx] {
            OpenSlot::Occupied { value, .. } => Some(value),
            _ => None,
        }
    }

    #[inline]
    fn prefetch_key(&self, key: &K) {
        if self.slots.is_empty() {
            return;
        }
        let idx = self.initial_probe_index(key);
        prefetch_read((&self.slots[idx]) as *const OpenSlot<K, V>);
    }

    fn contains_key(&self, key: &K) -> bool {
        self.find_index(key).is_some()
    }

    fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.ensure_insert_capacity();
        let idx = self.find_insert_index(&key);
        let replaced = std::mem::replace(&mut self.slots[idx], OpenSlot::Occupied { key, value });
        match replaced {
            OpenSlot::Empty => {
                self.len += 1;
                None
            }
            OpenSlot::Tombstone => {
                self.len += 1;
                self.tombstones = self.tombstones.saturating_sub(1);
                None
            }
            OpenSlot::Occupied { value, .. } => Some(value),
        }
    }

    fn remove(&mut self, key: &K) -> Option<V> {
        let idx = self.find_index(key)?;
        let removed = std::mem::replace(&mut self.slots[idx], OpenSlot::Tombstone);
        match removed {
            OpenSlot::Occupied { value, .. } => {
                self.len = self.len.saturating_sub(1);
                self.tombstones = self.tombstones.saturating_add(1);
                self.maybe_compact();
                Some(value)
            }
            other => {
                self.slots[idx] = other;
                None
            }
        }
    }

    fn ensure_insert_capacity(&mut self) {
        if self.slots.is_empty() {
            self.resize(NAT_TABLE_MIN_CAPACITY);
            return;
        }
        let used = self.len + self.tombstones + 1;
        let max_used = (self.slots.len() * NAT_TABLE_MAX_LOAD_PERCENT) / 100;
        if used > max_used.max(1) {
            self.resize((self.slots.len() * 2).min(NAT_TABLE_MAX_CAPACITY));
        } else if self.tombstones > self.len && self.tombstones > (self.slots.len() / 5) {
            self.resize(self.slots.len());
        }
    }

    fn maybe_compact(&mut self) {
        if self.slots.len() > NAT_TABLE_MIN_CAPACITY
            && self.len < (self.slots.len() / 4)
            && self.tombstones < (self.slots.len() / 4)
        {
            self.resize((self.slots.len() / 2).max(NAT_TABLE_MIN_CAPACITY));
            return;
        }
        if self.tombstones > self.len && self.tombstones > (self.slots.len() / 5) {
            self.resize(self.slots.len());
        }
    }

    fn resize(&mut self, requested: usize) {
        let capacity = normalize_capacity(requested);
        let old_slots = std::mem::replace(&mut self.slots, empty_slots(capacity));
        self.len = 0;
        self.tombstones = 0;
        for slot in old_slots {
            if let OpenSlot::Occupied { key, value } = slot {
                self.insert_without_resize(key, value);
            }
        }
    }

    fn insert_without_resize(&mut self, key: K, value: V) {
        let idx = self.find_insert_index(&key);
        match std::mem::replace(&mut self.slots[idx], OpenSlot::Occupied { key, value }) {
            OpenSlot::Empty => self.len += 1,
            OpenSlot::Tombstone => {
                self.len += 1;
                self.tombstones = self.tombstones.saturating_sub(1);
            }
            OpenSlot::Occupied { .. } => {}
        }
    }

    fn find_index(&self, key: &K) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut idx = self.initial_probe_index(key);
        for _ in 0..self.slots.len() {
            match &self.slots[idx] {
                OpenSlot::Empty => return None,
                OpenSlot::Tombstone => {}
                OpenSlot::Occupied {
                    key: existing_key, ..
                } => {
                    if existing_key == key {
                        return Some(idx);
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        None
    }

    fn find_insert_index(&self, key: &K) -> usize {
        let mask = self.slots.len() - 1;
        let mut first_tombstone = None;
        let mut idx = self.initial_probe_index(key);
        for _ in 0..self.slots.len() {
            match &self.slots[idx] {
                OpenSlot::Empty => return first_tombstone.unwrap_or(idx),
                OpenSlot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                OpenSlot::Occupied {
                    key: existing_key, ..
                } => {
                    if existing_key == key {
                        return idx;
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        first_tombstone.unwrap_or(0)
    }

    #[inline]
    fn initial_probe_index(&self, key: &K) -> usize {
        ((self.hash_fn)(key) as usize) & (self.slots.len() - 1)
    }
}

#[derive(Debug)]
pub struct NatTable {
    map: OpenMap<FlowKey, NatEntry>,
    reverse: OpenMap<ReverseKey, FlowKey>,
    idle_timeout_secs: u64,
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NatTable {
    pub fn new() -> Self {
        Self::new_with_timeout(DEFAULT_IDLE_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        let capacity = env_capacity("NEUWERK_NAT_TABLE_CAPACITY", NAT_TABLE_DEFAULT_CAPACITY);
        Self {
            map: OpenMap::new_with_capacity(capacity, flow_hash),
            reverse: OpenMap::new_with_capacity(capacity, reverse_hash),
            idle_timeout_secs,
        }
    }

    pub fn get_entry(&self, key: &FlowKey) -> Option<&NatEntry> {
        self.map.get(key)
    }

    pub fn get_or_create(&mut self, key: &FlowKey, now: u64) -> Result<u16, NatError> {
        self.get_or_create_with_status(key, now)
            .map(|(port, _)| port)
    }

    pub fn get_or_create_with_status(
        &mut self,
        key: &FlowKey,
        now: u64,
    ) -> Result<(u16, bool), NatError> {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen = now;
            return Ok((entry.external_port, false));
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

        if let Some(old) = self.map.insert(*key, entry) {
            let old_reverse_key = ReverseKey {
                external_port: old.external_port,
                remote_ip: old.internal.dst_ip,
                remote_port: old.internal.dst_port,
                proto: old.internal.proto,
            };
            self.reverse.remove(&old_reverse_key);
        }
        if let Some(old_flow) = self.reverse.insert(reverse_key, *key) {
            if old_flow != *key {
                self.map.remove(&old_flow);
            }
        }

        Ok((external_port, true))
    }

    pub fn reverse_lookup(&self, key: &ReverseKey) -> Option<FlowKey> {
        self.reverse.get(key).copied()
    }

    #[inline]
    pub fn prefetch_flow_key(&self, key: &FlowKey) {
        self.map.prefetch_key(key);
    }

    #[inline]
    pub fn prefetch_reverse_key(&self, key: &ReverseKey) {
        self.reverse.prefetch_key(key);
    }

    pub fn touch(&mut self, key: &FlowKey, now: u64) {
        if let Some(entry) = self.map.get_mut(key) {
            entry.last_seen = now;
        }
    }

    pub fn remove(&mut self, key: &FlowKey) -> bool {
        let Some(entry) = self.map.remove(key) else {
            return false;
        };
        let reverse_key = ReverseKey {
            external_port: entry.external_port,
            remote_ip: entry.internal.dst_ip,
            remote_port: entry.internal.dst_port,
            proto: entry.internal.proto,
        };
        self.reverse.remove(&reverse_key);
        true
    }

    pub fn evict_expired(&mut self, now: u64) -> usize {
        let timeout = self.idle_timeout_secs;
        let mut expired = Vec::new();
        for slot in &self.map.slots {
            let OpenSlot::Occupied { key, value } = slot else {
                continue;
            };
            if now.saturating_sub(value.last_seen) > timeout {
                expired.push(*key);
            }
        }
        for key in &expired {
            self.remove(key);
        }
        expired.len()
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.len() == 0
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

fn reverse_hash(key: &ReverseKey) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in key.external_port.to_be_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for byte in key.remote_ip.octets() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    for byte in key.remote_port.to_be_bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash ^= key.proto as u32;
    hash = hash.wrapping_mul(0x01000193);
    hash
}

#[inline]
fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use core::arch::x86_64::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(ptr.cast::<i8>(), _MM_HINT_T0);
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        use core::arch::x86::{_mm_prefetch, _MM_HINT_T0};
        _mm_prefetch(ptr.cast::<i8>(), _MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    let _ = ptr;
}

fn env_capacity(name: &str, default: usize) -> usize {
    let parsed = std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(default);
    normalize_capacity(parsed)
}

fn normalize_capacity(raw: usize) -> usize {
    raw.clamp(NAT_TABLE_MIN_CAPACITY, NAT_TABLE_MAX_CAPACITY)
        .next_power_of_two()
}

fn empty_slots<K, V>(capacity: usize) -> Vec<OpenSlot<K, V>> {
    let mut slots = Vec::with_capacity(capacity);
    slots.resize_with(capacity, || OpenSlot::Empty);
    slots
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

    #[test]
    fn nat_round_trip_lookup_and_remove() {
        let mut table = NatTable::new_with_timeout(300);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 12345,
            dst_port: 443,
            proto: 6,
        };
        let port = table.get_or_create(&flow, 1).expect("allocate nat port");
        let reverse = ReverseKey {
            external_port: port,
            remote_ip: flow.dst_ip,
            remote_port: flow.dst_port,
            proto: flow.proto,
        };
        assert_eq!(table.reverse_lookup(&reverse), Some(flow));
        assert!(table.remove(&flow));
        assert!(table.reverse_lookup(&reverse).is_none());
    }

    #[test]
    fn evict_expired_allows_deterministic_port_reuse() {
        let mut table = NatTable::new_with_timeout(1);
        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(203, 0, 113, 10),
            src_port: 12345,
            dst_port: 443,
            proto: 6,
        };

        let first = table.get_or_create(&flow, 1).unwrap();
        assert_eq!(table.evict_expired(3), 1);

        let (second, created) = table.get_or_create_with_status(&flow, 4).unwrap();
        assert!(created);
        assert_eq!(second, first);
    }

    #[test]
    fn nat_reports_port_exhaustion_for_single_remote_tuple() {
        let mut table = NatTable::new_with_timeout(300);
        let dst_ip = Ipv4Addr::new(198, 51, 100, 10);
        let dst_port = 443;
        let proto = 6;

        for src_port in 0..NatTable::port_range_len() {
            let flow = FlowKey {
                src_ip: Ipv4Addr::new(10, 0, 0, 2),
                dst_ip,
                src_port: src_port as u16,
                dst_port,
                proto,
            };
            table.get_or_create(&flow, 1).unwrap();
        }

        let exhausted = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 3),
            dst_ip,
            src_port: 65000,
            dst_port,
            proto,
        };
        assert_eq!(
            table.get_or_create(&exhausted, 2),
            Err(NatError::PortExhausted)
        );
    }

    #[test]
    fn allocation_wraps_from_port_max_to_port_min() {
        let mut table = NatTable::new_with_timeout(300);
        let mut flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(203, 0, 113, 40),
            src_port: 10000,
            dst_port: 8443,
            proto: 6,
        };
        let range = NatTable::port_range_len();
        while flow_hash(&flow) % range != range - 1 {
            flow.src_port = flow.src_port.wrapping_add(1);
        }

        let occupied = ReverseKey {
            external_port: PORT_MAX,
            remote_ip: flow.dst_ip,
            remote_port: flow.dst_port,
            proto: flow.proto,
        };
        table.reverse.insert(occupied, flow);

        let allocated = table.allocate_port(&flow).unwrap();
        assert_eq!(allocated, PORT_MIN);
    }
}
