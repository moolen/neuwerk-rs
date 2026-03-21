use std::net::Ipv4Addr;

use crate::dataplane::flow::FlowKey;

pub const PORT_MIN: u16 = 1024;
pub const PORT_MAX: u16 = 65535;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

const NAT_TABLE_DEFAULT_CAPACITY: usize = 1 << 15;
const NAT_TABLE_MIN_CAPACITY: usize = 1 << 10;
const NAT_TABLE_MAX_CAPACITY: usize = 1 << 26;
const NAT_TABLE_MAX_LOAD_PERCENT: usize = 70;
const PORT_RANGE_LEN: usize = (PORT_MAX as usize) - (PORT_MIN as usize) + 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenProbeKind {
    Hit,
    Miss,
}

#[derive(Debug, Clone, Copy)]
struct OpenProbe {
    idx: usize,
    slots_len: usize,
    kind: OpenProbeKind,
    steps: usize,
}

impl OpenProbe {
    #[inline]
    fn is_hit(self) -> bool {
        self.kind == OpenProbeKind::Hit
    }

    #[inline]
    fn steps(self) -> usize {
        self.steps
    }

    #[inline]
    fn result_label(self) -> &'static str {
        match self.kind {
            OpenProbeKind::Hit => "hit",
            OpenProbeKind::Miss => "miss",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatCreateObservation {
    pub external_port: u16,
    pub created: bool,
    pub map_probe_steps: usize,
    pub map_probe_result: &'static str,
    pub reverse_probe_steps: usize,
    pub reverse_probe_result: &'static str,
    pub port_scan_steps: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatReverseLookupObservation {
    pub flow: Option<FlowKey>,
    pub probe_steps: usize,
    pub probe_result: &'static str,
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

    fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = OpenSlot::Empty;
        }
        self.len = 0;
        self.tombstones = 0;
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

    fn get_mut_with_probe(&mut self, key: &K, probe: OpenProbe) -> Option<&mut V> {
        let idx = self
            .reusable_lookup_index(key, probe)
            .or_else(|| self.find_index(key))?;
        match &mut self.slots[idx] {
            OpenSlot::Occupied { value, .. } => Some(value),
            _ => None,
        }
    }

    fn get_with_probe(&self, key: &K, probe: OpenProbe) -> Option<&V> {
        let idx = self
            .reusable_lookup_index(key, probe)
            .or_else(|| self.find_index(key))?;
        match &self.slots[idx] {
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

    #[allow(dead_code)]
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

    fn insert_with_probe(&mut self, key: K, value: V, probe: OpenProbe) -> Option<V> {
        self.ensure_insert_capacity();
        let idx = self
            .reusable_insert_index(&key, probe)
            .unwrap_or_else(|| self.find_insert_index(&key));
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

    fn probe(&self, key: &K) -> OpenProbe {
        self.find_probe(key)
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

    fn find_probe(&self, key: &K) -> OpenProbe {
        if self.slots.is_empty() {
            return OpenProbe {
                idx: 0,
                slots_len: 0,
                kind: OpenProbeKind::Miss,
                steps: 0,
            };
        }
        let mask = self.slots.len() - 1;
        let mut first_tombstone = None;
        let mut idx = self.initial_probe_index(key);
        for step in 0..self.slots.len() {
            match &self.slots[idx] {
                OpenSlot::Empty => {
                    return OpenProbe {
                        idx: first_tombstone.unwrap_or(idx),
                        slots_len: self.slots.len(),
                        kind: OpenProbeKind::Miss,
                        steps: step + 1,
                    };
                }
                OpenSlot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                OpenSlot::Occupied {
                    key: existing_key, ..
                } => {
                    if existing_key == key {
                        return OpenProbe {
                            idx,
                            slots_len: self.slots.len(),
                            kind: OpenProbeKind::Hit,
                            steps: step + 1,
                        };
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        OpenProbe {
            idx: first_tombstone.unwrap_or(0),
            slots_len: self.slots.len(),
            kind: OpenProbeKind::Miss,
            steps: self.slots.len(),
        }
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

    fn reusable_lookup_index(&self, key: &K, probe: OpenProbe) -> Option<usize> {
        if self.slots.len() != probe.slots_len || !probe.is_hit() {
            return None;
        }
        match &self.slots[probe.idx] {
            OpenSlot::Occupied {
                key: existing_key, ..
            } if existing_key == key => Some(probe.idx),
            _ => None,
        }
    }

    fn reusable_insert_index(&self, key: &K, probe: OpenProbe) -> Option<usize> {
        if self.slots.len() != probe.slots_len || probe.is_hit() {
            return None;
        }
        match &self.slots[probe.idx] {
            OpenSlot::Empty | OpenSlot::Tombstone => Some(probe.idx),
            OpenSlot::Occupied {
                key: existing_key, ..
            } if existing_key == key => Some(probe.idx),
            _ => None,
        }
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
    next_port_hint: u32,
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
            next_port_hint: u32::MAX,
        }
    }

    pub fn get_entry(&self, key: &FlowKey) -> Option<&NatEntry> {
        self.map.get(key)
    }

    pub fn get_or_create(&mut self, key: &FlowKey, now: u64) -> Result<u16, NatError> {
        self.get_or_create_with_status(key, now)
            .map(|(port, _)| port)
    }

    pub fn get_or_create_with_observation(
        &mut self,
        key: &FlowKey,
        now: u64,
    ) -> Result<NatCreateObservation, NatError> {
        let map_probe = self.map.probe(key);
        if let Some(entry) = self.map.get_mut_with_probe(key, map_probe) {
            entry.last_seen = now;
            return Ok(NatCreateObservation {
                external_port: entry.external_port,
                created: false,
                map_probe_steps: map_probe.steps(),
                map_probe_result: map_probe.result_label(),
                reverse_probe_steps: 0,
                reverse_probe_result: "not_needed",
                port_scan_steps: 0,
            });
        }

        let (reverse_key, reverse_probe, port_scan_steps) =
            self.allocate_port(key).ok_or(NatError::PortExhausted)?;
        let external_port = reverse_key.external_port;
        let entry = NatEntry {
            internal: *key,
            external_port,
            last_seen: now,
        };

        if let Some(old) = self.map.insert_with_probe(*key, entry, map_probe) {
            let old_reverse_key = ReverseKey {
                external_port: old.external_port,
                remote_ip: old.internal.dst_ip,
                remote_port: old.internal.dst_port,
                proto: old.internal.proto,
            };
            self.reverse.remove(&old_reverse_key);
        }
        if let Some(old_flow) = self
            .reverse
            .insert_with_probe(reverse_key, *key, reverse_probe)
        {
            if old_flow != *key {
                self.map.remove(&old_flow);
            }
        }

        Ok(NatCreateObservation {
            external_port,
            created: true,
            map_probe_steps: map_probe.steps(),
            map_probe_result: map_probe.result_label(),
            reverse_probe_steps: reverse_probe.steps(),
            reverse_probe_result: reverse_probe.result_label(),
            port_scan_steps,
        })
    }

    pub fn get_or_create_with_status(
        &mut self,
        key: &FlowKey,
        now: u64,
    ) -> Result<(u16, bool), NatError> {
        let obs = self.get_or_create_with_observation(key, now)?;
        Ok((obs.external_port, obs.created))
    }

    pub fn reverse_lookup(&self, key: &ReverseKey) -> Option<FlowKey> {
        self.reverse_lookup_with_observation(key).flow
    }

    pub fn reverse_lookup_with_observation(&self, key: &ReverseKey) -> NatReverseLookupObservation {
        let probe = self.reverse.probe(key);
        let flow = self.reverse.get_with_probe(key, probe).copied();
        NatReverseLookupObservation {
            flow,
            probe_steps: probe.steps(),
            probe_result: probe.result_label(),
        }
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
        self.next_port_hint = (entry.external_port - PORT_MIN) as u32;
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

    pub fn clear(&mut self) {
        self.map.clear();
        self.reverse.clear();
        self.next_port_hint = u32::MAX;
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn capacity(&self) -> usize {
        self.map.capacity()
    }

    pub fn is_empty(&self) -> bool {
        self.map.len() == 0
    }

    pub fn port_range_len() -> u32 {
        PORT_RANGE_LEN as u32
    }

    fn allocate_port(&mut self, key: &FlowKey) -> Option<(ReverseKey, OpenProbe, usize)> {
        let range = Self::port_range_len();
        let start = if self.next_port_hint < range {
            self.next_port_hint
        } else {
            flow_hash(key) % range
        };
        let mut reverse_key = ReverseKey {
            external_port: PORT_MIN,
            remote_ip: key.dst_ip,
            remote_port: key.dst_port,
            proto: key.proto,
        };
        for i in 0..range {
            let offset = (start + i) % Self::port_range_len();
            reverse_key.external_port = PORT_MIN + offset as u16;
            let probe = self.reverse.probe(&reverse_key);
            if !probe.is_hit() {
                self.next_port_hint = if offset + 1 == range { 0 } else { offset + 1 };
                return Some((reverse_key, probe, (i + 1) as usize));
            }
        }
        None
    }
}

fn flow_hash(key: &FlowKey) -> u32 {
    let src_ip = u32::from_be_bytes(key.src_ip.octets());
    let dst_ip = u32::from_be_bytes(key.dst_ip.octets());
    let ports = ((key.src_port as u32) << 16) | key.dst_port as u32;
    let seed = src_ip.wrapping_mul(0x9e37_79b1)
        ^ dst_ip.rotate_left(7).wrapping_mul(0x85eb_ca6b)
        ^ ports.rotate_left(13).wrapping_mul(0xc2b2_ae35)
        ^ (key.proto as u32).wrapping_mul(0x27d4_eb2d);
    finalize_hash32(seed)
}

fn reverse_hash(key: &ReverseKey) -> u32 {
    let remote_ip = u32::from_be_bytes(key.remote_ip.octets());
    let ports = ((key.external_port as u32) << 16) | key.remote_port as u32;
    let seed = remote_ip.wrapping_mul(0x9e37_79b1)
        ^ ports.rotate_left(11).wrapping_mul(0x85eb_ca6b)
        ^ (key.proto as u32).wrapping_mul(0xc2b2_ae35);
    finalize_hash32(seed)
}

#[inline(always)]
fn finalize_hash32(mut value: u32) -> u32 {
    value ^= value >> 16;
    value = value.wrapping_mul(0x85eb_ca6b);
    value ^= value >> 13;
    value = value.wrapping_mul(0xc2b2_ae35);
    value ^ (value >> 16)
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

    fn colliding_flows_for_preferred_port(preferred_port: u16, count: usize) -> Vec<FlowKey> {
        let target_offset = (preferred_port - PORT_MIN) as u32;
        let mut flows = Vec::with_capacity(count);
        let mut seed = 0u32;
        while flows.len() < count {
            let flow = FlowKey {
                src_ip: Ipv4Addr::new(10, 2, ((seed / 250) % 250) as u8, (seed % 250) as u8 + 1),
                dst_ip: Ipv4Addr::new(198, 51, 100, 10),
                src_port: 10_000 + (seed % 50_000) as u16,
                dst_port: 443,
                proto: 6,
            };
            if flow_hash(&flow) % NatTable::port_range_len() == target_offset {
                flows.push(flow);
            }
            seed += 1;
        }
        flows
    }

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
    fn evict_expired_allows_port_reuse() {
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
        assert!((PORT_MIN..=PORT_MAX).contains(&second));
        assert!(second == first || second == first.saturating_add(1));
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
        let flows = colliding_flows_for_preferred_port(PORT_MAX, 2);

        let occupied = table.get_or_create(&flows[0], 1).unwrap();
        assert_eq!(occupied, PORT_MAX);

        let (allocated, _, _) = table.allocate_port(&flows[1]).unwrap();
        assert_eq!(allocated.external_port, PORT_MIN);
    }

    #[test]
    fn colliding_allocations_advance_after_preferred_port_is_taken() {
        let mut table = NatTable::new_with_timeout(300);
        let flows = colliding_flows_for_preferred_port(PORT_MIN, 3);

        let first = table.get_or_create(&flows[0], 1).unwrap();
        let second = table.get_or_create(&flows[1], 1).unwrap();
        let third = table.get_or_create(&flows[2], 1).unwrap();

        assert_eq!(first, PORT_MIN);
        assert_eq!(second, PORT_MIN + 1);
        assert_eq!(third, PORT_MIN + 2);
    }

    #[test]
    fn remove_reuses_recently_freed_port_first() {
        let mut table = NatTable::new_with_timeout(300);
        let remote_ip = Ipv4Addr::new(198, 51, 100, 10);
        let remote_port = 443;

        for i in 0..1024u32 {
            let flow = FlowKey {
                src_ip: Ipv4Addr::new(10, 1, (i / 250) as u8, (i % 250) as u8 + 1),
                dst_ip: remote_ip,
                src_port: 10_000 + i as u16,
                dst_port: remote_port,
                proto: 6,
            };
            table.get_or_create(&flow, 1).unwrap();
        }

        let flow = FlowKey {
            src_ip: Ipv4Addr::new(10, 250, 0, 1),
            dst_ip: remote_ip,
            src_port: 55_555,
            dst_port: remote_port,
            proto: 6,
        };
        let first_port = table.get_or_create(&flow, 1).unwrap();
        assert!(table.remove(&flow));
        let second_port = table.get_or_create(&flow, 2).unwrap();

        assert_eq!(second_port, first_port);
    }
}
