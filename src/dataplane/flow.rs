use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::dataplane::tls::TlsFlowState;

pub const DEFAULT_SOURCE_GROUP: &str = "default";

const FLOW_TABLE_DEFAULT_CAPACITY: usize = 1 << 15;
const FLOW_TABLE_MIN_CAPACITY: usize = 1 << 10;
const FLOW_TABLE_MAX_CAPACITY: usize = 1 << 26;
const FLOW_TABLE_MAX_LOAD_PERCENT: usize = 70;

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
    source_group: Option<Arc<str>>,
    pub policy_generation: u64,
    pub intercept_requires_service: bool,
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
            source_group: None,
            policy_generation: 0,
            intercept_requires_service: false,
        }
    }

    pub fn with_source_group(last_seen: u64, source_group: String) -> Self {
        let mut entry = Self::new(last_seen);
        entry.set_source_group_owned(source_group);
        entry
    }

    pub fn with_source_group_arc(last_seen: u64, source_group: Option<Arc<str>>) -> Self {
        let mut entry = Self::new(last_seen);
        entry.set_source_group_arc(source_group);
        entry
    }

    pub fn source_group(&self) -> &str {
        self.source_group.as_deref().unwrap_or(DEFAULT_SOURCE_GROUP)
    }

    pub fn source_group_arc(&self) -> Option<Arc<str>> {
        self.source_group.clone()
    }

    pub fn set_source_group_owned(&mut self, source_group: String) {
        self.set_source_group_arc(
            (source_group != DEFAULT_SOURCE_GROUP).then(|| Arc::from(source_group)),
        );
    }

    pub fn set_source_group_arc(&mut self, source_group: Option<Arc<str>>) {
        self.source_group = source_group.filter(|group| group.as_ref() != DEFAULT_SOURCE_GROUP);
    }
}

#[derive(Debug, Clone)]
pub struct ExpiredFlow {
    pub key: FlowKey,
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub source_group: Option<Arc<str>>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
enum FlowSlot {
    Empty,
    Tombstone,
    Occupied { key: FlowKey, entry: FlowEntry },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowProbeKind {
    Hit,
    Miss,
}

#[derive(Debug, Clone, Copy)]
pub struct FlowProbe {
    idx: usize,
    slots_len: usize,
    kind: FlowProbeKind,
}

impl FlowProbe {
    pub fn is_hit(self) -> bool {
        self.kind == FlowProbeKind::Hit
    }
}

#[derive(Debug)]
pub struct FlowTable {
    slots: Vec<FlowSlot>,
    len: usize,
    tombstones: usize,
    idle_timeout_secs: u64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTable {
    pub fn new() -> Self {
        Self::new_with_timeout(crate::dataplane::DEFAULT_IDLE_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        let capacity = env_capacity("NEUWERK_FLOW_TABLE_CAPACITY", FLOW_TABLE_DEFAULT_CAPACITY);
        Self {
            slots: empty_slots(capacity),
            len: 0,
            tombstones: 0,
            idle_timeout_secs,
        }
    }

    pub fn touch(&mut self, key: FlowKey, now: u64) -> bool {
        if let Some(entry) = self.get_entry_mut(&key) {
            entry.last_seen = now;
            return false;
        }
        self.ensure_insert_capacity();
        self.insert_without_resize(key, FlowEntry::new(now));
        true
    }

    pub fn insert(&mut self, key: FlowKey, entry: FlowEntry) {
        self.ensure_insert_capacity();
        self.insert_without_resize(key, entry);
    }

    pub fn insert_and_get_mut(&mut self, key: FlowKey, entry: FlowEntry) -> &mut FlowEntry {
        self.ensure_insert_capacity();
        let idx = self.insert_without_resize_get_index(key, entry);
        match &mut self.slots[idx] {
            FlowSlot::Occupied { entry, .. } => entry,
            _ => unreachable!("inserted flow entry must occupy a slot"),
        }
    }

    pub fn insert_with_probe_and_get_mut(
        &mut self,
        key: FlowKey,
        entry: FlowEntry,
        probe: FlowProbe,
    ) -> &mut FlowEntry {
        self.ensure_insert_capacity();
        let idx = self
            .reusable_insert_index(&key, probe)
            .unwrap_or_else(|| self.find_insert_index(&key));
        self.insert_without_resize_at_index(idx, key, entry);
        match &mut self.slots[idx] {
            FlowSlot::Occupied { entry, .. } => entry,
            _ => unreachable!("inserted flow entry must occupy a slot"),
        }
    }

    pub fn probe(&self, key: &FlowKey) -> FlowProbe {
        self.find_probe(key)
    }

    pub fn get_entry(&self, key: &FlowKey) -> Option<&FlowEntry> {
        let idx = self.find_index(key)?;
        match &self.slots[idx] {
            FlowSlot::Occupied { entry, .. } => Some(entry),
            _ => None,
        }
    }

    pub fn get_entry_mut(&mut self, key: &FlowKey) -> Option<&mut FlowEntry> {
        let idx = self.find_index(key)?;
        match &mut self.slots[idx] {
            FlowSlot::Occupied { entry, .. } => Some(entry),
            _ => None,
        }
    }

    pub fn get_entry_mut_with_probe(
        &mut self,
        key: &FlowKey,
        probe: FlowProbe,
    ) -> Option<&mut FlowEntry> {
        let idx = self
            .reusable_lookup_index(key, probe)
            .or_else(|| self.find_index(key))?;
        match &mut self.slots[idx] {
            FlowSlot::Occupied { entry, .. } => Some(entry),
            _ => None,
        }
    }

    #[inline]
    pub fn prefetch_key(&self, key: &FlowKey) {
        if self.slots.is_empty() {
            return;
        }
        let idx = self.initial_probe_index(key);
        prefetch_read((&self.slots[idx]) as *const FlowSlot);
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<FlowEntry> {
        let idx = self.find_index(key)?;
        let removed = std::mem::replace(&mut self.slots[idx], FlowSlot::Tombstone);
        match removed {
            FlowSlot::Occupied { entry, .. } => {
                self.len = self.len.saturating_sub(1);
                self.tombstones = self.tombstones.saturating_add(1);
                self.maybe_compact();
                Some(entry)
            }
            other => {
                self.slots[idx] = other;
                None
            }
        }
    }

    pub fn contains(&self, key: &FlowKey) -> bool {
        self.get_entry(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = FlowSlot::Empty;
        }
        self.len = 0;
        self.tombstones = 0;
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn evict_expired(&mut self, now: u64) -> Vec<ExpiredFlow> {
        let timeout = self.idle_timeout_secs;
        let mut expired = Vec::new();
        for idx in 0..self.slots.len() {
            let should_remove = match &self.slots[idx] {
                FlowSlot::Occupied { entry, .. } => now.saturating_sub(entry.last_seen) > timeout,
                _ => false,
            };
            if !should_remove {
                continue;
            }
            let removed = std::mem::replace(&mut self.slots[idx], FlowSlot::Tombstone);
            if let FlowSlot::Occupied { key, entry } = removed {
                self.len = self.len.saturating_sub(1);
                self.tombstones = self.tombstones.saturating_add(1);
                expired.push(ExpiredFlow {
                    key,
                    first_seen: entry.first_seen,
                    last_seen: entry.last_seen,
                    packets_in: entry.packets_in,
                    packets_out: entry.packets_out,
                    source_group: entry.source_group_arc(),
                });
            }
        }
        if !expired.is_empty() {
            self.maybe_compact();
        }
        expired
    }

    fn ensure_insert_capacity(&mut self) {
        if self.slots.is_empty() {
            self.resize(FLOW_TABLE_MIN_CAPACITY);
            return;
        }
        let used = self.len + self.tombstones + 1;
        let max_used = (self.slots.len() * FLOW_TABLE_MAX_LOAD_PERCENT) / 100;
        if used > max_used.max(1) {
            self.resize((self.slots.len() * 2).min(FLOW_TABLE_MAX_CAPACITY));
        } else if self.tombstones > self.len && self.tombstones > (self.slots.len() / 5) {
            self.resize(self.slots.len());
        }
    }

    fn maybe_compact(&mut self) {
        if self.slots.len() > FLOW_TABLE_MIN_CAPACITY
            && self.len < (self.slots.len() / 4)
            && self.tombstones < (self.slots.len() / 4)
        {
            self.resize((self.slots.len() / 2).max(FLOW_TABLE_MIN_CAPACITY));
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
            if let FlowSlot::Occupied { key, entry } = slot {
                self.insert_without_resize(key, entry);
            }
        }
    }

    fn insert_without_resize(&mut self, key: FlowKey, entry: FlowEntry) {
        self.insert_without_resize_get_index(key, entry);
    }

    fn insert_without_resize_get_index(&mut self, key: FlowKey, entry: FlowEntry) -> usize {
        let idx = self.find_insert_index(&key);
        self.insert_without_resize_at_index(idx, key, entry);
        idx
    }

    fn insert_without_resize_at_index(&mut self, idx: usize, key: FlowKey, entry: FlowEntry) {
        match std::mem::replace(&mut self.slots[idx], FlowSlot::Occupied { key, entry }) {
            FlowSlot::Empty => {
                self.len += 1;
            }
            FlowSlot::Tombstone => {
                self.len += 1;
                self.tombstones = self.tombstones.saturating_sub(1);
            }
            FlowSlot::Occupied { .. } => {}
        }
    }

    fn find_index(&self, key: &FlowKey) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let mask = self.slots.len() - 1;
        let mut idx = self.initial_probe_index(key);
        for _ in 0..self.slots.len() {
            match &self.slots[idx] {
                FlowSlot::Empty => return None,
                FlowSlot::Tombstone => {}
                FlowSlot::Occupied { key: existing, .. } => {
                    if existing == key {
                        return Some(idx);
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        None
    }

    fn find_probe(&self, key: &FlowKey) -> FlowProbe {
        if self.slots.is_empty() {
            return FlowProbe {
                idx: 0,
                slots_len: 0,
                kind: FlowProbeKind::Miss,
            };
        }
        let mask = self.slots.len() - 1;
        let mut first_tombstone = None;
        let mut idx = self.initial_probe_index(key);
        for _ in 0..self.slots.len() {
            match &self.slots[idx] {
                FlowSlot::Empty => {
                    return FlowProbe {
                        idx: first_tombstone.unwrap_or(idx),
                        slots_len: self.slots.len(),
                        kind: FlowProbeKind::Miss,
                    };
                }
                FlowSlot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                FlowSlot::Occupied { key: existing, .. } => {
                    if existing == key {
                        return FlowProbe {
                            idx,
                            slots_len: self.slots.len(),
                            kind: FlowProbeKind::Hit,
                        };
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        FlowProbe {
            idx: first_tombstone.unwrap_or(0),
            slots_len: self.slots.len(),
            kind: FlowProbeKind::Miss,
        }
    }

    fn find_insert_index(&self, key: &FlowKey) -> usize {
        let mask = self.slots.len() - 1;
        let mut first_tombstone = None;
        let mut idx = self.initial_probe_index(key);
        for _ in 0..self.slots.len() {
            match &self.slots[idx] {
                FlowSlot::Empty => {
                    return first_tombstone.unwrap_or(idx);
                }
                FlowSlot::Tombstone => {
                    if first_tombstone.is_none() {
                        first_tombstone = Some(idx);
                    }
                }
                FlowSlot::Occupied { key: existing, .. } => {
                    if existing == key {
                        return idx;
                    }
                }
            }
            idx = (idx + 1) & mask;
        }
        first_tombstone.unwrap_or(0)
    }

    fn reusable_lookup_index(&self, key: &FlowKey, probe: FlowProbe) -> Option<usize> {
        if probe.kind != FlowProbeKind::Hit
            || probe.slots_len != self.slots.len()
            || self.slots.is_empty()
        {
            return None;
        }
        match self.slots.get(probe.idx) {
            Some(FlowSlot::Occupied { key: existing, .. }) if existing == key => Some(probe.idx),
            _ => None,
        }
    }

    fn reusable_insert_index(&self, key: &FlowKey, probe: FlowProbe) -> Option<usize> {
        if probe.slots_len != self.slots.len() || self.slots.is_empty() {
            return None;
        }
        match (probe.kind, self.slots.get(probe.idx)) {
            (FlowProbeKind::Hit, Some(FlowSlot::Occupied { key: existing, .. }))
                if existing == key =>
            {
                Some(probe.idx)
            }
            (FlowProbeKind::Miss, Some(FlowSlot::Empty | FlowSlot::Tombstone)) => Some(probe.idx),
            (FlowProbeKind::Miss, Some(FlowSlot::Occupied { key: existing, .. }))
                if existing == key =>
            {
                Some(probe.idx)
            }
            _ => None,
        }
    }

    #[inline]
    fn initial_probe_index(&self, key: &FlowKey) -> usize {
        (flow_hash(key) as usize) & (self.slots.len() - 1)
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
    raw.clamp(FLOW_TABLE_MIN_CAPACITY, FLOW_TABLE_MAX_CAPACITY)
        .next_power_of_two()
}

fn empty_slots(capacity: usize) -> Vec<FlowSlot> {
    let mut slots = Vec::with_capacity(capacity);
    slots.resize_with(capacity, || FlowSlot::Empty);
    slots
}
