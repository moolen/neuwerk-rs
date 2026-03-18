use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::dataplane::tls::TlsFlowState;

pub const DEFAULT_SOURCE_GROUP: &str = "default";
const TCP_HANDSHAKE_SYN_OUTBOUND_SEEN: u8 = 1 << 0;
const TCP_HANDSHAKE_SYNACK_INBOUND_SEEN: u8 = 1 << 1;
const TCP_HANDSHAKE_COMPLETED: u8 = 1 << 2;

const FLOW_TABLE_DEFAULT_CAPACITY: usize = 1 << 15;
const FLOW_TABLE_MIN_CAPACITY: usize = 1 << 10;
const FLOW_TABLE_MAX_CAPACITY: usize = 1 << 26;
const FLOW_TABLE_MAX_LOAD_PERCENT: usize = 70;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakePhase {
    Unknown,
    SynOnly,
    SynAckSeen,
    Completed,
}

impl TcpHandshakePhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SynOnly => "syn_only",
            Self::SynAckSeen => "synack_seen",
            Self::Completed => "completed",
        }
    }
}

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
    tcp_handshake_state: u8,
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
            tcp_handshake_state: 0,
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

    pub fn note_syn_outbound(&mut self) {
        self.tcp_handshake_state |= TCP_HANDSHAKE_SYN_OUTBOUND_SEEN;
    }

    pub fn note_synack_inbound(&mut self) {
        self.tcp_handshake_state |= TCP_HANDSHAKE_SYNACK_INBOUND_SEEN;
    }

    pub fn syn_outbound_seen(&self) -> bool {
        (self.tcp_handshake_state & TCP_HANDSHAKE_SYN_OUTBOUND_SEEN) != 0
    }

    pub fn synack_inbound_seen(&self) -> bool {
        (self.tcp_handshake_state & TCP_HANDSHAKE_SYNACK_INBOUND_SEEN) != 0
    }

    pub fn handshake_completed(&self) -> bool {
        (self.tcp_handshake_state & TCP_HANDSHAKE_COMPLETED) != 0
    }

    pub fn note_handshake_completed(&mut self) {
        self.tcp_handshake_state |= TCP_HANDSHAKE_COMPLETED;
    }

    pub fn handshake_phase(&self) -> TcpHandshakePhase {
        if self.handshake_completed() {
            TcpHandshakePhase::Completed
        } else if self.synack_inbound_seen() {
            TcpHandshakePhase::SynAckSeen
        } else if self.syn_outbound_seen() {
            TcpHandshakePhase::SynOnly
        } else {
            TcpHandshakePhase::Unknown
        }
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
    pub handshake_phase: TcpHandshakePhase,
}

#[derive(Debug, Clone)]
pub struct SynOnlyEntry {
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets_out: u64,
    pub source_group: Option<Arc<str>>,
    pub policy_generation: u64,
    pub intercept_requires_service: bool,
}

impl SynOnlyEntry {
    pub fn new(last_seen: u64, source_group: Option<Arc<str>>) -> Self {
        Self {
            first_seen: last_seen,
            last_seen,
            packets_out: 0,
            source_group,
            policy_generation: 0,
            intercept_requires_service: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PromotedSynOnlyFlow {
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets_out: u64,
    pub source_group: Option<Arc<str>>,
    pub policy_generation: u64,
    pub intercept_requires_service: bool,
}

#[derive(Debug, Clone)]
pub struct EvictedSynOnlyFlow {
    pub key: FlowKey,
    pub first_seen: u64,
    pub last_seen: u64,
    pub source_group: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynOnlyUpsertResult {
    Inserted,
    Updated,
}

#[derive(Debug, Clone)]
pub struct SynOnlyTable {
    entries: HashMap<FlowKey, SynOnlyEntry>,
    idle_timeout_secs: u64,
}

impl SynOnlyTable {
    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        Self {
            entries: HashMap::new(),
            idle_timeout_secs,
        }
    }

    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout_secs
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn upsert(
        &mut self,
        key: FlowKey,
        now: u64,
        source_group: Option<Arc<str>>,
        policy_generation: u64,
        intercept_requires_service: bool,
    ) -> SynOnlyUpsertResult {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = now;
            entry.packets_out = entry.packets_out.saturating_add(1);
            entry.source_group = source_group;
            entry.policy_generation = policy_generation;
            entry.intercept_requires_service = intercept_requires_service;
            return SynOnlyUpsertResult::Updated;
        }
        let mut entry = SynOnlyEntry::new(now, source_group);
        entry.packets_out = 1;
        entry.policy_generation = policy_generation;
        entry.intercept_requires_service = intercept_requires_service;
        self.entries.insert(key, entry);
        SynOnlyUpsertResult::Inserted
    }

    pub fn remove(&mut self, key: &FlowKey) -> Option<SynOnlyEntry> {
        self.entries.remove(key)
    }

    pub fn promote(&mut self, key: &FlowKey, now: u64) -> Option<PromotedSynOnlyFlow> {
        let mut entry = self.entries.remove(key)?;
        entry.last_seen = now;
        Some(PromotedSynOnlyFlow {
            first_seen: entry.first_seen,
            last_seen: entry.last_seen,
            packets_out: entry.packets_out,
            source_group: entry.source_group,
            policy_generation: entry.policy_generation,
            intercept_requires_service: entry.intercept_requires_service,
        })
    }

    pub fn evict_expired(&mut self, now: u64) -> Vec<EvictedSynOnlyFlow> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let mut expired_keys = Vec::new();
        for (key, entry) in &self.entries {
            if now.saturating_sub(entry.last_seen) > self.idle_timeout_secs {
                expired_keys.push(*key);
            }
        }
        if expired_keys.is_empty() {
            return Vec::new();
        }
        let mut expired = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(entry) = self.entries.remove(&key) {
                expired.push(EvictedSynOnlyFlow {
                    key,
                    first_seen: entry.first_seen,
                    last_seen: entry.last_seen,
                    source_group: entry.source_group,
                });
            }
        }
        expired
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowResizeCounters {
    pub grow: u64,
    pub shrink: u64,
    pub rehash: u64,
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
    steps: usize,
}

impl FlowProbe {
    pub fn is_hit(self) -> bool {
        self.kind == FlowProbeKind::Hit
    }

    pub fn steps(self) -> usize {
        self.steps
    }

    pub fn result_label(self) -> &'static str {
        match self.kind {
            FlowProbeKind::Hit => "hit",
            FlowProbeKind::Miss => "miss",
        }
    }
}

#[derive(Debug)]
pub struct FlowTable {
    slots: Vec<FlowSlot>,
    len: usize,
    tombstones: usize,
    min_capacity: usize,
    idle_timeout_secs: u64,
    incomplete_tcp_idle_timeout_secs: u64,
    incomplete_tcp_syn_sent_idle_timeout_secs: u64,
    resize_counters: FlowResizeCounters,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowResizeReason {
    Grow,
    Shrink,
    Rehash,
}

impl FlowTable {
    pub fn new() -> Self {
        Self::new_with_timeout(crate::dataplane::DEFAULT_IDLE_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(idle_timeout_secs: u64) -> Self {
        let capacity = env_capacity("NEUWERK_FLOW_TABLE_CAPACITY", FLOW_TABLE_DEFAULT_CAPACITY);
        let incomplete_tcp_idle_timeout_secs = env_timeout_secs(
            "NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS",
            idle_timeout_secs,
        );
        let incomplete_tcp_syn_sent_idle_timeout_secs = env_timeout_secs(
            "NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS",
            incomplete_tcp_idle_timeout_secs,
        );
        Self {
            slots: empty_slots(capacity),
            len: 0,
            tombstones: 0,
            min_capacity: capacity,
            idle_timeout_secs,
            incomplete_tcp_idle_timeout_secs,
            incomplete_tcp_syn_sent_idle_timeout_secs,
            resize_counters: FlowResizeCounters::default(),
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

    pub fn capacity(&self) -> usize {
        self.slots.len()
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

    pub fn incomplete_tcp_syn_sent_idle_timeout_secs(&self) -> u64 {
        self.incomplete_tcp_syn_sent_idle_timeout_secs
    }

    pub fn tombstones(&self) -> usize {
        self.tombstones
    }

    pub fn resize_counters(&self) -> FlowResizeCounters {
        self.resize_counters
    }

    pub fn evict_expired(&mut self, now: u64) -> Vec<ExpiredFlow> {
        let mut expired = Vec::new();
        for idx in 0..self.slots.len() {
            let should_remove = match &self.slots[idx] {
                FlowSlot::Occupied { key, entry } => {
                    let timeout = self.entry_idle_timeout_secs(key, entry);
                    now.saturating_sub(entry.last_seen) > timeout
                }
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
                    handshake_phase: entry.handshake_phase(),
                });
            }
        }
        if !expired.is_empty() {
            self.maybe_compact();
        }
        expired
    }

    fn entry_idle_timeout_secs(&self, key: &FlowKey, entry: &FlowEntry) -> u64 {
        if key.proto != 6 {
            return self.idle_timeout_secs;
        }
        match entry.handshake_phase() {
            TcpHandshakePhase::Completed => self.idle_timeout_secs,
            TcpHandshakePhase::SynOnly => self.incomplete_tcp_syn_sent_idle_timeout_secs,
            TcpHandshakePhase::SynAckSeen | TcpHandshakePhase::Unknown => {
                self.incomplete_tcp_idle_timeout_secs
            }
        }
    }

    fn ensure_insert_capacity(&mut self) {
        if self.slots.is_empty() {
            self.resize(self.min_capacity, FlowResizeReason::Grow);
            return;
        }
        let used = self.len + self.tombstones + 1;
        let max_used = (self.slots.len() * FLOW_TABLE_MAX_LOAD_PERCENT) / 100;
        if used > max_used.max(1) {
            self.resize(
                (self.slots.len() * 2).min(FLOW_TABLE_MAX_CAPACITY),
                FlowResizeReason::Grow,
            );
        } else if self.tombstones > self.len && self.tombstones > (self.slots.len() / 5) {
            self.resize(self.slots.len(), FlowResizeReason::Rehash);
        }
    }

    fn maybe_compact(&mut self) {
        if self.slots.len() > self.min_capacity
            && self.len < (self.slots.len() / 4)
            && self.tombstones < (self.slots.len() / 4)
        {
            self.resize(
                (self.slots.len() / 2).max(self.min_capacity),
                FlowResizeReason::Shrink,
            );
            return;
        }
        if self.tombstones > self.len && self.tombstones > (self.slots.len() / 5) {
            self.resize(self.slots.len(), FlowResizeReason::Rehash);
        }
    }

    fn resize(&mut self, requested: usize, reason: FlowResizeReason) {
        match reason {
            FlowResizeReason::Grow => {
                self.resize_counters.grow = self.resize_counters.grow.saturating_add(1);
            }
            FlowResizeReason::Shrink => {
                self.resize_counters.shrink = self.resize_counters.shrink.saturating_add(1);
            }
            FlowResizeReason::Rehash => {
                self.resize_counters.rehash = self.resize_counters.rehash.saturating_add(1);
            }
        }
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
                steps: 0,
            };
        }
        let mask = self.slots.len() - 1;
        let mut first_tombstone = None;
        let mut idx = self.initial_probe_index(key);
        for step in 0..self.slots.len() {
            match &self.slots[idx] {
                FlowSlot::Empty => {
                    return FlowProbe {
                        idx: first_tombstone.unwrap_or(idx),
                        slots_len: self.slots.len(),
                        kind: FlowProbeKind::Miss,
                        steps: step + 1,
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
                            steps: step + 1,
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
            steps: self.slots.len(),
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
    let src_ip = u32::from_be_bytes(key.src_ip.octets());
    let dst_ip = u32::from_be_bytes(key.dst_ip.octets());
    let ports = ((key.src_port as u32) << 16) | key.dst_port as u32;
    let seed = src_ip.wrapping_mul(0x9e37_79b1)
        ^ dst_ip.rotate_left(7).wrapping_mul(0x85eb_ca6b)
        ^ ports.rotate_left(13).wrapping_mul(0xc2b2_ae35)
        ^ (key.proto as u32).wrapping_mul(0x27d4_eb2d);
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

fn env_timeout_secs(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_table(
        idle_timeout_secs: u64,
        incomplete_tcp_idle_timeout_secs: u64,
        incomplete_tcp_syn_sent_idle_timeout_secs: u64,
    ) -> FlowTable {
        FlowTable {
            slots: empty_slots(FLOW_TABLE_MIN_CAPACITY),
            len: 0,
            tombstones: 0,
            min_capacity: FLOW_TABLE_MIN_CAPACITY,
            idle_timeout_secs,
            incomplete_tcp_idle_timeout_secs,
            incomplete_tcp_syn_sent_idle_timeout_secs,
            resize_counters: FlowResizeCounters::default(),
        }
    }

    fn tcp_flow() -> FlowKey {
        FlowKey {
            src_ip: Ipv4Addr::new(10, 0, 0, 2),
            dst_ip: Ipv4Addr::new(198, 51, 100, 10),
            src_port: 12345,
            dst_port: 443,
            proto: 6,
        }
    }

    #[test]
    fn evict_expired_uses_short_syn_timeout_for_syn_only_flows() {
        let mut table = test_table(300, 300, 3);
        let flow = tcp_flow();
        let mut entry = FlowEntry::new(1);
        entry.note_syn_outbound();
        table.insert(flow, entry);

        let expired = table.evict_expired(5);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].key, flow);
        assert!(table.is_empty());
    }

    #[test]
    fn evict_expired_keeps_synack_seen_flows_on_longer_incomplete_timeout() {
        let mut table = test_table(300, 300, 3);
        let flow = tcp_flow();
        let mut entry = FlowEntry::new(1);
        entry.note_syn_outbound();
        entry.note_synack_inbound();
        table.insert(flow, entry);

        let expired = table.evict_expired(5);
        assert!(expired.is_empty());
        assert_eq!(table.len(), 1);
        assert!(table.get_entry(&flow).is_some());
    }

    #[test]
    fn flow_entry_reports_tcp_handshake_phase() {
        let entry = FlowEntry::new(1);
        assert_eq!(entry.handshake_phase(), TcpHandshakePhase::Unknown);

        let mut entry = FlowEntry::new(1);
        entry.note_syn_outbound();
        assert_eq!(entry.handshake_phase(), TcpHandshakePhase::SynOnly);

        let mut entry = FlowEntry::new(1);
        entry.note_synack_inbound();
        assert_eq!(entry.handshake_phase(), TcpHandshakePhase::SynAckSeen);

        let mut entry = FlowEntry::new(1);
        entry.note_syn_outbound();
        entry.note_synack_inbound();
        entry.note_handshake_completed();
        assert_eq!(entry.handshake_phase(), TcpHandshakePhase::Completed);
    }

    #[test]
    fn syn_only_table_promote_preserves_flow_metadata() {
        let mut table = SynOnlyTable::new_with_timeout(3);
        let key = tcp_flow();
        let source_group = Some(Arc::<str>::from("engineering"));
        let result = table.upsert(key, 10, source_group.clone(), 7, true);
        assert_eq!(result, SynOnlyUpsertResult::Inserted);
        let promoted = table.promote(&key, 11).expect("entry should exist");
        assert_eq!(promoted.first_seen, 10);
        assert_eq!(promoted.last_seen, 11);
        assert_eq!(promoted.packets_out, 1);
        assert_eq!(promoted.source_group, source_group);
        assert_eq!(promoted.policy_generation, 7);
        assert!(promoted.intercept_requires_service);
        assert!(table.is_empty());
    }

    #[test]
    fn syn_only_table_evicts_expired_entries() {
        let mut table = SynOnlyTable::new_with_timeout(3);
        let key = tcp_flow();
        let _ = table.upsert(key, 10, None, 0, false);
        let evicted = table.evict_expired(14);
        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].key, key);
        assert!(table.is_empty());
    }

    #[test]
    fn flow_table_does_not_shrink_below_initial_capacity() {
        let mut table = FlowTable {
            slots: empty_slots(8),
            len: 0,
            tombstones: 0,
            min_capacity: 8,
            idle_timeout_secs: 300,
            incomplete_tcp_idle_timeout_secs: 300,
            incomplete_tcp_syn_sent_idle_timeout_secs: 3,
            resize_counters: FlowResizeCounters::default(),
        };
        let flow = tcp_flow();
        table.insert(flow, FlowEntry::new(1));
        assert_eq!(table.capacity(), 8);
        let _ = table.remove(&flow);
        assert_eq!(table.capacity(), 8);
    }
}
