use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use crate::controlplane::Allowlist;
use crate::dataplane::flow::{FlowKey, FlowTable};
use crate::dataplane::nat::{NatTable, ReverseKey};
use crate::dataplane::packet::Packet;
use crate::dataplane::policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Drop,
    Forward { out_port: u16 },
    ToHost,
}

#[derive(Debug)]
pub struct EngineState {
    pub flows: FlowTable,
    pub nat: NatTable,
    pub allowlist: Arc<RwLock<Allowlist>>,
    pub internal_net: Ipv4Addr,
    pub internal_prefix: u8,
    pub public_ip: Ipv4Addr,
    pub data_port: u16,
}

impl EngineState {
    pub fn new(
        allowlist: Arc<RwLock<Allowlist>>,
        internal_net: Ipv4Addr,
        internal_prefix: u8,
        public_ip: Ipv4Addr,
        data_port: u16,
    ) -> Self {
        Self {
            flows: FlowTable::new(),
            nat: NatTable::new(),
            allowlist,
            internal_net,
            internal_prefix,
            public_ip,
            data_port,
        }
    }

    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        let prefix = self.internal_prefix.min(32);
        if prefix == 0 {
            return true;
        }
        let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
        let net = u32::from(self.internal_net) & mask;
        let addr = u32::from(ip) & mask;
        net == addr
    }
}

pub fn handle_packet(pkt: &mut Packet, state: &mut EngineState) -> Action {
    let src_ip = match pkt.src_ip() {
        Some(ip) => ip,
        None => return Action::Drop,
    };
    let dst_ip = match pkt.dst_ip() {
        Some(ip) => ip,
        None => return Action::Drop,
    };
    let proto = match pkt.protocol() {
        Some(p) => p,
        None => return Action::Drop,
    };
    let (src_port, dst_port) = match pkt.ports() {
        Some(ports) => ports,
        None => return Action::Drop,
    };

    if state.is_internal(src_ip) && !state.is_internal(dst_ip) {
        let allowed = match state.allowlist.read() {
            Ok(lock) => policy::is_allowed(&lock, dst_ip),
            Err(_) => false,
        };
        if !allowed {
            return Action::Drop;
        }

        let flow = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
        };
        let external_port = state.nat.get_or_create(&flow);

        if !pkt.set_src_ip(state.public_ip) {
            return Action::Drop;
        }
        if !pkt.set_src_port(external_port) {
            return Action::Drop;
        }
        if !pkt.recalc_checksums() {
            return Action::Drop;
        }

        state.flows.insert(flow);
        return Action::Forward {
            out_port: state.data_port,
        };
    }

    if dst_ip == state.public_ip {
        let reverse_key = ReverseKey {
            external_port: dst_port,
            remote_ip: src_ip,
            remote_port: src_port,
            proto,
        };
        if let Some(flow) = state.nat.reverse_lookup(&reverse_key) {
            if !pkt.set_dst_ip(flow.src_ip) {
                return Action::Drop;
            }
            if !pkt.set_dst_port(flow.src_port) {
                return Action::Drop;
            }
            if !pkt.recalc_checksums() {
                return Action::Drop;
            }
            return Action::Forward {
                out_port: state.data_port,
            };
        }
        return Action::Drop;
    }

    Action::Drop
}
