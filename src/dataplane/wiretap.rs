use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use crate::dataplane::flow::FlowKey;

pub const DEFAULT_WIRETAP_REPORT_INTERVAL_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WiretapEventType {
    Flow,
    FlowEnd,
}

#[derive(Debug, Clone)]
pub struct WiretapEvent {
    pub event_type: WiretapEventType,
    pub flow_id: String,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub packets_in: u64,
    pub packets_out: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone)]
pub struct WiretapEmitter {
    sender: mpsc::Sender<WiretapEvent>,
    report_interval_secs: u64,
}

impl WiretapEmitter {
    pub fn new(sender: mpsc::Sender<WiretapEvent>, report_interval_secs: u64) -> Self {
        Self {
            sender,
            report_interval_secs: report_interval_secs.max(1),
        }
    }

    pub fn report_interval_secs(&self) -> u64 {
        self.report_interval_secs
    }

    pub fn try_send(&self, event: WiretapEvent) {
        let _ = self.sender.try_send(event);
    }
}

pub fn flow_id_from_key(key: &FlowKey) -> String {
    format!(
        "{}:{}-{}:{}-{}",
        key.src_ip, key.src_port, key.dst_ip, key.dst_port, key.proto
    )
}
