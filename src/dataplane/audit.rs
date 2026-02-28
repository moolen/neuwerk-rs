use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc;

pub const DEFAULT_AUDIT_REPORT_INTERVAL_SECS: u64 = 1;
static AUDIT_SEND_FAIL_LOGS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    L4Deny,
    TlsDeny,
    IcmpDeny,
}

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub event_type: AuditEventType,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub source_group: String,
    pub sni: Option<String>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub observed_at: u64,
}

#[derive(Debug, Clone)]
pub struct AuditEmitter {
    sender: mpsc::Sender<AuditEvent>,
    report_interval_secs: u64,
}

impl AuditEmitter {
    pub fn new(sender: mpsc::Sender<AuditEvent>, report_interval_secs: u64) -> Self {
        Self {
            sender,
            report_interval_secs: report_interval_secs.max(1),
        }
    }

    pub fn report_interval_secs(&self) -> u64 {
        self.report_interval_secs
    }

    pub fn try_send(&self, event: AuditEvent) {
        if let Err(err) = self.sender.try_send(event) {
            if AUDIT_SEND_FAIL_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                eprintln!("audit: failed to enqueue event: {err}");
            }
        }
    }
}
