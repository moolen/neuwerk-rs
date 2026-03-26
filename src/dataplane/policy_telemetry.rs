use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc;
use tracing::warn;

static POLICY_TELEMETRY_SEND_FAIL_LOGS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone)]
pub struct PolicyTelemetryEvent {
    pub source_group: String,
    pub observed_at: u64,
}

#[derive(Debug, Clone)]
pub struct PolicyTelemetryEmitter {
    sender: mpsc::Sender<PolicyTelemetryEvent>,
}

impl PolicyTelemetryEmitter {
    pub fn new(sender: mpsc::Sender<PolicyTelemetryEvent>) -> Self {
        Self { sender }
    }

    pub fn try_send(&self, event: PolicyTelemetryEvent) {
        if let Err(err) = self.sender.try_send(event) {
            if POLICY_TELEMETRY_SEND_FAIL_LOGS.fetch_add(1, Ordering::Relaxed) < 20 {
                warn!(error = %err, "policy telemetry event enqueue failed");
            }
        }
    }
}
