use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

#[derive(Clone, Debug, Default)]
pub struct DrainControl {
    draining: Arc<AtomicBool>,
}

impl DrainControl {
    pub fn new() -> Self {
        Self {
            draining: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn set_draining(&self, draining: bool) {
        self.draining.store(draining, Ordering::Relaxed);
    }

    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }
}
