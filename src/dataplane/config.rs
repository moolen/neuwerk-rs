use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataplaneConfig {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Ipv4Addr,
    pub mac: [u8; 6],
    pub lease_expiry: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct DataplaneConfigStore {
    inner: Arc<RwLock<Option<DataplaneConfig>>>,
}

impl DataplaneConfigStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self) -> Option<DataplaneConfig> {
        match self.inner.read() {
            Ok(lock) => *lock,
            Err(_) => None,
        }
    }

    pub fn set(&self, cfg: DataplaneConfig) {
        if let Ok(mut lock) = self.inner.write() {
            *lock = Some(cfg);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut lock) = self.inner.write() {
            *lock = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_round_trip() {
        let store = DataplaneConfigStore::new();
        assert!(store.get().is_none());

        let cfg = DataplaneConfig {
            ip: Ipv4Addr::new(10, 0, 0, 2),
            prefix: 24,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            lease_expiry: Some(123),
        };
        store.set(cfg);
        assert_eq!(store.get(), Some(cfg));

        store.clear();
        assert!(store.get().is_none());
    }
}
