use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default)]
pub struct Allowlist {
    v4: HashSet<Ipv4Addr>,
    v6: HashSet<Ipv6Addr>,
}

impl Allowlist {
    pub fn new() -> Self {
        Self {
            v4: HashSet::new(),
            v6: HashSet::new(),
        }
    }

    pub fn add_ip(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                self.v4.insert(v4);
            }
            IpAddr::V6(v6) => {
                self.v6.insert(v6);
            }
        }
    }

    pub fn add_v4(&mut self, ip: Ipv4Addr) {
        self.v4.insert(ip);
    }

    pub fn add_v6(&mut self, ip: Ipv6Addr) {
        self.v6.insert(ip);
    }

    pub fn contains_v4(&self, ip: Ipv4Addr) -> bool {
        self.v4.contains(&ip)
    }

    pub fn contains_v6(&self, ip: Ipv6Addr) -> bool {
        self.v6.contains(&ip)
    }
}
