use std::net::Ipv4Addr;

use crate::controlplane::Allowlist;

pub fn is_allowed(allowlist: &Allowlist, dst: Ipv4Addr) -> bool {
    allowlist.contains_v4(dst)
}
