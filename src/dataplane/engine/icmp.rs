use super::*;

pub(super) fn icmp_is_error_type(icmp_type: u8) -> bool {
    matches!(icmp_type, 3 | 4 | 5 | 11 | 12)
}

include!("icmp/outbound.rs");
include!("icmp/inbound.rs");
