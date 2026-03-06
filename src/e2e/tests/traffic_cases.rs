use super::*;

mod cluster_policy;
mod icmp_cases;
mod misc_cases;
mod nat_cases;
mod ttl_fragment_cases;

pub(super) fn cluster_policy_update_applies(cfg: &TopologyConfig) -> Result<(), String> {
    cluster_policy::cluster_policy_update_applies(cfg)
}

pub(super) fn cluster_policy_update_denies_existing_flow(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    cluster_policy::cluster_policy_update_denies_existing_flow(cfg)
}

pub(super) fn cluster_policy_update_https_udp(cfg: &TopologyConfig) -> Result<(), String> {
    cluster_policy::cluster_policy_update_https_udp(cfg)
}

pub(super) fn cluster_policy_update_churn(cfg: &TopologyConfig) -> Result<(), String> {
    cluster_policy::cluster_policy_update_churn(cfg)
}

pub(super) fn icmp_echo_allowed(cfg: &TopologyConfig) -> Result<(), String> {
    icmp_cases::icmp_echo_allowed(cfg)
}

pub(super) fn icmp_type_filtering(cfg: &TopologyConfig) -> Result<(), String> {
    icmp_cases::icmp_type_filtering(cfg)
}

pub(super) fn icmp_ttl_exceeded(cfg: &TopologyConfig) -> Result<(), String> {
    ttl_fragment_cases::icmp_ttl_exceeded(cfg)
}

pub(super) fn udp_ttl_decremented(cfg: &TopologyConfig) -> Result<(), String> {
    ttl_fragment_cases::udp_ttl_decremented(cfg)
}

pub(super) fn ipv4_fragment_drop_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    ttl_fragment_cases::ipv4_fragment_drop_metrics(cfg)
}

pub(super) fn ipv4_fragment_not_forwarded(cfg: &TopologyConfig) -> Result<(), String> {
    ttl_fragment_cases::ipv4_fragment_not_forwarded(cfg)
}

pub(super) fn nat_idle_eviction_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    nat_cases::nat_idle_eviction_metrics(cfg)
}

pub(super) fn nat_port_deterministic(cfg: &TopologyConfig) -> Result<(), String> {
    nat_cases::nat_port_deterministic(cfg)
}

pub(super) fn nat_port_collision_isolation(cfg: &TopologyConfig) -> Result<(), String> {
    nat_cases::nat_port_collision_isolation(cfg)
}

pub(super) fn nat_stream_payload_integrity(cfg: &TopologyConfig) -> Result<(), String> {
    nat_cases::nat_stream_payload_integrity(cfg)
}

pub(super) fn snat_override_applied(cfg: &TopologyConfig) -> Result<(), String> {
    nat_cases::snat_override_applied(cfg)
}

pub(super) fn mgmt_api_unreachable_from_dataplane(cfg: &TopologyConfig) -> Result<(), String> {
    misc_cases::mgmt_api_unreachable_from_dataplane(cfg)
}

pub(super) fn service_lane_svc0_present(cfg: &TopologyConfig) -> Result<(), String> {
    misc_cases::service_lane_svc0_present(cfg)
}
