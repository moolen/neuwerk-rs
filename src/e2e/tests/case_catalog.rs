use super::*;

pub fn cases() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "api_bootstrap_tls_material",
            func: api_bootstrap_tls_material,
        },
        TestCase {
            name: "api_tls_san_allows_alt_ip",
            func: api_tls_san_allows_alt_ip,
        },
        TestCase {
            name: "api_health_ok",
            func: api_health_ok,
        },
        TestCase {
            name: "api_auth_required",
            func: api_auth_required,
        },
        TestCase {
            name: "api_auth_token_login_whoami",
            func: api_auth_token_login_whoami,
        },
        TestCase {
            name: "api_auth_cookie_login_whoami",
            func: api_auth_cookie_login_whoami,
        },
        TestCase {
            name: "api_auth_rejects_expired",
            func: api_auth_rejects_expired,
        },
        TestCase {
            name: "api_auth_token_login_rate_limit_scoped",
            func: api_auth_token_login_rate_limit_scoped,
        },
        TestCase {
            name: "api_auth_rotation_keeps_old_tokens",
            func: api_auth_rotation_keeps_old_tokens,
        },
        TestCase {
            name: "api_auth_retire_revokes_old_kid",
            func: api_auth_retire_revokes_old_kid,
        },
        TestCase {
            name: "api_service_accounts_lifecycle",
            func: api_service_accounts_lifecycle,
        },
        TestCase {
            name: "dpdk_dhcp_l2_hairpin",
            func: dpdk_dhcp_l2_hairpin,
        },
        TestCase {
            name: "dpdk_dhcp_retries_exhausted",
            func: dpdk_dhcp_retries_exhausted,
        },
        TestCase {
            name: "dpdk_dhcp_renewal_updates_config",
            func: dpdk_dhcp_renewal_updates_config,
        },
        TestCase {
            name: "dpdk_tls_intercept_service_lane_round_trip",
            func: dpdk_tls_intercept_service_lane_round_trip,
        },
        TestCase {
            name: "api_audit_policy_listed",
            func: api_audit_policy_listed,
        },
        TestCase {
            name: "api_audit_passthrough_overrides_deny",
            func: api_audit_passthrough_overrides_deny,
        },
        TestCase {
            name: "api_audit_findings_dns_passthrough_records_event",
            func: api_audit_findings_dns_passthrough_records_event,
        },
        TestCase {
            name: "api_audit_findings_l4_passthrough_records_event",
            func: api_audit_findings_l4_passthrough_records_event,
        },
        TestCase {
            name: "api_audit_findings_tls_passthrough_captures_sni",
            func: api_audit_findings_tls_passthrough_captures_sni,
        },
        TestCase {
            name: "api_audit_findings_icmp_passthrough_records_type_code",
            func: api_audit_findings_icmp_passthrough_records_type_code,
        },
        TestCase {
            name: "api_audit_findings_policy_id_filter_isolates_rotated_policies",
            func: api_audit_findings_policy_id_filter_isolates_rotated_policies,
        },
        TestCase {
            name: "api_policy_persisted_local",
            func: api_policy_persisted_local,
        },
        TestCase {
            name: "api_policy_active_semantics",
            func: api_policy_active_semantics,
        },
        TestCase {
            name: "api_policy_get_update_delete",
            func: api_policy_get_update_delete,
        },
        TestCase {
            name: "api_policy_list_ordering",
            func: api_policy_list_ordering,
        },
        TestCase {
            name: "api_policy_scale_last_rule_effective",
            func: api_policy_scale_last_rule_effective,
        },
        TestCase {
            name: "api_dns_cache_grouped",
            func: api_dns_cache_grouped,
        },
        TestCase {
            name: "api_stats_snapshot",
            func: api_stats_snapshot,
        },
        TestCase {
            name: "api_metrics_exposed",
            func: api_metrics_exposed,
        },
        TestCase {
            name: "api_body_limit_rejects_large",
            func: api_body_limit_rejects_large,
        },
        TestCase {
            name: "api_metrics_unauthenticated",
            func: api_metrics_unauthenticated,
        },
        TestCase {
            name: "api_metrics_integrity",
            func: api_metrics_integrity,
        },
        TestCase {
            name: "api_metrics_dns_dataplane",
            func: api_metrics_dns_dataplane,
        },
        TestCase {
            name: "api_tls_key_permissions",
            func: api_tls_key_permissions,
        },
        TestCase {
            name: "icmp_echo_allowed",
            func: icmp_echo_allowed,
        },
        TestCase {
            name: "icmp_type_filtering",
            func: icmp_type_filtering,
        },
        TestCase {
            name: "icmp_ttl_exceeded",
            func: icmp_ttl_exceeded,
        },
        TestCase {
            name: "udp_ttl_decremented",
            func: udp_ttl_decremented,
        },
        TestCase {
            name: "ipv4_fragment_drop_metrics",
            func: ipv4_fragment_drop_metrics,
        },
        TestCase {
            name: "ipv4_fragment_not_forwarded",
            func: ipv4_fragment_not_forwarded,
        },
        TestCase {
            name: "nat_idle_eviction_metrics",
            func: nat_idle_eviction_metrics,
        },
        TestCase {
            name: "nat_port_deterministic",
            func: nat_port_deterministic,
        },
        TestCase {
            name: "nat_port_collision_isolation",
            func: nat_port_collision_isolation,
        },
        TestCase {
            name: "nat_stream_payload_integrity",
            func: nat_stream_payload_integrity,
        },
        TestCase {
            name: "snat_override_applied",
            func: snat_override_applied,
        },
        TestCase {
            name: "mgmt_api_unreachable_from_dataplane",
            func: mgmt_api_unreachable_from_dataplane,
        },
        TestCase {
            name: "service_lane_svc0_present",
            func: service_lane_svc0_present,
        },
        TestCase {
            name: "cluster_policy_update_applies",
            func: cluster_policy_update_applies,
        },
        TestCase {
            name: "cluster_policy_update_denies_existing_flow",
            func: cluster_policy_update_denies_existing_flow,
        },
        TestCase {
            name: "cluster_policy_update_https_udp",
            func: cluster_policy_update_https_udp,
        },
        TestCase {
            name: "cluster_policy_update_churn",
            func: cluster_policy_update_churn,
        },
        TestCase {
            name: "http_denied_without_dns",
            func: http_denied_without_dns,
        },
        TestCase {
            name: "udp_denied_without_dns",
            func: udp_denied_without_dns,
        },
        TestCase {
            name: "https_denied_without_dns",
            func: https_denied_without_dns,
        },
        TestCase {
            name: "tls_sni_allows_https",
            func: tls_sni_allows_https,
        },
        TestCase {
            name: "tls_sni_allows_https_tls13",
            func: tls_sni_allows_https_tls13,
        },
        TestCase {
            name: "tls_sni_denies_https",
            func: tls_sni_denies_https,
        },
        TestCase {
            name: "tls_cert_tls12_allows",
            func: tls_cert_tls12_allows,
        },
        TestCase {
            name: "tls_cert_tls12_denies_san_mismatch",
            func: tls_cert_tls12_denies_san_mismatch,
        },
        TestCase {
            name: "tls_cert_tls13_denied",
            func: tls_cert_tls13_denied,
        },
        TestCase {
            name: "tls_cert_tls13_allows",
            func: tls_cert_tls13_allows,
        },
        TestCase {
            name: "tls_reassembly_client_hello",
            func: tls_reassembly_client_hello,
        },
        TestCase {
            name: "tls_intercept_http_allow",
            func: tls_intercept_http_allow,
        },
        TestCase {
            name: "tls_intercept_http_deny_rst",
            func: tls_intercept_http_deny_rst,
        },
        TestCase {
            name: "tls_intercept_response_header_deny_rst",
            func: tls_intercept_response_header_deny_rst,
        },
        TestCase {
            name: "tls_intercept_h2_allow",
            func: tls_intercept_h2_allow,
        },
        TestCase {
            name: "tls_intercept_h2_concurrency_smoke",
            func: tls_intercept_h2_concurrency_smoke,
        },
        TestCase {
            name: "tls_intercept_ca_rotation_reloads_runtime",
            func: tls_intercept_ca_rotation_reloads_runtime,
        },
        TestCase {
            name: "tls_intercept_h2_deny_fail_closed",
            func: tls_intercept_h2_deny_fail_closed,
        },
        TestCase {
            name: "tls_intercept_service_metrics",
            func: tls_intercept_service_metrics,
        },
        TestCase {
            name: "dns_allows_http",
            func: dns_allows_http,
        },
        TestCase {
            name: "dns_allows_udp",
            func: dns_allows_udp,
        },
        TestCase {
            name: "dns_allows_https",
            func: dns_allows_https,
        },
        TestCase {
            name: "dns_tcp_allows_https",
            func: dns_tcp_allows_https,
        },
        TestCase {
            name: "dns_tcp_blocks_nonmatch",
            func: dns_tcp_blocks_nonmatch,
        },
        TestCase {
            name: "dns_regex_allows_example",
            func: dns_regex_allows_example,
        },
        TestCase {
            name: "dns_regex_blocks_nonmatch",
            func: dns_regex_blocks_nonmatch,
        },
        TestCase {
            name: "dns_source_group_allows_secondary",
            func: dns_source_group_allows_secondary,
        },
        TestCase {
            name: "dns_source_group_blocks_secondary",
            func: dns_source_group_blocks_secondary,
        },
        TestCase {
            name: "dns_case_insensitive_match",
            func: dns_case_insensitive_match,
        },
        TestCase {
            name: "dns_upstream_failover_allows_secondary",
            func: dns_upstream_failover_allows_secondary,
        },
        TestCase {
            name: "dns_upstream_mismatch_nxdomain",
            func: dns_upstream_mismatch_nxdomain,
        },
        TestCase {
            name: "dns_long_name_match",
            func: dns_long_name_match,
        },
        TestCase {
            name: "dns_wildcard_allows_allowed_suffix",
            func: dns_wildcard_allows_allowed_suffix,
        },
        TestCase {
            name: "dns_deny_overrides_wildcard",
            func: dns_deny_overrides_wildcard,
        },
        TestCase {
            name: "udp_multi_flow",
            func: udp_multi_flow,
        },
        TestCase {
            name: "udp_reverse_nat_multi_flow",
            func: udp_reverse_nat_multi_flow,
        },
        TestCase {
            name: "tcp_reverse_nat_multi_flow",
            func: tcp_reverse_nat_multi_flow,
        },
        TestCase {
            name: "https_reverse_nat_multi_flow",
            func: https_reverse_nat_multi_flow,
        },
        TestCase {
            name: "stream_keeps_nat_alive",
            func: stream_keeps_nat_alive,
        },
        TestCase {
            name: "dns_allowlist_gc_evicts_idle",
            func: dns_allowlist_gc_evicts_idle,
        },
        TestCase {
            name: "dns_allowlist_gc_keeps_active_flow",
            func: dns_allowlist_gc_keeps_active_flow,
        },
    ]
}
