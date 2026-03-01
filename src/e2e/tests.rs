use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::controlplane::api_auth;
use crate::controlplane::audit::{AuditFinding, AuditFindingType, AuditQueryResponse};
use crate::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use crate::controlplane::policy_config::{DnsPolicy, PolicyConfig, PolicyMode, PolicyValue};
use crate::controlplane::policy_repository::{PolicyActive, PolicyRecord};
use crate::controlplane::service_accounts::{ServiceAccountStatus, TokenStatus};
use crate::controlplane::PolicyStore;
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, PolicySnapshot, PortRange, Proto, Rule, RuleAction, RuleMatch,
    RuleMode, SourceGroup, Tls13Uninspectable, TlsMatch, TlsMode,
};
use crate::dataplane::{
    DataplaneConfig, DpdkAdapter, EngineState, SharedArpState, SharedInterceptDemuxState,
};
use crate::e2e::services::{
    dns_query, dns_query_response, dns_query_response_tcp, http_api_client_with_cookie,
    http_api_health, http_api_post_raw, http_api_status, http_auth_token_login, http_auth_whoami,
    http_create_service_account, http_create_service_account_token, http_delete_policy,
    http_delete_service_account, http_get, http_get_audit_findings, http_get_dns_cache,
    http_get_path, http_get_policy, http_get_stats, http_list_policies,
    http_list_service_account_tokens, http_list_service_accounts,
    http_put_tls_intercept_ca_from_http_ca, http_revoke_service_account_token, http_set_policy,
    http_stream, http_stream_path, http_update_policy, http_wait_for_health, https_get,
    https_get_path, https_get_tls12, https_get_tls13, https_h2_get_path, https_leaf_cert_sha256,
    tls_client_hello_raw, udp_echo,
};
use crate::e2e::topology::TopologyConfig;
use ::time::format_description::well_known::Rfc3339;
use ::time::Duration as TimeDuration;
use ::time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{mpsc, watch};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;
use x509_parser::pem::parse_x509_pem;

pub struct TestCase {
    pub name: &'static str,
    pub func: fn(&TopologyConfig) -> Result<(), String>,
}

fn api_auth_token(cfg: &TopologyConfig) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let store = match ClusterStore::open_read_only(cfg.cluster_data_dir.join("raft")) {
            Ok(store) => store,
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(format!("open cluster store failed: {err}"));
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        match api_auth::load_keyset_from_store(&store)? {
            Some(keyset) => {
                let token = api_auth::mint_token(&keyset, "e2e", None, None)?;
                return Ok(token.token);
            }
            None => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for api auth keyset".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn api_auth_token_expired(cfg: &TopologyConfig) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let store = match ClusterStore::open_read_only(cfg.cluster_data_dir.join("raft")) {
            Ok(store) => store,
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(format!("open cluster store failed: {err}"));
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        match api_auth::load_keyset_from_store(&store)? {
            Some(keyset) => {
                let token = api_auth::mint_token_at(
                    &keyset,
                    "e2e-expired",
                    Some(60),
                    None,
                    OffsetDateTime::now_utc() - TimeDuration::hours(1),
                )?;
                return Ok(token.token);
            }
            None => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for api auth keyset".to_string());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

async fn auth_client(cfg: &TopologyConfig) -> Result<AuthClient, String> {
    let tls_dir = cfg.cluster_data_dir.join("tls");
    let tls = RaftTlsConfig::load(tls_dir)?;
    let addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.cluster_bind_port);
    AuthClient::connect(addr, tls).await
}

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

pub fn overlay_cases_vxlan() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "overlay_vxlan_round_trip",
            func: overlay_vxlan_round_trip,
        },
        TestCase {
            name: "overlay_vxlan_wrong_vni_drop",
            func: overlay_vxlan_wrong_vni_drop,
        },
        TestCase {
            name: "overlay_vxlan_wrong_port_drop",
            func: overlay_vxlan_wrong_port_drop,
        },
        TestCase {
            name: "overlay_vxlan_mtu_drop",
            func: overlay_vxlan_mtu_drop,
        },
    ]
}

pub fn overlay_cases_geneve() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "overlay_geneve_round_trip",
            func: overlay_geneve_round_trip,
        },
        TestCase {
            name: "overlay_geneve_wrong_vni_drop",
            func: overlay_geneve_wrong_vni_drop,
        },
        TestCase {
            name: "overlay_geneve_wrong_port_drop",
            func: overlay_geneve_wrong_port_drop,
        },
        TestCase {
            name: "overlay_geneve_mtu_drop",
            func: overlay_geneve_mtu_drop,
        },
    ]
}

fn api_health_ok(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async { http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await })
}

fn api_auth_required(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let health = http_api_status(api_addr, &tls_dir, "/health", None).await?;
        if !health.is_success() {
            return Err(format!("unexpected health status: {health}"));
        }
        let policies = http_api_status(api_addr, &tls_dir, "/api/v1/policies", None).await?;
        if policies != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized, got {policies}"));
        }
        let _ = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        Ok(())
    })
}

fn api_auth_token_login_whoami(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let login = http_auth_token_login(api_addr, &tls_dir, &token).await?;
        if login.sub != "e2e" {
            return Err(format!("unexpected token-login sub {}", login.sub));
        }
        let whoami = http_auth_whoami(api_addr, &tls_dir, &token).await?;
        if whoami.sub != "e2e" {
            return Err(format!("unexpected whoami sub {}", whoami.sub));
        }
        Ok(())
    })
}

fn api_auth_cookie_login_whoami(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let client = http_api_client_with_cookie(&tls_dir)?;
        let resp = client
            .post(format!("https://{api_addr}/api/v1/auth/token-login"))
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .map_err(|e| format!("auth token-login failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("auth token-login status {}", resp.status()));
        }
        let cookie = resp
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .ok_or_else(|| "missing auth cookie".to_string())?
            .to_string();
        let user = resp
            .json::<crate::e2e::services::AuthUser>()
            .await
            .map_err(|e| format!("auth token-login decode failed: {e}"))?;
        if user.sub != "e2e" {
            return Err(format!("unexpected token-login sub {}", user.sub));
        }
        let whoami = client
            .get(format!("https://{api_addr}/api/v1/auth/whoami"))
            .header(reqwest::header::COOKIE, cookie)
            .send()
            .await
            .map_err(|e| format!("auth whoami failed: {e}"))?;
        if !whoami.status().is_success() {
            return Err(format!("auth whoami status {}", whoami.status()));
        }
        let who = whoami
            .json::<crate::e2e::services::AuthUser>()
            .await
            .map_err(|e| format!("auth whoami decode failed: {e}"))?;
        if who.sub != "e2e" {
            return Err(format!("unexpected whoami sub {}", who.sub));
        }
        Ok(())
    })
}

fn api_auth_rejects_expired(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let expired = api_auth_token_expired(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&expired)).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized, got {status}"));
        }
        Ok(())
    })
}

fn api_auth_rotation_keeps_old_tokens(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let mut client = auth_client(cfg).await?;
        let (active_kid, _) = client.list_keys().await?;
        let (old_token, _, _) = client
            .mint_token("e2e-rotate-old", None, Some(&active_kid))
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("expected ok before rotation, got {status}"));
        }

        let _ = client.rotate_key().await?;

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("old token rejected after rotation: {status}"));
        }

        let (new_token, _, _) = client.mint_token("e2e-rotate-new", None, None).await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&new_token)).await?;
        if !status.is_success() {
            return Err(format!("new token rejected after rotation: {status}"));
        }
        Ok(())
    })
}

fn api_auth_retire_revokes_old_kid(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let mut client = auth_client(cfg).await?;

        let mut target_kid = None;
        let mut keys = client.list_keys().await?.1;
        if keys.len() < 2 {
            let _ = client.rotate_key().await?;
            keys = client.list_keys().await?.1;
        }
        for key in keys.iter() {
            if !key.signing && key.status == api_auth::ApiKeyStatus::Active {
                target_kid = Some(key.kid.clone());
                break;
            }
        }
        if target_kid.is_none() {
            let _ = client.rotate_key().await?;
            let keys = client.list_keys().await?.1;
            for key in keys.iter() {
                if !key.signing && key.status == api_auth::ApiKeyStatus::Active {
                    target_kid = Some(key.kid.clone());
                    break;
                }
            }
        }
        let target_kid =
            target_kid.ok_or_else(|| "no non-active key available to retire".to_string())?;

        let (old_token, _, _) = client
            .mint_token("e2e-retire-old", None, Some(&target_kid))
            .await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if !status.is_success() {
            return Err(format!("expected ok before retire, got {status}"));
        }

        client.retire_key(&target_kid).await?;

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&old_token)).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized after retire, got {status}"));
        }

        let (new_token, _, _) = client.mint_token("e2e-retire-new", None, None).await?;
        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&new_token)).await?;
        if !status.is_success() {
            return Err(format!("new token rejected after retire: {status}"));
        }
        Ok(())
    })
}

fn api_service_accounts_lifecycle(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let admin_token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;

        let account = http_create_service_account(
            api_addr,
            &tls_dir,
            "e2e-sa",
            Some("e2e service account"),
            Some(&admin_token),
        )
        .await?;
        if account.status != ServiceAccountStatus::Active {
            return Err(format!("expected active account, got {:?}", account.status));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let accounts =
                http_list_service_accounts(api_addr, &tls_dir, Some(&admin_token)).await?;
            if accounts.iter().any(|item| item.id == account.id) {
                break;
            }
            if Instant::now() >= deadline {
                return Err("service account not visible in list".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let token_resp = http_create_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some("primary"),
            Some("1h"),
            None,
            Some(&admin_token),
        )
        .await?;
        if token_resp.token_meta.service_account_id != account.id {
            return Err("token meta service account id mismatch".to_string());
        }
        if token_resp.token_meta.status != TokenStatus::Active {
            return Err(format!(
                "expected active token, got {:?}",
                token_resp.token_meta.status
            ));
        }
        if token_resp.token_meta.expires_at.is_none() {
            return Err("expected ttl token to include expires_at".to_string());
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&token_resp.token),
        )
        .await?;
        if !status.is_success() {
            return Err(format!("service account token rejected: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if tokens
                .iter()
                .any(|item| item.id == token_resp.token_meta.id)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err("token not visible in list".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_revoke_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            &token_resp.token_meta.id.to_string(),
            Some(&admin_token),
        )
        .await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected revoke status: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if let Some(token) = tokens
                .iter()
                .find(|item| item.id == token_resp.token_meta.id)
            {
                if token.status == TokenStatus::Revoked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("token was not revoked".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&token_resp.token),
        )
        .await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized after revoke, got {status}"));
        }

        let eternal_resp = http_create_service_account_token(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some("eternal"),
            None,
            Some(true),
            Some(&admin_token),
        )
        .await?;
        if eternal_resp.token_meta.expires_at.is_some() {
            return Err("expected eternal token to omit expires_at".to_string());
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&eternal_resp.token),
        )
        .await?;
        if !status.is_success() {
            return Err(format!("eternal token rejected: {status}"));
        }

        let status = http_delete_service_account(
            api_addr,
            &tls_dir,
            &account.id.to_string(),
            Some(&admin_token),
        )
        .await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected delete status: {status}"));
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let accounts =
                http_list_service_accounts(api_addr, &tls_dir, Some(&admin_token)).await?;
            if let Some(item) = accounts.iter().find(|item| item.id == account.id) {
                if item.status == ServiceAccountStatus::Disabled {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("service account not marked disabled".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let tokens = http_list_service_account_tokens(
                api_addr,
                &tls_dir,
                &account.id.to_string(),
                Some(&admin_token),
            )
            .await?;
            if let Some(token) = tokens
                .iter()
                .find(|item| item.id == eternal_resp.token_meta.id)
            {
                if token.status == TokenStatus::Revoked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("eternal token not revoked after account delete".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            Some(&eternal_resp.token),
        )
        .await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!(
                "expected unauthorized after account delete, got {status}"
            ));
        }

        Ok(())
    })
}

fn dpdk_dhcp_l2_hairpin(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::UNSPECIFIED,
            32,
            dataplane_config.clone(),
        );

        let mut dst_ips = IpSetV4::new();
        let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
        dst_ips.add_ip(upstream_ip);

        let rule = Rule {
            id: "allow-upstream".to_string(),
            priority: 0,
            matcher: RuleMatch {
                dst_ips: Some(dst_ips),
                proto: Proto::Any,
                src_ports: Vec::new(),
                dst_ports: Vec::new(),
                icmp_types: Vec::new(),
                icmp_codes: Vec::new(),
                tls: None,
            },
            action: RuleAction::Allow,
            mode: crate::dataplane::policy::RuleMode::Enforce,
        };

        let mut sources = IpSetV4::new();
        sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));

        let group = SourceGroup {
            id: "internal".to_string(),
            priority: 0,
            sources,
            rules: vec![rule],
            default_action: None,
        };

        policy_store
            .rebuild(
                vec![group],
                DnsPolicy::new(Vec::new()),
                Some(DefaultPolicy::Deny),
                crate::dataplane::policy::EnforcementMode::Enforce,
            )
            .map_err(|e| format!("{e}"))?;

        let policy = policy_store.snapshot();
        let mut state = EngineState::new_with_idle_timeout(
            policy,
            Ipv4Addr::UNSPECIFIED,
            32,
            Ipv4Addr::UNSPECIFIED,
            0,
            120,
        );
        state.set_dataplane_config(dataplane_config.clone());

        let (dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(32);
        let (cp_to_dp_tx, cp_to_dp_rx) = mpsc::channel(32);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(200),
                retry_max: 5,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: dataplane_config.clone(),
            policy_store: policy_store.clone(),
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });

        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        let lease_ip = Ipv4Addr::new(10, 0, 0, 1);
        let _ = mac_tx.send(fw_mac);

        let mut adapter = DpdkAdapter::new("dpdk-test".to_string())?;
        adapter.set_mac(fw_mac);
        adapter.set_dhcp_channels(dp_to_cp_tx, cp_to_dp_rx);

        let mut dhcp = DhcpTestServer::new(server_ip, server_mac, lease_ip, 120);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(cfg) = dataplane_config.get() {
                if cfg.ip == lease_ip {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("dhcp lease not applied".to_string());
            }
            while let Some(frame) = adapter.next_dhcp_frame(&state) {
                if let Some(resp) = dhcp.handle_client_frame(&frame) {
                    let _ = adapter.process_frame(&resp, &mut state);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let client_mac = [0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
        let client_ip = Ipv4Addr::new(10, 0, 0, 42);
        let arp_req = build_arp_request(client_mac, client_ip, lease_ip);
        let arp_reply = adapter
            .process_frame(&arp_req, &mut state)
            .ok_or_else(|| "expected arp reply".to_string())?;
        assert_arp_reply(&arp_reply, client_mac, client_ip, fw_mac, lease_ip)?;

        let outbound = build_ipv4_udp_frame(
            client_mac,
            fw_mac,
            client_ip,
            upstream_ip,
            40_000,
            80,
            b"ping",
        );
        let outbound_frame = adapter
            .process_frame(&outbound, &mut state)
            .ok_or_else(|| "expected outbound frame".to_string())?;
        let (out_src, out_dst, out_sport, out_dport) = parse_ipv4_udp(&outbound_frame)?;
        if out_src != lease_ip {
            return Err(format!("expected snat ip {lease_ip}, got {out_src}"));
        }
        if out_dst != upstream_ip || out_dport != 80 {
            return Err("unexpected outbound tuple".to_string());
        }

        let inbound = build_ipv4_udp_frame(
            server_mac,
            fw_mac,
            upstream_ip,
            lease_ip,
            80,
            out_sport,
            b"pong",
        );
        let inbound_frame = adapter
            .process_frame(&inbound, &mut state)
            .ok_or_else(|| "expected inbound frame".to_string())?;
        let (in_src, in_dst, in_sport, in_dport) = parse_ipv4_udp(&inbound_frame)?;
        if in_src != upstream_ip || in_sport != 80 {
            return Err("unexpected inbound src tuple".to_string());
        }
        if in_dst != client_ip || in_dport != 40_000 {
            return Err("reverse nat failed".to_string());
        }

        dhcp_task.abort();
        Ok(())
    })
}

fn dpdk_dhcp_retries_exhausted(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::UNSPECIFIED, 32);

        let (_dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(8);
        let (cp_to_dp_tx, mut cp_to_dp_rx) = mpsc::channel(8);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(50),
                retry_max: 2,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: DataplaneConfigStore::new(),
            policy_store,
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });
        let _ = mac_tx.send([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);

        let drain_task = tokio::spawn(async move { while cp_to_dp_rx.recv().await.is_some() {} });

        let result = tokio::time::timeout(Duration::from_secs(2), dhcp_task).await;
        drain_task.abort();

        match result {
            Ok(Ok(Ok(()))) => Err("expected dhcp failure, got success".to_string()),
            Ok(Ok(Err(err))) => {
                if err.contains("dhcp discovery retries exceeded") {
                    Ok(())
                } else {
                    Err(format!("unexpected dhcp error: {err}"))
                }
            }
            Ok(Err(err)) => Err(format!("dhcp task join failed: {err}")),
            Err(_) => Err("dhcp task did not finish".to_string()),
        }
    })
}

fn dpdk_dhcp_renewal_updates_config(_cfg: &TopologyConfig) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        let dataplane_config = DataplaneConfigStore::new();
        let policy_store = PolicyStore::new_with_config(
            DefaultPolicy::Deny,
            Ipv4Addr::UNSPECIFIED,
            32,
            dataplane_config.clone(),
        );

        let mut state = EngineState::new_with_idle_timeout(
            policy_store.snapshot(),
            Ipv4Addr::UNSPECIFIED,
            32,
            Ipv4Addr::UNSPECIFIED,
            0,
            120,
        );
        state.set_dataplane_config(dataplane_config.clone());

        let (dp_to_cp_tx, dp_to_cp_rx) = mpsc::channel(32);
        let (cp_to_dp_tx, cp_to_dp_rx) = mpsc::channel(32);
        let (mac_tx, mac_rx) = watch::channel([0u8; 6]);

        let dhcp_client = DhcpClient {
            config: DhcpClientConfig {
                timeout: Duration::from_millis(100),
                retry_max: 5,
                lease_min_secs: 1,
                hostname: None,
                update_internal_cidr: true,
                allow_router_fallback_from_subnet: false,
            },
            mac_rx,
            rx: dp_to_cp_rx,
            tx: cp_to_dp_tx,
            dataplane_config: dataplane_config.clone(),
            policy_store,
            metrics: None,
        };

        let dhcp_task = tokio::spawn(async move { dhcp_client.run().await });

        let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let server_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xef];
        let server_ip = Ipv4Addr::new(10, 0, 0, 254);
        let lease_ip = Ipv4Addr::new(10, 0, 0, 1);
        let lease_ip_new = Ipv4Addr::new(10, 0, 0, 9);
        let _ = mac_tx.send(fw_mac);

        let mut adapter = DpdkAdapter::new("dpdk-renew".to_string())?;
        adapter.set_mac(fw_mac);
        adapter.set_dhcp_channels(dp_to_cp_tx, cp_to_dp_rx);

        let mut dhcp = DhcpTestServer::new(server_ip, server_mac, lease_ip, 2);
        let mut saw_initial = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(cfg) = dataplane_config.get() {
                if cfg.ip == lease_ip_new {
                    break;
                }
                if cfg.ip == lease_ip && !saw_initial {
                    saw_initial = true;
                    dhcp.lease_ip = lease_ip_new;
                    dhcp.lease_time_secs = 2;
                }
            }
            if Instant::now() >= deadline {
                return Err("dhcp renewal did not update lease".to_string());
            }
            while let Some(frame) = adapter.next_dhcp_frame(&state) {
                if let Some(resp) = dhcp.handle_client_frame(&frame) {
                    let _ = adapter.process_frame(&resp, &mut state);
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        dhcp_task.abort();
        Ok(())
    })
}

fn dpdk_tls_intercept_service_lane_round_trip(_cfg: &TopologyConfig) -> Result<(), String> {
    let fw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    let client_mac = [0x02, 0x01, 0x02, 0x03, 0x04, 0x05];
    let client_ip = Ipv4Addr::new(10, 0, 0, 42);
    let fw_ip = Ipv4Addr::new(10, 0, 0, 1);
    let upstream_ip = Ipv4Addr::new(198, 51, 100, 10);
    let client_port = 40_000;

    let mut sources = IpSetV4::new();
    sources.add_cidr(CidrV4::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let rule = Rule {
        id: "tls-intercept".to_string(),
        priority: 0,
        matcher: RuleMatch {
            dst_ips: None,
            proto: Proto::Tcp,
            src_ports: Vec::new(),
            dst_ports: vec![PortRange {
                start: 443,
                end: 443,
            }],
            icmp_types: Vec::new(),
            icmp_codes: Vec::new(),
            tls: Some(TlsMatch {
                mode: TlsMode::Intercept,
                sni: None,
                server_san: None,
                server_cn: None,
                fingerprints_sha256: Vec::new(),
                trust_anchors: Vec::new(),
                tls13_uninspectable: Tls13Uninspectable::Deny,
                intercept_http: None,
            }),
        },
        action: RuleAction::Allow,
        mode: RuleMode::Enforce,
    };
    let group = SourceGroup {
        id: "internal".to_string(),
        priority: 0,
        sources,
        rules: vec![rule],
        default_action: None,
    };
    let policy = Arc::new(RwLock::new(PolicySnapshot::new_with_generation(
        DefaultPolicy::Deny,
        vec![group],
        1,
    )));

    let mut state = EngineState::new(
        policy,
        Ipv4Addr::new(10, 0, 0, 0),
        24,
        Ipv4Addr::new(203, 0, 113, 1),
        0,
    );
    state.set_service_policy_applied_generation(Arc::new(std::sync::atomic::AtomicU64::new(1)));
    state.set_intercept_to_host_steering(true);
    state.dataplane_config.set(DataplaneConfig {
        ip: fw_ip,
        prefix: 24,
        gateway: Ipv4Addr::new(10, 0, 0, 254),
        mac: fw_mac,
        lease_expiry: None,
    });

    let shared_arp = Arc::new(Mutex::new(SharedArpState::default()));
    let shared_demux = Arc::new(Mutex::new(SharedInterceptDemuxState::default()));
    let mut ingress = DpdkAdapter::new("dpdk-ingress".to_string())?;
    let mut egress = DpdkAdapter::new("dpdk-egress".to_string())?;
    ingress.set_mac(fw_mac);
    egress.set_mac(fw_mac);
    ingress.set_shared_arp(shared_arp.clone());
    egress.set_shared_arp(shared_arp);
    ingress.set_shared_intercept_demux(shared_demux.clone());
    egress.set_shared_intercept_demux(shared_demux);

    let arp_req = build_arp_request(client_mac, client_ip, fw_ip);
    let arp_reply = ingress
        .process_frame(&arp_req, &mut state)
        .ok_or_else(|| "expected arp reply".to_string())?;
    assert_arp_reply(&arp_reply, client_mac, client_ip, fw_mac, fw_ip)?;

    let syn = build_ipv4_tcp_frame(
        client_mac,
        fw_mac,
        client_ip,
        upstream_ip,
        client_port,
        443,
        1,
        0,
        0x02,
        &[],
    );
    if ingress.process_frame(&syn, &mut state).is_some() {
        return Err("intercept flow should not egress dataplane directly".to_string());
    }
    let host_frame = ingress
        .next_host_frame()
        .ok_or_else(|| "expected service-lane host frame".to_string())?;
    let (host_src_ip, host_dst_ip, host_src_port, host_dst_port) = parse_ipv4_tcp(&host_frame)?;
    if host_src_ip != client_ip || host_src_port != client_port {
        return Err("service-lane host frame source tuple mismatch".to_string());
    }
    if host_dst_ip != Ipv4Addr::new(169, 254, 255, 1) || host_dst_port != 15_443 {
        return Err("service-lane host frame did not target intercept endpoint".to_string());
    }

    let service_lane_egress = build_ipv4_tcp_frame(
        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        fw_mac,
        Ipv4Addr::new(169, 254, 255, 1),
        client_ip,
        15_443,
        client_port,
        2,
        2,
        0x18,
        b"ok",
    );
    let forwarded = egress
        .process_service_lane_egress_frame(&service_lane_egress, &state)
        .ok_or_else(|| "service-lane return frame did not forward".to_string())?;
    let (src_ip, dst_ip, src_port, dst_port) = parse_ipv4_tcp(&forwarded)?;
    if src_ip != upstream_ip || src_port != 443 {
        return Err("forwarded frame source tuple mismatch".to_string());
    }
    if dst_ip != client_ip || dst_port != client_port {
        return Err("forwarded frame destination tuple mismatch".to_string());
    }
    if forwarded[0..6] != client_mac || forwarded[6..12] != fw_mac {
        return Err("forwarded frame L2 rewrite mismatch".to_string());
    }
    if egress.next_dhcp_frame(&state).is_some() {
        return Err("unexpected ARP request queued on service-lane return path".to_string());
    }

    Ok(())
}

fn api_bootstrap_tls_material(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.key"), Duration::from_secs(5))?;
    Ok(())
}

fn api_tls_san_allows_alt_ip(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.crt"), Duration::from_secs(5))?;
    let sans = read_cert_sans(&tls_dir.join("node.crt"))?;
    if !sans.contains(&IpAddr::V4(cfg.fw_mgmt_ip_alt)) {
        return Err("http cert missing alt mgmt ip SAN".to_string());
    }
    Ok(())
}

fn api_audit_policy_listed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let before = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        let created =
            http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Audit, Some(&token)).await?;
        let after = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        if after.len() != before.len() + 1 {
            return Err("policy list size did not increase".to_string());
        }
        if !after.iter().any(|record| record.id == created.id) {
            return Err("created policy not found in list".to_string());
        }
        Ok(())
    })
}

fn api_audit_passthrough_overrides_deny(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let audit_policy = parse_policy(
        r#"default_policy: allow
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "deny-foo"
        mode: enforce
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
"#,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn api_audit_findings_dns_passthrough_records_event(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let audit_policy = parse_policy(
        r#"default_policy: allow
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "deny-foo"
        mode: enforce
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
"#,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        let query = build_audit_query(
            Some(record.id),
            Some("dns_deny"),
            Some("client-primary"),
            Some(50),
        )?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::DnsDeny
                && item.policy_id == Some(record.id)
                && item.source_group == "client-primary"
                && item.fqdn.as_deref() == Some("foo.allowed")
                && item.hostname.as_deref() == Some("foo.allowed")
                && item.query_type == Some(1)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing dns_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

fn api_audit_findings_l4_passthrough_records_event(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let payload = b"audit-l4";
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "apps"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-upstream-udp"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }
        let query = build_audit_query(Some(record.id), Some("l4_deny"), Some("apps"), Some(50))?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::L4Deny
                && item.policy_id == Some(record.id)
                && item.source_group == "apps"
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.dst_port == Some(cfg.up_udp_port)
                && item.proto == Some(17)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing l4_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

fn api_audit_findings_tls_passthrough_captures_sni(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let sni = "foo.allowed";
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "tls-audit"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-tls-sni"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            sni:
              exact: ["{sni}"]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        sni = sni
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let _record = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        // Prime DNS allowlist entry for upstream IP before HTTPS.
        let dns = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&dns, cfg.up_dp_ip)?;
        let start_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(5);
        let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
        let _ = https_get_tls12(https_addr, sni).await;
        let _ = tls_client_hello_raw(https_addr, sni, 2000).await;
        let query =
            build_audit_query_with_since(None, Some("tls_deny"), None, Some(start_ts), Some(200))?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(5))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::TlsDeny
                && item.sni.as_deref() == Some(sni)
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.dst_port == Some(443)
                && item.proto == Some(6)
                && item.last_seen >= start_ts
                && item.count >= 1
        }) {
            return Err(format!(
                "missing tls_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

fn api_audit_findings_icmp_passthrough_records_type_code(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "icmp-audit"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-icmp-echo"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [8]
          icmp_codes: [0]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let audit_policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    let record = rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await
    })?;
    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_secs(3)) {
        Ok(()) => {}
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            return Err(format!("{err}\n-- dataplane debug --\n{debug}"));
        }
    }
    rt.block_on(async {
        let query = build_audit_query(
            Some(record.id),
            Some("icmp_deny"),
            Some("icmp-audit"),
            Some(50),
        )?;
        let findings =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query, Duration::from_secs(3))
                .await?;
        if !findings.items.iter().any(|item| {
            item.finding_type == AuditFindingType::IcmpDeny
                && item.policy_id == Some(record.id)
                && item.source_group == "icmp-audit"
                && item.dst_ip == Some(cfg.up_dp_ip)
                && item.proto == Some(1)
                && item.icmp_type == Some(8)
                && item.icmp_code == Some(0)
                && item.count >= 1
        }) {
            return Err(format!(
                "missing icmp_deny audit finding: {:?}",
                findings.items
            ));
        }
        Ok(())
    })
}

fn api_audit_findings_policy_id_filter_isolates_rotated_policies(
    cfg: &TopologyConfig,
) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let payload_a = b"audit-policy-a";
    let payload_b = b"audit-policy-b";
    let policy_a_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "rotate-a"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-a"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy_b_yaml = format!(
        r#"
default_policy: allow
source_groups:
  - id: "rotate-b"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "deny-b"
        priority: 0
        mode: enforce
        action: deny
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy_a: PolicyConfig =
        serde_yaml::from_str(&policy_a_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let policy_b: PolicyConfig =
        serde_yaml::from_str(&policy_b_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record_a = http_set_policy(
            api_addr,
            &tls_dir,
            policy_a,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp_a = udp_echo(
            udp_bind,
            udp_server,
            payload_a,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp_a != payload_a {
            return Err("udp echo payload mismatch for policy A".to_string());
        }
        let query_a = build_audit_query(Some(record_a.id), Some("l4_deny"), None, Some(100))?;
        let findings_a =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query_a, Duration::from_secs(3))
                .await?;
        if !has_audit_finding(&findings_a.items, AuditFindingType::L4Deny, "rotate-a")
            || findings_a
                .items
                .iter()
                .all(|item| item.policy_id != Some(record_a.id))
        {
            return Err(format!(
                "policy A findings missing expected item: {:?}",
                findings_a.items
            ));
        }

        let record_b = http_set_policy(
            api_addr,
            &tls_dir,
            policy_b,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let resp_b = udp_echo(
            udp_bind,
            udp_server,
            payload_b,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp_b != payload_b {
            return Err("udp echo payload mismatch for policy B".to_string());
        }
        let query_b = build_audit_query(Some(record_b.id), Some("l4_deny"), None, Some(100))?;
        let findings_b =
            wait_for_audit_findings(api_addr, &tls_dir, &token, &query_b, Duration::from_secs(3))
                .await?;
        if !has_audit_finding(&findings_b.items, AuditFindingType::L4Deny, "rotate-b")
            || findings_b
                .items
                .iter()
                .all(|item| item.policy_id != Some(record_b.id))
        {
            return Err(format!(
                "policy B findings missing expected item: {:?}",
                findings_b.items
            ));
        }

        let recheck_a =
            http_get_audit_findings(api_addr, &tls_dir, Some(&query_a), Some(&token)).await?;
        if recheck_a
            .items
            .iter()
            .any(|item| item.policy_id != Some(record_a.id))
        {
            return Err(format!(
                "policy A query leaked other policy ids: {:?}",
                recheck_a.items
            ));
        }
        if recheck_a
            .items
            .iter()
            .any(|item| item.source_group != "rotate-a")
        {
            return Err(format!(
                "policy A query leaked other source groups: {:?}",
                recheck_a.items
            ));
        }

        let recheck_b =
            http_get_audit_findings(api_addr, &tls_dir, Some(&query_b), Some(&token)).await?;
        if recheck_b
            .items
            .iter()
            .any(|item| item.policy_id != Some(record_b.id))
        {
            return Err(format!(
                "policy B query leaked other policy ids: {:?}",
                recheck_b.items
            ));
        }
        if recheck_b
            .items
            .iter()
            .any(|item| item.source_group != "rotate-b")
        {
            return Err(format!(
                "policy B query leaked other source groups: {:?}",
                recheck_b.items
            ));
        }

        Ok(())
    })
}

fn api_policy_persisted_local(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let store_dir = std::path::PathBuf::from("/var/lib/neuwerk/local-policy-store");
        let active_path = store_dir.join("active.json");
        wait_for_path(&active_path, Duration::from_secs(5))?;
        let active: PolicyActive =
            serde_json::from_slice(&std::fs::read(&active_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("active json error: {e}"))?;
        if active.id != record.id {
            return Err("local active policy id mismatch".to_string());
        }
        let record_path = store_dir
            .join("policies")
            .join(format!("{}.json", record.id));
        wait_for_path(&record_path, Duration::from_secs(5))?;
        let stored: PolicyRecord =
            serde_json::from_slice(&std::fs::read(&record_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("stored policy json error: {e}"))?;
        if stored.id != record.id {
            return Err("stored policy id mismatch".to_string());
        }
        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

fn api_policy_active_semantics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let audit_policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let enforce_policy = parse_policy(policy_allow_foo_deny_cluster())?;
    let store_dir = std::path::PathBuf::from("/var/lib/neuwerk/local-policy-store");
    let active_path = store_dir.join("active.json");
    wait_for_path(&active_path, Duration::from_secs(5))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let baseline = read_active_id(&active_path)?;
        let audited = http_set_policy(
            api_addr,
            &tls_dir,
            audit_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let after_audit = read_active_id(&active_path)?;
        if after_audit != audited.id {
            return Err("audit policy did not become active".to_string());
        }
        let enforced = http_set_policy(
            api_addr,
            &tls_dir,
            enforce_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let after_enforce = read_active_id(&active_path)?;
        if after_enforce != enforced.id {
            return Err("enforce policy did not update active id".to_string());
        }
        if after_enforce == baseline {
            return Err("enforce policy did not replace baseline active id".to_string());
        }
        Ok(())
    })
}

fn api_policy_get_update_delete(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let record = http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy.clone(),
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;

        let fetched =
            http_get_policy(api_addr, &tls_dir, &record.id.to_string(), Some(&token)).await?;
        if fetched.id != record.id {
            return Err("policy get returned wrong record".to_string());
        }

        let mut updated_policy = baseline_policy.clone();
        updated_policy.default_policy = Some(PolicyValue::String("allow".to_string()));
        let updated = http_update_policy(
            api_addr,
            &tls_dir,
            &record.id.to_string(),
            updated_policy,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let updated_default = match updated.policy.default_policy {
            Some(PolicyValue::String(value)) => value,
            _ => "missing".to_string(),
        };
        if updated_default != "allow" {
            return Err(format!(
                "unexpected updated default_policy {}",
                updated_default
            ));
        }

        let status =
            http_delete_policy(api_addr, &tls_dir, &record.id.to_string(), Some(&token)).await?;
        if status != reqwest::StatusCode::NO_CONTENT {
            return Err(format!("unexpected delete status {status}"));
        }

        let status = http_api_status(
            api_addr,
            &tls_dir,
            &format!("/api/v1/policies/{}", record.id),
            Some(&token),
        )
        .await?;
        if status != reqwest::StatusCode::NOT_FOUND {
            return Err(format!("expected 404 after delete, got {status}"));
        }
        Ok(())
    })
}

fn api_policy_list_ordering(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_a = parse_policy(policy_allow_cluster_deny_foo())?;
    let policy_b = parse_policy(policy_allow_foo_deny_cluster())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let _ = http_set_policy(
            api_addr,
            &tls_dir,
            policy_a,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = http_set_policy(
            api_addr,
            &tls_dir,
            policy_b,
            PolicyMode::Audit,
            Some(&token),
        )
        .await?;
        let list = http_list_policies(api_addr, &tls_dir, Some(&token)).await?;
        if list.len() < 2 {
            return Err("policy list missing entries".to_string());
        }
        for window in list.windows(2) {
            let left = parse_created_at(&window[0])?;
            let right = parse_created_at(&window[1])?;
            if left > right {
                return Err("policy list not sorted by created_at".to_string());
            }
            if left == right && window[0].id.as_bytes() > window[1].id.as_bytes() {
                return Err("policy list not stable by id".to_string());
            }
        }
        Ok(())
    })
}

fn api_dns_cache_grouped(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let expected_ip = IpAddr::V4(cfg.up_dp_ip);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if resp.rcode != 0 || resp.ips.is_empty() {
            return Err("dns query did not return expected answer".to_string());
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let cache = http_get_dns_cache(api_addr, &tls_dir, Some(&token)).await?;
            if let Some(entry) = cache
                .entries
                .iter()
                .find(|entry| entry.hostname == "foo.allowed")
            {
                if entry.ips.iter().any(|ip| *ip == expected_ip) {
                    return Ok(());
                }
                return Err("dns cache entry missing expected ip".to_string());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for dns cache entry".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
}

fn api_stats_snapshot(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let stats = http_get_stats(api_addr, &tls_dir, Some(&token)).await?;
        let dataplane = stats.get("dataplane").ok_or("missing dataplane stats")?;
        let dns = stats.get("dns").ok_or("missing dns stats")?;
        let tls = stats.get("tls").ok_or("missing tls stats")?;
        let dhcp = stats.get("dhcp").ok_or("missing dhcp stats")?;
        let cluster = stats.get("cluster").ok_or("missing cluster stats")?;

        if !dataplane.is_object()
            || !dns.is_object()
            || !tls.is_object()
            || !dhcp.is_object()
            || !cluster.is_object()
        {
            return Err("stats payload not structured as expected".to_string());
        }
        Ok(())
    })
}

fn api_metrics_exposed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_api_health(api_addr, &tls_dir).await?;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        if !body.contains("http_requests_total") {
            return Err("metrics response missing http_requests_total".to_string());
        }
        if !body.contains("http_auth_total") {
            return Err("metrics response missing http_auth_total".to_string());
        }
        if !body.contains("dns_queries_total") {
            return Err("metrics response missing dns_queries_total".to_string());
        }
        if !body.contains("dp_packets_total") {
            return Err("metrics response missing dp_packets_total".to_string());
        }
        if !body.contains("raft_is_leader") {
            return Err("metrics response missing raft_is_leader".to_string());
        }
        if !body.contains("rocksdb_estimated_num_keys") {
            return Err("metrics response missing rocksdb_estimated_num_keys".to_string());
        }
        Ok(())
    })
}

fn api_body_limit_rejects_large(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let body = vec![b'a'; 3 * 1024 * 1024];
        let status =
            http_api_post_raw(api_addr, &tls_dir, "/api/v1/policies", body, Some(&token)).await?;
        if status != reqwest::StatusCode::PAYLOAD_TOO_LARGE {
            return Err(format!("expected 413, got {}", status));
        }
        Ok(())
    })
}

fn api_metrics_unauthenticated(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let status = http_api_status(api_addr, &tls_dir, "/api/v1/policies", None).await?;
        if status != reqwest::StatusCode::UNAUTHORIZED {
            return Err(format!("expected unauthorized status, got {status}"));
        }
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        if !body.contains("http_requests_total") {
            return Err("metrics response missing http_requests_total".to_string());
        }
        if !body.contains("http_auth_total") {
            return Err("metrics response missing http_auth_total".to_string());
        }
        let auth_denied = metric_value_with_labels(
            &body,
            "http_auth_total",
            &[("outcome", "deny"), ("reason", "missing_token")],
        )
        .ok_or_else(|| "missing http auth deny metrics".to_string())?;
        if auth_denied < 1.0 {
            return Err("http auth deny metrics did not increment".to_string());
        }
        Ok(())
    })
}

fn api_metrics_integrity(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_api_health(api_addr, &tls_dir).await?;
        let _ =
            http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Audit, Some(&token)).await?;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let health = metric_value(&body, "/health", "GET", "200")
            .ok_or_else(|| "missing health metrics".to_string())?;
        if health < 1.0 {
            return Err("health metrics did not increment".to_string());
        }
        let policy_post = metric_value(&body, "/api/v1/policies", "POST", "200")
            .ok_or_else(|| "missing policy post metrics".to_string())?;
        if policy_post < 1.0 {
            return Err("policy post metrics did not increment".to_string());
        }
        let auth_allow = metric_value_with_labels(
            &body,
            "http_auth_total",
            &[("outcome", "allow"), ("reason", "valid_token")],
        )
        .ok_or_else(|| "missing http auth allow metrics".to_string())?;
        if auth_allow < 1.0 {
            return Err("http auth allow metrics did not increment".to_string());
        }
        Ok(())
    })
}

fn api_metrics_dns_dataplane(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;

        let allow = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        assert_dns_allowed(&allow, cfg.up_dp_ip_alt)?;

        let deny = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&deny)?;

        let payload = b"metrics-udp";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_millis(500),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;

        let dns_allow = metric_value_with_labels(
            &body,
            "dns_queries_total",
            &[
                ("result", "allow"),
                ("reason", "policy_allow"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing dns allow metrics".to_string())?;
        if dns_allow < 1.0 {
            return Err("dns allow metrics did not increment".to_string());
        }
        let svc_dns_allow = metric_value_with_labels(
            &body,
            "svc_dns_queries_total",
            &[
                ("result", "allow"),
                ("reason", "policy_allow"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing svc dns allow metrics".to_string())?;
        if svc_dns_allow < 1.0 {
            return Err("svc dns allow metrics did not increment".to_string());
        }

        let dns_deny = metric_value_with_labels(
            &body,
            "dns_queries_total",
            &[
                ("result", "deny"),
                ("reason", "policy_deny"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing dns deny metrics".to_string())?;
        if dns_deny < 1.0 {
            return Err("dns deny metrics did not increment".to_string());
        }
        let svc_dns_deny = metric_value_with_labels(
            &body,
            "svc_dns_queries_total",
            &[
                ("result", "deny"),
                ("reason", "policy_deny"),
                ("source_group", "client-primary"),
            ],
        )
        .ok_or_else(|| "missing svc dns deny metrics".to_string())?;
        if svc_dns_deny < 1.0 {
            return Err("svc dns deny metrics did not increment".to_string());
        }

        let dns_nxdomain =
            metric_value_with_labels(&body, "dns_nxdomain_total", &[("source", "policy")])
                .ok_or_else(|| "missing dns nxdomain metrics".to_string())?;
        if dns_nxdomain < 1.0 {
            return Err("dns nxdomain metrics did not increment".to_string());
        }
        let svc_dns_nxdomain =
            metric_value_with_labels(&body, "svc_dns_nxdomain_total", &[("source", "policy")])
                .ok_or_else(|| "missing svc dns nxdomain metrics".to_string())?;
        if svc_dns_nxdomain < 1.0 {
            return Err("svc dns nxdomain metrics did not increment".to_string());
        }

        let dns_rtt_count = metric_value_with_labels(
            &body,
            "dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream rtt metrics".to_string())?;
        if dns_rtt_count < 1.0 {
            return Err("dns upstream rtt metrics did not increment".to_string());
        }
        let svc_dns_rtt_count = metric_value_with_labels(
            &body,
            "svc_dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing svc dns upstream rtt metrics".to_string())?;
        if svc_dns_rtt_count < 1.0 {
            return Err("svc dns upstream rtt metrics did not increment".to_string());
        }

        let dp_out = metric_value_with_labels(
            &body,
            "dp_packets_total",
            &[
                ("direction", "outbound"),
                ("proto", "udp"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        )
        .ok_or_else(|| "missing outbound dataplane packet metrics".to_string())?;
        if dp_out < 1.0 {
            return Err("outbound dataplane packet metrics did not increment".to_string());
        }

        let dp_in = metric_value_with_labels(
            &body,
            "dp_packets_total",
            &[
                ("direction", "inbound"),
                ("proto", "udp"),
                ("decision", "allow"),
                ("source_group", "internal"),
            ],
        )
        .ok_or_else(|| "missing inbound dataplane packet metrics".to_string())?;
        if dp_in < 1.0 {
            return Err("inbound dataplane packet metrics did not increment".to_string());
        }

        let flow_opens = metric_value_with_labels(
            &body,
            "dp_flow_opens_total",
            &[("proto", "udp"), ("source_group", "internal")],
        )
        .ok_or_else(|| "missing dataplane flow open metrics".to_string())?;
        if flow_opens < 1.0 {
            return Err("dataplane flow open metrics did not increment".to_string());
        }

        Ok(())
    })
}

fn api_tls_key_permissions(cfg: &TopologyConfig) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("node.key"), Duration::from_secs(5))?;
    let key_path = tls_dir.join("node.key");
    let mode = std::fs::metadata(&key_path)
        .map_err(|e| format!("read key metadata failed: {e}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!("node.key permissions too permissive: {:o}", mode));
    }
    Ok(())
}

fn icmp_echo_allowed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "icmp"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-icmp-echo"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [0, 8, 3, 11]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok::<(), String>(())
    })?;

    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_secs(3)) {
        Ok(()) => Ok(()),
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            Err(format!("{err}\n-- dataplane debug --\n{debug}"))
        }
    }
}

fn icmp_type_filtering(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "icmp-filter"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
      - id: "allow-icmp-time-exceeded"
        priority: 1
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: icmp
          icmp_types: [11]
          icmp_codes: [0]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok::<(), String>(())
    })?;

    match icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_millis(500)) {
        Ok(_) => {
            return Err("icmp echo unexpectedly allowed".to_string());
        }
        Err(err) => {
            if !err.contains("timed out") {
                return Err(format!("icmp echo unexpected error: {err}"));
            }
        }
    }

    let internal_port = 40123u16;
    let marker = b"icmp-filter";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let listen_timeout = Duration::from_secs(2);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let packet = wait_for_udp_packet_on_fd(
                fd,
                expected_src,
                expected_dst,
                expected_dst_port,
                Some(marker),
                listen_timeout,
            )?;
            unsafe {
                libc::close(fd);
            }
            Ok::<u16, String>(packet.src_port)
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    let mut payload = Vec::new();
    payload.extend_from_slice(marker);
    payload.extend_from_slice(&internal_port.to_be_bytes());
    send_udp_with_payload_from_port(
        cfg.client_dp_ip,
        internal_port,
        cfg.up_dp_ip,
        cfg.up_udp_port,
        &payload,
    )?;
    let ext_port_result = result_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|e| format!("upstream capture timed out: {e}"))?;
    let ext_port = ext_port_result.map_err(|e| format!("{e}"))??;
    let _ = handle.join();

    let upstream_ns_sender = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    upstream_ns_sender
        .run(|_| {
            send_icmp_time_exceeded(
                cfg.up_dp_ip,
                cfg.dp_public_ip,
                cfg.dp_public_ip,
                cfg.up_dp_ip,
                ext_port,
                cfg.up_udp_port,
            )
        })
        .map_err(|e| format!("{e}"))??;
    let icmp_fd = open_icmp_socket(cfg.client_dp_ip, Duration::from_secs(2))?;
    let icmp_result = wait_for_icmp_time_exceeded_on_fd(
        icmp_fd,
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        internal_port,
        cfg.up_udp_port,
        Some(cfg.up_dp_ip),
    );
    unsafe {
        libc::close(icmp_fd);
    }
    icmp_result
}

fn icmp_ttl_exceeded(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let dst_port = 33434u16;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "ttl"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = dst_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        let before_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let before = metric_plain_value(&before_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);

        let ttl_candidates = [1u32, 2u32];
        let mut last_ttl = ttl_candidates[0];
        let mut last_icmp_err: Option<String> = None;
        let mut ttl_idx = 1usize;
        let deadline = Instant::now() + Duration::from_secs(6);
        let icmp_fd = open_icmp_socket(cfg.client_dp_ip, Duration::from_millis(400))?;
        loop {
            let rx_before = dp_iface_rx_packets(cfg).unwrap_or(0);
            let ttl = last_ttl;
            let port = send_udp_with_ttl(
                cfg.client_dp_ip,
                cfg.up_dp_ip,
                dst_port,
                ttl,
            )?;
            let mut saw_rx = false;
            for _ in 0..5 {
                if dp_iface_rx_packets(cfg).unwrap_or(0) > rx_before {
                    saw_rx = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let icmp_result = wait_for_icmp_time_exceeded_on_fd(
                icmp_fd,
                cfg.client_dp_ip,
                cfg.up_dp_ip,
                port,
                dst_port,
                Some(cfg.dp_public_ip),
            );
            if let Err(err) = &icmp_result {
                last_icmp_err = Some(err.clone());
            }
            let after_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let after =
                metric_plain_value(&after_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);
            if after >= before + 1.0 {
                if icmp_result.is_ok() {
                    break;
                }
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ttl exceeded metrics incremented but ICMP time exceeded was not observed (ttl_exceeded_total={}, last_ttl={}, icmp_err={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    last_ttl,
                    icmp_result.unwrap_err()
                ));
            } else if icmp_result.is_ok() {
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ICMP time exceeded observed without ttl metrics increment (ttl_exceeded_total={}, last_ttl={}, expected_src={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    last_ttl,
                    cfg.dp_public_ip
                ));
            }
            if Instant::now() >= deadline {
                let dp_packets = metric_value_with_labels(
                    &after_body,
                    "dp_packets_total",
                    &[
                        ("direction", "outbound"),
                        ("proto", "udp"),
                        ("decision", "allow"),
                        ("source_group", "ttl"),
                    ],
                )
                .unwrap_or(0.0);
                let flow_opens = metric_value_with_labels(
                    &after_body,
                    "dp_flow_opens_total",
                    &[("proto", "udp"), ("source_group", "ttl")],
                )
                .unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                unsafe {
                    libc::close(icmp_fd);
                }
                return Err(format!(
                    "ttl exceeded metrics did not increment (ttl_exceeded_total={}, dp_packets_total={}, dp_flow_opens_total={}, dp0_rx_packets={}, last_ttl={}, last_icmp_err={})\n-- metrics --\n{after_body}\n-- dataplane debug --\n{debug}",
                    after,
                    dp_packets,
                    flow_opens,
                    dp_iface_rx_packets(cfg).unwrap_or(0),
                    last_ttl,
                    last_icmp_err.unwrap_or_else(|| "none".to_string())
                ));
            }
            let next_ttl = ttl_candidates[ttl_idx];
            ttl_idx = (ttl_idx + 1) % ttl_candidates.len();
            last_ttl = next_ttl;
            if !saw_rx {
                continue;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        unsafe {
            libc::close(icmp_fd);
        }
        Ok(())
    })
}

fn udp_ttl_decremented(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let ttl_port = cfg.up_udp_port.saturating_add(10);
    let ttl_send = 4u32;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "ttl-dec"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = ttl_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok::<(), String>(())
    })?;

    let marker = b"ttl-decrement";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = ttl_port;
    let listen_timeout = Duration::from_secs(2);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let socket = std::net::UdpSocket::bind((expected_dst, expected_dst_port))
                .map_err(|e| format!("udp listen bind failed: {e}"))?;
            let fd = socket.as_raw_fd();
            enable_ip_recv_ttl(fd)?;
            set_socket_timeout(fd, listen_timeout)?;
            let _ = ready_tx.send(());
            let ttl = recv_udp_ttl(fd, listen_timeout)?;
            Ok::<u8, String>(ttl)
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    let _ = send_udp_with_ttl_payload(cfg.client_dp_ip, cfg.up_dp_ip, ttl_port, ttl_send, marker)?;
    let ttl_result = result_rx.recv_timeout(Duration::from_secs(3)).map_err(|e| {
        let debug = overlay_debug_snapshot(cfg);
        let metrics = overlay_metrics_snapshot(metrics_addr);
        format!(
            "upstream capture timed out: {e}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
        )
    })?;
    let ttl = match ttl_result {
        Ok(Ok(ttl)) => ttl,
        Ok(Err(err)) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "udp ttl capture failed: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
        Err(err) => {
            let debug = overlay_debug_snapshot(cfg);
            let metrics = overlay_metrics_snapshot(metrics_addr);
            return Err(format!(
                "udp ttl capture netns error: {err}\n-- metrics --\n{metrics}\n-- dataplane debug --\n{debug}"
            ));
        }
    };
    let _ = handle.join();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    let after_body =
        rt.block_on(async { http_get_path(metrics_addr, "metrics", "/metrics").await })?;
    let after_packets = metric_value_with_labels(
        &after_body,
        "dp_packets_total",
        &[
            ("direction", "outbound"),
            ("proto", "udp"),
            ("decision", "allow"),
            ("source_group", "ttl-dec"),
        ],
    )
    .unwrap_or(0.0);
    if after_packets < 1.0 {
        return Err("udp ttl test did not record outbound dataplane packets".to_string());
    }
    if ttl > 2 {
        return Err(format!(
            "ttl not decremented enough (sent={}, observed={ttl})",
            ttl_send
        ));
    }
    Ok(())
}

fn ipv4_fragment_drop_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let before_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let before =
            metric_plain_value(&before_body, "dp_ipv4_fragments_dropped_total").unwrap_or(0.0);

        send_ipv4_udp_fragment(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            45000,
            cfg.up_udp_port,
            b"frag",
        )?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let after_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let after =
            metric_plain_value(&after_body, "dp_ipv4_fragments_dropped_total").unwrap_or(0.0);
        if after < before + 1.0 {
            return Err("fragment drop metrics did not increment".to_string());
        }
        Ok(())
    })
}

fn ipv4_fragment_not_forwarded(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "frag"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok::<(), String>(())
    })?;

    let marker = b"frag-block";
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let listen_timeout = Duration::from_millis(400);
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let result = match wait_for_udp_packet_on_fd(
                fd,
                expected_src,
                expected_dst,
                expected_dst_port,
                Some(marker),
                listen_timeout,
            ) {
                Ok(packet) => Err(format!(
                    "fragment unexpectedly forwarded (src_port={})",
                    packet.src_port
                )),
                Err(err) => {
                    if err.contains("timed out") {
                        Ok(())
                    } else {
                        Err(err)
                    }
                }
            };
            unsafe {
                libc::close(fd);
            }
            result
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    send_ipv4_udp_fragment(
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        45001,
        cfg.up_udp_port,
        marker,
    )?;
    let result = result_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("fragment capture timed out: {e}"))?;
    let _ = handle.join();
    result.map_err(|e| format!("{e}"))??;
    Ok(())
}

fn nat_idle_eviction_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "udp"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}", "{dst_ip_alt}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_ip_alt = cfg.up_dp_ip_alt,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
        let payload = b"nat-evict";
        let resp = udp_echo(client_bind, udp_server, payload, Duration::from_millis(500)).await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let baseline_active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
        let baseline_opens = metric_value_with_labels(
            &body,
            "dp_flow_opens_total",
            &[("proto", "udp"), ("source_group", "udp")],
        )
        .unwrap_or(0.0);
        let baseline_closes =
            metric_value_with_labels(&body, "dp_flow_closes_total", &[("reason", "idle_timeout")])
                .unwrap_or(0.0);

        let udp_server_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);
        let resp = udp_echo(
            client_bind,
            udp_server_alt,
            payload,
            Duration::from_millis(500),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch (alt)".to_string());
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let opens = metric_value_with_labels(
                &body,
                "dp_flow_opens_total",
                &[("proto", "udp"), ("source_group", "udp")],
            )
            .unwrap_or(0.0);
            let active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
            if opens > baseline_opens || active > baseline_active {
                break;
            }
            if Instant::now() >= deadline {
                return Err("expected flow opens to increase after udp flow".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        tokio::time::sleep(Duration::from_secs(cfg.idle_timeout_secs + 2)).await;
        let drop_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port + 1);
        send_udp_once(client_bind, drop_addr, b"evict")?;

        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let closes = metric_value_with_labels(
                &body,
                "dp_flow_closes_total",
                &[("reason", "idle_timeout")],
            )
            .unwrap_or(0.0);
            let active = metric_plain_value(&body, "dp_active_nat_entries").unwrap_or(0.0);
            if closes > baseline_closes || active <= baseline_active {
                break;
            }
            if Instant::now() >= deadline {
                return Err("expected nat entries to evict after idle timeout".to_string());
            }
        }

        Ok(())
    })
}

fn nat_port_deterministic(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "natdet"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok::<(), String>(())
    })?;

    let ports: Vec<u16> = (42000..42020).collect();
    let marker = b"natdet";
    let expected_src = cfg.dp_public_ip;
    let expected_dst = cfg.up_dp_ip;
    let expected_dst_port = cfg.up_udp_port;
    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let (ready_tx, ready_rx) = std_mpsc::channel();
    let (result_tx, result_rx) = std_mpsc::channel();
    let listen_timeout = Duration::from_secs(3);
    let port_count = ports.len();
    let handle = std::thread::spawn(move || {
        let res = upstream_ns.run(|_| {
            let fd = open_udp_raw_socket(expected_dst, listen_timeout)?;
            let _ = ready_tx.send(());
            let mut first: HashMap<u16, u16> = HashMap::new();
            let mut second: HashMap<u16, u16> = HashMap::new();
            while first.len() < port_count || second.len() < port_count {
                let packet = match wait_for_udp_packet_on_fd(
                    fd,
                    expected_src,
                    expected_dst,
                    expected_dst_port,
                    Some(marker),
                    listen_timeout,
                ) {
                    Ok(packet) => packet,
                    Err(err) => {
                        return Err(format!(
                            "nat capture timed out (first={}, second={}): {err}",
                            first.len(),
                            second.len()
                        ));
                    }
                };
                let offset = marker.len();
                if packet.payload.len() < offset + 3 {
                    continue;
                }
                let round = packet.payload[offset];
                let internal_port =
                    u16::from_be_bytes([packet.payload[offset + 1], packet.payload[offset + 2]]);
                match round {
                    0 => {
                        first.entry(internal_port).or_insert(packet.src_port);
                    }
                    1 => {
                        second.entry(internal_port).or_insert(packet.src_port);
                    }
                    _ => {}
                }
            }
            unsafe {
                libc::close(fd);
            }
            Ok((first, second))
        });
        let _ = result_tx.send(res);
    });

    ready_rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|e| format!("upstream listener not ready: {e}"))?;
    for &port in &ports {
        let mut payload = Vec::new();
        payload.extend_from_slice(marker);
        payload.push(0);
        payload.extend_from_slice(&port.to_be_bytes());
        send_udp_with_payload_from_port(
            cfg.client_dp_ip,
            port,
            cfg.up_dp_ip,
            cfg.up_udp_port,
            &payload,
        )?;
    }
    for &port in &ports {
        let mut payload = Vec::new();
        payload.extend_from_slice(marker);
        payload.push(1);
        payload.extend_from_slice(&port.to_be_bytes());
        send_udp_with_payload_from_port(
            cfg.client_dp_ip,
            port,
            cfg.up_dp_ip,
            cfg.up_udp_port,
            &payload,
        )?;
    }

    let result = result_rx
        .recv_timeout(Duration::from_secs(3))
        .map_err(|e| format!("nat capture timed out: {e}"))?;
    let _ = handle.join();
    let (first, second) = result.map_err(|e| format!("{e}"))??;
    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for &port in &ports {
        match (first.get(&port), second.get(&port)) {
            (Some(a), Some(b)) => {
                if a != b {
                    mismatches.push((port, *a, *b));
                }
            }
            _ => missing.push(port),
        }
    }
    if !missing.is_empty() {
        return Err(format!("missing NAT captures for ports: {:?}", missing));
    }
    if !mismatches.is_empty() {
        return Err(format!(
            "NAT mapping changed across packets: {:?}",
            mismatches
        ));
    }
    Ok(())
}

fn snat_override_applied(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "snat"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-http"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [80]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let body = http_get_path(
            SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80),
            "foo.allowed",
            "/whoami",
        )
        .await?;
        let whoami = http_body(&body);
        if whoami.trim() != cfg.dp_public_ip.to_string() {
            return Err(format!(
                "expected snat ip {}, got {}",
                cfg.dp_public_ip,
                whoami.trim()
            ));
        }
        Ok(())
    })
}

fn mgmt_api_unreachable_from_dataplane(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
        match http_get_path_bound(metrics_addr, "metrics", "/metrics", cfg.client_dp_ip).await {
            Ok(body) => Err(format!(
                "metrics reachable from dataplane: {}",
                http_body(&body).trim()
            )),
            Err(_) => Ok(()),
        }
    })
}

fn service_lane_svc0_present(cfg: &TopologyConfig) -> Result<(), String> {
    let output = Command::new("ip")
        .args([
            "netns", "exec", &cfg.fw_ns, "ip", "-o", "-4", "addr", "show", "dev", "svc0",
        ])
        .output()
        .map_err(|e| format!("service lane check invocation failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "service lane interface svc0 missing: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("169.254.255.1/30") {
        return Err(format!(
            "service lane svc0 missing expected address 169.254.255.1/30: {}",
            stdout.trim()
        ));
    }
    Ok(())
}

fn cluster_policy_update_applies(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let http_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 80);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        // Allow DNS allowlist GC to clear any entries created before policy applied.
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        tokio::time::sleep(Duration::from_secs(cfg.idle_timeout_secs + 2)).await;
        let dp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let evict_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port + 1);
        send_udp_once(dp_bind, evict_addr, b"evict")?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster.rcode != 0 || cluster.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy update".to_string());
        }

        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("http to cluster.allowed failed after policy update".to_string());
        }

        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("http to foo.allowed succeeded after deny update".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

fn cluster_policy_update_denies_existing_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if foo.rcode != 0 || foo.ips.is_empty() {
            return Err("foo.allowed DNS did not resolve before policy update".to_string());
        }

        let dp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
        let socket = UdpSocket::bind(dp_bind)
            .await
            .map_err(|e| format!("udp bind failed: {e}"))?;

        socket
            .send_to(b"before", udp_server)
            .await
            .map_err(|e| format!("udp send before failed: {e}"))?;
        let mut buf = vec![0u8; 2048];
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .map_err(|_| "udp recv before timed out".to_string())?
            .map_err(|e| format!("udp recv before failed: {e}"))?;

        http_set_policy(
            api_addr,
            &tls_dir,
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        socket
            .send_to(b"after", udp_server)
            .await
            .map_err(|e| format!("udp send after failed: {e}"))?;
        match tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((_len, _))) => {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err("udp to foo.allowed succeeded after deny update".to_string());
            }
            Ok(Err(err)) => {
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    baseline_policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                return Err(format!("udp recv after failed: {err}"));
            }
            Err(_) => {}
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

fn cluster_policy_update_https_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 443);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);

    let updated_policy = parse_policy(policy_allow_cluster_deny_foo())?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            updated_policy.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy update did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;

        let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster.rcode != 0 || cluster.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy update".to_string());
        }

        let https_resp = https_get(https_addr_alt, "cluster.allowed").await;
        if https_resp.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("https to cluster.allowed failed after policy update".to_string());
        }

        let udp_resp = udp_echo(
            udp_bind,
            udp_server_alt,
            b"cluster-udp",
            std::time::Duration::from_millis(500),
        )
        .await;
        if udp_resp.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("udp to cluster.allowed failed after policy update".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

fn cluster_policy_update_churn(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;

    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let http_addr_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), 80);

    let policy_a = parse_policy(policy_allow_cluster_deny_foo())?;
    let policy_b = parse_policy(policy_allow_foo_deny_cluster())?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy_a.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
            if foo.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy A did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let cluster_dns = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
        if cluster_dns.rcode != 0 || cluster_dns.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed DNS did not resolve after policy A".to_string());
        }
        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed http failed after policy A".to_string());
        }
        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed http succeeded after policy A".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            policy_b.clone(),
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let cluster = dns_query_response(client_bind, dns_server, "cluster.allowed").await?;
            if cluster.rcode == 3 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("policy B did not apply in time".to_string());
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let foo = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        if foo.rcode != 0 || foo.ips.is_empty() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed DNS did not resolve after policy B".to_string());
        }

        let foo_http = http_get(http_addr, "foo.allowed").await;
        if foo_http.is_err() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("foo.allowed http failed after policy B".to_string());
        }
        let cluster_http = http_get(http_addr_alt, "cluster.allowed").await;
        if cluster_http.is_ok() {
            http_set_policy(
                api_addr,
                &tls_dir,
                baseline_policy.clone(),
                PolicyMode::Enforce,
                Some(&token),
            )
            .await?;
            return Err("cluster.allowed http succeeded after policy B".to_string());
        }

        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        Ok(())
    })
}

fn policy_allow_cluster_deny_foo() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-cluster"
        priority: 0
        action: allow
        match:
          dns_hostname: '^cluster\.allowed$'
      - id: "deny-foo"
        priority: 1
        action: deny
        match:
          dns_hostname: '^foo\.allowed$'
  - id: "client-secondary"
    priority: 1
    sources:
      ips: ["192.0.2.3"]
    rules:
      - id: "allow-bar"
        action: allow
        match:
          dns_hostname: '^bar\.allowed$'
"#
}

fn policy_allow_spoof() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-spoof"
        priority: 0
        action: allow
        match:
          dns_hostname: '^spoof(-fail)?\.allowed$'
"#
}

fn policy_allow_foo_deny_cluster() -> &'static str {
    r#"default_policy: deny
source_groups:
  - id: "client-primary"
    priority: 0
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "allow-foo"
        priority: 0
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
      - id: "deny-cluster"
        priority: 1
        action: deny
        match:
          dns_hostname: '^cluster\.allowed$'
  - id: "client-secondary"
    priority: 1
    sources:
      ips: ["192.0.2.3"]
    rules:
      - id: "allow-bar"
        action: allow
        match:
          dns_hostname: '^bar\.allowed$'
"#
}

fn parse_policy(yaml: &str) -> Result<PolicyConfig, String> {
    serde_yaml::from_str(yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn wait_for_path(path: &std::path::Path, timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err(format!("timed out waiting for {}", path.display()))
}

fn read_active_id(path: &std::path::Path) -> Result<uuid::Uuid, String> {
    let payload = std::fs::read(path).map_err(|e| format!("read active policy failed: {e}"))?;
    let active: PolicyActive =
        serde_json::from_slice(&payload).map_err(|e| format!("active json error: {e}"))?;
    Ok(active.id)
}

fn parse_created_at(record: &PolicyRecord) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(&record.created_at, &Rfc3339)
        .map_err(|e| format!("invalid created_at {}: {e}", record.created_at))
}

fn metric_value(body: &str, path: &str, method: &str, status: &str) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with("http_requests_total{") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let labels = parts.next()?;
        let value = parts.next()?;
        let labels = labels
            .strip_prefix("http_requests_total{")?
            .strip_suffix('}')?;

        if !label_matches(labels, "path", path) {
            continue;
        }
        if !label_matches(labels, "method", method) {
            continue;
        }
        if !label_matches(labels, "status", status) {
            continue;
        }

        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

fn metric_value_with_labels(body: &str, metric: &str, labels: &[(&str, &str)]) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with(metric) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let labels_raw = parts.next()?;
        let value = parts.next()?;
        let labels_raw = labels_raw
            .strip_prefix(&format!("{metric}{{"))?
            .strip_suffix('}')?;

        let mut matches = true;
        for (key, expected) in labels {
            if !label_matches(labels_raw, key, expected) {
                matches = false;
                break;
            }
        }
        if !matches {
            continue;
        }
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

fn metric_plain_value(body: &str, metric: &str) -> Option<f64> {
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with(metric) {
            continue;
        }
        let rest = &line[metric.len()..];
        if rest.starts_with('{') {
            continue;
        }
        if !rest.starts_with(' ') && !rest.starts_with('\t') {
            continue;
        }
        let value = rest.split_whitespace().next()?;
        if let Ok(parsed) = value.parse::<f64>() {
            return Some(parsed);
        }
    }
    None
}

fn label_matches(labels: &str, key: &str, expected: &str) -> bool {
    for label in labels.split(',') {
        let mut iter = label.splitn(2, '=');
        let k = match iter.next() {
            Some(value) => value.trim(),
            None => continue,
        };
        let v = match iter.next() {
            Some(value) => value.trim(),
            None => continue,
        };
        if k == key {
            return v.trim_matches('"') == expected;
        }
    }
    false
}

fn http_body(response: &str) -> &str {
    response.splitn(2, "\r\n\r\n").nth(1).unwrap_or("")
}

async fn http_get_path_bound(
    addr: SocketAddr,
    host: &str,
    path: &str,
    bind_ip: Ipv4Addr,
) -> Result<String, String> {
    let socket = TcpSocket::new_v4().map_err(|e| format!("socket error: {e}"))?;
    socket
        .bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .map_err(|e| format!("bind error: {e}"))?;
    let mut stream = tokio::time::timeout(Duration::from_secs(1), socket.connect(addr))
        .await
        .map_err(|_| "http connect timed out".to_string())?
        .map_err(|e| format!("http connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("http read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn read_cert_sans(path: &std::path::Path) -> Result<Vec<IpAddr>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read cert failed: {e}"))?;
    let (_, pem) = parse_x509_pem(&pem).map_err(|e| format!("parse pem failed: {e}"))?;
    let (_, cert) = parse_x509_certificate(&pem.contents).map_err(|e| format!("{e}"))?;
    let mut ips = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in san.general_names.iter() {
                if let GeneralName::IPAddress(raw) = name {
                    if raw.len() == 4 {
                        let ip = IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]));
                        ips.push(ip);
                    }
                }
            }
        }
    }
    Ok(ips)
}

fn allowlist_gc_delay(cfg: &TopologyConfig) -> Duration {
    let secs = cfg
        .dns_allowlist_idle_secs
        .saturating_add(cfg.dns_allowlist_gc_interval_secs)
        .saturating_add(1);
    Duration::from_secs(secs.max(1))
}

fn http_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match http_get(http_addr, "foo.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "http denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

fn udp_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match udp_echo(
            bind,
            server,
            b"denied",
            std::time::Duration::from_millis(500),
        )
        .await
        {
            Ok(_) => Err("udp unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "udp denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

fn https_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let start = std::time::Instant::now();
        match https_get(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "https denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

fn tls_sni_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls12(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_sni_allows_https_tls13(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls13(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_sni_denies_https(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "bar.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls12(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded with sni mismatch".to_string()),
            Err(_) => Ok(()),
        }
    })
}

fn tls_cert_tls12_allows(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy(cfg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls12(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_cert_tls12_denies_san_mismatch(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy_with(cfg, "bar.allowed", "deny")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls12(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded with SAN mismatch".to_string()),
            Err(_) => Ok(()),
        }
    })
}

fn tls_cert_tls13_denied(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy(cfg)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls13(https_addr, "foo.allowed").await {
            Ok(_) => {
                Err("https unexpectedly succeeded on tls1.3 with cert constraints".to_string())
            }
            Err(_) => Ok(()),
        }
    })
}

fn tls_cert_tls13_allows(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_cert_policy_with(cfg, "foo.allowed", "allow")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let resp = https_get_tls13(https_addr, "foo.allowed").await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_reassembly_client_hello(cfg: &TopologyConfig) -> Result<(), String> {
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    let token = api_auth_token(cfg)?;
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let policy = tls_sni_policy(cfg, "foo.allowed")?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let read = tls_client_hello_raw(https_addr, "foo.allowed", 2000).await?;
        if read == 0 {
            return Err("tls raw client hello did not receive response".to_string());
        }
        Ok(())
    })
}

fn tls_intercept_http_allow(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let resp = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !resp.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected https response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_intercept_http_deny_rst(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        assert_https_path_denied_with_rst(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            https_addr,
            "foo.allowed",
            "/moolen",
        )
        .await
    })
}

fn tls_intercept_response_header_deny_rst(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy_with_response_deny(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        assert_https_path_denied_with_rst(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            https_addr,
            "foo.allowed",
            "/external-secrets/forbidden-response",
        )
        .await
    })
}

fn tls_intercept_h2_allow(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let resp = https_h2_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets?ref=main",
        )
        .await?;
        if !resp.starts_with("HTTP/2 200") {
            return Err(format!("unexpected h2 response: {}", first_line(&resp)));
        }
        Ok(())
    })
}

fn tls_intercept_h2_concurrency_smoke(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;

        const CONCURRENCY: usize = 8;
        const ROUNDS: usize = 3;
        for _round in 0..ROUNDS {
            let mut workers = Vec::with_capacity(CONCURRENCY);
            for _idx in 0..CONCURRENCY {
                workers.push(tokio::spawn(async move {
                    let mut last_err = String::new();
                    for _attempt in 0..5 {
                        match https_h2_get_path(
                            https_addr,
                            "foo.allowed",
                            "/external-secrets/external-secrets?ref=main",
                        )
                        .await
                        {
                            Ok(resp) => return Ok::<String, String>(resp),
                            Err(err) if looks_like_reset(&err) => {
                                last_err = err;
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    Err(format!(
                        "h2 allow path retries exhausted with reset-like errors: {last_err}"
                    ))
                }));
            }
            for worker in workers {
                let resp = worker
                    .await
                    .map_err(|e| format!("h2 worker join failed: {e}"))??;
                if !resp.starts_with("HTTP/2 200") {
                    return Err(format!(
                        "unexpected h2 response during concurrency smoke: {}",
                        first_line(&resp)
                    ));
                }
            }
        }

        match https_h2_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => Err(format!(
                "intercept h2 deny expected failure after load, got response: {}",
                first_line(&resp)
            )),
            Err(err) if looks_like_reset(&err) => Ok(()),
            Err(err) => Err(format!(
                "intercept h2 deny expected reset/close after load, got different failure: {err}"
            )),
        }
    })
}

fn tls_intercept_ca_rotation_reloads_runtime(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;

        let initial_fingerprint = https_leaf_cert_sha256(https_addr, "foo.allowed").await?;
        let baseline = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !baseline.starts_with("HTTP/1.1 200") {
            return Err(format!(
                "unexpected baseline https response: {}",
                first_line(&baseline)
            ));
        }

        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut rotated = false;
        let mut last = String::new();
        while Instant::now() < deadline {
            match https_leaf_cert_sha256(https_addr, "foo.allowed").await {
                Ok(fingerprint) => {
                    if fingerprint != initial_fingerprint {
                        rotated = true;
                        break;
                    }
                }
                Err(err) => {
                    last = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !rotated {
            return Err(format!(
                "tls intercept CA rotation did not change served leaf cert fingerprint within timeout (last error: {last})"
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut allow_ok = false;
        let mut last_allow = String::new();
        while Instant::now() < deadline {
            match https_get_path(https_addr, "foo.allowed", "/external-secrets/external-secrets")
                .await
            {
                Ok(resp) if resp.starts_with("HTTP/1.1 200") => {
                    allow_ok = true;
                    break;
                }
                Ok(resp) => {
                    last_allow = format!("unexpected response {}", first_line(&resp));
                }
                Err(err) => {
                    last_allow = err;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if !allow_ok {
            return Err(format!(
                "tls intercept allow path failed after CA rotation: {last_allow}"
            ));
        }

        assert_https_path_denied_with_rst(
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            https_addr,
            "foo.allowed",
            "/moolen",
        )
        .await
    })
}

fn tls_intercept_h2_deny_fail_closed(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        match https_h2_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => Err(format!(
                "intercept h2 deny expected failure, got response: {}",
                first_line(&resp)
            )),
            Err(err) => {
                if looks_like_reset(&err) {
                    Ok(())
                } else {
                    Err(format!(
                        "intercept h2 deny expected reset/close, got different failure: {err}"
                    ))
                }
            }
        }
    })
}

fn tls_intercept_service_metrics(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let policy = tls_intercept_policy(cfg)?;
    let token = api_auth_token(cfg)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_put_tls_intercept_ca_from_http_ca(api_addr, &tls_dir, Some(&token)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let _ = dns_query(client_bind, dns_server, "foo.allowed").await?;
        let allow = https_get_path(
            https_addr,
            "foo.allowed",
            "/external-secrets/external-secrets",
        )
        .await?;
        if !allow.starts_with("HTTP/1.1 200") {
            return Err(format!("unexpected allow response: {}", first_line(&allow)));
        }
        match https_get_path(https_addr, "foo.allowed", "/moolen?ref=main").await {
            Ok(resp) => {
                return Err(format!(
                    "intercept deny expected reset/failure, got response: {}",
                    first_line(&resp)
                ));
            }
            Err(err) if looks_like_reset(&err) => {}
            Err(err) => {
                return Err(format!(
                    "intercept deny expected reset/refused, got different failure: {err}"
                ));
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;

        let tls_allow = metric_value_with_labels(
            &body,
            "svc_tls_intercept_flows_total",
            &[("result", "allow")],
        )
        .ok_or_else(|| "missing svc tls allow metrics".to_string())?;
        if tls_allow < 1.0 {
            return Err("svc tls allow metrics did not increment".to_string());
        }
        let tls_deny = metric_value_with_labels(
            &body,
            "svc_tls_intercept_flows_total",
            &[("result", "deny")],
        )
        .ok_or_else(|| "missing svc tls deny metrics".to_string())?;
        if tls_deny < 1.0 {
            return Err("svc tls deny metrics did not increment".to_string());
        }
        let http_allow = metric_value_with_labels(
            &body,
            "svc_http_requests_total",
            &[("proto", "http1"), ("decision", "allow")],
        )
        .ok_or_else(|| "missing svc http allow metrics".to_string())?;
        if http_allow < 1.0 {
            return Err("svc http allow metrics did not increment".to_string());
        }
        let http_deny = metric_value_with_labels(
            &body,
            "svc_http_denies_total",
            &[
                ("proto", "http1"),
                ("phase", "request"),
                ("reason", "policy"),
            ],
        )
        .ok_or_else(|| "missing svc http deny metrics".to_string())?;
        if http_deny < 1.0 {
            return Err("svc http deny metrics did not increment".to_string());
        }
        let rst = metric_value_with_labels(
            &body,
            "svc_policy_rst_total",
            &[("reason", "request_policy")],
        )
        .ok_or_else(|| "missing svc policy rst metrics".to_string())?;
        if rst < 1.0 {
            return Err("svc policy rst metrics did not increment".to_string());
        }
        let fail_closed =
            metric_value_with_labels(&body, "svc_fail_closed_total", &[("component", "tls")])
                .ok_or_else(|| "missing svc fail-closed metrics".to_string())?;
        if fail_closed < 1.0 {
            return Err("svc fail-closed metrics did not increment".to_string());
        }

        Ok(())
    })
}

async fn assert_https_path_denied_with_rst(
    client_ip: Ipv4Addr,
    upstream_ip: Ipv4Addr,
    https_addr: SocketAddr,
    host: &str,
    path: &str,
) -> Result<(), String> {
    let tcp_fd = open_tcp_raw_socket(client_ip, Duration::from_secs(2))?;
    let request = https_get_path(https_addr, host, path).await;
    let rst_capture = wait_for_tcp_rst_on_fd(
        tcp_fd,
        upstream_ip,
        client_ip,
        Some(443),
        None,
        Duration::from_secs(2),
    );
    unsafe {
        libc::close(tcp_fd);
    }
    match request {
        Ok(resp) => Err(format!(
            "intercept deny expected reset/failure, got response: {}",
            first_line(&resp)
        )),
        Err(err) => {
            if !looks_like_reset(&err) {
                return Err(format!(
                    "intercept deny expected reset/refused, got different failure: {err}"
                ));
            }
            rst_capture.map(|_| ())
        }
    }
}

fn dns_allows_http(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let dns_start = std::time::Instant::now();
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        println!("dns response in {:?}: {:?}", dns_start.elapsed(), ips);
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http_start = std::time::Instant::now();
        let http = http_get(http_addr, "foo.allowed").await?;
        println!("http request completed in {:?}", http_start.elapsed());
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        let https_start = std::time::Instant::now();
        let https = https_get(https_addr, "foo.allowed").await?;
        println!("https request completed in {:?}", https_start.elapsed());
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }

        Ok(())
    })
}

fn dns_allows_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let payload = b"udp-allowed";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }
        Ok(())
    })
}

fn dns_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let https = https_get(https_addr, "foo.allowed").await?;
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }
        Ok(())
    })
}

fn dns_tcp_allows_https(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response_tcp(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;

        let https = https_get(https_addr, "foo.allowed").await?;
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }
        Ok(())
    })
}

fn dns_tcp_blocks_nonmatch(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response_tcp(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;

        match http_get(http_addr, "bar.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded after dns tcp NXDOMAIN".to_string()),
            Err(_) => Ok(()),
        }
    })
}

fn dns_regex_allows_example(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "api.example.com").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn dns_regex_blocks_nonmatch(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

fn dns_source_group_allows_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip_alt), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn dns_source_group_blocks_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip_alt), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "foo.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

fn dns_case_insensitive_match(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "FoO.AlLoWeD.").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn dns_upstream_failover_allows_secondary(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_spoof())?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let resp = dns_query_response(client_bind, dns_server, "spoof.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let mismatch = metric_value_with_labels(
            &body,
            "dns_upstream_mismatch_total",
            &[("reason", "txid"), ("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream mismatch metrics".to_string())?;
        if mismatch < 1.0 {
            return Err("dns upstream mismatch metrics did not increment".to_string());
        }
        let rtt_count = metric_value_with_labels(
            &body,
            "dns_upstream_rtt_seconds_count",
            &[("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream rtt metrics".to_string())?;
        if rtt_count < 1.0 {
            return Err("dns upstream rtt metrics did not increment".to_string());
        }
        Ok(())
    })
}

fn dns_upstream_mismatch_nxdomain(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let token = api_auth_token(cfg)?;
    let policy = parse_policy(policy_allow_spoof())?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;

        let resp = dns_query_response(client_bind, dns_server, "spoof-fail.allowed").await?;
        assert_dns_nxdomain(&resp)?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        let body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let mismatch = metric_value_with_labels(
            &body,
            "dns_upstream_mismatch_total",
            &[("reason", "txid"), ("source_group", "client-primary")],
        )
        .ok_or_else(|| "missing dns upstream mismatch metrics".to_string())?;
        if mismatch < 1.0 {
            return Err("dns upstream mismatch metrics did not increment".to_string());
        }
        Ok(())
    })
}

fn dns_long_name_match(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let token = api_auth_token(cfg)?;
    let baseline_policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    )))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            baseline_policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        let resp = dns_query_response(
            client_bind,
            dns_server,
            "very.long.subdomain.name.example.com",
        )
        .await?;
        if resp.rcode != 0 {
            let metrics = http_get_path(metrics_addr, "metrics", "/metrics")
                .await
                .unwrap_or_else(|err| format!("metrics fetch failed: {err}"));
            let policy_deny = metric_value_with_labels(
                &metrics,
                "dns_queries_total",
                &[
                    ("result", "deny"),
                    ("reason", "policy_deny"),
                    ("source_group", "client-primary"),
                ],
            )
            .unwrap_or(0.0);
            let mismatch = metric_value_with_labels(
                &metrics,
                "dns_queries_total",
                &[
                    ("result", "deny"),
                    ("reason", "upstream_mismatch"),
                    ("source_group", "client-primary"),
                ],
            )
            .unwrap_or(0.0);
            let nxdomain_policy = metric_value_with_labels(
                &metrics,
                "dns_nxdomain_total",
                &[("source", "policy")],
            )
            .unwrap_or(0.0);
            let nxdomain_upstream = metric_value_with_labels(
                &metrics,
                "dns_nxdomain_total",
                &[("source", "upstream")],
            )
            .unwrap_or(0.0);
            return Err(format!(
                "dns response unexpected rcode: {}; policy_deny={}, upstream_mismatch={}, nxdomain_policy={}, nxdomain_upstream={}",
                resp.rcode, policy_deny, mismatch, nxdomain_policy, nxdomain_upstream
            ));
        }
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn dns_wildcard_allows_allowed_suffix(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "baz.allowed").await?;
        assert_dns_allowed(&resp, cfg.up_dp_ip)?;
        Ok(())
    })
}

fn dns_deny_overrides_wildcard(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(client_bind, dns_server, "bar.allowed").await?;
        assert_dns_nxdomain(&resp)?;
        Ok(())
    })
}

fn udp_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let payload_a = b"flow-a";
        let payload_b = b"flow-b";
        let fut_a = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_a,
            std::time::Duration::from_secs(1),
        );
        let fut_b = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_b,
            std::time::Duration::from_secs(1),
        );

        let (resp_a, resp_b) = tokio::join!(fut_a, fut_b);
        let resp_a = resp_a?;
        let resp_b = resp_b?;
        if resp_a != payload_a || resp_b != payload_b {
            return Err("udp multi-flow payload mismatch".to_string());
        }
        Ok(())
    })
}

fn udp_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut sockets = Vec::new();
        for i in 0..8usize {
            let socket = tokio::net::UdpSocket::bind((IpAddr::V4(cfg.client_dp_ip), 0u16))
                .await
                .map_err(|e| format!("udp bind failed: {e}"))?;
            let payload = format!("flow-{i}").into_bytes();
            socket
                .send_to(&payload, udp_server)
                .await
                .map_err(|e| format!("udp send failed: {e}"))?;
            sockets.push((socket, payload));
        }

        let mut handles = Vec::new();
        for (socket, payload) in sockets {
            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                let (len, _) = tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    socket.recv_from(&mut buf),
                )
                .await
                .map_err(|_| "udp recv timed out".to_string())?
                .map_err(|e| format!("udp recv failed: {e}"))?;
                if buf[..len] != payload[..] {
                    return Err("udp reverse nat payload mismatch".to_string());
                }
                Ok(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("udp task failed: {err}")),
            }
        }

        Ok(())
    })
}

fn tcp_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut handles = Vec::new();
        for i in 0..8usize {
            let path = format!("/echo/flow-{i}");
            let expected = format!("flow-{i}");
            let handle = tokio::spawn(async move {
                let resp = http_get_path(http_addr, "foo.allowed", &path).await?;
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
                if body != expected {
                    return Err(format!("tcp reverse nat mismatch for {path}: {body}"));
                }
                Ok::<(), String>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("tcp task failed: {err}")),
            }
        }

        Ok(())
    })
}

fn https_reverse_nat_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let mut handles = Vec::new();
        for i in 0..8usize {
            let path = format!("/echo/flow-{i}");
            let expected = format!("flow-{i}");
            let handle = tokio::spawn(async move {
                let resp = https_get_path(https_addr, "foo.allowed", &path).await?;
                let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
                if body != expected {
                    return Err(format!("https reverse nat mismatch for {path}: {body}"));
                }
                Ok::<(), String>(())
            });
            handles.push(handle);
        }

        for handle in handles {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => return Err(err),
                Err(err) => return Err(format!("https task failed: {err}")),
            }
        }

        Ok(())
    })
}

fn stream_keeps_nat_alive(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }

        let total = http_stream(
            http_addr,
            "foo.allowed",
            std::time::Duration::from_millis(1500),
            std::time::Duration::from_secs(5),
        )
        .await?;
        if total == 0 {
            return Err("stream returned no data".to_string());
        }
        Ok(())
    })
}

fn dns_allowlist_gc_evicts_idle(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let deny_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)), 9999);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http = http_get(http_addr, "foo.allowed").await?;
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        tokio::time::sleep(std::time::Duration::from_secs(
            cfg.idle_timeout_secs.saturating_add(2),
        ))
        .await;
        let _ = udp_echo(
            udp_bind,
            deny_server,
            b"gc-probe",
            std::time::Duration::from_millis(200),
        )
        .await;
        tokio::time::sleep(allowlist_gc_delay(cfg)).await;

        match http_get(http_addr, "foo.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded after allowlist GC".to_string()),
            Err(_) => Ok(()),
        }
    })
}

fn dns_allowlist_gc_keeps_active_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let stream = tokio::spawn(http_stream_path(
            http_addr,
            "foo.allowed",
            "/stream-long",
            std::time::Duration::from_secs(4),
            std::time::Duration::from_secs(10),
        ));

        tokio::time::sleep(allowlist_gc_delay(cfg)).await;

        let payload = b"gc-keepalive";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }

        match stream.await {
            Ok(Ok(total)) if total > 0 => Ok(()),
            Ok(Ok(_)) => Err("stream returned no data".to_string()),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(format!("stream task failed: {err}")),
        }
    })
}

fn tls_sni_policy(cfg: &TopologyConfig, sni: &str) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-tls-sni"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            sni:
              exact: ["{sni}"]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        sni = sni
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn tls_cert_policy(cfg: &TopologyConfig) -> Result<PolicyConfig, String> {
    tls_cert_policy_with(cfg, "foo.allowed", "deny")
}

fn tls_cert_policy_with(
    cfg: &TopologyConfig,
    san: &str,
    tls13_uninspectable: &str,
) -> Result<PolicyConfig, String> {
    let ca_pem = std::fs::read_to_string(&cfg.upstream_tls_ca_path)
        .map_err(|e| format!("read upstream ca failed: {e}"))?;
    let ca_block = indent_lines(&ca_pem, 16);
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-tls-cert"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: tcp
          dst_ports: [443]
          tls:
            server_san:
              exact: ["{san}"]
            trust_anchors_pem:
              - |
{ca_block}
            tls13_uninspectable: {tls13_uninspectable}
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        san = san,
        ca_block = ca_block,
        tls13_uninspectable = tls13_uninspectable
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn tls_intercept_policy(cfg: &TopologyConfig) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls-intercept"
    sources:
      cidrs: ["{internal}/24"]
    rules:
      - id: "intercept-http"
        action: allow
        match:
          proto: tcp
          dst_ports: [443]
          tls:
            mode: intercept
            http:
              request:
                host:
                  exact: ["foo.allowed"]
                methods: ["GET"]
                path:
                  prefix: ["/external-secrets/"]
"#,
        internal = cfg.client_dp_ip
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn tls_intercept_policy_with_response_deny(cfg: &TopologyConfig) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "tls-intercept"
    sources:
      cidrs: ["{internal}/24"]
    rules:
      - id: "intercept-http"
        action: allow
        match:
          proto: tcp
          dst_ports: [443]
          tls:
            mode: intercept
            http:
              request:
                host:
                  exact: ["foo.allowed"]
                methods: ["GET"]
                path:
                  prefix: ["/external-secrets/"]
              response:
                headers:
                  deny_present: ["x-forbidden"]
"#,
        internal = cfg.client_dp_ip
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

fn first_line(msg: &str) -> &str {
    msg.split("\r\n").next().unwrap_or(msg)
}

fn looks_like_reset(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("reset")
        || lower.contains("broken pipe")
        || lower.contains("refused")
        || lower.contains("closed")
        || lower.contains("timed out")
}

fn indent_lines(value: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    value
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_audit_query(
    policy_id: Option<uuid::Uuid>,
    finding_type: Option<&str>,
    source_group: Option<&str>,
    limit: Option<usize>,
) -> Result<String, String> {
    build_audit_query_with_since(policy_id, finding_type, source_group, None, limit)
}

fn build_audit_query_with_since(
    policy_id: Option<uuid::Uuid>,
    finding_type: Option<&str>,
    source_group: Option<&str>,
    since: Option<u64>,
    limit: Option<usize>,
) -> Result<String, String> {
    let mut params: Vec<(String, String)> = Vec::new();
    if let Some(id) = policy_id {
        params.push(("policy_id".to_string(), id.to_string()));
    }
    if let Some(value) = finding_type {
        params.push(("finding_type".to_string(), value.to_string()));
    }
    if let Some(value) = source_group {
        params.push(("source_group".to_string(), value.to_string()));
    }
    if let Some(value) = since {
        params.push(("since".to_string(), value.to_string()));
    }
    if let Some(value) = limit {
        params.push(("limit".to_string(), value.to_string()));
    }
    serde_urlencoded::to_string(params).map_err(|err| err.to_string())
}

async fn wait_for_audit_findings(
    api_addr: SocketAddr,
    tls_dir: &std::path::Path,
    token: &str,
    query: &str,
    timeout: Duration,
) -> Result<AuditQueryResponse, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match http_get_audit_findings(api_addr, tls_dir, Some(query), Some(token)).await {
            Ok(resp) if !resp.items.is_empty() => return Ok(resp),
            Ok(_) => {}
            Err(err) => {
                if Instant::now() >= deadline {
                    return Err(err);
                }
            }
        }
        if Instant::now() >= deadline {
            let broad = http_get_audit_findings(api_addr, tls_dir, Some("limit=50"), Some(token))
                .await
                .map(|resp| resp.items)
                .unwrap_or_default();
            let typed = http_get_audit_findings(
                api_addr,
                tls_dir,
                Some("finding_type=tls_deny&limit=50"),
                Some(token),
            )
            .await
            .map(|resp| resp.items)
            .unwrap_or_default();
            return Err(format!(
                "timed out waiting for audit findings with query={query}; tls_deny_items={typed:?}; all_items={broad:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn has_audit_finding(
    items: &[AuditFinding],
    finding_type: AuditFindingType,
    source_group: &str,
) -> bool {
    items
        .iter()
        .any(|item| item.finding_type == finding_type && item.source_group == source_group)
}

fn assert_dns_allowed(
    resp: &crate::e2e::services::DnsResponse,
    expected_ip: Ipv4Addr,
) -> Result<(), String> {
    if resp.rcode != 0 {
        return Err(format!("dns response unexpected rcode: {}", resp.rcode));
    }
    if !resp.ips.contains(&IpAddr::V4(expected_ip)) {
        return Err(format!("dns response missing {}", expected_ip));
    }
    Ok(())
}

fn assert_dns_nxdomain(resp: &crate::e2e::services::DnsResponse) -> Result<(), String> {
    if resp.rcode != 3 {
        return Err(format!(
            "dns response expected NXDOMAIN, got rcode {}",
            resp.rcode
        ));
    }
    Ok(())
}

fn send_udp_once(bind: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind(bind).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(payload, dst)
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(())
}

fn send_udp_with_payload_from_port(
    bind_ip: Ipv4Addr,
    bind_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind((bind_ip, bind_port))
        .map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(payload, (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(())
}

fn send_udp_with_ttl(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ttl: u32,
) -> Result<u16, String> {
    let socket =
        std::net::UdpSocket::bind((bind_ip, 0)).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .set_ttl(ttl)
        .map_err(|e| format!("set ttl failed: {e}"))?;
    socket
        .send_to(b"ttl", (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(socket
        .local_addr()
        .map_err(|e| format!("udp local addr failed: {e}"))?
        .port())
}

fn send_udp_with_ttl_payload(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ttl: u32,
    payload: &[u8],
) -> Result<u16, String> {
    let socket =
        std::net::UdpSocket::bind((bind_ip, 0)).map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .set_ttl(ttl)
        .map_err(|e| format!("set ttl failed: {e}"))?;
    socket
        .send_to(payload, (dst_ip, dst_port))
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(socket
        .local_addr()
        .map_err(|e| format!("udp local addr failed: {e}"))?
        .port())
}

fn icmp_echo(bind_ip: Ipv4Addr, dst_ip: Ipv4Addr, timeout: Duration) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        bind_raw_socket(fd, bind_ip)?;
        set_socket_timeout(fd, timeout)?;

        let id = (unsafe { libc::getpid() } as u16) ^ 0x1234;
        let seq = 1u16;
        let mut payload = Vec::new();
        payload.extend_from_slice(b"ping");
        let mut pkt = vec![0u8; 8 + payload.len()];
        pkt[0] = 8;
        pkt[1] = 0;
        pkt[4..6].copy_from_slice(&id.to_be_bytes());
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..].copy_from_slice(&payload);
        let checksum = checksum16(&pkt);
        pkt[2..4].copy_from_slice(&checksum.to_be_bytes());

        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const _,
                pkt.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }

        let mut buf = vec![0u8; 2048];
        loop {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut
                {
                    return Err("icmp echo timed out".to_string());
                }
                return Err(err.to_string());
            }
            let n = n as usize;
            if let Some((ihl, proto, _src, _dst)) = parse_ipv4_header(&buf[..n]) {
                if proto != 1 || n < ihl + 8 {
                    continue;
                }
                let icmp_off = ihl;
                let icmp_type = buf[icmp_off];
                let icmp_code = buf[icmp_off + 1];
                if icmp_type != 0 || icmp_code != 0 {
                    continue;
                }
                let recv_id = u16::from_be_bytes([buf[icmp_off + 4], buf[icmp_off + 5]]);
                let recv_seq = u16::from_be_bytes([buf[icmp_off + 6], buf[icmp_off + 7]]);
                if recv_id == id && recv_seq == seq {
                    return Ok(());
                }
            } else if n >= 8 {
                let icmp_type = buf[0];
                let icmp_code = buf[1];
                if icmp_type != 0 || icmp_code != 0 {
                    continue;
                }
                let recv_id = u16::from_be_bytes([buf[4], buf[5]]);
                let recv_seq = u16::from_be_bytes([buf[6], buf[7]]);
                if recv_id == id && recv_seq == seq {
                    return Ok(());
                }
            }
        }
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

fn open_icmp_socket(bind_ip: Ipv4Addr, timeout: Duration) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

struct UdpPacketInfo {
    src_port: u16,
    payload: Vec<u8>,
}

fn open_tcp_raw_socket(bind_ip: Ipv4Addr, timeout: Duration) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

fn open_udp_raw_socket(bind_ip: Ipv4Addr, timeout: Duration) -> Result<i32, String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if let Err(err) = bind_raw_socket(fd, bind_ip) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    if let Err(err) = set_socket_timeout(fd, timeout) {
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }
    Ok(fd)
}

fn wait_for_udp_packet_on_fd(
    fd: i32,
    expected_src: Ipv4Addr,
    expected_dst: Ipv4Addr,
    expected_dst_port: u16,
    payload_prefix: Option<&[u8]>,
    timeout: Duration,
) -> Result<UdpPacketInfo, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        if Instant::now() >= deadline {
            return Err("udp capture timed out".to_string());
        }
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (ihl, proto, src, dst) = match parse_ipv4_header(&buf[..n]) {
            Some(values) => values,
            None => continue,
        };
        if proto != 17 {
            continue;
        }
        if src != expected_src || dst != expected_dst {
            continue;
        }
        if n < 9 {
            continue;
        }
        let udp_off = ihl;
        if n < udp_off + 8 {
            continue;
        }
        let src_port = u16::from_be_bytes([buf[udp_off], buf[udp_off + 1]]);
        let dst_port = u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
        if dst_port != expected_dst_port {
            continue;
        }
        let payload = buf[udp_off + 8..n].to_vec();
        if let Some(prefix) = payload_prefix {
            if !payload.starts_with(prefix) {
                continue;
            }
        }
        return Ok(UdpPacketInfo { src_port, payload });
    }
}

fn wait_for_tcp_rst_on_fd(
    fd: i32,
    expected_src: Ipv4Addr,
    expected_dst: Ipv4Addr,
    expected_src_port: Option<u16>,
    expected_dst_port: Option<u16>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    let mut last_non_rst: Option<(u8, u16, u16)> = None;
    loop {
        if Instant::now() >= deadline {
            return Err(match last_non_rst {
                Some((flags, src_port, dst_port)) => format!(
                    "tcp rst capture timed out (last flags=0x{flags:02x}, src_port={src_port}, dst_port={dst_port})"
                ),
                None => "tcp rst capture timed out".to_string(),
            });
        }
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (ihl, proto, src, dst) = match parse_ipv4_header(&buf[..n]) {
            Some(values) => values,
            None => continue,
        };
        if proto != 6 || src != expected_src || dst != expected_dst {
            continue;
        }
        if n < ihl + 20 {
            continue;
        }
        let tcp_off = ihl;
        let data_offset = ((buf[tcp_off + 12] >> 4) as usize) * 4;
        if data_offset < 20 || n < tcp_off + data_offset {
            continue;
        }
        let src_port = u16::from_be_bytes([buf[tcp_off], buf[tcp_off + 1]]);
        let dst_port = u16::from_be_bytes([buf[tcp_off + 2], buf[tcp_off + 3]]);
        if let Some(port) = expected_src_port {
            if src_port != port {
                continue;
            }
        }
        if let Some(port) = expected_dst_port {
            if dst_port != port {
                continue;
            }
        }
        let flags = buf[tcp_off + 13];
        if (flags & 0x04) != 0 {
            return Ok(());
        }
        last_non_rst = Some((flags, src_port, dst_port));
    }
}

fn wait_for_icmp_time_exceeded_on_fd(
    fd: i32,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    expected_outer_src: Option<Ipv4Addr>,
) -> Result<(), String> {
    let mut buf = vec![0u8; 2048];
    let mut last_unexpected: Option<(Ipv4Addr, Ipv4Addr)> = None;
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                return Err(match last_unexpected {
                    Some((src, dst)) => format!(
                        "icmp time exceeded timed out (last outer src={}, dst={})",
                        src, dst
                    ),
                    None => "icmp time exceeded timed out".to_string(),
                });
            }
            return Err(err.to_string());
        }
        let n = n as usize;
        let (icmp_off, inner_off, outer_src, outer_dst) =
            if let Some((ihl, proto, src, dst)) = parse_ipv4_header(&buf[..n]) {
                if proto != 1 || n < ihl + 8 {
                    continue;
                }
                (ihl, ihl + 8, Some(src), Some(dst))
            } else {
                if n < 8 {
                    continue;
                }
                (0usize, 8usize, None, None)
            };
        let icmp_type = buf[icmp_off];
        let icmp_code = buf[icmp_off + 1];
        if icmp_type != 11 || icmp_code != 0 {
            continue;
        }
        if n < inner_off + 20 {
            continue;
        }
        let inner_ihl = ((buf[inner_off] & 0x0f) as usize) * 4;
        if inner_ihl < 20 || n < inner_off + inner_ihl + 8 {
            continue;
        }
        let inner_proto = buf[inner_off + 9];
        if inner_proto != 17 {
            continue;
        }
        let inner_src = Ipv4Addr::new(
            buf[inner_off + 12],
            buf[inner_off + 13],
            buf[inner_off + 14],
            buf[inner_off + 15],
        );
        let inner_dst = Ipv4Addr::new(
            buf[inner_off + 16],
            buf[inner_off + 17],
            buf[inner_off + 18],
            buf[inner_off + 19],
        );
        if inner_src != src_ip || inner_dst != dst_ip {
            continue;
        }
        let udp_off = inner_off + inner_ihl;
        let inner_src_port = u16::from_be_bytes([buf[udp_off], buf[udp_off + 1]]);
        let inner_dst_port = u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
        if inner_src_port == src_port && inner_dst_port == dst_port {
            if let (Some(expected), Some(actual_src), Some(actual_dst)) =
                (expected_outer_src, outer_src, outer_dst)
            {
                if actual_src != expected {
                    last_unexpected = Some((actual_src, actual_dst));
                    continue;
                }
            }
            return Ok(());
        }
    }
}

fn send_ipv4_udp_fragment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        let hdrincl: libc::c_int = 1;
        let opt = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &hdrincl as *const _ as *const _,
                mem::size_of::<libc::c_int>() as u32,
            )
        };
        if opt < 0 {
            return Err(io::Error::last_os_error().to_string());
        }

        let total_len = 20 + 8 + payload.len();
        let mut buf = vec![0u8; total_len];
        buf[0] = 0x45;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        buf[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        buf[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        buf[8] = 64;
        buf[9] = 17;
        buf[10..12].copy_from_slice(&0u16.to_be_bytes());
        buf[12..16].copy_from_slice(&src_ip.octets());
        buf[16..20].copy_from_slice(&dst_ip.octets());
        let checksum = checksum16(&buf[..20]);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());

        let udp_off = 20;
        buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = (8 + payload.len()) as u16;
        buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
        buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());
        buf[udp_off + 8..].copy_from_slice(payload);

        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const _,
                buf.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

fn build_icmp_time_exceeded(
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_src_port: u16,
    inner_dst_port: u16,
) -> Vec<u8> {
    let inner_len = 20 + 8;
    let mut buf = vec![0u8; 8 + inner_len];
    buf[0] = 11;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&0u32.to_be_bytes());

    let ip_off = 8;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(inner_len as u16).to_be_bytes());
    buf[ip_off + 4..ip_off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 6..ip_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 8] = 1;
    buf[ip_off + 9] = 17;
    buf[ip_off + 10..ip_off + 12].copy_from_slice(&0u16.to_be_bytes());
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&inner_src.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&inner_dst.octets());

    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&inner_src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&inner_dst_port.to_be_bytes());
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&8u16.to_be_bytes());
    buf[udp_off + 6..udp_off + 8].copy_from_slice(&0u16.to_be_bytes());

    let checksum = checksum16(&buf);
    buf[2..4].copy_from_slice(&checksum.to_be_bytes());
    buf
}

fn send_icmp_time_exceeded(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inner_src: Ipv4Addr,
    inner_dst: Ipv4Addr,
    inner_src_port: u16,
    inner_dst_port: u16,
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        bind_raw_socket(fd, bind_ip)?;
        let pkt = build_icmp_time_exceeded(inner_src, inner_dst, inner_src_port, inner_dst_port);
        let dst = sockaddr_in(dst_ip, 0);
        let sent = unsafe {
            libc::sendto(
                fd,
                pkt.as_ptr() as *const _,
                pkt.len(),
                0,
                &dst as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        Ok(())
    })();
    unsafe {
        libc::close(fd);
    }
    result
}

fn checksum16(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        let value = u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        sum = sum.wrapping_add(value);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add((last as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse_ipv4_header(buf: &[u8]) -> Option<(usize, u8, Ipv4Addr, Ipv4Addr)> {
    if buf.len() < 20 {
        return None;
    }
    if (buf[0] >> 4) != 4 {
        return None;
    }
    let ihl = ((buf[0] & 0x0f) as usize) * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let proto = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some((ihl, proto, src, dst))
}

fn sockaddr_in(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        },
        sin_zero: [0; 8],
    }
}

fn bind_raw_socket(fd: i32, ip: Ipv4Addr) -> Result<(), String> {
    let addr = sockaddr_in(ip, 0);
    let res = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_in>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn set_socket_timeout(fd: i32, timeout: Duration) -> Result<(), String> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const _,
            mem::size_of::<libc::timeval>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn enable_ip_recv_ttl(fd: i32) -> Result<(), String> {
    let opt: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            &opt as *const _ as *const _,
            mem::size_of::<libc::c_int>() as u32,
        )
    };
    if res < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn recv_udp_ttl(fd: i32, timeout: Duration) -> Result<u8, String> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    let mut cmsg_buf = [0u8; 64];
    loop {
        if Instant::now() >= deadline {
            return Err("udp ttl timed out".to_string());
        }
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut _,
            iov_len: buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
        msg.msg_controllen = cmsg_buf.len();
        let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            return Err(err.to_string());
        }
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let cmsg_ref = unsafe { &*cmsg };
            if cmsg_ref.cmsg_level == libc::IPPROTO_IP && cmsg_ref.cmsg_type == libc::IP_TTL {
                let data = unsafe { libc::CMSG_DATA(cmsg) as *const u8 };
                let ttl = unsafe { *data };
                return Ok(ttl);
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }
        return Err("udp ttl missing".to_string());
    }
}

struct DhcpTestServer {
    server_ip: Ipv4Addr,
    server_mac: [u8; 6],
    lease_ip: Ipv4Addr,
    lease_time_secs: u32,
}

impl DhcpTestServer {
    fn new(
        server_ip: Ipv4Addr,
        server_mac: [u8; 6],
        lease_ip: Ipv4Addr,
        lease_time_secs: u32,
    ) -> Self {
        Self {
            server_ip,
            server_mac,
            lease_ip,
            lease_time_secs,
        }
    }

    fn handle_client_frame(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        let (_src_mac, payload) = parse_eth_ipv4_udp_payload(frame)?;
        let dhcp = parse_dhcp_message(payload)?;
        let reply_type = match dhcp.msg_type {
            1 => 2,
            3 => 5,
            _ => return None,
        };
        let reply = build_dhcp_reply(
            reply_type,
            dhcp.xid,
            dhcp.chaddr,
            self.lease_ip,
            self.server_ip,
            self.lease_time_secs,
            Ipv4Addr::new(255, 255, 255, 0),
            self.server_ip,
        );
        let mut frame = build_ipv4_udp_frame(
            self.server_mac,
            [0xff; 6],
            self.server_ip,
            Ipv4Addr::BROADCAST,
            67,
            68,
            &reply,
        );
        frame[0..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&self.server_mac);
        Some(frame)
    }
}

struct DhcpMessage {
    msg_type: u8,
    xid: u32,
    chaddr: [u8; 6],
}

fn parse_eth_ipv4_udp_payload(frame: &[u8]) -> Option<([u8; 6], &[u8])> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    let ihl = (frame[14] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < 14 + ihl + 8 {
        return None;
    }
    let udp_off = 14 + ihl;
    let len = u16::from_be_bytes([frame[udp_off + 4], frame[udp_off + 5]]) as usize;
    if len < 8 || frame.len() < udp_off + len {
        return None;
    }
    let payload_off = udp_off + 8;
    let payload_len = len - 8;
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    Some((src_mac, &frame[payload_off..payload_off + payload_len]))
}

fn parse_dhcp_message(buf: &[u8]) -> Option<DhcpMessage> {
    if buf.len() < 240 {
        return None;
    }
    if buf[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let xid = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut chaddr = [0u8; 6];
    chaddr.copy_from_slice(&buf[28..34]);
    let mut idx = 240;
    let mut msg_type = None;
    while idx < buf.len() {
        let code = buf[idx];
        idx += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            break;
        }
        if idx >= buf.len() {
            return None;
        }
        let len = buf[idx] as usize;
        idx += 1;
        if idx + len > buf.len() {
            return None;
        }
        if code == 53 && len == 1 {
            msg_type = Some(buf[idx]);
        }
        idx += len;
    }
    Some(DhcpMessage {
        msg_type: msg_type?,
        xid,
        chaddr,
    })
}

fn build_dhcp_reply(
    msg_type: u8,
    xid: u32,
    chaddr: [u8; 6],
    yiaddr: Ipv4Addr,
    server_ip: Ipv4Addr,
    lease_time: u32,
    subnet: Ipv4Addr,
    router: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = vec![0u8; 240];
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    buf[3] = 0;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&yiaddr.octets());
    buf[28..34].copy_from_slice(&chaddr);
    buf[236..240].copy_from_slice(&[99, 130, 83, 99]);
    push_option(&mut buf, 53, &[msg_type]);
    push_option(&mut buf, 1, &subnet.octets());
    push_option(&mut buf, 3, &router.octets());
    push_option(&mut buf, 51, &lease_time.to_be_bytes());
    push_option(&mut buf, 54, &server_ip.octets());
    buf.push(255);
    buf
}

fn push_option(buf: &mut Vec<u8>, code: u8, data: &[u8]) {
    buf.push(code);
    buf.push(data.len() as u8);
    buf.extend_from_slice(data);
}

fn build_ipv4_udp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; 14 + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip_off = 14;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 17;
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());
    let udp_off = ip_off + 20;
    buf[udp_off..udp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_off + 2..udp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_off + 8..udp_off + 8 + payload.len()].copy_from_slice(payload);
    buf
}

fn build_ipv4_tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 20 + payload.len();
    let mut buf = vec![0u8; 14 + total_len];
    buf[0..6].copy_from_slice(&dst_mac);
    buf[6..12].copy_from_slice(&src_mac);
    buf[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip_off = 14;
    buf[ip_off] = 0x45;
    buf[ip_off + 1] = 0;
    buf[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[ip_off + 8] = 64;
    buf[ip_off + 9] = 6;
    buf[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip.octets());
    buf[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip.octets());

    let tcp_off = ip_off + 20;
    buf[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    buf[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    buf[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    buf[tcp_off + 12] = 0x50;
    buf[tcp_off + 13] = flags;
    buf[tcp_off + 14..tcp_off + 16].copy_from_slice(&64_240u16.to_be_bytes());
    buf[tcp_off + 20..tcp_off + 20 + payload.len()].copy_from_slice(payload);

    let mut pkt = crate::dataplane::packet::Packet::new(buf);
    let _ = pkt.recalc_checksums();
    pkt.buffer().to_vec()
}

fn parse_ipv4_udp(frame: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16), String> {
    if frame.len() < 14 + 20 + 8 {
        return Err("frame too short".to_string());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err("not ipv4".to_string());
    }
    let ihl = (frame[14] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < 14 + ihl + 8 {
        return Err("invalid ipv4 header".to_string());
    }
    let src = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
    let dst = Ipv4Addr::new(frame[30], frame[31], frame[32], frame[33]);
    let udp_off = 14 + ihl;
    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
    Ok((src, dst, src_port, dst_port))
}

fn parse_ipv4_tcp(frame: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16), String> {
    if frame.len() < 14 + 20 + 20 {
        return Err("frame too short".to_string());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 {
        return Err("not ipv4".to_string());
    }
    let ip_off = 14;
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl + 20 {
        return Err("invalid ipv4 header".to_string());
    }
    if frame[ip_off + 9] != 6 {
        return Err("not tcp".to_string());
    }
    let src = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    let tcp_off = ip_off + ihl;
    let src_port = u16::from_be_bytes([frame[tcp_off], frame[tcp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[tcp_off + 2], frame[tcp_off + 3]]);
    Ok((src, dst, src_port, dst_port))
}

fn build_arp_request(sender_mac: [u8; 6], sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 42];
    buf[0..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(&sender_mac);
    buf[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    buf[14..16].copy_from_slice(&1u16.to_be_bytes());
    buf[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    buf[18] = 6;
    buf[19] = 4;
    buf[20..22].copy_from_slice(&1u16.to_be_bytes());
    buf[22..28].copy_from_slice(&sender_mac);
    buf[28..32].copy_from_slice(&sender_ip.octets());
    buf[32..38].copy_from_slice(&[0u8; 6]);
    buf[38..42].copy_from_slice(&target_ip.octets());
    buf
}

fn assert_arp_reply(
    frame: &[u8],
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Result<(), String> {
    if frame.len() < 42 {
        return Err("arp reply too short".to_string());
    }
    let op = u16::from_be_bytes([frame[20], frame[21]]);
    if op != 2 {
        return Err("not an arp reply".to_string());
    }
    if frame[22..28] != target_mac {
        return Err("arp reply sender mac mismatch".to_string());
    }
    let reply_sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if reply_sender_ip != target_ip {
        return Err("arp reply sender ip mismatch".to_string());
    }
    if frame[32..38] != sender_mac {
        return Err("arp reply target mac mismatch".to_string());
    }
    let reply_target_ip = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
    if reply_target_ip != sender_ip {
        return Err("arp reply target ip mismatch".to_string());
    }
    Ok(())
}

fn overlay_policy_allow_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let policy_yaml = format!(
        r#"
default_policy: deny
source_groups:
  - id: "overlay"
    priority: 0
    sources:
      cidrs: ["{src_cidr}"]
    rules:
      - id: "allow-udp"
        priority: 0
        action: allow
        match:
          dst_ips: ["{dst_ip}"]
          proto: udp
          dst_ports: [{dst_port}]
"#,
        src_cidr = format!("{}/24", cfg.client_dp_ip),
        dst_ip = cfg.up_dp_ip,
        dst_port = cfg.up_udp_port
    );
    let policy: PolicyConfig =
        serde_yaml::from_str(&policy_yaml).map_err(|e| format!("policy yaml error: {e}"))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(
            api_addr,
            &tls_dir,
            policy,
            PolicyMode::Enforce,
            Some(&token),
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        Ok::<(), String>(())
    })?;
    Ok(())
}

fn overlay_metrics_snapshot(metrics_addr: SocketAddr) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    match runtime {
        Ok(rt) => rt
            .block_on(async { http_get_path(metrics_addr, "metrics", "/metrics").await })
            .unwrap_or_else(|e| format!("metrics fetch failed: {e}")),
        Err(e) => format!("metrics runtime error: {e}"),
    }
}

fn overlay_debug_snapshot(cfg: &TopologyConfig) -> String {
    fn run_cmd(cmd: &str, args: &[&str]) -> String {
        let display = if args.is_empty() {
            cmd.to_string()
        } else {
            format!("{cmd} {}", args.join(" "))
        };
        match Command::new(cmd).args(args).output() {
            Ok(output) => format!(
                "$ {display}\nstatus: {}\nstdout:\n{}\nstderr:\n{}\n",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(err) => format!("$ {display}\nerror: {err}\n"),
        }
    }

    let mut out = String::new();
    let fw_ns = "fw-node";
    let dp0 = cfg.dp_tun_iface.as_str();
    let fw_dp = cfg.fw_dp_iface.as_str();
    let outer_dst = cfg.dp_public_ip.to_string();
    let inner_src = cfg.client_dp_ip.to_string();

    let cmds: Vec<(&str, Vec<&str>)> = vec![
        ("ip", vec!["netns", "exec", fw_ns, "ip", "-4", "rule"]),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "show", "table", "100",
            ],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-4", "route", "show"],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-s", "link", "show", dp0],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "ip", "-s", "link", "show", fw_dp],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "addr", "show", "dev", dp0,
            ],
        ),
        (
            "ip",
            vec!["netns", "exec", fw_ns, "sysctl", "net.ipv4.ip_forward"],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "get", &outer_dst, "iif", fw_dp,
            ],
        ),
        (
            "ip",
            vec![
                "netns", "exec", fw_ns, "ip", "-4", "route", "get", &inner_src, "iif", dp0,
            ],
        ),
    ];

    for (cmd, args) in cmds {
        out.push_str(&run_cmd(cmd, &args));
    }
    out
}

fn netns_read_u64(ns: &str, path: &str) -> Option<u64> {
    let output = Command::new("ip")
        .args(["netns", "exec", ns, "cat", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout);
    value.trim().parse::<u64>().ok()
}

fn dp_iface_rx_packets(cfg: &TopologyConfig) -> Option<u64> {
    let path = format!("/sys/class/net/{}/statistics/rx_packets", cfg.dp_tun_iface);
    netns_read_u64("fw-node", &path)
}

fn overlay_vxlan_round_trip(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let inner_payload = b"overlay-vxlan";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40000,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;

    let send_port = 5555u16;
    let outer_dst_ip = cfg.dp_public_ip;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, send_port))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (outer_dst_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, src) = match recv_socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
                let metrics = overlay_metrics_snapshot(metrics_addr);
                let in_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "in")],
                )
                .unwrap_or(0.0);
                let out_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "vxlan"), ("direction", "out")],
                )
                .unwrap_or(0.0);
                let decap_err =
                    metric_plain_value(&metrics, "overlay_decap_errors_total").unwrap_or(0.0);
                let encap_err =
                    metric_plain_value(&metrics, "overlay_encap_errors_total").unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                return Err(format!(
                    "overlay recv failed: {err} (overlay_packets in={}, out={}, decap_errors={}, encap_errors={})\n-- overlay debug --\n{debug}",
                    in_count, out_count, decap_err, encap_err
                ));
            }
            return Err(format!("overlay recv failed: {err}"));
        }
    };
    if src.ip() != IpAddr::V4(outer_dst_ip) {
        return Err(format!("unexpected overlay src ip: {}", src.ip()));
    }
    if src.port() != send_port {
        return Err(format!("unexpected overlay src port: {}", src.port()));
    }
    let (vni, inner_buf) = parse_vxlan_payload(&buf[..n])?;
    if vni != cfg.overlay_vxlan_vni {
        return Err(format!("vxlan vni mismatch: {vni}"));
    }
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_inner_ipv4_udp(inner_buf)?;
    if src_ip != cfg.client_dp_ip || dst_ip != cfg.up_dp_ip {
        return Err("inner ip mismatch".to_string());
    }
    if src_port != 40000 || dst_port != cfg.up_udp_port {
        return Err("inner port mismatch".to_string());
    }
    if payload != inner_payload {
        return Err("inner payload mismatch".to_string());
    }
    Ok(())
}

fn overlay_vxlan_wrong_vni_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-vxlan-bad-vni";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x03],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x04],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40100,
        cfg.up_udp_port,
        inner_payload,
    );
    let bad_vni = cfg.overlay_vxlan_vni.wrapping_add(1);
    let payload = build_vxlan_payload(&inner, bad_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5601))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for wrong vni".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_vxlan_wrong_port_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-vxlan-bad-port";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x05],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x06],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40101,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);
    let wrong_port = cfg.overlay_vxlan_port.wrapping_add(1);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5602))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, wrong_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for wrong port".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_vxlan_mtu_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);

    let payload_len = 1250usize;
    let inner_payload = vec![0xa5u8; payload_len];
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x07],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x08],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40102,
        cfg.up_udp_port,
        &inner_payload,
    );
    let payload = build_vxlan_payload(&inner, cfg.overlay_vxlan_vni);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5603))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_vxlan_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected vxlan response for mtu drop".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(150));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay mtu drops did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_round_trip(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let inner_payload = b"overlay-geneve";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x11],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x22],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40001,
        cfg.up_udp_port,
        inner_payload,
    );
    let options = vec![0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04];
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &options)?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;

    let send_port = 5556u16;
    let outer_dst_ip = cfg.dp_public_ip;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, send_port))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (outer_dst_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    let (n, src) = match recv_socket.recv_from(&mut buf) {
        Ok(value) => value,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
            {
                let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
                let metrics = overlay_metrics_snapshot(metrics_addr);
                let in_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "geneve"), ("direction", "in")],
                )
                .unwrap_or(0.0);
                let out_count = metric_value_with_labels(
                    &metrics,
                    "overlay_packets_total",
                    &[("mode", "geneve"), ("direction", "out")],
                )
                .unwrap_or(0.0);
                let decap_err =
                    metric_plain_value(&metrics, "overlay_decap_errors_total").unwrap_or(0.0);
                let encap_err =
                    metric_plain_value(&metrics, "overlay_encap_errors_total").unwrap_or(0.0);
                let debug = overlay_debug_snapshot(cfg);
                return Err(format!(
                    "overlay recv failed: {err} (overlay_packets in={}, out={}, decap_errors={}, encap_errors={})\n-- overlay debug --\n{debug}",
                    in_count, out_count, decap_err, encap_err
                ));
            }
            return Err(format!("overlay recv failed: {err}"));
        }
    };
    if src.ip() != IpAddr::V4(outer_dst_ip) {
        return Err(format!("unexpected overlay src ip: {}", src.ip()));
    }
    if src.port() != send_port {
        return Err(format!("unexpected overlay src port: {}", src.port()));
    }
    let (vni, opts, inner_buf) = parse_geneve_payload(&buf[..n])?;
    if vni != cfg.overlay_geneve_vni {
        return Err(format!("geneve vni mismatch: {vni}"));
    }
    if opts != options {
        return Err("geneve options mismatch".to_string());
    }
    let (src_ip, dst_ip, src_port, dst_port, payload) = parse_inner_ipv4_udp(inner_buf)?;
    if src_ip != cfg.client_dp_ip || dst_ip != cfg.up_dp_ip {
        return Err("inner ip mismatch".to_string());
    }
    if src_port != 40001 || dst_port != cfg.up_udp_port {
        return Err("inner port mismatch".to_string());
    }
    if payload != inner_payload {
        return Err("inner payload mismatch".to_string());
    }
    Ok(())
}

fn overlay_geneve_wrong_vni_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-geneve-bad-vni";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x13],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x14],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40110,
        cfg.up_udp_port,
        inner_payload,
    );
    let bad_vni = cfg.overlay_geneve_vni.wrapping_add(1);
    let payload = build_geneve_payload(&inner, bad_vni, &[])?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5604))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for wrong vni".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_wrong_port_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);

    let inner_payload = b"overlay-geneve-bad-port";
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x15],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x16],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40111,
        cfg.up_udp_port,
        inner_payload,
    );
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &[])?;
    let wrong_port = cfg.overlay_geneve_port.wrapping_add(1);

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_millis(400)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5605))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, wrong_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for wrong port".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(100));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_decap_errors_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay decap errors did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn overlay_geneve_mtu_drop(cfg: &TopologyConfig) -> Result<(), String> {
    overlay_policy_allow_udp(cfg)?;
    let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
    let before = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);

    let payload_len = 1250usize;
    let inner_payload = vec![0x5au8; payload_len];
    let inner = build_ipv4_udp_frame(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x17],
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x18],
        cfg.client_dp_ip,
        cfg.up_dp_ip,
        40112,
        cfg.up_udp_port,
        &inner_payload,
    );
    let payload = build_geneve_payload(&inner, cfg.overlay_geneve_vni, &[])?;

    let recv_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay recv bind failed: {e}"))?;
    recv_socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|e| format!("overlay recv timeout failed: {e}"))?;
    let send_socket = std::net::UdpSocket::bind((cfg.client_dp_ip, 5606))
        .map_err(|e| format!("overlay send bind failed: {e}"))?;
    send_socket
        .send_to(&payload, (cfg.dp_public_ip, cfg.overlay_geneve_port))
        .map_err(|e| format!("overlay send failed: {e}"))?;

    let mut buf = vec![0u8; 2048];
    match recv_socket.recv_from(&mut buf) {
        Ok(_) => return Err("unexpected geneve response for mtu drop".to_string()),
        Err(err)
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut => {}
        Err(err) => return Err(format!("overlay recv failed: {err}")),
    }

    std::thread::sleep(Duration::from_millis(150));
    let after = metric_plain_value(
        &overlay_metrics_snapshot(metrics_addr),
        "overlay_mtu_drops_total",
    )
    .unwrap_or(0.0);
    if after < before + 1.0 {
        return Err(format!(
            "overlay mtu drops did not increment (before={}, after={})",
            before, after
        ));
    }
    Ok(())
}

fn build_vxlan_payload(inner: &[u8], vni: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 8 + inner.len()];
    buf[0] = 0x08;
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[8..].copy_from_slice(inner);
    buf
}

fn build_geneve_payload(inner: &[u8], vni: u32, options: &[u8]) -> Result<Vec<u8>, String> {
    if options.len() % 4 != 0 {
        return Err("geneve options must be a multiple of 4 bytes".to_string());
    }
    let opt_len_words = (options.len() / 4) as u8;
    let header_len = 8 + options.len();
    let mut buf = vec![0u8; header_len + inner.len()];
    buf[0] = opt_len_words & 0x3f;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&0x6558u16.to_be_bytes());
    buf[4] = ((vni >> 16) & 0xff) as u8;
    buf[5] = ((vni >> 8) & 0xff) as u8;
    buf[6] = (vni & 0xff) as u8;
    buf[7] = 0;
    buf[8..header_len].copy_from_slice(options);
    buf[header_len..].copy_from_slice(inner);
    Ok(buf)
}

fn parse_vxlan_payload(buf: &[u8]) -> Result<(u32, &[u8]), String> {
    if buf.len() < 8 {
        return Err("vxlan payload too short".to_string());
    }
    if buf[0] & 0x08 == 0 {
        return Err("vxlan invalid flags".to_string());
    }
    let vni = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
    Ok((vni, &buf[8..]))
}

fn parse_geneve_payload(buf: &[u8]) -> Result<(u32, Vec<u8>, &[u8]), String> {
    if buf.len() < 8 {
        return Err("geneve payload too short".to_string());
    }
    let ver = buf[0] >> 6;
    if ver != 0 {
        return Err("geneve version mismatch".to_string());
    }
    let opt_len = (buf[0] & 0x3f) as usize * 4;
    let header_len = 8 + opt_len;
    if buf.len() < header_len {
        return Err("geneve options truncated".to_string());
    }
    let proto = u16::from_be_bytes([buf[2], buf[3]]);
    if proto != 0x6558 {
        return Err("geneve proto mismatch".to_string());
    }
    let vni = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
    let options = buf[8..header_len].to_vec();
    Ok((vni, options, &buf[header_len..]))
}

fn parse_inner_ipv4_udp(frame: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr, u16, u16, Vec<u8>), String> {
    let ip_off = if frame.len() >= 14 {
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype == 0x0800 {
            14
        } else {
            0
        }
    } else {
        0
    };
    if frame.len() < ip_off + 20 {
        return Err("inner ipv4 too short".to_string());
    }
    if (frame[ip_off] >> 4) != 4 {
        return Err("inner not ipv4".to_string());
    }
    let ihl = (frame[ip_off] & 0x0f) as usize * 4;
    if ihl < 20 || frame.len() < ip_off + ihl + 8 {
        return Err("inner ipv4 header invalid".to_string());
    }
    if frame[ip_off + 9] != 17 {
        return Err("inner not udp".to_string());
    }
    let src = Ipv4Addr::new(
        frame[ip_off + 12],
        frame[ip_off + 13],
        frame[ip_off + 14],
        frame[ip_off + 15],
    );
    let dst = Ipv4Addr::new(
        frame[ip_off + 16],
        frame[ip_off + 17],
        frame[ip_off + 18],
        frame[ip_off + 19],
    );
    let udp_off = ip_off + ihl;
    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
    let len = u16::from_be_bytes([frame[udp_off + 4], frame[udp_off + 5]]) as usize;
    if len < 8 || frame.len() < udp_off + len {
        return Err("inner udp length invalid".to_string());
    }
    let payload = frame[udp_off + 8..udp_off + len].to_vec();
    Ok((src, dst, src_port, dst_port, payload))
}
