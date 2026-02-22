use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use crate::controlplane::api_auth;
use crate::controlplane::dhcp::{DhcpClient, DhcpClientConfig};
use crate::controlplane::service_accounts::{ServiceAccountStatus, TokenStatus};
use crate::controlplane::cluster::rpc::{AuthClient, RaftTlsConfig};
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::policy_config::{DnsPolicy, PolicyConfig, PolicyMode, PolicyValue};
use crate::controlplane::policy_repository::{PolicyActive, PolicyRecord};
use crate::controlplane::PolicyStore;
use crate::dataplane::config::DataplaneConfigStore;
use crate::dataplane::policy::{
    CidrV4, DefaultPolicy, IpSetV4, Proto, Rule, RuleAction, RuleMatch, SourceGroup,
};
use crate::dataplane::{DpdkAdapter, EngineState};
use crate::e2e::services::{
    dns_query, dns_query_response, http_api_health, http_api_status, http_auth_token_login,
    http_api_client_with_cookie, http_api_post_raw, http_auth_whoami, http_create_service_account, http_create_service_account_token,
    http_delete_policy, http_delete_service_account, http_get, http_get_dns_cache, http_get_path,
    http_get_policy, http_get_stats, http_list_policies, http_list_service_account_tokens,
    http_list_service_accounts, http_revoke_service_account_token, http_set_policy, http_stream,
    http_stream_path, http_update_policy, http_wait_for_health, https_get, https_get_path,
    https_get_tls12, https_get_tls13, tls_client_hello_raw, udp_echo,
};
use crate::e2e::topology::TopologyConfig;
use ::time::format_description::well_known::Rfc3339;
use ::time::Duration as TimeDuration;
use ::time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::net::TcpSocket;
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
            name: "api_audit_policy_listed",
            func: api_audit_policy_listed,
        },
        TestCase {
            name: "api_audit_does_not_override",
            func: api_audit_does_not_override,
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
            name: "icmp_ttl_exceeded",
            func: icmp_ttl_exceeded,
        },
        TestCase {
            name: "ipv4_fragment_drop_metrics",
            func: ipv4_fragment_drop_metrics,
        },
        TestCase {
            name: "nat_idle_eviction_metrics",
            func: nat_idle_eviction_metrics,
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
            name: "cluster_policy_update_applies",
            func: cluster_policy_update_applies,
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
        let user = resp
            .json::<crate::e2e::services::AuthUser>()
            .await
            .map_err(|e| format!("auth token-login decode failed: {e}"))?;
        if user.sub != "e2e" {
            return Err(format!("unexpected token-login sub {}", user.sub));
        }
        let whoami = client
            .get(format!("https://{api_addr}/api/v1/auth/whoami"))
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

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&token_resp.token)).await?;
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
            if tokens.iter().any(|item| item.id == token_resp.token_meta.id) {
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
            if let Some(token) = tokens.iter().find(|item| item.id == token_resp.token_meta.id) {
                if token.status == TokenStatus::Revoked {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("token was not revoked".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let status =
            http_api_status(api_addr, &tls_dir, "/api/v1/policies", Some(&token_resp.token)).await?;
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
            let accounts = http_list_service_accounts(api_addr, &tls_dir, Some(&admin_token)).await?;
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

        policy_store.rebuild(vec![group], DnsPolicy::new(Vec::new()), Some(DefaultPolicy::Deny));

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

        let drain_task = tokio::spawn(async move {
            while cp_to_dp_rx.recv().await.is_some() {}
        });

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

fn api_audit_does_not_override(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let token = api_auth_token(cfg)?;
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let audit_policy = parse_policy(
        r#"default_policy: deny
source_groups:
  - id: "client-primary"
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "audit-allow"
        mode: audit
        action: allow
        match:
          dns_hostname: '^baz\.blocked$'
"#,
    )?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, audit_policy, PolicyMode::Audit, Some(&token)).await?;
        let resp = dns_query_response(client_bind, dns_server, "baz.blocked").await?;
        if resp.rcode != 3 {
            return Err("audit policy unexpectedly changed enforcement".to_string());
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
        let record =
            http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        let _ =
            http_set_policy(api_addr, &tls_dir, audit_policy, PolicyMode::Audit, Some(&token))
                .await?;
        let after_audit = read_active_id(&active_path)?;
        if after_audit != baseline {
            return Err("audit policy changed active id".to_string());
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

        let fetched = http_get_policy(api_addr, &tls_dir, &record.id.to_string(), Some(&token))
            .await?;
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
        let _ = http_set_policy(api_addr, &tls_dir, policy_a, PolicyMode::Audit, Some(&token))
            .await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _ = http_set_policy(api_addr, &tls_dir, policy_b, PolicyMode::Audit, Some(&token))
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
        let status = http_api_post_raw(
            api_addr,
            &tls_dir,
            "/api/v1/policies",
            body,
            Some(&token),
        )
        .await?;
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

        let dns_nxdomain = metric_value_with_labels(
            &body,
            "dns_nxdomain_total",
            &[("source", "policy")],
        )
        .ok_or_else(|| "missing dns nxdomain metrics".to_string())?;
        if dns_nxdomain < 1.0 {
            return Err("dns nxdomain metrics did not increment".to_string());
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
        return Err(format!(
            "node.key permissions too permissive: {:o}",
            mode
        ));
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
    let policy: PolicyConfig = serde_yaml::from_str(&policy_yaml)
        .map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        Ok::<(), String>(())
    })?;

    icmp_echo(cfg.client_dp_ip, cfg.up_dp_ip, Duration::from_secs(2))?;
    Ok(())
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
    let policy: PolicyConfig = serde_yaml::from_str(&policy_yaml)
        .map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        let before_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
        let before = metric_plain_value(&before_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);

        let src_port =
            send_udp_with_ttl(cfg.client_dp_ip, cfg.up_dp_ip, dst_port, 2)?;

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let after_body = http_get_path(metrics_addr, "metrics", "/metrics").await?;
            let after = metric_plain_value(&after_body, "dp_ipv4_ttl_exceeded_total").unwrap_or(0.0);
            if after >= before + 1.0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err("ttl exceeded metrics did not increment".to_string());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let _ = wait_for_icmp_time_exceeded(
            cfg.client_dp_ip,
            cfg.client_dp_ip,
            cfg.up_dp_ip,
            src_port,
            dst_port,
            Duration::from_millis(300),
        );

        Ok(())
    })
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
    let policy: PolicyConfig = serde_yaml::from_str(&policy_yaml)
        .map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;

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
        let baseline_closes = metric_value_with_labels(
            &body,
            "dp_flow_closes_total",
            &[("reason", "idle_timeout")],
        )
        .unwrap_or(0.0);

        let udp_server_alt = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip_alt), cfg.up_udp_port);
        let resp = udp_echo(client_bind, udp_server_alt, payload, Duration::from_millis(500)).await?;
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
    let policy: PolicyConfig = serde_yaml::from_str(&policy_yaml)
        .map_err(|e| format!("policy yaml error: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
                cfg.dp_public_ip, whoami.trim()
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
          dns_hostname: '^spoof\.allowed$'
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

fn metric_value_with_labels(
    body: &str,
    metric: &str,
    labels: &[(&str, &str)],
) -> Option<f64> {
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
    response
        .splitn(2, "\r\n\r\n")
        .nth(1)
        .unwrap_or("")
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        match https_get_tls13(https_addr, "foo.allowed").await {
            Ok(_) => Err("https unexpectedly succeeded on tls1.3 with cert constraints".to_string()),
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;
        tokio::time::sleep(cfg.allowlist_eviction_delay()).await;
        let read = tls_client_hello_raw(https_addr, "foo.allowed", 2000).await?;
        if read == 0 {
            return Err("tls raw client hello did not receive response".to_string());
        }
        Ok(())
    })
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
        http_set_policy(api_addr, &tls_dir, policy, PolicyMode::Enforce, Some(&token)).await?;

        let resp = dns_query_response(client_bind, dns_server, "spoof.allowed").await?;
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
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let resp = dns_query_response(
            client_bind,
            dns_server,
            "very.long.subdomain.name.example.com",
        )
        .await?;
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

fn first_line(msg: &str) -> &str {
    msg.split("\r\n").next().unwrap_or(msg)
}

fn indent_lines(value: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    value
        .lines()
        .map(|line| format!("{pad}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
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

fn send_udp_once(
    bind: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind(bind)
        .map_err(|e| format!("udp bind failed: {e}"))?;
    socket
        .send_to(payload, dst)
        .map_err(|e| format!("udp send failed: {e}"))?;
    Ok(())
}

fn send_udp_with_ttl(
    bind_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    ttl: u32,
) -> Result<u16, String> {
    let socket = std::net::UdpSocket::bind((bind_ip, 0))
        .map_err(|e| format!("udp bind failed: {e}"))?;
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
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
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

fn wait_for_icmp_time_exceeded(
    bind_ip: Ipv4Addr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    timeout: Duration,
) -> Result<(), String> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if fd < 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        bind_raw_socket(fd, bind_ip)?;
        set_socket_timeout(fd, timeout)?;
        let mut buf = vec![0u8; 2048];
        loop {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut
                {
                    return Err("icmp time exceeded timed out".to_string());
                }
                return Err(err.to_string());
            }
            let n = n as usize;
            let (icmp_off, inner_off) = if let Some((ihl, proto, _src, _dst)) =
                parse_ipv4_header(&buf[..n])
            {
                if proto != 1 || n < ihl + 8 {
                    continue;
                }
                (ihl, ihl + 8)
            } else {
                if n < 8 {
                    continue;
                }
                (0usize, 8usize)
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
            let inner_src_port =
                u16::from_be_bytes([buf[udp_off], buf[udp_off + 1]]);
            let inner_dst_port =
                u16::from_be_bytes([buf[udp_off + 2], buf[udp_off + 3]]);
            if inner_src_port == src_port && inner_dst_port == dst_port {
                return Ok(());
            }
        }
    })();
    unsafe {
        libc::close(fd);
    }
    result
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

fn build_arp_request(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Vec<u8> {
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
