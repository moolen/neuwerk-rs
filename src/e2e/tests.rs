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

mod api_auth_cases;
mod api_cases;
mod case_catalog;
mod dns_flow_cases;
mod dpdk_cases;
mod helpers;
mod overlay;
mod tls_cases;
mod traffic_cases;
use api_auth_cases::*;
use api_cases::*;
pub use case_catalog::cases;
use dns_flow_cases::*;
use dpdk_cases::*;
use helpers::*;
pub use overlay::{overlay_cases_geneve, overlay_cases_vxlan, overlay_cases_vxlan_dual_tunnel};
use tls_cases::*;
use traffic_cases::*;
