use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use axum::http::{Request, Response, StatusCode};
use base64::Engine;
use bytes::Bytes;
use h2::{client, server};
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyUsagePurpose};
use reqwest::Client;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::controlplane::audit::AuditQueryResponse;
use crate::controlplane::dns_proxy::extract_ips_from_dns_response;
use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
use crate::controlplane::policy_repository::{PolicyCreateRequest, PolicyRecord};
use crate::controlplane::service_accounts::{ServiceAccount, TokenMeta};

mod dns;
mod http_api;
mod models;
mod server_runtime;
mod tls;
mod udp;
mod upstream;

pub use dns::{dns_query, dns_query_response, dns_query_response_tcp, DnsResponse};
pub use http_api::{
    http_api_client_with_cookie, http_api_health, http_api_post_raw, http_api_put_raw,
    http_api_status, http_auth_token_login, http_auth_whoami, http_create_service_account,
    http_create_service_account_token, http_delete_policy, http_delete_service_account,
    http_delete_tls_intercept_ca, http_get, http_get_audit_findings, http_get_dns_cache,
    http_get_path, http_get_policy, http_get_policy_by_name, http_get_stats, http_list_policies,
    http_list_service_account_tokens, http_list_service_accounts,
    http_put_tls_intercept_ca_from_http_ca, http_revoke_service_account_token, http_set_policy,
    http_stream, http_stream_path, http_update_policy, http_update_service_account,
    http_upsert_policy_by_name, http_wait_for_health,
};
pub use models::{AuthUser, DnsCacheEntry, DnsCacheResponse};
#[cfg(test)]
pub(crate) use server_runtime::run_https_server;
pub use tls::{
    https_get, https_get_path, https_get_tls12, https_get_tls13, https_h2_get_path,
    https_h2_preface, https_leaf_cert_sha256, tls_client_hello_raw,
};
pub use udp::{udp_echo, udp_echo_eventually};
pub use upstream::{generate_upstream_tls_material, UpstreamServices, UpstreamTlsMaterial};

#[cfg(test)]
mod tests;
