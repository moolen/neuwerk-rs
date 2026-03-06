use std::collections::BTreeSet;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Json;
use openraft::RaftMetrics;
use reqwest::{Certificate as ReqwestCertificate, Client};
use serde::Deserialize;
use serde_json::json;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::controlplane::api_auth;
use crate::controlplane::audit::{AuditQueryResponse, AuditStore};
use crate::controlplane::cluster::bootstrap;
use crate::controlplane::cluster::config::ClusterConfig;
use crate::controlplane::cluster::migration;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterCommand;
use crate::controlplane::cluster::types::ClusterTypeConfig;
use crate::controlplane::dns_proxy::run_dns_proxy;
use crate::controlplane::http_api::{run_http_api, HttpApiCluster, HttpApiConfig};
use crate::controlplane::http_tls::{ensure_http_tls, HttpTlsConfig};
use crate::controlplane::integrations::IntegrationStore;
use crate::controlplane::intercept_tls::{
    local_intercept_ca_paths, INTERCEPT_CA_CERT_KEY, INTERCEPT_CA_ENVELOPE_KEY,
};
use crate::controlplane::kubernetes::run_kubernetes_resolver;
use crate::controlplane::metrics::Metrics;
use crate::controlplane::policy_config::{PolicyConfig, PolicyMode};
use crate::controlplane::policy_repository::{
    policy_item_key, PolicyCreateRequest, PolicyDiskStore, PolicyRecord, POLICY_ACTIVE_KEY,
    POLICY_INDEX_KEY,
};
use crate::controlplane::service_accounts::{
    ServiceAccount, ServiceAccountDiskStore, ServiceAccountStatus, TokenMeta, TokenStatus,
};
use crate::controlplane::wiretap::DnsMap;
use crate::controlplane::PolicyStore;
use crate::dataplane::config::DataplaneConfig;
use crate::dataplane::policy::{DefaultPolicy, DynamicIpSetV4};
use crate::dataplane::{handle_packet, Action, EngineState, Packet};
use crate::e2e::services::dns_query_response;
use crate::e2e::topology::Topology;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

mod api_cases;
use api_cases::*;
mod core_cases;
use core_cases::*;
mod failover_cases;
use failover_cases::*;
mod helpers;
use helpers::*;
mod kubernetes_failover_case;
use kubernetes_failover_case::*;
mod migration_cases;
use migration_cases::*;

struct ClusterCase {
    name: &'static str,
    func: fn() -> Result<(), String>,
}

pub fn run(topology: &Topology) -> Result<(), String> {
    for case in cases() {
        println!("running cluster case: {}", case.name);
        topology
            .fw()
            .run(|_| (case.func)())
            .map_err(|e| format!("{e}"))??;
    }
    Ok(())
}

fn cases() -> Vec<ClusterCase> {
    vec![
        ClusterCase {
            name: "cluster_mtls_enforced",
            func: cluster_mtls_enforced,
        },
        ClusterCase {
            name: "http_tls_ca_replication_joiner",
            func: http_tls_ca_replication_joiner,
        },
        ClusterCase {
            name: "http_tls_ca_persists_restart",
            func: http_tls_ca_persists_restart,
        },
        ClusterCase {
            name: "cluster_migrate_from_local_enforce",
            func: cluster_migrate_from_local_enforce,
        },
        ClusterCase {
            name: "cluster_migrate_from_local_audit",
            func: cluster_migrate_from_local_audit,
        },
        ClusterCase {
            name: "cluster_migrate_requires_http_ca_key",
            func: cluster_migrate_requires_http_ca_key,
        },
        ClusterCase {
            name: "cluster_migrate_force_overwrites",
            func: cluster_migrate_force_overwrites,
        },
        ClusterCase {
            name: "cluster_migrate_verify_detects_drift",
            func: cluster_migrate_verify_detects_drift,
        },
        ClusterCase {
            name: "http_api_proxy_to_leader",
            func: http_api_proxy_to_leader,
        },
        ClusterCase {
            name: "http_api_leader_loss",
            func: http_api_leader_loss,
        },
        ClusterCase {
            name: "cluster_audit_findings_live_generation_and_merge",
            func: cluster_audit_findings_live_generation_and_merge,
        },
        ClusterCase {
            name: "cluster_replication_put",
            func: cluster_replication_put,
        },
        ClusterCase {
            name: "cluster_gc_deterministic",
            func: cluster_gc_deterministic,
        },
        ClusterCase {
            name: "cluster_leader_failover_can_join",
            func: cluster_leader_failover_can_join,
        },
        ClusterCase {
            name: "cluster_kubernetes_resolver_leader_failover",
            func: cluster_kubernetes_resolver_leader_failover,
        },
    ]
}
