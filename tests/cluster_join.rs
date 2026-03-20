mod support;

use std::fs;

use neuwerk::controlplane::cloud::types::TerminationEvent;
use neuwerk::controlplane::cluster::bootstrap;
use neuwerk::controlplane::cluster::migration;
use neuwerk::controlplane::cluster::rpc::{IntegrationClient, RaftTlsConfig};
use neuwerk::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};
use neuwerk::controlplane::http_tls::{ensure_http_tls, HttpTlsConfig};
use neuwerk::controlplane::policy_config::{PolicyConfig, PolicyMode};
use neuwerk::controlplane::policy_repository::{PolicyDiskStore, PolicyRecord};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};
use support::cluster_fixture::{
    base_config, ensure_rustls_provider, next_local_addr as next_addr, write_token_file,
};
use support::cluster_membership::change_membership_with_retry;
use support::cluster_state::{
    wait_for_envelope, wait_for_state_absent, wait_for_state_value, wait_for_termination_count,
    write_put_with_retry,
};
use support::cluster_wait::{
    wait_for_leader, wait_for_new_leader, wait_for_stable_membership, wait_for_voter,
};
use support::fs::copy_dir_all;
use tempfile::TempDir;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

#[path = "cluster_join/failover_cases.rs"]
mod failover_cases;
#[path = "cluster_join/lifecycle_cases.rs"]
mod lifecycle_cases;
#[path = "cluster_join/membership_cases.rs"]
mod membership_cases;
#[path = "cluster_join/replay_quorum_cases.rs"]
mod replay_quorum_cases;
