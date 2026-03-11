use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use firewall::controlplane::api_auth::{list_summaries, load_keyset_from_file, ApiKeySet};
use firewall::controlplane::audit::AuditFinding;
use firewall::controlplane::cluster::store::{ClusterStore, ClusterStoreMetadata};
use firewall::controlplane::integrations::IntegrationKind;
use firewall::controlplane::policy_config::PolicyMode;
use firewall::controlplane::policy_repository::{PolicyActive, PolicyIndex, PolicyMeta};
use firewall::controlplane::service_accounts::{
    ServiceAccount, ServiceAccountDiskStore, ServiceAccountStatus, TokenMeta, TokenStatus,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tar::{Builder, Header};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SysdumpArgs {
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct WellKnownPaths {
    var_lib_root: PathBuf,
    etc_root: PathBuf,
    proc_root: PathBuf,
    sys_class_net_root: PathBuf,
    tmp_root: PathBuf,
}

impl Default for WellKnownPaths {
    fn default() -> Self {
        Self {
            var_lib_root: PathBuf::from("/var/lib/neuwerk"),
            etc_root: PathBuf::from("/etc"),
            proc_root: PathBuf::from("/proc"),
            sys_class_net_root: PathBuf::from("/sys/class/net"),
            tmp_root: PathBuf::from("/tmp"),
        }
    }
}

#[derive(Debug, Serialize)]
struct SysdumpManifest {
    generated_at: String,
    entries: Vec<ManifestEntry>,
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    kind: String,
    source: String,
    archive_path: String,
    status: String,
    note: Option<String>,
}

#[derive(Debug, Serialize, Default)]
struct SysdumpStateSummary {
    generated_at: String,
    mode_guess: String,
    node_id: Option<String>,
    local_policy_count: usize,
    local_active_policy_id: Option<String>,
    cluster_policy_count: Option<usize>,
    cluster_active_policy_id: Option<String>,
    local_service_account_count: usize,
    local_token_count: usize,
    cluster_service_account_count: Option<usize>,
    cluster_token_count: Option<usize>,
    local_integration_count: usize,
    cluster_integration_count: Option<usize>,
    audit_finding_count: usize,
    cluster_present: bool,
    metrics_success_count: usize,
}

#[derive(Debug, Serialize, Default)]
struct DetailedPolicySummary {
    local: Option<PolicyStoreSummary>,
    cluster: Option<PolicyStoreSummary>,
}

#[derive(Debug, Serialize)]
struct PolicyStoreSummary {
    count: usize,
    active_policy_id: Option<String>,
    policies: Vec<PolicyMetaSummary>,
}

#[derive(Debug, Serialize)]
struct PolicyMetaSummary {
    id: String,
    created_at: String,
    name: Option<String>,
    mode: PolicyMode,
}

#[derive(Debug, Serialize, Default)]
struct DetailedServiceAccountSummary {
    local: Option<ServiceAccountStoreSummary>,
    cluster: Option<ServiceAccountStoreSummary>,
}

#[derive(Debug, Serialize)]
struct ServiceAccountStoreSummary {
    account_count: usize,
    token_count: usize,
    accounts: Vec<ServiceAccountSummaryEntry>,
}

#[derive(Debug, Serialize)]
struct ServiceAccountSummaryEntry {
    id: String,
    name: String,
    status: ServiceAccountStatus,
    created_at: String,
    token_count: usize,
    active_token_count: usize,
}

#[derive(Debug, Serialize, Default)]
struct DetailedIntegrationSummary {
    local: Option<IntegrationStoreSummary>,
    cluster: Option<IntegrationStoreSummary>,
}

#[derive(Debug, Serialize)]
struct IntegrationStoreSummary {
    count: usize,
    integrations: Vec<IntegrationSummaryEntry>,
}

#[derive(Debug, Serialize)]
struct IntegrationSummaryEntry {
    id: String,
    created_at: String,
    name: String,
    kind: IntegrationKind,
    api_server_url: String,
    token_configured: bool,
}

#[derive(Debug, Serialize)]
struct ConfigurationSummary {
    local_http_ca_present: bool,
    local_intercept_ca_present: bool,
    local_api_auth: Option<ApiAuthSummary>,
    cluster_http_ca_present: Option<bool>,
    cluster_intercept_ca_present: Option<bool>,
    cluster_api_auth: Option<ApiAuthSummary>,
}

#[derive(Debug, Serialize)]
struct ApiAuthSummary {
    active_kid: String,
    key_count: usize,
    keys: Vec<ApiKeySummaryView>,
}

#[derive(Debug, Serialize)]
struct ApiKeySummaryView {
    kid: String,
    created_at: String,
    status: firewall::controlplane::api_auth::ApiKeyStatus,
    signing: bool,
}

#[derive(Debug, Serialize)]
struct AuditSummary {
    finding_count: usize,
}

#[derive(Debug, Serialize)]
struct MetricsSummary {
    attempts: Vec<HttpSnapshotResult>,
}

#[derive(Debug, Serialize, Clone)]
struct HttpSnapshotResult {
    name: String,
    url: String,
    archive_path: String,
    success: bool,
    status: Option<u16>,
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClusterSummary {
    current_term: Option<u64>,
    voted_for: Option<String>,
    vote_committed: Option<bool>,
    last_log_index: Option<u64>,
    last_purged_index: Option<u64>,
    last_applied_index: Option<u64>,
    membership_log_index: Option<u64>,
    joint_configs: Vec<Vec<String>>,
    voter_count: usize,
    node_count: usize,
    nodes: Vec<ClusterNodeSummary>,
    rocksdb: ClusterRocksdbSummary,
}

#[derive(Debug, Serialize)]
struct ClusterNodeSummary {
    node_id: String,
    addr: String,
    role: String,
    matched_index: Option<u64>,
    lag_entries: Option<u64>,
    caught_up: bool,
}

#[derive(Debug, Serialize)]
struct ClusterRocksdbSummary {
    estimated_num_keys: Option<u64>,
    live_sst_files_size_bytes: Option<u64>,
    total_sst_files_size_bytes: Option<u64>,
    memtable_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct LocalIntegrationIndex {
    integrations: Vec<LocalIntegrationMeta>,
}

#[derive(Debug, Deserialize)]
struct LocalIntegrationMeta {
    id: Uuid,
}

#[derive(Debug, Deserialize)]
struct StoredIntegrationRecordSummary {
    id: Uuid,
    created_at: String,
    name: String,
    kind: IntegrationKind,
    api_server_url: String,
    #[serde(default)]
    service_account_token: Option<String>,
    #[serde(default)]
    service_account_token_envelope: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct ClusterServiceAccountIndex {
    accounts: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Default)]
struct ClusterTokenIndex {
    tokens: Vec<Uuid>,
}

const CLUSTER_RAFT_DIR: &str = "cluster/raft";
const HTTP_TLS_DIR: &str = "http-tls";
const API_AUTH_FILENAME: &str = "api-auth.json";
const HTTP_CA_CERT_FILENAME: &str = "ca.crt";
const INTERCEPT_CA_CERT_FILENAME: &str = "intercept-ca.crt";

const POLICY_INDEX_KEY: &[u8] = b"policies/index";
const POLICY_ACTIVE_KEY: &[u8] = b"policies/active";
const SERVICE_ACCOUNTS_INDEX_KEY: &[u8] = b"auth/service-accounts/index";
const INTEGRATIONS_INDEX_KEY: &[u8] = b"integrations/index";
const API_KEYS_KEY: &[u8] = b"auth/api_keys";
const HTTP_CA_CERT_KEY: &[u8] = b"http/ca/cert";
const INTERCEPT_CA_CERT_KEY: &[u8] = b"settings/tls_intercept/ca_cert_pem";

pub fn sysdump_usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin} sysdump [--output <path>]\n\nFlags:\n  --output <path>  Write the sysdump archive to this path (default: /tmp/neuwerk-sysdump-<timestamp>.tar.gz)\n  -h, --help\n"
    )
}

pub fn parse_sysdump_args(bin: &str, args: &[String]) -> Result<SysdumpArgs, String> {
    let mut output = None;
    let mut args = args.iter().cloned();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", sysdump_usage(bin));
                std::process::exit(0);
            }
            "--output" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                output = Some(PathBuf::from(value));
            }
            _ if arg.starts_with("--output=") => {
                output = Some(PathBuf::from(
                    arg.trim_start_matches("--output=").to_string(),
                ));
            }
            _ => return Err(format!("unknown sysdump flag: {arg}")),
        }
    }
    Ok(SysdumpArgs { output })
}

pub async fn run_sysdump(args: SysdumpArgs) -> Result<PathBuf, String> {
    run_sysdump_with_paths(args, WellKnownPaths::default()).await
}

#[allow(dead_code)]
pub async fn build_local_sysdump_archive() -> Result<Vec<u8>, String> {
    build_local_sysdump_archive_with_paths(WellKnownPaths::default()).await
}

async fn run_sysdump_with_paths(
    args: SysdumpArgs,
    paths: WellKnownPaths,
) -> Result<PathBuf, String> {
    let now = OffsetDateTime::now_utc();
    let output = args
        .output
        .unwrap_or_else(|| default_output_path(&paths.tmp_root, now));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    let archive = build_local_sysdump_archive_with_paths_and_time(paths, now).await?;
    fs::write(&output, archive).map_err(|err| err.to_string())?;
    println!("{}", output.display());
    Ok(output)
}

#[allow(dead_code)]
async fn build_local_sysdump_archive_with_paths(paths: WellKnownPaths) -> Result<Vec<u8>, String> {
    build_local_sysdump_archive_with_paths_and_time(paths, OffsetDateTime::now_utc()).await
}

async fn build_local_sysdump_archive_with_paths_and_time(
    paths: WellKnownPaths,
    now: OffsetDateTime,
) -> Result<Vec<u8>, String> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    let mut manifest = SysdumpManifest {
        generated_at: format_rfc3339(now)?,
        entries: Vec::new(),
    };

    collect_var_lib_neuwerk(&paths, &mut builder, &mut manifest, now)?;
    collect_selected_etc(&paths, &mut builder, &mut manifest, now)?;
    collect_selected_proc(&paths, &mut builder, &mut manifest, now)?;
    collect_path_recursive(
        &paths.sys_class_net_root,
        Path::new("sys/class/net"),
        &mut builder,
        &mut manifest,
        now,
        None,
    )?;
    collect_command_snapshots(&mut builder, &mut manifest, now)?;
    let metrics = collect_http_snapshots(&mut builder, &mut manifest, now).await?;

    let mut state = SysdumpStateSummary {
        generated_at: format_rfc3339(now)?,
        ..SysdumpStateSummary::default()
    };
    state.node_id = read_trimmed(paths.var_lib_root.join("node_id"));
    state.mode_guess = guess_mode(&paths);
    state.metrics_success_count = metrics.attempts.iter().filter(|item| item.success).count();

    let policies = collect_policy_summaries(&paths, &mut manifest);
    state.local_policy_count = policies.local.as_ref().map(|item| item.count).unwrap_or(0);
    state.local_active_policy_id = policies
        .local
        .as_ref()
        .and_then(|item| item.active_policy_id.clone());
    state.cluster_policy_count = policies.cluster.as_ref().map(|item| item.count);
    state.cluster_active_policy_id = policies
        .cluster
        .as_ref()
        .and_then(|item| item.active_policy_id.clone());

    let service_accounts = collect_service_account_summaries(&paths, &mut manifest);
    state.local_service_account_count = service_accounts
        .local
        .as_ref()
        .map(|item| item.account_count)
        .unwrap_or(0);
    state.local_token_count = service_accounts
        .local
        .as_ref()
        .map(|item| item.token_count)
        .unwrap_or(0);
    state.cluster_service_account_count = service_accounts
        .cluster
        .as_ref()
        .map(|item| item.account_count);
    state.cluster_token_count = service_accounts
        .cluster
        .as_ref()
        .map(|item| item.token_count);

    let integrations = collect_integration_summaries(&paths, &mut manifest);
    state.local_integration_count = integrations
        .local
        .as_ref()
        .map(|item| item.count)
        .unwrap_or(0);
    state.cluster_integration_count = integrations.cluster.as_ref().map(|item| item.count);

    let audit = collect_audit_summary(&paths);
    state.audit_finding_count = audit.finding_count;

    let cluster = collect_cluster_summary(&paths, &mut manifest);
    state.cluster_present = cluster.is_some();

    let configuration = collect_configuration_summary(&paths, &mut manifest);

    append_json(
        &mut builder,
        "summary/state.json",
        &state,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/policies.json",
        &policies,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/service-accounts.json",
        &service_accounts,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/integrations.json",
        &integrations,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/audit.json",
        &audit,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/metrics.json",
        &metrics,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    append_json(
        &mut builder,
        "summary/configuration.json",
        &configuration,
        0o644,
        now,
        &mut manifest,
        "summary",
        "ok",
        None,
    )?;
    if let Some(cluster) = &cluster {
        append_json(
            &mut builder,
            "summary/cluster.json",
            cluster,
            0o644,
            now,
            &mut manifest,
            "summary",
            "ok",
            None,
        )?;
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|err| err.to_string())?;
    append_bytes(
        &mut builder,
        "summary/manifest.json",
        &manifest_bytes,
        0o644,
        now,
    )?;

    builder.finish().map_err(|err| err.to_string())?;
    let encoder = builder.into_inner().map_err(|err| err.to_string())?;
    encoder.finish().map_err(|err| err.to_string())
}

fn default_output_path(tmp_root: &Path, now: OffsetDateTime) -> PathBuf {
    tmp_root.join(format!(
        "neuwerk-sysdump-{:04}{:02}{:02}T{:02}{:02}{:02}Z.tar.gz",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    ))
}

fn guess_mode(paths: &WellKnownPaths) -> String {
    if paths.var_lib_root.join(CLUSTER_RAFT_DIR).exists() {
        "cluster".to_string()
    } else if paths.var_lib_root.join("local-policy-store").exists() {
        "local".to_string()
    } else {
        "unknown".to_string()
    }
}

fn collect_var_lib_neuwerk<W: Write>(
    paths: &WellKnownPaths,
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
) -> Result<(), String> {
    let root = &paths.var_lib_root;
    let manifest_only = root.join(CLUSTER_RAFT_DIR);
    collect_path_recursive(
        root,
        Path::new("var/lib/neuwerk"),
        builder,
        manifest,
        now,
        Some(&manifest_only),
    )
}

fn collect_selected_etc<W: Write>(
    paths: &WellKnownPaths,
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
) -> Result<(), String> {
    let files = [
        ("hostname", "etc/hostname"),
        ("hosts", "etc/hosts"),
        ("resolv.conf", "etc/resolv.conf"),
        ("os-release", "etc/os-release"),
        ("machine-id", "etc/machine-id"),
        (
            "systemd/system/firewall.service",
            "etc/systemd/system/firewall.service",
        ),
        (
            "systemd/system/firewall.service.d",
            "etc/systemd/system/firewall.service.d",
        ),
        ("default/firewall", "etc/default/firewall"),
    ];
    for (source, archive) in files {
        collect_path_recursive(
            &paths.etc_root.join(source),
            Path::new(archive),
            builder,
            manifest,
            now,
            None,
        )?;
    }

    for (source, archive) in [
        (
            PathBuf::from("/lib/systemd/system/firewall.service"),
            PathBuf::from("lib/systemd/system/firewall.service"),
        ),
        (
            PathBuf::from("/usr/lib/systemd/system/firewall.service"),
            PathBuf::from("usr/lib/systemd/system/firewall.service"),
        ),
    ] {
        collect_path_recursive(&source, &archive, builder, manifest, now, None)?;
    }
    Ok(())
}

fn collect_selected_proc<W: Write>(
    paths: &WellKnownPaths,
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
) -> Result<(), String> {
    let files = [
        ("cmdline", "proc/cmdline"),
        ("cpuinfo", "proc/cpuinfo"),
        ("meminfo", "proc/meminfo"),
        ("mounts", "proc/mounts"),
        ("uptime", "proc/uptime"),
        ("version", "proc/version"),
        ("net/dev", "proc/net/dev"),
        ("net/route", "proc/net/route"),
        ("pressure/cpu", "proc/pressure/cpu"),
        ("pressure/io", "proc/pressure/io"),
        ("pressure/memory", "proc/pressure/memory"),
        ("sys/kernel/hostname", "proc/sys/kernel/hostname"),
    ];
    for (source, archive) in files {
        collect_path_recursive(
            &paths.proc_root.join(source),
            Path::new(archive),
            builder,
            manifest,
            now,
            None,
        )?;
    }
    Ok(())
}

fn collect_path_recursive<W: Write>(
    source: &Path,
    archive_path: &Path,
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
    manifest_only_dir: Option<&Path>,
) -> Result<(), String> {
    if !source.exists() {
        manifest.entries.push(ManifestEntry {
            kind: "path".to_string(),
            source: source.display().to_string(),
            archive_path: archive_path.display().to_string(),
            status: "missing".to_string(),
            note: None,
        });
        return Ok(());
    }

    if let Some(manifest_only_dir) = manifest_only_dir {
        if source == manifest_only_dir {
            let listing = build_directory_manifest(source)?;
            append_json(
                builder,
                &format!("{}.manifest.json", archive_path.display()),
                &listing,
                0o644,
                now,
                manifest,
                "path",
                "manifest-only",
                Some("directory collected as manifest only".to_string()),
            )?;
            return Ok(());
        }
    }

    let metadata = fs::symlink_metadata(source).map_err(|err| err.to_string())?;
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(source).map_err(|err| err.to_string())?;
        append_text(
            builder,
            &format!("{}.symlink.txt", archive_path.display()),
            &format!("symlink -> {}\n", target.display()),
            0o644,
            now,
            manifest,
            "path",
            "symlink",
            None,
        )?;
        return Ok(());
    }

    if metadata.is_dir() {
        let mut entries = fs::read_dir(source)
            .map_err(|err| err.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| err.to_string())?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child_source = entry.path();
            let child_archive = archive_path.join(entry.file_name());
            collect_path_recursive(
                &child_source,
                &child_archive,
                builder,
                manifest,
                now,
                manifest_only_dir,
            )?;
        }
        return Ok(());
    }

    let bytes = fs::read(source).map_err(|err| err.to_string())?;
    let redacted = transform_file_bytes(source, bytes)?;
    append_bytes(
        builder,
        &archive_path.display().to_string(),
        &redacted,
        0o600,
        now,
    )?;
    manifest.entries.push(ManifestEntry {
        kind: "path".to_string(),
        source: source.display().to_string(),
        archive_path: archive_path.display().to_string(),
        status: "ok".to_string(),
        note: None,
    });
    Ok(())
}

fn collect_command_snapshots<W: Write>(
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
) -> Result<(), String> {
    let commands: [(&str, &[&str], &str); 7] = [
        (
            "systemctl",
            &["status", "firewall.service", "--no-pager"],
            "system/commands/systemctl-status-firewall.txt",
        ),
        (
            "systemctl",
            &["show", "firewall.service"],
            "system/commands/systemctl-show-firewall.txt",
        ),
        (
            "journalctl",
            &["-u", "firewall.service", "--no-pager", "-n", "2000"],
            "system/journal/firewall-service.log",
        ),
        (
            "ip",
            &["-details", "addr", "show"],
            "system/commands/ip-addr.txt",
        ),
        (
            "ip",
            &["-details", "link", "show"],
            "system/commands/ip-link.txt",
        ),
        (
            "ip",
            &["route", "show", "table", "all"],
            "system/commands/ip-route.txt",
        ),
        ("ip", &["rule", "show"], "system/commands/ip-rule.txt"),
    ];

    for (program, args, archive_path) in commands {
        let output = match Command::new(program).args(args).output() {
            Ok(output) => format_command_output(program, args, output),
            Err(err) => format!("command failed to start: {err}\n"),
        };
        append_text(
            builder,
            archive_path,
            &output,
            0o644,
            now,
            manifest,
            "command",
            "ok",
            None,
        )?;
    }
    Ok(())
}

async fn collect_http_snapshots<W: Write>(
    builder: &mut Builder<W>,
    manifest: &mut SysdumpManifest,
    now: OffsetDateTime,
) -> Result<MetricsSummary, String> {
    let http_client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|err| err.to_string())?;
    let https_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|err| err.to_string())?;

    let specs = [
        (
            "metrics-loopback-v4",
            "http://127.0.0.1:8080/metrics",
            "system/http/metrics-127.0.0.1-8080.prom",
            false,
        ),
        (
            "metrics-loopback-v6",
            "http://[::1]:8080/metrics",
            "system/http/metrics-ipv6-localhost-8080.prom",
            false,
        ),
        (
            "health-loopback-v4",
            "https://127.0.0.1:8443/health",
            "system/http/health-127.0.0.1-8443.txt",
            true,
        ),
        (
            "health-localhost",
            "https://localhost:8443/health",
            "system/http/health-localhost-8443.txt",
            true,
        ),
    ];

    let mut attempts = Vec::new();
    for (name, url, archive_path, tls) in specs {
        let client = if tls { &https_client } else { &http_client };
        let result = match client.get(url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let success = response.status().is_success();
                let body = match response.text().await {
                    Ok(body) => body,
                    Err(err) => format!("response body read failed: {err}\n"),
                };
                append_text(
                    builder,
                    archive_path,
                    &body,
                    0o644,
                    now,
                    manifest,
                    "http",
                    if success { "ok" } else { "http-error" },
                    Some(format!("status={status}")),
                )?;
                HttpSnapshotResult {
                    name: name.to_string(),
                    url: url.to_string(),
                    archive_path: archive_path.to_string(),
                    success,
                    status: Some(status),
                    note: None,
                }
            }
            Err(err) => {
                let body = format!("request failed: {err}\n");
                append_text(
                    builder,
                    archive_path,
                    &body,
                    0o644,
                    now,
                    manifest,
                    "http",
                    "request-failed",
                    Some(err.to_string()),
                )?;
                HttpSnapshotResult {
                    name: name.to_string(),
                    url: url.to_string(),
                    archive_path: archive_path.to_string(),
                    success: false,
                    status: None,
                    note: Some(err.to_string()),
                }
            }
        };
        attempts.push(result);
    }

    Ok(MetricsSummary { attempts })
}

fn collect_policy_summaries(
    paths: &WellKnownPaths,
    manifest: &mut SysdumpManifest,
) -> DetailedPolicySummary {
    let local = match collect_local_policy_summary(&paths.var_lib_root.join("local-policy-store")) {
        Ok(summary) => summary,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "policy-local",
                "summary/policies.json",
                err,
            ));
            None
        }
    };
    let cluster = match open_cluster_store(paths) {
        Ok(Some(store)) => match collect_cluster_policy_summary(&store) {
            Ok(summary) => summary,
            Err(err) => {
                manifest.entries.push(nonfatal_summary_entry(
                    "policy-cluster",
                    "summary/policies.json",
                    err,
                ));
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "policy-cluster-open",
                "summary/policies.json",
                err,
            ));
            None
        }
    };
    DetailedPolicySummary { local, cluster }
}

fn collect_local_policy_summary(path: &Path) -> Result<Option<PolicyStoreSummary>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let index: PolicyIndex = read_json_file(&path.join("index.json"))?.unwrap_or_default();
    let active: Option<PolicyActive> = read_json_file(&path.join("active.json"))?;
    Ok(Some(PolicyStoreSummary {
        count: index.policies.len(),
        active_policy_id: active.map(|item| item.id.to_string()),
        policies: policy_meta_summaries(index.policies),
    }))
}

fn collect_cluster_policy_summary(
    store: &ClusterStore,
) -> Result<Option<PolicyStoreSummary>, String> {
    let index: PolicyIndex = read_state_json(store, POLICY_INDEX_KEY)?.unwrap_or_default();
    let active: Option<PolicyActive> = read_state_json(store, POLICY_ACTIVE_KEY)?;
    Ok(Some(PolicyStoreSummary {
        count: index.policies.len(),
        active_policy_id: active.map(|item| item.id.to_string()),
        policies: policy_meta_summaries(index.policies),
    }))
}

fn policy_meta_summaries(items: Vec<PolicyMeta>) -> Vec<PolicyMetaSummary> {
    items
        .into_iter()
        .map(|item| PolicyMetaSummary {
            id: item.id.to_string(),
            created_at: item.created_at,
            name: item.name,
            mode: item.mode,
        })
        .collect()
}

fn collect_service_account_summaries(
    paths: &WellKnownPaths,
    manifest: &mut SysdumpManifest,
) -> DetailedServiceAccountSummary {
    let local = match collect_local_service_accounts(&paths.var_lib_root.join("service-accounts")) {
        Ok(summary) => summary,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "service-accounts-local",
                "summary/service-accounts.json",
                err,
            ));
            None
        }
    };
    let cluster = match open_cluster_store(paths) {
        Ok(Some(store)) => match collect_cluster_service_accounts(&store) {
            Ok(summary) => summary,
            Err(err) => {
                manifest.entries.push(nonfatal_summary_entry(
                    "service-accounts-cluster",
                    "summary/service-accounts.json",
                    err,
                ));
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "service-accounts-cluster-open",
                "summary/service-accounts.json",
                err,
            ));
            None
        }
    };
    DetailedServiceAccountSummary { local, cluster }
}

fn collect_local_service_accounts(
    path: &Path,
) -> Result<Option<ServiceAccountStoreSummary>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let store = ServiceAccountDiskStore::new(path.to_path_buf());
    let accounts = store.list_accounts().map_err(|err| err.to_string())?;
    let mut entries = Vec::with_capacity(accounts.len());
    let mut token_count = 0usize;
    for account in accounts {
        let tokens = store
            .list_tokens(account.id)
            .map_err(|err| err.to_string())?;
        let active_token_count = tokens
            .iter()
            .filter(|token| matches!(token.status, TokenStatus::Active))
            .count();
        token_count += tokens.len();
        entries.push(service_account_entry(
            account,
            tokens.len(),
            active_token_count,
        ));
    }
    Ok(Some(ServiceAccountStoreSummary {
        account_count: entries.len(),
        token_count,
        accounts: entries,
    }))
}

fn collect_cluster_service_accounts(
    store: &ClusterStore,
) -> Result<Option<ServiceAccountStoreSummary>, String> {
    let index: ClusterServiceAccountIndex =
        read_state_json(store, SERVICE_ACCOUNTS_INDEX_KEY)?.unwrap_or_default();
    if index.accounts.is_empty() {
        return Ok(Some(ServiceAccountStoreSummary {
            account_count: 0,
            token_count: 0,
            accounts: Vec::new(),
        }));
    }

    let mut entries = Vec::with_capacity(index.accounts.len());
    let mut token_count = 0usize;
    for account_id in index.accounts {
        let key = format!("auth/service-accounts/item/{account_id}");
        let Some(account): Option<ServiceAccount> = read_state_json(store, key.as_bytes())? else {
            continue;
        };
        let token_index_key = format!("auth/service-accounts/tokens/index/{account_id}");
        let token_index: ClusterTokenIndex =
            read_state_json(store, token_index_key.as_bytes())?.unwrap_or_default();
        let mut active_token_count = 0usize;
        for token_id in &token_index.tokens {
            let token_key = format!("auth/service-accounts/tokens/item/{token_id}");
            if let Some(token) = read_state_json::<TokenMeta>(store, token_key.as_bytes())? {
                if matches!(token.status, TokenStatus::Active) {
                    active_token_count += 1;
                }
            }
        }
        token_count += token_index.tokens.len();
        entries.push(service_account_entry(
            account,
            token_index.tokens.len(),
            active_token_count,
        ));
    }

    Ok(Some(ServiceAccountStoreSummary {
        account_count: entries.len(),
        token_count,
        accounts: entries,
    }))
}

fn service_account_entry(
    account: ServiceAccount,
    token_count: usize,
    active_token_count: usize,
) -> ServiceAccountSummaryEntry {
    ServiceAccountSummaryEntry {
        id: account.id.to_string(),
        name: account.name,
        status: account.status,
        created_at: account.created_at,
        token_count,
        active_token_count,
    }
}

fn collect_integration_summaries(
    paths: &WellKnownPaths,
    manifest: &mut SysdumpManifest,
) -> DetailedIntegrationSummary {
    let local = match collect_local_integrations(&paths.var_lib_root.join("integrations")) {
        Ok(summary) => summary,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "integrations-local",
                "summary/integrations.json",
                err,
            ));
            None
        }
    };
    let cluster = match open_cluster_store(paths) {
        Ok(Some(store)) => match collect_cluster_integrations(&store) {
            Ok(summary) => summary,
            Err(err) => {
                manifest.entries.push(nonfatal_summary_entry(
                    "integrations-cluster",
                    "summary/integrations.json",
                    err,
                ));
                None
            }
        },
        Ok(None) => None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "integrations-cluster-open",
                "summary/integrations.json",
                err,
            ));
            None
        }
    };
    DetailedIntegrationSummary { local, cluster }
}

fn collect_local_integrations(path: &Path) -> Result<Option<IntegrationStoreSummary>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let index: LocalIntegrationIndex =
        read_json_file(&path.join("index.json"))?.unwrap_or_default();
    let mut integrations = Vec::with_capacity(index.integrations.len());
    for meta in index.integrations {
        let record: Option<StoredIntegrationRecordSummary> =
            read_json_file(&path.join("integrations").join(format!("{}.json", meta.id)))?;
        if let Some(record) = record {
            integrations.push(integration_summary_entry(record));
        }
    }
    Ok(Some(IntegrationStoreSummary {
        count: integrations.len(),
        integrations,
    }))
}

fn collect_cluster_integrations(
    store: &ClusterStore,
) -> Result<Option<IntegrationStoreSummary>, String> {
    let index: LocalIntegrationIndex =
        read_state_json(store, INTEGRATIONS_INDEX_KEY)?.unwrap_or_default();
    let mut integrations = Vec::with_capacity(index.integrations.len());
    for meta in index.integrations {
        let key = format!("integrations/item/{}", meta.id);
        let record: Option<StoredIntegrationRecordSummary> =
            read_state_json(store, key.as_bytes())?;
        if let Some(record) = record {
            integrations.push(integration_summary_entry(record));
        }
    }
    Ok(Some(IntegrationStoreSummary {
        count: integrations.len(),
        integrations,
    }))
}

fn integration_summary_entry(record: StoredIntegrationRecordSummary) -> IntegrationSummaryEntry {
    let token_configured = record.service_account_token_envelope.is_some()
        || record
            .service_account_token
            .as_deref()
            .map(|token| !token.trim().is_empty())
            .unwrap_or(false);
    IntegrationSummaryEntry {
        id: record.id.to_string(),
        created_at: record.created_at,
        name: record.name,
        kind: record.kind,
        api_server_url: record.api_server_url,
        token_configured,
    }
}

fn collect_audit_summary(paths: &WellKnownPaths) -> AuditSummary {
    let snapshot_path = paths.var_lib_root.join("audit-store").join("snapshot.json");
    let findings = read_json_file::<AuditSnapshotView>(&snapshot_path)
        .ok()
        .flatten()
        .map(|snapshot| snapshot.findings.len())
        .unwrap_or(0);
    AuditSummary {
        finding_count: findings,
    }
}

#[derive(Debug, Deserialize, Default)]
struct AuditSnapshotView {
    findings: Vec<AuditFinding>,
}

fn collect_configuration_summary(
    paths: &WellKnownPaths,
    manifest: &mut SysdumpManifest,
) -> ConfigurationSummary {
    let local_http_ca_present = paths
        .var_lib_root
        .join(HTTP_TLS_DIR)
        .join(HTTP_CA_CERT_FILENAME)
        .exists();
    let local_intercept_ca_present = paths
        .var_lib_root
        .join(HTTP_TLS_DIR)
        .join(INTERCEPT_CA_CERT_FILENAME)
        .exists();
    let local_api_auth = collect_local_api_auth(&paths.var_lib_root.join(HTTP_TLS_DIR), manifest);

    let (cluster_http_ca_present, cluster_intercept_ca_present, cluster_api_auth) =
        match open_cluster_store(paths) {
            Ok(Some(store)) => {
                let http = store
                    .get_state_value(HTTP_CA_CERT_KEY)
                    .ok()
                    .flatten()
                    .is_some();
                let intercept = store
                    .get_state_value(INTERCEPT_CA_CERT_KEY)
                    .ok()
                    .flatten()
                    .is_some();
                let api_auth = collect_cluster_api_auth(&store, manifest);
                (Some(http), Some(intercept), api_auth)
            }
            Ok(None) => (None, None, None),
            Err(err) => {
                manifest.entries.push(nonfatal_summary_entry(
                    "configuration-cluster",
                    "summary/configuration.json",
                    err,
                ));
                (None, None, None)
            }
        };

    ConfigurationSummary {
        local_http_ca_present,
        local_intercept_ca_present,
        local_api_auth,
        cluster_http_ca_present,
        cluster_intercept_ca_present,
        cluster_api_auth,
    }
}

fn collect_local_api_auth(
    tls_dir: &Path,
    manifest: &mut SysdumpManifest,
) -> Option<ApiAuthSummary> {
    let path = tls_dir.join(API_AUTH_FILENAME);
    match load_keyset_from_file(&path) {
        Ok(Some(keyset)) => Some(api_auth_summary(keyset)),
        Ok(None) => None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "configuration-local-api-auth",
                "summary/configuration.json",
                err,
            ));
            None
        }
    }
}

fn collect_cluster_api_auth(
    store: &ClusterStore,
    manifest: &mut SysdumpManifest,
) -> Option<ApiAuthSummary> {
    match read_state_json::<ApiKeySet>(store, API_KEYS_KEY) {
        Ok(Some(keyset)) => Some(api_auth_summary(keyset)),
        Ok(None) => None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "configuration-cluster-api-auth",
                "summary/configuration.json",
                err,
            ));
            None
        }
    }
}

fn api_auth_summary(keyset: ApiKeySet) -> ApiAuthSummary {
    let keys = list_summaries(&keyset)
        .into_iter()
        .map(|key| ApiKeySummaryView {
            kid: key.kid,
            created_at: key.created_at,
            status: key.status,
            signing: key.signing,
        })
        .collect::<Vec<_>>();
    ApiAuthSummary {
        active_kid: keyset.active_kid,
        key_count: keys.len(),
        keys,
    }
}

fn collect_cluster_summary(
    paths: &WellKnownPaths,
    manifest: &mut SysdumpManifest,
) -> Option<ClusterSummary> {
    let store = match open_cluster_store(paths) {
        Ok(Some(store)) => store,
        Ok(None) => return None,
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "cluster-open",
                "summary/cluster.json",
                err,
            ));
            return None;
        }
    };
    match build_cluster_summary(&store) {
        Ok(summary) => Some(summary),
        Err(err) => {
            manifest.entries.push(nonfatal_summary_entry(
                "cluster-build",
                "summary/cluster.json",
                err,
            ));
            None
        }
    }
}

fn build_cluster_summary(store: &ClusterStore) -> Result<ClusterSummary, String> {
    let metadata = store.read_metadata()?;
    Ok(cluster_summary_from_metadata(store, metadata))
}

fn cluster_summary_from_metadata(
    store: &ClusterStore,
    metadata: ClusterStoreMetadata,
) -> ClusterSummary {
    let voter_ids = metadata
        .last_membership
        .voter_ids()
        .collect::<BTreeSet<_>>();
    let current_term = metadata
        .vote
        .as_ref()
        .map(|vote| vote.leader_id().get_term());
    let voted_for = metadata
        .vote
        .as_ref()
        .and_then(|vote| vote.leader_id().voted_for())
        .map(|node_id| node_id.to_string());
    let vote_committed = metadata.vote.as_ref().map(|vote| vote.is_committed());
    let last_log_index = metadata.last_log.as_ref().map(|item| item.index);
    let last_purged_index = metadata.last_purged.as_ref().map(|item| item.index);
    let last_applied_index = metadata.last_applied.as_ref().map(|item| item.index);
    let membership_log_index = metadata
        .last_membership
        .log_id()
        .as_ref()
        .map(|item| item.index);

    let mut nodes = metadata
        .last_membership
        .nodes()
        .map(|(node_id, node)| {
            let is_voter = voter_ids.contains(node_id);
            ClusterNodeSummary {
                node_id: node_id.to_string(),
                addr: node.addr.clone(),
                role: if voted_for.as_deref() == Some(&node_id.to_string()) {
                    "leader".to_string()
                } else if is_voter {
                    "voter".to_string()
                } else {
                    "learner".to_string()
                },
                matched_index: None,
                lag_entries: None,
                caught_up: false,
            }
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|a, b| {
        (a.role != "leader", a.node_id.as_str()).cmp(&(b.role != "leader", b.node_id.as_str()))
    });

    let joint_configs = metadata
        .last_membership
        .membership()
        .get_joint_config()
        .iter()
        .map(|config| {
            config
                .iter()
                .map(|item| item.to_string())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    ClusterSummary {
        current_term,
        voted_for,
        vote_committed,
        last_log_index,
        last_purged_index,
        last_applied_index,
        membership_log_index,
        joint_configs,
        voter_count: voter_ids.len(),
        node_count: nodes.len(),
        nodes,
        rocksdb: ClusterRocksdbSummary {
            estimated_num_keys: store.property_int_value("rocksdb.estimate-num-keys"),
            live_sst_files_size_bytes: store.property_int_value("rocksdb.live-sst-files-size"),
            total_sst_files_size_bytes: store.property_int_value("rocksdb.total-sst-files-size"),
            memtable_bytes: store.property_int_value("rocksdb.size-all-mem-tables"),
        },
    }
}

fn open_cluster_store(paths: &WellKnownPaths) -> Result<Option<ClusterStore>, String> {
    let cluster_path = paths.var_lib_root.join(CLUSTER_RAFT_DIR);
    if !cluster_path.exists() {
        return Ok(None);
    }
    ClusterStore::open_read_only(cluster_path)
        .map(Some)
        .map_err(|err| err.to_string())
}

fn build_directory_manifest(path: &Path) -> Result<Vec<DirectoryManifestEntry>, String> {
    let mut entries = Vec::new();
    build_directory_manifest_inner(path, path, &mut entries)?;
    Ok(entries)
}

fn build_directory_manifest_inner(
    root: &Path,
    current: &Path,
    out: &mut Vec<DirectoryManifestEntry>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|err| err.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|err| err.to_string())?
            .display()
            .to_string();
        let metadata = fs::symlink_metadata(&path).map_err(|err| err.to_string())?;
        let kind = if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "dir"
        } else {
            "file"
        };
        out.push(DirectoryManifestEntry {
            path: rel,
            kind: kind.to_string(),
            size: if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            },
        });
        if metadata.is_dir() {
            build_directory_manifest_inner(root, &path, out)?;
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct DirectoryManifestEntry {
    path: String,
    kind: String,
    size: Option<u64>,
}

fn transform_file_bytes(path: &Path, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let file_name = path
        .file_name()
        .and_then(|item| item.to_str())
        .unwrap_or_default();
    if file_name == "bootstrap-token" {
        return Ok(b"redacted bootstrap token\n".to_vec());
    }
    if file_name == API_AUTH_FILENAME {
        return redact_api_auth_json(bytes);
    }
    if should_redact_key_file(file_name) {
        return Ok(format!("redacted secret file: {file_name}\n").into_bytes());
    }
    Ok(bytes)
}

fn should_redact_key_file(file_name: &str) -> bool {
    file_name.ends_with(".key")
        || matches!(
            file_name,
            "node.key" | "ca.key" | "intercept-ca.key" | "secret.key"
        )
}

fn redact_api_auth_json(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let mut keyset: ApiKeySet = serde_json::from_slice(&bytes).map_err(|err| err.to_string())?;
    for key in &mut keyset.keys {
        if key.private_key.is_some() {
            key.private_key = Some("<redacted>".to_string());
        }
    }
    serde_json::to_vec_pretty(&keyset).map_err(|err| err.to_string())
}

fn read_trimmed(path: PathBuf) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>, String> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| err.to_string()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.to_string()),
    }
}

fn read_state_json<T: for<'de> Deserialize<'de>>(
    store: &ClusterStore,
    key: &[u8],
) -> Result<Option<T>, String> {
    match store.get_state_value(key)? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

fn append_json<W: Write, T: Serialize>(
    builder: &mut Builder<W>,
    archive_path: &str,
    value: &T,
    mode: u32,
    now: OffsetDateTime,
    manifest: &mut SysdumpManifest,
    kind: &str,
    status: &str,
    note: Option<String>,
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| err.to_string())?;
    append_bytes(builder, archive_path, &bytes, mode, now)?;
    manifest.entries.push(ManifestEntry {
        kind: kind.to_string(),
        source: archive_path.to_string(),
        archive_path: archive_path.to_string(),
        status: status.to_string(),
        note,
    });
    Ok(())
}

fn append_text<W: Write>(
    builder: &mut Builder<W>,
    archive_path: &str,
    text: &str,
    mode: u32,
    now: OffsetDateTime,
    manifest: &mut SysdumpManifest,
    kind: &str,
    status: &str,
    note: Option<String>,
) -> Result<(), String> {
    append_bytes(builder, archive_path, text.as_bytes(), mode, now)?;
    manifest.entries.push(ManifestEntry {
        kind: kind.to_string(),
        source: archive_path.to_string(),
        archive_path: archive_path.to_string(),
        status: status.to_string(),
        note,
    });
    Ok(())
}

fn append_bytes<W: Write>(
    builder: &mut Builder<W>,
    archive_path: &str,
    bytes: &[u8],
    mode: u32,
    now: OffsetDateTime,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(mode);
    header.set_mtime(now.unix_timestamp().max(0) as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, archive_path, Cursor::new(bytes))
        .map_err(|err| err.to_string())
}

fn format_command_output(program: &str, args: &[&str], output: std::process::Output) -> String {
    let mut body = String::new();
    body.push_str(&format!("$ {} {}\n", program, args.join(" ")));
    body.push_str(&format!("exit_status: {}\n\n", output.status));
    body.push_str("--- stdout ---\n");
    body.push_str(&String::from_utf8_lossy(&output.stdout));
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str("\n--- stderr ---\n");
    body.push_str(&String::from_utf8_lossy(&output.stderr));
    if !body.ends_with('\n') {
        body.push('\n');
    }
    body
}

fn nonfatal_summary_entry(source: &str, archive_path: &str, err: String) -> ManifestEntry {
    ManifestEntry {
        kind: "summary".to_string(),
        source: source.to_string(),
        archive_path: archive_path.to_string(),
        status: "error".to_string(),
        note: Some(err),
    }
}

fn format_rfc3339(value: OffsetDateTime) -> Result<String, String> {
    value.format(&Rfc3339).map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use firewall::controlplane::cluster::types::ClusterCommand;
    use openraft::entry::EntryPayload;
    use openraft::storage::{RaftLogStorage, RaftStateMachine};
    use openraft::{BasicNode, CommittedLeaderId, Entry, LogId, Membership, Vote};
    use std::collections::{BTreeMap, BTreeSet};
    use tempfile::TempDir;

    fn test_log_id(term: u64, node_id: u128, index: u64) -> LogId<u128> {
        LogId::new(CommittedLeaderId::new(term, node_id), index)
    }

    #[test]
    fn sysdump_redacts_api_auth_private_keys() {
        let input = br#"{
  "active_kid": "kid-1",
  "keys": [{
    "kid": "kid-1",
    "public_key": "pub",
    "private_key": "secret",
    "created_at": "2026-01-01T00:00:00Z",
    "status": "active"
  }]
}"#
        .to_vec();

        let redacted = transform_file_bytes(Path::new("/tmp/api-auth.json"), input).unwrap();
        let rendered = String::from_utf8(redacted).unwrap();
        assert!(rendered.contains("\"private_key\": \"<redacted>\""));
        assert!(!rendered.contains("\"private_key\": \"secret\""));
    }

    #[test]
    fn sysdump_redacts_secret_key_files() {
        let redacted =
            transform_file_bytes(Path::new("/tmp/intercept-ca.key"), b"pem".to_vec()).unwrap();
        assert_eq!(
            String::from_utf8(redacted).unwrap(),
            "redacted secret file: intercept-ca.key\n"
        );
    }

    #[tokio::test]
    async fn sysdump_cluster_summary_includes_membership_and_vote() {
        let dir = TempDir::new().unwrap();
        let mut store = ClusterStore::open(dir.path()).unwrap();

        store.save_vote(&Vote::new_committed(7, 11)).await.unwrap();

        let mut voters = BTreeSet::new();
        voters.insert(11u128);
        voters.insert(22u128);
        let mut nodes = BTreeMap::new();
        nodes.insert(
            11u128,
            BasicNode {
                addr: "10.0.0.11:7000".to_string(),
            },
        );
        nodes.insert(
            22u128,
            BasicNode {
                addr: "10.0.0.22:7000".to_string(),
            },
        );
        let membership = Membership::new(vec![voters], nodes);
        let entries = vec![
            Entry {
                log_id: test_log_id(7, 11, 2),
                payload: EntryPayload::Blank,
            },
            Entry {
                log_id: test_log_id(7, 11, 3),
                payload: EntryPayload::Membership(membership),
            },
            Entry {
                log_id: test_log_id(7, 11, 4),
                payload: EntryPayload::Normal(ClusterCommand::Put {
                    key: b"policies/index".to_vec(),
                    value: br#"{"policies":[]}"#.to_vec(),
                }),
            },
        ];
        store.apply(entries).await.unwrap();

        let summary = build_cluster_summary(&store).unwrap();
        assert_eq!(summary.current_term, Some(7));
        assert_eq!(summary.voted_for.as_deref(), Some("11"));
        assert_eq!(summary.vote_committed, Some(true));
        assert_eq!(summary.last_applied_index, Some(4));
        assert_eq!(summary.membership_log_index, Some(3));
        assert_eq!(summary.voter_count, 2);
        assert_eq!(summary.node_count, 2);
        assert_eq!(summary.nodes[0].role, "leader");
        assert_eq!(summary.nodes[0].node_id, "11");
    }
}
