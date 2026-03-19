use std::env;
use std::net::Ipv4Addr;

use firewall::controlplane::ready::ReadinessState;
use firewall::controlplane::wiretap::{load_or_create_node_id, WiretapHub};
use firewall::controlplane::{self, PolicyStore};
#[cfg(test)]
use firewall::dataplane::Packet;
use firewall::dataplane::{DataplaneConfigStore, DrainControl, SnatMode};
use firewall::logging;
mod runtime;
use tracing::{error, info, warn};

use runtime::auth::{auth_usage, parse_auth_args, run_auth_command};
use runtime::bootstrap::dataplane_config::{
    dpdk_static_config_from_env, imds_dataplane_from_mgmt_ip,
};
use runtime::bootstrap::dataplane_warmup::maybe_spawn_soft_dataplane_autoconfig_task;
use runtime::bootstrap::integration::build_integration_provider;
use runtime::bootstrap::network::{dataplane_ipv4_config, internal_ipv4_config};
use runtime::bootstrap::policy_state::init_local_controlplane_state;
use runtime::bootstrap::shutdown::spawn_signal_shutdown_task;
use runtime::bootstrap::startup::{
    build_dataplane_runtime_network_config, log_startup_summary, maybe_select_cluster_seed,
    resolve_bindings, run_cluster_migration_if_requested, start_cluster_runtime,
};
use runtime::bootstrap::task_wait::await_runtime_tasks;
use runtime::cli::{parse_args, usage, CloudProviderKind, DataPlaneMode};
#[cfg(test)]
use runtime::dpdk::worker_plan::{
    choose_dpdk_worker_plan, flow_steer_payload, parse_truthy_flag,
    service_lane_enabled_with_override, shared_demux_owner_for_packet,
    shared_demux_owner_for_packet_with_policy, DpdkPerfMode, DpdkSingleQueueStrategy,
    DpdkWorkerMode,
};
use runtime::startup::controlplane_runtime::start_controlplane_runtime;
use runtime::startup::dataplane_bootstrap::bootstrap_dataplane_runtime;
use runtime::startup::dataplane_thread::{spawn_dataplane_runtime_thread, DataplaneRuntimeConfig};
use runtime::startup::integration_task::spawn_integration_manager_task;
use runtime::sysdump::{parse_sysdump_args, run_sysdump, sysdump_usage};

fn boxed_error(msg: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::other(msg.into()).into()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Err(err) = logging::init_logging() {
        eprintln!("{err}");
    }
    let bin = env::args().next().unwrap_or_else(|| "firewall".to_string());
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(|arg| arg.as_str()) == Some("auth") {
        let cmd = match parse_auth_args(&bin, &args[1..]) {
            Ok(cmd) => cmd,
            Err(err) => {
                eprintln!("{err}\n\n{}", auth_usage(&bin));
                std::process::exit(2);
            }
        };
        if let Err(err) = run_auth_command(cmd).await {
            eprintln!("{err}");
            std::process::exit(2);
        }
        return Ok(());
    }
    if args.first().map(|arg| arg.as_str()) == Some("sysdump") {
        let cmd = match parse_sysdump_args(&bin, &args[1..]) {
            Ok(cmd) => cmd,
            Err(err) => {
                eprintln!("{err}\n\n{}", sysdump_usage(&bin));
                std::process::exit(2);
            }
        };
        if let Err(err) = run_sysdump(cmd).await {
            eprintln!("{err}");
            std::process::exit(2);
        }
        return Ok(());
    }

    let mut cfg = match parse_args(&bin, args) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}\n\n{}", usage(&bin));
            std::process::exit(2);
        }
    };
    if cfg.cloud_provider != CloudProviderKind::None {
        std::env::set_var("NEUWERK_CLOUD_PROVIDER", cfg.cloud_provider.as_str());
    }

    let integration_provider = build_integration_provider(&cfg).map_err(boxed_error)?;
    maybe_select_cluster_seed(&mut cfg, integration_provider.clone()).await;
    log_startup_summary(&cfg);

    let dpdk_enabled = matches!(cfg.data_plane_mode, DataPlaneMode::Dpdk);
    if dpdk_enabled && matches!(cfg.snat_mode, SnatMode::Static(_)) {
        eprintln!("--snat <ipv4> is only supported in software dataplane mode");
        std::process::exit(2);
    }
    let soft_dp_config = if dpdk_enabled {
        None
    } else {
        dataplane_ipv4_config(&cfg.data_plane_iface).await.ok()
    };

    let bindings = match resolve_bindings(&cfg, dpdk_enabled).await {
        Ok(bindings) => bindings,
        Err(err) => {
            eprintln!("management interface ip error: {err}");
            std::process::exit(2);
        }
    };
    let management_ip = bindings.management_ip;
    let http_bind = bindings.http_bind;
    let http_advertise = bindings.http_advertise;
    let metrics_bind = bindings.metrics_bind;

    info!(
        http_bind = %http_bind,
        http_advertise = %http_advertise,
        metrics_bind = %metrics_bind,
        "resolved control-plane listener addresses"
    );

    let dataplane_network = build_dataplane_runtime_network_config(&cfg);
    let internal_net = dataplane_network.internal_net;
    let internal_prefix = dataplane_network.internal_prefix;
    let public_ip = dataplane_network.public_ip;
    let data_port = dataplane_network.data_port;
    let overlay = dataplane_network.overlay;

    let dataplane_config = DataplaneConfigStore::new();
    let policy_store = PolicyStore::new_with_config(
        cfg.default_policy,
        internal_net,
        internal_prefix,
        dataplane_config.clone(),
    );
    if let Some((ip, prefix, mac)) = soft_dp_config {
        dataplane_config.set(firewall::dataplane::DataplaneConfig {
            ip,
            prefix,
            gateway: Ipv4Addr::UNSPECIFIED,
            mac,
            lease_expiry: None,
        });
    }

    if dpdk_enabled && dataplane_config.get().is_none() {
        match dpdk_static_config_from_env() {
            Ok(Some(config)) => {
                info!(
                    dataplane_ip = %config.ip,
                    dataplane_prefix = config.prefix,
                    dataplane_gateway = %config.gateway,
                    "dpdk static bootstrap configured dataplane address"
                );
                dataplane_config.set(config);
            }
            Ok(None) => {}
            Err(err) => warn!(error = %err, "dpdk static bootstrap failed"),
        }
    }

    if dpdk_enabled && dataplane_config.get().is_none() {
        match imds_dataplane_from_mgmt_ip(management_ip).await {
            Ok((ip, prefix, gateway, mac)) => {
                dataplane_config.set(firewall::dataplane::DataplaneConfig {
                    ip,
                    prefix,
                    gateway,
                    mac,
                    lease_expiry: None,
                });
                info!(
                    dataplane_ip = %ip,
                    dataplane_prefix = prefix,
                    dataplane_gateway = %gateway,
                    "dpdk imds bootstrap configured dataplane address"
                );
            }
            Err(err) => {
                warn!(error = %err, "dpdk imds bootstrap failed");
            }
        }
    }

    if !dpdk_enabled && cfg.internal_cidr.is_none() {
        if let Ok((ip, prefix)) =
            internal_ipv4_config(&cfg.management_iface, &cfg.data_plane_iface).await
        {
            let _ = policy_store.update_internal_cidr(ip, prefix);
        } else {
            warn!("internal CIDR not detected; relying on policy source groups");
        }
    }

    maybe_spawn_soft_dataplane_autoconfig_task(
        &cfg,
        dpdk_enabled,
        soft_dp_config.is_some(),
        dataplane_config.clone(),
    );
    let local_state = match init_local_controlplane_state(&cfg, &policy_store) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let local_policy_store = local_state.local_policy_store;
    let local_service_accounts_dir = local_state.local_service_accounts_dir;
    let local_integrations_dir = local_state.local_integrations_dir;
    let policy_applied_generation = policy_store.policy_applied_tracker();
    let service_policy_applied_generation = policy_store.service_policy_applied_tracker();
    let dns_allowlist_for_dp = policy_store.dns_allowlist();
    let wiretap_hub = WiretapHub::new(1024);
    let metrics = match controlplane::metrics::Metrics::new() {
        Ok(metrics) => metrics,
        Err(err) => {
            eprintln!("metrics init error: {err}");
            std::process::exit(2);
        }
    };
    if dpdk_enabled {
        match firewall::dataplane::preinit_dpdk_eal(&cfg.data_plane_iface) {
            Ok(()) => {
                metrics.set_dpdk_init_ok(true);
                info!("dpdk preinit complete");
            }
            Err(err) => {
                metrics.set_dpdk_init_ok(false);
                metrics.inc_dpdk_init_failure();
                error!(error = %err, "dpdk preinit failed");
                std::process::exit(2);
            }
        }
    }
    let node_id = match load_or_create_node_id(&cfg.cluster.node_id_path) {
        Ok(node_id) => node_id,
        Err(err) => {
            eprintln!("node id error: {err}");
            std::process::exit(2);
        }
    };
    let node_uuid = match uuid::Uuid::parse_str(node_id.trim()) {
        Ok(node_id) => node_id,
        Err(err) => {
            eprintln!("node id error: {err}");
            std::process::exit(2);
        }
    };

    let cluster_runtime =
        match start_cluster_runtime(&cfg, Some(wiretap_hub.clone()), metrics.clone()).await {
            Ok(runtime) => runtime,
            Err(err) => {
                error!(error = %err, "cluster runtime failed");
                std::process::exit(2);
            }
        };

    if let Err(err) = run_cluster_migration_if_requested(
        &cfg,
        cluster_runtime.as_ref(),
        local_policy_store.clone(),
        local_service_accounts_dir.clone(),
        node_uuid,
    )
    .await
    {
        eprintln!("{err}");
        std::process::exit(2);
    }

    let drain_control = DrainControl::new();
    let readiness = ReadinessState::new(
        dataplane_config.clone(),
        policy_store.clone(),
        cluster_runtime
            .as_ref()
            .map(|runtime| runtime.store.clone()),
        cluster_runtime.as_ref().map(|runtime| runtime.raft.clone()),
    );
    readiness.set_policy_ready(true);
    readiness.set_drain_control(drain_control.clone());

    let controlplane_runtime = match start_controlplane_runtime(
        &cfg,
        management_ip,
        http_bind,
        http_advertise,
        metrics_bind,
        policy_store.clone(),
        local_policy_store.clone(),
        local_integrations_dir.clone(),
        cluster_runtime.as_ref(),
        readiness.clone(),
        metrics.clone(),
        dpdk_enabled,
        node_id.clone(),
        wiretap_hub.clone(),
    )
    .await
    {
        Ok(handles) => handles,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    let runtime::startup::controlplane_runtime::ControlplaneRuntimeHandles {
        dns_task,
        http_task,
        http_shutdown,
        wiretap_emitter,
        audit_emitter,
        shared_intercept_demux,
    } = controlplane_runtime;

    let shutdown_task =
        spawn_signal_shutdown_task(readiness.clone(), drain_control.clone(), http_shutdown);

    let drain_control_for_dp = drain_control.clone();
    let _integration_task = spawn_integration_manager_task(
        &cfg,
        integration_provider.clone(),
        cluster_runtime.as_ref(),
        http_advertise,
        metrics.clone(),
        drain_control.clone(),
    )
    .map_err(boxed_error)?;

    let dataplane_bootstrap = bootstrap_dataplane_runtime(
        &cfg,
        dpdk_enabled,
        dataplane_config.clone(),
        policy_store.clone(),
        metrics.clone(),
        readiness.clone(),
    )
    .map_err(boxed_error)?;
    let runtime::startup::dataplane_bootstrap::DataplaneBootstrap {
        dhcp_task,
        dhcp_tx,
        dhcp_rx,
        mac_tx,
    } = dataplane_bootstrap;
    readiness.set_dataplane_running(true);
    let dataplane_task = match spawn_dataplane_runtime_thread(DataplaneRuntimeConfig {
        data_plane_iface: cfg.data_plane_iface,
        data_plane_mode: cfg.data_plane_mode,
        idle_timeout_secs: cfg.idle_timeout_secs,
        policy: policy_store.snapshot(),
        policy_snapshot: policy_store.shared_snapshot(),
        exact_source_group_index: policy_store.exact_source_group_index(),
        policy_applied_generation,
        service_policy_applied_generation,
        dns_allowlist: dns_allowlist_for_dp,
        dns_target_ips: cfg.dns_target_ips.clone(),
        wiretap_emitter: Some(wiretap_emitter),
        audit_emitter: Some(audit_emitter),
        internal_net,
        internal_prefix,
        public_ip,
        snat_mode: cfg.snat_mode,
        overlay: overlay.clone(),
        data_port,
        dataplane_config: dataplane_config.clone(),
        drain_control: Some(drain_control_for_dp),
        dhcp_tx,
        dhcp_rx,
        mac_tx,
        shared_intercept_demux: shared_intercept_demux.clone(),
        metrics: metrics.clone(),
    }) {
        Ok(task) => task,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    await_runtime_tasks(
        http_task,
        dns_task,
        dataplane_task,
        dhcp_task,
        Some(shutdown_task),
    )
    .await
    .map_err(boxed_error)
}

#[cfg(test)]
mod main_tests;
