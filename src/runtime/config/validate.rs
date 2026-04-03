use std::net::Ipv4Addr;
use std::path::PathBuf;

use super::schema::{DataplaneConfigFile, RuntimeConfigFile, SnatConfigFile};
use super::types::{
    AwsIntegrationConfig, AzureIntegrationConfig, BootstrapConfig, ClusterConfig, DataplaneConfig,
    DefaultPolicy, DnsConfig, DpdkConfig, DpdkIovaMode, DpdkOverlayConfig, DpdkPerfMode,
    DpdkSingleQueueMode, EncapMode, GcpIntegrationConfig, HttpConfig, IntegrationConfig,
    IntegrationMembershipConfig, IntegrationMode, LoadedConfig, MetricsConfig, PolicyConfig,
    RuntimeBehaviorConfig, SnatMode, TlsInterceptConfig, TlsInterceptH2Config, ValidatedConfig,
    DNS_UPSTREAM_TIMEOUT_MS_DEFAULT,
};
use neuwerk::controlplane::trafficd::UpstreamTlsVerificationMode;

const DNS_ALLOWLIST_IDLE_SLACK_SECS: u64 = 120;
const DNS_ALLOWLIST_GC_INTERVAL_SECS: u64 = 30;
const DHCP_TIMEOUT_SECS: u64 = 5;
const DHCP_RETRY_MAX: u32 = 5;
const DHCP_LEASE_MIN_SECS: u64 = 60;

pub(crate) fn validate_config(raw: RuntimeConfigFile) -> Result<LoadedConfig, String> {
    if raw.version != 1 {
        return Err(format!(
            "config validation error: unsupported config version {}, expected 1",
            raw.version
        ));
    }

    let cluster = build_cluster_config(raw.cluster);
    let integration = build_integration_config(raw.integration)?;
    let dataplane = build_dataplane_config(raw.dataplane)?;

    let validated = LoadedConfig {
        version: raw.version,
        bootstrap: BootstrapConfig {
            management_interface: raw.bootstrap.management_interface,
            data_interface: raw.bootstrap.data_interface,
            cloud_provider: canonical_cloud_provider(&raw.bootstrap.cloud_provider)?,
            data_plane_mode: canonical_data_plane_mode(&raw.bootstrap.data_plane_mode)?,
        },
        dns: validate_dns(raw.dns)?,
        runtime: build_runtime_behavior_config(raw.runtime)?,
        policy: build_policy_config(raw.policy)?,
        http: build_http_config(raw.http),
        metrics: raw
            .metrics
            .map_or_else(MetricsConfig::default, |metrics| MetricsConfig {
                bind: metrics.bind,
                allow_public_bind: metrics.allow_public_bind,
            }),
        cluster,
        integration,
        tls_intercept: build_tls_intercept_config(raw.tls_intercept)?,
        dataplane,
        dpdk: raw.dpdk.map(build_dpdk_config).transpose()?,
    };
    validate_semantics(&validated)?;
    Ok(validated)
}

fn build_runtime_behavior_config(
    raw: Option<super::schema::RuntimeBehaviorConfigFile>,
) -> Result<RuntimeBehaviorConfig, String> {
    let Some(raw) = raw else {
        return Ok(RuntimeBehaviorConfig::default());
    };
    let mut cfg = RuntimeBehaviorConfig::default();
    if let Some(threads) = raw.controlplane_worker_threads {
        if threads == 0 {
            return Err(
                "config validation error: runtime.controlplane_worker_threads must be > 0"
                    .to_string(),
            );
        }
        cfg.controlplane_worker_threads = threads;
    }
    if let Some(threads) = raw.http_worker_threads {
        if threads == 0 {
            return Err(
                "config validation error: runtime.http_worker_threads must be > 0".to_string(),
            );
        }
        cfg.http_worker_threads = threads;
    }
    if let Some(kubernetes) = raw.kubernetes {
        if let Some(secs) = kubernetes.reconcile_interval_secs {
            if secs == 0 {
                return Err(
                    "config validation error: runtime.kubernetes.reconcile_interval_secs must be > 0"
                        .to_string(),
                );
            }
            cfg.kubernetes.reconcile_interval_secs = secs;
        }
        if let Some(secs) = kubernetes.stale_grace_secs {
            if secs == 0 {
                return Err(
                    "config validation error: runtime.kubernetes.stale_grace_secs must be > 0"
                        .to_string(),
                );
            }
            cfg.kubernetes.stale_grace_secs = secs;
        }
    }
    Ok(cfg)
}

fn canonical_cloud_provider(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok("none".to_string());
    }
    if value.eq_ignore_ascii_case("azure") {
        return Ok("azure".to_string());
    }
    if value.eq_ignore_ascii_case("aws") {
        return Ok("aws".to_string());
    }
    if value.eq_ignore_ascii_case("gcp") {
        return Ok("gcp".to_string());
    }
    Err(format!(
        "config validation error: unsupported bootstrap.cloud_provider `{value}`"
    ))
}

fn canonical_data_plane_mode(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("soft") || value.eq_ignore_ascii_case("tun") {
        return Ok("tun".to_string());
    }
    if value.eq_ignore_ascii_case("tap") {
        return Ok("tap".to_string());
    }
    if value.eq_ignore_ascii_case("dpdk") {
        return Ok("dpdk".to_string());
    }
    Err(format!(
        "config validation error: unsupported bootstrap.data_plane_mode `{value}`"
    ))
}

fn validate_dns(raw: super::schema::DnsConfigFile) -> Result<DnsConfig, String> {
    if raw.target_ips.is_empty() {
        return Err("config validation error: dns.target_ips must not be empty".to_string());
    }
    if raw.upstreams.is_empty() {
        return Err("config validation error: dns.upstreams must not be empty".to_string());
    }
    let upstream_timeout_ms = raw
        .upstream_timeout_ms
        .unwrap_or(DNS_UPSTREAM_TIMEOUT_MS_DEFAULT);
    if upstream_timeout_ms == 0 {
        return Err("config validation error: dns.upstream_timeout_ms must be > 0".to_string());
    }
    Ok(DnsConfig {
        target_ips: raw.target_ips,
        upstreams: raw.upstreams,
        upstream_timeout_ms,
    })
}

fn build_policy_config(
    raw: Option<super::schema::PolicyConfigFile>,
) -> Result<PolicyConfig, String> {
    let Some(raw) = raw else {
        return Ok(PolicyConfig::default());
    };

    let default = raw
        .default
        .as_deref()
        .map(parse_default_policy)
        .transpose()?
        .unwrap_or(DefaultPolicy::Deny);
    let internal_cidr = raw
        .internal_cidr
        .as_deref()
        .map(parse_ipv4_cidr)
        .transpose()?;
    Ok(PolicyConfig {
        default,
        internal_cidr,
    })
}

fn parse_default_policy(value: &str) -> Result<DefaultPolicy, String> {
    if value.eq_ignore_ascii_case("allow") {
        return Ok(DefaultPolicy::Allow);
    }
    if value.eq_ignore_ascii_case("deny") {
        return Ok(DefaultPolicy::Deny);
    }
    Err(format!(
        "config validation error: unsupported policy.default `{value}`"
    ))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (net, prefix) = value.split_once('/').ok_or_else(|| {
        format!("config validation error: policy.internal_cidr must be CIDR, got `{value}`")
    })?;
    let net = net.parse::<Ipv4Addr>().map_err(|_| {
        format!("config validation error: policy.internal_cidr must be CIDR, got `{value}`")
    })?;
    let prefix = prefix.parse::<u8>().map_err(|_| {
        format!("config validation error: policy.internal_cidr must be CIDR, got `{value}`")
    })?;
    if prefix > 32 {
        return Err(format!(
            "config validation error: policy.internal_cidr prefix must be <= 32, got `{prefix}`"
        ));
    }
    Ok((net, prefix))
}

fn build_http_config(raw: Option<super::schema::HttpConfigFile>) -> HttpConfig {
    let Some(raw) = raw else {
        return HttpConfig::default();
    };
    HttpConfig {
        bind: raw.bind,
        advertise: raw.advertise,
        external_url: raw.external_url,
        tls_dir: raw
            .tls_dir
            .unwrap_or_else(|| PathBuf::from("/var/lib/neuwerk/http-tls")),
        cert_path: raw.cert_path,
        key_path: raw.key_path,
        ca_path: raw.ca_path,
        tls_san: raw.tls_san,
    }
}

fn build_cluster_config(raw: Option<super::schema::ClusterConfigFile>) -> ClusterConfig {
    let Some(raw) = raw else {
        return ClusterConfig::default();
    };

    let mut cfg = ClusterConfig::default();
    cfg.migrate_from_local = raw.migrate_from_local;
    cfg.migrate_force = raw.migrate_force;
    cfg.migrate_verify = raw.migrate_verify;

    let enabled = raw.bind.is_some()
        || raw.join_bind.is_some()
        || raw.advertise.is_some()
        || raw.join_seed.is_some()
        || raw.data_dir.is_some()
        || raw.node_id_path.is_some()
        || raw.token_path.is_some();
    if !enabled {
        return cfg;
    }

    cfg.enabled = true;
    cfg.bind = raw.bind.unwrap_or(cfg.bind);
    cfg.join_bind = raw.join_bind.unwrap_or_else(|| {
        std::net::SocketAddr::new(cfg.bind.ip(), cfg.bind.port().saturating_add(1))
    });
    cfg.advertise = raw.advertise.unwrap_or(cfg.bind);
    cfg.join_seed = raw.join_seed;
    cfg.data_dir = raw.data_dir.unwrap_or(cfg.data_dir);
    cfg.node_id_path = raw.node_id_path.unwrap_or(cfg.node_id_path);
    cfg.token_path = raw.token_path.unwrap_or(cfg.token_path);
    cfg
}

fn build_integration_config(
    raw: Option<super::schema::IntegrationConfigFile>,
) -> Result<IntegrationConfig, String> {
    let Some(raw) = raw else {
        return Ok(IntegrationConfig::default());
    };
    let mut cfg = IntegrationConfig::default();
    cfg.mode = raw
        .mode
        .as_deref()
        .map(parse_integration_mode)
        .transpose()?
        .unwrap_or(IntegrationMode::None);
    if let Some(route_name) = raw.route_name {
        cfg.route_name = route_name;
    }
    if let Some(cluster_name) = raw.cluster_name {
        cfg.cluster_name = cluster_name;
    }
    if let Some(drain_timeout_secs) = raw.drain_timeout_secs {
        cfg.drain_timeout_secs = drain_timeout_secs;
    }
    if let Some(reconcile_interval_secs) = raw.reconcile_interval_secs {
        cfg.reconcile_interval_secs = reconcile_interval_secs;
    }
    if let Some(membership) = raw.membership {
        cfg.membership = IntegrationMembershipConfig {
            auto_evict_terminating: membership
                .auto_evict_terminating
                .unwrap_or(cfg.membership.auto_evict_terminating),
            stale_after_secs: membership
                .stale_after_secs
                .unwrap_or(cfg.membership.stale_after_secs),
            min_voters: membership.min_voters.unwrap_or(cfg.membership.min_voters),
        };
    }
    if cfg.membership.min_voters == 0 {
        return Err(
            "config validation error: integration.membership.min_voters must be > 0".to_string(),
        );
    }
    cfg.aws = raw.aws.map(|aws| AwsIntegrationConfig {
        region: aws.region,
        vpc_id: aws.vpc_id,
        asg_name: aws.asg_name,
    });
    cfg.azure = raw.azure.map(|azure| AzureIntegrationConfig {
        subscription_id: azure.subscription_id,
        resource_group: azure.resource_group,
        vmss_name: azure.vmss_name,
    });
    cfg.gcp = raw.gcp.map(|gcp| GcpIntegrationConfig {
        project: gcp.project,
        region: gcp.region,
        ig_name: gcp.ig_name,
    });
    Ok(cfg)
}

fn parse_integration_mode(value: &str) -> Result<IntegrationMode, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok(IntegrationMode::None);
    }
    if value.eq_ignore_ascii_case("azure-vmss") {
        return Ok(IntegrationMode::AzureVmss);
    }
    if value.eq_ignore_ascii_case("aws-asg") {
        return Ok(IntegrationMode::AwsAsg);
    }
    if value.eq_ignore_ascii_case("gcp-mig") {
        return Ok(IntegrationMode::GcpMig);
    }
    Err(format!(
        "config validation error: unsupported integration.mode `{value}`"
    ))
}

fn build_dataplane_config(raw: Option<DataplaneConfigFile>) -> Result<DataplaneConfig, String> {
    let mut cfg = DataplaneConfig::default();
    let mut snat_explicit = false;
    let mut encap_udp_port_set = false;
    if let Some(raw) = raw {
        if let Some(idle_timeout_secs) = raw.idle_timeout_secs {
            if idle_timeout_secs == 0 {
                return Err(
                    "config validation error: dataplane.idle_timeout_secs must be >= 1".to_string(),
                );
            }
            cfg.idle_timeout_secs = idle_timeout_secs;
        }
        if let Some(dns_allowlist_idle_secs) = raw.dns_allowlist_idle_secs {
            if dns_allowlist_idle_secs == 0 {
                return Err(
                    "config validation error: dataplane.dns_allowlist_idle_secs must be >= 1"
                        .to_string(),
                );
            }
            cfg.dns_allowlist_idle_secs = dns_allowlist_idle_secs;
        } else {
            cfg.dns_allowlist_idle_secs = cfg.idle_timeout_secs + DNS_ALLOWLIST_IDLE_SLACK_SECS;
        }
        if let Some(dns_allowlist_gc_interval_secs) = raw.dns_allowlist_gc_interval_secs {
            if dns_allowlist_gc_interval_secs == 0 {
                return Err(
                    "config validation error: dataplane.dns_allowlist_gc_interval_secs must be >= 1"
                        .to_string(),
                );
            }
            cfg.dns_allowlist_gc_interval_secs = dns_allowlist_gc_interval_secs;
        } else {
            cfg.dns_allowlist_gc_interval_secs = DNS_ALLOWLIST_GC_INTERVAL_SECS;
        }
        if let Some(dhcp_timeout_secs) = raw.dhcp_timeout_secs {
            if dhcp_timeout_secs == 0 {
                return Err(
                    "config validation error: dataplane.dhcp_timeout_secs must be >= 1".to_string(),
                );
            }
            cfg.dhcp_timeout_secs = dhcp_timeout_secs;
        }
        if let Some(dhcp_retry_max) = raw.dhcp_retry_max {
            if dhcp_retry_max == 0 {
                return Err(
                    "config validation error: dataplane.dhcp_retry_max must be >= 1".to_string(),
                );
            }
            cfg.dhcp_retry_max = dhcp_retry_max;
        }
        if let Some(dhcp_lease_min_secs) = raw.dhcp_lease_min_secs {
            if dhcp_lease_min_secs == 0 {
                return Err(
                    "config validation error: dataplane.dhcp_lease_min_secs must be >= 1"
                        .to_string(),
                );
            }
            cfg.dhcp_lease_min_secs = dhcp_lease_min_secs;
        }
        if let Some(snat) = raw.snat {
            snat_explicit = true;
            cfg.snat = parse_snat_mode(snat)?;
        }
        if let Some(encap_mode) = raw.encap_mode {
            cfg.encap_mode = canonical_encap_mode(&encap_mode)?.to_string();
        }
        cfg.encap_vni = raw.encap_vni;
        cfg.encap_vni_internal = raw.encap_vni_internal;
        cfg.encap_vni_external = raw.encap_vni_external;
        if let Some(encap_udp_port) = raw.encap_udp_port {
            if encap_udp_port == 0 {
                return Err(
                    "config validation error: dataplane.encap_udp_port must be between 1 and 65535"
                        .to_string(),
                );
            }
            encap_udp_port_set = true;
            cfg.encap_udp_port = Some(encap_udp_port);
        }
        if let Some(encap_udp_port_internal) = raw.encap_udp_port_internal {
            if encap_udp_port_internal == 0 {
                return Err(
                    "config validation error: dataplane.encap_udp_port_internal must be between 1 and 65535"
                        .to_string(),
                );
            }
            cfg.encap_udp_port_internal = Some(encap_udp_port_internal);
        }
        if let Some(encap_udp_port_external) = raw.encap_udp_port_external {
            if encap_udp_port_external == 0 {
                return Err(
                    "config validation error: dataplane.encap_udp_port_external must be between 1 and 65535"
                        .to_string(),
                );
            }
            cfg.encap_udp_port_external = Some(encap_udp_port_external);
        }
        if let Some(encap_mtu) = raw.encap_mtu {
            if encap_mtu == 0 {
                return Err("config validation error: dataplane.encap_mtu must be >= 1".to_string());
            }
            cfg.encap_mtu = encap_mtu;
        }
        if let Some(flow_table_capacity) = raw.flow_table_capacity {
            if flow_table_capacity == 0 {
                return Err(
                    "config validation error: dataplane.flow_table_capacity must be >= 1"
                        .to_string(),
                );
            }
            cfg.flow_table_capacity = flow_table_capacity;
        }
        if let Some(nat_table_capacity) = raw.nat_table_capacity {
            if nat_table_capacity == 0 {
                return Err(
                    "config validation error: dataplane.nat_table_capacity must be >= 1"
                        .to_string(),
                );
            }
            cfg.nat_table_capacity = nat_table_capacity;
        }
        if let Some(flow_incomplete_tcp_idle_timeout_secs) =
            raw.flow_incomplete_tcp_idle_timeout_secs
        {
            if flow_incomplete_tcp_idle_timeout_secs == 0 {
                return Err(
                    "config validation error: dataplane.flow_incomplete_tcp_idle_timeout_secs must be >= 1"
                        .to_string(),
                );
            }
            cfg.flow_incomplete_tcp_idle_timeout_secs = Some(flow_incomplete_tcp_idle_timeout_secs);
        }
        if let Some(flow_incomplete_tcp_syn_sent_idle_timeout_secs) =
            raw.flow_incomplete_tcp_syn_sent_idle_timeout_secs
        {
            if flow_incomplete_tcp_syn_sent_idle_timeout_secs == 0 {
                return Err(
                    "config validation error: dataplane.flow_incomplete_tcp_syn_sent_idle_timeout_secs must be >= 1"
                        .to_string(),
                );
            }
            cfg.flow_incomplete_tcp_syn_sent_idle_timeout_secs =
                flow_incomplete_tcp_syn_sent_idle_timeout_secs;
        }
        cfg.syn_only_enabled = raw.syn_only_enabled;
        cfg.detailed_observability = raw.detailed_observability;
        if let Some(admission) = raw.admission {
            cfg.admission.max_active_flows = validate_optional_usize(
                admission.max_active_flows,
                "dataplane.admission.max_active_flows",
            )?;
            cfg.admission.max_active_nat_entries = validate_optional_usize(
                admission.max_active_nat_entries,
                "dataplane.admission.max_active_nat_entries",
            )?;
            cfg.admission.max_pending_tls_flows = validate_optional_usize(
                admission.max_pending_tls_flows,
                "dataplane.admission.max_pending_tls_flows",
            )?;
            cfg.admission.max_active_flows_per_source_group = validate_optional_usize(
                admission.max_active_flows_per_source_group,
                "dataplane.admission.max_active_flows_per_source_group",
            )?;
        }
    } else {
        cfg.dhcp_timeout_secs = DHCP_TIMEOUT_SECS;
        cfg.dhcp_retry_max = DHCP_RETRY_MAX;
        cfg.dhcp_lease_min_secs = DHCP_LEASE_MIN_SECS;
    }

    let encap_mode = parse_encap_mode(&cfg.encap_mode)?;
    if !snat_explicit && !matches!(encap_mode, EncapMode::None) {
        cfg.snat = SnatMode::None;
    }

    if matches!(encap_mode, EncapMode::Vxlan) && !encap_udp_port_set {
        if cfg.encap_vni_internal.is_some() && cfg.encap_udp_port_internal.is_none() {
            cfg.encap_udp_port_internal = Some(10800);
        }
        if cfg.encap_vni_external.is_some() && cfg.encap_udp_port_external.is_none() {
            cfg.encap_udp_port_external = Some(10801);
        }
    }

    cfg.encap_udp_port = Some(cfg.encap_udp_port.unwrap_or(match encap_mode {
        EncapMode::Geneve => 6081,
        EncapMode::Vxlan => 10800,
        EncapMode::None => 0,
    }));

    validate_overlay(&cfg, encap_mode)?;
    Ok(cfg)
}

fn build_dpdk_config(raw: super::schema::DpdkConfigFile) -> Result<DpdkConfig, String> {
    let mut cfg = DpdkConfig {
        static_ip: raw.static_ip,
        static_prefix_len: raw.static_prefix_len,
        static_gateway: raw.static_gateway,
        static_mac: raw.static_mac,
        ..DpdkConfig::default()
    };
    cfg.workers = match raw.workers.as_ref() {
        Some(value) => parse_dpdk_workers(value)?,
        None => None,
    };
    cfg.core_ids = raw.core_ids;
    cfg.allow_azure_multiworker = raw.allow_azure_multiworker;
    cfg.single_queue_mode = raw
        .single_queue_mode
        .as_deref()
        .map(parse_dpdk_single_queue_mode)
        .transpose()?
        .unwrap_or_default();
    cfg.perf_mode = raw
        .perf_mode
        .as_deref()
        .map(parse_dpdk_perf_mode)
        .transpose()?
        .unwrap_or_default();
    cfg.force_shared_rx_demux = raw.force_shared_rx_demux;
    cfg.pin_https_demux_owner = raw.pin_https_demux_owner;
    cfg.disable_service_lane = raw.disable_service_lane;
    cfg.lockless_queue_per_worker = raw.lockless_queue_per_worker;
    cfg.shared_rx_owner_only = raw.shared_rx_owner_only;
    if let Some(value) = raw.housekeeping_interval_packets {
        if value == 0 {
            return Err(
                "config validation error: dpdk.housekeeping_interval_packets must be > 0"
                    .to_string(),
            );
        }
        cfg.housekeeping_interval_packets = value;
    }
    if let Some(value) = raw.housekeeping_interval_us {
        if value == 0 {
            return Err(
                "config validation error: dpdk.housekeeping_interval_us must be > 0".to_string(),
            );
        }
        cfg.housekeeping_interval_us = value;
    }
    cfg.pin_state_shard_guard = raw.pin_state_shard_guard;
    if let Some(value) = raw.pin_state_shard_burst {
        if value == 0 {
            return Err(
                "config validation error: dpdk.pin_state_shard_burst must be > 0".to_string(),
            );
        }
        cfg.pin_state_shard_burst = value;
    }
    if let Some(value) = raw.state_shards {
        if value == 0 {
            return Err("config validation error: dpdk.state_shards must be > 0".to_string());
        }
        cfg.state_shards = Some(value);
    }
    cfg.disable_in_memory = raw.disable_in_memory;
    cfg.iova_mode = raw
        .iova_mode
        .as_deref()
        .map(parse_dpdk_iova_mode)
        .transpose()?;
    cfg.force_netvsc = raw.force_netvsc;
    cfg.gcp_auto_probe = raw.gcp_auto_probe;
    cfg.driver_preload = raw.driver_preload;
    cfg.skip_bus_pci_preload = raw.skip_bus_pci_preload;
    cfg.prefer_pci = raw.prefer_pci;
    cfg.queue_override = positive_u16(raw.queue_override, "dpdk.queue_override")?;
    cfg.port_mtu = minimum_u16(raw.port_mtu, "dpdk.port_mtu", 576)?;
    cfg.mbuf_data_room = positive_u16(raw.mbuf_data_room, "dpdk.mbuf_data_room")?;
    cfg.mbuf_pool_size = positive_u32(raw.mbuf_pool_size, "dpdk.mbuf_pool_size")?;
    if let Some(value) = raw.rx_ring_size {
        if value == 0 {
            return Err("config validation error: dpdk.rx_ring_size must be > 0".to_string());
        }
        cfg.rx_ring_size = value;
    }
    if let Some(value) = raw.tx_ring_size {
        if value == 0 {
            return Err("config validation error: dpdk.tx_ring_size must be > 0".to_string());
        }
        cfg.tx_ring_size = value;
    }
    cfg.tx_checksum_offload = raw.tx_checksum_offload;
    cfg.allow_retaless_multi_queue = raw.allow_retaless_multi_queue;
    if let Some(service_lane) = raw.service_lane {
        if let Some(interface) = service_lane.interface {
            if interface.trim().is_empty() {
                return Err(
                    "config validation error: dpdk.service_lane.interface must not be empty"
                        .to_string(),
                );
            }
            cfg.service_lane.interface = interface.trim().to_string();
        }
        if let Some(ip) = service_lane.intercept_service_ip {
            cfg.service_lane.intercept_service_ip = ip;
        }
        if let Some(port) = service_lane.intercept_service_port {
            if port == 0 {
                return Err(
                    "config validation error: dpdk.service_lane.intercept_service_port must be > 0"
                        .to_string(),
                );
            }
            cfg.service_lane.intercept_service_port = port;
        }
        cfg.service_lane.multi_queue = service_lane.multi_queue;
    }
    if let Some(intercept_demux) = raw.intercept_demux {
        if let Some(value) = intercept_demux.gc_interval_ms {
            if value == 0 {
                return Err(
                    "config validation error: dpdk.intercept_demux.gc_interval_ms must be > 0"
                        .to_string(),
                );
            }
            cfg.intercept_demux.gc_interval_ms = value;
        }
        if let Some(value) = intercept_demux.max_entries {
            if value == 0 {
                return Err(
                    "config validation error: dpdk.intercept_demux.max_entries must be > 0"
                        .to_string(),
                );
            }
            cfg.intercept_demux.max_entries = value;
        }
        if let Some(value) = intercept_demux.shard_count {
            if value == 0 {
                return Err(
                    "config validation error: dpdk.intercept_demux.shard_count must be > 0"
                        .to_string(),
                );
            }
            cfg.intercept_demux.shard_count = value;
        }
        if let Some(value) = intercept_demux.host_frame_queue_max {
            if value == 0 {
                return Err("config validation error: dpdk.intercept_demux.host_frame_queue_max must be > 0".to_string());
            }
            cfg.intercept_demux.host_frame_queue_max = value;
        }
        if let Some(value) = intercept_demux.pending_arp_queue_max {
            if value == 0 {
                return Err("config validation error: dpdk.intercept_demux.pending_arp_queue_max must be > 0".to_string());
            }
            cfg.intercept_demux.pending_arp_queue_max = value;
        }
    }
    cfg.gateway_mac = raw.gateway_mac;
    cfg.dhcp_server_ip = raw.dhcp_server_ip;
    cfg.dhcp_server_mac = raw.dhcp_server_mac;
    if let Some(overlay) = raw.overlay {
        cfg.overlay = DpdkOverlayConfig {
            swap_tunnels: overlay.swap_tunnels,
            force_tunnel_src_port: overlay.force_tunnel_src_port,
            debug: overlay.debug,
            health_probe_debug: overlay.health_probe_debug,
        };
    }
    Ok(cfg)
}

fn positive_u16(value: Option<u16>, field: &str) -> Result<Option<u16>, String> {
    match value {
        Some(0) => Err(format!("config validation error: {field} must be > 0")),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn minimum_u16(value: Option<u16>, field: &str, minimum: u16) -> Result<Option<u16>, String> {
    match value {
        Some(value) if value < minimum => Err(format!(
            "config validation error: {field} must be >= {minimum}"
        )),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn positive_u32(value: Option<u32>, field: &str) -> Result<Option<u32>, String> {
    match value {
        Some(0) => Err(format!("config validation error: {field} must be > 0")),
        Some(value) => Ok(Some(value)),
        None => Ok(None),
    }
}

fn parse_dpdk_workers(
    value: &super::schema::DpdkWorkersConfigFile,
) -> Result<Option<usize>, String> {
    match value {
        super::schema::DpdkWorkersConfigFile::Count(0) => {
            Err("config validation error: dpdk.workers must be > 0 or `auto`".to_string())
        }
        super::schema::DpdkWorkersConfigFile::Count(value) => Ok(Some(*value)),
        super::schema::DpdkWorkersConfigFile::Scalar(raw) => {
            let trimmed = raw.trim();
            if trimmed.eq_ignore_ascii_case("auto") || trimmed.is_empty() {
                Ok(None)
            } else {
                let value = trimmed.parse::<usize>().map_err(|_| {
                    format!("config validation error: unsupported dpdk.workers `{raw}`")
                })?;
                if value == 0 {
                    return Err(
                        "config validation error: dpdk.workers must be > 0 or `auto`".to_string(),
                    );
                }
                Ok(Some(value))
            }
        }
    }
}

fn parse_dpdk_single_queue_mode(value: &str) -> Result<DpdkSingleQueueMode, String> {
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "demux" | "shared-demux" | "shared_rx_demux"
    ) {
        return Ok(DpdkSingleQueueMode::Demux);
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "single" | "single-worker" | "single_worker"
    ) {
        return Ok(DpdkSingleQueueMode::SingleWorker);
    }
    Err(format!(
        "config validation error: unsupported dpdk.single_queue_mode `{value}`"
    ))
}

fn parse_dpdk_perf_mode(value: &str) -> Result<DpdkPerfMode, String> {
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "standard" | "default" | "off"
    ) {
        return Ok(DpdkPerfMode::Standard);
    }
    if matches!(
        value.to_ascii_lowercase().as_str(),
        "aggressive" | "on" | "1" | "true" | "yes"
    ) {
        return Ok(DpdkPerfMode::Aggressive);
    }
    Err(format!(
        "config validation error: unsupported dpdk.perf_mode `{value}`"
    ))
}

fn parse_dpdk_iova_mode(value: &str) -> Result<DpdkIovaMode, String> {
    if value.eq_ignore_ascii_case("va") {
        return Ok(DpdkIovaMode::Va);
    }
    if value.eq_ignore_ascii_case("pa") {
        return Ok(DpdkIovaMode::Pa);
    }
    Err(format!(
        "config validation error: unsupported dpdk.iova_mode `{value}`"
    ))
}

fn build_tls_intercept_config(
    raw: Option<super::schema::TlsInterceptConfigFile>,
) -> Result<Option<TlsInterceptConfig>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let mut cfg = TlsInterceptConfig::default();
    if let Some(upstream_verify) = raw.upstream_verify {
        cfg.upstream_verify = parse_tls_intercept_upstream_verify(&upstream_verify)?;
    }
    if let Some(io_timeout_secs) = raw.io_timeout_secs {
        if io_timeout_secs == 0 {
            return Err(
                "config validation error: tls_intercept.io_timeout_secs must be >= 1".to_string(),
            );
        }
        cfg.io_timeout_secs = io_timeout_secs;
    }
    if let Some(listen_backlog) = raw.listen_backlog {
        if listen_backlog == 0 {
            return Err(
                "config validation error: tls_intercept.listen_backlog must be >= 1".to_string(),
            );
        }
        cfg.listen_backlog = listen_backlog;
    }
    if let Some(h2) = raw.h2 {
        cfg.h2 = build_tls_intercept_h2_config(h2)?;
    }
    Ok(Some(cfg))
}

fn build_tls_intercept_h2_config(
    raw: super::schema::TlsInterceptH2ConfigFile,
) -> Result<TlsInterceptH2Config, String> {
    let mut cfg = TlsInterceptH2Config::default();
    if let Some(body_timeout_secs) = raw.body_timeout_secs {
        if body_timeout_secs == 0 {
            return Err(
                "config validation error: tls_intercept.h2.body_timeout_secs must be >= 1"
                    .to_string(),
            );
        }
        cfg.body_timeout_secs = body_timeout_secs;
    }
    if let Some(max_concurrent_streams) = raw.max_concurrent_streams {
        if max_concurrent_streams == 0 {
            return Err(
                "config validation error: tls_intercept.h2.max_concurrent_streams must be >= 1"
                    .to_string(),
            );
        }
        cfg.max_concurrent_streams = max_concurrent_streams;
    }
    if let Some(max_requests_per_connection) = raw.max_requests_per_connection {
        if max_requests_per_connection == 0 {
            return Err(
                "config validation error: tls_intercept.h2.max_requests_per_connection must be >= 1"
                    .to_string(),
            );
        }
        cfg.max_requests_per_connection = max_requests_per_connection;
    }
    if let Some(pool_shards) = raw.pool_shards {
        if pool_shards == 0 {
            return Err(
                "config validation error: tls_intercept.h2.pool_shards must be >= 1".to_string(),
            );
        }
        cfg.pool_shards = pool_shards;
    }
    cfg.detailed_metrics = raw.detailed_metrics;
    if let Some(selection_inflight_weight) = raw.selection_inflight_weight {
        if selection_inflight_weight == 0 {
            return Err(
                "config validation error: tls_intercept.h2.selection_inflight_weight must be >= 1"
                    .to_string(),
            );
        }
        cfg.selection_inflight_weight = selection_inflight_weight;
    }
    if let Some(reconnect_backoff_base_ms) = raw.reconnect_backoff_base_ms {
        if reconnect_backoff_base_ms == 0 {
            return Err(
                "config validation error: tls_intercept.h2.reconnect_backoff_base_ms must be >= 1"
                    .to_string(),
            );
        }
        cfg.reconnect_backoff_base_ms = reconnect_backoff_base_ms;
    }
    if let Some(reconnect_backoff_max_ms) = raw.reconnect_backoff_max_ms {
        if reconnect_backoff_max_ms == 0 {
            return Err(
                "config validation error: tls_intercept.h2.reconnect_backoff_max_ms must be >= 1"
                    .to_string(),
            );
        }
        cfg.reconnect_backoff_max_ms = reconnect_backoff_max_ms;
    }
    Ok(cfg)
}

fn parse_tls_intercept_upstream_verify(value: &str) -> Result<UpstreamTlsVerificationMode, String> {
    if value.eq_ignore_ascii_case("strict") {
        return Ok(UpstreamTlsVerificationMode::Strict);
    }
    if value.eq_ignore_ascii_case("insecure") {
        return Ok(UpstreamTlsVerificationMode::Insecure);
    }
    Err(format!(
        "config validation error: unsupported tls_intercept.upstream_verify `{value}`"
    ))
}

fn validate_optional_usize(value: Option<usize>, field: &str) -> Result<Option<usize>, String> {
    match value {
        Some(0) => Err(format!("config validation error: {field} must be >= 1")),
        _ => Ok(value),
    }
}

fn parse_snat_mode(raw: SnatConfigFile) -> Result<SnatMode, String> {
    match raw {
        SnatConfigFile::Scalar(value) => parse_snat_scalar(&value),
        SnatConfigFile::Detailed(value) => parse_snat_detailed(value.mode.as_str(), value.ip),
    }
}

fn parse_snat_scalar(value: &str) -> Result<SnatMode, String> {
    if value.eq_ignore_ascii_case("auto") {
        return Ok(SnatMode::Auto);
    }
    if value.eq_ignore_ascii_case("none") {
        return Ok(SnatMode::None);
    }
    if value.eq_ignore_ascii_case("static") {
        return Err(
            "config validation error: dataplane.snat.ip is required when dataplane.snat.mode=static"
                .to_string(),
        );
    }
    let ip = value
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("config validation error: unsupported dataplane.snat `{value}`"))?;
    Ok(SnatMode::Static(ip))
}

fn parse_snat_detailed(mode: &str, ip: Option<Ipv4Addr>) -> Result<SnatMode, String> {
    if mode.eq_ignore_ascii_case("auto") {
        return Ok(SnatMode::Auto);
    }
    if mode.eq_ignore_ascii_case("none") {
        return Ok(SnatMode::None);
    }
    if mode.eq_ignore_ascii_case("static") {
        let ip = ip.ok_or_else(|| {
            "config validation error: dataplane.snat.ip is required when dataplane.snat.mode=static"
                .to_string()
        })?;
        return Ok(SnatMode::Static(ip));
    }
    Err(format!(
        "config validation error: unsupported dataplane.snat.mode `{mode}`"
    ))
}

fn canonical_encap_mode(value: &str) -> Result<&'static str, String> {
    if value.eq_ignore_ascii_case("none") {
        return Ok("none");
    }
    if value.eq_ignore_ascii_case("vxlan") {
        return Ok("vxlan");
    }
    if value.eq_ignore_ascii_case("geneve") {
        return Ok("geneve");
    }
    Err(format!(
        "config validation error: unsupported dataplane.encap_mode `{value}`"
    ))
}

fn parse_encap_mode(value: &str) -> Result<EncapMode, String> {
    match canonical_encap_mode(value)? {
        "none" => Ok(EncapMode::None),
        "vxlan" => Ok(EncapMode::Vxlan),
        "geneve" => Ok(EncapMode::Geneve),
        _ => Err(format!(
            "config validation error: unsupported dataplane.encap_mode `{value}`"
        )),
    }
}

fn validate_overlay(cfg: &DataplaneConfig, mode: EncapMode) -> Result<(), String> {
    let udp_port = cfg.encap_udp_port.unwrap_or(0);
    match mode {
        EncapMode::None => Ok(()),
        EncapMode::Vxlan => {
            if udp_port == 0
                && cfg.encap_udp_port_internal.is_none()
                && cfg.encap_udp_port_external.is_none()
            {
                return Err("--encap-udp-port is required for vxlan mode".to_string());
            }
            if cfg.encap_vni.is_none()
                && cfg.encap_vni_internal.is_none()
                && cfg.encap_vni_external.is_none()
            {
                return Err("--encap-vni is required for vxlan mode".to_string());
            }
            Ok(())
        }
        EncapMode::Geneve => {
            if udp_port == 0 {
                return Err("--encap-udp-port is required for geneve mode".to_string());
            }
            Ok(())
        }
    }
}

pub(crate) fn validate_semantics(cfg: &ValidatedConfig) -> Result<(), String> {
    validate_interfaces(cfg)?;
    validate_dpdk_static_network(cfg)?;
    validate_integration_requirements(cfg)?;
    validate_metrics_bind_policy(cfg)?;
    validate_snat_mode(cfg)?;
    Ok(())
}

fn validate_interfaces(cfg: &ValidatedConfig) -> Result<(), String> {
    if cfg.bootstrap.management_interface == cfg.bootstrap.data_interface {
        return Err(
            "config validation error: bootstrap.management_interface and bootstrap.data_interface must be different"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_dpdk_static_network(cfg: &ValidatedConfig) -> Result<(), String> {
    let Some(dpdk) = cfg.dpdk.as_ref() else {
        return Ok(());
    };

    let has_any = dpdk.static_ip.is_some()
        || dpdk.static_prefix_len.is_some()
        || dpdk.static_gateway.is_some()
        || dpdk.static_mac.is_some();
    if !has_any {
        return Ok(());
    }

    let missing = [
        (dpdk.static_ip.is_none(), "dpdk.static_ip"),
        (dpdk.static_prefix_len.is_none(), "dpdk.static_prefix_len"),
        (dpdk.static_gateway.is_none(), "dpdk.static_gateway"),
        (dpdk.static_mac.is_none(), "dpdk.static_mac"),
    ]
    .into_iter()
    .filter_map(|(is_missing, key)| is_missing.then_some(key))
    .collect::<Vec<_>>();

    if missing.is_empty() {
        return Ok(());
    }

    Err(format!(
        "config validation error: partial dpdk.static configuration, missing {}",
        missing.join(", ")
    ))
}

fn validate_integration_requirements(cfg: &ValidatedConfig) -> Result<(), String> {
    match cfg.integration.mode {
        IntegrationMode::None => Ok(()),
        IntegrationMode::AwsAsg => {
            let aws = cfg.integration.aws.as_ref().ok_or_else(|| {
                "config validation error: integration.mode=aws-asg requires integration.aws block"
                    .to_string()
            })?;
            required_field(
                aws.region.as_deref(),
                "config validation error: integration.mode=aws-asg requires integration.aws.region",
            )?;
            required_field(
                aws.vpc_id.as_deref(),
                "config validation error: integration.mode=aws-asg requires integration.aws.vpc_id",
            )?;
            required_field(
                aws.asg_name.as_deref(),
                "config validation error: integration.mode=aws-asg requires integration.aws.asg_name",
            )
        }
        IntegrationMode::AzureVmss => {
            let azure = cfg.integration.azure.as_ref().ok_or_else(|| {
                "config validation error: integration.mode=azure-vmss requires integration.azure block"
                    .to_string()
            })?;
            required_field(
                azure.subscription_id.as_deref(),
                "config validation error: integration.mode=azure-vmss requires integration.azure.subscription_id",
            )?;
            required_field(
                azure.resource_group.as_deref(),
                "config validation error: integration.mode=azure-vmss requires integration.azure.resource_group",
            )?;
            required_field(
                azure.vmss_name.as_deref(),
                "config validation error: integration.mode=azure-vmss requires integration.azure.vmss_name",
            )
        }
        IntegrationMode::GcpMig => {
            let gcp = cfg.integration.gcp.as_ref().ok_or_else(|| {
                "config validation error: integration.mode=gcp-mig requires integration.gcp block"
                    .to_string()
            })?;
            required_field(
                gcp.project.as_deref(),
                "config validation error: integration.mode=gcp-mig requires integration.gcp.project",
            )?;
            required_field(
                gcp.region.as_deref(),
                "config validation error: integration.mode=gcp-mig requires integration.gcp.region",
            )?;
            required_field(
                gcp.ig_name.as_deref(),
                "config validation error: integration.mode=gcp-mig requires integration.gcp.ig_name",
            )
        }
    }?;

    if cfg.integration.drain_timeout_secs == 0 {
        return Err(
            "config validation error: integration.drain_timeout_secs must be >= 1".to_string(),
        );
    }
    if cfg.integration.reconcile_interval_secs == 0 {
        return Err(
            "config validation error: integration.reconcile_interval_secs must be >= 1".to_string(),
        );
    }
    if cfg.integration.cluster_name.trim().is_empty() {
        return Err(
            "config validation error: integration.cluster_name must not be empty".to_string(),
        );
    }
    Ok(())
}

fn required_field(value: Option<&str>, err: &str) -> Result<(), String> {
    if value.map(str::trim).filter(|v| !v.is_empty()).is_none() {
        return Err(err.to_string());
    }
    Ok(())
}

fn validate_metrics_bind_policy(cfg: &ValidatedConfig) -> Result<(), String> {
    let Some(bind) = cfg.metrics.bind else {
        return Ok(());
    };

    if metrics_bind_requires_guardrail(bind) && !cfg.metrics.allow_public_bind {
        return Err(
            "config validation error: metrics.bind is public, set metrics.allow_public_bind=true"
                .to_string(),
        );
    }

    Ok(())
}

fn metrics_bind_requires_guardrail(bind: std::net::SocketAddr) -> bool {
    match bind.ip() {
        std::net::IpAddr::V4(ip) => !(ip.is_loopback() || ip.is_private() || ip.is_link_local()),
        std::net::IpAddr::V6(ip) => {
            !(ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local())
        }
    }
}

fn validate_snat_mode(cfg: &ValidatedConfig) -> Result<(), String> {
    if !cfg.bootstrap.data_plane_mode.eq_ignore_ascii_case("dpdk") {
        return Ok(());
    }

    if matches!(cfg.dataplane.snat, SnatMode::Static(_)) {
        return Err(
            "config validation error: dataplane.snat=static is not supported with bootstrap.data_plane_mode=dpdk"
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::super::load_config_str;
    use super::super::types::{DpdkIovaMode, DpdkPerfMode, DpdkSingleQueueMode, SnatMode};

    fn parse_runtime_config(raw: &str) -> Result<super::super::LoadedConfig, String> {
        load_config_str(raw)
    }

    #[test]
    fn integration_membership_defaults_are_applied() {
        let cfg = parse_runtime_config(
            r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
integration:
  mode: none
"#,
        )
        .unwrap();
        assert!(cfg.integration.membership.auto_evict_terminating);
        assert_eq!(cfg.integration.membership.stale_after_secs, 0);
        assert_eq!(cfg.integration.membership.min_voters, 3);
    }

    #[test]
    fn integration_membership_rejects_zero_min_voters() {
        let err = parse_runtime_config(
            r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
integration:
  mode: aws-asg
  membership:
    min_voters: 0
"#,
        )
        .unwrap_err();
        assert!(err.contains("integration.membership.min_voters"), "{err}");
    }

    #[test]
    fn load_config_rejects_missing_version() {
        let raw = r#"
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: dpdk
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("missing field `version`"), "{err}");
    }

    #[test]
    fn load_config_rejects_unsupported_version() {
        let raw = r#"
version: 2
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: dpdk
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("unsupported config version 2"), "{err}");
    }

    #[test]
    fn validate_rejects_partial_static_dpdk_addressing() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: dpdk
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dpdk:
  static_ip: 10.0.2.5
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("dpdk.static"), "{err}");
    }

    #[test]
    fn validate_rejects_aws_asg_missing_required_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: soft
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
integration:
  mode: aws-asg
  route_name: neuwerk-default
  cluster_name: neuwerk
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("integration.aws"), "{err}");
    }

    #[test]
    fn validate_rejects_azure_vmss_missing_required_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: azure
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
integration:
  mode: azure-vmss
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("integration.azure"), "{err}");
    }

    #[test]
    fn validate_rejects_gcp_mig_missing_required_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: gcp
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
integration:
  mode: gcp-mig
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("integration.gcp"), "{err}");
    }

    #[test]
    fn validate_rejects_public_metrics_bind_without_allow_flag() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: soft
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
metrics:
  bind: 0.0.0.0:8080
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("metrics.allow_public_bind"), "{err}");
    }

    #[test]
    fn validate_accepts_metrics_fields_when_allow_flag_is_enabled() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: soft
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
metrics:
  bind: 0.0.0.0:8080
  allow_public_bind: true
"#;
        let cfg = load_config_str(raw).expect("metrics config should load");
        assert_eq!(
            cfg.metrics.bind,
            Some(SocketAddr::from(([0, 0, 0, 0], 8080)))
        );
        assert!(cfg.metrics.allow_public_bind);
    }

    #[test]
    fn validate_rejects_zero_incomplete_tcp_timeouts() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  flow_incomplete_tcp_idle_timeout_secs: 0
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(
            err.contains("dataplane.flow_incomplete_tcp_idle_timeout_secs"),
            "{err}"
        );

        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  flow_incomplete_tcp_syn_sent_idle_timeout_secs: 0
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(
            err.contains("dataplane.flow_incomplete_tcp_syn_sent_idle_timeout_secs"),
            "{err}"
        );
    }

    #[test]
    fn validate_loads_typed_tls_intercept_and_dataplane_runtime_knobs() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
runtime:
  controlplane_worker_threads: 7
  http_worker_threads: 3
  kubernetes:
    reconcile_interval_secs: 9
    stale_grace_secs: 301
tls_intercept:
  upstream_verify: insecure
  io_timeout_secs: 7
  listen_backlog: 2048
  h2:
    body_timeout_secs: 11
    max_concurrent_streams: 96
dataplane:
  flow_table_capacity: 65536
  nat_table_capacity: 131072
  flow_incomplete_tcp_idle_timeout_secs: 55
  flow_incomplete_tcp_syn_sent_idle_timeout_secs: 7
  syn_only_enabled: true
  detailed_observability: true
  admission:
    max_active_flows: 500
    max_active_nat_entries: 600
    max_pending_tls_flows: 700
    max_active_flows_per_source_group: 80
dpdk:
  workers: 5
  core_ids: [1, 3, 5]
  allow_azure_multiworker: true
  single_queue_mode: single
  perf_mode: aggressive
  force_shared_rx_demux: true
  pin_https_demux_owner: true
  disable_service_lane: true
  lockless_queue_per_worker: true
  shared_rx_owner_only: true
  housekeeping_interval_packets: 128
  housekeeping_interval_us: 400
  pin_state_shard_guard: true
  pin_state_shard_burst: 96
  state_shards: 6
  disable_in_memory: true
  iova_mode: va
  force_netvsc: true
  gcp_auto_probe: true
  driver_preload:
    - /opt/neuwerk/lib/custom-pmd.so
  skip_bus_pci_preload: true
  prefer_pci: true
  queue_override: 7
  port_mtu: 1600
  mbuf_data_room: 4096
  mbuf_pool_size: 16384
  rx_ring_size: 2048
  tx_ring_size: 4096
  tx_checksum_offload: false
  allow_retaless_multi_queue: true
  service_lane:
    interface: svc9
    intercept_service_ip: 169.254.200.10
    intercept_service_port: 16443
    multi_queue: true
  intercept_demux:
    gc_interval_ms: 2000
    max_entries: 1234
    shard_count: 16
    host_frame_queue_max: 456
    pending_arp_queue_max: 78
  gateway_mac: aa:bb:cc:dd:ee:ff
  dhcp_server_ip: 169.254.10.20
  dhcp_server_mac: 00:11:22:33:44:55
  overlay:
    swap_tunnels: true
    force_tunnel_src_port: true
    debug: true
    health_probe_debug: true
"#;
        let cfg = load_config_str(raw).expect("runtime knobs should load");
        assert_eq!(cfg.runtime.controlplane_worker_threads, 7);
        assert_eq!(cfg.runtime.http_worker_threads, 3);
        assert_eq!(cfg.runtime.kubernetes.reconcile_interval_secs, 9);
        assert_eq!(cfg.runtime.kubernetes.stale_grace_secs, 301);
        let tls = cfg
            .tls_intercept
            .expect("tls intercept settings should be present");
        assert!(matches!(
            tls.upstream_verify,
            neuwerk::controlplane::trafficd::UpstreamTlsVerificationMode::Insecure
        ));
        assert_eq!(tls.io_timeout_secs, 7);
        assert_eq!(tls.listen_backlog, 2048);
        assert_eq!(tls.h2.body_timeout_secs, 11);
        assert_eq!(tls.h2.max_concurrent_streams, 96);
        assert_eq!(cfg.dataplane.flow_table_capacity, 65536);
        assert_eq!(cfg.dataplane.nat_table_capacity, 131072);
        assert_eq!(
            cfg.dataplane.flow_incomplete_tcp_idle_timeout_secs,
            Some(55)
        );
        assert_eq!(
            cfg.dataplane.flow_incomplete_tcp_syn_sent_idle_timeout_secs,
            7
        );
        assert!(cfg.dataplane.syn_only_enabled);
        assert!(cfg.dataplane.detailed_observability);
        assert_eq!(cfg.dataplane.admission.max_active_flows, Some(500));
        assert_eq!(cfg.dataplane.admission.max_active_nat_entries, Some(600));
        assert_eq!(cfg.dataplane.admission.max_pending_tls_flows, Some(700));
        assert_eq!(
            cfg.dataplane.admission.max_active_flows_per_source_group,
            Some(80)
        );
        let dpdk = cfg.dpdk.expect("dpdk runtime config should be present");
        assert_eq!(dpdk.workers, Some(5));
        assert_eq!(dpdk.core_ids, vec![1, 3, 5]);
        assert!(dpdk.allow_azure_multiworker);
        assert_eq!(dpdk.single_queue_mode, DpdkSingleQueueMode::SingleWorker);
        assert_eq!(dpdk.perf_mode, DpdkPerfMode::Aggressive);
        assert!(dpdk.force_shared_rx_demux);
        assert!(dpdk.pin_https_demux_owner);
        assert!(dpdk.disable_service_lane);
        assert!(dpdk.lockless_queue_per_worker);
        assert!(dpdk.shared_rx_owner_only);
        assert_eq!(dpdk.housekeeping_interval_packets, 128);
        assert_eq!(dpdk.housekeeping_interval_us, 400);
        assert!(dpdk.pin_state_shard_guard);
        assert_eq!(dpdk.pin_state_shard_burst, 96);
        assert_eq!(dpdk.state_shards, Some(6));
        assert!(dpdk.disable_in_memory);
        assert_eq!(dpdk.iova_mode, Some(DpdkIovaMode::Va));
        assert!(dpdk.force_netvsc);
        assert!(dpdk.gcp_auto_probe);
        assert_eq!(
            dpdk.driver_preload,
            vec!["/opt/neuwerk/lib/custom-pmd.so".to_string()]
        );
        assert!(dpdk.skip_bus_pci_preload);
        assert!(dpdk.prefer_pci);
        assert_eq!(dpdk.queue_override, Some(7));
        assert_eq!(dpdk.port_mtu, Some(1600));
        assert_eq!(dpdk.mbuf_data_room, Some(4096));
        assert_eq!(dpdk.mbuf_pool_size, Some(16384));
        assert_eq!(dpdk.rx_ring_size, 2048);
        assert_eq!(dpdk.tx_ring_size, 4096);
        assert_eq!(dpdk.tx_checksum_offload, Some(false));
        assert!(dpdk.allow_retaless_multi_queue);
        assert_eq!(dpdk.service_lane.interface, "svc9");
        assert_eq!(
            dpdk.service_lane.intercept_service_ip,
            Ipv4Addr::new(169, 254, 200, 10)
        );
        assert_eq!(dpdk.service_lane.intercept_service_port, 16443);
        assert!(dpdk.service_lane.multi_queue);
        assert_eq!(dpdk.intercept_demux.gc_interval_ms, 2000);
        assert_eq!(dpdk.intercept_demux.max_entries, 1234);
        assert_eq!(dpdk.intercept_demux.shard_count, 16);
        assert_eq!(dpdk.intercept_demux.host_frame_queue_max, 456);
        assert_eq!(dpdk.intercept_demux.pending_arp_queue_max, 78);
        assert_eq!(dpdk.gateway_mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(dpdk.dhcp_server_ip, Some(Ipv4Addr::new(169, 254, 10, 20)));
        assert_eq!(dpdk.dhcp_server_mac.as_deref(), Some("00:11:22:33:44:55"));
        assert!(dpdk.overlay.swap_tunnels);
        assert!(dpdk.overlay.force_tunnel_src_port);
        assert!(dpdk.overlay.debug);
        assert!(dpdk.overlay.health_probe_debug);
    }

    #[test]
    fn validate_rejects_static_snat_missing_ip() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  snat:
    mode: static
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("dataplane.snat.ip"), "{err}");
    }

    #[test]
    fn validate_rejects_static_snat_with_dpdk_dataplane() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: dpdk
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  snat:
    mode: static
    ip: 198.51.100.77
"#;
        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("dataplane.snat"), "{err}");
    }

    #[test]
    fn validate_accepts_mixed_case_data_plane_mode_through_load_path() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: DpDk
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("mixed-case dataplane mode should load");
        assert_eq!(cfg.bootstrap.data_plane_mode, "dpdk");
    }

    #[test]
    fn validate_accepts_tap_data_plane_mode_through_load_path() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tap
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("tap mode should load");
        assert_eq!(cfg.bootstrap.data_plane_mode, "tap");
    }

    #[test]
    fn validate_overlay_defaults_match_cli_for_vxlan() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  encap_mode: vxlan
  encap_vni_internal: 1234
  encap_vni_external: 5678
"#;
        let cfg = load_config_str(raw).expect("vxlan config should load");
        assert_eq!(cfg.dataplane.encap_mode, "vxlan");
        assert_eq!(cfg.dataplane.encap_udp_port, Some(10800));
        assert_eq!(cfg.dataplane.encap_udp_port_internal, Some(10800));
        assert_eq!(cfg.dataplane.encap_udp_port_external, Some(10801));
        assert_eq!(cfg.dataplane.snat, SnatMode::None);
    }

    #[test]
    fn validate_rejects_vxlan_without_vni() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
dataplane:
  encap_mode: vxlan
"#;
        let err = load_config_str(raw).expect_err("vxlan must require a vni");
        assert!(err.contains("encap-vni"), "{err}");
    }

    #[test]
    fn validate_cluster_defaults_remain_disabled_when_block_absent() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("config should load");
        assert!(!cfg.cluster.enabled);
        assert_eq!(cfg.cluster.bind, SocketAddr::from(([127, 0, 0, 1], 9600)));
        assert_eq!(
            cfg.cluster.join_bind,
            SocketAddr::from(([127, 0, 0, 1], 9601))
        );
    }

    #[test]
    fn validate_maps_dns_target_ips() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
    - 10.0.0.54
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("config should load");
        assert_eq!(
            cfg.dns.target_ips,
            vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)]
        );
    }

    #[test]
    fn validate_defaults_dns_upstream_timeout_ms() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;
        let cfg = load_config_str(raw).expect("config should load");
        assert_eq!(cfg.dns.upstream_timeout_ms, 2_000);
    }

    #[test]
    fn validate_rejects_zero_dns_upstream_timeout_ms() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
  upstream_timeout_ms: 0
"#;
        let err = load_config_str(raw).expect_err("zero upstream timeout must be rejected");
        assert!(err.contains("dns.upstream_timeout_ms"), "{err}");
    }
}
