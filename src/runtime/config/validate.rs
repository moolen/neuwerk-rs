use std::net::Ipv4Addr;
use std::path::PathBuf;

use super::schema::{DataplaneConfigFile, RuntimeConfigFile, SnatConfigFile};
use super::types::{
    AwsIntegrationConfig, AzureIntegrationConfig, BootstrapConfig, ClusterConfig, DataplaneConfig,
    DefaultPolicy, DnsConfig, DpdkConfig, EncapMode, GcpIntegrationConfig, HttpConfig,
    IntegrationConfig, IntegrationMode, LoadedConfig, MetricsConfig, PolicyConfig, SnatMode,
    TlsInterceptConfig, ValidatedConfig,
};

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
        tls_intercept: raw.tls_intercept.map(|_| TlsInterceptConfig),
        dataplane,
        dpdk: raw.dpdk.map(|dpdk| DpdkConfig {
            static_ip: dpdk.static_ip,
            static_prefix_len: dpdk.static_prefix_len,
            static_gateway: dpdk.static_gateway,
            static_mac: dpdk.static_mac,
        }),
    };
    validate_semantics(&validated)?;
    Ok(validated)
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
    Ok(DnsConfig {
        target_ips: raw.target_ips,
        upstreams: raw.upstreams,
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

    if bind.ip().is_unspecified() && !cfg.metrics.allow_public_bind {
        return Err(
            "config validation error: metrics.bind is public, set metrics.allow_public_bind=true"
                .to_string(),
        );
    }

    Ok(())
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
    use super::super::types::SnatMode;

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
}
