use std::env;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use crate::runtime::bootstrap::cluster::build_cluster_config;
use neuwerk::controlplane::cloud::types::IntegrationMode;
use neuwerk::dataplane::{EncapMode, OverlayConfig, SnatMode, DEFAULT_IDLE_TIMEOUT_SECS};

use super::{
    parse_cidr, parse_csv_ipv4_list, parse_csv_socket_list, parse_default_policy,
    parse_integration_mode, parse_ipv4, parse_port, parse_socket, parse_vni, take_flag_value,
    usage, CliConfig, CloudProviderKind, DataPlaneMode, DHCP_LEASE_MIN_SECS, DHCP_RETRY_MAX,
    DHCP_TIMEOUT_SECS, DNS_ALLOWLIST_GC_INTERVAL_SECS, DNS_ALLOWLIST_IDLE_SLACK_SECS,
    INTEGRATION_CLUSTER_NAME, INTEGRATION_DRAIN_TIMEOUT_SECS, INTEGRATION_RECONCILE_INTERVAL_SECS,
    INTEGRATION_ROUTE_NAME,
};

pub fn parse_args(bin: &str, args: Vec<String>) -> Result<CliConfig, String> {
    let mut management_iface = None;
    let mut data_plane_iface = None;
    let mut dns_target_ips: Vec<Ipv4Addr> = Vec::new();
    let mut dns_target_ips_csv: Option<Vec<Ipv4Addr>> = None;
    let mut dns_upstreams: Vec<SocketAddr> = Vec::new();
    let mut dns_upstreams_csv: Option<Vec<SocketAddr>> = None;
    let mut data_plane_mode = DataPlaneMode::Soft(neuwerk::dataplane::SoftMode::Tun);
    let mut idle_timeout_secs = DEFAULT_IDLE_TIMEOUT_SECS;
    let mut dns_allowlist_idle_secs = None;
    let mut dns_allowlist_gc_interval_secs = None;
    let mut default_policy = neuwerk::dataplane::policy::DefaultPolicy::Deny;
    let mut dhcp_timeout_secs = DHCP_TIMEOUT_SECS;
    let mut dhcp_retry_max = DHCP_RETRY_MAX;
    let mut dhcp_lease_min_secs = DHCP_LEASE_MIN_SECS;
    let mut internal_cidr = None;
    let mut http_bind = None;
    let mut http_advertise = None;
    let mut http_external_url = None;
    let mut http_tls_dir = PathBuf::from("/var/lib/neuwerk/http-tls");
    let mut http_cert_path = None;
    let mut http_key_path = None;
    let mut http_ca_path = None;
    let mut http_tls_san: Vec<String> = Vec::new();
    let mut metrics_bind = None;
    let mut cloud_provider = CloudProviderKind::None;
    let mut snat_mode = SnatMode::Auto;
    let mut encap_mode = EncapMode::None;
    let mut encap_vni = None;
    let mut encap_vni_internal = None;
    let mut encap_vni_external = None;
    let mut encap_udp_port = None;
    let mut encap_udp_port_internal = None;
    let mut encap_udp_port_external = None;
    let mut encap_mtu: u16 = 1500;
    let mut snat_set = false;
    let mut cluster_bind = None;
    let mut cluster_join_bind = None;
    let mut cluster_advertise = None;
    let mut cluster_join = None;
    let mut cluster_data_dir = None;
    let mut node_id_path = None;
    let mut bootstrap_token_path = None;
    let mut cluster_migrate_from_local = false;
    let mut cluster_migrate_force = false;
    let mut cluster_migrate_verify = false;
    let mut integration_mode = IntegrationMode::None;
    let mut integration_route_name = INTEGRATION_ROUTE_NAME.to_string();
    let mut integration_drain_timeout_secs = INTEGRATION_DRAIN_TIMEOUT_SECS;
    let mut integration_reconcile_interval_secs = INTEGRATION_RECONCILE_INTERVAL_SECS;
    let mut integration_cluster_name = INTEGRATION_CLUSTER_NAME.to_string();
    let mut azure_subscription_id = None;
    let mut azure_resource_group = None;
    let mut azure_vmss_name = None;
    let mut aws_region = None;
    let mut aws_vpc_id = None;
    let mut aws_asg_name = None;
    let mut gcp_project = None;
    let mut gcp_region = None;
    let mut gcp_ig_name = None;

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{}", usage(bin));
                std::process::exit(0);
            }
            _ => {}
        }

        if arg == "--management-interface" || arg.starts_with("--management-interface=") {
            let value = take_flag_value("--management-interface", &arg, &mut args)?;
            management_iface = Some(value);
            continue;
        }
        if arg == "--data-plane-interface" || arg.starts_with("--data-plane-interface=") {
            let value = take_flag_value("--data-plane-interface", &arg, &mut args)?;
            data_plane_iface = Some(value);
            continue;
        }
        if arg == "--dns-target-ip" || arg.starts_with("--dns-target-ip=") {
            let value = take_flag_value("--dns-target-ip", &arg, &mut args)?;
            dns_target_ips.push(parse_ipv4("--dns-target-ip", &value)?);
            continue;
        }
        if arg == "--dns-target-ips" || arg.starts_with("--dns-target-ips=") {
            let value = take_flag_value("--dns-target-ips", &arg, &mut args)?;
            dns_target_ips_csv = Some(parse_csv_ipv4_list("--dns-target-ips", &value)?);
            continue;
        }
        if arg == "--dns-upstream" || arg.starts_with("--dns-upstream=") {
            let value = take_flag_value("--dns-upstream", &arg, &mut args)?;
            dns_upstreams.push(parse_socket("--dns-upstream", &value)?);
            continue;
        }
        if arg == "--dns-upstreams" || arg.starts_with("--dns-upstreams=") {
            let value = take_flag_value("--dns-upstreams", &arg, &mut args)?;
            dns_upstreams_csv = Some(parse_csv_socket_list("--dns-upstreams", &value)?);
            continue;
        }
        if arg == "--dns-listen" || arg.starts_with("--dns-listen=") {
            return Err(
                "--dns-listen has been removed; DNS interception now binds on management-ip:53"
                    .to_string(),
            );
        }
        if arg == "--data-plane-mode" || arg.starts_with("--data-plane-mode=") {
            let value = take_flag_value("--data-plane-mode", &arg, &mut args)?;
            data_plane_mode = DataPlaneMode::parse(&value)?;
            continue;
        }
        if arg == "--idle-timeout-secs" || arg.starts_with("--idle-timeout-secs=") {
            let value = take_flag_value("--idle-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--idle-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--idle-timeout-secs must be >= 1".to_string());
            }
            idle_timeout_secs = parsed;
            continue;
        }
        if arg == "--dns-allowlist-idle-secs" || arg.starts_with("--dns-allowlist-idle-secs=") {
            let value = take_flag_value("--dns-allowlist-idle-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dns-allowlist-idle-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dns-allowlist-idle-secs must be >= 1".to_string());
            }
            dns_allowlist_idle_secs = Some(parsed);
            continue;
        }
        if arg == "--dns-allowlist-gc-interval-secs"
            || arg.starts_with("--dns-allowlist-gc-interval-secs=")
        {
            let value = take_flag_value("--dns-allowlist-gc-interval-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dns-allowlist-gc-interval-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dns-allowlist-gc-interval-secs must be >= 1".to_string());
            }
            dns_allowlist_gc_interval_secs = Some(parsed);
            continue;
        }
        if arg == "--default-policy" || arg.starts_with("--default-policy=") {
            let value = take_flag_value("--default-policy", &arg, &mut args)?;
            default_policy = parse_default_policy(&value)?;
            continue;
        }
        if arg == "--dhcp-timeout-secs" || arg.starts_with("--dhcp-timeout-secs=") {
            let value = take_flag_value("--dhcp-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dhcp-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dhcp-timeout-secs must be >= 1".to_string());
            }
            dhcp_timeout_secs = parsed;
            continue;
        }
        if arg == "--dhcp-retry-max" || arg.starts_with("--dhcp-retry-max=") {
            let value = take_flag_value("--dhcp-retry-max", &arg, &mut args)?;
            let parsed = value
                .parse::<u32>()
                .map_err(|_| format!("--dhcp-retry-max must be a positive integer, got {value}"))?;
            if parsed == 0 {
                return Err("--dhcp-retry-max must be >= 1".to_string());
            }
            dhcp_retry_max = parsed;
            continue;
        }
        if arg == "--dhcp-lease-min-secs" || arg.starts_with("--dhcp-lease-min-secs=") {
            let value = take_flag_value("--dhcp-lease-min-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--dhcp-lease-min-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--dhcp-lease-min-secs must be >= 1".to_string());
            }
            dhcp_lease_min_secs = parsed;
            continue;
        }
        if arg == "--internal-cidr" || arg.starts_with("--internal-cidr=") {
            let value = take_flag_value("--internal-cidr", &arg, &mut args)?;
            internal_cidr = Some(parse_cidr("--internal-cidr", &value)?);
            continue;
        }
        if arg == "--snat" || arg.starts_with("--snat=") {
            let value = take_flag_value("--snat", &arg, &mut args)?;
            snat_mode = match value.as_str() {
                "none" | "NONE" => SnatMode::None,
                "auto" | "AUTO" => SnatMode::Auto,
                _ => {
                    let parsed = value.parse::<Ipv4Addr>().map_err(|_| {
                        format!("--snat must be none, auto, or an IPv4 address, got {value}")
                    })?;
                    SnatMode::Static(parsed)
                }
            };
            snat_set = true;
            continue;
        }
        if arg == "--encap" || arg.starts_with("--encap=") {
            let value = take_flag_value("--encap", &arg, &mut args)?;
            encap_mode = EncapMode::parse(&value)?;
            continue;
        }
        if arg == "--encap-vni" || arg.starts_with("--encap-vni=") {
            let value = take_flag_value("--encap-vni", &arg, &mut args)?;
            encap_vni = Some(parse_vni("--encap-vni", &value)?);
            continue;
        }
        if arg == "--encap-vni-internal" || arg.starts_with("--encap-vni-internal=") {
            let value = take_flag_value("--encap-vni-internal", &arg, &mut args)?;
            encap_vni_internal = Some(parse_vni("--encap-vni-internal", &value)?);
            continue;
        }
        if arg == "--encap-vni-external" || arg.starts_with("--encap-vni-external=") {
            let value = take_flag_value("--encap-vni-external", &arg, &mut args)?;
            encap_vni_external = Some(parse_vni("--encap-vni-external", &value)?);
            continue;
        }
        if arg == "--encap-udp-port" || arg.starts_with("--encap-udp-port=") {
            let value = take_flag_value("--encap-udp-port", &arg, &mut args)?;
            encap_udp_port = Some(parse_port("--encap-udp-port", &value)?);
            continue;
        }
        if arg == "--encap-udp-port-internal" || arg.starts_with("--encap-udp-port-internal=") {
            let value = take_flag_value("--encap-udp-port-internal", &arg, &mut args)?;
            encap_udp_port_internal = Some(parse_port("--encap-udp-port-internal", &value)?);
            continue;
        }
        if arg == "--encap-udp-port-external" || arg.starts_with("--encap-udp-port-external=") {
            let value = take_flag_value("--encap-udp-port-external", &arg, &mut args)?;
            encap_udp_port_external = Some(parse_port("--encap-udp-port-external", &value)?);
            continue;
        }
        if arg == "--encap-mtu" || arg.starts_with("--encap-mtu=") {
            let value = take_flag_value("--encap-mtu", &arg, &mut args)?;
            let parsed = value
                .parse::<u16>()
                .map_err(|_| format!("--encap-mtu must be a positive integer, got {value}"))?;
            if parsed == 0 {
                return Err("--encap-mtu must be >= 1".to_string());
            }
            encap_mtu = parsed;
            continue;
        }
        if arg == "--http-bind" || arg.starts_with("--http-bind=") {
            let value = take_flag_value("--http-bind", &arg, &mut args)?;
            http_bind = Some(parse_socket("--http-bind", &value)?);
            continue;
        }
        if arg == "--http-advertise" || arg.starts_with("--http-advertise=") {
            let value = take_flag_value("--http-advertise", &arg, &mut args)?;
            http_advertise = Some(parse_socket("--http-advertise", &value)?);
            continue;
        }
        if arg == "--http-external-url" || arg.starts_with("--http-external-url=") {
            let value = take_flag_value("--http-external-url", &arg, &mut args)?;
            http_external_url = Some(value);
            continue;
        }
        if arg == "--http-tls-dir" || arg.starts_with("--http-tls-dir=") {
            let value = take_flag_value("--http-tls-dir", &arg, &mut args)?;
            http_tls_dir = PathBuf::from(value);
            continue;
        }
        if arg == "--http-cert-path" || arg.starts_with("--http-cert-path=") {
            let value = take_flag_value("--http-cert-path", &arg, &mut args)?;
            http_cert_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-key-path" || arg.starts_with("--http-key-path=") {
            let value = take_flag_value("--http-key-path", &arg, &mut args)?;
            http_key_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-ca-path" || arg.starts_with("--http-ca-path=") {
            let value = take_flag_value("--http-ca-path", &arg, &mut args)?;
            http_ca_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--http-tls-san" || arg.starts_with("--http-tls-san=") {
            let value = take_flag_value("--http-tls-san", &arg, &mut args)?;
            for entry in value.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    http_tls_san.push(entry.to_string());
                }
            }
            continue;
        }
        if arg == "--metrics-bind" || arg.starts_with("--metrics-bind=") {
            let value = take_flag_value("--metrics-bind", &arg, &mut args)?;
            metrics_bind = Some(parse_socket("--metrics-bind", &value)?);
            continue;
        }
        if arg == "--cloud-provider" || arg.starts_with("--cloud-provider=") {
            let value = take_flag_value("--cloud-provider", &arg, &mut args)?;
            cloud_provider = CloudProviderKind::parse(&value)?;
            continue;
        }
        if arg == "--integration" || arg.starts_with("--integration=") {
            let value = take_flag_value("--integration", &arg, &mut args)?;
            integration_mode = parse_integration_mode(&value)?;
            continue;
        }
        if arg == "--integration-route-name" || arg.starts_with("--integration-route-name=") {
            let value = take_flag_value("--integration-route-name", &arg, &mut args)?;
            integration_route_name = value;
            continue;
        }
        if arg == "--integration-drain-timeout-secs"
            || arg.starts_with("--integration-drain-timeout-secs=")
        {
            let value = take_flag_value("--integration-drain-timeout-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!("--integration-drain-timeout-secs must be a positive integer, got {value}")
            })?;
            if parsed == 0 {
                return Err("--integration-drain-timeout-secs must be >= 1".to_string());
            }
            integration_drain_timeout_secs = parsed;
            continue;
        }
        if arg == "--integration-reconcile-interval-secs"
            || arg.starts_with("--integration-reconcile-interval-secs=")
        {
            let value = take_flag_value("--integration-reconcile-interval-secs", &arg, &mut args)?;
            let parsed = value.parse::<u64>().map_err(|_| {
                format!(
                    "--integration-reconcile-interval-secs must be a positive integer, got {value}"
                )
            })?;
            if parsed == 0 {
                return Err("--integration-reconcile-interval-secs must be >= 1".to_string());
            }
            integration_reconcile_interval_secs = parsed;
            continue;
        }
        if arg == "--integration-cluster-name" || arg.starts_with("--integration-cluster-name=") {
            let value = take_flag_value("--integration-cluster-name", &arg, &mut args)?;
            if value.trim().is_empty() {
                return Err("--integration-cluster-name must not be empty".to_string());
            }
            integration_cluster_name = value;
            continue;
        }
        if arg == "--azure-subscription-id" || arg.starts_with("--azure-subscription-id=") {
            let value = take_flag_value("--azure-subscription-id", &arg, &mut args)?;
            azure_subscription_id = Some(value);
            continue;
        }
        if arg == "--azure-resource-group" || arg.starts_with("--azure-resource-group=") {
            let value = take_flag_value("--azure-resource-group", &arg, &mut args)?;
            azure_resource_group = Some(value);
            continue;
        }
        if arg == "--azure-vmss-name" || arg.starts_with("--azure-vmss-name=") {
            let value = take_flag_value("--azure-vmss-name", &arg, &mut args)?;
            azure_vmss_name = Some(value);
            continue;
        }
        if arg == "--aws-region" || arg.starts_with("--aws-region=") {
            let value = take_flag_value("--aws-region", &arg, &mut args)?;
            aws_region = Some(value);
            continue;
        }
        if arg == "--aws-vpc-id" || arg.starts_with("--aws-vpc-id=") {
            let value = take_flag_value("--aws-vpc-id", &arg, &mut args)?;
            aws_vpc_id = Some(value);
            continue;
        }
        if arg == "--aws-asg-name" || arg.starts_with("--aws-asg-name=") {
            let value = take_flag_value("--aws-asg-name", &arg, &mut args)?;
            aws_asg_name = Some(value);
            continue;
        }
        if arg == "--gcp-project" || arg.starts_with("--gcp-project=") {
            let value = take_flag_value("--gcp-project", &arg, &mut args)?;
            gcp_project = Some(value);
            continue;
        }
        if arg == "--gcp-region" || arg.starts_with("--gcp-region=") {
            let value = take_flag_value("--gcp-region", &arg, &mut args)?;
            gcp_region = Some(value);
            continue;
        }
        if arg == "--gcp-ig-name" || arg.starts_with("--gcp-ig-name=") {
            let value = take_flag_value("--gcp-ig-name", &arg, &mut args)?;
            gcp_ig_name = Some(value);
            continue;
        }
        if arg == "--cluster-migrate-from-local" {
            cluster_migrate_from_local = true;
            continue;
        }
        if arg == "--cluster-migrate-force" {
            cluster_migrate_force = true;
            continue;
        }
        if arg == "--cluster-migrate-verify" {
            cluster_migrate_verify = true;
            continue;
        }
        if arg == "--cluster-bind" || arg.starts_with("--cluster-bind=") {
            let value = take_flag_value("--cluster-bind", &arg, &mut args)?;
            cluster_bind = Some(parse_socket("--cluster-bind", &value)?);
            continue;
        }
        if arg == "--cluster-join-bind" || arg.starts_with("--cluster-join-bind=") {
            let value = take_flag_value("--cluster-join-bind", &arg, &mut args)?;
            cluster_join_bind = Some(parse_socket("--cluster-join-bind", &value)?);
            continue;
        }
        if arg == "--cluster-advertise" || arg.starts_with("--cluster-advertise=") {
            let value = take_flag_value("--cluster-advertise", &arg, &mut args)?;
            cluster_advertise = Some(parse_socket("--cluster-advertise", &value)?);
            continue;
        }
        if arg == "--join" || arg.starts_with("--join=") {
            let value = take_flag_value("--join", &arg, &mut args)?;
            cluster_join = Some(parse_socket("--join", &value)?);
            continue;
        }
        if arg == "--cluster-data-dir" || arg.starts_with("--cluster-data-dir=") {
            let value = take_flag_value("--cluster-data-dir", &arg, &mut args)?;
            cluster_data_dir = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--node-id-path" || arg.starts_with("--node-id-path=") {
            let value = take_flag_value("--node-id-path", &arg, &mut args)?;
            node_id_path = Some(PathBuf::from(value));
            continue;
        }
        if arg == "--bootstrap-token-path" || arg.starts_with("--bootstrap-token-path=") {
            let value = take_flag_value("--bootstrap-token-path", &arg, &mut args)?;
            bootstrap_token_path = Some(PathBuf::from(value));
            continue;
        }

        return Err(format!("unknown flag: {arg}"));
    }

    if let Ok(value) = env::var("NEUWERK_CLUSTER_MIGRATE") {
        if matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES") {
            cluster_migrate_from_local = true;
        }
    }

    let mut missing = Vec::new();
    if dns_target_ips_csv.is_some() && !dns_target_ips.is_empty() {
        return Err(
            "cannot combine repeated --dns-target-ip with --dns-target-ips csv form".to_string(),
        );
    }
    if dns_upstreams_csv.is_some() && !dns_upstreams.is_empty() {
        return Err(
            "cannot combine repeated --dns-upstream with --dns-upstreams csv form".to_string(),
        );
    }
    if let Some(list) = dns_target_ips_csv.take() {
        dns_target_ips = list;
    }
    if let Some(list) = dns_upstreams_csv.take() {
        dns_upstreams = list;
    }
    if management_iface.is_none() {
        missing.push("--management-interface");
    }
    if data_plane_iface.is_none() {
        missing.push("--data-plane-interface");
    }
    if dns_target_ips.is_empty() {
        missing.push("--dns-target-ip");
    }
    if dns_upstreams.is_empty() {
        missing.push("--dns-upstream");
    }

    if !missing.is_empty() {
        return Err(format!("missing required flags: {}", missing.join(", ")));
    }

    if matches!(data_plane_mode, DataPlaneMode::Soft(_)) {
        if let Some(iface) = data_plane_iface.as_deref() {
            if super::looks_like_pci(iface) || super::looks_like_mac(iface) {
                return Err(
                    "--data-plane-interface must be a netdev when --data-plane-mode is tun or tap"
                        .to_string(),
                );
            }
        } else {
            return Err("missing required flags: --data-plane-interface".to_string());
        }
    }

    match integration_mode {
        IntegrationMode::AzureVmss => {
            if azure_subscription_id.is_none() {
                return Err(
                    "--azure-subscription-id is required for --integration azure-vmss".to_string(),
                );
            }
            if azure_resource_group.is_none() {
                return Err(
                    "--azure-resource-group is required for --integration azure-vmss".to_string(),
                );
            }
            if azure_vmss_name.is_none() {
                return Err(
                    "--azure-vmss-name is required for --integration azure-vmss".to_string()
                );
            }
        }
        IntegrationMode::AwsAsg => {
            if aws_region.is_none() {
                return Err("--aws-region is required for --integration aws-asg".to_string());
            }
            if aws_vpc_id.is_none() {
                return Err("--aws-vpc-id is required for --integration aws-asg".to_string());
            }
            if aws_asg_name.is_none() {
                return Err("--aws-asg-name is required for --integration aws-asg".to_string());
            }
        }
        IntegrationMode::GcpMig => {
            if gcp_project.is_none() {
                return Err("--gcp-project is required for --integration gcp-mig".to_string());
            }
            if gcp_region.is_none() {
                return Err("--gcp-region is required for --integration gcp-mig".to_string());
            }
            if gcp_ig_name.is_none() {
                return Err("--gcp-ig-name is required for --integration gcp-mig".to_string());
            }
        }
        IntegrationMode::None => {}
    }
    if management_iface == data_plane_iface {
        return Err(
            "--management-interface and --data-plane-interface must be different".to_string(),
        );
    }

    if !snat_set && encap_mode != EncapMode::None {
        snat_mode = SnatMode::None;
    }

    let encap_udp_port_set = encap_udp_port.is_some();
    if encap_mode == EncapMode::Vxlan && !encap_udp_port_set {
        if encap_vni_internal.is_some() && encap_udp_port_internal.is_none() {
            encap_udp_port_internal = Some(10800);
        }
        if encap_vni_external.is_some() && encap_udp_port_external.is_none() {
            encap_udp_port_external = Some(10801);
        }
    }

    let encap_udp_port = encap_udp_port.unwrap_or(match encap_mode {
        EncapMode::Geneve => 6081,
        EncapMode::Vxlan => 10800,
        EncapMode::None => 0,
    });

    let overlay = OverlayConfig {
        mode: encap_mode,
        udp_port: encap_udp_port,
        udp_port_internal: encap_udp_port_internal,
        udp_port_external: encap_udp_port_external,
        vni: encap_vni,
        vni_internal: encap_vni_internal,
        vni_external: encap_vni_external,
        mtu: encap_mtu,
    };
    overlay.validate()?;

    let dns_allowlist_idle_secs =
        dns_allowlist_idle_secs.unwrap_or(idle_timeout_secs + DNS_ALLOWLIST_IDLE_SLACK_SECS);
    let dns_allowlist_gc_interval_secs =
        dns_allowlist_gc_interval_secs.unwrap_or(DNS_ALLOWLIST_GC_INTERVAL_SECS);

    let management_iface = management_iface
        .ok_or_else(|| "missing required flags: --management-interface".to_string())?;
    let data_plane_iface = data_plane_iface
        .ok_or_else(|| "missing required flags: --data-plane-interface".to_string())?;

    Ok(CliConfig {
        management_iface,
        data_plane_iface,
        dns_target_ips,
        dns_upstreams,
        data_plane_mode,
        idle_timeout_secs,
        dns_allowlist_idle_secs,
        dns_allowlist_gc_interval_secs,
        default_policy,
        dhcp_timeout_secs,
        dhcp_retry_max,
        dhcp_lease_min_secs,
        internal_cidr,
        snat_mode,
        encap_mode,
        encap_vni,
        encap_vni_internal,
        encap_vni_external,
        encap_udp_port: Some(encap_udp_port),
        encap_udp_port_internal,
        encap_udp_port_external,
        encap_mtu,
        http_bind,
        http_advertise,
        http_external_url,
        http_tls_dir,
        http_cert_path,
        http_key_path,
        http_ca_path,
        http_tls_san,
        metrics_bind,
        cloud_provider,
        cluster: build_cluster_config(
            cluster_bind,
            cluster_join_bind,
            cluster_advertise,
            cluster_join,
            cluster_data_dir,
            node_id_path,
            bootstrap_token_path,
        )?,
        cluster_migrate_from_local,
        cluster_migrate_force,
        cluster_migrate_verify,
        integration_mode,
        integration_route_name,
        integration_drain_timeout_secs,
        integration_reconcile_interval_secs,
        integration_cluster_name,
        azure_subscription_id,
        azure_resource_group,
        azure_vmss_name,
        aws_region,
        aws_vpc_id,
        aws_asg_name,
        gcp_project,
        gcp_region,
        gcp_ig_name,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_args;
    use crate::runtime::cli::DataPlaneMode;

    fn required_args(data_plane_mode: &str, data_plane_iface: &str) -> Vec<String> {
        vec![
            "--management-interface".to_string(),
            "mgmt0".to_string(),
            "--data-plane-interface".to_string(),
            data_plane_iface.to_string(),
            "--dns-target-ip".to_string(),
            "10.0.0.53".to_string(),
            "--dns-upstream".to_string(),
            "1.1.1.1:53".to_string(),
            "--data-plane-mode".to_string(),
            data_plane_mode.to_string(),
        ]
    }

    #[test]
    fn parse_args_accepts_mac_selector_for_dpdk_mode() {
        let cfg = parse_args("neuwerk", required_args("dpdk", "mac:02:00:00:00:00:42"))
            .expect("cli config");

        assert_eq!(cfg.data_plane_mode, DataPlaneMode::Dpdk);
        assert_eq!(cfg.data_plane_iface, "mac:02:00:00:00:00:42");
    }

    #[test]
    fn parse_args_rejects_mac_selector_for_soft_modes() {
        let err = parse_args("neuwerk", required_args("tun", "mac:02:00:00:00:00:42"))
            .expect_err("soft dataplane must reject mac selector");

        assert_eq!(
            err,
            "--data-plane-interface must be a netdev when --data-plane-mode is tun or tap"
        );
    }
}
