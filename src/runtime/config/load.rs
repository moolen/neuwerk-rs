use std::path::Path;

use super::schema::RuntimeConfigFile;
use super::types::LoadedConfig;
use super::validate::validate_config;

pub fn load_config(path: &Path) -> Result<LoadedConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("config read error ({}): {err}", path.display()))?;
    load_config_str(&raw)
}

pub fn load_config_str(raw: &str) -> Result<LoadedConfig, String> {
    let parsed: RuntimeConfigFile =
        serde_yaml::from_str(raw).map_err(|err| format!("config parse error: {err}"))?;
    validate_config(parsed)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr};

    use super::super::{load_config, load_config_str};

    const MINIMAL_CONFIG: &str = r#"
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

    const STARTUP_REPRESENTATIVE_CONFIG: &str = r#"
version: 1
bootstrap:
  management_interface: mgmt0
  data_interface: dp0
  cloud_provider: azure
  data_plane_mode: tap
dns:
  target_ips:
    - 10.10.0.53
    - 10.10.0.54
  upstreams:
    - 1.1.1.1:53
    - 8.8.8.8:53
policy:
  default: allow
  internal_cidr: 10.123.0.0/16
http:
  bind: 127.0.0.1:9443
  advertise: 10.10.0.10:9443
  external_url: https://neuwerk.example.com
  tls_dir: /var/lib/neuwerk/http-tls
  cert_path: /var/lib/neuwerk/http-tls/server.crt
  key_path: /var/lib/neuwerk/http-tls/server.key
  ca_path: /var/lib/neuwerk/http-tls/ca.crt
  tls_san:
    - neuwerk.example.com
metrics:
  bind: 127.0.0.1:8080
  allow_public_bind: false
cluster:
  bind: 127.0.0.1:9600
  join_bind: 127.0.0.1:9601
  advertise: 10.10.0.10:9600
  join_seed: 10.10.0.11:9600
  data_dir: /var/lib/neuwerk/cluster
  node_id_path: /var/lib/neuwerk/node_id
  token_path: /var/lib/neuwerk/bootstrap-token
  migrate_from_local: true
  migrate_force: false
  migrate_verify: true
integration:
  mode: azure-vmss
  route_name: neuwerk-default
  cluster_name: neuwerk
  drain_timeout_secs: 300
  reconcile_interval_secs: 15
  azure:
    subscription_id: 00000000-0000-0000-0000-000000000000
    resource_group: rg-neuwerk
    vmss_name: vmss-neuwerk
dataplane:
  idle_timeout_secs: 120
  dns_allowlist_idle_secs: 240
  dns_allowlist_gc_interval_secs: 30
  dhcp_timeout_secs: 5
  dhcp_retry_max: 5
  dhcp_lease_min_secs: 60
  snat:
    mode: static
    ip: 198.51.100.20
  encap_mode: vxlan
  encap_vni: 1001
  encap_vni_internal: 1002
  encap_vni_external: 1003
  encap_udp_port: 10800
  encap_udp_port_internal: 10810
  encap_udp_port_external: 10811
  encap_mtu: 1450
dpdk:
  static_ip: 10.10.0.100
  static_prefix_len: 24
  static_gateway: 10.10.0.1
  static_mac: 02:00:00:00:00:42
"#;

    #[test]
    fn load_config_rejects_unknown_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
  mystery: true
dns:
  target_ips:
    - 10.0.0.53
  upstreams:
    - 10.0.0.2:53
"#;

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("unknown field"), "{err}");
    }

    #[test]
    fn load_config_rejects_wrong_scalar_types() {
        let raw = r#"
version: one
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

        let err = load_config_str(raw).unwrap_err();
        assert!(err.contains("invalid type"), "{err}");
    }

    #[test]
    fn load_config_accepts_minimal_valid_fixture() {
        let cfg = load_config_str(MINIMAL_CONFIG).expect("minimal config should parse");
        assert_eq!(cfg.version, 1);
        assert_eq!(cfg.bootstrap.management_interface, "eth0");
        assert_eq!(cfg.bootstrap.data_interface, "eth1");
        assert_eq!(cfg.bootstrap.cloud_provider, "none");
        assert_eq!(cfg.bootstrap.data_plane_mode, "tun");
        assert_eq!(cfg.dns.target_ips, vec![Ipv4Addr::new(10, 0, 0, 53)]);
        assert_eq!(
            cfg.dns.upstreams,
            vec![SocketAddr::from(([10, 0, 0, 2], 53))]
        );
    }

    #[test]
    fn load_config_reads_from_file_path() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file should be created");
        fs::write(tmp.path(), MINIMAL_CONFIG).expect("fixture should be written");

        let cfg = load_config(tmp.path()).expect("config file should parse");
        assert_eq!(cfg.version, 1);
    }

    #[test]
    fn load_config_accepts_startup_representative_fixture() {
        let cfg = load_config_str(STARTUP_REPRESENTATIVE_CONFIG).expect("config should parse");
        assert_eq!(cfg.bootstrap.management_interface, "mgmt0");
        assert_eq!(cfg.bootstrap.data_interface, "dp0");
        assert_eq!(cfg.bootstrap.cloud_provider, "azure");
        assert_eq!(cfg.bootstrap.data_plane_mode, "tap");
    }

    #[test]
    fn load_config_rejects_missing_dns_target_ips() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  cloud_provider: none
  data_plane_mode: tun
dns:
  upstreams:
    - 1.1.1.1:53
"#;

        let err = load_config_str(raw).expect_err("dns.target_ips is required");
        assert!(err.contains("target_ips"), "{err}");
    }
}
