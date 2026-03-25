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

    use super::super::{load_config, load_config_str};

    const MINIMAL_CONFIG: &str = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
dns:
  upstreams:
    - 10.0.0.2:53
"#;

    #[test]
    fn load_config_rejects_unknown_fields() {
        let raw = r#"
version: 1
bootstrap:
  management_interface: eth0
  data_interface: eth1
  data_plane_mode: dpdk
  mystery: true
dns:
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
  data_plane_mode: dpdk
dns:
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
        assert_eq!(cfg.bootstrap.data_plane_mode, "dpdk");
        assert_eq!(cfg.dns.upstreams, vec!["10.0.0.2:53"]);
    }

    #[test]
    fn load_config_reads_from_file_path() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file should be created");
        fs::write(tmp.path(), MINIMAL_CONFIG).expect("fixture should be written");

        let cfg = load_config(tmp.path()).expect("config file should parse");
        assert_eq!(cfg.version, 1);
    }
}
