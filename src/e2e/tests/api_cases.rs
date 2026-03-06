use super::*;

pub(super) fn api_bootstrap_tls_material(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.key"), Duration::from_secs(5))?;
    Ok(())
}

pub(super) fn api_tls_san_allows_alt_ip(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    wait_for_path(&tls_dir.join("node.crt"), Duration::from_secs(5))?;
    let sans = read_cert_sans(&tls_dir.join("node.crt"))?;
    if !sans.contains(&IpAddr::V4(cfg.fw_mgmt_ip_alt)) {
        return Err("http cert missing alt mgmt ip SAN".to_string());
    }
    Ok(())
}

include!("api_cases/audit_cases.rs");
include!("api_cases/policy_metrics_cases.rs");

pub(super) fn api_tls_key_permissions(cfg: &TopologyConfig) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("node.key"), Duration::from_secs(5))?;
    let key_path = tls_dir.join("node.key");
    let mode = std::fs::metadata(&key_path)
        .map_err(|e| format!("read key metadata failed: {e}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!("node.key permissions too permissive: {:o}", mode));
    }
    Ok(())
}
