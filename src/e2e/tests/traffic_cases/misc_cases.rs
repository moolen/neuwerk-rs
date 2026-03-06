use super::*;

pub(super) fn mgmt_api_unreachable_from_dataplane(cfg: &TopologyConfig) -> Result<(), String> {
    let tls_dir = cfg.http_tls_dir.clone();
    wait_for_path(&tls_dir.join("ca.crt"), Duration::from_secs(5))?;
    let api_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;
    rt.block_on(async {
        http_wait_for_health(api_addr, &tls_dir, Duration::from_secs(5)).await?;
        let metrics_addr = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), cfg.metrics_port);
        match http_get_path_bound(metrics_addr, "metrics", "/metrics", cfg.client_dp_ip).await {
            Ok(body) => Err(format!(
                "metrics reachable from dataplane: {}",
                http_body(&body).trim()
            )),
            Err(_) => Ok(()),
        }
    })
}

pub(super) fn service_lane_svc0_present(cfg: &TopologyConfig) -> Result<(), String> {
    let output = Command::new("ip")
        .args([
            "netns", "exec", &cfg.fw_ns, "ip", "-o", "-4", "addr", "show", "dev", "svc0",
        ])
        .output()
        .map_err(|e| format!("service lane check invocation failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "service lane interface svc0 missing: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if !stdout.contains("169.254.255.1/30") {
        return Err(format!(
            "service lane svc0 missing expected address 169.254.255.1/30: {}",
            stdout.trim()
        ));
    }
    Ok(())
}
