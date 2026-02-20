use std::net::{IpAddr, SocketAddr};

use crate::e2e::services::{dns_query, http_get, https_get};
use crate::e2e::topology::TopologyConfig;

pub struct TestCase {
    pub name: &'static str,
    pub func: fn(&TopologyConfig) -> Result<(), String>,
}

pub fn cases() -> Vec<TestCase> {
    vec![TestCase {
        name: "dns_allows_http",
        func: dns_allows_http,
    }]
}

fn dns_allows_http(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let https_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 443);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let mut ips = Vec::new();
        for _ in 0..10 {
            match dns_query(client_bind, dns_server, "foo.allowed").await {
                Ok(result) => {
                    ips = result;
                    break;
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
        if ips.is_empty() {
            return Err("dns query failed".to_string());
        }
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http = http_get(http_addr, "foo.allowed").await?;
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        let https = https_get(https_addr, "foo.allowed").await?;
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }

        Ok(())
    })
}

fn first_line(msg: &str) -> &str {
    msg.split("\r\n").next().unwrap_or(msg)
}
