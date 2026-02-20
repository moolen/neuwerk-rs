use std::net::{IpAddr, SocketAddr};

use crate::e2e::services::{dns_query, http_get, http_stream, https_get, udp_echo};
use crate::e2e::topology::TopologyConfig;

pub struct TestCase {
    pub name: &'static str,
    pub func: fn(&TopologyConfig) -> Result<(), String>,
}

pub fn cases() -> Vec<TestCase> {
    vec![
        TestCase {
            name: "http_denied_without_dns",
            func: http_denied_without_dns,
        },
        TestCase {
            name: "udp_denied_without_dns",
            func: udp_denied_without_dns,
        },
        TestCase {
            name: "dns_allows_http",
            func: dns_allows_http,
        },
        TestCase {
            name: "dns_allows_udp",
            func: dns_allows_udp,
        },
        TestCase {
            name: "udp_multi_flow",
            func: udp_multi_flow,
        },
        TestCase {
            name: "stream_keeps_nat_alive",
            func: stream_keeps_nat_alive,
        },
    ]
}

fn http_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let start = std::time::Instant::now();
        match http_get(http_addr, "foo.allowed").await {
            Ok(_) => Err("http unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "http denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
}

fn udp_denied_without_dns(cfg: &TopologyConfig) -> Result<(), String> {
    let bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime error: {e}"))?;

    rt.block_on(async {
        let start = std::time::Instant::now();
        match udp_echo(
            bind,
            server,
            b"denied",
            std::time::Duration::from_millis(500),
        )
        .await
        {
            Ok(_) => Err("udp unexpectedly succeeded without dns allowlist".to_string()),
            Err(err) => {
                println!(
                    "udp denied as expected (no dns), after {:?}: {}",
                    start.elapsed(),
                    err
                );
                Ok(())
            }
        }
    })
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
        let dns_start = std::time::Instant::now();
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
        println!("dns response in {:?}: {:?}", dns_start.elapsed(), ips);
        if !ips.contains(&IpAddr::V4(cfg.up_dp_ip)) {
            return Err(format!("dns response missing {}", cfg.up_dp_ip));
        }

        let http_start = std::time::Instant::now();
        let http = http_get(http_addr, "foo.allowed").await?;
        println!("http request completed in {:?}", http_start.elapsed());
        if !http.starts_with("HTTP/1.1 200") {
            return Err(format!("http status unexpected: {}", first_line(&http)));
        }

        let https_start = std::time::Instant::now();
        let https = https_get(https_addr, "foo.allowed").await?;
        println!("https request completed in {:?}", https_start.elapsed());
        if !https.starts_with("HTTP/1.1 200") {
            return Err(format!("https status unexpected: {}", first_line(&https)));
        }

        Ok(())
    })
}

fn dns_allows_udp(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_bind = SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

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

        let payload = b"udp-allowed";
        let resp = udp_echo(
            udp_bind,
            udp_server,
            payload,
            std::time::Duration::from_secs(1),
        )
        .await?;
        if resp != payload {
            return Err("udp echo payload mismatch".to_string());
        }
        Ok(())
    })
}

fn udp_multi_flow(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let udp_server = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), cfg.up_udp_port);

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

        let payload_a = b"flow-a";
        let payload_b = b"flow-b";
        let fut_a = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_a,
            std::time::Duration::from_secs(1),
        );
        let fut_b = udp_echo(
            SocketAddr::new(IpAddr::V4(cfg.client_dp_ip), 0),
            udp_server,
            payload_b,
            std::time::Duration::from_secs(1),
        );

        let (resp_a, resp_b) = tokio::join!(fut_a, fut_b);
        let resp_a = resp_a?;
        let resp_b = resp_b?;
        if resp_a != payload_a || resp_b != payload_b {
            return Err("udp multi-flow payload mismatch".to_string());
        }
        Ok(())
    })
}

fn stream_keeps_nat_alive(cfg: &TopologyConfig) -> Result<(), String> {
    let client_bind = SocketAddr::new(IpAddr::V4(cfg.client_mgmt_ip), 0);
    let dns_server = SocketAddr::new(IpAddr::V4(cfg.fw_mgmt_ip), 53);
    let http_addr = SocketAddr::new(IpAddr::V4(cfg.up_dp_ip), 80);

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

        let total = http_stream(
            http_addr,
            "foo.allowed",
            std::time::Duration::from_millis(1500),
            std::time::Duration::from_secs(5),
        )
        .await?;
        if total == 0 {
            return Err("stream returned no data".to_string());
        }
        Ok(())
    })
}

fn first_line(msg: &str) -> &str {
    msg.split("\r\n").next().unwrap_or(msg)
}
