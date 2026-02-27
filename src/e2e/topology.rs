use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use netns_rs::NetNs;

use crate::e2e::netlink::{
    add_address, add_gateway_route_v4, add_route_v4, add_rule_iif_v4, create_veth_pair,
    get_link_index, set_link_namespace, set_link_up, wait_for_link_index, with_handle,
};

pub struct Topology {
    client: Option<NetNs>,
    fw: Option<NetNs>,
    upstream: Option<NetNs>,
}

#[derive(Clone, Debug)]
pub struct TopologyConfig {
    pub client_ns: String,
    pub fw_ns: String,
    pub upstream_ns: String,
    pub client_mgmt_iface: String,
    pub fw_mgmt_iface: String,
    pub client_dp_iface: String,
    pub fw_dp_iface: String,
    pub fw_up_iface: String,
    pub up_dp_iface: String,
    pub fw_up_mgmt_iface: String,
    pub up_mgmt_iface: String,
    pub dp_tun_iface: String,
    pub client_mgmt_ip: Ipv4Addr,
    pub client_mgmt_ip_alt: Ipv4Addr,
    pub fw_mgmt_ip: Ipv4Addr,
    pub fw_mgmt_ip_alt: Ipv4Addr,
    pub client_dp_ip: Ipv4Addr,
    pub fw_dp_ip: Ipv4Addr,
    pub fw_up_ip: Ipv4Addr,
    pub up_dp_ip: Ipv4Addr,
    pub up_dp_ip_alt: Ipv4Addr,
    pub up_udp_port: u16,
    pub fw_up_mgmt_ip: Ipv4Addr,
    pub up_mgmt_ip: Ipv4Addr,
    pub dp_public_ip: Ipv4Addr,
    pub cluster_bind_port: u16,
    pub cluster_join_port: u16,
    pub http_bind_port: u16,
    pub metrics_port: u16,
    pub http_tls_sans: Vec<String>,
    pub idle_timeout_secs: u64,
    pub dns_allowlist_idle_secs: u64,
    pub dns_allowlist_gc_interval_secs: u64,
    pub overlay_vxlan_port: u16,
    pub overlay_vxlan_vni: u32,
    pub overlay_geneve_port: u16,
    pub overlay_geneve_vni: u32,
    pub cluster_data_dir: PathBuf,
    pub cluster_node_id_path: PathBuf,
    pub bootstrap_token_path: PathBuf,
    pub http_tls_dir: PathBuf,
    pub upstream_tls_ca_path: PathBuf,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self {
            client_ns: "fw-client".to_string(),
            fw_ns: "fw-node".to_string(),
            upstream_ns: "fw-upstream".to_string(),
            client_mgmt_iface: "veth-c-mgmt".to_string(),
            fw_mgmt_iface: "veth-fw-mgmt".to_string(),
            client_dp_iface: "veth-c-dp".to_string(),
            fw_dp_iface: "veth-fw-dp".to_string(),
            fw_up_iface: "veth-fw-up".to_string(),
            up_dp_iface: "veth-up-dp".to_string(),
            fw_up_mgmt_iface: "veth-fw-up-mgmt".to_string(),
            up_mgmt_iface: "veth-up-mgmt".to_string(),
            dp_tun_iface: "dp0".to_string(),
            client_mgmt_ip: Ipv4Addr::new(192, 0, 2, 2),
            client_mgmt_ip_alt: Ipv4Addr::new(192, 0, 2, 3),
            fw_mgmt_ip: Ipv4Addr::new(192, 0, 2, 1),
            fw_mgmt_ip_alt: Ipv4Addr::new(192, 0, 2, 10),
            client_dp_ip: Ipv4Addr::new(10, 0, 0, 2),
            fw_dp_ip: Ipv4Addr::new(10, 0, 0, 1),
            fw_up_ip: Ipv4Addr::new(198, 51, 100, 2),
            up_dp_ip: Ipv4Addr::new(198, 51, 100, 10),
            up_dp_ip_alt: Ipv4Addr::new(198, 51, 100, 20),
            up_udp_port: 9000,
            fw_up_mgmt_ip: Ipv4Addr::new(172, 16, 0, 1),
            up_mgmt_ip: Ipv4Addr::new(172, 16, 0, 2),
            dp_public_ip: Ipv4Addr::new(203, 0, 113, 1),
            cluster_bind_port: 9600,
            cluster_join_port: 9601,
            http_bind_port: 8443,
            metrics_port: 8080,
            http_tls_sans: vec![Ipv4Addr::new(192, 0, 2, 10).to_string()],
            idle_timeout_secs: 1,
            dns_allowlist_idle_secs: 2,
            dns_allowlist_gc_interval_secs: 1,
            overlay_vxlan_port: 10800,
            overlay_vxlan_vni: 800,
            overlay_geneve_port: 6081,
            overlay_geneve_vni: 100,
            cluster_data_dir: PathBuf::from("/tmp/neuwerk-e2e-cluster"),
            cluster_node_id_path: PathBuf::from("/tmp/neuwerk-e2e-cluster/node_id"),
            bootstrap_token_path: PathBuf::from("/tmp/neuwerk-e2e-cluster/bootstrap.json"),
            http_tls_dir: PathBuf::from("/tmp/neuwerk-e2e-cluster/http-tls"),
            upstream_tls_ca_path: PathBuf::from("/tmp/neuwerk-e2e-cluster/upstream-ca.pem"),
        }
    }
}

impl TopologyConfig {
    pub fn allowlist_eviction_delay(&self) -> Duration {
        let secs = self
            .idle_timeout_secs
            .saturating_add(self.dns_allowlist_idle_secs)
            .saturating_add(self.dns_allowlist_gc_interval_secs)
            .saturating_add(1);
        Duration::from_secs(secs.max(1))
    }
}

impl Topology {
    pub fn create(cfg: &TopologyConfig) -> Result<Self, String> {
        let client = NetNs::new(&cfg.client_ns).map_err(|e| format!("{e}"))?;
        let fw = NetNs::new(&cfg.fw_ns).map_err(|e| format!("{e}"))?;
        let upstream = NetNs::new(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
        Ok(Self {
            client: Some(client),
            fw: Some(fw),
            upstream: Some(upstream),
        })
    }

    pub fn setup(&self, cfg: &TopologyConfig) -> Result<(), String> {
        self.setup_links(cfg)?;
        self.configure_client(cfg)?;
        self.configure_fw_base(cfg)?;
        self.configure_upstream(cfg)?;
        Ok(())
    }

    fn setup_links(&self, cfg: &TopologyConfig) -> Result<(), String> {
        let fw_fd = self.fw().file().as_raw_fd();
        let client_fd = self.client().file().as_raw_fd();
        let up_fd = self.upstream().file().as_raw_fd();

        let veths = vec![
            (&cfg.client_mgmt_iface, &cfg.fw_mgmt_iface, client_fd, fw_fd),
            (&cfg.client_dp_iface, &cfg.fw_dp_iface, client_fd, fw_fd),
            (&cfg.fw_up_iface, &cfg.up_dp_iface, fw_fd, up_fd),
            (&cfg.fw_up_mgmt_iface, &cfg.up_mgmt_iface, fw_fd, up_fd),
        ];

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime error: {e}"))?;

        rt.block_on(async {
            with_handle(|handle| async move {
                for (left, right, left_ns, right_ns) in veths {
                    create_veth_pair(&handle, left, right).await?;
                    set_link_namespace(&handle, left, &left_ns).await?;
                    set_link_namespace(&handle, right, &right_ns).await?;
                }
                Ok(())
            })
            .await
        })
    }

    fn configure_client(&self, cfg: &TopologyConfig) -> Result<(), String> {
        self.client()
            .run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async {
                    with_handle(|handle| async move {
                        let lo = get_link_index(&handle, "lo").await?;
                        set_link_up(&handle, lo).await?;

                        let mgmt = get_link_index(&handle, &cfg.client_mgmt_iface).await?;
                        add_address(&handle, mgmt, IpAddr::V4(cfg.client_mgmt_ip), 24).await?;
                        add_address(&handle, mgmt, IpAddr::V4(cfg.client_mgmt_ip_alt), 24).await?;
                        set_link_up(&handle, mgmt).await?;

                        let dp = get_link_index(&handle, &cfg.client_dp_iface).await?;
                        add_address(&handle, dp, IpAddr::V4(cfg.client_dp_ip), 24).await?;
                        set_link_up(&handle, dp).await?;

                        add_gateway_route_v4(
                            &handle,
                            Ipv4Addr::new(0, 0, 0, 0),
                            0,
                            cfg.fw_dp_ip,
                            dp,
                        )
                        .await?;
                        Ok(())
                    })
                    .await
                })
            })
            .map_err(|e| format!("{e}"))?
    }

    fn configure_fw_base(&self, cfg: &TopologyConfig) -> Result<(), String> {
        self.fw()
            .run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async {
                    with_handle(|handle| async move {
                        let lo = get_link_index(&handle, "lo").await?;
                        set_link_up(&handle, lo).await?;

                        let mgmt = get_link_index(&handle, &cfg.fw_mgmt_iface).await?;
                        add_address(&handle, mgmt, IpAddr::V4(cfg.fw_mgmt_ip), 24).await?;
                        add_address(&handle, mgmt, IpAddr::V4(cfg.fw_mgmt_ip_alt), 24).await?;
                        set_link_up(&handle, mgmt).await?;

                        let dp = get_link_index(&handle, &cfg.fw_dp_iface).await?;
                        add_address(&handle, dp, IpAddr::V4(cfg.fw_dp_ip), 24).await?;
                        set_link_up(&handle, dp).await?;

                        let up = get_link_index(&handle, &cfg.fw_up_iface).await?;
                        add_address(&handle, up, IpAddr::V4(cfg.fw_up_ip), 24).await?;
                        set_link_up(&handle, up).await?;

                        let up_mgmt = get_link_index(&handle, &cfg.fw_up_mgmt_iface).await?;
                        add_address(&handle, up_mgmt, IpAddr::V4(cfg.fw_up_mgmt_ip), 24).await?;
                        set_link_up(&handle, up_mgmt).await?;

                        set_sysctl("net/ipv4/ip_forward", "1")?;
                        set_sysctl("net/ipv4/conf/all/rp_filter", "0")?;
                        set_sysctl("net/ipv4/conf/default/rp_filter", "0")?;
                        install_mgmt_isolation(
                            &cfg.fw_dp_iface,
                            cfg.fw_mgmt_ip,
                            cfg.client_dp_ip,
                            24,
                        )?;
                        install_mgmt_isolation(
                            &cfg.fw_dp_iface,
                            cfg.fw_mgmt_ip_alt,
                            cfg.client_dp_ip,
                            24,
                        )?;
                        Ok(())
                    })
                    .await
                })
            })
            .map_err(|e| format!("{e}"))?
    }

    fn configure_upstream(&self, cfg: &TopologyConfig) -> Result<(), String> {
        self.upstream()
            .run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async {
                    with_handle(|handle| async move {
                        let lo = get_link_index(&handle, "lo").await?;
                        set_link_up(&handle, lo).await?;

                        let dp = get_link_index(&handle, &cfg.up_dp_iface).await?;
                        add_address(&handle, dp, IpAddr::V4(cfg.up_dp_ip), 24).await?;
                        add_address(&handle, dp, IpAddr::V4(cfg.up_dp_ip_alt), 24).await?;
                        set_link_up(&handle, dp).await?;

                        let mgmt = get_link_index(&handle, &cfg.up_mgmt_iface).await?;
                        add_address(&handle, mgmt, IpAddr::V4(cfg.up_mgmt_ip), 24).await?;
                        set_link_up(&handle, mgmt).await?;

                        add_gateway_route_v4(
                            &handle,
                            Ipv4Addr::new(203, 0, 113, 0),
                            24,
                            cfg.fw_up_ip,
                            dp,
                        )
                        .await?;
                        Ok(())
                    })
                    .await
                })
            })
            .map_err(|e| format!("{e}"))?
    }

    pub fn configure_fw_dataplane(&self, cfg: &TopologyConfig) -> Result<(), String> {
        self.fw()
            .run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async {
                    with_handle(|handle| async move {
                        let dp0 =
                            wait_for_link_index(&handle, &cfg.dp_tun_iface, Duration::from_secs(3))
                                .await?;
                        set_link_up(&handle, dp0).await?;

                        add_route_v4(&handle, Ipv4Addr::new(0, 0, 0, 0), 0, dp0, Some(100)).await?;
                        add_rule_iif_v4(&handle, &cfg.fw_dp_iface, 100, Some(100)).await?;
                        add_rule_iif_v4(&handle, &cfg.fw_up_iface, 100, Some(101)).await?;
                        Ok(())
                    })
                    .await
                })
            })
            .map_err(|e| format!("{e}"))?
    }

    pub fn client(&self) -> &NetNs {
        self.client.as_ref().expect("client netns missing")
    }

    pub fn fw(&self) -> &NetNs {
        self.fw.as_ref().expect("fw netns missing")
    }

    pub fn upstream(&self) -> &NetNs {
        self.upstream.as_ref().expect("upstream netns missing")
    }
}

fn set_sysctl(path: &str, value: &str) -> Result<(), String> {
    let full = format!("/proc/sys/{path}");
    std::fs::write(&full, value).map_err(|e| format!("sysctl {full} failed: {e}"))
}

fn install_mgmt_isolation(
    iface: &str,
    dst: Ipv4Addr,
    src: Ipv4Addr,
    src_prefix: u8,
) -> Result<(), String> {
    let src_cidr = format!("{}/{}", cidr_base(src, src_prefix), src_prefix.min(32));
    let status = Command::new("iptables")
        .args([
            "-w",
            "-I",
            "INPUT",
            "-i",
            iface,
            "-d",
            &dst.to_string(),
            "-j",
            "DROP",
        ])
        .status()
        .map_err(|e| format!("iptables invocation failed: {e}"))?;
    if !status.success() {
        return Err("iptables rule install failed".to_string());
    }
    let status = Command::new("iptables")
        .args([
            "-w",
            "-I",
            "INPUT",
            "-s",
            &src_cidr,
            "-d",
            &dst.to_string(),
            "-j",
            "DROP",
        ])
        .status()
        .map_err(|e| format!("iptables invocation failed: {e}"))?;
    if !status.success() {
        return Err("iptables rule install failed".to_string());
    }
    Ok(())
}

fn cidr_base(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let prefix = prefix.min(32);
    let mask = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    let base = u32::from(ip) & mask;
    Ipv4Addr::from(base)
}

impl Drop for Topology {
    fn drop(&mut self) {
        if let Some(ns) = self.client.take() {
            let _ = ns.remove();
        }
        if let Some(ns) = self.fw.take() {
            let _ = ns.remove();
        }
        if let Some(ns) = self.upstream.take() {
            let _ = ns.remove();
        }
    }
}
