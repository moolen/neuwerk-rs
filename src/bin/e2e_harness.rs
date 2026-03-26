use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nix::sched::{setns, CloneFlags};
use std::os::unix::process::CommandExt;

use neuwerk::controlplane::api_auth;
use neuwerk::controlplane::cluster::store::ClusterStore;
use neuwerk::controlplane::policy_config::{PolicyConfig, PolicyMode};
use neuwerk::controlplane::policy_repository::PolicyActive;
use neuwerk::e2e::cluster_tests;
use neuwerk::e2e::services::{
    generate_upstream_tls_material, http_set_policy, http_wait_for_health, UpstreamServices,
};
use neuwerk::e2e::tests::{
    cases, overlay_cases_geneve, overlay_cases_vxlan, overlay_cases_vxlan_dual_tunnel, TestCase,
};
use neuwerk::e2e::topology::{Topology, TopologyConfig};

const RUNTIME_CONFIG_DIR: &str = "/etc/neuwerk";
const RUNTIME_CONFIG_PATH: &str = "/etc/neuwerk/config.yaml";
const RUNTIME_CONFIG_LOCK_PATH: &str = "/tmp/neuwerk-runtime-config.lock";

#[derive(Clone, Debug)]
struct RuntimeConfigPaths {
    dir: PathBuf,
    config: PathBuf,
    lock: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_root()?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let case_filter = selected_case_names();
    let skip_cluster = env_flag("NEUWERK_E2E_SKIP_CLUSTER");
    let skip_overlay = env_flag("NEUWERK_E2E_SKIP_OVERLAY");

    let mut cfg = TopologyConfig::default();
    cleanup_stale_netns(&cfg)?;
    let cluster_dir = create_temp_dir("e2e-cluster")?;
    let token_path = cluster_dir.join("bootstrap.json");
    write_token_file(&token_path)?;
    cfg.cluster_data_dir = cluster_dir.clone();
    cfg.cluster_node_id_path = cluster_dir.join("node_id");
    cfg.bootstrap_token_path = token_path;
    cfg.http_tls_dir = cluster_dir.join("http-tls");
    cfg.upstream_tls_ca_path = cluster_dir.join("upstream-ca.pem");

    let topology = Topology::create(&cfg)?;
    topology.setup(&cfg)?;

    if !skip_cluster {
        cluster_tests::run(&topology)?;
    }

    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let tls_material = generate_upstream_tls_material()?;
    std::fs::write(&cfg.upstream_tls_ca_path, &tls_material.ca_pem)
        .map_err(|e| format!("write upstream ca failed: {e}"))?;

    let upstream_services = UpstreamServices::start(
        upstream_ns,
        (cfg.up_mgmt_ip, 53).into(),
        (cfg.up_mgmt_ip_alt, 53).into(),
        (cfg.up_dp_ip, 80).into(),
        (cfg.up_dp_ip, 443).into(),
        (cfg.up_dp_ip, cfg.up_udp_port).into(),
        cfg.up_dp_ip,
        cfg.up_dp_ip_alt,
        tls_material,
    )?;

    let mut neuwerk = spawn_neuwerk(
        &topology,
        &cfg,
        &OverlayConfigOverrides::default(),
        &[],
    )?;
    topology.configure_fw_dataplane(&cfg)?;

    let mut result = run_cases(&cfg, &topology, &upstream_services, case_filter.as_ref());

    neuwerk.kill();

    if result.is_ok() && !skip_overlay {
        result = run_overlay_suites(&cfg, &topology);
    }

    drop(upstream_services);
    drop(topology);

    result.map_err(|e| e.into())
}

fn cleanup_stale_netns(cfg: &TopologyConfig) -> Result<(), String> {
    let names = [&cfg.client_ns, &cfg.fw_ns, &cfg.upstream_ns];
    for name in names {
        let output = Command::new("ip")
            .args(["netns", "del", name])
            .output()
            .map_err(|e| format!("ip netns del {name} failed: {e}"))?;
        if output.status.success() {
            continue;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file") || stderr.contains("Cannot find") {
            continue;
        }
        return Err(format!("failed to delete netns {name}: {}", stderr.trim()));
    }
    Ok(())
}

fn run_cases(
    cfg: &TopologyConfig,
    topology: &Topology,
    _services: &UpstreamServices,
    case_filter: Option<&HashSet<String>>,
) -> Result<(), String> {
    for case in cases() {
        if case_filter.is_some_and(|selected| !selected.contains(case.name)) {
            continue;
        }
        provision_baseline_policy(cfg, topology)?;
        run_case(cfg, topology, &case)?;
    }
    Ok(())
}

fn selected_case_names() -> Option<HashSet<String>> {
    let raw = std::env::var("NEUWERK_E2E_CASE_FILTER").ok()?;
    let selected = raw
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>();
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false)
}

fn run_overlay_suites(cfg: &TopologyConfig, topology: &Topology) -> Result<(), String> {
    run_overlay_suite(
        cfg,
        topology,
        overlay_cases_vxlan(),
        OverlayConfigOverrides {
            snat: "none".to_string(),
            encap_mode: Some("vxlan".to_string()),
            encap_vni: Some(cfg.overlay_vxlan_vni),
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: Some(cfg.overlay_vxlan_port),
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: Some(1200),
            swap_tunnels: false,
        },
        vec![],
    )?;
    run_overlay_suite(
        cfg,
        topology,
        overlay_cases_vxlan_dual_tunnel(),
        OverlayConfigOverrides {
            snat: "none".to_string(),
            encap_mode: Some("vxlan".to_string()),
            encap_vni: None,
            encap_vni_internal: Some(cfg.overlay_vxlan_vni),
            encap_vni_external: Some(cfg.overlay_vxlan_vni.wrapping_add(1)),
            encap_udp_port: None,
            encap_udp_port_internal: Some(cfg.overlay_vxlan_port),
            encap_udp_port_external: Some(cfg.overlay_vxlan_port.wrapping_add(1)),
            encap_mtu: Some(1200),
            swap_tunnels: true,
        },
        vec![("NEUWERK_GWLB_SWAP_TUNNELS".to_string(), "1".to_string())],
    )?;
    run_overlay_suite(
        cfg,
        topology,
        overlay_cases_geneve(),
        OverlayConfigOverrides {
            snat: "none".to_string(),
            encap_mode: Some("geneve".to_string()),
            encap_vni: Some(cfg.overlay_geneve_vni),
            encap_vni_internal: None,
            encap_vni_external: None,
            encap_udp_port: Some(cfg.overlay_geneve_port),
            encap_udp_port_internal: None,
            encap_udp_port_external: None,
            encap_mtu: Some(1200),
            swap_tunnels: false,
        },
        vec![],
    )?;
    Ok(())
}

fn run_overlay_suite(
    cfg: &TopologyConfig,
    topology: &Topology,
    cases: Vec<TestCase>,
    overlay: OverlayConfigOverrides,
    extra_env: Vec<(String, String)>,
) -> Result<(), String> {
    let mut neuwerk = spawn_neuwerk(topology, cfg, &overlay, &extra_env)?;
    topology.configure_fw_dataplane(cfg)?;
    for case in cases {
        run_case(cfg, topology, &case)?;
    }
    neuwerk.kill();
    Ok(())
}

fn run_case(cfg: &TopologyConfig, topology: &Topology, case: &TestCase) -> Result<(), String> {
    println!("running case: {}", case.name);
    topology
        .client()
        .run(|_| (case.func)(cfg))
        .map_err(|e| format!("{e}"))?
}

fn provision_baseline_policy(cfg: &TopologyConfig, topology: &Topology) -> Result<(), String> {
    let baseline_policy = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/e2e_policy.yaml"
    ));
    let policy: PolicyConfig =
        serde_yaml::from_str(baseline_policy).map_err(|e| format!("policy yaml error: {e}"))?;
    let token = auth_token(cfg)?;
    let api_addr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(cfg.fw_mgmt_ip), cfg.http_bind_port);
    let tls_dir = cfg.http_tls_dir.clone();
    topology
        .client()
        .run(|_| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("tokio runtime error: {e}"))?;
            rt.block_on(async {
                http_wait_for_health(api_addr, &tls_dir, std::time::Duration::from_secs(10))
                    .await?;
                let record = http_set_policy(
                    api_addr,
                    &tls_dir,
                    policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
                let active_path =
                    std::path::PathBuf::from("/var/lib/neuwerk/local-policy-store/active.json");
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
                loop {
                    match std::fs::read(&active_path)
                        .ok()
                        .and_then(|payload| serde_json::from_slice::<PolicyActive>(&payload).ok())
                    {
                        Some(active) if active.id == record.id => break,
                        _ => {
                            if std::time::Instant::now() >= deadline {
                                return Err(format!(
                                    "timed out waiting for baseline active id {}; last active path={}",
                                    record.id,
                                    active_path.display()
                                ));
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        }
                    }
                }
                Ok(())
            })
        })
        .map_err(|e| format!("{e}"))?
}

fn auth_token(cfg: &TopologyConfig) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let store = match ClusterStore::open_read_only(cfg.cluster_data_dir.join("raft")) {
            Ok(store) => store,
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!("open cluster store failed: {err}"));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        match api_auth::load_keyset_from_store(&store)? {
            Some(keyset) => {
                let token = api_auth::mint_token(&keyset, "e2e", None, None)?;
                return Ok(token.token);
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    return Err("timed out waiting for api auth keyset".to_string());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
}

fn spawn_neuwerk(
    topology: &Topology,
    cfg: &TopologyConfig,
    overlay: &OverlayConfigOverrides,
    extra_env: &[(String, String)],
) -> Result<NeuwerkProcess, String> {
    let bin = neuwerk_binary_path().map_err(|e| format!("{e}"))?;
    let ns_file = topology
        .fw()
        .file()
        .try_clone()
        .map_err(|e| format!("clone netns fd failed: {e}"))?;
    let runtime_config = install_runtime_config(&build_runtime_config_yaml(cfg, overlay))?;

    let mut cmd = Command::new(bin);
    cmd.stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    for (key, value) in extra_env {
        cmd.env(key, value);
    }

    unsafe {
        cmd.pre_exec(move || {
            setns(&ns_file, CloneFlags::CLONE_NEWNET).map_err(std::io::Error::other)?;
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn neuwerk: {e}"))?;

    Ok(NeuwerkProcess {
        child,
        runtime_config: Some(runtime_config),
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct OverlayConfigOverrides {
    snat: String,
    encap_mode: Option<String>,
    encap_vni: Option<u32>,
    encap_vni_internal: Option<u32>,
    encap_vni_external: Option<u32>,
    encap_udp_port: Option<u16>,
    encap_udp_port_internal: Option<u16>,
    encap_udp_port_external: Option<u16>,
    encap_mtu: Option<u16>,
    swap_tunnels: bool,
}

fn build_runtime_config_yaml(cfg: &TopologyConfig, overlay: &OverlayConfigOverrides) -> String {
    let (snat_mode, snat_ip) = match overlay.snat.trim() {
        "" => ("static", Some(cfg.dp_public_ip.to_string())),
        "none" => ("none", None),
        "auto" => ("auto", None),
        ip => ("static", Some(ip.to_string())),
    };

    let mut yaml = String::new();
    writeln!(&mut yaml, "version: 1").unwrap();
    writeln!(&mut yaml, "bootstrap:").unwrap();
    writeln!(&mut yaml, "  management_interface: {}", cfg.fw_mgmt_iface).unwrap();
    writeln!(&mut yaml, "  data_interface: {}", cfg.dp_tun_iface).unwrap();
    writeln!(&mut yaml, "  cloud_provider: none").unwrap();
    writeln!(&mut yaml, "  data_plane_mode: tun").unwrap();

    writeln!(&mut yaml, "dns:").unwrap();
    writeln!(&mut yaml, "  target_ips:").unwrap();
    writeln!(&mut yaml, "    - {}", cfg.fw_mgmt_ip).unwrap();
    writeln!(&mut yaml, "  upstreams:").unwrap();
    writeln!(&mut yaml, "    - {}:53", cfg.up_mgmt_ip).unwrap();
    writeln!(&mut yaml, "    - {}:53", cfg.up_mgmt_ip_alt).unwrap();

    writeln!(&mut yaml, "http:").unwrap();
    writeln!(
        &mut yaml,
        "  bind: {}:{}",
        cfg.fw_mgmt_ip, cfg.http_bind_port
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  advertise: {}:{}",
        cfg.fw_mgmt_ip, cfg.http_bind_port
    )
    .unwrap();
    writeln!(&mut yaml, "  tls_dir: {}", cfg.http_tls_dir.display()).unwrap();
    if !cfg.http_tls_sans.is_empty() {
        writeln!(&mut yaml, "  tls_san:").unwrap();
        for san in &cfg.http_tls_sans {
            writeln!(&mut yaml, "    - {san}").unwrap();
        }
    }

    writeln!(&mut yaml, "metrics:").unwrap();
    writeln!(
        &mut yaml,
        "  bind: {}:{}",
        cfg.fw_mgmt_ip, cfg.metrics_port
    )
    .unwrap();
    writeln!(&mut yaml, "  allow_public_bind: true").unwrap();

    writeln!(&mut yaml, "cluster:").unwrap();
    writeln!(
        &mut yaml,
        "  bind: {}:{}",
        cfg.fw_mgmt_ip, cfg.cluster_bind_port
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  join_bind: {}:{}",
        cfg.fw_mgmt_ip, cfg.cluster_join_port
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  advertise: {}:{}",
        cfg.fw_mgmt_ip, cfg.cluster_bind_port
    )
    .unwrap();
    writeln!(&mut yaml, "  data_dir: {}", cfg.cluster_data_dir.display()).unwrap();
    writeln!(
        &mut yaml,
        "  node_id_path: {}",
        cfg.cluster_node_id_path.display()
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  token_path: {}",
        cfg.bootstrap_token_path.display()
    )
    .unwrap();

    writeln!(&mut yaml, "tls_intercept:").unwrap();
    writeln!(&mut yaml, "  upstream_verify: insecure").unwrap();

    writeln!(&mut yaml, "dataplane:").unwrap();
    writeln!(
        &mut yaml,
        "  idle_timeout_secs: {}",
        cfg.idle_timeout_secs
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  dns_allowlist_idle_secs: {}",
        cfg.dns_allowlist_idle_secs
    )
    .unwrap();
    writeln!(
        &mut yaml,
        "  dns_allowlist_gc_interval_secs: {}",
        cfg.dns_allowlist_gc_interval_secs
    )
    .unwrap();
    writeln!(&mut yaml, "  snat:").unwrap();
    writeln!(&mut yaml, "    mode: {snat_mode}").unwrap();
    if let Some(ip) = snat_ip {
        writeln!(&mut yaml, "    ip: {ip}").unwrap();
    }
    if let Some(encap_mode) = &overlay.encap_mode {
        writeln!(&mut yaml, "  encap_mode: {encap_mode}").unwrap();
    }
    if let Some(encap_vni) = overlay.encap_vni {
        writeln!(&mut yaml, "  encap_vni: {encap_vni}").unwrap();
    }
    if let Some(encap_vni_internal) = overlay.encap_vni_internal {
        writeln!(&mut yaml, "  encap_vni_internal: {encap_vni_internal}").unwrap();
    }
    if let Some(encap_vni_external) = overlay.encap_vni_external {
        writeln!(&mut yaml, "  encap_vni_external: {encap_vni_external}").unwrap();
    }
    if let Some(encap_udp_port) = overlay.encap_udp_port {
        writeln!(&mut yaml, "  encap_udp_port: {encap_udp_port}").unwrap();
    }
    if let Some(encap_udp_port_internal) = overlay.encap_udp_port_internal {
        writeln!(
            &mut yaml,
            "  encap_udp_port_internal: {encap_udp_port_internal}"
        )
        .unwrap();
    }
    if let Some(encap_udp_port_external) = overlay.encap_udp_port_external {
        writeln!(
            &mut yaml,
            "  encap_udp_port_external: {encap_udp_port_external}"
        )
        .unwrap();
    }
    if let Some(encap_mtu) = overlay.encap_mtu {
        writeln!(&mut yaml, "  encap_mtu: {encap_mtu}").unwrap();
    }
    if overlay.swap_tunnels {
        writeln!(&mut yaml, "dpdk:").unwrap();
        writeln!(&mut yaml, "  overlay:").unwrap();
        writeln!(&mut yaml, "    swap_tunnels: true").unwrap();
    }

    yaml
}

fn install_runtime_config(yaml: &str) -> Result<InstalledRuntimeConfig, String> {
    install_runtime_config_with_paths(&default_runtime_config_paths(), yaml)
}

fn install_runtime_config_with_paths(
    paths: &RuntimeConfigPaths,
    yaml: &str,
) -> Result<InstalledRuntimeConfig, String> {
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&paths.lock)
        .map_err(|err| format!("open runtime config lock failed: {err}"))?;
    flock_exclusive(&lock_file)?;

    let config_dir = paths.dir.as_path();
    let created_dir = if config_dir.exists() {
        false
    } else {
        fs::create_dir_all(config_dir)
            .map_err(|err| format!("create runtime config dir failed: {err}"))?;
        true
    };

    let previous = match fs::read(&paths.config) {
        Ok(raw) => Some(raw),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => return Err(format!("read existing runtime config failed: {err}")),
    };

    fs::write(&paths.config, yaml)
        .map_err(|err| format!("write runtime config {} failed: {err}", paths.config.display()))?;

    Ok(InstalledRuntimeConfig {
        paths: paths.clone(),
        lock_file,
        previous,
        created_dir,
    })
}

struct NeuwerkProcess {
    child: Child,
    runtime_config: Option<InstalledRuntimeConfig>,
}

impl NeuwerkProcess {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = self.child.wait();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
        let _ = self.runtime_config.take();
    }
}

impl Drop for NeuwerkProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

struct InstalledRuntimeConfig {
    paths: RuntimeConfigPaths,
    lock_file: File,
    previous: Option<Vec<u8>>,
    created_dir: bool,
}

impl Drop for InstalledRuntimeConfig {
    fn drop(&mut self) {
        if let Some(previous) = &self.previous {
            let _ = fs::write(&self.paths.config, previous);
        } else {
            let _ = fs::remove_file(&self.paths.config);
            if self.created_dir {
                let _ = fs::remove_dir(&self.paths.dir);
            }
        }
        let _ = flock_unlock(&self.lock_file);
    }
}

fn default_runtime_config_paths() -> RuntimeConfigPaths {
    RuntimeConfigPaths {
        dir: PathBuf::from(RUNTIME_CONFIG_DIR),
        config: PathBuf::from(RUNTIME_CONFIG_PATH),
        lock: PathBuf::from(RUNTIME_CONFIG_LOCK_PATH),
    }
}

fn flock_exclusive(file: &File) -> Result<(), String> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "lock runtime config failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn flock_unlock(file: &File) -> Result<(), String> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "unlock runtime config failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn neuwerk_binary_path() -> Result<std::path::PathBuf, std::io::Error> {
    let mut exe = std::env::current_exe()?;
    exe.set_file_name("neuwerk");
    Ok(exe)
}

fn ensure_root() -> Result<(), String> {
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Err("e2e harness must be run as root".to_string());
    }
    Ok(())
}

fn create_temp_dir(label: &str) -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join(format!("neuwerk-{}-{}", label, uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create temp dir failed: {e}"))?;
    Ok(dir)
}

fn write_token_file(path: &PathBuf) -> Result<(), String> {
    let json = r#"{
  "tokens": [
    { "kid": "e2e", "token": "b64:dGVzdC1zZWNyZXQ=", "valid_until": "2027-01-01T00:00:00Z" }
  ]
}"#;
    std::fs::write(path, json).map_err(|e| format!("write token file failed: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| format!("set token file permissions failed: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn runtime_config_yaml_maps_base_tun_settings() {
        let cfg = TopologyConfig::default();

        let yaml = build_runtime_config_yaml(&cfg, &OverlayConfigOverrides::default());

        assert!(yaml.contains("management_interface: veth-fw-mgmt"), "{yaml}");
        assert!(yaml.contains("data_interface: dp0"), "{yaml}");
        assert!(yaml.contains("data_plane_mode: tun"), "{yaml}");
        assert!(yaml.contains("target_ips:\n    - 192.0.2.1"), "{yaml}");
        assert!(
            yaml.contains("upstreams:\n    - 172.16.0.2:53\n    - 172.16.0.3:53"),
            "{yaml}"
        );
        assert!(yaml.contains("bind: 192.0.2.1:8443"), "{yaml}");
        assert!(yaml.contains("join_bind: 192.0.2.1:9601"), "{yaml}");
        assert!(yaml.contains("data_dir: /tmp/neuwerk-e2e-cluster"), "{yaml}");
        assert!(yaml.contains("idle_timeout_secs: 1"), "{yaml}");
        assert!(yaml.contains("dns_allowlist_idle_secs: 2"), "{yaml}");
        assert!(yaml.contains("dns_allowlist_gc_interval_secs: 1"), "{yaml}");
        assert!(yaml.contains("mode: static"), "{yaml}");
        assert!(yaml.contains("ip: 203.0.113.1"), "{yaml}");
        assert!(yaml.contains("allow_public_bind: true"), "{yaml}");
        assert!(yaml.contains("upstream_verify: insecure"), "{yaml}");
    }

    #[test]
    fn runtime_config_yaml_maps_dual_tunnel_overlay_settings() {
        let cfg = TopologyConfig::default();
        let overrides = OverlayConfigOverrides {
            snat: "none".to_string(),
            encap_mode: Some("vxlan".to_string()),
            encap_vni: None,
            encap_vni_internal: Some(cfg.overlay_vxlan_vni),
            encap_vni_external: Some(cfg.overlay_vxlan_vni.wrapping_add(1)),
            encap_udp_port: None,
            encap_udp_port_internal: Some(cfg.overlay_vxlan_port),
            encap_udp_port_external: Some(cfg.overlay_vxlan_port.wrapping_add(1)),
            encap_mtu: Some(1200),
            swap_tunnels: true,
        };

        let yaml = build_runtime_config_yaml(&cfg, &overrides);

        assert!(yaml.contains("mode: none"), "{yaml}");
        assert!(yaml.contains("encap_mode: vxlan"), "{yaml}");
        assert!(yaml.contains("encap_vni_internal: 800"), "{yaml}");
        assert!(yaml.contains("encap_vni_external: 801"), "{yaml}");
        assert!(yaml.contains("encap_udp_port_internal: 10800"), "{yaml}");
        assert!(yaml.contains("encap_udp_port_external: 10801"), "{yaml}");
        assert!(yaml.contains("encap_mtu: 1200"), "{yaml}");
        assert!(yaml.contains("swap_tunnels: true"), "{yaml}");
    }

    #[test]
    fn neuwerk_process_kill_releases_runtime_config_lock() {
        let cfg = TopologyConfig::default();
        let tempdir = tempfile::tempdir().expect("tempdir");
        let paths = test_runtime_config_paths(tempdir.path());
        let runtime_config = install_runtime_config_with_paths(
            &paths,
            &build_runtime_config_yaml(&cfg, &OverlayConfigOverrides::default()),
        )
        .expect("runtime config install");
        let child = Command::new("sleep")
            .arg("60")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep child");
        let mut neuwerk = NeuwerkProcess {
            child,
            runtime_config: Some(runtime_config),
        };

        neuwerk.kill();

        assert!(
            runtime_config_lock_available(&paths),
            "runtime config lock is still held"
        );
    }

    fn runtime_config_lock_available(paths: &RuntimeConfigPaths) -> bool {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&paths.lock)
            .expect("open runtime config lock");
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            let _ = flock_unlock(&file);
            true
        } else {
            false
        }
    }

    fn test_runtime_config_paths(root: &std::path::Path) -> RuntimeConfigPaths {
        RuntimeConfigPaths {
            dir: root.join("etc-neuwerk"),
            config: root.join("etc-neuwerk/config.yaml"),
            lock: root.join("neuwerk-runtime-config.lock"),
        }
    }
}
