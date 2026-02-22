use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use nix::sched::{setns, CloneFlags};
use rustls;
use std::os::unix::process::CommandExt;

use firewall::controlplane::api_auth;
use firewall::controlplane::cluster::store::ClusterStore;
use firewall::controlplane::policy_config::{PolicyConfig, PolicyMode};
use firewall::e2e::cluster_tests;
use firewall::e2e::services::{
    generate_upstream_tls_material, http_set_policy, http_wait_for_health, UpstreamServices,
};
use firewall::e2e::tests::{cases, TestCase};
use firewall::e2e::topology::{Topology, TopologyConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_root()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut cfg = TopologyConfig::default();
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

    cluster_tests::run(&topology)?;

    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let tls_material = generate_upstream_tls_material()?;
    std::fs::write(&cfg.upstream_tls_ca_path, &tls_material.ca_pem)
        .map_err(|e| format!("write upstream ca failed: {e}"))?;

    let upstream_services = UpstreamServices::start(
        upstream_ns,
        (cfg.up_mgmt_ip, 53).into(),
        (cfg.up_dp_ip, 80).into(),
        (cfg.up_dp_ip, 443).into(),
        (cfg.up_dp_ip, cfg.up_udp_port).into(),
        cfg.up_dp_ip,
        cfg.up_dp_ip_alt,
        tls_material,
    )?;

    let mut firewall = spawn_firewall(&topology, &cfg)?;
    topology.configure_fw_dataplane(&cfg)?;

    let result = run_cases(&cfg, &topology, &upstream_services);

    let _ = firewall.kill();
    drop(upstream_services);
    drop(topology);

    result.map_err(|e| e.into())
}

fn run_cases(
    cfg: &TopologyConfig,
    topology: &Topology,
    _services: &UpstreamServices,
) -> Result<(), String> {
    for case in cases() {
        provision_baseline_policy(cfg, topology)?;
        run_case(cfg, topology, &case)?;
    }
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
                http_set_policy(
                    api_addr,
                    &tls_dir,
                    policy.clone(),
                    PolicyMode::Enforce,
                    Some(&token),
                )
                .await?;
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

fn spawn_firewall(topology: &Topology, cfg: &TopologyConfig) -> Result<Child, String> {
    let bin = firewall_binary_path().map_err(|e| format!("{e}"))?;
    let ns_file = topology
        .fw()
        .file()
        .try_clone()
        .map_err(|e| format!("clone netns fd failed: {e}"))?;

    let mut cmd = Command::new(bin);
    cmd.arg("--management-interface")
        .arg(&cfg.fw_mgmt_iface)
        .arg("--data-plane-interface")
        .arg(&cfg.dp_tun_iface)
        .arg("--data-plane-mode")
        .arg("tun")
        .arg("--idle-timeout-secs")
        .arg(cfg.idle_timeout_secs.to_string())
        .arg("--dns-allowlist-idle-secs")
        .arg(cfg.dns_allowlist_idle_secs.to_string())
        .arg("--dns-allowlist-gc-interval-secs")
        .arg(cfg.dns_allowlist_gc_interval_secs.to_string())
        .arg("--dns-upstream")
        .arg(format!("{}:53", cfg.up_mgmt_ip))
        .arg("--dns-listen")
        .arg(format!("{}:53", cfg.fw_mgmt_ip))
        .arg("--snat-ip")
        .arg(cfg.dp_public_ip.to_string())
        .arg("--http-tls-dir")
        .arg(&cfg.http_tls_dir)
        .arg("--cluster-bind")
        .arg(format!("{}:{}", cfg.fw_mgmt_ip, cfg.cluster_bind_port))
        .arg("--cluster-join-bind")
        .arg(format!("{}:{}", cfg.fw_mgmt_ip, cfg.cluster_join_port))
        .arg("--cluster-advertise")
        .arg(format!("{}:{}", cfg.fw_mgmt_ip, cfg.cluster_bind_port))
        .arg("--cluster-data-dir")
        .arg(&cfg.cluster_data_dir)
        .arg("--node-id-path")
        .arg(&cfg.cluster_node_id_path)
        .arg("--bootstrap-token-path")
        .arg(&cfg.bootstrap_token_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if !cfg.http_tls_sans.is_empty() {
        cmd.arg("--http-tls-san")
            .arg(cfg.http_tls_sans.join(","));
    }

    unsafe {
        cmd.pre_exec(move || {
            setns(&ns_file, CloneFlags::CLONE_NEWNET)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| format!("failed to spawn firewall: {e}"))
}

fn firewall_binary_path() -> Result<std::path::PathBuf, std::io::Error> {
    let mut exe = std::env::current_exe()?;
    exe.set_file_name("firewall");
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
    Ok(())
}
