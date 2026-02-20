use std::process::{Child, Command, Stdio};

use nix::sched::{setns, CloneFlags};
use rustls;
use std::os::unix::process::CommandExt;

use firewall::e2e::services::UpstreamServices;
use firewall::e2e::tests::{cases, TestCase};
use firewall::e2e::topology::{Topology, TopologyConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ensure_root()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cfg = TopologyConfig::default();
    let topology = Topology::create(&cfg)?;
    topology.setup(&cfg)?;

    let upstream_ns = netns_rs::NetNs::get(&cfg.upstream_ns).map_err(|e| format!("{e}"))?;
    let upstream_services = UpstreamServices::start(
        upstream_ns,
        (cfg.up_mgmt_ip, 53).into(),
        (cfg.up_dp_ip, 80).into(),
        (cfg.up_dp_ip, 443).into(),
        (cfg.up_dp_ip, cfg.up_udp_port).into(),
        cfg.up_dp_ip,
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
        .arg("1")
        .arg("--dns-upstream")
        .arg(format!("{}:53", cfg.up_mgmt_ip))
        .arg("--dns-listen")
        .arg(format!("{}:53", cfg.fw_mgmt_ip))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

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
