pub(super) fn init_eal(iface: &str) -> Result<(), String> {
    let cached = EAL_INIT.get_or_init(|| {
            let max_cores = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
                .max(1);
            let requested = std::env::var("NEUWERK_DPDK_WORKERS")
                .ok()
                .and_then(|val| val.parse::<usize>().ok())
                .unwrap_or(max_cores)
                .max(1);
            let requested = requested.min(max_cores);
            let core_ids = std::env::var("NEUWERK_DPDK_CORE_IDS")
                .ok()
                .map(|raw| parse_core_id_list(&raw))
                .filter(|ids| !ids.is_empty())
                .map(|mut ids| {
                    ids.truncate(requested);
                    ids
                })
                .unwrap_or_else(|| (0..requested).collect());
            let core_list = if core_ids.is_empty() {
                "0".to_string()
            } else {
                core_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            tracing::info!("dpdk: eal lcore list={}", core_list);
            let mut args = vec![
                "firewall".to_string(),
                "-l".to_string(),
                core_list,
                "-n".to_string(),
                "4".to_string(),
                "--proc-type=primary".to_string(),
                "--file-prefix=neuwerk".to_string(),
                "--no-telemetry".to_string(),
            ];
            let disable_in_memory = std::env::var("NEUWERK_DPDK_DISABLE_IN_MEMORY")
                .ok()
                .map(|raw| matches!(raw.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false);
            if !disable_in_memory {
                args.push("--in-memory".to_string());
            } else {
                tracing::info!("dpdk: NEUWERK_DPDK_DISABLE_IN_MEMORY enabled; omitting --in-memory");
            }
            let cloud_provider = std::env::var("NEUWERK_CLOUD_PROVIDER")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let iova_override = std::env::var("NEUWERK_DPDK_IOVA").ok();
            if let Some(mode) = iova_override.as_deref() {
                let mode = mode.trim().to_ascii_lowercase();
                if mode == "va" || mode == "pa" {
                    args.push(format!("--iova-mode={}", mode));
                } else {
                    tracing::warn!("dpdk: invalid NEUWERK_DPDK_IOVA={}, ignoring", mode);
                }
            } else if !iommu_groups_present() {
                args.push("--iova-mode=va".to_string());
                tracing::warn!("dpdk: no iommu groups detected; forcing iova=va");
            }
            let force_netvsc = std::env::var("NEUWERK_DPDK_NETVSC")
                .ok()
                .as_deref()
                == Some("1");
            for driver in resolve_eal_driver_preloads(iface, &cloud_provider, force_netvsc) {
                tracing::info!("dpdk: preloading driver {}", driver);
                args.push("-d".to_string());
                args.push(driver);
            }
            let allow_azure_pmds = cloud_provider == "azure";
            let allow_gcp_autoprobe = cloud_provider == "gcp"
                && std::env::var("NEUWERK_GCP_DPDK_AUTOPROBE")
                    .ok()
                    .as_deref()
                    == Some("1");
            if allow_gcp_autoprobe {
                tracing::info!("dpdk: gcp auto-probe override enabled");
            }
            if let Some(pci) = normalize_pci_arg(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    tracing::info!(
                        "dpdk: gcp auto-probe enabled; ignoring explicit pci selector {}",
                        pci
                    );
                }
            } else if let Ok(pci) = pci_addr_for_iface(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    tracing::info!(
                        "dpdk: gcp auto-probe enabled; ignoring iface-derived pci selector {}",
                        pci
                    );
                }
            } else if let Some(mac) = normalize_mac_arg(iface) {
                let mac_str = format_mac(mac);
                if allow_azure_pmds {
                    if let Some(pci) = mana_pci_for_mac(mac) {
                        args.push("-a".to_string());
                        args.push(format!("{},mac={}", pci, format_mac(mac)));
                    } else if let Some(netvsc_iface) = netvsc_iface_for_mac(mac) {
                        args.push("--vdev".to_string());
                        args.push(format!(
                            "net_vdev_netvsc,iface={},force=1",
                            netvsc_iface
                        ));
                    } else if let Some(pci) = pci_addr_for_mac(mac) {
                        args.push("-a".to_string());
                        args.push(pci);
                    } else if force_netvsc {
                        args.push("--vdev".to_string());
                        args.push(format!("net_vdev_netvsc,iface=data0,force=1"));
                    } else {
                        args.push("--vdev".to_string());
                        args.push(format!("net_mana,mac={}", mac_str));
                    }
                } else if allow_gcp_autoprobe {
                    tracing::info!(
                        "dpdk: gcp auto-probe enabled; using mac selector {} after probe",
                        mac_str
                    );
                } else if let Some(pci) = pci_addr_for_mac(mac) {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    return Err(format!(
                        "dpdk: mac selector {} did not resolve to PCI; use --data-plane-interface pci:<addr> or set --cloud-provider azure",
                        mac_str
                    ));
                }
            }
            tracing::info!("dpdk: eal args: {}", args.join(" "));
            let cstrings: Vec<CString> = args
                .iter()
                .map(|arg| {
                    CString::new(arg.as_str())
                        .map_err(|_| format!("dpdk: eal arg contains interior NUL: {arg:?}"))
                })
                .collect::<Result<_, _>>()?;
            let mut argv: Vec<*mut c_char> =
                cstrings.iter().map(|s| s.as_ptr() as *mut c_char).collect();
            let argc = argv.len() as i32;
            let ret = unsafe { rte_eal_init(argc, argv.as_mut_ptr()) };
            if ret < 0 {
                return Err(format!("dpdk: rte_eal_init failed (rte_errno={})", unsafe {
                    rust_rte_errno()
                }));
            }
            Ok(())
        });
    cached.clone()
}

fn iommu_groups_present() -> bool {
    let Ok(entries) = fs::read_dir("/sys/kernel/iommu_groups") else {
        return false;
    };
    entries.flatten().next().is_some()
}

fn resolve_eal_driver_preloads(
    iface: &str,
    cloud_provider: &str,
    force_netvsc: bool,
) -> Vec<String> {
    let iface_looks_pci = normalize_pci_arg(iface).is_some()
        || pci_addr_for_iface(iface).is_ok()
        || normalize_mac_arg(iface)
            .and_then(pci_addr_for_mac)
            .is_some();
    let driver_names = base_driver_preload_names(iface_looks_pci, cloud_provider, force_netvsc);
    let search_dirs = dpdk_driver_search_dirs();
    let mut resolved = Vec::new();
    for name in driver_names {
        if let Some(path) = resolve_driver_lib_path(name, &search_dirs) {
            if !resolved.contains(&path) {
                resolved.push(path);
            }
        }
    }
    if let Ok(extra) = std::env::var("NEUWERK_DPDK_DRIVER_PRELOAD") {
        for raw in extra.split(',') {
            let token = raw.trim();
            if token.is_empty() {
                continue;
            }
            let resolved_path = if token.contains('/') {
                let candidate = Path::new(token);
                if candidate.is_file() {
                    Some(candidate.display().to_string())
                } else {
                    None
                }
            } else {
                resolve_driver_lib_path(token, &search_dirs)
            };
            if let Some(path) = resolved_path {
                if !resolved.contains(&path) {
                    resolved.push(path);
                }
            }
        }
    }
    resolved
}

fn base_driver_preload_names(
    iface_looks_pci: bool,
    cloud_provider: &str,
    force_netvsc: bool,
) -> Vec<&'static str> {
    let skip_bus_pci = std::env::var("NEUWERK_DPDK_SKIP_BUS_PCI_PRELOAD")
        .ok()
        .map(|raw| matches!(raw.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let mut driver_names: Vec<&'static str> = vec!["librte_mempool_ring.so"];
    if iface_looks_pci && !skip_bus_pci {
        driver_names.push("librte_bus_pci.so");
    }
    match cloud_provider {
        "gcp" => {
            if !skip_bus_pci {
                driver_names.push("librte_bus_pci.so");
            }
            driver_names.push("librte_net_gve.so");
        }
        "aws" => {
            if !skip_bus_pci {
                driver_names.push("librte_bus_pci.so");
            }
            driver_names.push("librte_net_ena.so");
        }
        "azure" => {
            if !skip_bus_pci {
                driver_names.push("librte_bus_pci.so");
            }
            driver_names.push("librte_bus_vdev.so");
            driver_names.push("librte_bus_vmbus.so");
            driver_names.push("librte_net_mana.so");
            driver_names.push("librte_net_netvsc.so");
            driver_names.push("librte_net_vdev_netvsc.so");
        }
        _ => {}
    }
    if force_netvsc {
        driver_names.push("librte_bus_vdev.so");
        driver_names.push("librte_bus_vmbus.so");
        driver_names.push("librte_net_netvsc.so");
        driver_names.push("librte_net_vdev_netvsc.so");
    }
    driver_names
}

fn dpdk_driver_search_dirs() -> Vec<String> {
    let mut dirs = Vec::new();
    for env_name in ["RTE_EAL_PMD_PATH", "LD_LIBRARY_PATH"] {
        let Some(raw) = std::env::var_os(env_name) else {
            continue;
        };
        for entry in std::env::split_paths(&raw) {
            if !entry.is_dir() {
                continue;
            }
            let value = entry.display().to_string();
            if !dirs.contains(&value) {
                dirs.push(value);
            }
        }
    }
    dirs
}

fn resolve_driver_lib_path(name: &str, search_dirs: &[String]) -> Option<String> {
    for dir in search_dirs {
        let dir_path = Path::new(dir);
        let exact = dir_path.join(name);
        if exact.is_file() {
            return Some(exact.display().to_string());
        }
        let prefix = format!("{name}.");
        let Ok(entries) = fs::read_dir(dir_path) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if file_name == name || file_name.starts_with(&prefix) {
                let path = entry.path();
                if path.is_file() {
                    return Some(path.display().to_string());
                }
            }
        }
    }
    None
}

fn pci_addr_for_iface(iface: &str) -> Result<String, String> {
    let path = format!("/sys/class/net/{iface}/device");
    let target = fs::read_link(Path::new(&path))
        .map_err(|err| format!("dpdk: read_link {path} failed: {err}"))?;
    let name = target
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "dpdk: invalid pci device name".to_string())?;
    Ok(name.to_string())
}

fn port_id_for_iface_or_pci(iface: &str, ports: &[PortInfo]) -> Result<u16, String> {
    if let Some(mac) = normalize_mac_arg(iface) {
        match port_id_for_mac(mac, ports) {
            Ok(port) => return Ok(port),
            Err(err) => {
                if ports.len() == 1 {
                    tracing::warn!(
                        "dpdk: {} (single port available, falling back to port {})",
                        err, ports[0].id
                    );
                    return Ok(ports[0].id);
                }
                return Err(err);
            }
        }
    }
    if let Some(pci) = normalize_pci_arg(iface) {
        return port_id_for_name(&pci);
    }
    if let Ok(pci) = pci_addr_for_iface(iface) {
        if let Ok(port) = port_id_for_name(&pci) {
            return Ok(port);
        }
    }
    if ports.len() == 1 {
        return Ok(ports[0].id);
    }
    Err(format!(
        "dpdk: multiple ports available ({}), unable to map interface or pci {iface}",
        ports.len()
    ))
}

fn port_id_for_name(name: &str) -> Result<u16, String> {
    let cname = CString::new(name).map_err(|_| "dpdk: invalid device name".to_string())?;
    let mut port_id: u16 = 0;
    let ret = unsafe { rte_eth_dev_get_port_by_name(cname.as_ptr(), &mut port_id) };
    if ret != 0 {
        return Err(format!("dpdk: rte_eth_dev_get_port_by_name failed ({ret})"));
    }
    Ok(port_id)
}

fn port_id_for_mac(mac: [u8; 6], ports: &[PortInfo]) -> Result<u16, String> {
    let matches: Vec<&PortInfo> = ports.iter().filter(|port| port.mac == mac).collect();
    if matches.is_empty() {
        return Err(format!("dpdk: no port found with mac {}", format_mac(mac)));
    }
    if matches.len() == 1 {
        return Ok(matches[0].id);
    }
    let prefer_pci = std::env::var("NEUWERK_DPDK_PREFER_PCI").ok().as_deref() == Some("1");
    if prefer_pci {
        if let Some(port) = matches
            .iter()
            .find(|port| port_name_is_pci(port.name.as_deref()))
        {
            tracing::info!(
                "dpdk: NEUWERK_DPDK_PREFER_PCI=1 selecting pci port {}",
                port.id
            );
            return Ok(port.id);
        }
    }
    if let Some(port) = matches
        .iter()
        .find(|port| port_name_is_netvsc(port.name.as_deref()))
    {
        return Ok(port.id);
    }
    if let Some(port) = matches
        .iter()
        .find(|port| port_name_is_failsafe(port.name.as_deref()))
    {
        return Ok(port.id);
    }
    if let Some(port) = matches
        .iter()
        .find(|port| port_name_is_tap(port.name.as_deref()))
    {
        return Ok(port.id);
    }
    Ok(matches[0].id)
}

fn port_name_is_failsafe(name: Option<&str>) -> bool {
    name.map(|name| name.contains("failsafe")).unwrap_or(false)
}

fn port_name_is_netvsc(name: Option<&str>) -> bool {
    name.map(|name| {
        let name = name.to_ascii_lowercase();
        if name.contains("failsafe") || name.contains("tap") {
            return false;
        }
        name.contains("netvsc") || name.contains("net_vdev_netvsc")
    })
    .unwrap_or(false)
}

fn port_name_is_tap(name: Option<&str>) -> bool {
    name.map(|name| name.contains("tap")).unwrap_or(false)
}

fn port_name_is_pci(name: Option<&str>) -> bool {
    name.map(|name| is_pci_addr(name)).unwrap_or(false)
}

fn normalize_pci_arg(value: &str) -> Option<String> {
    let value = value.trim();
    let value = value.strip_prefix("pci:").unwrap_or(value);
    if is_pci_addr(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn normalize_mac_arg(value: &str) -> Option<[u8; 6]> {
    let value = value.trim();
    let value = value.strip_prefix("mac:").unwrap_or(value);
    parse_mac(value)
}

fn parse_mac(value: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let parts: Vec<&str> = value.split(|c| c == ':' || c == '-').collect();
    if parts.len() != 6 {
        return None;
    }
    for (idx, part) in parts.iter().enumerate() {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let parsed = u8::from_str_radix(part, 16).ok()?;
        bytes[idx] = parsed;
    }
    Some(bytes)
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn pci_addr_for_mac(mac: [u8; 6]) -> Option<String> {
    let target = format_mac(mac);
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" {
            continue;
        }
        let addr_path = format!("/sys/class/net/{}/address", name);
        let addr = fs::read_to_string(addr_path).ok()?;
        if addr.trim().eq_ignore_ascii_case(&target) {
            if let Ok(pci) = pci_addr_for_iface(&name) {
                if is_pci_addr(&pci) {
                    return Some(pci);
                }
            }
        }
    }
    None
}

fn netvsc_iface_for_mac(mac: [u8; 6]) -> Option<String> {
    let target = format_mac(mac);
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" {
            continue;
        }
        let addr_path = format!("/sys/class/net/{}/address", name);
        let addr = fs::read_to_string(addr_path).ok()?;
        if !addr.trim().eq_ignore_ascii_case(&target) {
            continue;
        }
        let driver_path = format!("/sys/class/net/{}/device/driver", name);
        let driver = fs::read_link(driver_path).ok()?;
        let driver_name = driver.file_name()?.to_string_lossy();
        if driver_name == "hv_netvsc" {
            return Some(name.to_string());
        }
    }
    None
}

fn mana_pci_for_mac(mac: [u8; 6]) -> Option<String> {
    let target = format_mac(mac);
    let entries = fs::read_dir("/sys/class/net").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" {
            continue;
        }
        let addr_path = format!("/sys/class/net/{}/address", name);
        let addr = fs::read_to_string(addr_path).ok()?;
        if !addr.trim().eq_ignore_ascii_case(&target) {
            continue;
        }
        let driver_path = format!("/sys/class/net/{}/device/driver", name);
        let driver = fs::read_link(driver_path).ok()?;
        let driver_name = driver.file_name()?.to_string_lossy();
        if driver_name == "mana" {
            if let Ok(pci) = pci_addr_for_iface(&name) {
                if is_pci_addr(&pci) {
                    return Some(pci);
                }
            }
        }
    }
    None
}

fn is_pci_addr(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 2 && parts.len() != 3 {
        return false;
    }
    let (domain, bus, devfn) = if parts.len() == 3 {
        (Some(parts[0]), parts[1], parts[2])
    } else {
        (None, parts[0], parts[1])
    };
    if let Some(domain) = domain {
        if !is_hex_len(domain, 4) {
            return false;
        }
    }
    if !is_hex_len(bus, 2) {
        return false;
    }
    let mut devfn_parts = devfn.split('.');
    let dev = match devfn_parts.next() {
        Some(dev) => dev,
        None => return false,
    };
    let func = match devfn_parts.next() {
        Some(func) => func,
        None => return false,
    };
    if devfn_parts.next().is_some() {
        return false;
    }
    is_hex_len(dev, 2) && is_hex_len(func, 1)
}

fn available_ports() -> Vec<PortInfo> {
    let mut ports = Vec::new();
    for port in 0..dpdk_sys::RTE_MAX_ETHPORTS {
        let port = port as u16;
        let valid = unsafe { rte_eth_dev_is_valid_port(port) };
        if valid == 0 {
            continue;
        }
        let mut addr: ether_addr = unsafe { std::mem::zeroed() };
        unsafe { rte_eth_macaddr_get(port, &mut addr) };
        let name = port_name(port);
        ports.push(PortInfo {
            id: port,
            mac: addr.addr_bytes,
            name,
        });
    }
    ports
}

fn port_name(port_id: u16) -> Option<String> {
    let mut buf = vec![0u8; dpdk_sys::RTE_ETH_NAME_MAX_LEN as usize];
    let ret = unsafe { rte_eth_dev_get_name_by_port(port_id, buf.as_mut_ptr() as *mut c_char) };
    if ret != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

fn is_hex_len(value: &str, len: usize) -> bool {
    value.len() == len && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod eal_preload_tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::{
        base_driver_preload_names, normalize_mac_arg, parse_mac, port_id_for_iface_or_pci,
        port_id_for_mac, PortInfo,
    };

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn port(id: u16, mac: [u8; 6], name: Option<&str>) -> PortInfo {
        PortInfo {
            id,
            mac,
            name: name.map(str::to_string),
        }
    }

    fn with_prefer_pci_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let _env_guard = ENV_LOCK.lock().expect("env lock");
        let old_value = std::env::var("NEUWERK_DPDK_PREFER_PCI").ok();

        match value {
            Some(value) => std::env::set_var("NEUWERK_DPDK_PREFER_PCI", value),
            None => std::env::remove_var("NEUWERK_DPDK_PREFER_PCI"),
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        match old_value {
            Some(value) => std::env::set_var("NEUWERK_DPDK_PREFER_PCI", value),
            None => std::env::remove_var("NEUWERK_DPDK_PREFER_PCI"),
        }

        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    #[test]
    fn gcp_preloads_include_pci_bus_and_gve() {
        let names = base_driver_preload_names(true, "gcp", false);
        let names: HashSet<_> = names.into_iter().collect();
        assert!(names.contains("librte_mempool_ring.so"));
        assert!(names.contains("librte_bus_pci.so"));
        assert!(names.contains("librte_net_gve.so"));
    }

    #[test]
    fn azure_netvsc_preloads_include_vdev_stack() {
        let names = base_driver_preload_names(false, "azure", true);
        let names: HashSet<_> = names.into_iter().collect();
        assert!(names.contains("librte_mempool_ring.so"));
        assert!(names.contains("librte_bus_vdev.so"));
        assert!(names.contains("librte_bus_vmbus.so"));
        assert!(names.contains("librte_net_netvsc.so"));
        assert!(names.contains("librte_net_vdev_netvsc.so"));
    }

    #[test]
    fn parse_mac_accepts_colon_or_hyphen_separated_hex() {
        let expected = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some(expected));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some(expected));
        assert_eq!(normalize_mac_arg(" mac:AA-BB-CC-DD-EE-FF "), Some(expected));
    }

    #[test]
    fn parse_mac_rejects_invalid_octets() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:xyz"), None);
        assert_eq!(normalize_mac_arg("mac:aa:bb:cc:dd:ee:gg"), None);
    }

    #[test]
    fn port_lookup_by_mac_prefers_netvsc_without_override() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x42];
        let ports = vec![
            port(3, mac, Some("tap42")),
            port(5, mac, Some("failsafe0")),
            port(7, mac, Some("net_vdev_netvsc0")),
        ];

        assert_eq!(port_id_for_mac(mac, &ports).expect("port"), 7);
    }

    #[test]
    fn port_lookup_by_mac_prefers_pci_when_override_enabled() {
        with_prefer_pci_env(Some("1"), || {
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x43];
            let ports = vec![
                port(3, mac, Some("net_vdev_netvsc0")),
                port(5, mac, Some("0000:00:08.0")),
            ];

            assert_eq!(port_id_for_mac(mac, &ports).expect("port"), 5);
        });
    }

    #[test]
    fn port_lookup_by_mac_reports_not_found_when_multiple_ports_exist() {
        let ports = vec![
            port(
                1,
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                Some("net_vdev_netvsc0"),
            ),
            port(
                2,
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                Some("0000:00:08.0"),
            ),
        ];

        let err = port_id_for_iface_or_pci("mac:02:00:00:00:00:99", &ports).expect_err("error");
        assert!(err.contains("no port found with mac 02:00:00:00:00:99"));
    }

    #[test]
    fn port_lookup_by_mac_falls_back_to_single_port_when_only_one_exists() {
        let only_port = port(11, [0x02, 0x00, 0x00, 0x00, 0x00, 0x0b], Some("failsafe0"));
        let selected =
            port_id_for_iface_or_pci("mac:02:00:00:00:00:99", &[only_port]).expect("fallback");

        assert_eq!(selected, 11);
    }
}
