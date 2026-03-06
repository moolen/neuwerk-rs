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
            eprintln!("dpdk: eal lcore list={}", core_list);
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
                eprintln!("dpdk: NEUWERK_DPDK_DISABLE_IN_MEMORY enabled; omitting --in-memory");
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
                    eprintln!("dpdk: invalid NEUWERK_DPDK_IOVA={}, ignoring", mode);
                }
            } else if !iommu_groups_present() {
                args.push("--iova-mode=va".to_string());
                eprintln!("dpdk: no iommu groups detected; forcing iova=va");
            }
            let force_netvsc = std::env::var("NEUWERK_DPDK_NETVSC")
                .ok()
                .as_deref()
                == Some("1");
            let allow_azure_pmds = cloud_provider == "azure";
            let allow_gcp_autoprobe = cloud_provider == "gcp"
                && std::env::var("NEUWERK_GCP_DPDK_AUTOPROBE")
                    .ok()
                    .as_deref()
                    == Some("1");
            if allow_gcp_autoprobe {
                eprintln!("dpdk: gcp auto-probe override enabled");
            }
            if let Some(pci) = normalize_pci_arg(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    eprintln!(
                        "dpdk: gcp auto-probe enabled; ignoring explicit pci selector {}",
                        pci
                    );
                }
            } else if let Ok(pci) = pci_addr_for_iface(iface) {
                if !allow_gcp_autoprobe {
                    args.push("-a".to_string());
                    args.push(pci);
                } else {
                    eprintln!(
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
                    eprintln!(
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
            eprintln!("dpdk: eal args: {}", args.join(" "));
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
                    eprintln!(
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
            eprintln!(
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

