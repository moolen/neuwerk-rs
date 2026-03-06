fn discover_kind_api(cluster_name: &str) -> Result<KindApiConfig, String> {
    let context = format!("kind-{cluster_name}");
    run_kubectl(&context, &["create", "namespace", TEST_NAMESPACE]).or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    run_kubectl(
        &context,
        &[
            "-n",
            TEST_NAMESPACE,
            "create",
            "serviceaccount",
            TEST_SERVICE_ACCOUNT,
        ],
    )
    .or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    run_kubectl(
        &context,
        &[
            "create",
            "clusterrolebinding",
            "neuwerk-e2e-resolver-binding",
            "--clusterrole=cluster-admin",
            &format!(
                "--serviceaccount={}:{}",
                TEST_NAMESPACE, TEST_SERVICE_ACCOUNT
            ),
        ],
    )
    .or_else(|err| {
        if err.contains("AlreadyExists") {
            Ok(String::new())
        } else {
            Err(err)
        }
    })?;
    let token = run_kubectl(
        &context,
        &[
            "-n",
            TEST_NAMESPACE,
            "create",
            "token",
            TEST_SERVICE_ACCOUNT,
            "--duration=2h",
        ],
    )?;

    let kubeconfig = run_cmd("kind", &["get", "kubeconfig", "--name", cluster_name])?;
    let value: serde_yaml::Value = serde_yaml::from_str(&kubeconfig)
        .map_err(|err| format!("invalid kubeconfig yaml: {err}"))?;
    let cluster = value
        .get("clusters")
        .and_then(|clusters| clusters.as_sequence())
        .and_then(|clusters| clusters.first())
        .and_then(|entry| entry.get("cluster"))
        .ok_or_else(|| "kubeconfig missing clusters[0].cluster".to_string())?;
    let server = cluster
        .get("server")
        .and_then(|server| server.as_str())
        .ok_or_else(|| "kubeconfig missing server".to_string())?
        .to_string();
    let ca_data = cluster
        .get("certificate-authority-data")
        .and_then(|ca| ca.as_str())
        .ok_or_else(|| "kubeconfig missing certificate-authority-data".to_string())?;
    let ca_pem = BASE64_STANDARD
        .decode(ca_data.trim())
        .map_err(|err| format!("invalid certificate-authority-data: {err}"))?;
    let ca_pem = String::from_utf8(ca_pem).map_err(|err| format!("invalid ca pem utf8: {err}"))?;

    Ok(KindApiConfig {
        context,
        server,
        ca_pem,
        token: token.trim().to_string(),
    })
}

fn first_node_name(context: &str) -> Result<String, String> {
    let output = run_kubectl(context, &["get", "nodes", "-o", "json"])?;
    let value: serde_json::Value =
        serde_json::from_str(&output).map_err(|err| format!("invalid nodes json: {err}"))?;
    let name = value
        .get("items")
        .and_then(|items| items.as_array())
        .and_then(|items| items.first())
        .and_then(|item| item.get("metadata"))
        .and_then(|meta| meta.get("name"))
        .and_then(|name| name.as_str())
        .ok_or_else(|| "no nodes found".to_string())?;
    Ok(name.to_string())
}

fn create_pod(
    context: &str,
    namespace: &str,
    pod_name: &str,
    labels: &[(&str, &str)],
) -> Result<(), String> {
    let mut args = vec![
        "-n",
        namespace,
        "run",
        pod_name,
        "--image",
        POD_IMAGE,
        "--restart=Never",
    ];
    let labels_arg = labels
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(",");
    if !labels_arg.is_empty() {
        args.push("--labels");
        args.push(labels_arg.as_str());
    }
    run_kubectl(context, &args)?;
    Ok(())
}

fn delete_pod(context: &str, namespace: &str, pod_name: &str) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "delete",
            "pod",
            pod_name,
            "--ignore-not-found=true",
            "--wait=true",
            "--timeout=60s",
        ],
    )?;
    Ok(())
}

fn label_pod(
    context: &str,
    namespace: &str,
    pod_name: &str,
    key: &str,
    value: &str,
) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "label",
            "pod",
            pod_name,
            &format!("{key}={value}"),
            "--overwrite",
        ],
    )?;
    Ok(())
}

fn remove_pod_label(
    context: &str,
    namespace: &str,
    pod_name: &str,
    key: &str,
) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "-n",
            namespace,
            "label",
            "pod",
            pod_name,
            &format!("{key}-"),
        ],
    )?;
    Ok(())
}

fn label_node(context: &str, node_name: &str, key: &str, value: &str) -> Result<(), String> {
    run_kubectl(
        context,
        &[
            "label",
            "node",
            node_name,
            &format!("{key}={value}"),
            "--overwrite",
        ],
    )?;
    Ok(())
}

fn remove_node_label(context: &str, node_name: &str, key: &str) -> Result<(), String> {
    run_kubectl(context, &["label", "node", node_name, &format!("{key}-")])?;
    Ok(())
}

fn cleanup_labels(context: &str, namespace: &str, pod_name: &str, node_name: &str) {
    let labels = [
        LABEL_POD_BASE_KEY,
        LABEL_STALE_KEY,
        LABEL_NAMESPACE_KEY,
        LABEL_UNION_KEY,
        LABEL_UNION_EXTRA_KEY,
        LABEL_PRIORITY_KEY,
        LABEL_CHURN_POD_KEY,
    ];
    for key in labels {
        let _ = remove_pod_label(context, namespace, pod_name, key);
    }
    let node_labels = [
        LABEL_NODE_BASE_KEY,
        LABEL_UNION_NODE_KEY,
        LABEL_CHURN_NODE_KEY,
    ];
    for key in node_labels {
        let _ = remove_node_label(context, node_name, key);
    }
}

fn current_dynamic_ips(policy_store: &PolicyStore) -> BTreeSet<Ipv4Addr> {
    policy_store
        .kubernetes_bindings()
        .into_iter()
        .next()
        .map(|binding| {
            binding
                .dynamic_set
                .ips()
                .into_iter()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
}

async fn wait_for_binding_count(
    policy_store: &PolicyStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if policy_store.kubernetes_bindings().len() == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {expected} kubernetes bindings (current={})",
                policy_store.kubernetes_bindings().len()
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn wait_for_dynamic_ip_count(
    policy_store: &PolicyStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let count = current_dynamic_ips(policy_store).len();
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ip count {expected} (current={count})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_any_dynamic_ip(
    policy_store: &PolicyStore,
    timeout: Duration,
) -> Result<Ipv4Addr, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(ip) = current_dynamic_ips(policy_store).into_iter().next() {
            return Ok(ip);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for any dynamic ip".to_string());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_dynamic_ips_exact(
    policy_store: &PolicyStore,
    expected: BTreeSet<Ipv4Addr>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let ips = current_dynamic_ips(policy_store);
        if ips == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ips {expected:?} (current={ips:?})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_dynamic_ips_contains(
    policy_store: &PolicyStore,
    expected_ip: Ipv4Addr,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let ips = current_dynamic_ips(policy_store);
        if ips.contains(&expected_ip) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ip {expected_ip} (current={ips:?})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

async fn wait_for_pod_ip(
    context: &str,
    namespace: &str,
    pod_name: &str,
    timeout: Duration,
) -> Result<Ipv4Addr, String> {
    let deadline = Instant::now() + timeout;
    loop {
        let output = run_kubectl(
            context,
            &["-n", namespace, "get", "pod", pod_name, "-o", "json"],
        )?;
        let value: serde_json::Value = serde_json::from_str(&output)
            .map_err(|err| format!("invalid pod json for {pod_name}: {err}"))?;
        if let Some(ip) = value
            .get("status")
            .and_then(|status| status.get("podIP"))
            .and_then(|ip| ip.as_str())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        {
            return Ok(ip);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for pod ip: {namespace}/{pod_name}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn assert_action(label: &str, got: Action, expected: Action) -> Result<(), String> {
    if got == expected {
        Ok(())
    } else {
        Err(format!(
            "{} mismatch: expected {:?}, got {:?}",
            label, expected, got
        ))
    }
}

fn evaluate_packet(
    policy: &Arc<RwLock<PolicySnapshot>>,
    src_ip: Ipv4Addr,
    src_port: u16,
) -> Action {
    let mut state = EngineState::new(policy.clone(), src_ip, 32, Ipv4Addr::new(203, 0, 113, 1), 0);
    set_dataplane_ip(&mut state, src_ip);
    let mut packet = build_ipv4_udp(
        src_ip,
        Ipv4Addr::new(198, 51, 100, 10),
        src_port,
        8080,
        b"kind-e2e",
    );
    handle_packet(&mut packet, &mut state)
}

fn set_dataplane_ip(state: &mut EngineState, ip: Ipv4Addr) {
    state.dataplane_config.set(DataplaneConfig {
        ip,
        prefix: 32,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0; 6],
        lease_expiry: None,
    });
}

fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Packet {
    let total_len = 20 + 8 + payload.len();
    let mut buf = vec![0u8; total_len];
    buf[0] = 0x45;
    buf[1] = 0;
    buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&0u16.to_be_bytes());
    buf[6..8].copy_from_slice(&0u16.to_be_bytes());
    buf[8] = 64;
    buf[9] = 17;
    buf[10..12].copy_from_slice(&0u16.to_be_bytes());
    buf[12..16].copy_from_slice(&src_ip.octets());
    buf[16..20].copy_from_slice(&dst_ip.octets());

    let l4_off = 20;
    buf[l4_off..l4_off + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[l4_off + 2..l4_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[l4_off + 4..l4_off + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[l4_off + 6..l4_off + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[l4_off + 8..].copy_from_slice(payload);

    let mut pkt = Packet::new(buf);
    pkt.recalc_checksums();
    pkt
}

fn run_kubectl(context: &str, args: &[&str]) -> Result<String, String> {
    let mut full_args = Vec::with_capacity(args.len() + 2);
    full_args.push("--context");
    full_args.push(context);
    full_args.extend_from_slice(args);
    run_cmd("kubectl", &full_args)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| format!("{cmd} execution failed: {err}"))?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "{cmd} {:?} failed with status {}:\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
