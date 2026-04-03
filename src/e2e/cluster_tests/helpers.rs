use super::*;

pub(super) fn mock_ca_pem() -> Result<String, String> {
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = rcgen::Certificate::from_params(params)
        .map_err(|err| format!("mock ca generation failed: {err}"))?;
    cert.serialize_pem()
        .map_err(|err| format!("mock ca pem serialization failed: {err}"))
}

pub(super) async fn wait_for_binding_count(
    policy_store: &PolicyStore,
    expected: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let count = policy_store.kubernetes_bindings().len();
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for kubernetes bindings count {expected}, current={count}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn wait_for_dynamic_ips_exact(
    policy_store: &PolicyStore,
    expected: BTreeSet<Ipv4Addr>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let current = current_dynamic_ips(policy_store);
        if current == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for dynamic ips {expected:?}, current={current:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) fn current_dynamic_ips(policy_store: &PolicyStore) -> BTreeSet<Ipv4Addr> {
    policy_store
        .kubernetes_bindings()
        .into_iter()
        .next()
        .map(|binding| binding.dynamic_set.ips().into_iter().collect())
        .unwrap_or_default()
}

pub(super) fn evaluate_udp_8080(
    policy_store: &PolicyStore,
    src_ip: Ipv4Addr,
    src_port: u16,
) -> Action {
    let policy = policy_store.snapshot();
    let mut state = EngineState::new(policy.clone(), src_ip, 32, Ipv4Addr::new(203, 0, 113, 1), 0);
    state.dataplane_config.set(DataplaneConfig {
        ip: src_ip,
        prefix: 32,
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        mac: [0; 6],
        lease_expiry: None,
    });
    let mut packet = build_ipv4_udp_packet(
        src_ip,
        Ipv4Addr::new(198, 51, 100, 10),
        src_port,
        8080,
        b"cluster-k8s-failover",
    );
    handle_packet(&mut packet, &mut state)
}

pub(super) fn build_ipv4_udp_packet(
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

    let udp_offset = 20;
    buf[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    buf[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    let udp_len = (8 + payload.len()) as u16;
    buf[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());
    buf[udp_offset + 6..udp_offset + 8].copy_from_slice(&0u16.to_be_bytes());
    buf[udp_offset + 8..].copy_from_slice(payload);

    let mut packet = Packet::new(buf);
    packet.recalc_checksums();
    packet
}

pub(super) fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(super) fn create_temp_dir(label: &str) -> Result<PathBuf, String> {
    let base = std::env::temp_dir().join(format!("neuwerk-e2e-{}-{}", label, uuid::Uuid::new_v4()));
    fs::create_dir_all(&base).map_err(|e| format!("temp dir create failed: {e}"))?;
    Ok(base)
}

pub(super) fn write_token_file(path: &Path) -> Result<(), String> {
    let json = serde_json::json!({
        "tokens": [
            {
                "kid": "test",
                "token": "b64:dGVzdC1zZWNyZXQ=",
                "valid_until": "2027-01-01T00:00:00Z"
            }
        ]
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&json).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("write token file failed: {e}"))?;
    #[cfg(unix)]
    {
        let perms = <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600);
        fs::set_permissions(path, perms)
            .map_err(|e| format!("set token file permissions failed: {e}"))?;
    }
    Ok(())
}

pub(super) fn next_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

pub(super) fn base_config(data_dir: &Path, token_path: &Path) -> ClusterConfig {
    let mut cfg = ClusterConfig::disabled();
    cfg.enabled = true;
    cfg.data_dir = data_dir.to_path_buf();
    cfg.token_path = token_path.to_path_buf();
    cfg.node_id_path = data_dir.join("node_id");
    cfg
}

pub(super) fn next_addr_on(ip: Ipv4Addr) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    addr
}

pub(super) fn next_port_on(ip: Ipv4Addr) -> u16 {
    let listener = TcpListener::bind((ip, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    port
}

pub(super) fn load_node_id(dir: &Path) -> Result<u128, String> {
    let raw =
        fs::read_to_string(dir.join("node_id")).map_err(|e| format!("read node id failed: {e}"))?;
    let id = uuid::Uuid::parse_str(raw.trim()).map_err(|e| format!("parse node id failed: {e}"))?;
    Ok(id.as_u128())
}

pub(super) fn load_node_uuid(dir: &Path) -> Result<uuid::Uuid, String> {
    let raw =
        fs::read_to_string(dir.join("node_id")).map_err(|e| format!("read node id failed: {e}"))?;
    uuid::Uuid::parse_str(raw.trim()).map_err(|e| format!("parse node id failed: {e}"))
}

pub(super) async fn wait_for_voter(
    raft: &openraft::Raft<ClusterTypeConfig>,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.membership_config
            .membership()
            .voter_ids()
            .any(|id| id == node_id)
        {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for voter membership".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

pub(super) async fn wait_for_no_leader(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.current_leader.is_none() {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for leader loss".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

pub(super) async fn wait_for_stable_membership(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<(), String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if m.membership_config.membership().get_joint_config().len() == 1 {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for stable membership".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

pub(super) async fn wait_for_leader(
    raft: &openraft::Raft<ClusterTypeConfig>,
    timeout: Duration,
) -> Result<u128, String> {
    let mut metrics = raft.metrics();
    let deadline = Instant::now() + timeout;
    loop {
        let m: RaftMetrics<u128, openraft::BasicNode> = metrics.borrow().clone();
        if let Some(leader) = m.current_leader {
            return Ok(leader);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("timed out waiting for leader".to_string());
        }
        let remaining = deadline - now;
        tokio::time::timeout(remaining, metrics.changed())
            .await
            .map_err(|_| "metrics wait timeout".to_string())?
            .map_err(|_| "metrics channel closed".to_string())?;
    }
}

pub(super) async fn wait_for_new_leader(
    rafts: [&openraft::Raft<ClusterTypeConfig>; 2],
    old_leader: u128,
    timeout: Duration,
) -> Result<u128, String> {
    let deadline = Instant::now() + timeout;
    loop {
        for raft in rafts {
            let m = raft.metrics().borrow().clone();
            if let Some(leader) = m.current_leader {
                if leader != old_leader {
                    return Ok(leader);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for new leader".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn wait_for_envelope(
    store: &ClusterStore,
    node_id: u128,
    timeout: Duration,
) -> Result<(), String> {
    let key = format!("ca/envelope/{node_id}").into_bytes();
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(&key)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for ca envelope".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn wait_for_state_value(
    store: &ClusterStore,
    key: &[u8],
    expected: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = store.get_state_value(key)? {
            if value == expected {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state value".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn wait_for_state_present(
    store: &ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(key)?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state key".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) fn mint_auth_token(store: &ClusterStore) -> Result<String, String> {
    let keyset = api_auth::load_keyset_from_store(store)?
        .ok_or_else(|| "missing api auth keyset".to_string())?;
    let token = api_auth::mint_token(&keyset, "e2e-cluster", None, None)?;
    Ok(token.token)
}

pub(super) async fn wait_for_state_absent(
    store: &ClusterStore,
    key: &[u8],
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if store.get_state_value(key)?.is_none() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for state key removal".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) fn sample_policy(rule_id: &str) -> Result<PolicyConfig, String> {
    let yaml = format!(
        r#"default_policy: deny
source_groups:
  - id: "client-primary"
    mode: enforce
    sources:
      ips: ["192.0.2.2"]
    rules:
      - id: "{rule_id}"
        action: allow
        match:
          dns_hostname: '^foo\.allowed$'
"#
    );
    serde_yaml::from_str(&yaml).map_err(|e| format!("policy yaml error: {e}"))
}

pub(super) fn seed_local_policy(
    store: &PolicyDiskStore,
    mode: PolicyMode,
) -> Result<PolicyRecord, String> {
    let policy = sample_policy("migration-rule")?;
    let record = PolicyRecord::new(mode, policy, None)?;
    store
        .write_record(&record)
        .map_err(|err| format!("local policy write failed: {err}"))?;
    if mode.is_active() {
        store
            .set_active(Some(record.id))
            .map_err(|err| format!("local policy active write failed: {err}"))?;
    }
    Ok(record)
}

pub(super) fn seed_local_service_accounts(dir: &Path) -> Result<Vec<ServiceAccount>, String> {
    let store = ServiceAccountDiskStore::new(dir.to_path_buf());
    let mut accounts = Vec::new();

    let account = ServiceAccount::new(
        "svc-primary".to_string(),
        Some("primary account".to_string()),
        "migration-test".to_string(),
    )?;
    store
        .write_account(&account)
        .map_err(|err| format!("write account failed: {err}"))?;
    let token = TokenMeta::new(
        account.id,
        Some("primary-token".to_string()),
        "migration-test".to_string(),
        "kid-1".to_string(),
        None,
        uuid::Uuid::new_v4(),
    )?;
    store
        .write_token(&token)
        .map_err(|err| format!("write token failed: {err}"))?;
    accounts.push(account);

    let mut account_disabled = ServiceAccount::new(
        "svc-disabled".to_string(),
        None,
        "migration-test".to_string(),
    )?;
    account_disabled.status = ServiceAccountStatus::Disabled;
    store
        .write_account(&account_disabled)
        .map_err(|err| format!("write disabled account failed: {err}"))?;
    let mut token_revoked = TokenMeta::new(
        account_disabled.id,
        Some("revoked-token".to_string()),
        "migration-test".to_string(),
        "kid-2".to_string(),
        None,
        uuid::Uuid::new_v4(),
    )?;
    token_revoked.status = TokenStatus::Revoked;
    token_revoked.revoked_at = Some(
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc().unix_timestamp().to_string()),
    );
    store
        .write_token(&token_revoked)
        .map_err(|err| format!("write revoked token failed: {err}"))?;
    accounts.push(account_disabled);

    Ok(accounts)
}

pub(super) fn seed_local_intercept_ca(tls_dir: &Path) -> Result<(), String> {
    let ca_cert_path = tls_dir.join("ca.crt");
    let ca_key_path = tls_dir.join("ca.key");
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        return Err("http tls ca cert/key missing while seeding intercept ca".to_string());
    }
    let (intercept_cert_path, intercept_key_path) = local_intercept_ca_paths(tls_dir);
    let cert = fs::read(&ca_cert_path).map_err(|err| format!("read ca cert failed: {err}"))?;
    let key = fs::read(&ca_key_path).map_err(|err| format!("read ca key failed: {err}"))?;
    fs::write(&intercept_cert_path, cert)
        .map_err(|err| format!("write intercept ca cert failed: {err}"))?;
    fs::write(&intercept_key_path, key)
        .map_err(|err| format!("write intercept ca key failed: {err}"))?;
    Ok(())
}

pub(super) fn keysets_equivalent(left: &api_auth::ApiKeySet, right: &api_auth::ApiKeySet) -> bool {
    if left.active_kid != right.active_kid {
        return false;
    }
    if left.keys.len() != right.keys.len() {
        return false;
    }
    left.keys.iter().zip(right.keys.iter()).all(|(l, r)| {
        l.kid == r.kid
            && l.public_key == r.public_key
            && l.private_key == r.private_key
            && l.created_at == r.created_at
            && l.status == r.status
    })
}

pub(super) fn regenerate_local_keyset(tls_dir: &Path) -> Result<(), String> {
    let path = api_auth::local_keyset_path(tls_dir);
    if path.exists() {
        fs::remove_file(&path).map_err(|err| format!("remove keyset failed: {err}"))?;
    }
    api_auth::ensure_local_keyset(tls_dir).map_err(|err| format!("ensure keyset failed: {err}"))?;
    Ok(())
}

pub(super) fn spawn_http_api(
    bind_addr: SocketAddr,
    metrics_bind: SocketAddr,
    tls_dir: PathBuf,
    local_policy_dir: PathBuf,
    token_path: PathBuf,
    cluster: Option<HttpApiCluster>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    spawn_http_api_with_audit(
        bind_addr,
        metrics_bind,
        tls_dir,
        local_policy_dir,
        token_path,
        cluster,
        None,
    )
}

pub(super) fn spawn_http_api_with_audit(
    bind_addr: SocketAddr,
    metrics_bind: SocketAddr,
    tls_dir: PathBuf,
    local_policy_dir: PathBuf,
    token_path: PathBuf,
    cluster: Option<HttpApiCluster>,
    audit_store: Option<AuditStore>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_policy_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind,
        allow_public_metrics_bind: false,
        tls_dir,
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: bind_addr.ip(),
        token_path,
        external_url: None,
        cluster_tls_dir: None,
        cluster_membership_min_voters: 3,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().map_err(|err| format!("metrics init failed: {err}"))?;
    Ok(tokio::spawn(async move {
        let _ = run_http_api(
            cfg,
            policy_store,
            local_store,
            cluster,
            audit_store,
            None,
            None,
            None,
            metrics,
        )
        .await;
    }))
}

pub(super) fn http_api_client(tls_dir: &Path) -> Result<Client, String> {
    let ca =
        fs::read(tls_dir.join("ca.crt")).map_err(|e| format!("read http ca cert failed: {e}"))?;
    let ca = ReqwestCertificate::from_pem(&ca).map_err(|e| format!("invalid http ca cert: {e}"))?;
    Client::builder()
        .add_root_certificate(ca)
        .build()
        .map_err(|e| format!("http client build failed: {e}"))
}

pub(super) async fn http_wait_for_health(
    addr: SocketAddr,
    tls_dir: &Path,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match http_api_status(addr, tls_dir, "/health", None).await {
            Ok(status) if status.is_success() => return Ok(()),
            Ok(_) | Err(_) => {}
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for http api health".to_string());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub(super) async fn http_api_status(
    addr: SocketAddr,
    tls_dir: &Path,
    path: &str,
    auth_token: Option<&str>,
) -> Result<reqwest::StatusCode, String> {
    let client = http_api_client(tls_dir)?;
    let mut req = client.get(format!("https://{addr}{path}"));
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("http request failed: {e}"))?;
    Ok(resp.status())
}

pub(super) async fn http_set_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    policy: PolicyConfig,
    _mode: PolicyMode,
    auth_token: Option<&str>,
) -> Result<PolicyConfig, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.put(format!("https://{addr}/api/v1/policy")).json(&policy);
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy put failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy put status {}", resp.status()));
    }
    resp.json::<PolicyConfig>()
        .await
        .map_err(|e| format!("policy decode failed: {e}"))
}

pub(super) async fn http_get_policy(
    addr: SocketAddr,
    tls_dir: &Path,
    auth_token: Option<&str>,
) -> Result<PolicyConfig, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/policy"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("policy list failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("policy get status {}", resp.status()));
    }
    resp.json::<PolicyConfig>()
        .await
        .map_err(|e| format!("policy get decode failed: {e}"))
}

pub(super) async fn http_get_audit_findings(
    addr: SocketAddr,
    tls_dir: &Path,
    query: &str,
    auth_token: Option<&str>,
) -> Result<AuditQueryResponse, String> {
    let client = http_api_client(tls_dir)?;
    let mut builder = client.get(format!("https://{addr}/api/v1/audit/findings?{query}"));
    if let Some(token) = auth_token {
        builder = builder.bearer_auth(token);
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| format!("audit query failed: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("audit query status {status}: {body}"));
    }
    resp.json::<AuditQueryResponse>()
        .await
        .map_err(|e| format!("audit query decode failed: {e}"))
}
