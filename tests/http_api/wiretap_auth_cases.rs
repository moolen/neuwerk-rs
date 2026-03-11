use super::*;

#[tokio::test]
async fn http_api_wiretap_stream_local_cookie_auth_emits_events() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let login_resp = client
        .post(format!("https://{bind_addr}/api/v1/auth/token-login"))
        .json(&serde_json::json!({ "token": token.token }))
        .send()
        .await
        .unwrap();
    assert!(login_resp.status().is_success());
    let set_cookie = login_resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("missing set-cookie");
    let cookie = set_cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("neuwerk_auth="));

    let resp = client
        .get(format!("https://{bind_addr}/api/v1/wiretap/stream"))
        .header(reqwest::header::COOKIE, cookie)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(content_type.contains("text/event-stream"));

    let mut stream = resp.bytes_stream();
    let read_handle = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut buf = String::new();
        while Instant::now() < deadline {
            let timeout = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(timeout, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    buf.push_str(&String::from_utf8_lossy(&chunk));
                    if buf.contains("event: flow") && buf.contains("local-flow") {
                        return Ok::<(), String>(());
                    }
                }
                Ok(Some(Err(err))) => return Err(format!("stream error: {err}")),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Err(format!(
            "wiretap stream missing expected event payload: {buf}"
        ))
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    wiretap_hub.publish(WiretapEvent {
        event_type: WiretapEventType::Flow,
        flow_id: "local-flow".to_string(),
        src_ip: Ipv4Addr::new(10, 0, 0, 9),
        dst_ip: Ipv4Addr::new(198, 51, 100, 42),
        src_port: 45678,
        dst_port: 443,
        proto: 6,
        packets_in: 0,
        packets_out: 1,
        last_seen: 1,
        hostname: Some("api.example.com".to_string()),
        node_id: "node-local".to_string(),
    });

    match read_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err}"),
        Err(err) => panic!("wiretap stream task failed: {err}"),
    }

    server.abort();
}

#[tokio::test]
async fn http_api_wiretap_stream_local_query_token_is_rejected() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/wiretap/stream?access_token={}",
            token.token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    server.abort();
}

#[tokio::test]
async fn http_api_query_token_auth_is_wiretap_only() {
    ensure_rustls_provider();
    let dir = TempDir::new().unwrap();
    let tls_dir = dir.path().join("http-tls");
    let local_store_dir = dir.path().join("policies");
    let bind_addr = next_addr(Ipv4Addr::LOCALHOST);
    let metrics_addr = next_addr(Ipv4Addr::LOCALHOST);
    let wiretap_hub = WiretapHub::new(32);
    let server_wiretap_hub = wiretap_hub.clone();

    let policy_store = PolicyStore::new(DefaultPolicy::Deny, Ipv4Addr::new(10, 0, 0, 0), 24);
    let local_store = PolicyDiskStore::new(local_store_dir);
    let cfg = HttpApiConfig {
        bind_addr,
        advertise_addr: bind_addr,
        metrics_bind: metrics_addr,
        tls_dir: tls_dir.clone(),
        cert_path: None,
        key_path: None,
        ca_path: None,
        san_entries: Vec::new(),
        management_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        token_path: dir.path().join("token.json"),
        external_url: None,
        cluster_tls_dir: None,
        tls_intercept_ca_ready: None,
        tls_intercept_ca_generation: None,
    };
    let metrics = Metrics::new().unwrap();

    let server = tokio::spawn(async move {
        http_api::run_http_api(
            cfg,
            policy_store,
            local_store,
            None,
            None,
            Some(server_wiretap_hub),
            None,
            None,
            metrics,
        )
        .await
        .map_err(|err| format!("http api error: {err}"))
    });

    wait_for_file(&tls_dir.join("ca.crt"), Duration::from_secs(2))
        .await
        .unwrap();
    wait_for_tcp(bind_addr, Duration::from_secs(2))
        .await
        .unwrap();
    let auth_path = api_auth::local_keyset_path(&tls_dir);
    wait_for_file(&auth_path, Duration::from_secs(2))
        .await
        .unwrap();
    let keyset = api_auth::load_keyset_from_file(&auth_path)
        .unwrap()
        .expect("missing local api keyset");
    let token = api_auth::mint_token(&keyset, "wiretap-ui-test", None, None).unwrap();

    let client = http_api_client(&tls_dir).unwrap();
    let resp = client
        .get(format!(
            "https://{bind_addr}/api/v1/policies?access_token={}",
            token.token
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    server.abort();
}
