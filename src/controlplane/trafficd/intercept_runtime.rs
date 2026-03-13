fn build_intercept_listener(bind_addr: SocketAddr) -> Result<TcpListener, String> {
    let socket = match bind_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(|err| format!("trafficd tls intercept socket create failed: {err}"))?;
    socket
        .set_reuseaddr(true)
        .map_err(|err| format!("trafficd tls intercept reuseaddr setup failed: {err}"))?;

    socket
        .bind(bind_addr)
        .map_err(|err| format!("trafficd tls intercept bind failed: {err}"))?;
    socket
        .listen(tls_intercept_listen_backlog())
        .map_err(|err| format!("trafficd tls intercept listen failed: {err}"))
}

fn classify_tls_intercept_error(err: &str) -> (&'static str, &'static str) {
    let stage = if err.contains("client tls handshake") {
        "client_tls_accept"
    } else if err.contains("client request read") {
        "http1_request_read"
    } else if err.contains("upstream response read") {
        "http1_response_read"
    } else if err.contains("upstream tcp connect") {
        "upstream_tcp_connect"
    } else if err.contains("upstream tls connect") {
        "upstream_tls_handshake"
    } else if err.contains("h2 upstream handshake") {
        "upstream_h2_handshake"
    } else if err.contains("h2 upstream ready") {
        "upstream_h2_ready"
    } else if err.contains("h2 upstream send") {
        "upstream_h2_send"
    } else if err.contains("h2 upstream response") {
        "upstream_response"
    } else if err.contains("h2 upstream body send") {
        "upstream_body_send"
    } else if err.contains("h2 upstream body read") {
        "upstream_body_read"
    } else if err.contains("h2 request body") {
        "h2_request_body_read"
    } else if err.contains("h2 server handshake") {
        "h2_server_handshake"
    } else if err.contains("h2 client request")
        || err.contains("h2 accept failed")
        || err.contains("h2 client closed before request")
    {
        "h2_client_accept"
    } else if err.contains("client write") {
        "client_write"
    } else {
        "other"
    };

    let lower = err.to_ascii_lowercase();
    let reason = if lower.contains("timed out") {
        "timeout"
    } else if lower.contains("exceeds max size") {
        "oversize"
    } else if lower.contains("request denied by policy") || lower.contains("response denied by policy") {
        "policy"
    } else if lower.contains("no matching intercept rule") {
        "no_policy"
    } else if lower.contains("closed") || lower.contains("eof") {
        "closed"
    } else if lower.contains("invalid") || lower.contains("unsupported") {
        "invalid"
    } else {
        "failure"
    };

    (stage, reason)
}

fn record_tls_intercept_connection_error(metrics: &Metrics, err: &str) {
    let (stage, reason) = classify_tls_intercept_error(err);
    metrics.inc_svc_tls_intercept_error(stage, reason);
}

fn is_benign_h2_response_body_termination(err: &h2::Error) -> bool {
    matches!(err.reason(), Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL))
        || err
            .to_string()
            .contains("stream no longer needed")
}

pub async fn run_tls_intercept_runtime(cfg: TlsInterceptRuntimeConfig) -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let acceptor = build_tls_intercept_acceptor(
        &cfg.intercept_ca_cert_pem,
        &cfg.intercept_ca_key_der,
        INTERCEPT_LEAF_CACHE_TTL,
        INTERCEPT_LEAF_CACHE_MAX_ENTRIES,
    )?;
    let verify_mode = if cfg.upstream_tls_insecure {
        upstream_tls::UpstreamTlsVerificationMode::Insecure
    } else {
        upstream_tls::UpstreamTlsVerificationMode::Strict
    };
    let connector_h1 = upstream_tls::build_tls_connector(Vec::new(), verify_mode)?;
    let connector_h2 = upstream_tls::build_tls_connector(vec![b"h2".to_vec()], verify_mode)?;
    let upstream_h2_pool: UpstreamH2Pool = Arc::new(AsyncMutex::new(HashMap::new()));
    let listener = build_intercept_listener(cfg.bind_addr)?;
    info!(
        bind_addr = %cfg.bind_addr,
        io_timeout_secs = tls_io_timeout().as_secs(),
        h2_body_idle_timeout_secs = tls_h2_body_idle_timeout().as_secs(),
        h2_max_concurrent_streams = tls_h2_max_concurrent_streams(),
        listen_backlog = tls_intercept_listen_backlog(),
        "trafficd tls intercept runtime configured"
    );

    if let Some(tx) = cfg.startup_status_tx {
        let _ = tx.send(Ok(()));
    }

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                warn!(error = %err, "trafficd tls intercept accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let connector_h1 = connector_h1.clone();
        let connector_h2 = connector_h2.clone();
        let upstream_h2_pool = upstream_h2_pool.clone();
        let metrics = cfg.metrics.clone();
        let policy_snapshot = cfg.policy_snapshot.clone();
        let intercept_demux = cfg.intercept_demux.clone();
        let upstream_override = cfg.upstream_override;
        tokio::spawn(async move {
            match std::panic::AssertUnwindSafe(handle_tls_intercept_client(
                stream,
                acceptor,
                connector_h1,
                connector_h2,
                upstream_h2_pool,
                metrics.clone(),
                policy_snapshot,
                intercept_demux,
                upstream_override,
            ))
            .catch_unwind()
            .await
            {
                Ok(Ok(())) => {
                    metrics.inc_svc_tls_intercept_flow("allow");
                }
                Ok(Err(err)) => {
                    metrics.inc_svc_tls_intercept_flow("deny");
                    record_tls_intercept_connection_error(&metrics, &err);
                    let lower = err.to_ascii_lowercase();
                    if lower.contains("timed out")
                        || lower.contains("failed")
                        || lower.contains("invalid")
                        || lower.contains("unsupported")
                        || lower.contains("no matching")
                    {
                        metrics.inc_svc_fail_closed("tls");
                    }
                    warn!(error = %err, "trafficd tls intercept connection error");
                }
                Err(_) => {
                    metrics.inc_svc_tls_intercept_flow("deny");
                    metrics.inc_svc_tls_intercept_error("runtime", "panic");
                    metrics.inc_svc_fail_closed("tls");
                    warn!("trafficd tls intercept task panicked");
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tls_intercept_client(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    connector_h1: TlsConnector,
    connector_h2: TlsConnector,
    upstream_h2_pool: UpstreamH2Pool,
    metrics: Metrics,
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let _connection_guard = InflightMetricGuard::new(&metrics, "connections");
    let peer_addr = stream
        .peer_addr()
        .map_err(|err| format!("tls intercept: peer addr unavailable: {err}"))?;
    let src_ip = match peer_addr.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return Err("tls intercept: ipv6 peers unsupported".to_string()),
    };
    let local_addr = stream
        .local_addr()
        .map_err(|err| format!("tls intercept: local addr unavailable: {err}"))?;
    let mut orig_dst = original_dst_addr(&stream).unwrap_or(local_addr);
    if orig_dst == local_addr {
        if let Some(mapped) =
            lookup_intercept_demux_original_dst(&intercept_demux, src_ip, peer_addr.port())
        {
            orig_dst = mapped;
        }
    }

    let mut policy = None;
    if let Ok(lock) = policy_snapshot.read() {
        let dst_ip = match orig_dst.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err("tls intercept: ipv6 destinations unsupported".to_string()),
        };
        let meta = PacketMeta {
            src_ip,
            dst_ip,
            proto: 6,
            src_port: peer_addr.port(),
            dst_port: orig_dst.port(),
            icmp_type: None,
            icmp_code: None,
        };
        policy = find_intercept_http_policy(&lock, &meta);
        if policy.is_none() && orig_dst == local_addr {
            if let Some(inferred_dst) = infer_intercept_original_dst(&lock, src_ip) {
                let inferred_meta = PacketMeta {
                    src_ip,
                    dst_ip: match inferred_dst.ip() {
                        IpAddr::V4(ip) => ip,
                        IpAddr::V6(_) => {
                            return Err("tls intercept: ipv6 destinations unsupported".to_string());
                        }
                    },
                    proto: 6,
                    src_port: peer_addr.port(),
                    dst_port: inferred_dst.port(),
                    icmp_type: None,
                    icmp_code: None,
                };
                if let Some(inferred_policy) = find_intercept_http_policy(&lock, &inferred_meta) {
                    orig_dst = inferred_dst;
                    policy = Some(inferred_policy);
                }
            }
        }
    }

    let Some(policy) = policy else {
        set_linger_rst(&stream);
        return Err("tls intercept: no matching intercept rule".to_string());
    };

    let client_tls_start = std::time::Instant::now();
    let mut client_tls = tokio::time::timeout(tls_io_timeout(), acceptor.accept(stream))
        .await
        .map_err(|_| "tls intercept: client tls handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: client tls handshake failed: {err}"))?;
    metrics.observe_svc_tls_intercept_phase("client_tls_accept", client_tls_start.elapsed());
    let client_alpn = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|value| value.to_vec());

    if client_alpn.as_deref() == Some(b"h2") {
        return handle_tls_intercept_h2(
            client_tls,
            connector_h2,
            upstream_h2_pool,
            metrics,
            policy.http_policy,
            policy.enforce_http_policy,
            orig_dst,
            upstream_override,
        )
        .await;
    }

    handle_tls_intercept_http1(
        &mut client_tls,
        connector_h1,
        &metrics,
        policy.http_policy,
        policy.enforce_http_policy,
        orig_dst,
        upstream_override,
    )
    .await
}

fn set_linger_rst(stream: &TcpStream) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let _ = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
    }
}

async fn connect_upstream_tls(
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    metrics: &Metrics,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let tcp_connect_start = std::time::Instant::now();
    let upstream_tcp = tokio::time::timeout(tls_io_timeout(), TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| "tls intercept: upstream tcp connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tcp connect failed: {err}"))?;
    metrics.observe_svc_tls_intercept_phase("upstream_tcp_connect", tcp_connect_start.elapsed());
    let server_name_raw = if host.is_empty() {
        upstream_addr.ip().to_string()
    } else {
        host.to_string()
    };
    let server_name = rustls::pki_types::ServerName::try_from(server_name_raw.clone())
        .map_err(|_| format!("tls intercept: invalid server name '{server_name_raw}'"))?;
    let tls_connect_start = std::time::Instant::now();
    let tls = tokio::time::timeout(tls_io_timeout(), connector.connect(server_name, upstream_tcp))
        .await
        .map_err(|_| "tls intercept: upstream tls connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tls connect failed: {err}"))?;
    metrics.observe_svc_tls_intercept_phase("upstream_tls_handshake", tls_connect_start.elapsed());
    Ok(tls)
}

async fn connect_upstream_h2_client(
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    metrics: &Metrics,
) -> Result<Arc<UpstreamH2Client>, String> {
    let upstream_tls = connect_upstream_tls(connector, upstream_addr, host, metrics).await?;
    let h2_handshake_start = std::time::Instant::now();
    let (send_request, upstream_conn) =
        tokio::time::timeout(tls_io_timeout(), client::handshake(upstream_tls))
            .await
            .map_err(|_| "tls intercept: h2 upstream handshake timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream handshake failed: {err}"))?;
    metrics.observe_svc_tls_intercept_phase("upstream_h2_handshake", h2_handshake_start.elapsed());
    let session_guard = InflightMetricGuard::new(metrics, "upstream_h2_sessions");
    tokio::spawn(async move {
        let _session_guard = session_guard;
        let _ = upstream_conn.await;
    });
    Ok(Arc::new(UpstreamH2Client {
        send_request: AsyncMutex::new(send_request),
        in_flight_streams: AtomicUsize::new(0),
    }))
}

fn remove_pooled_upstream_h2_client(
    pool: &mut HashMap<String, Vec<Arc<UpstreamH2Client>>>,
    pool_key: &str,
    client: &Arc<UpstreamH2Client>,
) {
    let mut remove_host = false;
    if let Some(clients) = pool.get_mut(pool_key) {
        clients.retain(|existing| !Arc::ptr_eq(existing, client));
        remove_host = clients.is_empty();
    }
    if remove_host {
        pool.remove(pool_key);
    }
}

async fn get_or_connect_upstream_h2_client(
    pool: &UpstreamH2Pool,
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    pool_key: &str,
    metrics: &Metrics,
) -> Result<(Arc<UpstreamH2Client>, UpstreamH2StreamGuard), String> {
    let mut lock = pool.lock().await;
    let max_streams_per_client = tls_h2_max_concurrent_streams() as usize;
    if let Some(existing) = lock
        .get(pool_key)
        .and_then(|clients| {
            clients
                .iter()
                .filter_map(|client| {
                    let in_flight = client.in_flight_streams.load(Ordering::Acquire);
                    (in_flight < max_streams_per_client).then_some((in_flight, client.clone()))
                })
                .min_by_key(|(in_flight, _)| *in_flight)
                .map(|(_, client)| client)
        })
    {
        metrics.inc_svc_tls_intercept_upstream_h2_pool("hit");
        let guard = UpstreamH2StreamGuard::new(existing.clone());
        return Ok((existing, guard));
    }

    let created = connect_upstream_h2_client(connector, upstream_addr, host, metrics).await?;
    metrics.inc_svc_tls_intercept_upstream_h2_pool("miss");
    lock.entry(pool_key.to_string())
        .or_default()
        .push(created.clone());
    let guard = UpstreamH2StreamGuard::new(created.clone());
    Ok((created, guard))
}

async fn send_upstream_h2_request(
    client: &Arc<UpstreamH2Client>,
    request: axum::http::Request<()>,
    end_of_stream: bool,
) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
    let mut send_request = client.send_request.lock().await;
    tokio::time::timeout(tls_io_timeout(), send_request.clone().ready())
        .await
        .map_err(|_| "tls intercept: h2 upstream ready timed out".to_string())?
        .map_err(|err| format!("tls intercept: h2 upstream ready failed: {err}"))?;
    send_request
        .send_request(request, end_of_stream)
        .map_err(|err| format!("tls intercept: h2 upstream send failed: {err}"))
}

async fn send_upstream_h2_request_via_pool(
    pool: &UpstreamH2Pool,
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    request: axum::http::Request<()>,
    end_of_stream: bool,
    metrics: &Metrics,
) -> Result<(
    UpstreamH2StreamGuard,
    h2::client::ResponseFuture,
    h2::SendStream<Bytes>,
), String> {
    let pool_key = format!("{host}@{upstream_addr}");
    let (client, guard) = get_or_connect_upstream_h2_client(
        pool,
        connector.clone(),
        upstream_addr,
        host,
        &pool_key,
        metrics,
    )
    .await?;
    match send_upstream_h2_request(&client, request.clone(), end_of_stream).await {
        Ok((response_fut, send_stream)) => Ok((guard, response_fut, send_stream)),
        Err(first_err) => {
            drop(guard);
            {
                let mut lock = pool.lock().await;
                remove_pooled_upstream_h2_client(&mut lock, &pool_key, &client);
            }
            metrics.inc_svc_tls_intercept_upstream_h2_pool("reconnect");
            let reconnected =
                connect_upstream_h2_client(connector, upstream_addr, host, metrics).await?;
            {
                let mut lock = pool.lock().await;
                lock.entry(pool_key)
                    .or_default()
                    .push(reconnected.clone());
            }
            let reconnect_guard = UpstreamH2StreamGuard::new(reconnected.clone());
            send_upstream_h2_request(&reconnected, request, end_of_stream)
                .await
                .map(|(response_fut, send_stream)| (reconnect_guard, response_fut, send_stream))
                .map_err(|retry_err| format!("{first_err}; retry failed: {retry_err}"))
        }
    }
}

async fn handle_tls_intercept_http1(
    client_tls: &mut tokio_rustls::server::TlsStream<TcpStream>,
    connector: TlsConnector,
    metrics: &Metrics,
    policy: Option<TlsInterceptHttpPolicy>,
    enforce_http_policy: bool,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let request_read_start = std::time::Instant::now();
    let req_bytes =
        tokio::time::timeout(tls_io_timeout(), http_match::read_http_message(client_tls))
            .await
            .map_err(|_| "tls intercept: client request read timed out".to_string())??;
    metrics.observe_svc_tls_intercept_phase("http1_request_read", request_read_start.elapsed());
    let request = http_match::parse_http_request(&req_bytes)?;

    let mut request_denied = false;
    if let Some(req_policy) = policy.as_ref().and_then(|policy| policy.request.as_ref()) {
        if !http_match::request_allowed(req_policy, &request) {
            request_denied = true;
            metrics.inc_svc_http_request("http1", "deny");
            metrics.inc_svc_http_deny("http1", "request", "policy");
            if enforce_http_policy {
                metrics.inc_svc_policy_rst("request_policy");
                metrics.inc_svc_fail_closed("tls");
                set_linger_rst(client_tls.get_mut().0);
                return Err("tls intercept: request denied by policy".to_string());
            }
        }
    }
    if !request_denied {
        metrics.inc_svc_http_request("http1", "allow");
    }

    let upstream_addr = upstream_override.unwrap_or(orig_dst);
    let mut upstream_tls =
        connect_upstream_tls(connector, upstream_addr, &request.host, metrics).await?;
    upstream_tls
        .write_all(&request.raw)
        .await
        .map_err(|err| format!("tls intercept: upstream write failed: {err}"))?;

    let response_read_start = std::time::Instant::now();
    let response_bytes = tokio::time::timeout(
        tls_io_timeout(),
        http_match::read_http_message(&mut upstream_tls),
    )
    .await
    .map_err(|_| "tls intercept: upstream response read timed out".to_string())??;
    metrics.observe_svc_tls_intercept_phase("http1_response_read", response_read_start.elapsed());
    let response = http_match::parse_http_response(&response_bytes)?;

    if let Some(resp_policy) = policy.as_ref().and_then(|policy| policy.response.as_ref()) {
        if !http_match::response_allowed(resp_policy, &response) {
            metrics.inc_svc_http_deny("http1", "response", "policy");
            if enforce_http_policy {
                metrics.inc_svc_policy_rst("response_policy");
                metrics.inc_svc_fail_closed("tls");
                set_linger_rst(client_tls.get_mut().0);
                return Err("tls intercept: response denied by policy".to_string());
            }
        }
    }

    client_tls
        .write_all(&response.raw)
        .await
        .map_err(|err| format!("tls intercept: client write failed: {err}"))?;
    client_tls
        .shutdown()
        .await
        .map_err(|err| format!("tls intercept: client shutdown failed: {err}"))?;
    Ok(())
}

#[cfg(test)]
async fn read_h2_request_body_with_conn_progress(
    client_conn: &mut server::Connection<tokio_rustls::server::TlsStream<TcpStream>, Bytes>,
    mut body: h2::RecvStream,
) -> Result<Vec<u8>, String> {
    enum ReadProgress {
        Continue,
        Done,
    }

    let mut out = Vec::new();
    let body_idle_timeout = tls_h2_body_idle_timeout();
    loop {
        let progress = match tokio::time::timeout(body_idle_timeout, async {
            tokio::select! {
                next = body.data() => {
                    match next {
                        Some(chunk) => {
                            let chunk = chunk.map_err(|err| {
                                format!("tls intercept: h2 request body read failed: {err}")
                            })?;
                            body.flow_control()
                                .release_capacity(chunk.len())
                                .map_err(|err| {
                                    format!(
                                        "tls intercept: h2 request body flow control release failed: {err}"
                                    )
                                })?;
                            out.extend_from_slice(&chunk);
                            if out.len() > http_match::HTTP_MAX_BODY_BYTES {
                                return Err("tls intercept: h2 request body exceeds max size".to_string());
                            }
                            Ok(ReadProgress::Continue)
                        }
                        None => Ok(ReadProgress::Done),
                    }
                }
                next = client_conn.accept() => {
                    match next {
                        Some(Ok((_request, mut respond))) => {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                            Ok(ReadProgress::Continue)
                        }
                        Some(Err(err)) => Err(format!(
                            "tls intercept: h2 client stream accept failed while reading request body: {err}"
                        )),
                        None => Err("tls intercept: h2 client closed while request body pending".to_string()),
                    }
                }
            }
        })
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(format!(
                    "tls intercept: h2 request body read timed out after {}s with {} bytes buffered",
                    body_idle_timeout.as_secs(),
                    out.len()
                ));
            }
        };

        if matches!(progress, ReadProgress::Done) {
            break;
        }
    }

    Ok(out)
}

#[cfg(test)]
async fn read_h2_request_body_with_timeout(
    mut body: h2::RecvStream,
    body_idle_timeout: Duration,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(next) = tokio::time::timeout(body_idle_timeout, body.data())
        .await
        .map_err(|_| {
            format!(
                "tls intercept: h2 request body read timed out after {}s with {} bytes buffered",
                body_idle_timeout.as_secs(),
                out.len()
            )
        })?
    {
        let chunk = next.map_err(|err| format!("tls intercept: h2 request body read failed: {err}"))?;
        out.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).map_err(|err| {
            format!("tls intercept: h2 request body flow control release failed: {err}")
        })?;
        if out.len() > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 request body exceeds max size".to_string());
        }
    }
    Ok(out)
}

async fn drain_h2_request_body(
    mut body: h2::RecvStream,
) -> Result<usize, String> {
    let body_idle_timeout = tls_h2_body_idle_timeout();
    let mut body_bytes = 0usize;
    while let Some(next) = tokio::time::timeout(body_idle_timeout, body.data())
        .await
        .map_err(|_| {
            format!(
                "tls intercept: h2 request body read timed out after {}s with {} bytes buffered",
                body_idle_timeout.as_secs(),
                body_bytes
            )
        })?
    {
        let chunk =
            next.map_err(|err| format!("tls intercept: h2 request body read failed: {err}"))?;
        let chunk_len = chunk.len();
        body_bytes = body_bytes.saturating_add(chunk_len);
        if body_bytes > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 request body exceeds max size".to_string());
        }
        body.flow_control().release_capacity(chunk_len).map_err(|err| {
            format!("tls intercept: h2 request body flow control release failed: {err}")
        })?;
    }

    Ok(body_bytes)
}

async fn await_h2_upstream_response(
    response_fut: std::pin::Pin<&mut h2::client::ResponseFuture>,
) -> Result<axum::http::Response<h2::RecvStream>, String> {
    tokio::time::timeout(tls_io_timeout(), response_fut)
        .await
        .map_err(|_| "tls intercept: h2 upstream response timed out".to_string())?
        .map_err(|err| format!("tls intercept: h2 upstream response failed: {err}"))
}

async fn forward_h2_request_body(
    mut body: h2::RecvStream,
    mut upstream_send_stream: h2::SendStream<Bytes>,
    response_fut: h2::client::ResponseFuture,
) -> Result<(usize, axum::http::Response<h2::RecvStream>), String> {
    let body_idle_timeout = tls_h2_body_idle_timeout();
    let mut body_bytes = 0usize;
    let mut response_fut = std::pin::pin!(response_fut);

    loop {
        tokio::select! {
            upstream_response = &mut response_fut => {
                let upstream_response = upstream_response
                    .map_err(|err| format!("tls intercept: h2 upstream response failed: {err}"))?;
                body_bytes = body_bytes.saturating_add(drain_h2_request_body(body).await?);
                return Ok((body_bytes, upstream_response));
            }
            next = tokio::time::timeout(body_idle_timeout, body.data()) => {
                let Some(next) = next
                    .map_err(|_| {
                        format!(
                            "tls intercept: h2 request body read timed out after {}s with {} bytes buffered",
                            body_idle_timeout.as_secs(),
                            body_bytes
                        )
                    })?
                else {
                    if body.is_end_stream() {
                        let upstream_response = await_h2_upstream_response(response_fut.as_mut()).await?;
                        return Ok((body_bytes, upstream_response));
                    }

                    upstream_send_stream
                        .send_data(Bytes::new(), true)
                        .map_err(|err| format!("tls intercept: h2 upstream body send failed: {err}"))?;
                    let upstream_response = await_h2_upstream_response(response_fut.as_mut()).await?;
                    return Ok((body_bytes, upstream_response));
                };
                let chunk =
                    next.map_err(|err| format!("tls intercept: h2 request body read failed: {err}"))?;
                let chunk_len = chunk.len();
                body_bytes = body_bytes.saturating_add(chunk_len);
                if body_bytes > http_match::HTTP_MAX_BODY_BYTES {
                    return Err("tls intercept: h2 request body exceeds max size".to_string());
                }

                let end_stream = body.is_end_stream();
                let send_result = upstream_send_stream.send_data(chunk, end_stream);
                body.flow_control().release_capacity(chunk_len).map_err(|err| {
                    format!("tls intercept: h2 request body flow control release failed: {err}")
                })?;

                match send_result {
                    Ok(()) => {
                        if end_stream {
                            let upstream_response = await_h2_upstream_response(response_fut.as_mut()).await?;
                            return Ok((body_bytes, upstream_response));
                        }
                    }
                    Err(err) => {
                        let err_string = err.to_string();
                        if err_string.contains("inactive stream") {
                            let upstream_response = await_h2_upstream_response(response_fut.as_mut()).await?;
                            body_bytes = body_bytes.saturating_add(drain_h2_request_body(body).await?);
                            return Ok((body_bytes, upstream_response));
                        }
                        return Err(format!("tls intercept: h2 upstream body send failed: {err}"));
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_tls_intercept_h2_stream(
    request: axum::http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    connector_h2: TlsConnector,
    upstream_pool: UpstreamH2Pool,
    metrics: Metrics,
    policy: Option<TlsInterceptHttpPolicy>,
    enforce_http_policy: bool,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let _stream_guard = InflightMetricGuard::new(&metrics, "h2_streams");
    let request_policy = policy.as_ref().and_then(|policy| policy.request.as_ref());
    let response_policy = policy.as_ref().and_then(|policy| policy.response.as_ref());
    let parsed_request = http_match::parsed_request_from_h2(
        &request,
        request_policy.and_then(|policy| policy.query.as_ref()).is_some(),
        request_policy.and_then(|policy| policy.headers.as_ref()).is_some(),
    );
    let request_body_end_stream = request.body().is_end_stream();
    let request_target = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    let mut request_denied = false;
    if let Some(req_policy) = request_policy {
        if !http_match::request_allowed(req_policy, &parsed_request) {
            request_denied = true;
            metrics.inc_svc_http_request("h2", "deny");
            metrics.inc_svc_http_deny("h2", "request", "policy");
            if enforce_http_policy {
                metrics.inc_svc_policy_rst("request_policy");
                metrics.inc_svc_fail_closed("tls");
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                return Ok(());
            }
        }
    }
    if !request_denied {
        metrics.inc_svc_http_request("h2", "allow");
    }

    let upstream_addr = upstream_override.unwrap_or(orig_dst);
    let upstream_host = if parsed_request.host.is_empty() {
        upstream_addr.ip().to_string()
    } else {
        parsed_request.host.clone()
    };
    let upstream_req = http_match::request_for_upstream_h2(
        &parsed_request.method,
        request_target,
        &upstream_host,
        request.headers(),
    )?;
    let (_upstream_stream_guard, response_fut, upstream_send_stream) =
        send_upstream_h2_request_via_pool(
            &upstream_pool,
            connector_h2,
            upstream_addr,
            &upstream_host,
            upstream_req,
            request_body_end_stream,
            &metrics,
        )
        .await?;
    let upstream_response = if !request_body_end_stream {
        let request_body_start = std::time::Instant::now();
        let (request_body_bytes, upstream_response) =
            forward_h2_request_body(request.into_body(), upstream_send_stream, response_fut).await?;
        metrics.observe_svc_tls_intercept_phase("h2_request_body_read", request_body_start.elapsed());
        if request_body_bytes > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 request body exceeds max size".to_string());
        }
        upstream_response
    } else {
        tokio::time::timeout(tls_io_timeout(), response_fut)
            .await
            .map_err(|_| "tls intercept: h2 upstream response timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream response failed: {err}"))?
    };
    let (upstream_parts, mut upstream_body) = upstream_response.into_parts();
    let upstream_header_response = Response::from_parts(upstream_parts, ());
    if let Some(resp_policy) = response_policy {
        let parsed_response = http_match::parsed_response_from_h2(&upstream_header_response, true);
        if !http_match::response_allowed(resp_policy, &parsed_response) {
            metrics.inc_svc_http_deny("h2", "response", "policy");
            if enforce_http_policy {
                metrics.inc_svc_policy_rst("response_policy");
                metrics.inc_svc_fail_closed("tls");
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                return Ok(());
            }
        }
    }

    let downstream_response = http_match::response_from_upstream_h2(&upstream_header_response)?;
    let downstream_end_stream = upstream_body.is_end_stream();
    let mut downstream_send = respond
        .send_response(downstream_response, downstream_end_stream)
        .map_err(|err| format!("tls intercept: h2 downstream send failed: {err}"))?;
    let mut downstream_stream_closed = downstream_end_stream;
    let body_idle_timeout = tls_h2_body_idle_timeout();
    let mut body_bytes = 0usize;
    while let Some(next) = tokio::time::timeout(body_idle_timeout, upstream_body.data())
        .await
        .map_err(|_| {
            format!(
                "tls intercept: h2 upstream body read timed out after {}s",
                body_idle_timeout.as_secs()
            )
        })?
    {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(err) if is_benign_h2_response_body_termination(&err) => break,
            Err(err) => {
                return Err(format!("tls intercept: h2 upstream body read failed: {err}"));
            }
        };
        body_bytes = body_bytes.saturating_add(chunk.len());
        upstream_body
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| {
                format!(
                    "tls intercept: h2 upstream body flow control release failed: {err}"
                )
            })?;
        if body_bytes > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 response body exceeds max size".to_string());
        }
        let end_stream = upstream_body.is_end_stream();
        downstream_send
            .send_data(chunk, end_stream)
            .map_err(|err| format!("tls intercept: h2 downstream body send failed: {err}"))?;
        downstream_stream_closed = end_stream;
    }
    if !downstream_stream_closed {
        downstream_send
            .send_data(Bytes::new(), true)
            .map_err(|err| format!("tls intercept: h2 downstream body send failed: {err}"))?;
    }
    Ok(())
}

async fn handle_tls_intercept_h2(
    client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    connector_h2: TlsConnector,
    upstream_pool: UpstreamH2Pool,
    metrics: Metrics,
    policy: Option<TlsInterceptHttpPolicy>,
    enforce_http_policy: bool,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    let mut h2_builder = server::Builder::new();
    h2_builder.max_concurrent_streams(tls_h2_max_concurrent_streams());
    let mut client_conn = tokio::time::timeout(tls_io_timeout(), h2_builder.handshake(client_tls))
        .await
        .map_err(|_| "tls intercept: h2 server handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: h2 server handshake failed: {err}"))?;
    let mut saw_request = false;
    let mut client_closed = false;
    let mut stream_tasks: tokio::task::JoinSet<Result<(), String>> = tokio::task::JoinSet::new();
    loop {
        if client_closed {
            match stream_tasks.join_next().await {
                Some(Ok(Ok(()))) => continue,
                Some(Ok(Err(err))) => return Err(err),
                Some(Err(err)) => {
                    return Err(format!("tls intercept: h2 stream task join failed: {err}"));
                }
                None => {
                    return if saw_request {
                        Ok(())
                    } else {
                        Err("tls intercept: h2 client closed before request".to_string())
                    };
                }
            }
        }

        if stream_tasks.is_empty() {
            let next = if saw_request {
                match tokio::time::timeout(tls_io_timeout(), client_conn.accept()).await {
                    Ok(next) => next,
                    Err(_) => {
                        client_conn.graceful_shutdown();
                        return Ok(());
                    }
                }
            } else {
                tokio::time::timeout(tls_io_timeout(), client_conn.accept())
                    .await
                    .map_err(|_| "tls intercept: h2 client request timed out".to_string())?
            };
            let Some(next) = next else {
                return if saw_request {
                    Ok(())
                } else {
                    Err("tls intercept: h2 client closed before request".to_string())
                };
            };
            let (request, respond) =
                next.map_err(|err| format!("tls intercept: h2 accept failed: {err}"))?;
            saw_request = true;
            stream_tasks.spawn(handle_tls_intercept_h2_stream(
                request,
                respond,
                connector_h2.clone(),
                upstream_pool.clone(),
                metrics.clone(),
                policy.clone(),
                enforce_http_policy,
                orig_dst,
                upstream_override,
            ));
            continue;
        }

        tokio::select! {
            joined = stream_tasks.join_next() => {
                match joined {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(err))) => return Err(err),
                    Some(Err(err)) => return Err(format!("tls intercept: h2 stream task join failed: {err}")),
                    None => {}
                }
            }
            next = client_conn.accept() => {
                match next {
                    Some(Ok((request, respond))) => {
                        saw_request = true;
                        stream_tasks.spawn(handle_tls_intercept_h2_stream(
                            request,
                            respond,
                            connector_h2.clone(),
                            upstream_pool.clone(),
                            metrics.clone(),
                            policy.clone(),
                            enforce_http_policy,
                            orig_dst,
                            upstream_override,
                        ));
                    }
                    Some(Err(err)) => return Err(format!("tls intercept: h2 accept failed: {err}")),
                    None => client_closed = true,
                }
            }
        }
    }
}
