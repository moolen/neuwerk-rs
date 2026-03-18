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
    } else if lower.contains("request denied by policy")
        || lower.contains("response denied by policy")
    {
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

fn classify_upstream_h2_ready_error_kind(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("timed out") {
        "timeout"
    } else if lower.contains("cancel") {
        "cancel"
    } else if lower.contains("refused_stream") || lower.contains("refused stream") {
        "refused_stream"
    } else if lower.contains("protocol_error") || lower.contains("protocol error") {
        "protocol_error"
    } else if lower.contains("internal_error") || lower.contains("internal error") {
        "internal_error"
    } else if lower.contains("flow_control_error") || lower.contains("flow control error") {
        "flow_control_error"
    } else if lower.contains("enhance_your_calm") || lower.contains("enhance your calm") {
        "enhance_your_calm"
    } else if lower.contains("connection reset by peer") {
        "conn_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("not connected") {
        "not_connected"
    } else if lower.contains("unexpected eof") || lower.contains("eof") {
        "eof"
    } else if lower.contains("closed") {
        "closed"
    } else {
        "other"
    }
}

fn classify_upstream_response_error_kind(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("timed out") {
        "timeout"
    } else if lower.contains("cancel") {
        "cancel"
    } else if lower.contains("refused_stream") || lower.contains("refused stream") {
        "refused_stream"
    } else if lower.contains("protocol_error") || lower.contains("protocol error") {
        "protocol_error"
    } else if lower.contains("internal_error") || lower.contains("internal error") {
        "internal_error"
    } else if lower.contains("flow_control_error") || lower.contains("flow control error") {
        "flow_control_error"
    } else if lower.contains("enhance_your_calm") || lower.contains("enhance your calm") {
        "enhance_your_calm"
    } else if lower.contains("stream no longer needed") {
        "stream_no_longer_needed"
    } else if lower.contains("connection reset by peer") {
        "conn_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("unexpected eof") || lower.contains("eof") {
        "eof"
    } else if lower.contains("closed") {
        "closed"
    } else if lower.contains("not a result of an error") {
        "no_error_close"
    } else {
        "other"
    }
}

fn classify_upstream_h2_conn_close_kind(err: &h2::Error) -> &'static str {
    if let Some(reason) = err.reason() {
        if reason == h2::Reason::NO_ERROR {
            return "no_error";
        }
        if reason == h2::Reason::CANCEL {
            return "cancel";
        }
        if reason == h2::Reason::REFUSED_STREAM {
            return "refused_stream";
        }
        if reason == h2::Reason::PROTOCOL_ERROR {
            return "protocol_error";
        }
        if reason == h2::Reason::INTERNAL_ERROR {
            return "internal_error";
        }
        if reason == h2::Reason::FLOW_CONTROL_ERROR {
            return "flow_control_error";
        }
        if reason == h2::Reason::ENHANCE_YOUR_CALM {
            return "enhance_your_calm";
        }
        return "h2_reason_other";
    }
    let lower = err.to_string().to_ascii_lowercase();
    if lower.contains("timed out") {
        "timeout"
    } else if lower.contains("connection reset by peer") {
        "conn_reset"
    } else if lower.contains("broken pipe") {
        "broken_pipe"
    } else if lower.contains("unexpected eof") || lower.contains("eof") {
        "eof"
    } else if lower.contains("closed") {
        "closed"
    } else {
        "other"
    }
}

fn classify_upstream_h2_conn_termination(err: &h2::Error) -> (&'static str, &'static str) {
    if let Some(reason) = err.reason() {
        let reason = if reason == h2::Reason::NO_ERROR {
            "no_error"
        } else if reason == h2::Reason::CANCEL {
            "cancel"
        } else if reason == h2::Reason::REFUSED_STREAM {
            "refused_stream"
        } else if reason == h2::Reason::PROTOCOL_ERROR {
            "protocol_error"
        } else if reason == h2::Reason::INTERNAL_ERROR {
            "internal_error"
        } else if reason == h2::Reason::FLOW_CONTROL_ERROR {
            "flow_control_error"
        } else if reason == h2::Reason::ENHANCE_YOUR_CALM {
            "enhance_your_calm"
        } else {
            "other"
        };
        return ("goaway", reason);
    }
    let lower = err.to_string().to_ascii_lowercase();
    if lower.contains("connection reset by peer") {
        ("rst", "conn_reset")
    } else if lower.contains("broken pipe") {
        ("io", "broken_pipe")
    } else if lower.contains("unexpected eof") || lower.contains("eof") {
        ("io", "eof")
    } else if lower.contains("timed out") {
        ("io", "timeout")
    } else if lower.contains("closed") {
        ("io", "closed")
    } else {
        ("other", "other")
    }
}

fn classify_upstream_h2_retry_cause(err: &str) -> &'static str {
    let lower = err.to_ascii_lowercase();
    if lower.contains("h2 upstream ready failed") || lower.contains("h2 upstream ready timed out") {
        "ready_failed"
    } else if lower.contains("h2 upstream send failed") {
        "send_failed"
    } else if lower.contains("upstream connection closed") {
        "connection_closed"
    } else {
        "other"
    }
}

fn update_upstream_h2_send_wait_ewma(client: &UpstreamH2Client, sample: Duration) {
    let sample_us = sample
        .as_micros()
        .min(u128::from(u64::MAX))
        .try_into()
        .unwrap_or(u64::MAX);
    let mut prev = client.send_wait_ewma_us.load(Ordering::Acquire);
    loop {
        let next = if prev == 0 {
            sample_us
        } else {
            prev.saturating_mul(7).saturating_add(sample_us) / 8
        };
        match client.send_wait_ewma_us.compare_exchange_weak(
            prev,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(observed) => prev = observed,
        }
    }
}

fn observe_selected_inflight_peak(metrics: &Metrics, selected_in_flight: usize) {
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let observed_sec = UPSTREAM_H2_SELECTED_INFLIGHT_WINDOW_SEC.load(Ordering::Acquire);
    if observed_sec != now_sec
        && UPSTREAM_H2_SELECTED_INFLIGHT_WINDOW_SEC
            .compare_exchange(observed_sec, now_sec, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        UPSTREAM_H2_SELECTED_INFLIGHT_WINDOW_MAX.store(selected_in_flight, Ordering::Release);
        metrics.set_svc_tls_intercept_upstream_h2_selected_inflight_peak(selected_in_flight);
        return;
    }

    let mut prev = UPSTREAM_H2_SELECTED_INFLIGHT_WINDOW_MAX.load(Ordering::Acquire);
    while selected_in_flight > prev {
        match UPSTREAM_H2_SELECTED_INFLIGHT_WINDOW_MAX.compare_exchange_weak(
            prev,
            selected_in_flight,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                metrics
                    .set_svc_tls_intercept_upstream_h2_selected_inflight_peak(selected_in_flight);
                break;
            }
            Err(observed) => prev = observed,
        }
    }
}

fn upstream_h2_reconnect_backoff_map(
) -> &'static std::sync::Mutex<HashMap<String, UpstreamH2ReconnectBackoffState>> {
    UPSTREAM_H2_RECONNECT_BACKOFF.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn upstream_h2_reconnect_backoff_wait(pool_key: &str) -> Duration {
    let map = upstream_h2_reconnect_backoff_map();
    let lock = map
        .lock()
        .expect("upstream h2 reconnect backoff map poisoned");
    let Some(state) = lock.get(pool_key) else {
        return Duration::from_millis(0);
    };
    state
        .next_allowed_at
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(0))
}

fn upstream_h2_reconnect_backoff_record_failure(pool_key: &str) -> Duration {
    let map = upstream_h2_reconnect_backoff_map();
    let mut lock = map
        .lock()
        .expect("upstream h2 reconnect backoff map poisoned");
    let now = Instant::now();
    let mut state = lock
        .get(pool_key)
        .copied()
        .unwrap_or(UpstreamH2ReconnectBackoffState {
            failures: 0,
            next_allowed_at: now,
        });
    state.failures = state.failures.saturating_add(1);
    let base_ms = tls_h2_reconnect_backoff_base_ms();
    let max_ms = tls_h2_reconnect_backoff_max_ms();
    let shift = state.failures.saturating_sub(1).min(12);
    let backoff_ms = base_ms
        .saturating_mul(1u64 << shift)
        .min(max_ms)
        .max(base_ms);
    let delay = Duration::from_millis(backoff_ms);
    state.next_allowed_at = now + delay;
    lock.insert(pool_key.to_string(), state);
    delay
}

fn upstream_h2_reconnect_backoff_record_success(pool_key: &str) {
    let map = upstream_h2_reconnect_backoff_map();
    let mut lock = map
        .lock()
        .expect("upstream h2 reconnect backoff map poisoned");
    lock.remove(pool_key);
}

fn record_tls_intercept_connection_error(metrics: &Metrics, err: &str) {
    let (stage, reason) = classify_tls_intercept_error(err);
    metrics.inc_svc_tls_intercept_error(stage, reason);
    if stage == "upstream_h2_ready" {
        metrics.inc_svc_tls_intercept_upstream_h2_ready_error(
            classify_upstream_h2_ready_error_kind(err),
        );
    } else if stage == "upstream_response" {
        metrics.inc_svc_tls_intercept_upstream_response_error(
            classify_upstream_response_error_kind(err),
        );
    }
}

fn is_benign_h2_response_body_termination(err: &h2::Error) -> bool {
    matches!(
        err.reason(),
        Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL)
    ) || err.to_string().contains("stream no longer needed")
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
    let h2_pool_shards = tls_h2_pool_shards() as usize;
    let upstream_h2_pool: UpstreamH2Pool = Arc::new(UpstreamH2PoolState::new(h2_pool_shards));
    let upstream_h2_connect_inflight: UpstreamH2ConnectInFlight =
        Arc::new(UpstreamH2ConnectInFlightState::new(h2_pool_shards));
    let listener = build_intercept_listener(cfg.bind_addr)?;
    info!(
        bind_addr = %cfg.bind_addr,
        io_timeout_secs = tls_io_timeout().as_secs(),
        h2_body_idle_timeout_secs = tls_h2_body_idle_timeout().as_secs(),
        h2_max_concurrent_streams = tls_h2_max_concurrent_streams(),
        h2_max_requests_per_connection = tls_h2_max_requests_per_connection(),
        h2_selection_inflight_weight = tls_h2_selection_inflight_weight(),
        h2_pool_shards = tls_h2_pool_shards(),
        h2_reconnect_backoff_base_ms = tls_h2_reconnect_backoff_base_ms(),
        h2_reconnect_backoff_max_ms = tls_h2_reconnect_backoff_max_ms(),
        h2_detailed_metrics = tls_h2_detailed_metrics_enabled(),
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
        let upstream_h2_connect_inflight = upstream_h2_connect_inflight.clone();
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
                upstream_h2_connect_inflight,
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
    upstream_h2_connect_inflight: UpstreamH2ConnectInFlight,
    metrics: Metrics,
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    intercept_demux: Arc<SharedInterceptDemuxState>,
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
            upstream_h2_connect_inflight,
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
    let tls = tokio::time::timeout(
        tls_io_timeout(),
        connector.connect(server_name, upstream_tcp),
    )
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
    let metrics_task = metrics.clone();
    let client = Arc::new(UpstreamH2Client {
        send_request: StdMutex::new(send_request),
        in_flight_streams: AtomicUsize::new(0),
        total_streams_started: AtomicUsize::new(0),
        send_wait_ewma_us: AtomicU64::new(0),
        is_closed: AtomicBool::new(false),
    });
    let client_weak = Arc::downgrade(&client);
    tokio::spawn(async move {
        let _session_guard = session_guard;
        let (close_reason, termination_kind, termination_reason) = match upstream_conn.await {
            Ok(()) => ("graceful", "graceful", "graceful"),
            Err(err) => {
                let close_reason = classify_upstream_h2_conn_close_kind(&err);
                let (kind, reason) = classify_upstream_h2_conn_termination(&err);
                (close_reason, kind, reason)
            }
        };
        if let Some(client) = client_weak.upgrade() {
            client.is_closed.store(true, Ordering::Release);
        }
        metrics_task.inc_svc_tls_intercept_upstream_h2_pool("conn_closed");
        metrics_task.inc_svc_tls_intercept_upstream_h2_conn_closed(close_reason);
        metrics_task.inc_svc_tls_intercept_upstream_h2_conn_termination(
            termination_kind,
            termination_reason,
        );
    });
    Ok(client)
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

fn upstream_h2_selection_score(
    in_flight: usize,
    send_wait_ewma_us: u64,
    inflight_weight: u64,
) -> (u64, usize) {
    let in_flight_u64 = in_flight.min(u64::MAX as usize) as u64;
    let score = in_flight_u64
        .saturating_mul(inflight_weight)
        .saturating_add(send_wait_ewma_us);
    (score, in_flight)
}

fn select_upstream_h2_client(
    pool: &mut HashMap<String, Vec<Arc<UpstreamH2Client>>>,
    pool_key: &str,
    max_streams_per_client: usize,
    max_requests_per_connection: usize,
    metrics: &Metrics,
) -> Option<Arc<UpstreamH2Client>> {
    let inflight_weight = tls_h2_selection_inflight_weight();
    let mut remove_host = false;
    let mut pruned = 0usize;
    let mut retired_pruned = 0usize;
    let selected = pool.get_mut(pool_key).and_then(|clients| {
        let before = clients.len();
        clients.retain(|client| {
            if client.is_closed.load(Ordering::Acquire) {
                return false;
            }
            let in_flight = client.in_flight_streams.load(Ordering::Acquire);
            let total_streams = client.total_streams_started.load(Ordering::Acquire);
            if total_streams >= max_requests_per_connection && in_flight == 0 {
                client.is_closed.store(true, Ordering::Release);
                retired_pruned = retired_pruned.saturating_add(1);
                return false;
            }
            true
        });
        pruned = before.saturating_sub(clients.len());
        if clients.is_empty() {
            remove_host = true;
            return None;
        }
        if tls_h2_detailed_metrics_enabled() {
            metrics.observe_svc_tls_intercept_upstream_h2_pool_width(clients.len());
        }
        clients
            .iter()
            .filter_map(|client| {
                let in_flight = client.in_flight_streams.load(Ordering::Acquire);
                let total_streams = client.total_streams_started.load(Ordering::Acquire);
                (in_flight < max_streams_per_client && total_streams < max_requests_per_connection)
                    .then(|| {
                        let send_wait_ewma_us = client.send_wait_ewma_us.load(Ordering::Acquire);
                        let score = upstream_h2_selection_score(
                            in_flight,
                            send_wait_ewma_us,
                            inflight_weight,
                        );
                        (score, in_flight, client.clone())
                    })
            })
            .min_by_key(|(score, in_flight, _)| (*score, *in_flight))
            .map(|(_, in_flight, client)| {
                observe_selected_inflight_peak(metrics, in_flight);
                if tls_h2_detailed_metrics_enabled() {
                    metrics.observe_svc_tls_intercept_upstream_h2_selected_inflight(in_flight);
                }
                client
            })
    });
    if remove_host {
        pool.remove(pool_key);
    }
    let stale_pruned = pruned.saturating_sub(retired_pruned);
    for _ in 0..stale_pruned {
        metrics.inc_svc_tls_intercept_upstream_h2_pool("stale_pruned");
    }
    for _ in 0..retired_pruned {
        metrics.inc_svc_tls_intercept_upstream_h2_pool("retired_pruned");
    }
    selected
}

async fn get_or_connect_upstream_h2_client_with<Connect, ConnectFuture>(
    pool: &UpstreamH2Pool,
    connect_inflight: &UpstreamH2ConnectInFlight,
    pool_key: &str,
    metrics: &Metrics,
    connect: Connect,
) -> Result<(Arc<UpstreamH2Client>, UpstreamH2StreamGuard), String>
where
    Connect: FnOnce() -> ConnectFuture,
    ConnectFuture: std::future::Future<Output = Result<Arc<UpstreamH2Client>, String>>,
{
    let max_streams_per_client = tls_h2_max_concurrent_streams() as usize;
    let max_requests_per_connection = tls_h2_max_requests_per_connection();
    loop {
        let lock_wait_start = std::time::Instant::now();
        let mut lock = pool.lock_key(pool_key).await;
        metrics.observe_svc_tls_intercept_phase(
            "upstream_h2_pool_lock_wait",
            lock_wait_start.elapsed(),
        );
        if let Some(existing) = select_upstream_h2_client(
            &mut lock,
            pool_key,
            max_streams_per_client,
            max_requests_per_connection,
            metrics,
        ) {
            metrics.inc_svc_tls_intercept_upstream_h2_pool("hit");
            let guard = UpstreamH2StreamGuard::new(existing.clone());
            return Ok((existing, guard));
        }
        drop(lock);

        let (is_connector, connect_gate) = {
            let mut lock = connect_inflight.lock_key(pool_key).await;
            if let Some(existing) = lock.get(pool_key) {
                (false, existing.clone())
            } else {
                let gate = Arc::new(Notify::new());
                lock.insert(pool_key.to_string(), gate.clone());
                (true, gate)
            }
        };
        if !is_connector {
            metrics.inc_svc_tls_intercept_upstream_h2_pool("connect_wait");
            connect_gate.notified().await;
            continue;
        }

        let connect_start = std::time::Instant::now();
        let created = connect().await;
        metrics
            .observe_svc_tls_intercept_phase("upstream_h2_pool_connect", connect_start.elapsed());

        let gate = {
            let mut lock = connect_inflight.lock_key(pool_key).await;
            lock.remove(pool_key)
        };
        if let Some(gate) = gate {
            gate.notify_waiters();
        }

        let created = created?;
        let relock_wait_start = std::time::Instant::now();
        let mut lock = pool.lock_key(pool_key).await;
        metrics.observe_svc_tls_intercept_phase(
            "upstream_h2_pool_lock_wait",
            relock_wait_start.elapsed(),
        );
        if let Some(existing) = select_upstream_h2_client(
            &mut lock,
            pool_key,
            max_streams_per_client,
            max_requests_per_connection,
            metrics,
        ) {
            created.is_closed.store(true, Ordering::Release);
            metrics.inc_svc_tls_intercept_upstream_h2_pool("connect_raced");
            let guard = UpstreamH2StreamGuard::new(existing.clone());
            return Ok((existing, guard));
        }

        metrics.inc_svc_tls_intercept_upstream_h2_pool("miss");
        lock.entry(pool_key.to_string())
            .or_default()
            .push(created.clone());
        let guard = UpstreamH2StreamGuard::new(created.clone());
        return Ok((created, guard));
    }
}

async fn get_or_connect_upstream_h2_client(
    pool: &UpstreamH2Pool,
    connect_inflight: &UpstreamH2ConnectInFlight,
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    pool_key: &str,
    metrics: &Metrics,
) -> Result<(Arc<UpstreamH2Client>, UpstreamH2StreamGuard), String> {
    get_or_connect_upstream_h2_client_with(pool, connect_inflight, pool_key, metrics, || {
        connect_upstream_h2_client(connector, upstream_addr, host, metrics)
    })
    .await
}

async fn send_upstream_h2_request(
    client: &Arc<UpstreamH2Client>,
    request: axum::http::Request<()>,
    end_of_stream: bool,
    metrics: &Metrics,
) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
    if client.is_closed.load(Ordering::Acquire) {
        return Err(
            "tls intercept: h2 upstream ready failed: upstream connection closed".to_string(),
        );
    }
    let lock_wait_start = std::time::Instant::now();
    let mut send_request = client
        .send_request
        .lock()
        .map_err(|_| "tls intercept: h2 upstream sender lock poisoned".to_string())?
        .clone();
    let send_lock_wait = lock_wait_start.elapsed();
    update_upstream_h2_send_wait_ewma(client, send_lock_wait);
    metrics.observe_svc_tls_intercept_phase("upstream_h2_send_lock_wait", send_lock_wait);
    if tls_h2_detailed_metrics_enabled() {
        metrics.observe_svc_tls_intercept_upstream_h2_send_wait(
            "sender_clone_lock_wait",
            send_lock_wait,
        );
        let ready_wait_start = std::time::Instant::now();
        let ready_result =
            tokio::time::timeout(tls_io_timeout(), send_request.clone().ready()).await;
        let ready_wait = ready_wait_start.elapsed();
        metrics.observe_svc_tls_intercept_phase("upstream_h2_ready_wait", ready_wait);
        metrics.observe_svc_tls_intercept_upstream_h2_send_wait("ready_wait", ready_wait);
        if let Err(err) = ready_result
            .map_err(|_| "tls intercept: h2 upstream ready timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream ready failed: {err}"))
        {
            client.is_closed.store(true, Ordering::Release);
            return Err(err);
        }
    } else {
        if let Err(err) = tokio::time::timeout(tls_io_timeout(), send_request.clone().ready())
            .await
            .map_err(|_| "tls intercept: h2 upstream ready timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream ready failed: {err}"))
        {
            client.is_closed.store(true, Ordering::Release);
            return Err(err);
        }
    }
    send_request
        .send_request(request, end_of_stream)
        .map_err(|err| {
            client.is_closed.store(true, Ordering::Release);
            format!("tls intercept: h2 upstream send failed: {err}")
        })
}

fn upstream_h2_pool_keys_for_shard_count(
    host: &str,
    upstream_addr: SocketAddr,
    shard_count: usize,
    primary_shard: usize,
) -> Vec<(String, usize)> {
    if shard_count <= 1 {
        return vec![(format!("{host}@{upstream_addr}"), 0)];
    }

    let mut keys = Vec::with_capacity(shard_count);
    for offset in 0..shard_count {
        let shard = (primary_shard + offset) % shard_count;
        keys.push((format!("{host}@{upstream_addr}#s{shard}"), shard));
    }
    keys
}

fn upstream_h2_pool_keys(host: &str, upstream_addr: SocketAddr) -> (Vec<(String, usize)>, usize) {
    let shard_count = tls_h2_pool_shards();
    if shard_count <= 1 {
        return (vec![(format!("{host}@{upstream_addr}"), 0)], shard_count);
    }
    let primary_shard = UPSTREAM_H2_POOL_SHARD_RR.fetch_add(1, Ordering::Relaxed) % shard_count;
    (
        upstream_h2_pool_keys_for_shard_count(host, upstream_addr, shard_count, primary_shard),
        shard_count,
    )
}

async fn try_get_existing_upstream_h2_client(
    pool: &UpstreamH2Pool,
    pool_key: &str,
    metrics: &Metrics,
) -> Option<(Arc<UpstreamH2Client>, UpstreamH2StreamGuard)> {
    let max_streams_per_client = tls_h2_max_concurrent_streams() as usize;
    let max_requests_per_connection = tls_h2_max_requests_per_connection();
    let lock_wait_start = std::time::Instant::now();
    let mut lock = pool.lock_key(pool_key).await;
    metrics
        .observe_svc_tls_intercept_phase("upstream_h2_pool_lock_wait", lock_wait_start.elapsed());
    let selected = select_upstream_h2_client(
        &mut lock,
        pool_key,
        max_streams_per_client,
        max_requests_per_connection,
        metrics,
    )?;
    metrics.inc_svc_tls_intercept_upstream_h2_pool("hit");
    let guard = UpstreamH2StreamGuard::new(selected.clone());
    Some((selected, guard))
}

async fn evict_unhealthy_upstream_h2_client(
    pool: &UpstreamH2Pool,
    pool_key: &str,
    client: &Arc<UpstreamH2Client>,
    metrics: &Metrics,
    reason: &'static str,
) {
    client.is_closed.store(true, Ordering::Release);
    let mut lock = pool.lock_key(pool_key).await;
    remove_pooled_upstream_h2_client(&mut lock, pool_key, client);
    metrics.inc_svc_tls_intercept_upstream_h2_pool(reason);
}

async fn maybe_wait_upstream_h2_reconnect_backoff(pool_key: &str, metrics: &Metrics) {
    let wait = upstream_h2_reconnect_backoff_wait(pool_key);
    if wait.is_zero() {
        return;
    }
    metrics.inc_svc_tls_intercept_upstream_h2_pool("reconnect_backoff_wait");
    metrics.observe_svc_tls_intercept_phase("upstream_h2_reconnect_backoff_wait", wait);
    tokio::time::sleep(wait).await;
}

async fn send_upstream_h2_request_via_pool(
    pool: &UpstreamH2Pool,
    connect_inflight: &UpstreamH2ConnectInFlight,
    connector: TlsConnector,
    upstream_addr: SocketAddr,
    host: &str,
    request: axum::http::Request<()>,
    end_of_stream: bool,
    metrics: &Metrics,
) -> Result<
    (
        String,
        Arc<UpstreamH2Client>,
        UpstreamH2StreamGuard,
        h2::client::ResponseFuture,
        h2::SendStream<Bytes>,
    ),
    String,
> {
    let (pool_keys, shard_count) = upstream_h2_pool_keys(host, upstream_addr);
    let (primary_pool_key, primary_shard) = &pool_keys[0];
    if shard_count > 1 {
        metrics.inc_svc_tls_intercept_upstream_h2_shard_select(*primary_shard);
    }

    for (idx, (pool_key, _shard)) in pool_keys.iter().enumerate() {
        if idx > 0 {
            metrics.inc_svc_tls_intercept_upstream_h2_pool("cross_shard_probe");
        }
        let Some((client, guard)) =
            try_get_existing_upstream_h2_client(pool, pool_key, metrics).await
        else {
            continue;
        };
        if idx > 0 {
            metrics.inc_svc_tls_intercept_upstream_h2_pool("cross_shard_hit");
        }
        match send_upstream_h2_request(&client, request.clone(), end_of_stream, metrics).await {
            Ok((response_fut, send_stream)) => {
                upstream_h2_reconnect_backoff_record_success(pool_key);
                return Ok((pool_key.clone(), client, guard, response_fut, send_stream));
            }
            Err(err) => {
                drop(guard);
                evict_unhealthy_upstream_h2_client(
                    pool,
                    pool_key,
                    &client,
                    metrics,
                    "unhealthy_ready_or_send_evict",
                )
                .await;
                metrics.inc_svc_tls_intercept_upstream_h2_retry(classify_upstream_h2_retry_cause(
                    &err,
                ));
            }
        }
    }

    maybe_wait_upstream_h2_reconnect_backoff(primary_pool_key, metrics).await;

    let (client, guard) = get_or_connect_upstream_h2_client(
        pool,
        connect_inflight,
        connector.clone(),
        upstream_addr,
        host,
        primary_pool_key,
        metrics,
    )
    .await?;
    match send_upstream_h2_request(&client, request.clone(), end_of_stream, metrics).await {
        Ok((response_fut, send_stream)) => {
            upstream_h2_reconnect_backoff_record_success(primary_pool_key);
            Ok((
                primary_pool_key.clone(),
                client,
                guard,
                response_fut,
                send_stream,
            ))
        }
        Err(first_err) => {
            drop(guard);
            evict_unhealthy_upstream_h2_client(
                pool,
                primary_pool_key,
                &client,
                metrics,
                "unhealthy_ready_or_send_evict",
            )
            .await;
            metrics.inc_svc_tls_intercept_upstream_h2_retry(classify_upstream_h2_retry_cause(
                &first_err,
            ));
            metrics.inc_svc_tls_intercept_upstream_h2_pool("reconnect");
            let reconnect_backoff = upstream_h2_reconnect_backoff_record_failure(primary_pool_key);
            if !reconnect_backoff.is_zero() {
                metrics.observe_svc_tls_intercept_phase(
                    "upstream_h2_reconnect_backoff_wait",
                    reconnect_backoff,
                );
                tokio::time::sleep(reconnect_backoff).await;
            }
            let reconnected =
                connect_upstream_h2_client(connector, upstream_addr, host, metrics).await?;
            {
                let mut lock = pool.lock_key(primary_pool_key).await;
                lock.entry(primary_pool_key.clone())
                    .or_default()
                    .push(reconnected.clone());
            }
            let reconnect_guard = UpstreamH2StreamGuard::new(reconnected.clone());
            match send_upstream_h2_request(&reconnected, request, end_of_stream, metrics).await {
                Ok((response_fut, send_stream)) => {
                    upstream_h2_reconnect_backoff_record_success(primary_pool_key);
                    Ok((
                        primary_pool_key.clone(),
                        reconnected,
                        reconnect_guard,
                        response_fut,
                        send_stream,
                    ))
                }
                Err(retry_err) => {
                    drop(reconnect_guard);
                    evict_unhealthy_upstream_h2_client(
                        pool,
                        primary_pool_key,
                        &reconnected,
                        metrics,
                        "unhealthy_retry_evict",
                    )
                    .await;
                    let _ = upstream_h2_reconnect_backoff_record_failure(primary_pool_key);
                    metrics.inc_svc_tls_intercept_upstream_h2_pool("retry_failed");
                    Err(format!("{first_err}; retry failed: {retry_err}"))
                }
            }
        }
    }
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn get_or_connect_upstream_h2_client_releases_pool_lock_before_connect() {
    use tokio::sync::{Barrier, Notify};

    let pool: UpstreamH2Pool = Arc::new(UpstreamH2PoolState::new(1));
    let connect_inflight: UpstreamH2ConnectInFlight =
        Arc::new(UpstreamH2ConnectInFlightState::new(1));
    let metrics = Metrics::new().expect("metrics");
    let connect_started = Arc::new(Barrier::new(2));
    let release_connect = Arc::new(Notify::new());

    let task = {
        let pool = pool.clone();
        let metrics = metrics.clone();
        let connect_started = connect_started.clone();
        let release_connect = release_connect.clone();
        tokio::spawn(async move {
            let _ = get_or_connect_upstream_h2_client_with(
                &pool,
                &connect_inflight,
                "foo.allowed@127.0.0.1:443",
                &metrics,
                move || async move {
                    connect_started.wait().await;
                    release_connect.notified().await;
                    Err("test connect blocked".to_string())
                },
            )
            .await;
        })
    };

    connect_started.wait().await;
    assert!(
        pool.try_lock_key("foo.allowed@127.0.0.1:443").is_ok(),
        "upstream h2 pool lock should not be held while connect future is in-flight"
    );
    release_connect.notify_waiters();
    task.await.expect("join test connect task");
}

#[cfg(test)]
#[test]
fn upstream_h2_selection_score_prefers_lower_send_wait_at_same_inflight() {
    let weight = 128;
    let lhs = upstream_h2_selection_score(4, 10, weight);
    let rhs = upstream_h2_selection_score(4, 200, weight);
    assert!(
        lhs < rhs,
        "lower send-wait EWMA should win when in-flight matches"
    );
}

#[cfg(test)]
#[test]
fn upstream_h2_selection_score_prefers_lower_inflight_when_send_wait_equal() {
    let weight = 128;
    let low_inflight = upstream_h2_selection_score(2, 100, weight);
    let high_inflight = upstream_h2_selection_score(3, 100, weight);
    assert!(
        low_inflight < high_inflight,
        "lower in-flight should win when send-wait EWMA is equal"
    );
}

#[cfg(test)]
#[test]
fn upstream_h2_pool_keys_for_shard_count_covers_all_shards_from_primary() {
    let upstream_addr: SocketAddr = "127.0.0.1:443".parse().expect("parse upstream addr");
    let keys = upstream_h2_pool_keys_for_shard_count("foo.allowed", upstream_addr, 4, 2);
    let shards: Vec<usize> = keys.iter().map(|(_, shard)| *shard).collect();
    assert_eq!(shards, vec![2, 3, 0, 1]);
    assert_eq!(keys.len(), 4);
}

#[cfg(test)]
#[test]
fn upstream_h2_reconnect_backoff_progresses_and_resets() {
    let key = format!(
        "unit-test-backoff-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos()
    );
    upstream_h2_reconnect_backoff_record_success(&key);
    assert!(
        upstream_h2_reconnect_backoff_wait(&key).is_zero(),
        "backoff wait should be zero when no failure has been recorded"
    );

    let first = upstream_h2_reconnect_backoff_record_failure(&key);
    let first_wait = upstream_h2_reconnect_backoff_wait(&key);
    assert!(
        !first_wait.is_zero(),
        "recorded failure should create a non-zero backoff wait"
    );
    assert!(
        first_wait <= first,
        "remaining wait should not exceed configured delay"
    );

    let second = upstream_h2_reconnect_backoff_record_failure(&key);
    assert!(
        second >= first,
        "subsequent failures should not reduce reconnect backoff"
    );

    upstream_h2_reconnect_backoff_record_success(&key);
    assert!(
        upstream_h2_reconnect_backoff_wait(&key).is_zero(),
        "successful reconnect should clear backoff state"
    );
}

#[cfg(test)]
#[tokio::test(flavor = "current_thread")]
async fn get_or_connect_upstream_h2_client_singleflights_connect_per_pool_key() {
    let pool: UpstreamH2Pool = Arc::new(UpstreamH2PoolState::new(1));
    let connect_inflight: UpstreamH2ConnectInFlight =
        Arc::new(UpstreamH2ConnectInFlightState::new(1));
    let metrics = Metrics::new().expect("metrics");
    let release_connect = Arc::new(Notify::new());
    let (first_started_tx, first_started_rx) = oneshot::channel();
    let first_started_tx = Arc::new(std::sync::Mutex::new(Some(first_started_tx)));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let peak_in_flight = Arc::new(AtomicUsize::new(0));
    let connect_calls = Arc::new(AtomicUsize::new(0));
    let release_open = Arc::new(AtomicBool::new(false));

    let run_connect = |pool: UpstreamH2Pool,
                       connect_inflight: UpstreamH2ConnectInFlight,
                       metrics: Metrics,
                       release_connect: Arc<Notify>,
                       release_open: Arc<AtomicBool>,
                       first_started_tx: Arc<std::sync::Mutex<Option<oneshot::Sender<()>>>>,
                       in_flight: Arc<AtomicUsize>,
                       peak_in_flight: Arc<AtomicUsize>,
                       connect_calls: Arc<AtomicUsize>| {
        tokio::spawn(async move {
            let _ = get_or_connect_upstream_h2_client_with(
                &pool,
                &connect_inflight,
                "foo.allowed@127.0.0.1:443",
                &metrics,
                move || async move {
                    connect_calls.fetch_add(1, Ordering::AcqRel);
                    let now = in_flight.fetch_add(1, Ordering::AcqRel) + 1;
                    let mut prev = peak_in_flight.load(Ordering::Acquire);
                    while now > prev {
                        match peak_in_flight.compare_exchange(
                            prev,
                            now,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            Err(observed) => prev = observed,
                        }
                    }
                    if let Some(tx) = first_started_tx.lock().expect("first_started lock").take() {
                        let _ = tx.send(());
                    }
                    while !release_open.load(Ordering::Acquire) {
                        release_connect.notified().await;
                    }
                    in_flight.fetch_sub(1, Ordering::AcqRel);
                    Err("test connect failed".to_string())
                },
            )
            .await;
        })
    };

    let task_a = run_connect(
        pool.clone(),
        connect_inflight.clone(),
        metrics.clone(),
        release_connect.clone(),
        release_open.clone(),
        first_started_tx.clone(),
        in_flight.clone(),
        peak_in_flight.clone(),
        connect_calls.clone(),
    );
    let task_b = run_connect(
        pool.clone(),
        connect_inflight.clone(),
        metrics.clone(),
        release_connect.clone(),
        release_open.clone(),
        first_started_tx,
        in_flight,
        peak_in_flight.clone(),
        connect_calls.clone(),
    );

    let _ = first_started_rx.await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        connect_calls.load(Ordering::Acquire),
        1,
        "only one connector should execute while the first connect attempt is in-flight"
    );
    assert_eq!(
        peak_in_flight.load(Ordering::Acquire),
        1,
        "concurrent connect attempts for a single upstream key should be serialized"
    );
    release_open.store(true, Ordering::Release);
    release_connect.notify_waiters();
    let _ = task_a.await;
    let _ = task_b.await;
    assert_eq!(
        peak_in_flight.load(Ordering::Acquire),
        1,
        "connect attempts must remain serialized even after retries"
    );
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
        let chunk =
            next.map_err(|err| format!("tls intercept: h2 request body read failed: {err}"))?;
        out.extend_from_slice(&chunk);
        body.flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| {
                format!("tls intercept: h2 request body flow control release failed: {err}")
            })?;
        if out.len() > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 request body exceeds max size".to_string());
        }
    }
    Ok(out)
}

async fn drain_h2_request_body(mut body: h2::RecvStream) -> Result<usize, String> {
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
        body.flow_control()
            .release_capacity(chunk_len)
            .map_err(|err| {
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
    upstream_connect_inflight: UpstreamH2ConnectInFlight,
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
        request_policy
            .and_then(|policy| policy.query.as_ref())
            .is_some(),
        request_policy
            .and_then(|policy| policy.headers.as_ref())
            .is_some(),
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
    let (
        upstream_pool_key,
        upstream_client,
        _upstream_stream_guard,
        response_fut,
        upstream_send_stream,
    ) = send_upstream_h2_request_via_pool(
        &upstream_pool,
        &upstream_connect_inflight,
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
            match forward_h2_request_body(request.into_body(), upstream_send_stream, response_fut)
                .await
            {
                Ok(value) => value,
                Err(err) => {
                    evict_unhealthy_upstream_h2_client(
                        &upstream_pool,
                        &upstream_pool_key,
                        &upstream_client,
                        &metrics,
                        "unhealthy_response_evict",
                    )
                    .await;
                    return Err(err);
                }
            };
        metrics
            .observe_svc_tls_intercept_phase("h2_request_body_read", request_body_start.elapsed());
        if request_body_bytes > http_match::HTTP_MAX_BODY_BYTES {
            return Err("tls intercept: h2 request body exceeds max size".to_string());
        }
        upstream_response
    } else {
        match tokio::time::timeout(tls_io_timeout(), response_fut).await {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                evict_unhealthy_upstream_h2_client(
                    &upstream_pool,
                    &upstream_pool_key,
                    &upstream_client,
                    &metrics,
                    "unhealthy_response_evict",
                )
                .await;
                return Err(format!("tls intercept: h2 upstream response failed: {err}"));
            }
            Err(_) => {
                evict_unhealthy_upstream_h2_client(
                    &upstream_pool,
                    &upstream_pool_key,
                    &upstream_client,
                    &metrics,
                    "unhealthy_response_evict",
                )
                .await;
                return Err("tls intercept: h2 upstream response timed out".to_string());
            }
        }
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
    while let Some(next) = match tokio::time::timeout(body_idle_timeout, upstream_body.data()).await
    {
        Ok(next) => next,
        Err(_) => {
            evict_unhealthy_upstream_h2_client(
                &upstream_pool,
                &upstream_pool_key,
                &upstream_client,
                &metrics,
                "unhealthy_response_evict",
            )
            .await;
            return Err(format!(
                "tls intercept: h2 upstream body read timed out after {}s",
                body_idle_timeout.as_secs()
            ));
        }
    } {
        let chunk = match next {
            Ok(chunk) => chunk,
            Err(err) if is_benign_h2_response_body_termination(&err) => break,
            Err(err) => {
                evict_unhealthy_upstream_h2_client(
                    &upstream_pool,
                    &upstream_pool_key,
                    &upstream_client,
                    &metrics,
                    "unhealthy_response_evict",
                )
                .await;
                return Err(format!(
                    "tls intercept: h2 upstream body read failed: {err}"
                ));
            }
        };
        body_bytes = body_bytes.saturating_add(chunk.len());
        upstream_body
            .flow_control()
            .release_capacity(chunk.len())
            .map_err(|err| {
                format!("tls intercept: h2 upstream body flow control release failed: {err}")
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
    upstream_connect_inflight: UpstreamH2ConnectInFlight,
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
                upstream_connect_inflight.clone(),
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
                            upstream_connect_inflight.clone(),
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
