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
        .listen(128)
        .map_err(|err| format!("trafficd tls intercept listen failed: {err}"))
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
    let listener = build_intercept_listener(cfg.bind_addr)?;

    if let Some(tx) = cfg.startup_status_tx {
        let _ = tx.send(Ok(()));
    }

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(err) => {
                eprintln!("trafficd tls intercept accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let connector_h1 = connector_h1.clone();
        let connector_h2 = connector_h2.clone();
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
                    let lower = err.to_ascii_lowercase();
                    if lower.contains("timed out")
                        || lower.contains("failed")
                        || lower.contains("invalid")
                        || lower.contains("unsupported")
                        || lower.contains("no matching")
                    {
                        metrics.inc_svc_fail_closed("tls");
                    }
                    eprintln!("trafficd tls intercept connection error: {err}");
                }
                Err(_) => {
                    metrics.inc_svc_tls_intercept_flow("deny");
                    metrics.inc_svc_fail_closed("tls");
                    eprintln!("trafficd tls intercept task panicked");
                }
            }
        });
    }
}

async fn handle_tls_intercept_client(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    connector_h1: TlsConnector,
    connector_h2: TlsConnector,
    metrics: Metrics,
    policy_snapshot: Arc<RwLock<PolicySnapshot>>,
    intercept_demux: Arc<Mutex<SharedInterceptDemuxState>>,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
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

    let mut client_tls = tokio::time::timeout(TLS_IO_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| "tls intercept: client tls handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: client tls handshake failed: {err}"))?;
    let client_alpn = client_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|value| value.to_vec());

    if client_alpn.as_deref() == Some(b"h2") {
        return handle_tls_intercept_h2(
            client_tls,
            connector_h2,
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
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let upstream_tcp = tokio::time::timeout(TLS_IO_TIMEOUT, TcpStream::connect(upstream_addr))
        .await
        .map_err(|_| "tls intercept: upstream tcp connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tcp connect failed: {err}"))?;
    let server_name_raw = if host.is_empty() {
        upstream_addr.ip().to_string()
    } else {
        host.to_string()
    };
    let server_name = rustls::pki_types::ServerName::try_from(server_name_raw.clone())
        .map_err(|_| format!("tls intercept: invalid server name '{server_name_raw}'"))?;
    tokio::time::timeout(TLS_IO_TIMEOUT, connector.connect(server_name, upstream_tcp))
        .await
        .map_err(|_| "tls intercept: upstream tls connect timed out".to_string())?
        .map_err(|err| format!("tls intercept: upstream tls connect failed: {err}"))
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
    let req_bytes = tokio::time::timeout(TLS_IO_TIMEOUT, http_match::read_http_message(client_tls))
        .await
        .map_err(|_| "tls intercept: client request read timed out".to_string())??;
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
    let mut upstream_tls = connect_upstream_tls(connector, upstream_addr, &request.host).await?;
    upstream_tls
        .write_all(&request.raw)
        .await
        .map_err(|err| format!("tls intercept: upstream write failed: {err}"))?;

    let response_bytes = tokio::time::timeout(
        TLS_IO_TIMEOUT,
        http_match::read_http_message(&mut upstream_tls),
    )
    .await
    .map_err(|_| "tls intercept: upstream response read timed out".to_string())??;
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
                            let _ = respond.send_reset(h2::Reason::REFUSED_STREAM);
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

async fn handle_tls_intercept_h2(
    client_tls: tokio_rustls::server::TlsStream<TcpStream>,
    connector_h2: TlsConnector,
    metrics: Metrics,
    policy: Option<TlsInterceptHttpPolicy>,
    enforce_http_policy: bool,
    orig_dst: SocketAddr,
    upstream_override: Option<SocketAddr>,
) -> Result<(), String> {
    // Process one active stream per h2 connection.
    //
    // The intercept path performs full request/response inspection before
    // completing a stream. Allowing high stream concurrency can create flow
    // control stalls under load when large request bodies are in flight.
    let mut h2_builder = server::Builder::new();
    h2_builder.max_concurrent_streams(1);
    let mut client_conn = tokio::time::timeout(TLS_IO_TIMEOUT, h2_builder.handshake(client_tls))
        .await
        .map_err(|_| "tls intercept: h2 server handshake timed out".to_string())?
        .map_err(|err| format!("tls intercept: h2 server handshake failed: {err}"))?;
    let mut saw_request = false;
    loop {
        let next = if saw_request {
            match tokio::time::timeout(TLS_IO_TIMEOUT, client_conn.accept()).await {
                Ok(next) => next,
                Err(_) => {
                    // No additional streams arrived before timeout; close this
                    // intercept connection after the completed exchange.
                    client_conn.graceful_shutdown();
                    return Ok(());
                }
            }
        } else {
            tokio::time::timeout(TLS_IO_TIMEOUT, client_conn.accept())
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

        saw_request = true;
        let (request, mut respond) =
            next.map_err(|err| format!("tls intercept: h2 accept failed: {err}"))?;
        let parsed_request = http_match::parsed_request_from_h2(&request);
        let request_target = request
            .uri()
            .path_and_query()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let request_body =
            read_h2_request_body_with_conn_progress(&mut client_conn, request.into_body()).await?;

        let mut request_denied = false;
        if let Some(req_policy) = policy.as_ref().and_then(|policy| policy.request.as_ref()) {
            if !http_match::request_allowed(req_policy, &parsed_request) {
                request_denied = true;
                metrics.inc_svc_http_request("h2", "deny");
                metrics.inc_svc_http_deny("h2", "request", "policy");
                if enforce_http_policy {
                    metrics.inc_svc_policy_rst("request_policy");
                    metrics.inc_svc_fail_closed("tls");
                    return Err("tls intercept: h2 request denied by policy".to_string());
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
        let upstream_tls =
            connect_upstream_tls(connector_h2.clone(), upstream_addr, &upstream_host).await?;
        let (mut send_request, upstream_conn) =
            tokio::time::timeout(TLS_IO_TIMEOUT, client::handshake(upstream_tls))
                .await
                .map_err(|_| "tls intercept: h2 upstream handshake timed out".to_string())?
                .map_err(|err| format!("tls intercept: h2 upstream handshake failed: {err}"))?;
        tokio::spawn(async move {
            let _ = upstream_conn.await;
        });

        let upstream_req = http_match::request_for_upstream_h2(
            &parsed_request.method,
            &request_target,
            &upstream_host,
        )?;
        let end_of_stream = request_body.is_empty();
        let (response_fut, mut upstream_send_stream) = send_request
            .send_request(upstream_req, end_of_stream)
            .map_err(|err| format!("tls intercept: h2 upstream send failed: {err}"))?;
        if !request_body.is_empty() {
            upstream_send_stream
                .send_data(Bytes::from(request_body), true)
                .map_err(|err| format!("tls intercept: h2 upstream body send failed: {err}"))?;
        }

        let upstream_response = tokio::time::timeout(TLS_IO_TIMEOUT, response_fut)
            .await
            .map_err(|_| "tls intercept: h2 upstream response timed out".to_string())?
            .map_err(|err| format!("tls intercept: h2 upstream response failed: {err}"))?;
        let (upstream_parts, mut upstream_body) = upstream_response.into_parts();
        let upstream_header_response = Response::from_parts(upstream_parts, ());
        let parsed_response = http_match::parsed_response_from_h2(&upstream_header_response);
        if let Some(resp_policy) = policy.as_ref().and_then(|policy| policy.response.as_ref()) {
            if !http_match::response_allowed(resp_policy, &parsed_response) {
                metrics.inc_svc_http_deny("h2", "response", "policy");
                if enforce_http_policy {
                    metrics.inc_svc_policy_rst("response_policy");
                    metrics.inc_svc_fail_closed("tls");
                    return Err("tls intercept: h2 response denied by policy".to_string());
                }
            }
        }

        let downstream_response = http_match::response_from_upstream_h2(&upstream_header_response)?;
        let mut downstream_send = respond
            .send_response(downstream_response, upstream_body.is_end_stream())
            .map_err(|err| format!("tls intercept: h2 downstream send failed: {err}"))?;
        let mut body_bytes = 0usize;
        while let Some(next) = tokio::time::timeout(TLS_IO_TIMEOUT, upstream_body.data())
            .await
            .map_err(|_| "tls intercept: h2 upstream body read timed out".to_string())?
        {
            let chunk =
                next.map_err(|err| format!("tls intercept: h2 upstream body read failed: {err}"))?;
            body_bytes = body_bytes.saturating_add(chunk.len());
            if body_bytes > http_match::HTTP_MAX_BODY_BYTES {
                return Err("tls intercept: h2 response body exceeds max size".to_string());
            }
            downstream_send
                .send_data(chunk, upstream_body.is_end_stream())
                .map_err(|err| format!("tls intercept: h2 downstream body send failed: {err}"))?;
        }
    }
}
