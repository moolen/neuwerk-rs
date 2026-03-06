use super::*;

pub(crate) async fn run_http_server(bind: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("http bind failed: {e}"))?;
    loop {
        let (mut stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("http accept failed: {e}"))?;
        tokio::spawn(async move {
            let _ = handle_http(&mut stream, peer).await;
        });
    }
}

pub(crate) async fn run_udp_echo_server(bind: SocketAddr) -> Result<(), String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("udp echo bind failed: {e}"))?;
    let mut buf = vec![0u8; 2048];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("udp echo recv failed: {e}"))?;
        socket
            .send_to(&buf[..len], peer)
            .await
            .map_err(|e| format!("udp echo send failed: {e}"))?;
    }
}

pub(crate) async fn run_https_server(
    bind: SocketAddr,
    tls: UpstreamTlsMaterial,
) -> Result<(), String> {
    crate::e2e::services::tls::ensure_rustls_provider();
    let cert_chain: Vec<CertificateDer<'static>> = tls
        .cert_chain
        .into_iter()
        .map(|cert| CertificateDer::from(cert).into_owned())
        .collect();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls.key_der));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| format!("tls server config failed: {e}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("https bind failed: {e}"))?;
    loop {
        let (stream, peer) = listener
            .accept()
            .await
            .map_err(|e| format!("https accept failed: {e}"))?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(tls) = acceptor.accept(stream).await {
                let alpn = tls.get_ref().1.alpn_protocol().map(|value| value.to_vec());
                if alpn.as_deref() == Some(b"h2") {
                    let _ = handle_http_h2(tls, peer).await;
                } else {
                    let mut tls = tls;
                    let _ = handle_http(&mut tls, peer).await;
                }
            }
        });
    }
}

fn response_body_for_path(
    path: &str,
    peer: SocketAddr,
) -> (StatusCode, Vec<(String, String)>, Vec<u8>) {
    if path == "/whoami" {
        return (
            StatusCode::OK,
            Vec::new(),
            peer.ip().to_string().into_bytes(),
        );
    }
    if path == "/external-secrets/forbidden-response" {
        return (
            StatusCode::OK,
            vec![("x-forbidden".to_string(), "1".to_string())],
            b"forbidden".to_vec(),
        );
    }
    if let Some(rest) = path.strip_prefix("/echo/") {
        return (StatusCode::OK, Vec::new(), rest.as_bytes().to_vec());
    }
    (StatusCode::OK, Vec::new(), b"ok".to_vec())
}

async fn handle_http_h2(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    peer: SocketAddr,
) -> Result<(), String> {
    let mut conn = server::handshake(tls)
        .await
        .map_err(|e| format!("https h2 server handshake failed: {e}"))?;
    while let Some(next) = conn.accept().await {
        let (request, mut respond) = next.map_err(|e| format!("https h2 accept failed: {e}"))?;
        let path = request
            .uri()
            .path_and_query()
            .map(|value| value.path())
            .unwrap_or("/");
        let (status, extra_headers, body) = response_body_for_path(path, peer);
        let mut response = Response::builder().status(status);
        for (name, value) in &extra_headers {
            response = response.header(name, value);
        }
        let response = response
            .body(())
            .map_err(|e| format!("https h2 response build failed: {e}"))?;
        let mut send = respond
            .send_response(response, body.is_empty())
            .map_err(|e| format!("https h2 send response failed: {e}"))?;
        if !body.is_empty() {
            send.send_data(Bytes::from(body), true)
                .map_err(|e| format!("https h2 send body failed: {e}"))?;
        }
    }
    Ok(())
}

async fn handle_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
) -> Result<(), String> {
    let mut buf = [0u8; 1024];
    let read = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    if read == 0 {
        return Ok(());
    }
    let req = String::from_utf8_lossy(&buf[..read]);
    let mut parts = req.split_whitespace();
    let _method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    if path == "/stream" || path == "/stream-long" {
        let chunk = vec![b'x'; 256];
        let chunks = if path == "/stream-long" {
            60usize
        } else {
            20usize
        };
        let total_len = chunk.len() * chunks;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            total_len
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        for _ in 0..chunks {
            stream.write_all(&chunk).await.map_err(|e| e.to_string())?;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = stream.shutdown().await;
        return Ok(());
    }

    if path == "/whoami" {
        let body = peer.ip().to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(response.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let _ = stream.shutdown().await;
        return Ok(());
    }

    let body_string;
    let body: &[u8] = if let Some(rest) = path.strip_prefix("/echo/") {
        body_string = rest.to_string();
        body_string.as_bytes()
    } else if path == "/external-secrets/forbidden-response" {
        b"forbidden"
    } else {
        b"ok"
    };
    let extra_headers = if path == "/external-secrets/forbidden-response" {
        "X-Forbidden: 1\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n",
        extra_headers,
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;
    let _ = stream.shutdown().await;
    Ok(())
}
