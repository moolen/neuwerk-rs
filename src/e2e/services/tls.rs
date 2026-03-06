use super::*;

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub(crate) fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn https_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path(addr, host, "/").await
}

pub async fn https_leaf_cert_sha256(addr: SocketAddr, host: &str) -> Result<[u8; 32], String> {
    ensure_rustls_provider();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "https connect timed out".to_string())?
        .map_err(|e| format!("https connect failed: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "tls connect timed out".to_string())?
    .map_err(|e| format!("tls connect failed: {e}"))?;
    let (_io, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| "tls peer certificate chain missing".to_string())?;
    let leaf = certs
        .first()
        .ok_or_else(|| "tls peer leaf certificate missing".to_string())?;
    let digest = Sha256::digest(leaf.as_ref());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

pub async fn https_get_path(addr: SocketAddr, host: &str, path: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, path, None).await
}

pub async fn https_get_tls12(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, "/", Some(&[&rustls::version::TLS12])).await
}

pub async fn https_get_tls13(addr: SocketAddr, host: &str) -> Result<String, String> {
    https_get_path_with_versions(addr, host, "/", Some(&[&rustls::version::TLS13])).await
}

pub async fn https_h2_preface(addr: SocketAddr, host: &str) -> Result<usize, String> {
    ensure_rustls_provider();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "https h2 connect timed out".to_string())?
        .map_err(|e| format!("https h2 connect failed: {e}"))?;

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "tls h2 connect timed out".to_string())?
    .map_err(|e| format!("tls h2 connect failed: {e}"))?;

    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let settings = [0u8, 0, 0, 4, 0, 0, 0, 0, 0];
    tls.write_all(preface)
        .await
        .map_err(|e| format!("https h2 preface write failed: {e}"))?;
    tls.write_all(&settings)
        .await
        .map_err(|e| format!("https h2 settings write failed: {e}"))?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), tls.read(&mut buf))
        .await
        .map_err(|_| "https h2 read timed out".to_string())?
        .map_err(|e| format!("https h2 read failed: {e}"))?;
    if n == 0 {
        return Err("https h2 peer closed".to_string());
    }
    Ok(n)
}

pub async fn https_h2_get_path(addr: SocketAddr, host: &str, path: &str) -> Result<String, String> {
    ensure_rustls_provider();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));

    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "https h2 connect timed out".to_string())?
        .map_err(|e| format!("https h2 connect failed: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let tls = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "tls h2 connect timed out".to_string())?
    .map_err(|e| format!("tls h2 connect failed: {e}"))?;

    let (mut send_request, connection) =
        tokio::time::timeout(std::time::Duration::from_secs(3), client::handshake(tls))
            .await
            .map_err(|_| "https h2 handshake timed out".to_string())?
            .map_err(|e| format!("https h2 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri(path)
        .header("host", host)
        .body(())
        .map_err(|e| format!("https h2 request build failed: {e}"))?;
    let (response_fut, _) = send_request
        .send_request(request, true)
        .map_err(|e| format!("https h2 request send failed: {e}"))?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(3), response_fut)
        .await
        .map_err(|_| "https h2 response timed out".to_string())?
        .map_err(|e| format!("https h2 response failed: {e}"))?;
    let status = response.status();
    let mut body = Vec::new();
    let mut recv = response.into_body();
    while let Some(next) = recv.data().await {
        let chunk = next.map_err(|e| format!("https h2 body read failed: {e}"))?;
        body.extend_from_slice(&chunk);
    }
    Ok(format!(
        "HTTP/2 {}\r\n\r\n{}",
        status.as_u16(),
        String::from_utf8_lossy(&body)
    ))
}

async fn https_get_path_with_versions(
    addr: SocketAddr,
    host: &str,
    path: &str,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> Result<String, String> {
    ensure_rustls_provider();
    let builder = match versions {
        Some(versions) => rustls::ClientConfig::builder_with_protocol_versions(versions),
        None => rustls::ClientConfig::builder(),
    };
    let config = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
        .await
        .map_err(|_| "https connect timed out".to_string())?
        .map_err(|e| format!("https connect failed: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| "tls connect timed out".to_string())?
    .map_err(|e| format!("tls connect failed: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("https write failed: {e}"))?;
    let mut buf = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), tls.read_to_end(&mut buf))
        .await
        .map_err(|_| "https read timed out".to_string())?
        .map_err(|e| format!("https read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}

pub async fn tls_client_hello_raw(
    addr: SocketAddr,
    sni: &str,
    padding_len: usize,
) -> Result<usize, String> {
    ensure_rustls_provider();
    let mut stream =
        tokio::time::timeout(std::time::Duration::from_secs(3), TcpStream::connect(addr))
            .await
            .map_err(|_| "tls raw connect timed out".to_string())?
            .map_err(|e| format!("tls raw connect failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    let record = build_client_hello_record(sni, padding_len)?;

    let mut offset = 0usize;
    let chunk = 1024usize;
    while offset < record.len() {
        let end = (offset + chunk).min(record.len());
        stream
            .write_all(&record[offset..end])
            .await
            .map_err(|e| format!("tls raw write failed: {e}"))?;
        offset = end;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let mut buf = vec![0u8; 2048];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| "tls raw read timed out".to_string())?
        .map_err(|e| format!("tls raw read failed: {e}"))?;
    Ok(read)
}

fn build_client_hello_record(sni: &str, padding_len: usize) -> Result<Vec<u8>, String> {
    let sni_bytes = sni.as_bytes();
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0u16.to_be_bytes());
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    if padding_len > 0 {
        if padding_len > u16::MAX as usize {
            return Err("padding too large".to_string());
        }
        extensions.extend_from_slice(&0x0015u16.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.extend_from_slice(&vec![0u8; padding_len]);
    }

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(1);
    handshake.push(((body.len() >> 16) & 0xff) as u8);
    handshake.push(((body.len() >> 8) & 0xff) as u8);
    handshake.push((body.len() & 0xff) as u8);
    handshake.extend_from_slice(&body);

    let mut record = Vec::new();
    record.push(22);
    record.extend_from_slice(&0x0303u16.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}
