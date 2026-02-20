use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::thread::JoinHandle;

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::controlplane::dns_proxy::extract_ips_from_dns_response;

#[derive(Debug)]
pub struct UpstreamServices {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    pub dns_addr: SocketAddr,
    pub http_addr: SocketAddr,
    pub https_addr: SocketAddr,
    pub answer_ip: Ipv4Addr,
}

impl UpstreamServices {
    pub fn start(
        ns: netns_rs::NetNs,
        dns_addr: SocketAddr,
        http_addr: SocketAddr,
        https_addr: SocketAddr,
        answer_ip: Ipv4Addr,
    ) -> Result<Self, String> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread = std::thread::spawn(move || {
            let _ = ns.run(|_| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("tokio runtime error: {e}"))?;
                rt.block_on(async move {
                    let dns_task = tokio::spawn(run_dns_server(dns_addr, answer_ip));
                    let http_task = tokio::spawn(run_http_server(http_addr));
                    let https_task = tokio::spawn(run_https_server(https_addr));

                    let _ = shutdown_rx.await;
                    dns_task.abort();
                    http_task.abort();
                    https_task.abort();
                    Ok::<(), String>(())
                })
            });
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
            dns_addr,
            http_addr,
            https_addr,
            answer_ip,
        })
    }
}

impl Drop for UpstreamServices {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

async fn run_dns_server(bind: SocketAddr, answer_ip: Ipv4Addr) -> Result<(), String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("dns bind failed: {e}"))?;
    let mut buf = vec![0u8; 512];
    loop {
        let (len, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("dns recv failed: {e}"))?;
        let request = &buf[..len];
        let response = build_dns_response(request, answer_ip);
        if let Some(resp) = response {
            socket
                .send_to(&resp, peer)
                .await
                .map_err(|e| format!("dns send failed: {e}"))?;
        }
    }
}

fn build_dns_response(request: &[u8], answer_ip: Ipv4Addr) -> Option<Vec<u8>> {
    if request.len() < 12 {
        return None;
    }
    let mut idx = 12;
    let name = parse_qname(request, &mut idx)?;
    if idx + 4 > request.len() {
        return None;
    }
    let qdcount = request[4..6].to_vec();
    let qsection = &request[12..idx + 4];

    let mut resp = Vec::new();
    resp.extend_from_slice(&request[0..2]); // transaction ID
    if name.eq_ignore_ascii_case("foo.allowed") {
        resp.extend_from_slice(&[0x81, 0x80]); // standard response
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x01]); // ancount
    } else {
        resp.extend_from_slice(&[0x81, 0x83]); // NXDOMAIN
        resp.extend_from_slice(&qdcount);
        resp.extend_from_slice(&[0x00, 0x00]); // ancount
    }
    resp.extend_from_slice(&[0x00, 0x00]); // nscount
    resp.extend_from_slice(&[0x00, 0x00]); // arcount
    resp.extend_from_slice(qsection);

    if name.eq_ignore_ascii_case("foo.allowed") {
        resp.extend_from_slice(&[0xc0, 0x0c]); // name ptr
        resp.extend_from_slice(&[0x00, 0x01]); // type A
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // ttl 30
        resp.extend_from_slice(&[0x00, 0x04]); // rdlen
        resp.extend_from_slice(&answer_ip.octets());
    }
    Some(resp)
}

fn parse_qname(buf: &[u8], idx: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    while *idx < buf.len() {
        let len = buf[*idx] as usize;
        *idx += 1;
        if len == 0 {
            return Some(labels.join("."));
        }
        if *idx + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[*idx..*idx + len]).to_string());
        *idx += len;
    }
    None
}

async fn run_http_server(bind: SocketAddr) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("http bind failed: {e}"))?;
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("http accept failed: {e}"))?;
        tokio::spawn(async move {
            let _ = handle_http(&mut stream).await;
        });
    }
}

async fn run_https_server(bind: SocketAddr) -> Result<(), String> {
    let cert = generate_simple_self_signed(vec!["foo.allowed".to_string()])
        .map_err(|e| format!("cert gen failed: {e}"))?;
    let cert_der = CertificateDer::from(cert.serialize_der().map_err(|e| e.to_string())?);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        cert.serialize_private_key_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("tls server config failed: {e}"))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("https bind failed: {e}"))?;
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| format!("https accept failed: {e}"))?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Ok(mut tls) = acceptor.accept(stream).await {
                let _ = handle_http(&mut tls).await;
            }
        });
    }
}

async fn handle_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: &mut S) -> Result<(), String> {
    let mut buf = [0u8; 1024];
    let _ = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    let body = b"ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(body)
        .await
        .map_err(|e| e.to_string())?;
    let _ = stream.shutdown().await;
    Ok(())
}

pub async fn dns_query(
    bind: SocketAddr,
    server: SocketAddr,
    name: &str,
) -> Result<Vec<IpAddr>, String> {
    let socket = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("dns client bind failed: {e}"))?;
    let query = build_dns_query(name);
    socket
        .send_to(&query, server)
        .await
        .map_err(|e| format!("dns client send failed: {e}"))?;
    let mut buf = vec![0u8; 512];
    let (len, _) = socket
        .recv_from(&mut buf)
        .await
        .map_err(|e| format!("dns client recv failed: {e}"))?;
    Ok(extract_ips_from_dns_response(&buf[..len]))
}

fn build_dns_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x12, 0x34]); // id
    msg.extend_from_slice(&[0x01, 0x00]); // flags
    msg.extend_from_slice(&[0x00, 0x01]); // qdcount
    msg.extend_from_slice(&[0x00, 0x00]); // ancount
    msg.extend_from_slice(&[0x00, 0x00]); // nscount
    msg.extend_from_slice(&[0x00, 0x00]); // arcount
    for label in name.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&[0x00, 0x01]); // qtype A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass IN
    msg
}

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

pub async fn http_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("http connect failed: {e}"))?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("http write failed: {e}"))?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("http read failed: {e}"))?;
    let text = String::from_utf8_lossy(&buf).to_string();
    Ok(text)
}

pub async fn https_get(addr: SocketAddr, host: &str) -> Result<String, String> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("https connect failed: {e}"))?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| "invalid server name".to_string())?;
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("tls connect failed: {e}"))?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("https write failed: {e}"))?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("https read failed: {e}"))?;
    Ok(String::from_utf8_lossy(&buf).to_string())
}
