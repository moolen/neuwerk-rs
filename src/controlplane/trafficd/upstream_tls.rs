use std::sync::Arc;

use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamTlsVerificationMode {
    Strict,
    Insecure,
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

pub(super) fn build_insecure_tls_connector(alpn_protocols: Vec<Vec<u8>>) -> TlsConnector {
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    TlsConnector::from(Arc::new(config))
}

pub(super) fn build_tls_connector(
    alpn_protocols: Vec<Vec<u8>>,
    verify_mode: UpstreamTlsVerificationMode,
) -> Result<TlsConnector, String> {
    match verify_mode {
        UpstreamTlsVerificationMode::Strict => build_strict_tls_connector(alpn_protocols),
        UpstreamTlsVerificationMode::Insecure => Ok(build_insecure_tls_connector(alpn_protocols)),
    }
}

fn build_strict_tls_connector(alpn_protocols: Vec<Vec<u8>>) -> Result<TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native_roots = rustls_native_certs::load_native_certs()
        .map_err(|err| format!("tls intercept: load native roots failed: {err}"))?;
    let mut added = 0usize;
    for cert in native_roots {
        if roots.add(cert).is_ok() {
            added = added.saturating_add(1);
        }
    }
    if added == 0 {
        return Err("tls intercept: no valid native root certificates available".to_string());
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    Ok(TlsConnector::from(Arc::new(config)))
}

pub(super) fn parse_upstream_tls_verify_mode(raw: Option<&str>) -> UpstreamTlsVerificationMode {
    match raw {
        Some(value) if value.eq_ignore_ascii_case("insecure") => {
            UpstreamTlsVerificationMode::Insecure
        }
        _ => UpstreamTlsVerificationMode::Strict,
    }
}

pub(super) fn upstream_tls_verify_mode_from_env() -> UpstreamTlsVerificationMode {
    let raw = std::env::var("NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY").ok();
    let mode = parse_upstream_tls_verify_mode(raw.as_deref());
    if let Some(value) = raw {
        if !value.eq_ignore_ascii_case("strict") && !value.eq_ignore_ascii_case("insecure") {
            eprintln!(
                "trafficd tls intercept: unknown NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY='{value}', defaulting to strict"
            );
        }
    }
    mode
}
