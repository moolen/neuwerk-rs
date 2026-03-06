use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::controlplane::cluster::bootstrap::ca::CaSigner;
use tokio_rustls::TlsAcceptor;

#[derive(Debug)]
struct CachedCertifiedKey {
    key: Arc<rustls::sign::CertifiedKey>,
    minted_at: Instant,
}

#[derive(Debug)]
pub(super) struct InterceptLeafCertResolver {
    ca_cert_pem: Vec<u8>,
    ca_key_der: Vec<u8>,
    ttl: Duration,
    max_entries: usize,
    cache: Mutex<HashMap<String, CachedCertifiedKey>>,
}

impl InterceptLeafCertResolver {
    pub(super) fn new(
        ca_cert_pem: Vec<u8>,
        ca_key_der: Vec<u8>,
        ttl: Duration,
        max_entries: usize,
    ) -> Result<Self, String> {
        CaSigner::from_cert_and_key(&ca_cert_pem, &ca_key_der)
            .map_err(|err| format!("tls intercept: invalid ca material: {err}"))?;
        Ok(Self {
            ca_cert_pem,
            ca_key_der,
            ttl,
            max_entries: max_entries.max(1),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn resolve_server_name(
        &self,
        requested: Option<&str>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = canonical_intercept_server_name(requested);
        let mut cache = self.cache.lock().ok()?;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.minted_at) <= self.ttl);
        if let Some(entry) = cache.get(&name) {
            return Some(entry.key.clone());
        }
        let minted = self.mint_certified_key(&name).ok()?;
        if cache.len() >= self.max_entries {
            evict_oldest_cached_cert(&mut cache);
        }
        cache.insert(
            name,
            CachedCertifiedKey {
                key: minted.clone(),
                minted_at: now,
            },
        );
        Some(minted)
    }

    fn mint_certified_key(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
        let signer = CaSigner::from_cert_and_key(&self.ca_cert_pem, &self.ca_key_der)
            .map_err(|err| format!("tls intercept: invalid ca material: {err}"))?;
        let (cert_chain_der, key_der) = mint_intercept_server_cert_for_host(&signer, host)?;
        certified_key_from_der(cert_chain_der, key_der)
    }
}

impl rustls::server::ResolvesServerCert for InterceptLeafCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.resolve_server_name(client_hello.server_name())
    }
}

#[cfg(test)]
pub(super) fn build_tls_acceptor(
    cert_chain_der: &[Vec<u8>],
    key_der: &[u8],
) -> Result<TlsAcceptor, String> {
    if cert_chain_der.is_empty() {
        return Err("tls intercept requires at least one cert in chain".to_string());
    }
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain_der
        .iter()
        .cloned()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der.to_vec(),
    ));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| format!("tls intercept server config failed: {err}"))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub(super) fn build_tls_intercept_acceptor(
    ca_cert_pem: &[u8],
    ca_key_der: &[u8],
    ttl: Duration,
    max_entries: usize,
) -> Result<TlsAcceptor, String> {
    let resolver = InterceptLeafCertResolver::new(
        ca_cert_pem.to_vec(),
        ca_key_der.to_vec(),
        ttl,
        max_entries,
    )?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn certified_key_from_der(
    cert_chain_der: Vec<Vec<u8>>,
    key_der: Vec<u8>,
) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
    if cert_chain_der.is_empty() {
        return Err("tls intercept: minted leaf cert is empty".to_string());
    }
    let cert_chain: Vec<rustls::pki_types::CertificateDer<'static>> = cert_chain_der
        .into_iter()
        .map(rustls::pki_types::CertificateDer::from)
        .collect();
    let key = rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
        key_der,
    ));
    let provider = rustls::crypto::ring::default_provider();
    let certified = rustls::sign::CertifiedKey::from_der(cert_chain, key, &provider)
        .map_err(|err| format!("tls intercept: invalid certified key: {err}"))?;
    Ok(Arc::new(certified))
}

fn canonical_intercept_server_name(requested: Option<&str>) -> String {
    let Some(raw) = requested else {
        return "intercept.local".to_string();
    };
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return "intercept.local".to_string();
    }
    if rustls::pki_types::ServerName::try_from(trimmed.clone()).is_err() {
        return "intercept.local".to_string();
    }
    trimmed
}

fn evict_oldest_cached_cert(cache: &mut HashMap<String, CachedCertifiedKey>) {
    let mut oldest_key: Option<String> = None;
    let mut oldest_time = Instant::now();
    for (name, entry) in cache.iter() {
        if oldest_key.is_none() || entry.minted_at <= oldest_time {
            oldest_key = Some(name.clone());
            oldest_time = entry.minted_at;
        }
    }
    if let Some(name) = oldest_key {
        cache.remove(&name);
    }
}

fn mint_intercept_server_cert_for_host(
    ca_signer: &CaSigner,
    host: &str,
) -> Result<(Vec<Vec<u8>>, Vec<u8>), String> {
    use rcgen::{Certificate, CertificateParams, DnType};
    let host = canonical_intercept_server_name(Some(host));
    let mut params = CertificateParams::new(vec![host.clone()]);
    params.distinguished_name.push(DnType::CommonName, &host);
    let leaf = Certificate::from_params(params).map_err(|err| err.to_string())?;
    let csr = leaf
        .serialize_request_der()
        .map_err(|err| err.to_string())?;
    let leaf_pem = ca_signer.sign_csr(&csr).map_err(|err| err.to_string())?;
    let mut leaf_reader = std::io::BufReader::new(leaf_pem.as_slice());
    let leaf_chain = rustls_pemfile::certs(&mut leaf_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    if leaf_chain.is_empty() {
        return Err("tls intercept: minted leaf cert is empty".to_string());
    }
    let mut chain: Vec<Vec<u8>> = leaf_chain
        .into_iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect();
    let mut ca_reader = std::io::BufReader::new(ca_signer.cert_pem());
    let ca_chain = rustls_pemfile::certs(&mut ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| err.to_string())?;
    for cert in ca_chain {
        chain.push(cert.as_ref().to_vec());
    }
    Ok((chain, leaf.serialize_private_key_der()))
}
