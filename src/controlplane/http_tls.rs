use std::collections::HashSet;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;

use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, SanType};
use time::OffsetDateTime;

use crate::controlplane::cluster::bootstrap::ca::{
    decrypt_ca_key, encrypt_ca_key, CaEnvelope, CaSigner,
};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::{ClusterCommand, ClusterTypeConfig};

pub(crate) const HTTP_CA_CERT_KEY: &[u8] = b"http/ca/cert";
pub(crate) const HTTP_CA_ENVELOPE_KEY: &[u8] = b"http/ca/envelope";

#[derive(Clone)]
pub struct HttpTlsConfig {
    pub tls_dir: PathBuf,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub ca_path: Option<PathBuf>,
    pub ca_key_path: Option<PathBuf>,
    pub san_entries: Vec<String>,
    pub advertise_addr: SocketAddr,
    pub management_ip: IpAddr,
    pub token_path: PathBuf,
    pub raft: Option<openraft::Raft<ClusterTypeConfig>>,
    pub store: Option<ClusterStore>,
}

#[derive(Debug, Clone)]
pub struct HttpTlsMaterial {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_pem: Vec<u8>,
}

pub async fn ensure_http_tls(cfg: HttpTlsConfig) -> Result<HttpTlsMaterial, String> {
    ensure_rustls_provider();
    let paths = resolve_paths(&cfg);

    let mut cert_exists = paths.cert_path.exists();
    let mut key_exists = paths.key_path.exists();
    if cert_exists != key_exists {
        eprintln!("warning: http tls cert/key mismatch; removing and regenerating");
        if cert_exists {
            fs::remove_file(&paths.cert_path).map_err(|err| err.to_string())?;
        }
        if key_exists {
            fs::remove_file(&paths.key_path).map_err(|err| err.to_string())?;
        }
        cert_exists = paths.cert_path.exists();
        key_exists = paths.key_path.exists();
    }
    if cert_exists != key_exists {
        return Err("http tls: cert/key mismatch".to_string());
    }

    if cert_exists {
        let ca_pem = load_or_fetch_ca_cert(&paths, cfg.store.as_ref(), cfg.raft.as_ref()).await?;
        ensure_permissions(&paths.key_path, 0o600)?;
        if cfg.raft.is_none() && cfg.store.is_none() {
            if paths.ca_path.exists() && !paths.ca_key_path.exists() {
                eprintln!("warning: http tls ca.key missing; migration to cluster will require regenerating the HTTP CA");
            }
        }
        return Ok(HttpTlsMaterial {
            cert_path: paths.cert_path,
            key_path: paths.key_path,
            ca_pem,
        });
    }

    let sans = build_sans(cfg.management_ip, cfg.advertise_addr, &cfg.san_entries)?;

    if let (Some(raft), Some(store)) = (cfg.raft.clone(), cfg.store.clone()) {
        if store.get_state_value(HTTP_CA_CERT_KEY)?.is_some() {
            let ca_signer = load_http_ca_signer(&store, &cfg.token_path)?;
            let (csr, key_pem) = build_csr(sans)?;
            let cert_pem = ca_signer.sign_csr(&csr).map_err(|err| err.to_string())?;
            persist_tls_material(&paths, &key_pem, &cert_pem, ca_signer.cert_pem(), None)?;
            return Ok(HttpTlsMaterial {
                cert_path: paths.cert_path,
                key_path: paths.key_path,
                ca_pem: ca_signer.cert_pem().to_vec(),
            });
        }

        let ca_signer = build_ca_signer()?;
        let (csr, key_pem) = build_csr(sans)?;
        let cert_pem = ca_signer.sign_csr(&csr).map_err(|err| err.to_string())?;
        persist_tls_material(&paths, &key_pem, &cert_pem, ca_signer.cert_pem(), None)?;
        ensure_http_ca(&raft, &store, &cfg.token_path, ca_signer).await?;
        let ca_pem = fs::read(&paths.ca_path).map_err(|err| err.to_string())?;
        return Ok(HttpTlsMaterial {
            cert_path: paths.cert_path,
            key_path: paths.key_path,
            ca_pem,
        });
    }

    let ca_signer = match load_local_ca_signer(&paths)? {
        Some(signer) => signer,
        None => build_ca_signer()?,
    };
    let (csr, key_pem) = build_csr(sans)?;
    let cert_pem = ca_signer.sign_csr(&csr).map_err(|err| err.to_string())?;
    persist_tls_material(
        &paths,
        &key_pem,
        &cert_pem,
        ca_signer.cert_pem(),
        Some(ca_signer.key_der()),
    )?;

    Ok(HttpTlsMaterial {
        cert_path: paths.cert_path,
        key_path: paths.key_path,
        ca_pem: ca_signer.cert_pem().to_vec(),
    })
}

#[derive(Debug, Clone)]
struct HttpTlsPaths {
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_path: PathBuf,
    ca_key_path: PathBuf,
}

fn resolve_paths(cfg: &HttpTlsConfig) -> HttpTlsPaths {
    let cert_path = cfg
        .cert_path
        .clone()
        .unwrap_or_else(|| cfg.tls_dir.join("node.crt"));
    let key_path = cfg
        .key_path
        .clone()
        .unwrap_or_else(|| cfg.tls_dir.join("node.key"));
    let ca_path = cfg
        .ca_path
        .clone()
        .unwrap_or_else(|| cfg.tls_dir.join("ca.crt"));
    let ca_key_path = cfg
        .ca_key_path
        .clone()
        .unwrap_or_else(|| cfg.tls_dir.join("ca.key"));
    HttpTlsPaths {
        cert_path,
        key_path,
        ca_path,
        ca_key_path,
    }
}

fn load_local_ca_signer(paths: &HttpTlsPaths) -> Result<Option<CaSigner>, String> {
    let cert_exists = paths.ca_path.exists();
    let key_exists = paths.ca_key_path.exists();
    if cert_exists != key_exists {
        return Err("http tls: ca cert/key mismatch".to_string());
    }
    if !cert_exists {
        return Ok(None);
    }
    let ca_cert = fs::read(&paths.ca_path).map_err(|err| err.to_string())?;
    let ca_key = fs::read(&paths.ca_key_path).map_err(|err| err.to_string())?;
    CaSigner::from_cert_and_key(&ca_cert, &ca_key)
        .map(Some)
        .map_err(|err| err.to_string())
}

async fn load_or_fetch_ca_cert(
    paths: &HttpTlsPaths,
    store: Option<&ClusterStore>,
    raft: Option<&openraft::Raft<ClusterTypeConfig>>,
) -> Result<Vec<u8>, String> {
    if paths.ca_path.exists() {
        let pem = fs::read(&paths.ca_path).map_err(|err| err.to_string())?;
        if let (Some(raft), Some(store)) = (raft, store) {
            if store.get_state_value(HTTP_CA_CERT_KEY)?.is_none() {
                let cmd = ClusterCommand::Put {
                    key: HTTP_CA_CERT_KEY.to_vec(),
                    value: pem.clone(),
                };
                let _ = raft.client_write(cmd).await;
            }
        }
        return Ok(pem);
    }

    if let Some(store) = store {
        if let Some(pem) = store.get_state_value(HTTP_CA_CERT_KEY)? {
            if let Some(parent) = paths.ca_path.parent() {
                fs::create_dir_all(parent).map_err(|err| err.to_string())?;
            }
            fs::write(&paths.ca_path, &pem).map_err(|err| err.to_string())?;
            return Ok(pem);
        }
        return Err("missing http ca cert".to_string());
    }
    Ok(Vec::new())
}

async fn ensure_http_ca(
    raft: &openraft::Raft<ClusterTypeConfig>,
    store: &ClusterStore,
    token_path: &Path,
    ca_signer: CaSigner,
) -> Result<(), String> {
    if store.get_state_value(HTTP_CA_CERT_KEY)?.is_some() {
        return Ok(());
    }

    let token_store = TokenStore::load(token_path).map_err(|err| err.to_string())?;
    let token = token_store
        .current(OffsetDateTime::now_utc())
        .map_err(|err| err.to_string())?;

    let cert_pem = ca_signer.cert_pem().to_vec();
    let cmd = ClusterCommand::Put {
        key: HTTP_CA_CERT_KEY.to_vec(),
        value: cert_pem,
    };
    raft.client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let envelope = encrypt_ca_key(&token.kid, &token.token, ca_signer.key_der())
        .map_err(|err| err.to_string())?;
    let encoded = bincode::serialize(&envelope).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: HTTP_CA_ENVELOPE_KEY.to_vec(),
        value: encoded,
    };
    raft.client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    Ok(())
}

pub fn load_http_ca_signer(store: &ClusterStore, token_path: &Path) -> Result<CaSigner, String> {
    let ca_cert = store
        .get_state_value(HTTP_CA_CERT_KEY)?
        .ok_or_else(|| "missing http ca cert".to_string())?;
    let envelope = store
        .get_state_value(HTTP_CA_ENVELOPE_KEY)?
        .ok_or_else(|| "missing http ca envelope".to_string())?;
    let envelope: CaEnvelope = bincode::deserialize(&envelope).map_err(|err| err.to_string())?;
    let token_store = TokenStore::load(token_path).map_err(|err| err.to_string())?;
    let token = token_store
        .get(&envelope.kid)
        .ok_or_else(|| "missing token for http ca envelope".to_string())?;
    let ca_key = decrypt_ca_key(&envelope, &token.token).map_err(|err| err.to_string())?;
    CaSigner::from_cert_and_key(&ca_cert, &ca_key).map_err(|err| err.to_string())
}

fn build_sans(
    management_ip: IpAddr,
    advertise_addr: SocketAddr,
    extra: &[String],
) -> Result<Vec<SanType>, String> {
    let mut seen = HashSet::new();
    let mut sans = Vec::new();

    push_san_ip(management_ip, &mut seen, &mut sans);
    push_san_ip(advertise_addr.ip(), &mut seen, &mut sans);

    for entry in extra {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Ok(ip) = entry.parse::<IpAddr>() {
            push_san_ip(ip, &mut seen, &mut sans);
        } else {
            if seen.insert(entry.to_ascii_lowercase()) {
                sans.push(SanType::DnsName(entry.to_string()));
            }
        }
    }

    Ok(sans)
}

fn push_san_ip(ip: IpAddr, seen: &mut HashSet<String>, sans: &mut Vec<SanType>) {
    let key = ip.to_string();
    if seen.insert(key) {
        sans.push(SanType::IpAddress(ip));
    }
}

fn build_csr(sans: Vec<SanType>) -> Result<(Vec<u8>, String), String> {
    let mut params = CertificateParams::new(Vec::new());
    params.subject_alt_names = sans;
    let cert = Certificate::from_params(params).map_err(|err| err.to_string())?;
    let csr = cert
        .serialize_request_der()
        .map_err(|err| err.to_string())?;
    let key_pem = cert.serialize_private_key_pem();
    Ok((csr, key_pem))
}

fn build_ca_signer() -> Result<CaSigner, String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = Certificate::from_params(params).map_err(|err| err.to_string())?;
    CaSigner::new(cert).map_err(|err| err.to_string())
}

fn persist_tls_material(
    paths: &HttpTlsPaths,
    key_pem: &str,
    cert_pem: &[u8],
    ca_pem: &[u8],
    ca_key_der: Option<&[u8]>,
) -> Result<(), String> {
    if let Some(parent) = paths.cert_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    if let Some(parent) = paths.key_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    if let Some(parent) = paths.ca_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    if let Some(parent) = paths.ca_key_path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    write_with_mode(&paths.key_path, key_pem.as_bytes(), 0o600)?;
    write_with_mode(&paths.cert_path, cert_pem, 0o644)?;
    write_with_mode(&paths.ca_path, ca_pem, 0o644)?;
    if let Some(ca_key_der) = ca_key_der {
        write_with_mode(&paths.ca_key_path, ca_key_der, 0o600)?;
    }
    Ok(())
}

fn write_with_mode(path: &Path, contents: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|err| err.to_string())?;
    file.write_all(contents).map_err(|err| err.to_string())?;
    file.sync_all().map_err(|err| err.to_string())?;
    ensure_permissions(path, mode)?;
    Ok(())
}

fn ensure_permissions(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(path)
            .map_err(|err| err.to_string())?
            .permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn ensure_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
