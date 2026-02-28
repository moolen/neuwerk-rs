use std::fs;
use std::path::{Path, PathBuf};

use crate::controlplane::cluster::bootstrap::ca::{decrypt_ca_key, CaEnvelope, CaSigner};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::store::ClusterStore;

pub(crate) const INTERCEPT_CA_CERT_KEY: &[u8] = b"settings/tls_intercept/ca_cert_pem";
pub(crate) const INTERCEPT_CA_ENVELOPE_KEY: &[u8] = b"settings/tls_intercept/ca_key_envelope";

const INTERCEPT_CA_CERT_FILENAME: &str = "intercept-ca.crt";
const INTERCEPT_CA_KEY_FILENAME: &str = "intercept-ca.key";

pub fn local_intercept_ca_paths(tls_dir: &Path) -> (PathBuf, PathBuf) {
    (
        tls_dir.join(INTERCEPT_CA_CERT_FILENAME),
        tls_dir.join(INTERCEPT_CA_KEY_FILENAME),
    )
}

pub fn load_local_intercept_ca_pair(tls_dir: &Path) -> Result<Option<(Vec<u8>, Vec<u8>)>, String> {
    let (cert_path, key_path) = local_intercept_ca_paths(tls_dir);
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    if cert_exists != key_exists {
        return Err(
            "missing http-tls/intercept-ca.key; restart in local mode to write a complete intercept CA pair before migration".to_string(),
        );
    }
    if !cert_exists {
        return Ok(None);
    }
    let cert = fs::read(cert_path).map_err(|err| err.to_string())?;
    let key = fs::read(key_path).map_err(|err| err.to_string())?;
    Ok(Some((cert, key)))
}

pub fn has_intercept_ca_material(
    tls_dir: &Path,
    store: Option<&ClusterStore>,
) -> Result<bool, String> {
    if let Some(store) = store {
        let cert_present = store.get_state_value(INTERCEPT_CA_CERT_KEY)?.is_some();
        let envelope_present = store.get_state_value(INTERCEPT_CA_ENVELOPE_KEY)?.is_some();
        if cert_present != envelope_present {
            return Err("cluster tls intercept ca material is incomplete".to_string());
        }
        return Ok(cert_present);
    }
    Ok(load_local_intercept_ca_pair(tls_dir)?.is_some())
}

#[derive(Clone)]
pub enum InterceptCaSource {
    Local {
        tls_dir: PathBuf,
    },
    Cluster {
        store: ClusterStore,
        token_path: PathBuf,
    },
}

pub fn load_intercept_ca_signer(source: &InterceptCaSource) -> Result<CaSigner, String> {
    match source {
        InterceptCaSource::Local { tls_dir } => {
            let Some((cert, key)) = load_local_intercept_ca_pair(tls_dir)? else {
                return Err("missing local tls intercept ca material".to_string());
            };
            CaSigner::from_cert_and_key(&cert, &key).map_err(|err| err.to_string())
        }
        InterceptCaSource::Cluster { store, token_path } => {
            let cert = store
                .get_state_value(INTERCEPT_CA_CERT_KEY)?
                .ok_or_else(|| "missing cluster tls intercept ca cert".to_string())?;
            let encoded = store
                .get_state_value(INTERCEPT_CA_ENVELOPE_KEY)?
                .ok_or_else(|| "missing cluster tls intercept ca key envelope".to_string())?;
            let envelope: CaEnvelope =
                bincode::deserialize(&encoded).map_err(|err| err.to_string())?;
            let token_store = TokenStore::load(token_path).map_err(
                |err: crate::controlplane::cluster::bootstrap::token::TokenError| err.to_string(),
            )?;
            let token = token_store
                .get(&envelope.kid)
                .ok_or_else(|| "missing token for tls intercept ca envelope".to_string())?;
            let key = decrypt_ca_key(&envelope, &token.token).map_err(|err| err.to_string())?;
            CaSigner::from_cert_and_key(&cert, &key).map_err(|err| err.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_local_pair_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let value = load_local_intercept_ca_pair(dir.path()).unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn load_local_pair_errors_on_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, _key_path) = local_intercept_ca_paths(dir.path());
        std::fs::write(cert_path, b"cert").unwrap();
        let err = load_local_intercept_ca_pair(dir.path()).unwrap_err();
        assert!(err.contains("intercept-ca.key"));
    }

    #[test]
    fn has_material_uses_local_pair() {
        let dir = tempfile::tempdir().unwrap();
        let (cert_path, key_path) = local_intercept_ca_paths(dir.path());
        std::fs::write(cert_path, b"cert").unwrap();
        std::fs::write(key_path, b"key").unwrap();
        let value = has_intercept_ca_material(dir.path(), None).unwrap();
        assert!(value);
    }
}
