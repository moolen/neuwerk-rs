use ring::aead;
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroize;

use rcgen::{Certificate, CertificateParams, KeyPair};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CaEnvelope {
    pub kid: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

pub struct CaSigner {
    cert: Certificate,
    cert_pem: Vec<u8>,
    key_der: Vec<u8>,
}

impl CaSigner {
    pub fn new(cert: Certificate) -> Result<Self, rcgen::Error> {
        let cert_pem = cert.serialize_pem()?.into_bytes();
        let key_der = cert.serialize_private_key_der();
        Ok(Self {
            cert,
            cert_pem,
            key_der,
        })
    }

    pub fn from_cert_and_key(cert_pem: &[u8], key_der: &[u8]) -> Result<Self, rcgen::Error> {
        let key_pair = KeyPair::from_der(key_der)?;
        let params = CertificateParams::from_ca_cert_pem(
            std::str::from_utf8(cert_pem).map_err(|_| rcgen::Error::CouldNotParseCertificate)?,
            key_pair,
        )?;
        let cert = Certificate::from_params(params)?;
        Ok(Self {
            cert,
            cert_pem: cert_pem.to_vec(),
            key_der: key_der.to_vec(),
        })
    }

    pub fn sign_csr(&self, csr_der: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let csr = rcgen::CertificateSigningRequest::from_der(csr_der)?;
        let pem = csr.serialize_pem_with_signer(&self.cert)?;
        Ok(pem.into_bytes())
    }

    pub fn cert_pem(&self) -> &[u8] {
        &self.cert_pem
    }

    pub fn key_der(&self) -> &[u8] {
        &self.key_der
    }
}

impl Drop for CaSigner {
    fn drop(&mut self) {
        self.key_der.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CaEnvelopeError {
    #[error("invalid nonce length")]
    InvalidNonce,
    #[error("crypto error")]
    Crypto,
    #[error("rng error")]
    Rng,
}

pub fn encrypt_ca_key(kid: &str, psk: &[u8], ca_key: &[u8]) -> Result<CaEnvelope, CaEnvelopeError> {
    let rng = SystemRandom::new();
    let mut salt = vec![0u8; 32];
    let mut nonce = vec![0u8; 12];
    rng.fill(&mut salt).map_err(|_| CaEnvelopeError::Rng)?;
    rng.fill(&mut nonce).map_err(|_| CaEnvelopeError::Rng)?;

    let key = derive_key(psk, &salt)?;
    let sealing_key = aead::LessSafeKey::new(key);
    let aad = aead::Aad::empty();

    let mut in_out = ca_key.to_vec();
    sealing_key
        .seal_in_place_append_tag(
            aead::Nonce::try_assume_unique_for_key(&nonce)
                .map_err(|_| CaEnvelopeError::InvalidNonce)?,
            aad,
            &mut in_out,
        )
        .map_err(|_| CaEnvelopeError::Crypto)?;

    Ok(CaEnvelope {
        kid: kid.to_string(),
        salt,
        nonce,
        ciphertext: in_out,
    })
}

pub fn decrypt_ca_key(envelope: &CaEnvelope, psk: &[u8]) -> Result<Vec<u8>, CaEnvelopeError> {
    let key = derive_key(psk, &envelope.salt)?;
    let opening_key = aead::LessSafeKey::new(key);
    let nonce = aead::Nonce::try_assume_unique_for_key(&envelope.nonce)
        .map_err(|_| CaEnvelopeError::InvalidNonce)?;
    let aad = aead::Aad::empty();
    let mut in_out = envelope.ciphertext.clone();
    let plaintext = opening_key
        .open_in_place(nonce, aad, &mut in_out)
        .map_err(|_| CaEnvelopeError::Crypto)?;
    Ok(plaintext.to_vec())
}

fn derive_key(psk: &[u8], salt: &[u8]) -> Result<aead::UnboundKey, CaEnvelopeError> {
    let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = hkdf_salt.extract(psk);
    let okm = prk
        .expand(&[b"neuwerk-ca-envelope"], &aead::CHACHA20_POLY1305)
        .map_err(|_| CaEnvelopeError::Crypto)?;
    let mut key_bytes = [0u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| CaEnvelopeError::Crypto)?;
    let key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| CaEnvelopeError::Crypto)?;
    key_bytes.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let psk = b"super-secret";
        let ca_key = b"ca-private-key";
        let envelope = encrypt_ca_key("kid-1", psk, ca_key).unwrap();
        let plaintext = decrypt_ca_key(&envelope, psk).unwrap();
        assert_eq!(plaintext, ca_key);
    }
}
