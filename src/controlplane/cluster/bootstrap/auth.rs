use std::net::SocketAddr;

use hmac::{Hmac, Mac};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::Sha256;
use uuid::Uuid;

use crate::controlplane::cluster::types::{JoinRequest, JoinResponse};

const JOIN_REQUEST_CONTEXT: &[u8] = b"neuwerk.cluster.join.request.v1";
const JOIN_RESPONSE_CONTEXT: &[u8] = b"neuwerk.cluster.join.response.v2";
const JOIN_KEY_CONTEXT: &[u8] = b"neuwerk.cluster.join.key.v1";
const JOIN_ENCRYPT_CONTEXT: &[u8] = b"neuwerk.cluster.join.encrypt.v1";

pub(super) fn build_join_request_hmac(
    psk: &[u8],
    node_id: Uuid,
    endpoint: SocketAddr,
    nonce: &[u8],
    csr: &[u8],
) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk)
        .map_err(|err| format!("join request hmac init failed: {err}"))?;
    mac.update(JOIN_REQUEST_CONTEXT);
    update_join_request_material(&mut mac, node_id, endpoint, nonce, csr);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn verify_join_request_hmac(psk: &[u8], req: &JoinRequest) -> Result<(), String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk).map_err(|_| "invalid hmac key")?;
    mac.update(JOIN_REQUEST_CONTEXT);
    update_join_request_material(&mut mac, req.node_id, req.endpoint, &req.nonce, &req.csr);
    mac.verify_slice(&req.psk_hmac)
        .map_err(|_| "invalid psk hmac".to_string())
}

pub(super) fn encrypt_join_response_payload(
    psk: &[u8],
    req: &JoinRequest,
    signed_cert: &[u8],
    ca_cert: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), String> {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&rand::random::<[u8; 12]>());
    let key = derive_join_key(psk, req)?;
    let sealing_key = build_aead_key(&key)?;

    let mut plaintext = encode_payload(signed_cert, ca_cert);
    let aad = build_join_aad(req);
    sealing_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut plaintext,
        )
        .map_err(|_| "join response encrypt failed".to_string())?;
    Ok((plaintext, nonce))
}

pub(super) fn decrypt_join_response_payload(
    psk: &[u8],
    req: &JoinRequest,
    encrypted_payload: &[u8],
    payload_nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if payload_nonce.len() != 12 {
        return Err("invalid join payload nonce".to_string());
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(payload_nonce);
    let key = derive_join_key(psk, req)?;
    let opening_key = build_aead_key(&key)?;
    let aad = build_join_aad(req);

    let mut ciphertext = encrypted_payload.to_vec();
    let plaintext = opening_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| "join response decrypt failed".to_string())?;
    decode_payload(plaintext)
}

pub(super) fn build_join_response_hmac(
    psk: &[u8],
    req: &JoinRequest,
    encrypted_payload: &[u8],
    payload_nonce: &[u8],
) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk)
        .map_err(|err| format!("join response hmac init failed: {err}"))?;
    mac.update(JOIN_RESPONSE_CONTEXT);
    update_join_request_material(&mut mac, req.node_id, req.endpoint, &req.nonce, &req.csr);
    update_len_prefixed(&mut mac, encrypted_payload);
    update_len_prefixed(&mut mac, payload_nonce);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub(super) fn verify_join_response_hmac(
    psk: &[u8],
    req: &JoinRequest,
    resp: &JoinResponse,
) -> Result<(), String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk)
        .map_err(|err| format!("join response hmac init failed: {err}"))?;
    mac.update(JOIN_RESPONSE_CONTEXT);
    update_join_request_material(&mut mac, req.node_id, req.endpoint, &req.nonce, &req.csr);
    update_len_prefixed(&mut mac, &resp.encrypted_payload);
    update_len_prefixed(&mut mac, &resp.payload_nonce);
    mac.verify_slice(&resp.response_hmac)
        .map_err(|_| "invalid join response hmac".to_string())
}

fn derive_join_key(psk: &[u8], req: &JoinRequest) -> Result<[u8; 32], String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk)
        .map_err(|err| format!("join key derive init failed: {err}"))?;
    mac.update(JOIN_KEY_CONTEXT);
    update_join_request_material(&mut mac, req.node_id, req.endpoint, &req.nonce, &req.csr);
    let digest = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn build_aead_key(key: &[u8; 32]) -> Result<LessSafeKey, String> {
    let unbound = UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map_err(|_| "join aead key init failed".to_string())?;
    Ok(LessSafeKey::new(unbound))
}

fn build_join_aad(req: &JoinRequest) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(JOIN_ENCRYPT_CONTEXT);
    append_len_prefixed(&mut aad, req.node_id.as_bytes());
    append_len_prefixed(&mut aad, req.endpoint.to_string().as_bytes());
    append_len_prefixed(&mut aad, &req.nonce);
    append_len_prefixed(&mut aad, &req.csr);
    aad
}

fn encode_payload(signed_cert: &[u8], ca_cert: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + signed_cert.len() + ca_cert.len());
    append_len_prefixed(&mut out, signed_cert);
    append_len_prefixed(&mut out, ca_cert);
    out
}

fn decode_payload(payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (signed_cert, used) = take_len_prefixed(payload, 0)?;
    let (ca_cert, used2) = take_len_prefixed(payload, used)?;
    if used2 != payload.len() {
        return Err("invalid encrypted join payload".to_string());
    }
    Ok((signed_cert.to_vec(), ca_cert.to_vec()))
}

fn update_join_request_material(
    mac: &mut Hmac<Sha256>,
    node_id: Uuid,
    endpoint: SocketAddr,
    nonce: &[u8],
    csr: &[u8],
) {
    update_len_prefixed(mac, node_id.as_bytes());
    update_len_prefixed(mac, endpoint.to_string().as_bytes());
    update_len_prefixed(mac, nonce);
    update_len_prefixed(mac, csr);
}

fn update_len_prefixed(mac: &mut Hmac<Sha256>, value: &[u8]) {
    let len = value.len() as u64;
    mac.update(&len.to_be_bytes());
    mac.update(value);
}

fn append_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    let len = value.len() as u64;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(value);
}

fn take_len_prefixed<'a>(buf: &'a [u8], offset: usize) -> Result<(&'a [u8], usize), String> {
    if offset + 8 > buf.len() {
        return Err("invalid encrypted join payload".to_string());
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&buf[offset..offset + 8]);
    let len = u64::from_be_bytes(raw) as usize;
    let start = offset + 8;
    let end = start + len;
    if end > buf.len() {
        return Err("invalid encrypted join payload".to_string());
    }
    Ok((&buf[start..end], end))
}
