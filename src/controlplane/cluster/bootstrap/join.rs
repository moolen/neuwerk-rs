use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeSet;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::controlplane::cluster::bootstrap::ca::{decrypt_ca_key, encrypt_ca_key, CaSigner};
use crate::controlplane::cluster::bootstrap::token::TokenStore;
use crate::controlplane::cluster::config::RetryConfig;
use crate::controlplane::cluster::rpc::JoinHandler;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::Node;
use crate::controlplane::cluster::types::{
    ClusterCommand, ClusterTypeConfig, JoinRequest, JoinResponse,
};

pub struct JoinService {
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
    token_path: PathBuf,
    node_id: u128,
    signer: Arc<Mutex<Option<CaSigner>>>,
    retry: RetryConfig,
}

impl JoinService {
    pub fn new(
        raft: openraft::Raft<ClusterTypeConfig>,
        store: ClusterStore,
        token_path: PathBuf,
        node_id: u128,
        signer: Arc<Mutex<Option<CaSigner>>>,
        retry: RetryConfig,
    ) -> Self {
        Self {
            raft,
            store,
            token_path,
            node_id,
            signer,
            retry,
        }
    }
}

#[async_trait::async_trait]
impl JoinHandler for JoinService {
    async fn handle_join(&self, req: JoinRequest) -> Result<JoinResponse, String> {
        let token_store = TokenStore::load(&self.token_path).map_err(|err| err.to_string())?;
        let now = OffsetDateTime::now_utc();
        let joiner_token = token_store
            .get(&req.kid)
            .ok_or_else(|| "unknown kid".to_string())?;
        if let Some(until) = joiner_token.valid_until {
            if until < now {
                return Err("token expired".to_string());
            }
        }

        verify_hmac(&joiner_token.token, &req)?;

        let node_id = req.node_id.as_u128();
        let node = Node {
            addr: req.endpoint.to_string(),
        };

        let mut signer_guard = self.signer.lock().await;
        if signer_guard.is_none() {
            let signer = load_signer(&self.store, &token_store, self.node_id)?;
            *signer_guard = Some(signer);
        }
        let signer = signer_guard
            .as_ref()
            .ok_or_else(|| "signer unavailable".to_string())?;
        let signed_cert = signer.sign_csr(&req.csr).map_err(|err| err.to_string())?;

        let envelope = encrypt_ca_key(&req.kid, &joiner_token.token, signer.key_der())
            .map_err(|err| err.to_string())?;

        let raft = self.raft.clone();
        let retry = self.retry.clone();
        tokio::spawn(async move {
            upsert_envelope_with_retry(raft.clone(), node_id, envelope, retry.clone()).await;
            promote_with_retry(raft, node_id, node, retry).await;
        });

        Ok(JoinResponse {
            signed_cert,
            ca_cert: signer.cert_pem().to_vec(),
        })
    }
}

async fn promote_with_retry(
    raft: openraft::Raft<ClusterTypeConfig>,
    node_id: u128,
    node: Node,
    retry: RetryConfig,
) {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let add_ok = raft.add_learner(node_id, node.clone(), true).await.is_ok();
        if add_ok {
            let metrics = raft.metrics().borrow().clone();
            let mut voters: BTreeSet<_> =
                metrics.membership_config.membership().voter_ids().collect();
            voters.insert(node_id);
            if raft.change_membership(voters, true).await.is_ok() {
                return;
            }
        }
        if attempt >= retry.max_attempts {
            return;
        }
        let delay = backoff_delay(attempt, retry.base_delay, retry.max_delay, retry.jitter_ms);
        sleep(delay).await;
    }
}

fn backoff_delay(attempt: u32, base: Duration, max: Duration, jitter_ms: u64) -> Duration {
    let exp = 2u64.saturating_pow(attempt.saturating_sub(1));
    let mut delay = base.saturating_mul(exp as u32);
    if delay > max {
        delay = max;
    }
    let jitter = rand::random::<u64>() % (jitter_ms + 1);
    delay + Duration::from_millis(jitter)
}

fn verify_hmac(psk: &[u8], req: &JoinRequest) -> Result<(), String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk).map_err(|_| "invalid hmac key")?;
    mac.update(req.node_id.as_bytes());
    mac.update(req.endpoint.to_string().as_bytes());
    mac.update(&req.nonce);
    mac.update(&req.csr);
    mac.verify_slice(&req.psk_hmac)
        .map_err(|_| "invalid psk hmac".to_string())
}

fn load_signer(
    store: &ClusterStore,
    token_store: &TokenStore,
    node_id: u128,
) -> Result<CaSigner, String> {
    let ca_cert = store
        .get_state_value(b"ca/cert")?
        .ok_or_else(|| "missing ca cert".to_string())?;
    let envelope_key = format!("ca/envelope/{}", node_id).into_bytes();
    let envelope_raw = store
        .get_state_value(&envelope_key)?
        .ok_or_else(|| "missing ca envelope".to_string())?;
    let envelope: crate::controlplane::cluster::bootstrap::ca::CaEnvelope =
        bincode::deserialize(&envelope_raw).map_err(|err| err.to_string())?;
    let token = token_store
        .get(&envelope.kid)
        .ok_or_else(|| "missing token for ca envelope".to_string())?;
    let ca_key = decrypt_ca_key(&envelope, &token.token).map_err(|err| err.to_string())?;
    CaSigner::from_cert_and_key(&ca_cert, &ca_key).map_err(|err| err.to_string())
}

async fn upsert_envelope_with_retry(
    raft: openraft::Raft<ClusterTypeConfig>,
    node_id: u128,
    envelope: crate::controlplane::cluster::bootstrap::ca::CaEnvelope,
    retry: RetryConfig,
) {
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let cmd = ClusterCommand::UpsertCaEnvelope {
            node_id,
            envelope: envelope.clone(),
        };
        if raft.client_write(cmd).await.is_ok() {
            return;
        }
        if attempt >= retry.max_attempts {
            return;
        }
        let delay = backoff_delay(attempt, retry.base_delay, retry.max_delay, retry.jitter_ms);
        sleep(delay).await;
    }
}
