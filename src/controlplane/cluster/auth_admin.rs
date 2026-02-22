use crate::controlplane::api_auth::{
    list_summaries, mint_token, retire_key, rotate_key, ApiKeySet, ApiKeyStatus, ApiKeySummary,
};
use crate::controlplane::cluster::rpc::AuthHandler;
use crate::controlplane::cluster::store::ClusterStore;
use crate::controlplane::cluster::types::ClusterTypeConfig;

pub struct AuthService {
    raft: openraft::Raft<ClusterTypeConfig>,
    store: ClusterStore,
}

impl AuthService {
    pub fn new(raft: openraft::Raft<ClusterTypeConfig>, store: ClusterStore) -> Self {
        Self { raft, store }
    }

    fn load_keyset(&self) -> Result<ApiKeySet, String> {
        crate::controlplane::api_auth::load_keyset_from_store(&self.store)?
            .ok_or_else(|| "missing api auth keyset".to_string())
    }

    async fn persist_keyset(&self, keyset: &ApiKeySet) -> Result<(), String> {
        crate::controlplane::api_auth::persist_keyset_via_raft(&self.raft, keyset).await
    }

    fn ensure_active(keyset: &ApiKeySet) -> Result<(), String> {
        let signing = keyset
            .keys
            .iter()
            .find(|key| key.kid == keyset.active_kid);
        match signing {
            Some(key) if key.status == ApiKeyStatus::Active => Ok(()),
            Some(_) => Err("active signing key is retired".to_string()),
            None => Err("active signing key missing".to_string()),
        }
    }
}

#[async_trait::async_trait]
impl AuthHandler for AuthService {
    async fn rotate_key(&self) -> Result<ApiKeySummary, String> {
        let mut keyset = self.load_keyset()?;
        let key = rotate_key(&mut keyset)?;
        Self::ensure_active(&keyset)?;
        self.persist_keyset(&keyset).await?;
        Ok(ApiKeySummary {
            kid: key.kid,
            status: key.status,
            created_at: key.created_at,
            signing: true,
        })
    }

    async fn list_keys(&self) -> Result<(String, Vec<ApiKeySummary>), String> {
        let keyset = self.load_keyset()?;
        let summaries = list_summaries(&keyset);
        Ok((keyset.active_kid, summaries))
    }

    async fn retire_key(&self, kid: String) -> Result<(), String> {
        let mut keyset = self.load_keyset()?;
        retire_key(&mut keyset, &kid)?;
        Self::ensure_active(&keyset)?;
        self.persist_keyset(&keyset).await
    }

    async fn mint_token(
        &self,
        sub: String,
        ttl_secs: Option<i64>,
        kid: Option<String>,
    ) -> Result<(String, String, i64), String> {
        let keyset = self.load_keyset()?;
        let minted = mint_token(&keyset, &sub, ttl_secs, kid.as_deref())?;
        Ok((minted.token, minted.kid, minted.exp))
    }
}
