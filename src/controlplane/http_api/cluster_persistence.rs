use super::*;

pub(super) async fn persist_cluster_policy(
    cluster: &HttpApiCluster,
    record: &PolicyRecord,
) -> Result<(), String> {
    let record_bytes = serde_json::to_vec(record).map_err(|err| err.to_string())?;
    let item_key = policy_item_key(record.id);
    let cmd = ClusterCommand::Put {
        key: item_key,
        value: record_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let mut index = read_cluster_index(&cluster.store)?;
    let meta = PolicyMeta::from(record);
    if let Some(existing) = index.policies.iter_mut().find(|item| item.id == meta.id) {
        *existing = meta;
    } else {
        index.policies.push(meta);
    }
    index.policies.sort_by(|a, b| {
        let ts = a.created_at.cmp(&b.created_at);
        if ts == std::cmp::Ordering::Equal {
            a.id.as_bytes().cmp(b.id.as_bytes())
        } else {
            ts
        }
    });
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    if record.mode.is_active() {
        let active = PolicyActive { id: record.id };
        let active_bytes = serde_json::to_vec(&active).map_err(|err| err.to_string())?;
        let cmd = ClusterCommand::Put {
            key: POLICY_ACTIVE_KEY.to_vec(),
            value: active_bytes,
        };
        cluster
            .raft
            .client_write(cmd)
            .await
            .map_err(|err| err.to_string())?;
    } else if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
        if active.id == record.id {
            let cmd = ClusterCommand::Delete {
                key: POLICY_ACTIVE_KEY.to_vec(),
            };
            cluster
                .raft
                .client_write(cmd)
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    Ok(())
}

pub(super) async fn delete_cluster_policy(
    cluster: &HttpApiCluster,
    id: Uuid,
) -> Result<(), String> {
    let cmd = ClusterCommand::Delete {
        key: policy_item_key(id),
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    let mut index = read_cluster_index(&cluster.store)?;
    index.policies.retain(|meta| meta.id != id);
    let index_bytes = serde_json::to_vec(&index).map_err(|err| err.to_string())?;
    let cmd = ClusterCommand::Put {
        key: POLICY_INDEX_KEY.to_vec(),
        value: index_bytes,
    };
    cluster
        .raft
        .client_write(cmd)
        .await
        .map_err(|err| err.to_string())?;

    if let Ok(Some(active)) = read_cluster_active(&cluster.store) {
        if active.id == id {
            let cmd = ClusterCommand::Delete {
                key: POLICY_ACTIVE_KEY.to_vec(),
            };
            cluster
                .raft
                .client_write(cmd)
                .await
                .map_err(|err| err.to_string())?;
        }
    }

    Ok(())
}

pub(super) fn read_cluster_index(store: &ClusterStore) -> Result<PolicyIndex, String> {
    let raw = store.get_state_value(POLICY_INDEX_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw).map_err(|err| err.to_string()),
        None => Ok(PolicyIndex::default()),
    }
}

pub(super) fn read_cluster_active(store: &ClusterStore) -> Result<Option<PolicyActive>, String> {
    let raw = store.get_state_value(POLICY_ACTIVE_KEY)?;
    match raw {
        Some(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}
