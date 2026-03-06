use std::ops::RangeBounds;
use std::path::Path;
use std::sync::Arc;

use openraft::entry::EntryPayload;
use openraft::storage::{LogFlushed, RaftLogReader, RaftLogStorage, RaftStateMachine};
use openraft::LogId;
use openraft::LogState;
use openraft::OptionalSend;
use openraft::RaftSnapshotBuilder;
use openraft::Snapshot;
use openraft::SnapshotMeta;
use openraft::StorageError;
use openraft::StoredMembership;
use openraft::Vote;
use openraft::{ErrorSubject, ErrorVerb};
use rocksdb::{ColumnFamilyDescriptor, IteratorMode, Options, WriteBatch, DB};
use std::io::Cursor;
use tokio::io::AsyncReadExt;

use crate::controlplane::cluster::types::{
    ClusterCommand, ClusterResponse, ClusterTypeConfig, Node, NodeId,
};

const CF_META: &str = "meta";
const CF_LOG: &str = "log";
const CF_STATE: &str = "state";
const CF_SNAPSHOT: &str = "snapshot";

const KEY_VOTE: &[u8] = b"vote";
const KEY_LAST_PURGED: &[u8] = b"last_purged";
const KEY_LAST_LOG: &[u8] = b"last_log";
const KEY_LAST_APPLIED: &[u8] = b"last_applied";
const KEY_LAST_MEMBERSHIP: &[u8] = b"last_membership";
const KEY_SNAPSHOT_META: &[u8] = b"snapshot_meta";
const KEY_SNAPSHOT_DATA: &[u8] = b"snapshot_data";

#[derive(Debug, Clone)]
pub struct ClusterStore {
    db: Arc<DB>,
}

#[derive(Debug, Clone)]
pub struct ClusterLogReader {
    db: Arc<DB>,
}

#[derive(Debug, Clone)]
pub struct ClusterSnapshotBuilder {
    db: Arc<DB>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotData {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, Node>,
    kv: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ClusterStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
            ColumnFamilyDescriptor::new(CF_LOG, Options::default()),
            ColumnFamilyDescriptor::new(CF_STATE, Options::default()),
            ColumnFamilyDescriptor::new(CF_SNAPSHOT, Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn open_read_only(path: impl AsRef<Path>) -> Result<Self, rocksdb::Error> {
        let mut opts = Options::default();
        opts.create_if_missing(false);
        opts.create_missing_column_families(false);
        let cfs = vec![CF_META, CF_LOG, CF_STATE, CF_SNAPSHOT];
        let db = DB::open_cf_for_read_only(&opts, path, cfs, false)?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn property_int_value(&self, name: &str) -> Option<u64> {
        self.db.property_int_value(name).ok().flatten()
    }

    pub fn scan_state_prefix(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, String> {
        let cf = self.cf(CF_STATE).map_err(|err| err.to_string())?;
        let mut entries = Vec::new();
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(prefix, rocksdb::Direction::Forward));
        for item in iter {
            let (key, value) = item.map_err(|err| err.to_string())?;
            if !key.starts_with(prefix) {
                break;
            }
            entries.push((key.to_vec(), value.to_vec()));
        }
        Ok(entries)
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError<NodeId>> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| map_storage_err(format!("missing column family {name}")))
    }

    fn get_meta<T: serde::de::DeserializeOwned>(
        &self,
        key: &[u8],
    ) -> Result<Option<T>, StorageError<NodeId>> {
        let cf = self.cf(CF_META)?;
        let raw = self.db.get_cf(cf, key).map_err(map_storage_err)?;
        if let Some(raw) = raw {
            let parsed = bincode::deserialize(&raw).map_err(map_storage_err)?;
            Ok(Some(parsed))
        } else {
            Ok(None)
        }
    }

    fn put_meta<T: serde::Serialize>(
        &self,
        key: &[u8],
        value: &T,
        batch: &mut WriteBatch,
    ) -> Result<(), StorageError<NodeId>> {
        let cf = self.cf(CF_META)?;
        let encoded = bincode::serialize(value).map_err(map_storage_err)?;
        batch.put_cf(cf, key, encoded);
        Ok(())
    }

    fn get_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError<NodeId>> {
        let cf = self.cf(CF_STATE)?;
        let raw = self.db.get_cf(cf, key).map_err(map_storage_err)?;
        Ok(raw)
    }

    pub fn get_state_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.get_state(key).map_err(|err| err.to_string())
    }

    fn put_state(
        &self,
        key: &[u8],
        value: &[u8],
        batch: &mut WriteBatch,
    ) -> Result<(), StorageError<NodeId>> {
        let cf = self.cf(CF_STATE)?;
        batch.put_cf(cf, key, value);
        Ok(())
    }

    fn delete_state(&self, key: &[u8], batch: &mut WriteBatch) -> Result<(), StorageError<NodeId>> {
        let cf = self.cf(CF_STATE)?;
        batch.delete_cf(cf, key);
        Ok(())
    }
}

impl RaftLogReader<ClusterTypeConfig> for ClusterLogReader {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<<ClusterTypeConfig as openraft::RaftTypeConfig>::Entry>, StorageError<NodeId>>
    {
        let (start, end) = bounds_to_range(range);
        let cf = self
            .db
            .cf_handle(CF_LOG)
            .ok_or_else(|| map_storage_err("missing column family log"))?;
        let mut entries = Vec::new();
        let iter = self.db.iterator_cf(
            cf,
            IteratorMode::From(&encode_u64_be(start), rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key, value) = item.map_err(map_storage_err)?;
            let idx = decode_u64_be(&key);
            if idx >= end {
                break;
            }
            let entry = bincode::deserialize(&value).map_err(map_storage_err)?;
            entries.push(entry);
        }
        Ok(entries)
    }
}

impl RaftLogReader<ClusterTypeConfig> for ClusterStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<<ClusterTypeConfig as openraft::RaftTypeConfig>::Entry>, StorageError<NodeId>>
    {
        let mut reader = ClusterLogReader {
            db: self.db.clone(),
        };
        reader.try_get_log_entries(range).await
    }
}

impl RaftLogStorage<ClusterTypeConfig> for ClusterStore {
    type LogReader = ClusterLogReader;

    async fn get_log_state(&mut self) -> Result<LogState<ClusterTypeConfig>, StorageError<NodeId>> {
        let last_purged = self.get_meta(KEY_LAST_PURGED)?;
        let last_log = self.get_meta(KEY_LAST_LOG)?;
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last_log,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        ClusterLogReader {
            db: self.db.clone(),
        }
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut batch = WriteBatch::default();
        self.put_meta(KEY_VOTE, vote, &mut batch)?;
        self.db.write(batch).map_err(map_storage_err)?;
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        self.get_meta(KEY_VOTE)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<ClusterTypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = <ClusterTypeConfig as openraft::RaftTypeConfig>::Entry>
            + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let cf = self.cf(CF_LOG)?;
        let mut batch = WriteBatch::default();
        let mut last_log_id: Option<LogId<NodeId>> = None;
        for entry in entries {
            let idx = entry.log_id.index;
            let encoded = bincode::serialize(&entry).map_err(map_storage_err)?;
            batch.put_cf(cf, encode_u64_be(idx), encoded);
            last_log_id = Some(entry.log_id.clone());
        }
        if let Some(last_log_id) = last_log_id {
            self.put_meta(KEY_LAST_LOG, &last_log_id, &mut batch)?;
        }
        self.db.write(batch).map_err(map_storage_err)?;
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let cf = self.cf(CF_LOG)?;
        let mut batch = WriteBatch::default();
        let last_log = self.get_meta::<LogId<NodeId>>(KEY_LAST_LOG)?;
        let last_index = last_log.as_ref().map(|id| id.index).unwrap_or(0);
        for idx in log_id.index..=last_index {
            batch.delete_cf(cf, encode_u64_be(idx));
        }
        if log_id.index == 0 {
            batch.delete_cf(self.cf(CF_META)?, KEY_LAST_LOG);
        } else {
            let new_last = log_id.index.saturating_sub(1);
            if let Some(entry) = self
                .db
                .get_cf(cf, encode_u64_be(new_last))
                .map_err(map_storage_err)?
            {
                let entry: openraft::Entry<ClusterTypeConfig> =
                    bincode::deserialize(&entry).map_err(map_storage_err)?;
                self.put_meta(KEY_LAST_LOG, &entry.log_id, &mut batch)?;
            } else {
                batch.delete_cf(self.cf(CF_META)?, KEY_LAST_LOG);
            }
        }
        self.db.write(batch).map_err(map_storage_err)?;
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let cf = self.cf(CF_LOG)?;
        let mut batch = WriteBatch::default();
        for idx in 0..=log_id.index {
            batch.delete_cf(cf, encode_u64_be(idx));
        }
        self.put_meta(KEY_LAST_PURGED, &log_id, &mut batch)?;
        self.db.write(batch).map_err(map_storage_err)?;
        Ok(())
    }
}

impl RaftStateMachine<ClusterTypeConfig> for ClusterStore {
    type SnapshotBuilder = ClusterSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, Node>), StorageError<NodeId>> {
        let last_applied = self.get_meta(KEY_LAST_APPLIED)?;
        let membership = self
            .get_meta(KEY_LAST_MEMBERSHIP)?
            .unwrap_or_else(StoredMembership::default);
        Ok((last_applied, membership))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<ClusterResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = <ClusterTypeConfig as openraft::RaftTypeConfig>::Entry>
            + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut batch = WriteBatch::default();
        let mut responses = Vec::new();
        let mut last_applied: Option<LogId<NodeId>> = None;

        for entry in entries {
            last_applied = Some(entry.log_id.clone());
            match entry.payload {
                EntryPayload::Blank => {
                    responses.push(ClusterResponse::ok());
                }
                EntryPayload::Membership(m) => {
                    let stored = StoredMembership::new(Some(entry.log_id.clone()), m);
                    self.put_meta(KEY_LAST_MEMBERSHIP, &stored, &mut batch)?;
                    responses.push(ClusterResponse::ok());
                }
                EntryPayload::Normal(cmd) => {
                    apply_command(&cmd, self, &mut batch)?;
                    responses.push(ClusterResponse::ok());
                }
            }
        }

        if let Some(last_applied) = last_applied {
            self.put_meta(KEY_LAST_APPLIED, &last_applied, &mut batch)?;
        }
        self.db.write(batch).map_err(map_storage_err)?;
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        ClusterSnapshotBuilder {
            db: self.db.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<
        Box<<ClusterTypeConfig as openraft::RaftTypeConfig>::SnapshotData>,
        StorageError<NodeId>,
    > {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        snapshot: Box<<ClusterTypeConfig as openraft::RaftTypeConfig>::SnapshotData>,
    ) -> Result<(), StorageError<NodeId>> {
        let mut reader = snapshot;
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .await
            .map_err(map_storage_err)?;
        let decoded: SnapshotData = bincode::deserialize(&buf).map_err(map_storage_err)?;

        let mut batch = WriteBatch::default();
        let state_cf = self.cf(CF_STATE)?;
        let iter = self.db.iterator_cf(state_cf, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(map_storage_err)?;
            batch.delete_cf(state_cf, key);
        }
        for (key, value) in decoded.kv {
            batch.put_cf(state_cf, key, value);
        }

        self.put_meta(KEY_LAST_APPLIED, &decoded.last_applied, &mut batch)?;
        self.put_meta(KEY_LAST_MEMBERSHIP, &decoded.last_membership, &mut batch)?;
        self.put_meta(KEY_SNAPSHOT_META, meta, &mut batch)?;
        let snapshot_cf = self.cf(CF_SNAPSHOT)?;
        batch.put_cf(snapshot_cf, KEY_SNAPSHOT_DATA, buf);
        self.db.write(batch).map_err(map_storage_err)?;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ClusterTypeConfig>>, StorageError<NodeId>> {
        let meta: Option<SnapshotMeta<NodeId, Node>> = self.get_meta(KEY_SNAPSHOT_META)?;
        let cf = self.cf(CF_SNAPSHOT)?;
        let data = self
            .db
            .get_cf(cf, KEY_SNAPSHOT_DATA)
            .map_err(map_storage_err)?;

        match (meta, data) {
            (Some(meta), Some(data)) => Ok(Some(Snapshot {
                meta,
                snapshot: Box::new(Cursor::new(data)),
            })),
            _ => Ok(None),
        }
    }
}

impl RaftSnapshotBuilder<ClusterTypeConfig> for ClusterSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<ClusterTypeConfig>, StorageError<NodeId>> {
        let store = ClusterStore {
            db: self.db.clone(),
        };
        let last_applied: Option<LogId<NodeId>> = store.get_meta(KEY_LAST_APPLIED)?;
        let last_membership: StoredMembership<NodeId, Node> = store
            .get_meta(KEY_LAST_MEMBERSHIP)?
            .unwrap_or_else(StoredMembership::default);

        let state_cf = store.cf(CF_STATE)?;
        let mut kv = Vec::new();
        let iter = store.db.iterator_cf(state_cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(map_storage_err)?;
            kv.push((key.to_vec(), value.to_vec()));
        }

        let snapshot_data = SnapshotData {
            last_applied: last_applied.clone(),
            last_membership: last_membership.clone(),
            kv,
        };
        let encoded = bincode::serialize(&snapshot_data).map_err(map_storage_err)?;
        let snapshot_id = format!(
            "snapshot-{}",
            last_applied.as_ref().map(|id| id.index).unwrap_or(0)
        );
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(encoded)),
        })
    }
}

fn apply_command(
    cmd: &ClusterCommand,
    store: &ClusterStore,
    batch: &mut WriteBatch,
) -> Result<(), StorageError<NodeId>> {
    match cmd {
        ClusterCommand::Put { key, value } => {
            store.put_state(key, value, batch)?;
        }
        ClusterCommand::Delete { key } => {
            store.delete_state(key, batch)?;
        }
        ClusterCommand::Gc { cutoff_unix } => {
            let cutoff = *cutoff_unix;
            let state_cf = store.cf(CF_STATE)?;
            let prefix = b"dns/last_seen/";
            let iter = store.db.iterator_cf(state_cf, IteratorMode::Start);
            for item in iter {
                let (key, value) = item.map_err(map_storage_err)?;
                if !key.starts_with(prefix) {
                    continue;
                }
                let ts: i64 = match bincode::deserialize(&value) {
                    Ok(ts) => ts,
                    Err(_) => continue,
                };
                if ts < cutoff {
                    batch.delete_cf(state_cf, &key);
                    let suffix = &key[prefix.len()..];
                    let mut map_key = b"dns/map/".to_vec();
                    map_key.extend_from_slice(suffix);
                    batch.delete_cf(state_cf, map_key);
                }
            }
        }
        ClusterCommand::SetCaCert { pem } => {
            store.put_state(b"ca/cert", pem, batch)?;
        }
        ClusterCommand::UpsertCaEnvelope { node_id, envelope } => {
            let key = format!("ca/envelope/{}", node_id).into_bytes();
            let value = bincode::serialize(envelope).map_err(map_storage_err)?;
            store.put_state(&key, &value, batch)?;
        }
    }
    Ok(())
}

fn bounds_to_range<RB: RangeBounds<u64>>(range: RB) -> (u64, u64) {
    use std::ops::Bound;
    let start = match range.start_bound() {
        Bound::Included(v) => *v,
        Bound::Excluded(v) => v.saturating_add(1),
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(v) => v.saturating_add(1),
        Bound::Excluded(v) => *v,
        Bound::Unbounded => u64::MAX,
    };
    (start, end)
}

fn encode_u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn decode_u64_be(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    if bytes.len() >= 8 {
        buf.copy_from_slice(&bytes[..8]);
    }
    u64::from_be_bytes(buf)
}

fn map_storage_err<E: std::fmt::Display>(err: E) -> StorageError<NodeId> {
    StorageError::from_io_error(
        ErrorSubject::Store,
        ErrorVerb::Read,
        std::io::Error::new(std::io::ErrorKind::Other, err.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controlplane::api_auth::API_KEYS_KEY;
    use crate::controlplane::integrations::INTEGRATIONS_INDEX_KEY;
    use crate::controlplane::policy_repository::{POLICY_ACTIVE_KEY, POLICY_INDEX_KEY};
    use crate::controlplane::service_accounts::SERVICE_ACCOUNTS_INDEX_KEY;
    use tempfile::TempDir;

    #[test]
    fn gc_removes_stale_dns_entries() {
        let dir = TempDir::new().unwrap();
        let store = ClusterStore::open(dir.path()).unwrap();

        let mut batch = WriteBatch::default();
        let stale_ts = bincode::serialize(&10i64).unwrap();
        let fresh_ts = bincode::serialize(&200i64).unwrap();

        store
            .put_state(b"dns/last_seen/foo/1.1.1.1", &stale_ts, &mut batch)
            .unwrap();
        store
            .put_state(b"dns/map/foo/1.1.1.1", b"meta", &mut batch)
            .unwrap();
        store
            .put_state(b"dns/last_seen/bar/2.2.2.2", &fresh_ts, &mut batch)
            .unwrap();
        store
            .put_state(b"dns/map/bar/2.2.2.2", b"meta", &mut batch)
            .unwrap();
        store.db.write(batch).unwrap();

        let mut batch = WriteBatch::default();
        apply_command(&ClusterCommand::Gc { cutoff_unix: 100 }, &store, &mut batch).unwrap();
        store.db.write(batch).unwrap();

        assert!(store
            .get_state(b"dns/last_seen/foo/1.1.1.1")
            .unwrap()
            .is_none());
        assert!(store.get_state(b"dns/map/foo/1.1.1.1").unwrap().is_none());

        assert!(store
            .get_state(b"dns/last_seen/bar/2.2.2.2")
            .unwrap()
            .is_some());
        assert!(store.get_state(b"dns/map/bar/2.2.2.2").unwrap().is_some());
    }

    #[tokio::test]
    async fn snapshot_restore_preserves_critical_prefixes() {
        let dir = TempDir::new().unwrap();
        let source_dir = dir.path().join("source");
        let restore_dir = dir.path().join("restore");
        let mut source = ClusterStore::open(&source_dir).unwrap();

        let expected: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (POLICY_INDEX_KEY.to_vec(), br#"{"policies":[]}"#.to_vec()),
            (
                POLICY_ACTIVE_KEY.to_vec(),
                br#"{"id":"00000000-0000-0000-0000-000000000001"}"#.to_vec(),
            ),
            (
                API_KEYS_KEY.to_vec(),
                br#"{"active_kid":"kid-1","keys":[]}"#.to_vec(),
            ),
            (
                SERVICE_ACCOUNTS_INDEX_KEY.to_vec(),
                br#"{"accounts":[]}"#.to_vec(),
            ),
            (
                INTEGRATIONS_INDEX_KEY.to_vec(),
                br#"{"records":[]}"#.to_vec(),
            ),
            (
                b"integration/termination/i-snapshot".to_vec(),
                br#"{"id":"evt-1","instance_id":"i-snapshot","deadline_epoch":123}"#.to_vec(),
            ),
        ];

        let mut batch = WriteBatch::default();
        for (key, value) in &expected {
            source.put_state(key, value, &mut batch).unwrap();
        }
        source.db.write(batch).unwrap();

        let mut builder = source.get_snapshot_builder().await;
        let snapshot = builder.build_snapshot().await.unwrap();
        let meta = snapshot.meta.clone();
        let mut reader = snapshot.snapshot;
        let mut payload = Vec::new();
        reader.read_to_end(&mut payload).await.unwrap();

        let mut restored = ClusterStore::open(&restore_dir).unwrap();
        restored
            .install_snapshot(&meta, Box::new(Cursor::new(payload)))
            .await
            .unwrap();

        for (key, value) in &expected {
            let got = restored.get_state(key).unwrap().unwrap_or_else(|| {
                panic!("missing restored key {:?}", String::from_utf8_lossy(key))
            });
            assert_eq!(
                got,
                *value,
                "restored key mismatch {:?}",
                String::from_utf8_lossy(key)
            );
        }

        let current = restored.get_current_snapshot().await.unwrap();
        assert!(
            current.is_some(),
            "restored snapshot metadata should be present"
        );
    }

    #[test]
    fn gc_compaction_churn_preserves_non_dns_state() {
        let dir = TempDir::new().unwrap();
        let store = ClusterStore::open(dir.path()).unwrap();

        let mut batch = WriteBatch::default();
        store
            .put_state(
                POLICY_INDEX_KEY,
                br#"{"policies":[{"id":"steady"}]}"#,
                &mut batch,
            )
            .unwrap();
        store
            .put_state(
                API_KEYS_KEY,
                br#"{"active_kid":"steady","keys":[]}"#,
                &mut batch,
            )
            .unwrap();
        store.db.write(batch).unwrap();

        for round in 0..32i64 {
            let mut batch = WriteBatch::default();
            let stale_key = format!("dns/last_seen/stale/{round}");
            let stale_map = format!("dns/map/stale/{round}");
            let stale_ts = bincode::serialize(&(round - 200)).unwrap();
            store
                .put_state(stale_key.as_bytes(), &stale_ts, &mut batch)
                .unwrap();
            store
                .put_state(stale_map.as_bytes(), b"stale", &mut batch)
                .unwrap();

            let fresh_key = format!("dns/last_seen/fresh/{round}");
            let fresh_map = format!("dns/map/fresh/{round}");
            let fresh_ts = bincode::serialize(&(round + 1000)).unwrap();
            store
                .put_state(fresh_key.as_bytes(), &fresh_ts, &mut batch)
                .unwrap();
            store
                .put_state(fresh_map.as_bytes(), b"fresh", &mut batch)
                .unwrap();
            store.db.write(batch).unwrap();

            let mut gc_batch = WriteBatch::default();
            apply_command(
                &ClusterCommand::Gc {
                    cutoff_unix: round - 100,
                },
                &store,
                &mut gc_batch,
            )
            .unwrap();
            store.db.write(gc_batch).unwrap();

            let state_cf = store.cf(CF_STATE).unwrap();
            store
                .db
                .compact_range_cf(state_cf, None::<&[u8]>, None::<&[u8]>);
        }

        assert!(store.get_state(POLICY_INDEX_KEY).unwrap().is_some());
        assert!(store.get_state(API_KEYS_KEY).unwrap().is_some());

        let stale_entries = store.scan_state_prefix(b"dns/last_seen/stale/").unwrap();
        assert!(
            stale_entries.is_empty(),
            "stale entries should be fully collected"
        );

        let fresh_entries = store.scan_state_prefix(b"dns/last_seen/fresh/").unwrap();
        assert!(
            !fresh_entries.is_empty(),
            "fresh entries should remain after churn"
        );
    }
}
