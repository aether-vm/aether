//! `redb` table layout and typed JSON helpers.
//!
//! | table | key | value |
//! | --- | --- | --- |
//! | `system` | `pool_uuid` / `daemon_epoch` / `last_boot` / `schema` | JSON scalar |
//! | `frames` | frame base32 | [`FrameRecord`] |
//! | `holds` | `<frame base32>/<hold key>` | [`Hold`] |
//! | `pending_reclaim` | frame base32 | [`ReclaimMark`] |
//! | `timelines` | timeline name | [`TimelineRecord`](crate::model::TimelineRecord) |
//! | `worlds` | world base32 | [`WorldRecord`] |
//! | `idempotency` | `<owner>\0<request id>` | [`IdempotencyRecord`] |
//! | `quarantine` | `epoch-<n>/<name>` | [`QuarantineRecord`] |

use aos_types::FrameId;
use redb::{
    Database, Durability, ReadableTable, Table, TableDefinition, WriteTransaction,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::error::Result;
use crate::idempotency::IdempotencyRecord;
use crate::model::{FrameRecord, Hold, IdempotencyKey, QuarantineRecord, WorldRecord};

/// Raw table type used everywhere: string keys, JSON values.
pub(crate) type Def = TableDefinition<'static, &'static str, &'static [u8]>;
/// An open writable table of [`Def`] shape.
pub(crate) type RawTable<'t> = Table<'t, &'static str, &'static [u8]>;

pub(crate) const SYSTEM: Def = TableDefinition::new("system");
pub(crate) const FRAMES: Def = TableDefinition::new("frames");
pub(crate) const HOLDS: Def = TableDefinition::new("holds");
pub(crate) const PENDING_RECLAIM: Def = TableDefinition::new("pending_reclaim");
pub(crate) const TIMELINES: Def = TableDefinition::new("timelines");
pub(crate) const WORLDS: Def = TableDefinition::new("worlds");
pub(crate) const IDEMPOTENCY: Def = TableDefinition::new("idempotency");
pub(crate) const QUARANTINE: Def = TableDefinition::new("quarantine");

pub(crate) const ALL_TABLES: [Def; 8] = [
    SYSTEM,
    FRAMES,
    HOLDS,
    PENDING_RECLAIM,
    TIMELINES,
    WORLDS,
    IDEMPOTENCY,
    QUARANTINE,
];

pub(crate) const SYS_POOL_UUID: &str = "pool_uuid";
pub(crate) const SYS_DAEMON_EPOCH: &str = "daemon_epoch";
pub(crate) const SYS_LAST_BOOT: &str = "last_boot";
pub(crate) const SYS_SCHEMA: &str = "schema";
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// A deferred delete request on a held frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReclaimMark {
    pub requested_by: String,
    pub requested_at_ms: u64,
}

/// Begin a write transaction that is durable on commit (`fsync` before `commit()` returns).
///
/// Two-phase commit: without it redb detects a torn commit only through a checksum of the new
/// root, which record contents chosen by an untrusted caller could collide with.
pub(crate) fn begin_write(db: &Database) -> Result<WriteTransaction> {
    let mut tx = db.begin_write()?;
    tx.set_durability(Durability::Immediate);
    tx.set_two_phase_commit(true);
    Ok(tx)
}

/// Create every table so later read transactions never see `TableDoesNotExist`.
pub(crate) fn ensure_tables(tx: &WriteTransaction) -> Result<()> {
    for def in ALL_TABLES {
        tx.open_table(def)?;
    }
    Ok(())
}

pub(crate) fn frame_key(f: &FrameId) -> String {
    f.to_base32()
}

pub(crate) fn hold_key(f: &FrameId, hold: &Hold) -> String {
    format!("{}/{}", f.to_base32(), hold.key())
}

pub(crate) fn idem_key(k: &IdempotencyKey) -> String {
    format!("{}\0{}", k.owner, k.request_id)
}

pub(crate) fn quarantine_key(r: &QuarantineRecord) -> String {
    format!("{}/{}", r.quarantined_epoch.cgroup_dir_name(), r.name)
}

pub(crate) fn get_json<T, Tbl>(t: &Tbl, key: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    match t.get(key)? {
        Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
        None => Ok(None),
    }
}

pub(crate) fn put_json<T: Serialize>(
    t: &mut Table<'_, &'static str, &'static [u8]>,
    key: &str,
    v: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(v)?;
    t.insert(key, bytes.as_slice())?;
    Ok(())
}

/// All rows, decoded.
pub(crate) fn scan_json<T, Tbl>(t: &Tbl) -> Result<Vec<(String, T)>>
where
    T: DeserializeOwned,
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    let mut out = Vec::new();
    for item in t.iter()? {
        let (k, v) = item?;
        out.push((k.value().to_owned(), serde_json::from_slice(v.value())?));
    }
    Ok(out)
}

/// Rows whose key starts with `prefix` (prefix must end in `/`).
pub(crate) fn scan_prefix<T, Tbl>(t: &Tbl, prefix: &str) -> Result<Vec<(String, T)>>
where
    T: DeserializeOwned,
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    debug_assert!(prefix.ends_with('/'));
    // '/' + 1 == '0': every key with the prefix sorts strictly below `<stem>0`.
    let end = format!("{}0", &prefix[..prefix.len() - 1]);
    let mut out = Vec::new();
    for item in t.range(prefix..end.as_str())? {
        let (k, v) = item?;
        out.push((k.value().to_owned(), serde_json::from_slice(v.value())?));
    }
    Ok(out)
}

/// Holds of one frame.
pub(crate) fn holds_of<Tbl>(t: &Tbl, f: &FrameId) -> Result<Vec<(String, Hold)>>
where
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    scan_prefix(t, &format!("{}/", f.to_base32()))
}

/// Remove every hold of a frame, returning how many were removed.
pub(crate) fn clear_holds(
    t: &mut Table<'_, &'static str, &'static [u8]>,
    f: &FrameId,
) -> Result<usize> {
    let keys: Vec<String> = holds_of(t, f)?.into_iter().map(|(k, _)| k).collect();
    for k in &keys {
        t.remove(k.as_str())?;
    }
    Ok(keys.len())
}

pub(crate) fn load_frame<Tbl>(t: &Tbl, f: &FrameId) -> Result<Option<FrameRecord>>
where
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    get_json(t, &frame_key(f))
}

pub(crate) fn load_world<Tbl>(t: &Tbl, w: &aos_types::WorldId) -> Result<Option<WorldRecord>>
where
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    get_json(t, &w.to_base32())
}

pub(crate) fn load_idem<Tbl>(t: &Tbl, k: &IdempotencyKey) -> Result<Option<IdempotencyRecord>>
where
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    get_json(t, &idem_key(k))
}
