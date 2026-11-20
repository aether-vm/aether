//! R0: pool / metadata pairing, process lock and empty-database protection.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;

use aos_types::PersistProof;
use redb::Database;

use crate::config::{LOCK_FILE, MetaConfig, POOL_UUID_FILE};
use crate::error::{MetaError, Result};
use crate::model::PoolId;
use crate::tables::{
    self, SCHEMA_VERSION, SYS_POOL_UUID, SYS_SCHEMA, SYSTEM, begin_write, ensure_tables,
};

/// Exclusive OS lock on `pool_root/.lock`, released when dropped (or when the process dies).
#[derive(Debug)]
pub(crate) struct PoolLock {
    _file: File,
}

pub(crate) fn prepare_dirs(cfg: &MetaConfig) -> Result<()> {
    for d in [
        cfg.meta_dir.clone(),
        cfg.pool_root.clone(),
        cfg.objects_dir(),
        cfg.quarantine_dir(),
    ] {
        fs::create_dir_all(&d).map_err(|e| MetaError::io(format!("creating {}", d.display()), e))?;
    }
    Ok(())
}

/// Refuse `meta_dir` on the pool filesystem (F0-1 / F0-4: shared Btrfs transactions and
/// `ENOSPC` break `redb` commits).
#[cfg(target_os = "linux")]
pub(crate) fn check_filesystems(cfg: &MetaConfig) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if cfg.allow_same_fs_for_testing {
        return Ok(());
    }
    let dev = |p: &std::path::Path| {
        fs::metadata(p)
            .map(|m| m.dev())
            .map_err(|e| MetaError::io(format!("stat {}", p.display()), e))
    };
    if dev(&cfg.meta_dir)? == dev(&cfg.pool_root)? {
        return Err(MetaError::SameFilesystemForbidden {
            meta_dir: cfg.meta_dir.clone(),
            pool_root: cfg.pool_root.clone(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn check_filesystems(_cfg: &MetaConfig) -> Result<()> {
    Ok(())
}

pub(crate) fn acquire_lock(cfg: &MetaConfig) -> Result<PoolLock> {
    let path = cfg.pool_root.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| MetaError::io(format!("opening {}", path.display()), e))?;
    match file.try_lock() {
        Ok(()) => Ok(PoolLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(MetaError::PoolLocked { path }),
        Err(TryLockError::Error(e)) => {
            Err(MetaError::io(format!("locking {}", path.display()), e))
        }
    }
}

/// Entry names in `objects/` (any entry counts, managed or not).
pub(crate) fn list_objects(cfg: &MetaConfig) -> Result<Vec<OsString>> {
    let dir = cfg.objects_dir();
    let ctx = || format!("listing {}", dir.display());
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| MetaError::io(ctx(), e))? {
        out.push(entry.map_err(|e| MetaError::io(ctx(), e))?.file_name());
    }
    out.sort();
    Ok(out)
}

pub(crate) fn read_pool_uuid(cfg: &MetaConfig) -> Result<Option<PoolId>> {
    let path = cfg.pool_root.join(POOL_UUID_FILE);
    match fs::read_to_string(&path) {
        Ok(raw) => PoolId::parse(raw.strip_suffix('\n').unwrap_or(&raw)).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(MetaError::io(format!("reading {}", path.display()), e)),
    }
}

/// Write `POOL_UUID` atomically and durably (tmp + fsync + rename + fsync parent).
fn write_pool_uuid(cfg: &MetaConfig, id: &PoolId) -> Result<()> {
    let path = cfg.pool_root.join(POOL_UUID_FILE);
    let tmp = cfg.pool_root.join(format!("{POOL_UUID_FILE}.tmp"));
    let io_err = |what: &str, e| MetaError::io(format!("{what} {}", path.display()), e);
    fs::write(&tmp, format!("{id}\n")).map_err(|e| io_err("writing", e))?;
    let _ = PersistProof::fsync_file_and_parent(&tmp).map_err(|e| io_err("fsync", e))?;
    fs::rename(&tmp, &path).map_err(|e| io_err("renaming", e))?;
    let _ = PersistProof::fsync_file_and_parent(&path).map_err(|e| io_err("fsync", e))?;
    Ok(())
}

/// R0: open (or, for a provably empty pool, create) the database and verify the pool pairing.
pub(crate) fn open_or_init_db(cfg: &MetaConfig) -> Result<(Database, PoolId)> {
    let db_path = cfg.db_path();
    let pool_uuid = read_pool_uuid(cfg)?;
    let object_count = list_objects(cfg)?.len();
    let exists = db_path
        .try_exists()
        .map_err(|e| MetaError::io(format!("stat {}", db_path.display()), e))?;

    let db = if exists {
        match Database::open(&db_path) {
            Ok(db) => db,
            Err(e) if object_count > 0 => {
                return Err(MetaError::MissingMetaForNonEmptyPool {
                    db_path,
                    object_count,
                    reason: e.to_string(),
                });
            }
            Err(e) => {
                return Err(MetaError::MetaUnreadable {
                    db_path,
                    reason: e.to_string(),
                });
            }
        }
    } else {
        if object_count > 0 {
            return Err(MetaError::MissingMetaForNonEmptyPool {
                db_path,
                object_count,
                reason: "database file does not exist".into(),
            });
        }
        // Brand-new (or provably empty) pool: POOL_UUID first, then the database.
        if pool_uuid.is_none() {
            write_pool_uuid(cfg, &PoolId::random()?)?;
        }
        let db = Database::create(&db_path)?;
        let _ = PersistProof::fsync_dir(&cfg.meta_dir)
            .map_err(|e| MetaError::io(format!("fsync {}", cfg.meta_dir.display()), e))?;
        db
    };
    let pool_uuid = read_pool_uuid(cfg)?;

    let tx = begin_write(&db)?;
    ensure_tables(&tx)?;
    let id = {
        let mut sys = tx.open_table(SYSTEM)?;
        let meta_uuid: Option<PoolId> = tables::get_json(&sys, SYS_POOL_UUID)?;
        match (pool_uuid, meta_uuid) {
            (Some(p), Some(m)) if p == m => p,
            // Crash between creating the database file and its first commit.
            (Some(p), None) if object_count == 0 => {
                tables::put_json(&mut sys, SYS_POOL_UUID, &p)?;
                tables::put_json(&mut sys, SYS_SCHEMA, &SCHEMA_VERSION)?;
                p
            }
            (pool, meta) => return Err(MetaError::PoolUuidMismatch { pool, meta }),
        }
    };
    tx.commit()?;
    Ok((db, id))
}
