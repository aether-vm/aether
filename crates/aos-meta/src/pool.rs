//! R0: pool / metadata pairing, process lock and empty-database protection.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;

use aos_types::PersistProof;
use redb::{Database, TableError};

use crate::config::{LOCK_FILE, MetaConfig, POOL_UUID_FILE};
use crate::error::{MetaError, Result};
use crate::model::PoolId;
use crate::tables::{
    self, ALL_TABLES, SCHEMA_VERSION, SYS_POOL_UUID, SYS_SCHEMA, SYSTEM, begin_write,
    ensure_tables,
};

/// Linux `BTRFS_SUPER_MAGIC` (`0x9123683E`).
pub const BTRFS_SUPER_MAGIC_RAW: i64 = 0x9123_683e;

/// Pure filesystem-separation predicate: refuses `meta_dir` when it shares `st_dev` or
/// `f_fsid` with `pool_root`, or when `meta_dir` itself resides on Btrfs (where subvolumes
/// get distinct synthetic `st_dev`s on the same pool).
#[must_use]
pub fn is_same_or_forbidden_fs(
    meta_dev: u64,
    pool_dev: u64,
    meta_fsid: [i32; 2],
    pool_fsid: [i32; 2],
    meta_fstype: i64,
) -> bool {
    meta_dev == pool_dev || meta_fsid == pool_fsid || meta_fstype == BTRFS_SUPER_MAGIC_RAW
}

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

/// Refuse `meta_dir` on the pool filesystem or on Btrfs (F0-1 / F0-4: shared Btrfs transactions
/// and `ENOSPC` break `redb` commits, and Btrfs subvolumes have distinct `st_dev`s).
#[cfg(target_os = "linux")]
pub(crate) fn check_filesystems(cfg: &MetaConfig) -> Result<()> {
    use nix::sys::statfs::{BTRFS_SUPER_MAGIC, statfs};
    use std::os::unix::fs::MetadataExt;
    if cfg.allow_same_fs_for_testing {
        return Ok(());
    }
    let dev = |p: &std::path::Path| {
        fs::metadata(p)
            .map(|m| m.dev())
            .map_err(|e| MetaError::io(format!("stat {}", p.display()), e))
    };
    let sfs = |p: &std::path::Path| {
        statfs(p).map_err(|e| {
            MetaError::io(
                format!("statfs {}", p.display()),
                io::Error::from_raw_os_error(e as i32),
            )
        })
    };
    let (meta_dev, pool_dev) = (dev(&cfg.meta_dir)?, dev(&cfg.pool_root)?);
    let (meta_fs, pool_fs) = (sfs(&cfg.meta_dir)?, sfs(&cfg.pool_root)?);
    if meta_dev == pool_dev
        || meta_fs.filesystem_id() == pool_fs.filesystem_id()
        || meta_fs.filesystem_type() == BTRFS_SUPER_MAGIC
    {
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

    // Read-only verification first: if an existing database fails pairing or schema checks
    // (or the subsequent R6 pre-flight check), we must not mutate `forkloom.redb`.
    {
        let rtx = db.begin_read()?;
        match rtx.open_table(SYSTEM) {
            Ok(sys) => {
                let meta_uuid: Option<PoolId> = tables::get_json(&sys, SYS_POOL_UUID)?;
                let schema: Option<u32> = tables::get_json(&sys, SYS_SCHEMA)?;
                match (pool_uuid, meta_uuid) {
                    (Some(p), Some(m)) if p == m => {
                        if schema != Some(SCHEMA_VERSION) {
                            return Err(MetaError::UnsupportedSchema {
                                found: schema,
                                supported: SCHEMA_VERSION,
                            });
                        }
                        let all_exist = ALL_TABLES.iter().all(|def| rtx.open_table(*def).is_ok());
                        if all_exist {
                            return Ok((db, p));
                        }
                    }
                    (Some(_), None) if schema.is_none() && object_count == 0 => {
                        // Crash between creating the database file and its first commit.
                    }
                    (pool, meta) => return Err(MetaError::PoolUuidMismatch { pool, meta }),
                }
            }
            Err(TableError::TableDoesNotExist(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }

    let tx = begin_write(&db)?;
    ensure_tables(&tx)?;
    let id = {
        let mut sys = tx.open_table(SYSTEM)?;
        let meta_uuid: Option<PoolId> = tables::get_json(&sys, SYS_POOL_UUID)?;
        let schema: Option<u32> = tables::get_json(&sys, SYS_SCHEMA)?;
        match (pool_uuid, meta_uuid) {
            (Some(p), Some(m)) if p == m => {
                if schema != Some(SCHEMA_VERSION) {
                    return Err(MetaError::UnsupportedSchema {
                        found: schema,
                        supported: SCHEMA_VERSION,
                    });
                }
                p
            }
            // Crash between creating the database file and its first commit.
            (Some(p), None) if schema.is_none() && object_count == 0 => {
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
