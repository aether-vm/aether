//! R0: pool / metadata pairing, empty-database protection and the process lock.

mod common;

use aos_meta::{MetaError, PoolId};
use aos_types::EpochId;
use common::*;

#[test]
fn fresh_pool_writes_pool_uuid_and_epochs_increase() {
    let h = Harness::new("r0-fresh");
    let (e, s) = h.open(boot_a());
    assert_eq!(s.new_epoch, EpochId::FIRST);
    assert!(!s.boot_changed);
    let pool_id = e.pool_id();
    let on_disk = std::fs::read_to_string(h.cfg.pool_root.join("POOL_UUID")).unwrap();
    assert_eq!(on_disk, format!("{pool_id}\n"));
    assert!(h.cfg.db_path().exists());
    drop(e);

    let (e, s) = h.open(boot_a());
    assert_eq!(e.pool_id(), pool_id);
    assert_eq!(s.new_epoch.get(), 2);
    assert_eq!(e.daemon_epoch().get(), 2);
}

#[test]
fn missing_meta_with_non_empty_pool_refuses_and_touches_nothing() {
    let h = Harness::new("r0-missing");
    let (mut e, _) = h.open(boot_a());
    h.durable(&mut e);
    drop(e);
    let before = h.pool_objects();
    assert_eq!(before.len(), 2);

    std::fs::remove_file(h.cfg.db_path()).unwrap();
    match h.try_open(boot_a()) {
        Err(MetaError::MissingMetaForNonEmptyPool { object_count, .. }) => {
            assert_eq!(object_count, 2);
        }
        other => panic!("expected MissingMetaForNonEmptyPool, got {other:?}"),
    }
    assert_eq!(h.pool_objects(), before, "objects/ must be untouched");
    assert!(h.quarantine_entries().is_empty());
    assert!(!h.cfg.db_path().exists(), "must never auto-create an empty database");
    assert!(h.ctl.calls().iter().all(|c| !c.starts_with("destroy")));
}

#[test]
fn corrupt_meta_with_non_empty_pool_refuses_and_keeps_the_corrupt_file() {
    let h = Harness::new("r0-corrupt");
    let (mut e, _) = h.open(boot_a());
    h.durable(&mut e);
    drop(e);
    let garbage = vec![0x5au8; 8192];
    std::fs::write(h.cfg.db_path(), &garbage).unwrap();
    let before = h.pool_objects();
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::MissingMetaForNonEmptyPool { .. })
    ));
    assert_eq!(h.pool_objects(), before);
    assert_eq!(std::fs::read(h.cfg.db_path()).unwrap(), garbage);
}

#[test]
fn corrupt_meta_with_empty_pool_is_still_refused() {
    let h = Harness::new("r0-corrupt-empty");
    drop(h.open(boot_a()));
    std::fs::write(h.cfg.db_path(), b"not a redb file").unwrap();
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::MetaUnreadable { .. })
    ));
}

#[test]
fn tampered_missing_or_malformed_pool_uuid_refuses() {
    let h = Harness::new("r0-uuid");
    let (e, _) = h.open(boot_a());
    let real = e.pool_id();
    drop(e);
    let uuid_path = h.cfg.pool_root.join("POOL_UUID");

    let other = PoolId::from_bytes([7; 16]);
    std::fs::write(&uuid_path, format!("{other}\n")).unwrap();
    match h.try_open(boot_a()) {
        Err(MetaError::PoolUuidMismatch { pool, meta }) => {
            assert_eq!(pool, Some(other));
            assert_eq!(meta, Some(real));
        }
        other => panic!("expected PoolUuidMismatch, got {other:?}"),
    }

    std::fs::remove_file(&uuid_path).unwrap();
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::PoolUuidMismatch { pool: None, .. })
    ));

    std::fs::write(&uuid_path, real.to_string().to_uppercase()).unwrap();
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::MalformedPoolUuid(_))
    ));

    std::fs::write(&uuid_path, format!("{real}\n")).unwrap();
    let (e, _) = h.open(boot_a());
    assert_eq!(e.pool_id(), real);
}

#[test]
fn second_engine_on_the_same_pool_is_locked_out() {
    let h = Harness::new("r0-lock");
    let (e, _) = h.open(boot_a());
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::PoolLocked { .. })
    ));
    drop(e);
    let (_e, s) = h.open(boot_a());
    assert_eq!(s.new_epoch.get(), 2, "the refused attempt must not consume an epoch");
}

#[cfg(target_os = "linux")]
#[test]
fn meta_on_pool_filesystem_is_refused_unless_testing() {
    let h = Harness::new("r0-samefs");
    let mut cfg = h.cfg.clone();
    cfg.allow_same_fs_for_testing = false;
    let r = aos_meta::MetaEngine::open_and_recover(
        cfg,
        boot_a(),
        Box::new(aos_meta::FsArtifactBackend::new(&h.vol)),
        h.clock.clone(),
    );
    assert!(matches!(r, Err(MetaError::SameFilesystemForbidden { .. })));
    assert!(!h.cfg.db_path().exists());
}
