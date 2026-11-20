//! R1 boot / pin renewal, R2 fencing and lost worlds, R6 quarantine and circuit breaker.

mod common;

use std::sync::atomic::Ordering;

use aos_meta::{
    CreateWorldRequest, FrameDurability, FrameState, Hold, MetaError, ObjectKind, PinSpec,
    WorldState,
};
use aos_types::{EpochId, FrameId};
use common::*;

const HOUR: u64 = 3600 * 1000;

#[test]
fn same_boot_restart_keeps_volatile_frames() {
    let h = Harness::new("r1-same-boot");
    let (mut e, _) = h.open(boot_a());
    let v = h.volatile(&mut e);
    let tmpfs_before = h.tmpfs_objects();
    assert_eq!(tmpfs_before.len(), 1);
    drop(e);

    let (e, s) = h.open(boot_a());
    assert!(!s.boot_changed);
    assert_eq!(s.volatile_expired, 0);
    assert!(matches!(
        e.frame(v).unwrap().unwrap().state,
        FrameState::Committed { .. }
    ));
    assert_eq!(h.tmpfs_objects(), tmpfs_before);
    assert_eq!(h.pool_objects().len(), 2, "disk + vmstate stay in the pool");
}

#[test]
fn boot_change_expires_every_volatile_frame_and_its_holds() {
    let h = Harness::new("r1-new-boot");
    let (mut e, _) = h.open(boot_a());
    let d = h.durable(&mut e);
    let v1 = h.volatile(&mut e);
    let v2 = h.volatile(&mut e);
    e.pin_frame(
        v1,
        &PinSpec {
            pin_id: "p".into(),
            owner: "alice".into(),
            lease_ttl_ms: HOUR,
        },
    )
    .unwrap();
    let w = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: v2,
                labels: labels(&[("job", "mcts")]),
                lease_ttl_ms: 10_000,
            },
            None,
        )
        .unwrap();
    let durable_names = names(&e, d);
    drop(e);

    let (e, s) = h.open(boot_b());
    assert!(s.boot_changed);
    assert_eq!(s.volatile_expired, 2);
    assert_eq!(s.deleting_completed, 2);
    assert_eq!(s.worlds_marked_lost, 1);
    assert_eq!(s.pins_renewed_on_boot, 0, "the only pin sat on an expired volatile frame");
    assert!(e.frame(v1).unwrap().is_none());
    assert!(e.frame(v2).unwrap().is_none());
    assert!(e.holds(v1).unwrap().is_empty());
    assert!(h.tmpfs_objects().is_empty());
    assert_eq!(h.pool_objects(), durable_names.into_iter().collect());
    assert!(matches!(
        e.world(w.world_id).unwrap().unwrap().state,
        WorldState::Lost { .. }
    ));
    assert_eq!(e.current_boot(), boot_b());
}

#[test]
fn pins_survive_ten_hours_of_downtime_and_restart_from_recovery_time() {
    let h = Harness::new("r1-pin-downtime");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    e.pin_frame(
        f,
        &PinSpec {
            pin_id: "eval-run".into(),
            owner: "alice".into(),
            lease_ttl_ms: HOUR,
        },
    )
    .unwrap();
    drop(e);

    h.clock.advance(10 * HOUR);
    let now = T0 + 10 * HOUR;
    let (mut e, s) = h.open(boot_a());
    assert_eq!(s.pins_renewed_on_boot, 1);
    match &e.holds(f).unwrap()[..] {
        [Hold::Pin { expires_at_ms, .. }] => assert_eq!(*expires_at_ms, now + HOUR),
        other => panic!("unexpected holds {other:?}"),
    }
    assert_eq!(e.collect_garbage(now).unwrap().pins_expired, 0);
    assert!(e.frame(f).unwrap().is_some());
    // The lease still runs out normally afterwards.
    assert_eq!(e.collect_garbage(now + HOUR).unwrap().pins_expired, 1);
    assert!(e.holds(f).unwrap().is_empty());
}

#[test]
fn gateway_fence_failure_aborts_before_any_world_is_touched() {
    let h = Harness::new("r2-fence");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let w = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: f,
                labels: labels(&[("team", "rl")]),
                lease_ttl_ms: 10_000,
            },
            None,
        )
        .unwrap();
    drop(e);

    h.ctl.fail_fence.store(true, Ordering::SeqCst);
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::Hook {
            stage: "fence_gateway",
            ..
        })
    ));
    let calls = h.ctl.calls();
    assert_eq!(calls.last().unwrap(), "fence:2");
    assert!(!calls.iter().any(|c| c == "kill:2"), "never kill before fencing succeeded");
    h.ctl.fail_fence.store(false, Ordering::SeqCst);

    h.ctl.fail_kill.store(true, Ordering::SeqCst);
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::Hook {
            stage: "kill_stale_epochs",
            ..
        })
    ));
    h.ctl.fail_kill.store(false, Ordering::SeqCst);

    let (e, s) = h.open(boot_a());
    assert_eq!(s.worlds_marked_lost, 1, "failed attempts must not have marked anything");
    let calls = h.ctl.calls();
    let tail: Vec<_> = calls[calls.len() - 2..].to_vec();
    assert_eq!(tail, vec![format!("fence:{}", s.new_epoch), format!("kill:{}", s.new_epoch)]);
    let rec = e.world(w.world_id).unwrap().unwrap();
    assert_eq!(
        rec.state,
        WorldState::Lost {
            origin_epoch: EpochId::FIRST,
            lost_in_epoch: s.new_epoch,
            lost_at_ms: T0,
        }
    );
}

#[test]
fn old_epoch_worlds_become_lost_release_holds_and_keep_a_tombstone() {
    let h = Harness::new("r2-lost");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let w = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: f,
                labels: labels(&[("team", "rl"), ("run", "7")]),
                lease_ttl_ms: 10_000,
            },
            None,
        )
        .unwrap();
    assert_eq!(e.holds(f).unwrap().len(), 1);
    drop(e);

    let (mut e, s) = h.open(boot_a());
    assert_eq!(s.worlds_marked_lost, 1);
    assert!(e.holds(f).unwrap().is_empty(), "WorldBase hold released");
    let found = e
        .list_worlds_by_labels("alice", &labels(&[("run", "7")]))
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].world_id, w.world_id);
    assert!(matches!(found[0].state, WorldState::Lost { .. }));
    assert!(matches!(
        e.renew_world_lease(w.world_id, "alice", w.fencing_token),
        Err(MetaError::WorldNotRunning(_))
    ));
    // Tombstones expire.
    let ttl = e.config().world_tombstone_ttl_ms;
    assert_eq!(e.collect_garbage(T0 + ttl - 1).unwrap().tombstones_purged, 0);
    assert_eq!(e.collect_garbage(T0 + ttl).unwrap().tombstones_purged, 1);
    assert!(e.world(w.world_id).unwrap().is_none());
}

#[test]
fn few_orphans_are_quarantined_then_purged_after_the_grace_period() {
    let h = Harness::new("r6-quarantine");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let keep = names(&e, f);
    drop(e);

    let ghost = aos_meta::ManagedObject::new(FrameId::random(), ObjectKind::DiskImage).name();
    let ghost_dir = aos_meta::ManagedObject::new(FrameId::random(), ObjectKind::TreeSubvol).name();
    h.add_orphan(&ghost);
    std::fs::create_dir_all(h.objects_dir().join(&ghost_dir).join("usr")).unwrap();
    h.add_orphan("stray.tmp");

    let (mut e, s) = h.open(boot_a());
    assert_eq!(s.orphans_quarantined, 3);
    assert_eq!(s.objects_scanned, 5);
    assert_eq!(h.pool_objects(), keep.iter().cloned().collect());
    let q: std::collections::BTreeSet<String> = [&ghost, &ghost_dir, &"stray.tmp".to_owned()]
        .iter()
        .map(|n| format!("epoch-2/{n}"))
        .collect();
    assert_eq!(h.quarantine_entries(), q, "moved, not deleted");
    let recs = e.quarantine_records().unwrap();
    assert_eq!(recs.len(), 3);
    let grace = e.config().quarantine_grace_ms;
    assert!(recs.iter().all(|r| r.purge_after_ms == T0 + grace));

    assert_eq!(e.collect_garbage(T0 + grace - 1).unwrap().quarantine_purged, 0);
    assert_eq!(h.quarantine_entries().len(), 3);
    assert_eq!(e.collect_garbage(T0 + grace).unwrap().quarantine_purged, 3);
    assert!(h.quarantine_entries().is_empty());
    assert!(e.quarantine_records().unwrap().is_empty());
    assert_eq!(h.pool_objects(), keep.into_iter().collect(), "committed frame untouched");
}

#[test]
fn breaker_trips_on_absolute_orphan_count_and_touches_nothing() {
    let h = Harness::new("r6-breaker-abs");
    let (mut e, _) = h.open(boot_a());
    h.durable(&mut e);
    drop(e);
    for i in 0..60 {
        h.add_orphan(&format!("orphan-{i:02}"));
    }
    let before = h.pool_objects();
    match h.try_open(boot_a()) {
        Err(MetaError::OrphanCircuitBreakerTriggered {
            orphan_count,
            total_objects,
        }) => {
            assert_eq!(orphan_count, 60);
            assert_eq!(total_objects, 62);
        }
        other => panic!("expected breaker, got {other:?}"),
    }
    assert_eq!(h.pool_objects(), before);
    assert!(h.quarantine_entries().is_empty());
}

#[test]
fn breaker_trips_on_orphan_ratio_and_releases_once_within_limits() {
    let h = Harness::new("r6-breaker-ratio");
    let (mut e, _) = h.open(boot_a());
    for _ in 0..25 {
        h.commit_frame(&mut e, FrameDurability::Durable, None, &[ObjectKind::DiskImage]);
    }
    drop(e);
    for i in 0..5 {
        h.add_orphan(&format!("orphan-{i}"));
    }
    let before = h.pool_objects();
    assert!(matches!(
        h.try_open(boot_a()),
        Err(MetaError::OrphanCircuitBreakerTriggered {
            orphan_count: 5,
            total_objects: 30
        })
    ));
    assert_eq!(h.pool_objects(), before, "breaker must leave the scene untouched");
    assert!(h.quarantine_entries().is_empty());

    // Operator removes the suspicious entries: 2 / 27 = 7.4% is within limits.
    for i in 0..3 {
        std::fs::remove_file(h.objects_dir().join(format!("orphan-{i}"))).unwrap();
    }
    let (e, s) = h.open(boot_a());
    assert_eq!(s.orphans_quarantined, 2);
    assert_eq!(e.frames().unwrap().len(), 25);
    assert_eq!(h.pool_objects().len(), 25);
}
