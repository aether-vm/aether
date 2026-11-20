//! I1 ~ I4: intent first, typed durability proofs, unique commit point, rollback-only recovery.

mod common;

use std::sync::atomic::Ordering;

use aos_meta::{
    CommitProofBundle, DeleteOutcome, FrameDurability, FrameState, Hold, IdempotencyKey,
    ManagedObject, MetaError, ObjectKind, PinSpec, TimelineTarget,
};
use aos_types::{Ephemeral, PersistProof, Persisted};
use common::*;

const DISK_VM: &[ObjectKind] = &[ObjectKind::DiskImage, ObjectKind::VmState];

#[test]
fn crash_after_prepare_rolls_back_half_written_objects_only() {
    let h = Harness::new("i4-rollback");
    let (mut e, _) = h.open(boot_a());
    let committed = h.durable(&mut e);
    let committed_names = names(&e, committed);

    let prepared = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                Some(committed),
                &[ObjectKind::TreeSubvol, ObjectKind::DiskImage, ObjectKind::MemImage],
            ),
            None,
        )
        .unwrap();
    // Half the artifacts exist when the process "crashes": a truncated disk and a subvolume.
    let disk = ManagedObject::new(prepared.frame_id, ObjectKind::DiskImage);
    std::fs::write(h.objects_dir().join(disk.name()), b"trunc").unwrap();
    h.create_object(
        &ManagedObject::new(prepared.frame_id, ObjectKind::TreeSubvol),
        FrameDurability::Durable,
    );
    assert_eq!(h.pool_objects().len(), 4);
    drop(e); // crash

    let (e, s) = h.open(boot_a());
    assert_eq!(s.preparing_rolled_back, 1);
    assert_eq!(s.orphans_quarantined, 0, "half objects are destroyed by R3, not quarantined");
    assert!(e.frame(prepared.frame_id).unwrap().is_none());
    assert_eq!(
        h.pool_objects(),
        committed_names.iter().cloned().collect(),
        "only the committed frame's objects survive"
    );
    assert!(matches!(
        e.frame(committed).unwrap().unwrap().state,
        FrameState::Committed { .. }
    ));
}

#[test]
fn prepare_idempotency_is_dropped_with_the_rolled_back_frame() {
    let h = Harness::new("i4-idem");
    let (mut e, _) = h.open(boot_a());
    let key = IdempotencyKey::new("alice", "req-prepare-1");
    let req = Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM);
    let first = e.prepare_frame(&req, Some(&key)).unwrap();
    assert_eq!(e.prepare_frame(&req, Some(&key)).unwrap(), first, "replay before crash");
    drop(e);

    let (mut e, s) = h.open(boot_a());
    assert_eq!(s.preparing_rolled_back, 1);
    let retry = e.prepare_frame(&req, Some(&key)).unwrap();
    assert_ne!(retry.frame_id, first.frame_id, "retry must re-run the protocol");
    assert!(matches!(
        e.frame(retry.frame_id).unwrap().unwrap().state,
        FrameState::Preparing { .. }
    ));
}

#[test]
fn durable_commit_demands_exact_persisted_proofs() {
    let h = Harness::new("i2-proofs");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let disk = ManagedObject::new(p.frame_id, ObjectKind::DiskImage);
    let vm = ManagedObject::new(p.frame_id, ObjectKind::VmState);
    h.create_object(&disk, FrameDurability::Durable);
    h.create_object(&vm, FrameDurability::Durable);
    let req = Harness::commit_req(p.frame_id, "alice");

    // Ephemeral proof on a durable frame.
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_ephemeral(Ephemeral::new_for_boot(vm, boot_a()));
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    // Missing proof.
    let bundle = CommitProofBundle::new().with_persisted(h.persisted(&disk));
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    // Proof that fsynced some other file.
    let elsewhere = h.root.join("elsewhere.bin");
    std::fs::write(&elsewhere, b"x").unwrap();
    let forged = Persisted::new(vm, PersistProof::fsync_file_and_parent(&elsewhere).unwrap());
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(forged);
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    // Proof for an object of another frame / duplicate proof.
    let foreign = ManagedObject::new(aos_types::FrameId::random(), ObjectKind::VmState);
    h.create_object(&foreign, FrameDurability::Durable);
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&foreign));
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&vm));
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    assert!(matches!(
        e.frame(p.frame_id).unwrap().unwrap().state,
        FrameState::Preparing { .. }
    ));
    // Wrong owner.
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&vm));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "mallory"), bundle, None),
        Err(MetaError::OwnerMismatch { .. })
    ));

    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&vm));
    let c = e.commit_frame(&req, bundle, None).unwrap();
    assert_eq!(c.objects, vec![disk, vm]);
    let bundle = CommitProofBundle::new();
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::FrameWrongState { .. })
    ));
}

#[test]
fn commit_replay_with_same_key_needs_no_proofs_and_conflicts_on_change() {
    let h = Harness::new("i3-idem");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let bundle = h.produce(&p, boot_a());
    let key = IdempotencyKey::new("alice", "commit-1");
    let req = Harness::commit_req(p.frame_id, "alice");
    let first = e.commit_frame(&req, bundle, Some(&key)).unwrap();
    drop(e);
    let (mut e, _) = h.open(boot_a());
    assert_eq!(
        e.commit_frame(&req, CommitProofBundle::new(), Some(&key)).unwrap(),
        first
    );
    let mut changed = req.clone();
    changed.disk_clean = false;
    assert!(matches!(
        e.commit_frame(&changed, CommitProofBundle::new(), Some(&key)),
        Err(MetaError::IdempotencyConflict { .. })
    ));
}

#[test]
fn volatile_frames_can_never_become_timeline_heads() {
    let h = Harness::new("x-timeline");
    let (mut e, _) = h.open(boot_a());
    let v = h.volatile(&mut e);
    assert!(matches!(
        e.advance_timeline_cas("main", None, v, None),
        Err(MetaError::VolatileInTimelineForbidden(f)) if f == v
    ));
    assert_eq!(e.timeline_head("main").unwrap(), None);

    // Same rule inside the atomic commit path.
    let p = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Volatile,
                None,
                &[ObjectKind::DiskImage, ObjectKind::MemImage],
            ),
            None,
        )
        .unwrap();
    let bundle = h.produce(&p, boot_a());
    let mut req = Harness::commit_req(p.frame_id, "alice");
    req.timeline = Some(TimelineTarget {
        timeline: "main".into(),
        expected_old: None,
    });
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::VolatileInTimelineForbidden(_))
    ));
    assert_eq!(e.timeline_head("main").unwrap(), None);
}

#[test]
fn durable_child_of_volatile_parent_requires_full_mem_promotion() {
    let h = Harness::new("x-promote");
    let (mut e, _) = h.open(boot_a());
    let parent = h.volatile(&mut e);

    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, Some(parent), DISK_VM),
            None
        ),
        Err(MetaError::MemPromotionRequired { parent: p }) if p == parent
    ));
    let p = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                Some(parent),
                &[ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState],
            ),
            None,
        )
        .unwrap();
    assert!(p.requires_full_mem_promotion);
    let [disk, mem, vm] = [ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState]
        .map(|k| ManagedObject::new(p.frame_id, k));
    for o in [disk, mem, vm] {
        h.create_object(&o, FrameDurability::Durable);
    }
    // Memory still only "ephemeral" (e.g. left in tmpfs): rejected.
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_ephemeral(Ephemeral::new_for_boot(mem, boot_a()))
        .with_persisted(h.persisted(&vm));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&mem))
        .with_persisted(h.persisted(&vm));
    e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bundle, None)
        .unwrap();
    e.advance_timeline_cas("main", None, p.frame_id, None).unwrap();
}

#[test]
fn volatile_memory_proof_from_another_boot_is_rejected() {
    let h = Harness::new("x-boot-proof");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Volatile,
                None,
                &[ObjectKind::MemImage],
            ),
            None,
        )
        .unwrap();
    let mem = p.expected_objects[0];
    h.create_object(&mem, FrameDurability::Volatile);
    let stale = CommitProofBundle::new().with_ephemeral(Ephemeral::new_for_boot(mem, boot_b()));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), stale, None),
        Err(MetaError::ProofRejected { .. })
    ));
    // A Persisted proof cannot stand in for a tmpfs memory image either.
    std::fs::write(h.objects_dir().join(mem.name()), b"x").unwrap();
    let wrong = CommitProofBundle::new().with_persisted(h.persisted(&mem));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), wrong, None),
        Err(MetaError::ProofRejected { .. })
    ));
    std::fs::remove_file(h.objects_dir().join(mem.name())).unwrap();
    let ok = CommitProofBundle::new().with_ephemeral(Ephemeral::new_for_boot(mem, boot_a()));
    e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), ok, None)
        .unwrap();
}

#[test]
fn timeline_cas_moves_the_head_hold_atomically() {
    let h = Harness::new("timeline-cas");
    let (mut e, _) = h.open(boot_a());
    let a = h.durable(&mut e);
    let b = h.durable(&mut e);
    let head = |name: &str| Hold::TimelineHead {
        timeline_name: name.into(),
    };

    e.advance_timeline_cas("main", None, a, None).unwrap();
    assert_eq!(e.holds(a).unwrap(), vec![head("main")]);
    match e.advance_timeline_cas("main", None, b, None) {
        Err(MetaError::TimelineCasMismatch { actual, .. }) => assert_eq!(actual, Some(a)),
        other => panic!("expected CAS mismatch, got {other:?}"),
    }
    let adv = e.advance_timeline_cas("main", Some(a), b, None).unwrap();
    assert_eq!(adv.previous, Some(a));
    assert!(e.holds(a).unwrap().is_empty());
    assert_eq!(e.holds(b).unwrap(), vec![head("main")]);
    assert_eq!(e.timeline_head("main").unwrap(), Some(b));

    // Atomic commit + CAS.
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, Some(b), DISK_VM),
            None,
        )
        .unwrap();
    let bundle = h.produce(&p, boot_a());
    let mut req = Harness::commit_req(p.frame_id, "alice");
    req.timeline = Some(TimelineTarget {
        timeline: "main".into(),
        expected_old: Some(b),
    });
    let c = e.commit_frame(&req, bundle, None).unwrap();
    assert_eq!(c.timeline.unwrap().head, p.frame_id);
    assert!(e.holds(b).unwrap().is_empty());
    drop(e);
    let (e, _) = h.open(boot_a());
    assert_eq!(e.timeline_head("main").unwrap(), Some(p.frame_id));
}

#[test]
fn failed_cas_inside_commit_leaves_the_frame_preparing() {
    let h = Harness::new("commit-cas-fail");
    let (mut e, _) = h.open(boot_a());
    let a = h.durable(&mut e);
    e.advance_timeline_cas("main", None, a, None).unwrap();
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let bundle = h.produce(&p, boot_a());
    let mut req = Harness::commit_req(p.frame_id, "alice");
    req.timeline = Some(TimelineTarget {
        timeline: "main".into(),
        expected_old: None,
    });
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::TimelineCasMismatch { .. })
    ));
    assert!(matches!(
        e.frame(p.frame_id).unwrap().unwrap().state,
        FrameState::Preparing { .. }
    ));
    assert_eq!(e.timeline_head("main").unwrap(), Some(a));
}

#[test]
fn held_frames_are_deferred_and_reclaimed_once_unheld() {
    let h = Harness::new("delete-deferred");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let files = names(&e, f);
    e.pin_frame(
        f,
        &PinSpec {
            pin_id: "keep".into(),
            owner: "alice".into(),
            lease_ttl_ms: 60_000,
        },
    )
    .unwrap();
    assert!(matches!(
        e.delete_frame(f, "mallory", None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert_eq!(
        e.delete_frame(f, "alice", None).unwrap(),
        DeleteOutcome::Deferred { holds: 1 }
    );
    assert!(e.is_marked_for_reclaim(f).unwrap());
    assert!(matches!(
        e.pin_frame(
            f,
            &PinSpec {
                pin_id: "late".into(),
                owner: "alice".into(),
                lease_ttl_ms: 1
            }
        ),
        Err(MetaError::FrameMarkedForDeletion(_))
    ));
    assert_eq!(e.collect_garbage(T0).unwrap().frames_deleted, 0);
    assert!(files.iter().all(|n| h.pool_objects().contains(n)));

    e.unpin_frame(f, "keep", "alice").unwrap();
    let gc = e.collect_garbage(T0).unwrap();
    assert_eq!(gc.frames_deleted, 1);
    assert!(e.frame(f).unwrap().is_none());
    assert!(h.pool_objects().is_empty());
}

#[test]
fn deletion_interrupted_by_hook_failure_is_finished_by_recovery() {
    let h = Harness::new("r5-resume");
    let (mut e, _) = h.open(boot_a());
    let keep = h.durable(&mut e);
    let f = h.durable(&mut e);
    h.ctl.fail_destroy.store(true, Ordering::SeqCst);
    assert!(matches!(
        e.delete_frame(f, "alice", None),
        Err(MetaError::Hook { .. })
    ));
    assert!(matches!(
        e.frame(f).unwrap().unwrap().state,
        FrameState::Deleting { .. }
    ));
    assert_eq!(h.pool_objects().len(), 4);
    drop(e);

    // Recovery with a failing hook refuses to start but loses nothing.
    assert!(matches!(h.try_open(boot_a()), Err(MetaError::Hook { .. })));
    h.ctl.fail_destroy.store(false, Ordering::SeqCst);
    let (e, s) = h.open(boot_a());
    assert_eq!(s.deleting_completed, 1);
    assert!(e.frame(f).unwrap().is_none());
    assert_eq!(h.pool_objects(), names(&e, keep).into_iter().collect());
}

#[test]
fn aborting_a_preparing_frame_destroys_partial_objects() {
    let h = Harness::new("abort");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    h.create_object(&p.expected_objects[0], FrameDurability::Durable);
    assert_eq!(
        e.delete_frame(p.frame_id, "alice", None).unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(e.frame(p.frame_id).unwrap().is_none());
    assert!(h.pool_objects().is_empty());
}

#[test]
fn prepare_validates_parent_kinds_and_labels() {
    let h = Harness::new("prepare-validate");
    let (mut e, _) = h.open(boot_a());
    let missing = aos_types::FrameId::random();
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, Some(missing), DISK_VM),
            None
        ),
        Err(MetaError::FrameNotFound(_))
    ));
    let pending = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                Some(pending.frame_id),
                DISK_VM
            ),
            None
        ),
        Err(MetaError::FrameWrongState { .. })
    ));
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                None,
                &[ObjectKind::DiskImage, ObjectKind::DiskImage]
            ),
            None
        ),
        Err(MetaError::InvalidArgument(_))
    ));
    let mut req = Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM);
    req.labels = (0..33).map(|i| (format!("k{i}"), "v".to_owned())).collect();
    assert!(matches!(
        e.prepare_frame(&req, None),
        Err(MetaError::InvalidLabels(_))
    ));
    req.labels = labels(&[("k", &"v".repeat(513))]);
    assert!(matches!(
        e.prepare_frame(&req, None),
        Err(MetaError::InvalidLabels(_))
    ));
}
