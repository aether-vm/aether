//! Dedicated Gate 2 regression suite covering every P0, P1, and P2 finding from fsck's pre-audit.

mod common;

use std::ffi::OsString;
use std::sync::atomic::Ordering;

use aos_meta::{
    BTRFS_SUPER_MAGIC_RAW, Clock, CommitProofBundle, CreateWorldRequest, DeleteOutcome,
    FencingToken, FrameDurability, FrameState, Hold, IdempotencyKey, ManagedObject, MetaError,
    ObjectKind, PinSpec, PrepareFrameRequest, TimelineRecord, TimelineTarget, WorldFence,
    is_same_or_forbidden_fs,
};
use aos_types::{Ephemeral, PersistProof, Persisted};
use common::*;
use redb::{Database, TableDefinition};

const DISK_VM: &[ObjectKind] = &[ObjectKind::DiskImage, ObjectKind::VmState];
const HOUR: u64 = 3600 * 1000;

// ============================================================================ P0-1

#[test]
fn p0_1_tree_subvol_requires_subvolume_proof_and_rejects_dir_proof() {
    let h = Harness::new("p0-1-subvol-proof");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                None,
                &[ObjectKind::TreeSubvol],
            ),
            None,
        )
        .unwrap();
    let subvol = p.expected_objects[0];
    let path = h.create_object(&subvol, FrameDurability::Durable);

    // Weak `ProofKind::Dir` (which omits parent `objects/` fsync) must be rejected.
    let weak_proof = PersistProof::fsync_dir(&path).unwrap();
    let bad_bundle = CommitProofBundle::new().with_persisted(Persisted::new(subvol, weak_proof));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bad_bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));

    // `ProofKind::Subvolume` (`PersistProof::fsync_subvolume`) must be accepted.
    let strong_proof = PersistProof::fsync_subvolume(&path).unwrap();
    let ok_bundle = CommitProofBundle::new().with_persisted(Persisted::new(subvol, strong_proof));
    let committed = e
        .commit_frame(&Harness::commit_req(p.frame_id, "alice"), ok_bundle, None)
        .unwrap();
    assert_eq!(committed.frame_id, p.frame_id);
}

// ============================================================================ P0-2

#[test]
fn p0_2_verify_unchanged_at_commit_and_missing_committed_object_on_recovery() {
    let h = Harness::new("p0-2-verify-unchanged");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let disk = ManagedObject::new(p.frame_id, ObjectKind::DiskImage);
    let vm = ManagedObject::new(p.frame_id, ObjectKind::VmState);
    let disk_path = h.create_object(&disk, FrameDurability::Durable);
    let vm_path = h.create_object(&vm, FrameDurability::Durable);

    // Proof taken before the file is resized/truncated after fsync: must be rejected at commit.
    let stale_disk = h.persisted(&disk);
    std::fs::write(&disk_path, b"modified-after-fsync-longer-payload").unwrap();
    let bundle = CommitProofBundle::new()
        .with_persisted(stale_disk)
        .with_persisted(h.persisted(&vm));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));

    // Proof taken before the file is unlinked after fsync: must be rejected at commit.
    let vanished_vm = h.persisted(&vm);
    std::fs::remove_file(&vm_path).unwrap();
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(vanished_vm);
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bundle, None),
        Err(MetaError::ProofRejected { .. })
    ));

    // Re-create vmstate and commit properly.
    h.create_object(&vm, FrameDurability::Durable);
    let bundle = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_persisted(h.persisted(&vm));
    e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), bundle, None)
        .unwrap();
    drop(e);

    // Delete a committed pool object behind the engine's back -> R6 reverse check must fail.
    std::fs::remove_file(&disk_path).unwrap();
    match h.try_open(boot_a()) {
        Err(MetaError::MissingCommittedObject {
            frame_id,
            object_name,
        }) => {
            assert_eq!(frame_id, p.frame_id);
            assert_eq!(object_name, disk.name());
        }
        other => panic!("expected MissingCommittedObject, got {other:?}"),
    }
}

// ============================================================================ P0-3

#[test]
fn p0_3_small_pool_circuit_breaker_blocks_restored_backup_wipe() {
    let h = Harness::new("p0-3-small-pool-breaker");
    let (mut e, _) = h.open(boot_a());
    let base = h.commit_frame(
        &mut e,
        FrameDurability::Durable,
        None,
        &[ObjectKind::DiskImage],
    );
    drop(e);

    // Snapshot the 1-object redb backup.
    let backup_bytes = std::fs::read(h.cfg.db_path()).unwrap();

    // Advance the pool by committing 16 more 1-object frames (total = 17 < min_orphan_ratio_sample 20).
    let (mut e, _) = h.open(boot_a());
    for _ in 0..16 {
        h.commit_frame(
            &mut e,
            FrameDurability::Durable,
            Some(base),
            &[ObjectKind::DiskImage],
        );
    }
    drop(e);
    let pool_before = h.pool_objects();
    assert_eq!(pool_before.len(), 17);

    // Operator accidentally restores the old 1-object forkloom.redb backup (16/17 = 94% orphans).
    std::fs::write(h.cfg.db_path(), &backup_bytes).unwrap();
    match h.try_open(boot_a()) {
        Err(MetaError::OrphanCircuitBreakerTriggered {
            orphan_count,
            total_objects,
        }) => {
            assert_eq!(orphan_count, 16);
            assert_eq!(total_objects, 17);
        }
        other => panic!("expected OrphanCircuitBreakerTriggered, got {other:?}"),
    }
    assert_eq!(h.pool_objects(), pool_before, "pool must not be touched");
    assert!(h.quarantine_entries().is_empty());

    // Config validation rejects invalid max_small_pool_orphans bounds.
    let mut bad_zero = Harness::new("p0-3-cfg-zero");
    bad_zero.cfg.max_small_pool_orphans = 0;
    assert!(matches!(
        bad_zero.try_open(boot_a()),
        Err(MetaError::InvalidArgument(_))
    ));
    let mut bad_ge_sample = Harness::new("p0-3-cfg-sample");
    bad_ge_sample.cfg.max_small_pool_orphans = bad_ge_sample.cfg.min_orphan_ratio_sample;
    assert!(matches!(
        bad_ge_sample.try_open(boot_a()),
        Err(MetaError::InvalidArgument(_))
    ));
}

// ============================================================================ P0-4

#[test]
fn p0_4_volatile_frame_rejects_ephemeral_proof_for_pool_located_objects() {
    let h = Harness::new("p0-4-vol-pool-proof");
    let (mut e, _) = h.open(boot_a());
    let p = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Volatile,
                None,
                &[ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState],
            ),
            None,
        )
        .unwrap();
    let disk = ManagedObject::new(p.frame_id, ObjectKind::DiskImage);
    let mem = ManagedObject::new(p.frame_id, ObjectKind::MemImage);
    let vm = ManagedObject::new(p.frame_id, ObjectKind::VmState);
    h.create_object(&disk, FrameDurability::Volatile);
    h.create_object(&mem, FrameDurability::Volatile);
    h.create_object(&vm, FrameDurability::Volatile);

    // Ephemeral proof for Pool-located DiskImage on a Volatile frame must be rejected.
    let forged_disk = CommitProofBundle::new()
        .with_ephemeral(Ephemeral::new_for_boot(disk, boot_a()))
        .with_ephemeral(Ephemeral::new_for_boot(mem, boot_a()))
        .with_persisted(h.persisted(&vm));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), forged_disk, None),
        Err(MetaError::ProofRejected { .. })
    ));

    // Ephemeral proof for Pool-located VmState on a Volatile frame must be rejected.
    let forged_vm = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_ephemeral(Ephemeral::new_for_boot(mem, boot_a()))
        .with_ephemeral(Ephemeral::new_for_boot(vm, boot_a()));
    assert!(matches!(
        e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), forged_vm, None),
        Err(MetaError::ProofRejected { .. })
    ));

    // Proper Persisted proofs for Pool objects + Ephemeral proof for tmpfs MemImage succeeds.
    let valid = CommitProofBundle::new()
        .with_persisted(h.persisted(&disk))
        .with_ephemeral(Ephemeral::new_for_boot(mem, boot_a()))
        .with_persisted(h.persisted(&vm));
    e.commit_frame(&Harness::commit_req(p.frame_id, "alice"), valid, None)
        .unwrap();
}

// ============================================================================ P0-5

#[test]
fn p0_5_preflight_check_guarantees_zero_mutation_before_r1_r2_r3_r5() {
    let h = Harness::new("p0-5-preflight");
    let (mut e, _) = h.open(boot_a());

    // 1. A committed durable frame.
    let committed = h.durable(&mut e);
    // 2. An old-boot volatile frame (which R1/R5 would expire & destroy on boot_b).
    let _vol = h.volatile(&mut e);
    // 3. A running world (which R2 would fence, kill, and mark Lost).
    let _world = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: committed,
                labels: labels(&[("env", "prod")]),
                lease_ttl_ms: 10_000,
            },
            None,
        )
        .unwrap();
    // 4. An in-flight Preparing frame with an object on disk (which R3 would roll back & unlink).
    let prep = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                None,
                &[ObjectKind::DiskImage],
            ),
            None,
        )
        .unwrap();
    h.create_object(&prep.expected_objects[0], FrameDurability::Durable);
    // 5. A Deleting frame whose hook failed (which R5 would unlink).
    let to_del = h.commit_frame(
        &mut e,
        FrameDurability::Durable,
        None,
        &[ObjectKind::DiskImage],
    );
    h.ctl.fail_destroy.store(true, Ordering::SeqCst);
    let _ = e.delete_frame(to_del, "alice", None);
    h.ctl.fail_destroy.store(false, Ordering::SeqCst);
    drop(e);

    // Inject 3 wild orphans in this small pool (< 20 objects) to trip the R6 breaker.
    for i in 0..3 {
        h.add_orphan(&format!("wild-orphan-{i}"));
    }

    let db_before = std::fs::read(h.cfg.db_path()).unwrap();
    let pool_before = h.pool_objects();
    let tmpfs_before = h.tmpfs_objects();
    h.ctl.calls.lock().unwrap().clear();

    // Attempt recovery on a NEW boot (`boot_b()`): pre-flight must abort BEFORE R1/R2/R3/R5 run!
    assert!(matches!(
        h.try_open(boot_b()),
        Err(MetaError::OrphanCircuitBreakerTriggered { .. })
    ));

    assert_eq!(
        std::fs::read(h.cfg.db_path()).unwrap(),
        db_before,
        "redb must be byte-for-byte untouched when pre-flight breaker trips"
    );
    assert_eq!(
        h.pool_objects(),
        pool_before,
        "R3/R5 must not have deleted Preparing/Deleting/Volatile objects before R6 breaker"
    );
    assert_eq!(h.tmpfs_objects(), tmpfs_before);
    assert!(h.quarantine_entries().is_empty());
    assert!(
        h.ctl.calls().is_empty(),
        "no R2/R3/R5 hooks may run before pre-flight succeeds, got {:?}",
        h.ctl.calls()
    );

    // Remove the 3 orphans, then verify schema version check (`SYS_SCHEMA` -> `UnsupportedSchema`).
    for i in 0..3 {
        std::fs::remove_file(h.objects_dir().join(format!("wild-orphan-{i}"))).unwrap();
    }
    let bad_schema_db = h.root.join("bad_schema.redb");
    std::fs::copy(h.cfg.db_path(), &bad_schema_db).unwrap();
    {
        let sys_def: TableDefinition<'static, &'static str, &'static [u8]> =
            TableDefinition::new("system");
        let db = Database::open(h.cfg.db_path()).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut sys = tx.open_table(sys_def).unwrap();
            sys.insert("schema", b"99".as_slice()).unwrap();
        }
        tx.commit().unwrap();
    }
    let tampered_bytes = std::fs::read(h.cfg.db_path()).unwrap();
    assert!(matches!(
        h.try_open(boot_b()),
        Err(MetaError::UnsupportedSchema {
            found: Some(99),
            supported: 1
        })
    ));
    assert_eq!(std::fs::read(h.cfg.db_path()).unwrap(), tampered_bytes);
}

// ============================================================================ P1-1

#[test]
fn p1_1_timeline_ownership_and_delete_timeline() {
    let h = Harness::new("p1-1-timelines");
    let (mut e, _) = h.open(boot_a());
    let f_alice = h.durable(&mut e);
    let p_bob = e
        .prepare_frame(
            &Harness::prepare_req("bob", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let b_bob = h.produce(&p_bob, boot_a());
    e.commit_frame(&Harness::commit_req(p_bob.frame_id, "bob"), b_bob, None)
        .unwrap();
    let f_bob = p_bob.frame_id;

    // Alice cannot create a timeline pointing to Bob's frame.
    assert!(matches!(
        e.advance_timeline_cas("main", "alice", None, f_bob, None),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // Alice creates "main" on her own frame.
    e.advance_timeline_cas("main", "alice", None, f_alice, None)
        .unwrap();
    assert_eq!(
        e.timeline("main").unwrap(),
        Some(TimelineRecord {
            head: f_alice,
            owner: "alice".into(),
        })
    );

    // Bob cannot hijack Alice's timeline onto Bob's frame (either via advance_timeline_cas or commit_frame).
    assert!(matches!(
        e.advance_timeline_cas("main", "bob", Some(f_alice), f_bob, None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    let p_bob2 = e
        .prepare_frame(
            &Harness::prepare_req("bob", FrameDurability::Durable, Some(f_bob), DISK_VM),
            None,
        )
        .unwrap();
    let b_bob2 = h.produce(&p_bob2, boot_a());
    let mut c_bob2 = Harness::commit_req(p_bob2.frame_id, "bob");
    c_bob2.timeline = Some(TimelineTarget {
        timeline: "main".into(),
        expected_old: Some(f_alice),
    });
    assert!(matches!(
        e.commit_frame(&c_bob2, b_bob2, None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert_eq!(e.timeline_head("main").unwrap(), Some(f_alice));

    // Bob cannot delete Alice's timeline; deleting an unknown timeline returns TimelineNotFound.
    assert!(matches!(
        e.delete_timeline("main", "bob", None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert!(matches!(
        e.delete_timeline("unknown", "alice", None),
        Err(MetaError::TimelineNotFound(name)) if name == "unknown"
    ));

    // Alice deletes "main" idempotently; the TimelineHead hold on f_alice is released.
    let del_key = IdempotencyKey::new("alice", "del-tl-1");
    assert_eq!(
        e.delete_timeline("main", "alice", Some(&del_key)).unwrap(),
        f_alice
    );
    assert_eq!(
        e.delete_timeline("main", "alice", Some(&del_key)).unwrap(),
        f_alice,
        "idempotent replay of delete_timeline"
    );
    assert!(e.timeline("main").unwrap().is_none());
    assert!(e.holds(f_alice).unwrap().is_empty());
}

// ============================================================================ P1-2

#[test]
fn p1_2_frame_ownership_acls_and_ttl_bounds() {
    let h = Harness::new("p1-2-acls-ttls");
    let (mut e, _) = h.open(boot_a());
    let f_alice = h.durable(&mut e);

    // 1. Bob cannot pin Alice's frame.
    assert!(matches!(
        e.pin_frame(
            f_alice,
            &PinSpec {
                pin_id: "dos".into(),
                owner: "bob".into(),
                lease_ttl_ms: 1_000,
            }
        ),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // 2. Alice cannot pin with lease_ttl_ms > max_pin_ttl_ms (or u64::MAX).
    let max_pin = e.config().max_pin_ttl_ms;
    for bad_ttl in [0, max_pin + 1, u64::MAX] {
        assert!(matches!(
            e.pin_frame(
                f_alice,
                &PinSpec {
                    pin_id: "p".into(),
                    owner: "alice".into(),
                    lease_ttl_ms: bad_ttl,
                }
            ),
            Err(MetaError::InvalidArgument(_))
        ));
    }

    // 3. commit_frame rejects pin with mismatched owner or out-of-range TTL.
    let p = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM),
            None,
        )
        .unwrap();
    let bundle = h.produce(&p, boot_a());
    let mut req = Harness::commit_req(p.frame_id, "alice");
    req.pin = Some(PinSpec {
        pin_id: "p".into(),
        owner: "bob".into(),
        lease_ttl_ms: 1_000,
    });
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // 4. Bob cannot fork a child frame from Alice's parent frame.
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req("bob", FrameDurability::Durable, Some(f_alice), DISK_VM),
            None
        ),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // 5. Bob cannot launch a world from Alice's base frame, and world lease_ttl_ms is bounded.
    assert!(matches!(
        e.create_world(
            &CreateWorldRequest {
                owner: "bob".into(),
                base_frame: f_alice,
                labels: Default::default(),
                lease_ttl_ms: 1_000,
            },
            None
        ),
        Err(MetaError::OwnerMismatch { .. })
    ));
    let max_world = e.config().max_world_lease_ttl_ms;
    for bad_ttl in [0, max_world + 1, u64::MAX] {
        assert!(matches!(
            e.create_world(
                &CreateWorldRequest {
                    owner: "alice".into(),
                    base_frame: f_alice,
                    labels: Default::default(),
                    lease_ttl_ms: bad_ttl,
                },
                None
            ),
            Err(MetaError::InvalidArgument(_))
        ));
    }
}

// ============================================================================ P1-3

#[test]
fn p1_3_create_world_replay_never_leaks_post_takeover_fencing_token() {
    let h = Harness::new("p1-3-world-replay-fence");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let key = IdempotencyKey::new("alice", "create-world-1");
    let req = CreateWorldRequest {
        owner: "alice".into(),
        base_frame: f,
        labels: Default::default(),
        lease_ttl_ms: 10_000,
    };

    let created = e.create_world(&req, Some(&key)).unwrap();
    assert_eq!(created.fencing_token, FencingToken::FIRST);

    // Another executor takes over the world (token 2).
    let t2 = e.acquire_world_fence(created.world_id, "alice").unwrap();
    assert_eq!(t2.get(), 2);

    // Partitioned original creator replays create_world: must get FencingToken::FIRST (1), NOT 2!
    let replayed = e.create_world(&req, Some(&key)).unwrap();
    assert_eq!(replayed.world_id, created.world_id);
    assert_eq!(replayed.fencing_token, FencingToken::FIRST);

    // Using the replayed token is properly fenced out.
    assert!(matches!(
        e.check_world_mutation(created.world_id, "alice", replayed.fencing_token),
        Err(MetaError::FencedOut {
            presented,
            current,
            ..
        }) if presented == FencingToken::FIRST && current == t2
    ));

    // Config validation requires world_tombstone_ttl_ms >= idempotency_ttl_ms.
    let mut bad_cfg = Harness::new("p1-3-bad-tombstone-ttl");
    bad_cfg.cfg.world_tombstone_ttl_ms = bad_cfg.cfg.idempotency_ttl_ms - 1;
    assert!(matches!(
        bad_cfg.try_open(boot_a()),
        Err(MetaError::InvalidArgument(_))
    ));
}

// ============================================================================ P1-4

#[test]
fn p1_4_prepare_commit_and_acquire_fence_require_running_world_and_live_lease() {
    let h = Harness::new("p1-4-world-liveness");
    let (mut e, _) = h.open(boot_a());
    let base = h.durable(&mut e);

    // Case 1: World destroyed after prepare_frame -> commit_frame must fail with WorldNotRunning.
    let w1 = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: base,
                labels: Default::default(),
                lease_ttl_ms: 10_000,
            },
            None,
        )
        .unwrap();
    let prep1 = e
        .prepare_frame(
            &PrepareFrameRequest {
                owner: "alice".into(),
                durability: FrameDurability::Durable,
                parent: Some(base),
                object_kinds: vec![ObjectKind::DiskImage],
                labels: Default::default(),
                source_world: Some(WorldFence {
                    world_id: w1.world_id,
                    token: w1.fencing_token,
                }),
            },
            None,
        )
        .unwrap();
    let bundle1 = h.produce(&prep1, boot_a());
    e.destroy_world(w1.world_id, "alice", w1.fencing_token, None)
        .unwrap();
    let mut creq1 = Harness::commit_req(prep1.frame_id, "alice");
    creq1.fence = Some(w1.fencing_token);
    assert!(matches!(
        e.commit_frame(&creq1, bundle1, None),
        Err(MetaError::WorldNotRunning(id)) if id == w1.world_id
    ));

    // Case 2: World's in-memory lease expires before expire_due_world_leases runs.
    let w2 = e
        .create_world(
            &CreateWorldRequest {
                owner: "alice".into(),
                base_frame: base,
                labels: Default::default(),
                lease_ttl_ms: 1_000,
            },
            None,
        )
        .unwrap();
    let prep2 = e
        .prepare_frame(
            &PrepareFrameRequest {
                owner: "alice".into(),
                durability: FrameDurability::Durable,
                parent: Some(base),
                object_kinds: vec![ObjectKind::DiskImage],
                labels: Default::default(),
                source_world: Some(WorldFence {
                    world_id: w2.world_id,
                    token: w2.fencing_token,
                }),
            },
            None,
        )
        .unwrap();
    let bundle2 = h.produce(&prep2, boot_a());

    // Advance monotonic clock past w2's 1_000ms lease without running expire_due_world_leases.
    h.clock.advance(1_000);

    assert!(matches!(
        e.acquire_world_fence(w2.world_id, "alice"),
        Err(MetaError::WorldNotRunning(id)) if id == w2.world_id
    ));
    assert!(matches!(
        e.prepare_frame(
            &PrepareFrameRequest {
                owner: "alice".into(),
                durability: FrameDurability::Durable,
                parent: Some(base),
                object_kinds: vec![ObjectKind::DiskImage],
                labels: Default::default(),
                source_world: Some(WorldFence {
                    world_id: w2.world_id,
                    token: w2.fencing_token,
                }),
            },
            None,
        ),
        Err(MetaError::WorldNotRunning(id)) if id == w2.world_id
    ));
    let mut creq2 = Harness::commit_req(prep2.frame_id, "alice");
    creq2.fence = Some(w2.fencing_token);
    assert!(matches!(
        e.commit_frame(&creq2, bundle2, None),
        Err(MetaError::WorldNotRunning(id)) if id == w2.world_id
    ));
}

// ============================================================================ P1-5

#[test]
fn p1_5_wall_clock_jumps_never_expire_active_pins_or_shrink_high_ms() {
    let h = Harness::new("p1-5-wall-jumps");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let ttl = 60_000;
    e.pin_frame(
        f,
        &PinSpec {
            pin_id: "pin-1".into(),
            owner: "alice".into(),
            lease_ttl_ms: ttl,
        },
    )
    .unwrap();
    // Mark frame for deferred deletion so any false pin expiry would physically delete it.
    assert_eq!(
        e.delete_frame(f, "alice", None).unwrap(),
        DeleteOutcome::Deferred { holds: 1 }
    );

    // 1. Huge forward wall-clock jump (10 hours) with zero elapsed monotonic time.
    h.clock.jump_wall(10 * HOUR);
    let gc = e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!(gc.pins_expired, 0, "forward wall jump must not expire active pin");
    assert_eq!(gc.frames_deleted, 0, "pinned frame must not be deleted on wall jump");
    assert!(e.frame(f).unwrap().is_some());

    // Renewing after a forward wall jump must succeed.
    let r_fwd = e.renew_pin_lease(f, "pin-1", "alice").unwrap();
    assert!(r_fwd.expires_at_ms >= T0 + 10 * HOUR + ttl);

    // 2. Huge backward wall-clock jump (back to 1_000ms) must not shrink high_ms or stall flushes.
    h.clock.set_wall(1_000);
    let r_back = e.renew_pin_lease(f, "pin-1", "alice").unwrap();
    assert_eq!(
        r_back.expires_at_ms, r_fwd.expires_at_ms,
        "backward wall jump must never shrink high_ms"
    );
    // Advance monotonic time by pin_flush_interval_ms (less than pin TTL = 60_000 vanishes? No, interval = 60_000, advance 30_000 twice with renewal).
    h.clock.advance(30_000);
    e.renew_pin_lease(f, "pin-1", "alice").unwrap();
    h.clock.advance(30_000);
    let r_flushed = e.renew_pin_lease(f, "pin-1", "alice").unwrap();
    assert!(
        r_flushed.flushed,
        "monotonic flush interval must trigger even when wall clock jumped backward"
    );

    // 3. Only when monotonic time advances by full TTL without renewal does GC expire the pin.
    h.clock.advance(ttl);
    let gc = e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!(gc.pins_expired, 1);
    assert_eq!(gc.frames_deleted, 1);
    assert!(e.frame(f).unwrap().is_none());
}

// ============================================================================ P1-6 & P2-6

#[test]
fn p1_6_delete_frame_idempotency_on_hook_failure_and_abort_prepare_idempotency() {
    let h = Harness::new("p1-6-delete-idem");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    let del_key = IdempotencyKey::new("alice", "del-f-1");

    // (a) Hook fails on first delete_frame call -> frame enters Deleting, objects remain on disk.
    h.ctl.fail_destroy.store(true, Ordering::SeqCst);
    assert!(matches!(
        e.delete_frame(f, "alice", Some(&del_key)),
        Err(MetaError::Hook { .. })
    ));
    assert!(matches!(
        e.frame(f).unwrap().unwrap().state,
        FrameState::Deleting { .. }
    ));
    assert_eq!(h.pool_objects().len(), 2);

    // P2-6: Another owner cannot call delete_frame on Alice's Deleting frame.
    assert!(matches!(
        e.delete_frame(f, "mallory", None),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // Retrying with the same IdempotencyKey while hook still fails still returns the hook error.
    assert!(matches!(
        e.delete_frame(f, "alice", Some(&del_key)),
        Err(MetaError::Hook { .. })
    ));

    // Once the hook recovers, retrying with the same IdempotencyKey completes physical deletion.
    h.ctl.fail_destroy.store(false, Ordering::SeqCst);
    assert_eq!(
        e.delete_frame(f, "alice", Some(&del_key)).unwrap(),
        DeleteOutcome::Deleted
    );
    assert!(e.frame(f).unwrap().is_none());
    assert!(h.pool_objects().is_empty());

    // Subsequent replay after completion is a clean no-op returning Deleted.
    assert_eq!(
        e.delete_frame(f, "alice", Some(&del_key)).unwrap(),
        DeleteOutcome::Deleted
    );

    // (b) Aborting a Preparing frame drops its prepare_frame idempotency record.
    let prep_key = IdempotencyKey::new("alice", "prep-abort-1");
    let prep_req = Harness::prepare_req("alice", FrameDurability::Durable, None, DISK_VM);
    let p1 = e.prepare_frame(&prep_req, Some(&prep_key)).unwrap();

    // If abort is interrupted by hook failure (state = Deleting) and prepare_frame is replayed
    // before deletion finishes, PreparedFrameAborted is returned.
    h.ctl.fail_destroy.store(true, Ordering::SeqCst);
    let _ = e.delete_frame(p1.frame_id, "alice", None);
    h.ctl.fail_destroy.store(false, Ordering::SeqCst);
    assert!(matches!(
        e.prepare_frame(&prep_req, Some(&prep_key)),
        Err(MetaError::PreparedFrameAborted(id)) if id == p1.frame_id
    ));

    // After abort completes, retrying prepare_frame with prep_key allocates a fresh frame.
    e.delete_frame(p1.frame_id, "alice", None).unwrap();
    let p2 = e.prepare_frame(&prep_req, Some(&prep_key)).unwrap();
    assert_ne!(p2.frame_id, p1.frame_id);
    assert!(matches!(
        e.frame(p2.frame_id).unwrap().unwrap().state,
        FrameState::Preparing { .. }
    ));
}

// ============================================================================ P1-7

#[test]
fn p1_7_btrfs_subvolume_and_fsid_same_filesystem_detection() {
    const EXT4_SUPER_MAGIC: i64 = 0xef53;
    // Different synthetic st_dev (Btrfs subvolumes), same f_fsid -> forbidden.
    assert!(is_same_or_forbidden_fs(
        41,
        42,
        [0x1234, 0x5678],
        [0x1234, 0x5678],
        EXT4_SUPER_MAGIC
    ));
    // Different st_dev and different f_fsid, but meta_dir is on Btrfs -> forbidden.
    assert!(is_same_or_forbidden_fs(
        41,
        99,
        [1, 2],
        [3, 4],
        BTRFS_SUPER_MAGIC_RAW
    ));
    // Same st_dev -> forbidden.
    assert!(is_same_or_forbidden_fs(
        41,
        41,
        [1, 2],
        [3, 4],
        EXT4_SUPER_MAGIC
    ));
    // Distinct st_dev, distinct f_fsid, and meta_dir on ext4/XFS -> allowed.
    assert!(!is_same_or_forbidden_fs(
        41,
        99,
        [1, 2],
        [3, 4],
        EXT4_SUPER_MAGIC
    ));
}

// ============================================================================ P1-9

#[test]
fn p1_9_prepare_frame_rejects_pending_reclaim_parent_and_holds_parent_while_preparing() {
    let h = Harness::new("p1-9-parent-hold");
    let (mut e, _) = h.open(boot_a());
    let parent = h.volatile(&mut e);

    // 1. If parent is already in PENDING_RECLAIM, prepare_frame(parent) is rejected.
    e.pin_frame(
        parent,
        &PinSpec {
            pin_id: "p".into(),
            owner: "alice".into(),
            lease_ttl_ms: 10_000,
        },
    )
    .unwrap();
    assert_eq!(
        e.delete_frame(parent, "alice", None).unwrap(),
        DeleteOutcome::Deferred { holds: 1 }
    );
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                Some(parent),
                &[ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState],
            ),
            None,
        ),
        Err(MetaError::FrameMarkedForDeletion(id)) if id == parent
    ));

    // 2. Fresh parent: prepare_frame attaches Hold::PreparingParent, preventing mid-copy deletion.
    let parent2 = h.volatile(&mut e);
    let child1 = e
        .prepare_frame(
            &Harness::prepare_req(
                "alice",
                FrameDurability::Durable,
                Some(parent2),
                &[ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState],
            ),
            None,
        )
        .unwrap();
    assert_eq!(
        e.holds(parent2).unwrap(),
        vec![Hold::PreparingParent {
            child_frame: child1.frame_id
        }]
    );
    assert_eq!(
        e.delete_frame(parent2, "alice", None).unwrap(),
        DeleteOutcome::Deferred { holds: 1 },
        "parent must not be deleted while child is Preparing"
    );
    assert_eq!(e.collect_garbage(h.clock.now_ms()).unwrap().frames_deleted, 0);
    assert!(e.frame(parent2).unwrap().is_some());

    // Committing child1 releases PreparingParent, allowing GC to reclaim parent2.
    let bundle1 = h.produce(&child1, boot_a());
    e.commit_frame(&Harness::commit_req(child1.frame_id, "alice"), bundle1, None)
        .unwrap();
    assert!(e.holds(parent2).unwrap().is_empty());
    assert_eq!(e.collect_garbage(h.clock.now_ms()).unwrap().frames_deleted, 1);
    assert!(e.frame(parent2).unwrap().is_none());

    // 3. Aborting a Preparing child also releases PreparingParent on its parent.
    let parent3 = h.durable(&mut e);
    let child2 = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, Some(parent3), DISK_VM),
            None,
        )
        .unwrap();
    assert_eq!(e.holds(parent3).unwrap().len(), 1);
    e.delete_frame(child2.frame_id, "alice", None).unwrap();
    assert!(e.holds(parent3).unwrap().is_empty());

    // 4. Crash rollback (R3) also releases PreparingParent on its parent.
    let child3 = e
        .prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, Some(parent3), DISK_VM),
            None,
        )
        .unwrap();
    assert_eq!(
        e.holds(parent3).unwrap(),
        vec![Hold::PreparingParent {
            child_frame: child3.frame_id
        }]
    );
    drop(e);
    let (e, s) = h.open(boot_a());
    assert_eq!(s.preparing_rolled_back, 1);
    assert!(e.holds(parent3).unwrap().is_empty());
}

// ============================================================================ P2-2 & P2-3

#[test]
fn p2_2_and_p2_3_quarantine_raw_filename_and_corrupt_hold_key_safety() {
    // P2-2: QuarantineRecord preserves raw OsString when present.
    let rec = aos_meta::QuarantineRecord {
        name: "lossy\u{fffd}".into(),
        raw_name: Some(OsString::from("exact-raw-os-name")),
        quarantined_epoch: aos_types::EpochId::FIRST,
        quarantined_at_ms: T0,
        purge_after_ms: T0 + 1_000,
    };
    assert_eq!(rec.file_name(), OsString::from("exact-raw-os-name"));

    // P2-3: Malformed short key in HOLDS returns MetaError::Codec instead of panicking.
    let h = Harness::new("p2-3-corrupt-hold-key");
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    e.pin_frame(
        f,
        &PinSpec {
            pin_id: "p".into(),
            owner: "alice".into(),
            lease_ttl_ms: 1_000,
        },
    )
    .unwrap();
    drop(e);

    {
        let holds_def: TableDefinition<'static, &'static str, &'static [u8]> =
            TableDefinition::new("holds");
        let db = Database::open(h.cfg.db_path()).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut holds = tx.open_table(holds_def).unwrap();
            let bad_hold = serde_json::to_vec(&Hold::Pin {
                pin_id: "bad".into(),
                owner: "alice".into(),
                lease_ttl_ms: 1_000,
                expires_at_ms: T0 + 1_000,
            })
            .unwrap();
            holds.insert("short", bad_hold.as_slice()).unwrap();
        }
        tx.commit().unwrap();
    }
    assert!(matches!(h.try_open(boot_a()), Err(MetaError::Codec(_))));
}
