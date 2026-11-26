//! World lifecycle: idempotency across crashes, fencing tokens, label selectors, leases, pins.

mod common;

use aos_meta::{
    Clock, CreateWorldRequest, FencingToken, FrameDurability, Hold, IdempotencyKey, MetaEngine,
    MetaError, ObjectKind, PinSpec, PrepareFrameRequest, WorldEndReason, WorldFence, WorldState,
};
use aos_types::FrameId;
use common::*;

fn world_req(base: FrameId, pairs: &[(&str, &str)]) -> CreateWorldRequest {
    CreateWorldRequest {
        owner: "alice".into(),
        base_frame: base,
        labels: labels(pairs),
        lease_ttl_ms: 1_000,
        driver: "namespace".into(),
    }
}

fn setup(tag: &str) -> (Harness, MetaEngine, FrameId) {
    let h = Harness::new(tag);
    let (mut e, _) = h.open(boot_a());
    let f = h.durable(&mut e);
    (h, e, f)
}

#[test]
fn create_world_replay_after_crash_returns_the_lost_original() {
    let (h, mut e, f) = setup("idem-world");
    let key = IdempotencyKey::new("alice", "create-42");
    let req = world_req(f, &[("job", "a")]);
    let w = e.create_world(&req, Some(&key)).unwrap();
    assert_eq!(e.create_world(&req, Some(&key)).unwrap(), w, "replay while running");
    drop(e);

    let (mut e, _) = h.open(boot_a());
    let replay = e.create_world(&req, Some(&key)).unwrap();
    assert_eq!(replay.world_id, w.world_id);
    assert!(matches!(replay.state, WorldState::Lost { .. }));
    assert_eq!(e.worlds().unwrap().len(), 1, "never a second world");
    assert!(e.holds(f).unwrap().is_empty(), "replay must not re-attach a hold");

    let mut changed = req.clone();
    changed.lease_ttl_ms = 2_000;
    assert!(matches!(
        e.create_world(&changed, Some(&key)),
        Err(MetaError::IdempotencyConflict { .. })
    ));
    assert!(matches!(
        e.create_world(&req, Some(&IdempotencyKey::new("bob", "create-42"))),
        Err(MetaError::OwnerMismatch { .. })
    ));
    // A different operation reusing the key is a conflict as well.
    assert!(matches!(
        e.prepare_frame(
            &Harness::prepare_req("alice", FrameDurability::Durable, None, &[ObjectKind::DiskImage]),
            Some(&key)
        ),
        Err(MetaError::IdempotencyConflict { .. })
    ));
    // Records expire with their TTL.
    let ttl = e.config().idempotency_ttl_ms;
    h.clock.advance(ttl);
    assert!(e.collect_garbage(T0 + ttl).unwrap().idempotency_purged >= 1);
}

#[test]
fn fencing_token_fences_out_the_previous_executor() {
    let (h, mut e, f) = setup("fence-token");
    let w = e.create_world(&world_req(f, &[("job", "a")]), None).unwrap();
    let t1 = w.fencing_token;
    assert_eq!(t1, FencingToken::FIRST);

    assert!(matches!(
        e.acquire_world_fence(w.world_id, "mallory"),
        Err(MetaError::OwnerMismatch { .. })
    ));
    let t2 = e.acquire_world_fence(w.world_id, "alice").unwrap();
    assert_eq!(t2.get(), 2);

    assert!(matches!(
        e.renew_world_lease(w.world_id, "alice", t1),
        Err(MetaError::FencedOut { presented, current, .. }) if presented == t1 && current == t2
    ));
    assert!(matches!(
        e.check_world_mutation(w.world_id, "alice", t1),
        Err(MetaError::FencedOut { .. })
    ));
    assert!(matches!(
        e.destroy_world(w.world_id, "alice", t1, None),
        Err(MetaError::FencedOut { .. })
    ));
    let snapshot = |token| PrepareFrameRequest {
        owner: "alice".into(),
        durability: FrameDurability::Durable,
        parent: Some(f),
        object_kinds: vec![ObjectKind::DiskImage],
        labels: Default::default(),
        source_world: Some(WorldFence {
            world_id: w.world_id,
            token,
        }),
    };
    assert!(matches!(
        e.prepare_frame(&snapshot(t1), None),
        Err(MetaError::FencedOut { .. })
    ));
    // The new executor works, and its frame commit is fenced too.
    e.renew_world_lease(w.world_id, "alice", t2).unwrap();
    let p = e.prepare_frame(&snapshot(t2), None).unwrap();
    let t3 = e.acquire_world_fence(w.world_id, "alice").unwrap();
    let mut req = Harness::commit_req(p.frame_id, "alice");
    req.fence = Some(t2);
    let bundle = h.produce(&p, boot_a());
    assert!(matches!(
        e.commit_frame(&req, bundle, None),
        Err(MetaError::FencedOut { .. })
    ));
    req.fence = Some(t3);
    let bundle = h.produce(&p, boot_a());
    e.commit_frame(&req, bundle, None).unwrap();

    let gone = e.destroy_world(w.world_id, "alice", t3, None).unwrap();
    assert!(matches!(
        gone.state,
        WorldState::Destroyed {
            reason: WorldEndReason::Requested { .. },
            ..
        }
    ));
    drop(e);
    let (e, _) = h.open(boot_a());
    assert_eq!(e.world(w.world_id).unwrap().unwrap().fencing_token, t3, "token is durable");
}

#[test]
fn selectors_must_be_non_empty_and_never_cross_owners() {
    let (h, mut e, f) = setup("selector");
    let a1 = e.create_world(&world_req(f, &[("team", "rl"), ("run", "1")]), None).unwrap();
    let a2 = e.create_world(&world_req(f, &[("team", "rl"), ("run", "2")]), None).unwrap();
    let a3 = e.create_world(&world_req(f, &[("team", "web")]), None).unwrap();
    let mut bob_on_alice = world_req(f, &[("team", "rl")]);
    bob_on_alice.owner = "bob".into();
    assert!(matches!(
        e.create_world(&bob_on_alice, None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    let p_bob = e
        .prepare_frame(
            &Harness::prepare_req("bob", FrameDurability::Durable, None, &[ObjectKind::DiskImage]),
            None,
        )
        .unwrap();
    let bundle_bob = h.produce(&p_bob, boot_a());
    e.commit_frame(&Harness::commit_req(p_bob.frame_id, "bob"), bundle_bob, None)
        .unwrap();
    let mut bob_req = world_req(p_bob.frame_id, &[("team", "rl")]);
    bob_req.owner = "bob".into();
    let b1 = e.create_world(&bob_req, None).unwrap();

    let empty = Default::default();
    assert!(matches!(
        e.destroy_worlds_by_labels("alice", &empty),
        Err(MetaError::EmptySelectorForbidden)
    ));
    assert!(matches!(
        e.list_worlds_by_labels("alice", &empty),
        Err(MetaError::EmptySelectorForbidden)
    ));
    // Bob cannot reach Alice's worlds, by selector or directly.
    let rl = labels(&[("team", "rl")]);
    assert_eq!(e.destroy_worlds_by_labels("bob", &rl).unwrap(), vec![b1.world_id]);
    assert!(matches!(
        e.destroy_world(a1.world_id, "bob", a1.fencing_token, None),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert!(e.world(a1.world_id).unwrap().unwrap().state.is_running());

    let mut destroyed = e.destroy_worlds_by_labels("alice", &rl).unwrap();
    destroyed.sort();
    let mut want = vec![a1.world_id, a2.world_id];
    want.sort();
    assert_eq!(destroyed, want);
    assert!(e.world(a3.world_id).unwrap().unwrap().state.is_running());
    match e.world(a1.world_id).unwrap().unwrap().state {
        WorldState::Destroyed {
            reason: WorldEndReason::BatchSelector { by, selector },
            ..
        } => {
            assert_eq!(by, "alice");
            assert_eq!(selector, rl);
        }
        other => panic!("unexpected {other:?}"),
    }
    let holds = e.holds(f).unwrap();
    assert_eq!(holds.len(), 1, "only a3 still holds the base frame");
    assert!(matches!(&holds[0], Hold::WorldBase { world_id, .. } if *world_id == a3.world_id));
}

#[test]
fn world_leases_are_memory_only_and_expire_into_destroyed() {
    let (h, mut e, f) = setup("lease");
    let w = e.create_world(&world_req(f, &[("job", "a")]), None).unwrap();
    let db = h.cfg.db_path();
    let stamp = |p: &std::path::Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.len(), m.modified().unwrap())
    };
    let before = stamp(&db);
    for _ in 0..200 {
        h.clock.advance(5);
        e.renew_world_lease(w.world_id, "alice", w.fencing_token).unwrap();
    }
    assert_eq!(stamp(&db), before, "renewals must not write redb");

    // now = T0 + 1000, lease until T0 + 2000
    let now = h.clock_instant();
    assert!(e.expire_due_world_leases(now).unwrap().is_empty());
    h.clock.advance(999);
    assert!(e.expire_due_world_leases(h.clock_instant()).unwrap().is_empty());
    h.clock.advance(1);
    assert_eq!(e.expire_due_world_leases(h.clock_instant()).unwrap(), vec![w.world_id]);
    assert!(matches!(
        e.world(w.world_id).unwrap().unwrap().state,
        WorldState::Destroyed {
            reason: WorldEndReason::LeaseExpired,
            ..
        }
    ));
    assert!(e.holds(f).unwrap().is_empty());
    assert!(matches!(
        e.renew_world_lease(w.world_id, "alice", w.fencing_token),
        Err(MetaError::WorldNotRunning(_))
    ));
}

#[test]
fn lapsed_lease_cannot_be_renewed_before_the_reaper_runs() {
    let (h, mut e, f) = setup("lease-lapsed");
    let w = e.create_world(&world_req(f, &[("job", "a")]), None).unwrap();
    h.clock.advance(1_000);
    assert!(matches!(
        e.renew_world_lease(w.world_id, "alice", w.fencing_token),
        Err(MetaError::WorldNotRunning(_))
    ));
}

#[test]
fn pin_renewals_flush_to_redb_at_low_frequency() {
    let (h, mut e, f) = setup("pin-flush");
    let ttl = 60_000;
    e.pin_frame(
        f,
        &PinSpec {
            pin_id: "p".into(),
            owner: "alice".into(),
            lease_ttl_ms: ttl,
        },
    )
    .unwrap();
    let persisted = |e: &MetaEngine| match &e.holds(f).unwrap()[..] {
        [Hold::Pin { expires_at_ms, .. }] => *expires_at_ms,
        other => panic!("unexpected {other:?}"),
    };
    assert_eq!(persisted(&e), T0 + ttl);

    h.clock.advance(1_000);
    let r = e.renew_pin_lease(f, "p", "alice").unwrap();
    assert!(!r.flushed);
    assert_eq!(r.expires_at_ms, T0 + 1_000 + ttl);
    assert_eq!(persisted(&e), T0 + ttl, "memory only");
    assert!(matches!(
        e.renew_pin_lease(f, "p", "mallory"),
        Err(MetaError::OwnerMismatch { .. })
    ));

    // GC honours the in-memory high-water mark.
    assert_eq!(e.collect_garbage(T0 + ttl).unwrap().pins_expired, 0);

    // Less than half a TTL left on disk -> flush.
    h.clock.advance(30_000);
    let r = e.renew_pin_lease(f, "p", "alice").unwrap();
    assert!(r.flushed);
    assert_eq!(persisted(&e), T0 + 31_000 + ttl);

    h.clock.advance(1_000);
    assert!(!e.renew_pin_lease(f, "p", "alice").unwrap().flushed);
    assert_eq!(e.flush_dirty_pins().unwrap(), 1);
    assert_eq!(persisted(&e), T0 + 32_000 + ttl);
    assert_eq!(e.flush_dirty_pins().unwrap(), 0);

    // Unflushed renewals are lost on crash but recovery restarts the lease anyway.
    h.clock.advance(1_000);
    e.renew_pin_lease(f, "p", "alice").unwrap();
    drop(e);
    let (e, s) = h.open(boot_a());
    assert_eq!(s.pins_renewed_on_boot, 1);
    assert_eq!(persisted(&e), T0 + 33_000 + ttl);
}

#[test]
fn pins_are_owned_and_unknown_pins_are_reported() {
    let (h, mut e, f) = setup("pin-owner");
    let spec = PinSpec {
        pin_id: "p".into(),
        owner: "alice".into(),
        lease_ttl_ms: 10,
    };
    e.pin_frame(f, &spec).unwrap();
    let stolen = PinSpec {
        owner: "bob".into(),
        ..spec.clone()
    };
    assert!(matches!(
        e.pin_frame(f, &stolen),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert!(matches!(
        e.unpin_frame(f, "p", "bob"),
        Err(MetaError::OwnerMismatch { .. })
    ));
    assert!(matches!(
        e.unpin_frame(f, "nope", "alice"),
        Err(MetaError::PinNotFound { .. })
    ));
    assert!(matches!(
        e.renew_pin_lease(f, "nope", "alice"),
        Err(MetaError::PinNotFound { .. })
    ));
    h.clock.advance(10);
    assert_eq!(e.collect_garbage(T0 + 10).unwrap().pins_expired, 1);
    assert!(matches!(
        e.renew_pin_lease(f, "p", "alice"),
        Err(MetaError::PinNotFound { .. })
    ));
}

#[test]
fn destroy_world_replay_and_create_world_validation() {
    let (_h, mut e, f) = setup("destroy-idem");
    let w = e.create_world(&world_req(f, &[("job", "a")]), None).unwrap();
    let key = IdempotencyKey::new("alice", "destroy-1");
    let first = e
        .destroy_world(w.world_id, "alice", w.fencing_token, Some(&key))
        .unwrap();
    let again = e
        .destroy_world(w.world_id, "alice", w.fencing_token, Some(&key))
        .unwrap();
    assert_eq!(first, again);

    let mut bad = world_req(f, &[]);
    bad.lease_ttl_ms = 0;
    assert!(matches!(
        e.create_world(&bad, None),
        Err(MetaError::InvalidArgument(_))
    ));
    let mut bad = world_req(f, &[]);
    bad.labels = (0..33).map(|i| (format!("k{i}"), String::new())).collect();
    assert!(matches!(
        e.create_world(&bad, None),
        Err(MetaError::InvalidLabels(_))
    ));
    assert!(matches!(
        e.create_world(&world_req(FrameId::random(), &[]), None),
        Err(MetaError::FrameNotFound(_))
    ));
}

trait ClockInstant {
    fn clock_instant(&self) -> std::time::Instant;
}

impl ClockInstant for Harness {
    fn clock_instant(&self) -> std::time::Instant {
        aos_meta::Clock::now_instant(&*self.clock)
    }
}

#[test]
fn create_world_key_outlives_its_ttl_while_the_world_is_running() {
    let (h, mut e, f) = setup("idem-live-world");
    let key = IdempotencyKey::new("alice", "create-1");
    let req = world_req(f, &[]);
    let w = e.create_world(&req, Some(&key)).unwrap();
    let ttl = e.config().idempotency_ttl_ms;
    h.clock.advance(ttl + 1);
    e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!(
        e.create_world(&req, Some(&key)).unwrap().world_id,
        w.world_id,
        "a retry must not create a second world next to the running one"
    );

    // Once the world has ended its key lasts another TTL, like a short-lived world's.
    e.expire_idle_world_leases(|_| false).unwrap();
    h.clock.advance(ttl - 1);
    e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!(
        e.create_world(&req, Some(&key)).unwrap().world_id,
        w.world_id,
        "a retry right after the end of a long-lived world must see that world"
    );
    h.clock.advance(1);
    e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_ne!(e.create_world(&req, Some(&key)).unwrap().world_id, w.world_id);
}

/// A `destroy_world` key recorded after the world had already ended outlives the tombstone's
/// own TTL; the tombstone stays as long as the key that replays to it.
#[test]
fn a_destroy_key_recorded_after_the_end_keeps_the_tombstone_it_replays() {
    const HOUR: u64 = 3600 * 1000;
    let (h, mut e, f) = setup("idem-late-destroy");
    let w = e.create_world(&world_req(f, &[]), None).unwrap();
    h.clock.advance(1_001);
    assert_eq!(e.expire_idle_world_leases(|_| false).unwrap(), [w.world_id]);
    let tombstone_ttl = e.config().world_tombstone_ttl_ms;
    assert_eq!(tombstone_ttl, 24 * HOUR);

    h.clock.advance(12 * HOUR);
    let key = IdempotencyKey::new("alice", "destroy-late");
    let first = e
        .destroy_world(w.world_id, "alice", w.fencing_token, Some(&key))
        .unwrap();
    h.clock.advance(12 * HOUR);
    e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!(
        e.destroy_world(w.world_id, "alice", w.fencing_token, Some(&key))
            .expect("the key still replays"),
        first
    );

    h.clock.advance(12 * HOUR);
    let gc = e.collect_garbage(h.clock.now_ms()).unwrap();
    assert_eq!((gc.idempotency_purged, gc.tombstones_purged), (1, 1));
    assert!(e.world(w.world_id).unwrap().is_none());
}
