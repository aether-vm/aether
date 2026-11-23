//! Mini F0-8: 50 rounds of random prepare / commit / delete / pin / timeline / world operations,
//! wild orphans, injected deletion failures and host reboots, each ending in a "crash"
//! (dropping the engine) and a full recovery. After every recovery the metadata and the
//! filesystem must agree exactly with an independent model.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use aos_meta::{
    CreateWorldRequest, DeleteOutcome, FrameDurability, FrameState, ManagedObject, MetaError,
    ObjectKind, ObjectLocation, PinSpec,
};
use aos_types::{BootId, FrameId};
use common::*;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn pick<T: Copy>(&mut self, v: &[T]) -> Option<T> {
        if v.is_empty() {
            None
        } else {
            Some(v[self.below(v.len() as u64) as usize])
        }
    }
}

#[derive(Default)]
struct Model {
    frames: BTreeMap<FrameId, (FrameDurability, Vec<ManagedObject>)>,
    pinned: BTreeSet<FrameId>,
    head: Option<FrameId>,
    world_bases: BTreeSet<FrameId>,
    marked: BTreeSet<FrameId>,
}

impl Model {
    fn held(&self, f: &FrameId) -> bool {
        self.pinned.contains(f) || self.head == Some(*f) || self.world_bases.contains(f)
    }

    fn remove(&mut self, f: &FrameId) {
        self.frames.remove(f);
        self.pinned.remove(f);
        self.world_bases.remove(f);
        self.marked.remove(f);
        assert_ne!(self.head, Some(*f), "timeline head can never be removed");
    }

    fn ids(&self, d: Option<FrameDurability>) -> Vec<FrameId> {
        self.frames
            .iter()
            .filter(|(_, (dur, _))| d.is_none_or(|d| *dur == d))
            .map(|(f, _)| *f)
            .collect()
    }

    fn names(&self, loc: ObjectLocation) -> BTreeSet<String> {
        self.frames
            .values()
            .flat_map(|(d, objs)| objs.iter().filter(move |o| o.location(*d) == loc))
            .map(ManagedObject::name)
            .collect()
    }
}

const KINDS: [ObjectKind; 4] = [
    ObjectKind::TreeSubvol,
    ObjectKind::DiskImage,
    ObjectKind::MemImage,
    ObjectKind::VmState,
];

#[test]
fn fifty_rounds_of_random_crashes_keep_metadata_and_pool_in_lockstep() {
    let h = Harness::new("crash-loop");
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut boot: BootId = boot_a();
    let (mut e, _) = h.open(boot);
    let mut m = Model::default();
    let mut quarantined_live = 0usize;
    let grace = e.config().quarantine_grace_ms;
    let mut totals = [0usize; 6];

    for round in 0..50u32 {
        let mut in_flight = 0usize;
        let mut failed_deletes = 0usize;

        for _ in 0..1 + rng.below(8) {
            match rng.below(12) {
                0..=3 => {
                    let mut kinds: Vec<ObjectKind> =
                        KINDS.iter().copied().filter(|_| rng.below(2) == 0).collect();
                    if kinds.is_empty() {
                        kinds.push(ObjectKind::DiskImage);
                    }
                    let cands: Vec<FrameId> = m
                        .ids(Some(FrameDurability::Durable))
                        .into_iter()
                        .filter(|f| !m.marked.contains(f))
                        .collect();
                    let parent = rng.pick(&cands);
                    let f = h.commit_frame(&mut e, FrameDurability::Durable, parent, &kinds);
                    m.frames
                        .insert(f, (FrameDurability::Durable, e.frame(f).unwrap().unwrap().state.objects().to_vec()));
                }
                4 => {
                    let f = h.volatile(&mut e);
                    m.frames
                        .insert(f, (FrameDurability::Volatile, e.frame(f).unwrap().unwrap().state.objects().to_vec()));
                }
                5 | 6 => {
                    // Prepared, partially produced, never committed.
                    let d = if rng.below(2) == 0 {
                        FrameDurability::Durable
                    } else {
                        FrameDurability::Volatile
                    };
                    let p = e
                        .prepare_frame(&Harness::prepare_req("alice", d, None, &KINDS), None)
                        .unwrap();
                    for o in &p.expected_objects {
                        if rng.below(2) == 0 {
                            h.create_object(o, d);
                        }
                    }
                    in_flight += 1;
                }
                7 | 8 => {
                    let Some(f) = rng.pick(&m.ids(None)) else { continue };
                    let inject = rng.below(3) == 0;
                    h.ctl.fail_destroy.store(inject, Ordering::SeqCst);
                    let r = e.delete_frame(f, "alice", None);
                    h.ctl.fail_destroy.store(false, Ordering::SeqCst);
                    match r {
                        Ok(DeleteOutcome::Deleted) => {
                            assert!(!m.held(&f));
                            m.remove(&f);
                        }
                        Ok(DeleteOutcome::Deferred { .. }) => {
                            assert!(m.held(&f));
                            m.marked.insert(f);
                        }
                        Err(MetaError::Hook { .. }) => {
                            assert!(inject && !m.held(&f));
                            m.remove(&f);
                            failed_deletes += 1;
                        }
                        Err(other) => panic!("delete failed: {other}"),
                    }
                }
                9 => {
                    let cands: Vec<FrameId> = m
                        .ids(Some(FrameDurability::Durable))
                        .into_iter()
                        .filter(|f| !m.marked.contains(f))
                        .collect();
                    let Some(f) = rng.pick(&cands) else { continue };
                    if rng.below(2) == 0 {
                        e.pin_frame(
                            f,
                            &PinSpec {
                                pin_id: "keep".into(),
                                owner: "alice".into(),
                                lease_ttl_ms: 7 * 24 * 3600 * 1000,
                            },
                        )
                        .unwrap();
                        m.pinned.insert(f);
                    } else {
                        e.advance_timeline_cas("main", "alice", m.head, f, None)
                            .unwrap();
                        m.head = Some(f);
                    }
                }
                10 => {
                    let pinned: Vec<FrameId> = m.pinned.iter().copied().collect();
                    let Some(f) = rng.pick(&pinned) else { continue };
                    e.unpin_frame(f, "keep", "alice").unwrap();
                    m.pinned.remove(&f);
                }
                _ => {
                    let cands: Vec<FrameId> = m
                        .ids(None)
                        .into_iter()
                        .filter(|f| !m.marked.contains(f))
                        .collect();
                    let Some(f) = rng.pick(&cands) else { continue };
                    e.create_world(
                        &CreateWorldRequest {
                            owner: "alice".into(),
                            base_frame: f,
                            labels: labels(&[("round", &round.to_string())]),
                            lease_ttl_ms: 60_000,
                        },
                        None,
                    )
                    .unwrap();
                    m.world_bases.insert(f);
                }
            }
        }

        // Wild orphans, kept under both breaker limits.
        let known = m.names(ObjectLocation::Pool).len();
        let max_k = if known + 2 < 20 { 3 } else { 2 };
        let k = rng.below(max_k) as usize;
        for i in 0..k {
            if rng.below(2) == 0 {
                h.add_orphan(&format!("wild-{round}-{i}"));
            } else {
                let ghost = ManagedObject::new(FrameId::random(), ObjectKind::DiskImage);
                h.add_orphan(&ghost.name());
            }
        }

        // Crash, maybe across a host reboot.
        drop(e);
        let rebooted = rng.below(6) == 0;
        let mut expected_deleting = failed_deletes;
        if rebooted {
            boot = if boot == boot_a() { boot_b() } else { boot_a() };
            // Real host reboot wipes volatile tmpfs.
            for entry in std::fs::read_dir(&h.vol).unwrap() {
                let _ = aos_meta::hooks::remove_path(&entry.unwrap().path());
            }
            for f in m.ids(Some(FrameDurability::Volatile)) {
                m.remove(&f);
                expected_deleting += 1;
            }
        }
        m.world_bases.clear();
        let reclaimed: Vec<FrameId> =
            m.marked.iter().copied().filter(|f| !m.held(f)).collect();
        for f in &reclaimed {
            m.remove(f);
        }
        expected_deleting += reclaimed.len();

        let (ne, s) = h.open(boot);
        e = ne;
        assert_eq!(s.boot_changed, rebooted, "round {round}");
        assert_eq!(s.preparing_rolled_back, in_flight, "round {round}");
        assert_eq!(s.deleting_completed, expected_deleting, "round {round}");
        assert_eq!(s.orphans_quarantined, k, "round {round}");
        assert_eq!(s.pins_renewed_on_boot, m.pinned.len(), "round {round}");
        totals[0] += in_flight;
        totals[1] += failed_deletes;
        totals[2] += k;
        totals[3] += usize::from(rebooted);
        totals[4] += reclaimed.len();
        quarantined_live += k;

        // Ledger == reality.
        let frames = e.frames().unwrap();
        assert!(
            frames.iter().all(|r| matches!(r.state, FrameState::Committed { .. })),
            "round {round}: only committed frames survive recovery"
        );
        let ids: BTreeSet<FrameId> = frames.iter().map(|r| r.frame_id).collect();
        assert_eq!(ids, m.frames.keys().copied().collect(), "round {round}: frame set");
        assert_eq!(h.pool_objects(), m.names(ObjectLocation::Pool), "round {round}: pool");
        assert_eq!(
            h.tmpfs_objects(),
            m.names(ObjectLocation::VolatileTmpfs),
            "round {round}: tmpfs"
        );
        assert_eq!(h.quarantine_entries().len(), quarantined_live, "round {round}: quarantine");
        assert_eq!(e.quarantine_records().unwrap().len(), quarantined_live);
        assert_eq!(e.timeline_head("main").unwrap(), m.head);
        for f in m.frames.keys() {
            assert_eq!(e.is_marked_for_reclaim(*f).unwrap(), m.marked.contains(f));
            assert_eq!(e.holds(*f).unwrap().len(), usize::from(m.pinned.contains(f)) + usize::from(m.head == Some(*f)));
        }
        assert!(e.worlds().unwrap().iter().all(|w| !w.state.is_running()));

        if round % 10 == 9 {
            h.clock.advance(grace);
            let now = aos_meta::Clock::now_ms(&*h.clock);
            let gc = e.collect_garbage(now).unwrap();
            assert_eq!(gc.quarantine_purged, quarantined_live);
            assert_eq!(gc.pins_expired, 0, "pins were renewed by recovery");
            assert_eq!(gc.frames_deleted, 0);
            quarantined_live = 0;
            totals[5] += gc.tombstones_purged;
            assert!(h.quarantine_entries().is_empty());
        }
    }
    eprintln!(
        "crash loop: rolled_back={} failed_deletes={} orphans={} reboots={} reclaimed={} tombstones={} surviving_frames={}",
        totals[0],
        totals[1],
        totals[2],
        totals[3],
        totals[4],
        totals[5],
        m.frames.len()
    );
    assert!(totals[0] > 0 && totals[1] > 0 && totals[2] > 0 && totals[3] > 0, "loop must exercise every path: {totals:?}");
}
