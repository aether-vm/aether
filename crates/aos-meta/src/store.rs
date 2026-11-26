//! `MetaEngine`: frame state machine (I1 ~ I4), timelines and garbage collection.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aos_types::{BootId, EpochId, Ephemeral, FrameId, Persisted, ProofKind, WorldId};
use redb::{Database, ReadableTable};
use serde::{Deserialize, Serialize};

use crate::config::{Clock, MetaConfig};
use crate::error::{MetaError, Result};
use crate::hooks::{RecoveryHooks, ignore_not_found};
use crate::idempotency::{
    IdemResponse, IdempotencyRecord, check_replay, hex, request_digest, validate_key,
};
use crate::lease::{PinLease, WorldLease};
use crate::model::{
    DeleteReason, FencingToken, FrameDurability, FrameRecord, FrameState, Hold, IdempotencyKey,
    Labels, ManagedObject, ObjectKind, ObjectLocation, PinSpec, PoolId, QuarantineRecord,
    TimelineRecord, WorldRecord, validate_labels, validate_name,
};
use crate::pool::PoolLock;
use crate::tables::{
    self, FRAMES, HOLDS, IDEMPOTENCY, PENDING_RECLAIM, QUARANTINE, RawTable, ReclaimMark,
    TIMELINES, WORLDS, begin_write, frame_key, hold_key, idem_key,
};

/// The single-writer metadata engine. Obtain one through [`MetaEngine::open_and_recover`].
pub struct MetaEngine {
    pub(crate) cfg: MetaConfig,
    pub(crate) db: Database,
    pub(crate) pool_id: PoolId,
    pub(crate) epoch: EpochId,
    pub(crate) boot: BootId,
    pub(crate) hooks: Box<dyn RecoveryHooks>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) world_leases: HashMap<WorldId, WorldLease>,
    pub(crate) pin_leases: HashMap<(FrameId, String), PinLease>,
    /// When this engine was opened (monotonic).
    pub(crate) opened_at: Instant,
    /// Monotonic purge deadline of every quarantine record this run created, by record key.
    pub(crate) quarantine_due: HashMap<String, Instant>,
    // Declared last: the pool lock is released only after the database is closed.
    pub(crate) _lock: PoolLock,
}

impl std::fmt::Debug for MetaEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetaEngine")
            .field("pool_id", &self.pool_id)
            .field("epoch", &self.epoch)
            .field("boot", &self.boot)
            .finish_non_exhaustive()
    }
}

// ============================================================================ request / response types

/// Proof that a fencing token is current for a world.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldFence {
    /// World.
    pub world_id: WorldId,
    /// Token presented by the caller.
    pub token: FencingToken,
}

/// T1 request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareFrameRequest {
    /// Owner.
    pub owner: String,
    /// Persistence class.
    pub durability: FrameDurability,
    /// Lineage parent (must be committed).
    pub parent: Option<FrameId>,
    /// Objects the producer will create (no duplicates).
    pub object_kinds: Vec<ObjectKind>,
    /// Immutable labels.
    pub labels: Labels,
    /// World being captured, with the caller's fencing token.
    pub source_world: Option<WorldFence>,
}

/// T1 response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedFrame {
    /// Newly allocated frame id.
    pub frame_id: FrameId,
    /// Persistence class.
    pub durability: FrameDurability,
    /// Objects the producer may create (names are canonical).
    pub expected_objects: Vec<ManagedObject>,
    /// Durable child of a volatile parent.
    pub requires_full_mem_promotion: bool,
}

/// Timeline update performed atomically with a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineTarget {
    /// Timeline name.
    pub timeline: String,
    /// Expected current head (CAS).
    pub expected_old: Option<FrameId>,
}

/// T2 request (the proofs travel separately in a [`CommitProofBundle`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitFrameRequest {
    /// Frame in `Preparing`.
    pub frame_id: FrameId,
    /// Owner (must match the prepare).
    pub owner: String,
    /// Guest `syncfs` completed before capture.
    pub disk_clean: bool,
    /// Current fencing token of the source world (required iff the frame has one).
    pub fence: Option<FencingToken>,
    /// Pin attached atomically with the commit.
    pub pin: Option<PinSpec>,
    /// Timeline advanced atomically with the commit (durable frames only).
    pub timeline: Option<TimelineTarget>,
}

/// T2 response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedFrame {
    /// Frame.
    pub frame_id: FrameId,
    /// Persistence class.
    pub durability: FrameDurability,
    /// Objects owned by the frame.
    pub objects: Vec<ManagedObject>,
    /// Timeline update, if requested.
    pub timeline: Option<TimelineAdvance>,
}

/// Result of a timeline CAS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineAdvance {
    /// Timeline.
    pub timeline: String,
    /// Previous head.
    pub previous: Option<FrameId>,
    /// New head.
    pub head: FrameId,
}

/// Result of [`MetaEngine::delete_frame`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteOutcome {
    /// Metadata and objects are gone.
    Deleted,
    /// The frame is still held; it is reclaimed once the last hold is released.
    Deferred {
        /// Holds at the time of the request.
        holds: usize,
    },
}

/// Durability evidence for one object of a frame being committed.
#[derive(Debug)]
pub enum ObjectProof {
    /// `fsync(file) + fsync(parent)` (or `fsync(dir)` for subvolumes) at the canonical pool path.
    Persisted(Persisted<ManagedObject>),
    /// Boot-bound volatile object (volatile frames only).
    Ephemeral(Ephemeral<ManagedObject>),
}

/// All proofs for a commit. Durable frames need a [`Persisted`] proof for every object; volatile
/// frames may use [`Ephemeral`] proofs bound to the current boot (and must for tmpfs memory).
#[derive(Debug, Default)]
pub struct CommitProofBundle {
    proofs: Vec<ObjectProof>,
}

impl CommitProofBundle {
    /// Empty bundle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a persisted proof.
    #[must_use]
    pub fn with_persisted(mut self, p: Persisted<ManagedObject>) -> Self {
        self.proofs.push(ObjectProof::Persisted(p));
        self
    }

    /// Add an ephemeral proof.
    #[must_use]
    pub fn with_ephemeral(mut self, e: Ephemeral<ManagedObject>) -> Self {
        self.proofs.push(ObjectProof::Ephemeral(e));
        self
    }

    /// Add any proof.
    pub fn push(&mut self, p: ObjectProof) {
        self.proofs.push(p);
    }
}

/// Statistics of one [`MetaEngine::collect_garbage`] pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Pins whose lease ran out.
    pub pins_expired: usize,
    /// Frames physically deleted.
    pub frames_deleted: usize,
    /// Quarantined entries purged after their grace period.
    pub quarantine_purged: usize,
    /// World tombstones dropped.
    pub tombstones_purged: usize,
    /// Idempotency records dropped.
    pub idempotency_purged: usize,
    /// Objects that could not be destroyed. They stay recorded and are retried by the next pass.
    pub failures: Vec<String>,
    /// The deletion limit was reached with work left over.
    pub more: bool,
}

pub(crate) fn wrong_state(frame: FrameId, expected: &'static str, s: &FrameState) -> MetaError {
    MetaError::FrameWrongState {
        frame,
        expected,
        actual: s.name(),
    }
}

pub(crate) fn check_owner(resource: impl FnOnce() -> String, owner: &str, caller: &str) -> Result<()> {
    if owner == caller {
        Ok(())
    } else {
        Err(MetaError::OwnerMismatch {
            resource: resource(),
            caller: caller.to_owned(),
        })
    }
}

pub(crate) fn check_fence(w: &WorldRecord, caller: &str, token: FencingToken) -> Result<()> {
    check_owner(|| format!("world {}", w.world_id), &w.owner, caller)?;
    if token != w.fencing_token {
        return Err(MetaError::FencedOut {
            world: w.world_id,
            presented: token,
            current: w.fencing_token,
        });
    }
    Ok(())
}

pub(crate) fn idem_prepare(
    idem: Option<&IdempotencyKey>,
    owner: &str,
    op: &str,
    req: &impl Serialize,
) -> Result<Option<[u8; 32]>> {
    idem.map(|k| {
        validate_key(k, owner)?;
        request_digest(op, req)
    })
    .transpose()
}

pub(crate) fn idem_lookup<Tbl>(
    t: &Tbl,
    idem: Option<&IdempotencyKey>,
    op: &str,
    digest: Option<&[u8; 32]>,
) -> Result<Option<IdemResponse>>
where
    Tbl: ReadableTable<&'static str, &'static [u8]>,
{
    match (idem, digest) {
        (Some(k), Some(d)) => check_replay(tables::load_idem(t, k)?, k, op, d),
        _ => Ok(None),
    }
}

pub(crate) fn idem_store(
    t: &mut RawTable<'_>,
    idem: Option<&IdempotencyKey>,
    op: &str,
    digest: Option<&[u8; 32]>,
    response: IdemResponse,
    now_ms: u64,
    prepared_frame: Option<FrameId>,
) -> Result<()> {
    if let (Some(k), Some(d)) = (idem, digest) {
        let rec = IdempotencyRecord {
            op: op.to_owned(),
            digest_hex: hex(d),
            response,
            recorded_at_ms: now_ms,
            prepared_frame,
        };
        tables::put_json(t, &idem_key(k), &rec)?;
    }
    Ok(())
}

fn replay_mismatch() -> MetaError {
    MetaError::Codec("idempotency record holds a response of another operation".into())
}

/// CAS a timeline inside an open transaction, moving the `TimelineHead` hold.
fn timeline_cas(
    timelines: &mut RawTable<'_>,
    holds: &mut RawTable<'_>,
    name: &str,
    owner: &str,
    expected: Option<FrameId>,
    new_head: FrameId,
) -> Result<TimelineAdvance> {
    let existing: Option<TimelineRecord> = tables::get_json(timelines, name)?;
    if let Some(rec) = &existing {
        check_owner(|| format!("timeline {name:?}"), &rec.owner, owner)?;
    }
    let current = existing.map(|r| r.head);
    if current != expected {
        return Err(MetaError::TimelineCasMismatch {
            timeline: name.to_owned(),
            expected,
            actual: current,
        });
    }
    let hold = Hold::TimelineHead {
        timeline_name: name.to_owned(),
    };
    if let Some(old) = current {
        holds.remove(hold_key(&old, &hold).as_str())?;
    }
    tables::put_json(holds, &hold_key(&new_head, &hold), &hold)?;
    let next = TimelineRecord {
        head: new_head,
        owner: owner.to_owned(),
    };
    tables::put_json(timelines, name, &next)?;
    Ok(TimelineAdvance {
        timeline: name.to_owned(),
        previous: current,
        head: new_head,
    })
}

impl MetaEngine {
    // ======================================================================== accessors

    /// Pool identity.
    #[must_use]
    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    /// This incarnation's daemon epoch.
    #[must_use]
    pub fn daemon_epoch(&self) -> EpochId {
        self.epoch
    }

    /// Boot id sampled at startup.
    #[must_use]
    pub fn current_boot(&self) -> BootId {
        self.boot
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &MetaConfig {
        &self.cfg
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub(crate) fn read_table<T>(
        &self,
        def: tables::Def,
        f: impl FnOnce(&redb::ReadOnlyTable<&'static str, &'static [u8]>) -> Result<T>,
    ) -> Result<T> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(def)?;
        f(&t)
    }

    /// One frame.
    pub fn frame(&self, id: FrameId) -> Result<Option<FrameRecord>> {
        self.read_table(FRAMES, |t| tables::load_frame(t, &id))
    }

    /// Every frame (any state).
    pub fn frames(&self) -> Result<Vec<FrameRecord>> {
        self.read_table(FRAMES, |t| {
            Ok(tables::scan_json(t)?.into_iter().map(|(_, r)| r).collect())
        })
    }

    /// Holds attached to a frame (pins show their persisted expiry).
    pub fn holds(&self, id: FrameId) -> Result<Vec<Hold>> {
        self.read_table(HOLDS, |t| {
            Ok(tables::holds_of(t, &id)?.into_iter().map(|(_, h)| h).collect())
        })
    }

    /// Whether a delete was requested while the frame was held.
    pub fn is_marked_for_reclaim(&self, id: FrameId) -> Result<bool> {
        self.read_table(PENDING_RECLAIM, |t| Ok(t.get(frame_key(&id).as_str())?.is_some()))
    }

    /// Current head of a timeline.
    pub fn timeline_head(&self, name: &str) -> Result<Option<FrameId>> {
        self.read_table(TIMELINES, |t| {
            Ok(tables::get_json::<TimelineRecord, _>(t, name)?.map(|r| r.head))
        })
    }

    /// Full record of a timeline (`head` and `owner`).
    pub fn timeline(&self, name: &str) -> Result<Option<TimelineRecord>> {
        self.read_table(TIMELINES, |t| tables::get_json(t, name))
    }

    /// One world (including tombstones).
    pub fn world(&self, id: WorldId) -> Result<Option<WorldRecord>> {
        self.read_table(WORLDS, |t| tables::load_world(t, &id))
    }

    /// Every world record (including tombstones).
    pub fn worlds(&self) -> Result<Vec<WorldRecord>> {
        self.read_table(WORLDS, |t| {
            Ok(tables::scan_json(t)?.into_iter().map(|(_, r)| r).collect())
        })
    }

    /// Quarantine bookkeeping.
    pub fn quarantine_records(&self) -> Result<Vec<QuarantineRecord>> {
        self.read_table(QUARANTINE, |t| {
            Ok(tables::scan_json(t)?.into_iter().map(|(_, r)| r).collect())
        })
    }

    // ======================================================================== physical deletion

    pub(crate) fn destroy_objects(
        &mut self,
        durability: FrameDurability,
        objects: &[ManagedObject],
    ) -> Result<()> {
        let dir = self.cfg.objects_dir();
        for o in objects {
            let r = match o.location(durability) {
                ObjectLocation::Pool => self.hooks.destroy_pool_object(&dir.join(o.name()), o),
                ObjectLocation::VolatileTmpfs => self.hooks.destroy_volatile_object(o),
            };
            ignore_not_found(r).map_err(|source| MetaError::Hook {
                stage: "destroy_object",
                source,
            })?;
        }
        Ok(())
    }

    /// Destroy the objects of a `Deleting` frame, then drop its record.
    pub(crate) fn complete_deletion(&mut self, rec: &FrameRecord) -> Result<()> {
        debug_assert!(matches!(rec.state, FrameState::Deleting { .. }));
        self.destroy_objects(rec.state.durability(), rec.state.objects())?;
        let tx = begin_write(&self.db)?;
        {
            let mut frames = tx.open_table(FRAMES)?;
            let mut holds = tx.open_table(HOLDS)?;
            let mut pending = tx.open_table(PENDING_RECLAIM)?;
            let mut idem = tx.open_table(IDEMPOTENCY)?;
            let key = frame_key(&rec.frame_id);
            frames.remove(key.as_str())?;
            pending.remove(key.as_str())?;
            tables::clear_holds(&mut holds, &rec.frame_id)?;
            for (ik, r) in tables::scan_json::<IdempotencyRecord, _>(&idem)? {
                if r.prepared_frame == Some(rec.frame_id) {
                    idem.remove(ik.as_str())?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    // ======================================================================== T1: prepare

    /// I1: durably record the intent to create a frame **before** any artifact exists.
    pub fn prepare_frame(
        &mut self,
        req: &PrepareFrameRequest,
        idem: Option<&IdempotencyKey>,
    ) -> Result<PreparedFrame> {
        const OP: &str = "prepare_frame";
        validate_name("owner", &req.owner)?;
        validate_labels(&req.labels)?;
        let mut kinds = req.object_kinds.clone();
        kinds.sort();
        if kinds.is_empty() || kinds.windows(2).any(|w| w[0] == w[1]) {
            return Err(MetaError::InvalidArgument(
                "object_kinds must be non-empty and free of duplicates".into(),
            ));
        }
        let digest = idem_prepare(idem, &req.owner, OP, req)?;
        let now = self.now_ms();

        let tx = begin_write(&self.db)?;
        let prepared = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            let mut frames = tx.open_table(FRAMES)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                return match resp {
                    IdemResponse::Prepared(p) => match tables::load_frame(&frames, &p.frame_id)? {
                        Some(FrameRecord {
                            state: FrameState::Preparing { .. } | FrameState::Committed { .. },
                            ..
                        }) => Ok(p),
                        _ => Err(MetaError::PreparedFrameAborted(p.frame_id)),
                    },
                    _ => Err(replay_mismatch()),
                };
            }
            let pending = tx.open_table(PENDING_RECLAIM)?;
            let mut holds = tx.open_table(HOLDS)?;
            if let Some(sw) = &req.source_world {
                let worlds = tx.open_table(WORLDS)?;
                let w = tables::load_world(&worlds, &sw.world_id)?
                    .ok_or(MetaError::WorldNotFound(sw.world_id))?;
                check_fence(&w, &req.owner, sw.token)?;
                if !w.state.is_running() {
                    return Err(MetaError::WorldNotRunning(sw.world_id));
                }
                self.live_lease(sw.world_id, &req.owner, sw.token)?;
            }
            let mut promotion = false;
            if let Some(p) = req.parent {
                let prec = tables::load_frame(&frames, &p)?.ok_or(MetaError::FrameNotFound(p))?;
                let FrameState::Committed {
                    durability: pdur,
                    boot_id,
                    objects,
                    owner: parent_owner,
                    ..
                } = &prec.state
                else {
                    return Err(wrong_state(p, "Committed", &prec.state));
                };
                check_owner(|| format!("frame {p}"), parent_owner, &req.owner)?;
                if pending.get(frame_key(&p).as_str())?.is_some() {
                    return Err(MetaError::FrameMarkedForDeletion(p));
                }
                if *pdur == FrameDurability::Volatile {
                    if *boot_id != self.boot {
                        return Err(MetaError::StaleBoot {
                            frame: p,
                            recorded: *boot_id,
                            current: self.boot,
                        });
                    }
                    if req.durability == FrameDurability::Durable {
                        promotion = true;
                        let parent_has_mem = objects.iter().any(|o| o.kind == ObjectKind::MemImage);
                        if parent_has_mem && !kinds.contains(&ObjectKind::MemImage) {
                            return Err(MetaError::MemPromotionRequired { parent: p });
                        }
                    }
                }
            }
            let frame_id = FrameId::try_random()
                .map_err(|e| MetaError::io("generating frame id", std::io::Error::other(e)))?;
            let expected: Vec<ManagedObject> =
                kinds.iter().map(|k| ManagedObject::new(frame_id, *k)).collect();
            let rec = FrameRecord {
                frame_id,
                state: FrameState::Preparing {
                    durability: req.durability,
                    boot_id: self.boot,
                    parent: req.parent,
                    expected_objects: expected.clone(),
                    created_epoch: self.epoch,
                    labels: req.labels.clone(),
                    owner: req.owner.clone(),
                    created_at_ms: now,
                    requires_full_mem_promotion: promotion,
                    source_world: req.source_world.map(|s| s.world_id),
                },
            };
            tables::put_json(&mut frames, &frame_key(&frame_id), &rec)?;
            if let Some(p) = req.parent {
                let hold = Hold::PreparingParent {
                    child_frame: frame_id,
                };
                tables::put_json(&mut holds, &hold_key(&p, &hold), &hold)?;
            }
            let prepared = PreparedFrame {
                frame_id,
                durability: req.durability,
                expected_objects: expected,
                requires_full_mem_promotion: promotion,
            };
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::Prepared(prepared.clone()),
                now,
                Some(frame_id),
            )?;
            prepared
        };
        tx.commit()?;
        Ok(prepared)
    }

    // ======================================================================== T2: commit

    fn verify_proofs(
        &self,
        frame: FrameId,
        durability: FrameDurability,
        expected: &[ManagedObject],
        bundle: CommitProofBundle,
    ) -> Result<()> {
        let reject = |reason: String| MetaError::ProofRejected { frame, reason };
        let dir = self.cfg.objects_dir();
        let mut seen = BTreeSet::new();
        for p in bundle.proofs {
            let obj = match p {
                ObjectProof::Persisted(p) => {
                    let obj = *p.value();
                    if obj.location(durability) != ObjectLocation::Pool {
                        return Err(reject(format!(
                            "{obj} lives in volatile tmpfs and needs an Ephemeral proof"
                        )));
                    }
                    let want_kind = if obj.kind.is_dir() {
                        ProofKind::Subvolume
                    } else {
                        ProofKind::FileAndParent
                    };
                    let want_path = dir.join(obj.name());
                    if p.proof().kind() != want_kind || p.proof().path() != want_path {
                        return Err(reject(format!(
                            "proof for {obj} covers {:?} {}, expected {want_kind:?} {}",
                            p.proof().kind(),
                            p.proof().path().display(),
                            want_path.display()
                        )));
                    }
                    p.proof().verify_unchanged().map_err(|err| {
                        reject(format!("proof for {obj} failed verify_unchanged: {err}"))
                    })?;
                    obj
                }
                ObjectProof::Ephemeral(e) => {
                    if durability == FrameDurability::Durable {
                        return Err(reject(format!(
                            "durable frame requires a Persisted proof for {}, got Ephemeral",
                            e.into_inner_for_cleanup()
                        )));
                    }
                    let obj = *e.get_at(&self.boot).map_err(|err| reject(err.to_string()))?;
                    if obj.location(durability) != ObjectLocation::VolatileTmpfs {
                        return Err(reject(format!(
                            "{obj} lives in the pool and requires a Persisted proof even on a volatile frame"
                        )));
                    }
                    obj
                }
            };
            if !expected.contains(&obj) {
                return Err(reject(format!("{obj} is not an expected object of this frame")));
            }
            if !seen.insert(obj) {
                return Err(reject(format!("duplicate proof for {obj}")));
            }
        }
        if let Some(missing) = expected.iter().find(|o| !seen.contains(*o)) {
            return Err(reject(format!("missing proof for {missing}")));
        }
        Ok(())
    }

    /// I3: the unique commit point. Atomically `Preparing -> Committed`, optional pin, optional
    /// timeline CAS and the idempotency record, in one `Durability::Immediate` transaction.
    pub fn commit_frame(
        &mut self,
        req: &CommitFrameRequest,
        proofs: CommitProofBundle,
        idem: Option<&IdempotencyKey>,
    ) -> Result<CommittedFrame> {
        const OP: &str = "commit_frame";
        validate_name("owner", &req.owner)?;
        if let Some(pin) = &req.pin {
            validate_pin(pin, self.cfg.max_pin_ttl_ms)?;
            check_owner(|| format!("frame {}", req.frame_id), &req.owner, &pin.owner)?;
        }
        if let Some(tl) = &req.timeline {
            validate_name("timeline", &tl.timeline)?;
        }
        let digest = idem_prepare(idem, &req.owner, OP, req)?;
        let now = self.now_ms();
        let now_inst = self.clock.now_instant();

        let tx = begin_write(&self.db)?;
        let (out, pin_lease) = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                return match resp {
                    IdemResponse::Committed(c) => Ok(c),
                    _ => Err(replay_mismatch()),
                };
            }
            let mut frames = tx.open_table(FRAMES)?;
            let mut holds = tx.open_table(HOLDS)?;
            let rec = tables::load_frame(&frames, &req.frame_id)?
                .ok_or(MetaError::FrameNotFound(req.frame_id))?;
            let FrameState::Preparing {
                durability,
                boot_id,
                parent,
                expected_objects,
                created_epoch,
                labels,
                owner,
                source_world,
                ..
            } = rec.state
            else {
                return Err(wrong_state(req.frame_id, "Preparing", &rec.state));
            };
            check_owner(|| format!("frame {}", req.frame_id), &owner, &req.owner)?;
            if let Some(w) = source_world {
                let worlds = tx.open_table(WORLDS)?;
                let wr = tables::load_world(&worlds, &w)?.ok_or(MetaError::WorldNotFound(w))?;
                let token = req.fence.ok_or_else(|| {
                    MetaError::InvalidArgument(
                        "fence token required to commit a frame captured from a world".into(),
                    )
                })?;
                check_fence(&wr, &req.owner, token)?;
                if !wr.state.is_running() {
                    return Err(MetaError::WorldNotRunning(w));
                }
                self.live_lease(w, &req.owner, token)?;
            }
            if durability == FrameDurability::Volatile && boot_id != self.boot {
                return Err(MetaError::StaleBoot {
                    frame: req.frame_id,
                    recorded: boot_id,
                    current: self.boot,
                });
            }
            if req.timeline.is_some() && durability == FrameDurability::Volatile {
                return Err(MetaError::VolatileInTimelineForbidden(req.frame_id));
            }
            self.verify_proofs(req.frame_id, durability, &expected_objects, proofs)?;

            let committed = FrameRecord {
                frame_id: req.frame_id,
                state: FrameState::Committed {
                    durability,
                    boot_id,
                    parent,
                    objects: expected_objects.clone(),
                    disk_clean: req.disk_clean,
                    created_epoch,
                    committed_at_ms: now,
                    labels,
                    owner,
                },
            };
            tables::put_json(&mut frames, &frame_key(&req.frame_id), &committed)?;
            if let Some(p) = parent {
                let hold = Hold::PreparingParent {
                    child_frame: req.frame_id,
                };
                holds.remove(hold_key(&p, &hold).as_str())?;
            }

            let mut pin_lease = None;
            if let Some(pin) = &req.pin {
                let expires = now.saturating_add(pin.lease_ttl_ms);
                let hold = Hold::Pin {
                    pin_id: pin.pin_id.clone(),
                    owner: pin.owner.clone(),
                    lease_ttl_ms: pin.lease_ttl_ms,
                    expires_at_ms: expires,
                };
                tables::put_json(&mut holds, &hold_key(&req.frame_id, &hold), &hold)?;
                pin_lease = Some((pin.clone(), expires));
            }
            let timeline = match &req.timeline {
                Some(tl) => {
                    let mut timelines = tx.open_table(TIMELINES)?;
                    Some(timeline_cas(
                        &mut timelines,
                        &mut holds,
                        &tl.timeline,
                        &req.owner,
                        tl.expected_old,
                        req.frame_id,
                    )?)
                }
                None => None,
            };
            let out = CommittedFrame {
                frame_id: req.frame_id,
                durability,
                objects: expected_objects,
                timeline,
            };
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::Committed(out.clone()),
                now,
                None,
            )?;
            (out, pin_lease)
        };
        tx.commit()?;
        if let Some((pin, expires)) = pin_lease {
            self.pin_leases.insert(
                (req.frame_id, pin.pin_id),
                PinLease::new(pin.owner, pin.lease_ttl_ms, expires, now, now_inst),
            );
        }
        Ok(out)
    }

    // ======================================================================== timelines

    /// Atomically move a timeline head (durable committed frames only), transferring the
    /// `TimelineHead` hold. The first writer becomes the timeline owner; only the owner may
    /// advance it, and only onto frames owned by the caller.
    pub fn advance_timeline_cas(
        &mut self,
        timeline: &str,
        owner: &str,
        expected_old: Option<FrameId>,
        new_head: FrameId,
        idem: Option<&IdempotencyKey>,
    ) -> Result<TimelineAdvance> {
        const OP: &str = "advance_timeline";
        validate_name("timeline", timeline)?;
        validate_name("owner", owner)?;
        let digest = idem_prepare(idem, owner, OP, &(timeline, owner, expected_old, new_head))?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let out = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                return match resp {
                    IdemResponse::TimelineAdvanced(a) => Ok(a),
                    _ => Err(replay_mismatch()),
                };
            }
            let frames = tx.open_table(FRAMES)?;
            let pending = tx.open_table(PENDING_RECLAIM)?;
            let mut holds = tx.open_table(HOLDS)?;
            let mut timelines = tx.open_table(TIMELINES)?;
            let rec = tables::load_frame(&frames, &new_head)?
                .ok_or(MetaError::FrameNotFound(new_head))?;
            if rec.state.durability() == FrameDurability::Volatile {
                return Err(MetaError::VolatileInTimelineForbidden(new_head));
            }
            let FrameState::Committed {
                owner: frame_owner, ..
            } = &rec.state
            else {
                return Err(wrong_state(new_head, "Committed", &rec.state));
            };
            check_owner(|| format!("frame {new_head}"), frame_owner, owner)?;
            if pending.get(frame_key(&new_head).as_str())?.is_some() {
                return Err(MetaError::FrameMarkedForDeletion(new_head));
            }
            let out = timeline_cas(
                &mut timelines,
                &mut holds,
                timeline,
                owner,
                expected_old,
                new_head,
            )?;
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::TimelineAdvanced(out.clone()),
                now,
                None,
            )?;
            out
        };
        tx.commit()?;
        Ok(out)
    }

    /// Delete a timeline (owner-checked), releasing its `TimelineHead` hold on the former head.
    pub fn delete_timeline(
        &mut self,
        timeline: &str,
        owner: &str,
        idem: Option<&IdempotencyKey>,
    ) -> Result<FrameId> {
        const OP: &str = "delete_timeline";
        validate_name("timeline", timeline)?;
        validate_name("owner", owner)?;
        let digest = idem_prepare(idem, owner, OP, &(timeline, owner))?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let head = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                return match resp {
                    IdemResponse::TimelineDeleted(f) => Ok(f),
                    _ => Err(replay_mismatch()),
                };
            }
            let mut timelines = tx.open_table(TIMELINES)?;
            let mut holds = tx.open_table(HOLDS)?;
            let rec: TimelineRecord = tables::get_json(&timelines, timeline)?
                .ok_or_else(|| MetaError::TimelineNotFound(timeline.to_owned()))?;
            check_owner(|| format!("timeline {timeline:?}"), &rec.owner, owner)?;
            let hold = Hold::TimelineHead {
                timeline_name: timeline.to_owned(),
            };
            holds.remove(hold_key(&rec.head, &hold).as_str())?;
            timelines.remove(timeline)?;
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::TimelineDeleted(rec.head),
                now,
                None,
            )?;
            rec.head
        };
        tx.commit()?;
        Ok(head)
    }

    // ======================================================================== delete

    /// Delete a frame. Unheld committed frames (and aborted `Preparing` frames) are deleted now;
    /// held frames are marked and reclaimed by [`Self::collect_garbage`] once unheld.
    ///
    /// If an object cannot be destroyed the frame stays `Deleting` and the hook error is
    /// returned; recovery (R5), GC, and idempotent retries resume the deletion.
    pub fn delete_frame(
        &mut self,
        frame: FrameId,
        owner: &str,
        idem: Option<&IdempotencyKey>,
    ) -> Result<DeleteOutcome> {
        const OP: &str = "delete_frame";
        validate_name("owner", owner)?;
        let digest = idem_prepare(idem, owner, OP, &(frame, owner))?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let (outcome, to_delete, is_replay) = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            let mut frames = tx.open_table(FRAMES)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                let IdemResponse::Deleted(d) = resp else {
                    return Err(replay_mismatch());
                };
                let still_deleting = tables::load_frame(&frames, &frame)?
                    .filter(|r| matches!(r.state, FrameState::Deleting { .. }));
                (d, still_deleting, true)
            } else {
                let mut pending = tx.open_table(PENDING_RECLAIM)?;
                let mut holds = tx.open_table(HOLDS)?;
                let rec = tables::load_frame(&frames, &frame)?
                    .ok_or(MetaError::FrameNotFound(frame))?;
                if let Some(o) = rec.state.owner() {
                    check_owner(|| format!("frame {frame}"), o, owner)?;
                }
                let deleting = |reason| FrameRecord {
                    frame_id: frame,
                    state: FrameState::Deleting {
                        durability: rec.state.durability(),
                        objects: rec.state.objects().to_vec(),
                        reason,
                        marked_at_ms: now,
                        owner: rec
                            .state
                            .owner()
                            .map(str::to_owned)
                            .or_else(|| Some(owner.to_owned())),
                    },
                };
                let (outcome, next) = match &rec.state {
                    FrameState::Preparing { parent, .. } => {
                        if let Some(p) = parent {
                            let hold = Hold::PreparingParent { child_frame: frame };
                            holds.remove(hold_key(p, &hold).as_str())?;
                        }
                        (
                            DeleteOutcome::Deleted,
                            Some(deleting(DeleteReason::Aborted { by: owner.into() })),
                        )
                    }
                    FrameState::Committed { .. } => {
                        let n = tables::holds_of(&holds, &frame)?.len();
                        if n > 0 {
                            let mark = ReclaimMark {
                                requested_by: owner.into(),
                                requested_at_ms: now,
                            };
                            tables::put_json(&mut pending, &frame_key(&frame), &mark)?;
                            (DeleteOutcome::Deferred { holds: n }, None)
                        } else {
                            (
                                DeleteOutcome::Deleted,
                                Some(deleting(DeleteReason::Requested { by: owner.into() })),
                            )
                        }
                    }
                    FrameState::Deleting { .. } => (DeleteOutcome::Deleted, Some(rec.clone())),
                };
                if let Some(next) = &next {
                    tables::put_json(&mut frames, &frame_key(&frame), next)?;
                }
                idem_store(
                    &mut idem_t,
                    idem,
                    OP,
                    digest.as_ref(),
                    IdemResponse::Deleted(outcome.clone()),
                    now,
                    None,
                )?;
                (outcome, next, false)
            }
        };
        if is_replay {
            drop(tx);
        } else {
            tx.commit()?;
        }
        if let Some(rec) = to_delete {
            self.pin_leases.retain(|(f, _), _| *f != frame);
            self.complete_deletion(&rec)?;
        }
        Ok(outcome)
    }

    // ======================================================================== garbage collection

    /// Expire pins, reclaim unheld frames marked for deletion, finish pending deletions, purge
    /// quarantine entries past their grace period and drop stale tombstones / idempotency
    /// records.
    pub fn collect_garbage(&mut self, _now_ms: u64) -> Result<GcReport> {
        self.collect_garbage_batch(usize::MAX)
    }

    /// [`Self::collect_garbage`] that stops after `max_deletions` physical deletions, so a caller
    /// sharing the engine can release it in between.
    ///
    /// An object that cannot be destroyed is reported in [`GcReport::failures`], does not count
    /// against the limit and does not stop the pass.
    pub fn collect_garbage_batch(&mut self, max_deletions: usize) -> Result<GcReport> {
        let now_ms = self.now_ms();
        let now_inst = self.clock.now_instant();
        let mut report = GcReport::default();

        // 1. pins + 2. deferred deletes, in one transaction.
        let tx = begin_write(&self.db)?;
        let mut expired_pins = Vec::new();
        {
            let mut frames = tx.open_table(FRAMES)?;
            let mut holds = tx.open_table(HOLDS)?;
            let mut pending = tx.open_table(PENDING_RECLAIM)?;
            for (key, hold) in tables::scan_json::<Hold, _>(&holds)? {
                let Hold::Pin {
                    pin_id,
                    expires_at_ms,
                    ..
                } = &hold
                else {
                    continue;
                };
                let frame = tables::parse_hold_key_frame(&key)?;
                let expired = match self.pin_leases.get(&(frame, pin_id.clone())) {
                    Some(lease) => lease.expires_at <= now_inst,
                    None => *expires_at_ms <= now_ms,
                };
                if expired {
                    holds.remove(key.as_str())?;
                    expired_pins.push((frame, pin_id.clone()));
                }
            }
            report.pins_expired = expired_pins.len();
            for (key, _mark) in tables::scan_json::<ReclaimMark, _>(&pending)? {
                let frame = FrameId::from_base32(&key)
                    .map_err(|e| MetaError::Codec(format!("reclaim key {key:?}: {e}")))?;
                match tables::load_frame(&frames, &frame)? {
                    Some(rec @ FrameRecord {
                        state: FrameState::Committed { .. },
                        ..
                    }) => {
                        if tables::holds_of(&holds, &frame)?.is_empty() {
                            let next = FrameRecord {
                                frame_id: frame,
                                state: FrameState::Deleting {
                                    durability: rec.state.durability(),
                                    objects: rec.state.objects().to_vec(),
                                    reason: DeleteReason::Reclaimed,
                                    marked_at_ms: now_ms,
                                    owner: rec.state.owner().map(str::to_owned),
                                },
                            };
                            tables::put_json(&mut frames, &key, &next)?;
                            pending.remove(key.as_str())?;
                        }
                    }
                    _ => {
                        pending.remove(key.as_str())?;
                    }
                }
            }
        }
        tx.commit()?;
        for k in expired_pins {
            self.pin_leases.remove(&k);
        }

        // 3. finish every pending physical deletion.
        let deleting: Vec<FrameRecord> = self
            .frames()?
            .into_iter()
            .filter(|r| matches!(r.state, FrameState::Deleting { .. }))
            .collect();
        let mut budget = max_deletions;
        for rec in &deleting {
            if budget == 0 {
                report.more = true;
                break;
            }
            match self.complete_deletion(rec) {
                Ok(()) => {
                    report.frames_deleted += 1;
                    budget -= 1;
                }
                Err(e @ MetaError::Hook { .. }) => {
                    report.failures.push(format!("frame {}: {e}", rec.frame_id));
                }
                Err(e) => return Err(e),
            }
        }

        // 4. quarantine purge (physical delete first, record second: a crash in between only
        //    leaves a record whose purge hits NotFound next time).
        // Due on the wall clock and on the monotonic clock: a wall clock that jumped ahead, or
        // that moved on while agentd was down, cannot purge anything on its own.
        let min_uptime_end = self
            .opened_at
            .checked_add(Duration::from_millis(self.cfg.quarantine_min_uptime_ms));
        let due: Vec<QuarantineRecord> = self
            .quarantine_records()?
            .into_iter()
            .filter(|r| {
                let mono_due = self
                    .quarantine_due
                    .get(&tables::quarantine_key(r))
                    .copied()
                    .or(min_uptime_end);
                now_ms >= r.purge_after_ms && mono_due.is_some_and(|t| now_inst >= t)
            })
            .collect();
        let qroot = self.cfg.quarantine_dir();
        let mut purged = Vec::new();
        for r in &due {
            if budget == 0 {
                report.more = true;
                break;
            }
            let dir = qroot.join(r.quarantined_epoch.cgroup_dir_name());
            let path = dir.join(r.file_name());
            match ignore_not_found(self.hooks.purge_quarantined(&path)) {
                Ok(()) => {
                    purged.push(r);
                    budget -= 1;
                    // Best effort: the epoch directory disappears once its last entry is purged.
                    let _ = std::fs::remove_dir(&dir);
                }
                Err(e) => report.failures.push(format!("{}: {e}", path.display())),
            }
        }
        if !purged.is_empty() {
            let tx = begin_write(&self.db)?;
            {
                let mut q = tx.open_table(QUARANTINE)?;
                for r in &purged {
                    q.remove(tables::quarantine_key(r).as_str())?;
                }
            }
            for r in &purged {
                self.quarantine_due.remove(&tables::quarantine_key(r));
            }
            tx.commit()?;
            report.quarantine_purged = purged.len();
        }

        // 5. tombstones + 6. idempotency records.
        let tx = begin_write(&self.db)?;
        {
            let mut worlds = tx.open_table(WORLDS)?;
            for (key, w) in tables::scan_json::<WorldRecord, _>(&worlds)? {
                if w.state
                    .ended_at_ms()
                    .is_some_and(|t| t.saturating_add(self.cfg.world_tombstone_ttl_ms) <= now_ms)
                {
                    worlds.remove(key.as_str())?;
                    report.tombstones_purged += 1;
                }
            }
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            for (key, r) in tables::scan_json::<IdempotencyRecord, _>(&idem_t)? {
                if r.recorded_at_ms.saturating_add(self.cfg.idempotency_ttl_ms) > now_ms {
                    continue;
                }
                // Forgetting the key of a running world would let a retry create a second one.
                if let IdemResponse::World(id) = &r.response
                    && tables::load_world(&worlds, id)?
                        .is_some_and(|w| w.state.ended_at_ms().is_none())
                {
                    continue;
                }
                idem_t.remove(key.as_str())?;
                report.idempotency_purged += 1;
            }
        }
        tx.commit()?;
        Ok(report)
    }
}

pub(crate) fn validate_pin(pin: &PinSpec, max_pin_ttl_ms: u64) -> Result<()> {
    validate_name("pin id", &pin.pin_id)?;
    validate_name("pin owner", &pin.owner)?;
    if pin.lease_ttl_ms == 0 || pin.lease_ttl_ms > max_pin_ttl_ms {
        return Err(MetaError::InvalidArgument(format!(
            "pin lease_ttl_ms {} must be within 1..={max_pin_ttl_ms}",
            pin.lease_ttl_ms
        )));
    }
    Ok(())
}
