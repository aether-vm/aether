//! Startup: R0 pool guard, R1 epoch / boot / pin renewal, R2 fencing, R3~R5 rollback-only
//! cleanup and R6 orphan quarantine with a circuit breaker.
//!
//! Every step is idempotent: a crash anywhere inside recovery is handled by simply running
//! recovery again. Nothing is ever rolled forward.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::sync::Arc;
use std::time::Instant;

use aos_types::{BootId, EpochId, FrameId, PersistProof};
use redb::{Database, TableError};

use crate::config::{Clock, MetaConfig};
use crate::error::{MetaError, Result};
use crate::hooks::RecoveryHooks;
use crate::idempotency::IdempotencyRecord;
use crate::lease::PinLease;
use crate::model::{
    DeleteReason, FrameDurability, FrameRecord, FrameState, Hold, ObjectLocation,
    QuarantineRecord, WorldRecord, WorldState,
};
use crate::pool;
use crate::store::MetaEngine;
use crate::tables::{
    self, FRAMES, HOLDS, IDEMPOTENCY, PENDING_RECLAIM, QUARANTINE, ReclaimMark, SYS_DAEMON_EPOCH,
    SYS_LAST_BOOT, SYSTEM, WORLDS, begin_write, ensure_tables, frame_key, hold_key,
};

/// What recovery did; every counter is exact so stress tests can assert on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySummary {
    /// Epoch of this incarnation.
    pub new_epoch: EpochId,
    /// The host rebooted since the previous incarnation.
    pub boot_changed: bool,
    /// Volatile committed frames of an older boot moved to `Deleting` (R1).
    pub volatile_expired: usize,
    /// Pins whose lease was reset to `now + lease_ttl` (R1).
    pub pins_renewed_on_boot: usize,
    /// Running worlds of older epochs declared `Lost` (R2).
    pub worlds_marked_lost: usize,
    /// `Preparing` frames rolled back (R3).
    pub preparing_rolled_back: usize,
    /// Frames whose physical deletion was completed (R4/R5).
    pub deleting_completed: usize,
    /// Orphans moved to `quarantine/epoch-<n>/` (R6).
    pub orphans_quarantined: usize,
    /// Entries in `objects/` when R6 ran.
    pub objects_scanned: usize,
}

struct R1Outcome {
    epoch: EpochId,
    boot_changed: bool,
    volatile_expired: usize,
    pins_renewed: usize,
    pin_leases: HashMap<(FrameId, String), PinLease>,
}

fn validate_config(cfg: &MetaConfig) -> Result<()> {
    if !(0.0..=1.0).contains(&cfg.max_orphan_ratio) {
        return Err(MetaError::InvalidArgument(
            "max_orphan_ratio must be within 0.0..=1.0".into(),
        ));
    }
    if cfg.meta_dir.as_os_str().is_empty() || cfg.pool_root.as_os_str().is_empty() {
        return Err(MetaError::InvalidArgument(
            "meta_dir and pool_root must be set".into(),
        ));
    }
    if cfg.max_orphan_count == 0 {
        return Err(MetaError::InvalidArgument(
            "max_orphan_count must be > 0".into(),
        ));
    }
    if cfg.min_orphan_ratio_sample == 0 {
        return Err(MetaError::InvalidArgument(
            "min_orphan_ratio_sample must be > 0".into(),
        ));
    }
    if cfg.max_small_pool_orphans == 0
        || cfg.max_small_pool_orphans > cfg.max_orphan_count
        || cfg.max_small_pool_orphans >= cfg.min_orphan_ratio_sample
    {
        return Err(MetaError::InvalidArgument(
            "max_small_pool_orphans must be within 1..min_orphan_ratio_sample and <= max_orphan_count"
                .into(),
        ));
    }
    if cfg.max_pin_ttl_ms == 0 {
        return Err(MetaError::InvalidArgument(
            "max_pin_ttl_ms must be > 0".into(),
        ));
    }
    if cfg.max_world_lease_ttl_ms == 0 {
        return Err(MetaError::InvalidArgument(
            "max_world_lease_ttl_ms must be > 0".into(),
        ));
    }
    if cfg.idempotency_ttl_ms == 0 || cfg.world_tombstone_ttl_ms < cfg.idempotency_ttl_ms {
        return Err(MetaError::InvalidArgument(
            "world_tombstone_ttl_ms must be >= idempotency_ttl_ms (> 0)".into(),
        ));
    }
    Ok(())
}

fn check_orphan_breaker(cfg: &MetaConfig, orphan_count: usize, total_objects: usize) -> Result<()> {
    #[allow(clippy::cast_precision_loss)]
    let ratio_or_small_tripped = if total_objects < cfg.min_orphan_ratio_sample {
        orphan_count > cfg.max_small_pool_orphans
    } else {
        total_objects > 0 && (orphan_count as f64 / total_objects as f64) > cfg.max_orphan_ratio
    };
    if orphan_count > cfg.max_orphan_count || ratio_or_small_tripped {
        return Err(MetaError::OrphanCircuitBreakerTriggered {
            orphan_count,
            total_objects,
        });
    }
    Ok(())
}

/// Read-only R0/R6 pre-flight check before R1/R2/R3/R5 mutate `redb` or unlink any objects:
/// verifies orphan circuit-breaker bounds (against all known `Committed | Preparing | Deleting`
/// pool objects) and ensures every `Committed` frame's pool objects exist on disk.
fn preflight_r6_check(cfg: &MetaConfig, db: &Database) -> Result<()> {
    let rtx = db.begin_read()?;
    let records: Vec<FrameRecord> = match rtx.open_table(FRAMES) {
        Ok(t) => tables::scan_json(&t)?.into_iter().map(|(_, r)| r).collect(),
        Err(TableError::TableDoesNotExist(_)) => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    let entries = pool::list_objects(cfg)?;
    let total = entries.len();
    let on_disk: HashSet<&OsStr> = entries.iter().map( std::ffi::OsString::as_os_str).collect();
    let mut known = HashSet::new();
    for rec in &records {
        let d = rec.state.durability();
        for o in rec.state.objects() {
            if o.location(d) == ObjectLocation::Pool {
                known.insert(o.name());
            }
        }
    }
    let orphan_count = entries
        .iter()
        .filter(|e| e.to_str().is_none_or(|n| !known.contains(n)))
        .count();
    check_orphan_breaker(cfg, orphan_count, total)?;

    for rec in &records {
        if let FrameState::Committed {
            durability,
            objects,
            ..
        } = &rec.state
        {
            for o in objects {
                if o.location(*durability) == ObjectLocation::Pool {
                    let name = o.name();
                    if !on_disk.contains(OsStr::new(&name)) {
                        return Err(MetaError::MissingCommittedObject {
                            frame_id: rec.frame_id,
                            object_name: name,
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

/// R1 in a single durable transaction.
fn r1_epoch_boot_pins(
    db: &Database,
    current_boot: BootId,
    now_ms: u64,
    now_instant: Instant,
) -> Result<R1Outcome> {
    let tx = begin_write(db)?;
    ensure_tables(&tx)?;
    let out = {
        let mut sys = tx.open_table(SYSTEM)?;
        let mut frames = tx.open_table(FRAMES)?;
        let mut holds = tx.open_table(HOLDS)?;
        let mut pending = tx.open_table(PENDING_RECLAIM)?;

        let prev: Option<EpochId> = tables::get_json(&sys, SYS_DAEMON_EPOCH)?;
        let epoch = match prev {
            Some(e) => e.next().ok_or(MetaError::EpochOverflow)?,
            None => EpochId::FIRST,
        };
        let last_boot: Option<BootId> = tables::get_json(&sys, SYS_LAST_BOOT)?;
        let boot_changed = last_boot.is_some_and(|b| b != current_boot);
        tables::put_json(&mut sys, SYS_DAEMON_EPOCH, &epoch)?;
        tables::put_json(&mut sys, SYS_LAST_BOOT, &current_boot)?;

        // Volatile frames of any other boot are dead: their tmpfs is gone.
        let mut committed = HashSet::new();
        let mut volatile_expired = 0;
        for (key, rec) in tables::scan_json::<FrameRecord, _>(&frames)? {
            match &rec.state {
                FrameState::Committed {
                    durability: FrameDurability::Volatile,
                    boot_id,
                    objects,
                    owner,
                    ..
                } if *boot_id != current_boot => {
                    let next = FrameRecord {
                        frame_id: rec.frame_id,
                        state: FrameState::Deleting {
                            durability: FrameDurability::Volatile,
                            objects: objects.clone(),
                            reason: DeleteReason::StaleBoot,
                            marked_at_ms: now_ms,
                            owner: Some(owner.clone()),
                        },
                    };
                    tables::put_json(&mut frames, &key, &next)?;
                    tables::clear_holds(&mut holds, &rec.frame_id)?;
                    pending.remove(key.as_str())?;
                    volatile_expired += 1;
                }
                FrameState::Committed { .. } => {
                    committed.insert(rec.frame_id);
                }
                _ => {}
            }
        }

        // §7.3: pin leases restart from `now`, so downtime never expires retained frames.
        let mut pins_renewed = 0;
        let mut pin_leases = HashMap::new();
        for (key, hold) in tables::scan_json::<Hold, _>(&holds)? {
            let frame = tables::parse_hold_key_frame(&key)?;
            if !committed.contains(&frame) {
                holds.remove(key.as_str())?;
                continue;
            }
            if let Hold::Pin {
                pin_id,
                owner,
                lease_ttl_ms,
                ..
            } = hold
            {
                let expires_at_ms = now_ms.saturating_add(lease_ttl_ms);
                let renewed = Hold::Pin {
                    pin_id: pin_id.clone(),
                    owner: owner.clone(),
                    lease_ttl_ms,
                    expires_at_ms,
                };
                tables::put_json(&mut holds, &key, &renewed)?;
                pin_leases.insert(
                    (frame, pin_id),
                    PinLease::new(owner, lease_ttl_ms, expires_at_ms, now_ms, now_instant),
                );
                pins_renewed += 1;
            }
        }
        R1Outcome {
            epoch,
            boot_changed,
            volatile_expired,
            pins_renewed,
            pin_leases,
        }
    };
    tx.commit()?;
    Ok(out)
}

impl MetaEngine {
    /// Open the pool and run the full R0 ~ R6 recovery pipeline.
    ///
    /// `current_boot` is sampled once by the caller (normally [`BootId::current`]) and used
    /// for every boot comparison of this incarnation. If any step fails the engine is dropped
    /// (releasing the pool lock) and the error is returned; re-running recovery is always safe.
    pub fn open_and_recover(
        cfg: MetaConfig,
        current_boot: BootId,
        hooks: Box<dyn RecoveryHooks>,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, RecoverySummary)> {
        // R0 + read-only R6 pre-flight check (before any redb mutation or object deletion)
        validate_config(&cfg)?;
        pool::prepare_dirs(&cfg)?;
        pool::check_filesystems(&cfg)?;
        let lock = pool::acquire_lock(&cfg)?;
        let (db, pool_id) = pool::open_or_init_db(&cfg)?;
        preflight_r6_check(&cfg, &db)?;

        // R1
        let r1 = r1_epoch_boot_pins(&db, current_boot, clock.now_ms(), clock.now_instant())?;
        let mut engine = MetaEngine {
            cfg,
            db,
            pool_id,
            epoch: r1.epoch,
            boot: current_boot,
            hooks,
            clock,
            world_leases: HashMap::new(),
            pin_leases: r1.pin_leases,
            _lock: lock,
        };
        let mut s = RecoverySummary {
            new_epoch: r1.epoch,
            boot_changed: r1.boot_changed,
            volatile_expired: r1.volatile_expired,
            pins_renewed_on_boot: r1.pins_renewed,
            worlds_marked_lost: 0,
            preparing_rolled_back: 0,
            deleting_completed: 0,
            orphans_quarantined: 0,
            objects_scanned: 0,
        };

        engine.r2_fence_and_lose_worlds(&mut s)?;
        engine.r3_rollback_preparing(&mut s)?;
        engine.r5_finish_deletions(&mut s)?;
        engine.r6_quarantine_orphans(&mut s)?;
        Ok((engine, s))
    }

    /// R2: gateway fence, then kill old epochs, then mark their worlds `Lost`.
    fn r2_fence_and_lose_worlds(&mut self, s: &mut RecoverySummary) -> Result<()> {
        self.hooks
            .fence_gateway(self.epoch)
            .map_err(|source| MetaError::Hook {
                stage: "fence_gateway",
                source,
            })?;
        self.hooks
            .kill_stale_epochs(self.epoch)
            .map_err(|source| MetaError::Hook {
                stage: "kill_stale_epochs",
                source,
            })?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut holds = tx.open_table(HOLDS)?;
            for (key, mut w) in tables::scan_json::<WorldRecord, _>(&worlds)? {
                let WorldState::Running { epoch } = w.state else {
                    continue;
                };
                let hold = Hold::WorldBase {
                    world_id: w.world_id,
                    epoch,
                };
                holds.remove(hold_key(&w.base_frame, &hold).as_str())?;
                w.state = WorldState::Lost {
                    origin_epoch: epoch,
                    lost_in_epoch: self.epoch,
                    lost_at_ms: now,
                };
                tables::put_json(&mut worlds, &key, &w)?;
                s.worlds_marked_lost += 1;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// R3: I4 — every `Preparing` frame is destroyed, never completed.
    fn r3_rollback_preparing(&mut self, s: &mut RecoverySummary) -> Result<()> {
        let preparing: Vec<FrameRecord> = self
            .frames()?
            .into_iter()
            .filter(|r| matches!(r.state, FrameState::Preparing { .. }))
            .collect();
        if preparing.is_empty() {
            return Ok(());
        }
        for rec in &preparing {
            self.destroy_objects(rec.state.durability(), rec.state.objects())?;
        }
        let ids: HashSet<FrameId> = preparing.iter().map(|r| r.frame_id).collect();
        let tx = begin_write(&self.db)?;
        {
            let mut frames = tx.open_table(FRAMES)?;
            let mut holds = tx.open_table(HOLDS)?;
            let mut idem = tx.open_table(IDEMPOTENCY)?;
            for rec in &preparing {
                frames.remove(frame_key(&rec.frame_id).as_str())?;
                tables::clear_holds(&mut holds, &rec.frame_id)?;
                if let FrameState::Preparing {
                    parent: Some(p), ..
                } = rec.state
                {
                    let hold = Hold::PreparingParent {
                        child_frame: rec.frame_id,
                    };
                    holds.remove(hold_key(&p, &hold).as_str())?;
                }
            }
            for (key, r) in tables::scan_json::<IdempotencyRecord, _>(&idem)? {
                if r.prepared_frame.is_some_and(|f| ids.contains(&f)) {
                    idem.remove(key.as_str())?;
                }
            }
        }
        tx.commit()?;
        s.preparing_rolled_back = ids.len();
        Ok(())
    }

    /// R4/R5: reclaim deferred deletes that are no longer held, then finish every `Deleting`
    /// frame.
    fn r5_finish_deletions(&mut self, s: &mut RecoverySummary) -> Result<()> {
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        {
            let mut frames = tx.open_table(FRAMES)?;
            let holds = tx.open_table(HOLDS)?;
            let mut pending = tx.open_table(PENDING_RECLAIM)?;
            for (key, _) in tables::scan_json::<ReclaimMark, _>(&pending)? {
                let frame = FrameId::from_base32(&key)
                    .map_err(|e| MetaError::Codec(format!("reclaim key {key:?}: {e}")))?;
                match tables::load_frame(&frames, &frame)? {
                    Some(rec) if matches!(rec.state, FrameState::Committed { .. }) => {
                        if tables::holds_of(&holds, &frame)?.is_empty() {
                            let next = FrameRecord {
                                frame_id: frame,
                                state: FrameState::Deleting {
                                    durability: rec.state.durability(),
                                    objects: rec.state.objects().to_vec(),
                                    reason: DeleteReason::Reclaimed,
                                    marked_at_ms: now,
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

        let deleting: Vec<FrameRecord> = self
            .frames()?
            .into_iter()
            .filter(|r| matches!(r.state, FrameState::Deleting { .. }))
            .collect();
        for rec in &deleting {
            self.complete_deletion(rec)?;
            s.deleting_completed += 1;
        }
        Ok(())
    }

    /// R6: move unreferenced `objects/` entries into `quarantine/epoch-<n>/`, unless there are
    /// so many that the metadata itself is suspect (then touch nothing and refuse to start).
    fn r6_quarantine_orphans(&mut self, s: &mut RecoverySummary) -> Result<()> {
        let frames = self.frames()?;
        let mut known = HashSet::new();
        for rec in &frames {
            let d = rec.state.durability();
            for o in rec.state.objects() {
                if o.location(d) == ObjectLocation::Pool {
                    known.insert(o.name());
                }
            }
        }
        let entries = pool::list_objects(&self.cfg)?;
        let total = entries.len();
        s.objects_scanned = total;
        let on_disk: HashSet<&OsStr> = entries.iter().map(std::ffi::OsString::as_os_str).collect();
        let orphans: Vec<_> = entries
            .iter()
            .filter(|e| e.to_str().is_none_or(|n| !known.contains(n)))
            .cloned()
            .collect();
        let n = orphans.len();
        check_orphan_breaker(&self.cfg, n, total)?;
        for rec in &frames {
            if let FrameState::Committed {
                durability,
                objects,
                ..
            } = &rec.state
            {
                for o in objects {
                    if o.location(*durability) == ObjectLocation::Pool {
                        let name = o.name();
                        if !on_disk.contains(OsStr::new(&name)) {
                            return Err(MetaError::MissingCommittedObject {
                                frame_id: rec.frame_id,
                                object_name: name,
                            });
                        }
                    }
                }
            }
        }
        if n == 0 {
            return Ok(());
        }

        let now = self.now_ms();
        let qdir = self.cfg.quarantine_dir().join(self.epoch.cgroup_dir_name());
        fs::create_dir_all(&qdir)
            .map_err(|e| MetaError::io(format!("creating {}", qdir.display()), e))?;
        let records: Vec<QuarantineRecord> = orphans
            .iter()
            .map(|o| QuarantineRecord {
                name: o.to_string_lossy().into_owned(),
                raw_name: if o.to_str().is_some() {
                    None
                } else {
                    Some(o.clone())
                },
                quarantined_epoch: self.epoch,
                quarantined_at_ms: now,
                purge_after_ms: now.saturating_add(self.cfg.quarantine_grace_ms),
            })
            .collect();
        // Record first: a crash before the rename leaves a record whose purge hits NotFound,
        // never an unrecorded file in quarantine.
        let tx = begin_write(&self.db)?;
        {
            let mut q = tx.open_table(QUARANTINE)?;
            for r in &records {
                tables::put_json(&mut q, &tables::quarantine_key(r), r)?;
            }
        }
        tx.commit()?;
        let objects = self.cfg.objects_dir();
        for o in &orphans {
            let (from, to) = (objects.join(o), qdir.join(o));
            fs::rename(&from, &to).map_err(|e| {
                MetaError::io(format!("quarantining {} -> {}", from.display(), to.display()), e)
            })?;
        }
        for d in [&qdir, &objects] {
            let _ = PersistProof::fsync_dir(d)
                .map_err(|e| MetaError::io(format!("fsync {}", d.display()), e))?;
        }
        s.orphans_quarantined = n;
        Ok(())
    }
}
