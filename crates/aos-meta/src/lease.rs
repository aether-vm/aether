//! World lifecycle (in-memory monotonic leases + fencing tokens) and pin leases (memory
//! high-water mark, low-frequency flush to `redb`).

use std::time::{Duration, Instant};

use aos_types::{FrameId, WorldId};
use redb::ReadableTable;
use serde::{Deserialize, Serialize};

use crate::error::{MetaError, Result};
use crate::idempotency::IdemResponse;
use crate::model::{
    FencingToken, FrameDurability, FrameState, Hold, IdempotencyKey, Labels, PinSpec,
    WorldEndReason, WorldRecord, WorldState, labels_match, validate_labels, validate_name,
};
use crate::store::{
    MetaEngine, check_fence, check_owner, idem_lookup, idem_prepare, idem_store, validate_pin,
    wrong_state,
};
use crate::tables::{
    self, FRAMES, HOLDS, IDEMPOTENCY, PENDING_RECLAIM, RawTable, WORLDS, begin_write, frame_key,
    hold_key,
};

/// In-memory lease of a running world. Never written to `redb`.
#[derive(Debug, Clone)]
pub(crate) struct WorldLease {
    owner: String,
    token: FencingToken,
    ttl: Duration,
    expires_at: Instant,
}

/// In-memory view of a pin lease.
#[derive(Debug, Clone)]
pub(crate) struct PinLease {
    owner: String,
    ttl_ms: u64,
    /// Monotonic expiry of the live in-memory pin lease.
    pub(crate) expires_at: Instant,
    /// Monotonic instant when this pin was last flushed to `redb`.
    last_flush_at: Instant,
    /// Latest renewal (memory only until flushed).
    pub(crate) high_ms: u64,
    /// Value currently stored in `redb`.
    persisted_ms: u64,
}

impl PinLease {
    pub(crate) fn new(
        owner: String,
        ttl_ms: u64,
        expires_ms: u64,
        _now_ms: u64,
        now_instant: Instant,
    ) -> Self {
        Self {
            owner,
            ttl_ms,
            expires_at: now_instant + Duration::from_millis(ttl_ms),
            last_flush_at: now_instant,
            high_ms: expires_ms,
            persisted_ms: expires_ms,
        }
    }
}

/// Request to start a world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateWorldRequest {
    /// Owner.
    pub owner: String,
    /// Committed base frame.
    pub base_frame: FrameId,
    /// Immutable labels.
    pub labels: Labels,
    /// In-memory lease length (> 0).
    pub lease_ttl_ms: u64,
    /// Requested driver; only distinguishes idempotent requests.
    pub driver: String,
}

/// Result of [`MetaEngine::renew_pin_lease`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinRenewal {
    /// New (in-memory) expiry.
    pub expires_at_ms: u64,
    /// Expiry currently persisted in `redb`.
    pub persisted_expires_at_ms: u64,
    /// Whether this renewal wrote to `redb`.
    pub flushed: bool,
}

fn end_world(
    worlds: &mut RawTable<'_>,
    holds: &mut RawTable<'_>,
    mut w: WorldRecord,
    destroyed_at_ms: u64,
    reason: WorldEndReason,
) -> Result<WorldRecord> {
    let WorldState::Running { epoch } = w.state else {
        return Ok(w);
    };
    let hold = Hold::WorldBase {
        world_id: w.world_id,
        epoch,
    };
    holds.remove(hold_key(&w.base_frame, &hold).as_str())?;
    w.state = WorldState::Destroyed {
        epoch,
        destroyed_at_ms,
        reason,
    };
    tables::put_json(worlds, &w.world_id.to_base32(), &w)?;
    Ok(w)
}

impl MetaEngine {
    // ======================================================================== worlds

    /// Start a world on a committed base frame: persists the record (token
    /// [`FencingToken::FIRST`]) and a `WorldBase` hold, then registers an in-memory lease.
    pub fn create_world(
        &mut self,
        req: &CreateWorldRequest,
        idem: Option<&IdempotencyKey>,
    ) -> Result<WorldRecord> {
        const OP: &str = "create_world";
        validate_name("owner", &req.owner)?;
        validate_labels(&req.labels)?;
        if req.lease_ttl_ms == 0 || req.lease_ttl_ms > self.cfg.max_world_lease_ttl_ms {
            return Err(MetaError::InvalidArgument(format!(
                "lease_ttl_ms {} must be within 1..={}",
                req.lease_ttl_ms, self.cfg.max_world_lease_ttl_ms
            )));
        }
        let digest = idem_prepare(idem, &req.owner, OP, req)?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let rec = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            let mut worlds = tx.open_table(WORLDS)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                let IdemResponse::World(id) = resp else {
                    return Err(MetaError::Codec("unexpected replay response".into()));
                };
                let mut w =
                    tables::load_world(&worlds, &id)?.ok_or(MetaError::WorldNotFound(id))?;
                // Always return the token originally issued to create_world, never a post-takeover
                // token (§7.3 fencing).
                w.fencing_token = FencingToken::FIRST;
                return Ok(w);
            }
            let frames = tx.open_table(FRAMES)?;
            let pending = tx.open_table(PENDING_RECLAIM)?;
            let mut holds = tx.open_table(HOLDS)?;
            let base = tables::load_frame(&frames, &req.base_frame)?
                .ok_or(MetaError::FrameNotFound(req.base_frame))?;
            let FrameState::Committed {
                durability,
                boot_id,
                owner: base_owner,
                ..
            } = &base.state
            else {
                return Err(wrong_state(req.base_frame, "Committed", &base.state));
            };
            check_owner(
                || format!("frame {}", req.base_frame),
                base_owner,
                &req.owner,
            )?;
            if *durability == FrameDurability::Volatile && *boot_id != self.boot {
                return Err(MetaError::StaleBoot {
                    frame: req.base_frame,
                    recorded: *boot_id,
                    current: self.boot,
                });
            }
            if pending.get(frame_key(&req.base_frame).as_str())?.is_some() {
                return Err(MetaError::FrameMarkedForDeletion(req.base_frame));
            }
            let world_id = WorldId::try_random()
                .map_err(|e| MetaError::io("generating world id", std::io::Error::other(e)))?;
            let rec = WorldRecord {
                world_id,
                base_frame: req.base_frame,
                owner: req.owner.clone(),
                labels: req.labels.clone(),
                fencing_token: FencingToken::FIRST,
                state: WorldState::Running { epoch: self.epoch },
            };
            tables::put_json(&mut worlds, &world_id.to_base32(), &rec)?;
            let hold = Hold::WorldBase {
                world_id,
                epoch: self.epoch,
            };
            tables::put_json(&mut holds, &hold_key(&req.base_frame, &hold), &hold)?;
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::World(world_id),
                now,
                None,
            )?;
            rec
        };
        tx.commit()?;
        let ttl = Duration::from_millis(req.lease_ttl_ms);
        self.world_leases.insert(
            rec.world_id,
            WorldLease {
                owner: rec.owner.clone(),
                token: rec.fencing_token,
                ttl,
                expires_at: self.clock.now_instant() + ttl,
            },
        );
        Ok(rec)
    }

    /// The world an earlier `create_world` with this key and request produced, if any.
    pub fn replay_create_world(
        &self,
        req: &CreateWorldRequest,
        key: &IdempotencyKey,
    ) -> Result<Option<WorldRecord>> {
        const OP: &str = "create_world";
        let digest = idem_prepare(Some(key), &req.owner, OP, req)?;
        let found =
            self.read_table(IDEMPOTENCY, |t| idem_lookup(t, Some(key), OP, digest.as_ref()))?;
        let id = match found {
            None => return Ok(None),
            Some(IdemResponse::World(id)) => id,
            Some(_) => return Err(MetaError::Codec("unexpected replay response".into())),
        };
        let mut w = self.world(id)?.ok_or(MetaError::WorldNotFound(id))?;
        w.fencing_token = FencingToken::FIRST;
        Ok(Some(w))
    }

    /// End a world whose sandbox never came up and, in the same transaction, forget the
    /// idempotency key of its `create_world` so a retry starts over.
    pub fn abort_create_world(
        &mut self,
        world: WorldId,
        owner: &str,
        idem: Option<&IdempotencyKey>,
    ) -> Result<()> {
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut holds = tx.open_table(HOLDS)?;
            let w = tables::load_world(&worlds, &world)?.ok_or(MetaError::WorldNotFound(world))?;
            check_owner(|| format!("world {world}"), &w.owner, owner)?;
            end_world(
                &mut worlds,
                &mut holds,
                w,
                now,
                WorldEndReason::Requested { by: owner.into() },
            )?;
            if let Some(key) = idem {
                let mut idem_t = tx.open_table(IDEMPOTENCY)?;
                let ours = tables::load_idem(&idem_t, key)?
                    .is_some_and(|r| r.response == IdemResponse::World(world));
                if ours {
                    idem_t.remove(tables::idem_key(key).as_str())?;
                }
            }
        }
        tx.commit()?;
        self.world_leases.remove(&world);
        Ok(())
    }

    pub(crate) fn live_lease(
        &self,
        world: WorldId,
        owner: &str,
        token: FencingToken,
    ) -> Result<&WorldLease> {
        let lease = self
            .world_leases
            .get(&world)
            .filter(|l| l.expires_at > self.clock.now_instant())
            .ok_or(MetaError::WorldNotRunning(world))?;
        check_owner(|| format!("world {world}"), &lease.owner, owner)?;
        if token != lease.token {
            return Err(MetaError::FencedOut {
                world,
                presented: token,
                current: lease.token,
            });
        }
        Ok(lease)
    }

    /// Check that `(owner, token)` may mutate a running world. Pure memory.
    pub fn check_world_mutation(
        &self,
        world: WorldId,
        owner: &str,
        token: FencingToken,
    ) -> Result<()> {
        self.live_lease(world, owner, token).map(|_| ())
    }

    /// Extend a world lease on the monotonic clock. Pure memory: **no `redb` access**.
    pub fn renew_world_lease(
        &mut self,
        world: WorldId,
        owner: &str,
        token: FencingToken,
    ) -> Result<Instant> {
        let ttl = self.live_lease(world, owner, token)?.ttl;
        let expires_at = self.clock.now_instant() + ttl;
        if let Some(l) = self.world_leases.get_mut(&world) {
            l.expires_at = expires_at;
        }
        Ok(expires_at)
    }

    /// Take over a world: persist `fencing_token + 1` and return it. Every later call with an
    /// older token is [`MetaError::FencedOut`].
    pub fn acquire_world_fence(&mut self, world: WorldId, owner: &str) -> Result<FencingToken> {
        let now_inst = self.clock.now_instant();
        let tx = begin_write(&self.db)?;
        let token = {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut w =
                tables::load_world(&worlds, &world)?.ok_or(MetaError::WorldNotFound(world))?;
            check_owner(|| format!("world {world}"), &w.owner, owner)?;
            if !w.state.is_running()
                || self
                    .world_leases
                    .get(&world)
                    .is_none_or(|l| l.expires_at <= now_inst)
            {
                return Err(MetaError::WorldNotRunning(world));
            }
            w.fencing_token = w
                .fencing_token
                .next()
                .ok_or_else(|| MetaError::InvalidArgument("fencing token overflow".into()))?;
            tables::put_json(&mut worlds, &world.to_base32(), &w)?;
            w.fencing_token
        };
        tx.commit()?;
        if let Some(l) = self.world_leases.get_mut(&world) {
            l.token = token;
        }
        Ok(token)
    }

    /// Destroy a world (fencing-checked). Destroying an ended world returns its tombstone.
    pub fn destroy_world(
        &mut self,
        world: WorldId,
        owner: &str,
        token: FencingToken,
        idem: Option<&IdempotencyKey>,
    ) -> Result<WorldRecord> {
        const OP: &str = "destroy_world";
        validate_name("owner", owner)?;
        let digest = idem_prepare(idem, owner, OP, &(world, owner, token))?;
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let rec = {
            let mut idem_t = tx.open_table(IDEMPOTENCY)?;
            let mut worlds = tx.open_table(WORLDS)?;
            if let Some(resp) = idem_lookup(&idem_t, idem, OP, digest.as_ref())? {
                let IdemResponse::World(id) = resp else {
                    return Err(MetaError::Codec("unexpected replay response".into()));
                };
                return tables::load_world(&worlds, &id)?.ok_or(MetaError::WorldNotFound(id));
            }
            let mut holds = tx.open_table(HOLDS)?;
            let w = tables::load_world(&worlds, &world)?.ok_or(MetaError::WorldNotFound(world))?;
            check_fence(&w, owner, token)?;
            let rec = end_world(
                &mut worlds,
                &mut holds,
                w,
                now,
                WorldEndReason::Requested { by: owner.into() },
            )?;
            idem_store(
                &mut idem_t,
                idem,
                OP,
                digest.as_ref(),
                IdemResponse::World(world),
                now,
                None,
            )?;
            rec
        };
        tx.commit()?;
        self.world_leases.remove(&world);
        Ok(rec)
    }

    /// End every world whose in-memory lease is due at `now`; returns the worlds the sandbox
    /// layer must kill.
    pub fn expire_due_world_leases(&mut self, now: Instant) -> Result<Vec<WorldId>> {
        self.expire_leases(now, |_| false)
    }

    /// Like [`Self::expire_due_world_leases`] at the engine's current time, but postponing worlds
    /// for which `busy` returns `true`.
    pub fn expire_idle_world_leases(
        &mut self,
        busy: impl Fn(&WorldId) -> bool,
    ) -> Result<Vec<WorldId>> {
        let now = self.clock.now_instant();
        self.expire_leases(now, busy)
    }

    fn expire_leases(
        &mut self,
        now: Instant,
        busy: impl Fn(&WorldId) -> bool,
    ) -> Result<Vec<WorldId>> {
        let mut due: Vec<WorldId> = self
            .world_leases
            .iter()
            .filter(|(w, l)| l.expires_at <= now && !busy(w))
            .map(|(w, _)| *w)
            .collect();
        if due.is_empty() {
            return Ok(due);
        }
        due.sort();
        let now_ms = self.now_ms();
        let tx = begin_write(&self.db)?;
        {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut holds = tx.open_table(HOLDS)?;
            for id in &due {
                if let Some(w) = tables::load_world(&worlds, id)? {
                    end_world(&mut worlds, &mut holds, w, now_ms, WorldEndReason::LeaseExpired)?;
                }
            }
        }
        tx.commit()?;
        for id in &due {
            self.world_leases.remove(id);
        }
        Ok(due)
    }

    /// Worlds (including tombstones) of `owner` whose labels contain `selector`.
    pub fn list_worlds_by_labels(&self, owner: &str, selector: &Labels) -> Result<Vec<WorldRecord>> {
        if selector.is_empty() {
            return Err(MetaError::EmptySelectorForbidden);
        }
        Ok(self
            .worlds()?
            .into_iter()
            .filter(|w| w.owner == owner && labels_match(&w.labels, selector))
            .collect())
    }

    /// Destroy every running world of `owner` matching a non-empty selector. Never touches other
    /// owners' worlds; the caller is recorded in the tombstone.
    pub fn destroy_worlds_by_labels(&mut self, owner: &str, selector: &Labels) -> Result<Vec<WorldId>> {
        validate_name("owner", owner)?;
        if selector.is_empty() {
            return Err(MetaError::EmptySelectorForbidden);
        }
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let mut ids = Vec::new();
        {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut holds = tx.open_table(HOLDS)?;
            for (_, w) in tables::scan_json::<WorldRecord, _>(&worlds)? {
                if w.owner == owner && w.state.is_running() && labels_match(&w.labels, selector) {
                    ids.push(w.world_id);
                    end_world(
                        &mut worlds,
                        &mut holds,
                        w,
                        now,
                        WorldEndReason::BatchSelector {
                            by: owner.into(),
                            selector: selector.clone(),
                        },
                    )?;
                }
            }
        }
        tx.commit()?;
        for id in &ids {
            self.world_leases.remove(id);
        }
        Ok(ids)
    }

    // ======================================================================== pins

    /// Attach (or refresh) a pin on a committed frame.
    pub fn pin_frame(&mut self, frame: FrameId, spec: &PinSpec) -> Result<Hold> {
        validate_pin(spec, self.cfg.max_pin_ttl_ms)?;
        let now = self.now_ms();
        let now_inst = self.clock.now_instant();
        let expires = now.saturating_add(spec.lease_ttl_ms);
        let hold = Hold::Pin {
            pin_id: spec.pin_id.clone(),
            owner: spec.owner.clone(),
            lease_ttl_ms: spec.lease_ttl_ms,
            expires_at_ms: expires,
        };
        let tx = begin_write(&self.db)?;
        {
            let frames = tx.open_table(FRAMES)?;
            let pending = tx.open_table(PENDING_RECLAIM)?;
            let mut holds = tx.open_table(HOLDS)?;
            let rec =
                tables::load_frame(&frames, &frame)?.ok_or(MetaError::FrameNotFound(frame))?;
            let FrameState::Committed {
                owner: frame_owner, ..
            } = &rec.state
            else {
                return Err(wrong_state(frame, "Committed", &rec.state));
            };
            check_owner(|| format!("frame {frame}"), frame_owner, &spec.owner)?;
            if pending.get(frame_key(&frame).as_str())?.is_some() {
                return Err(MetaError::FrameMarkedForDeletion(frame));
            }
            let key = hold_key(&frame, &hold);
            if let Some(Hold::Pin { owner, .. }) = tables::get_json::<Hold, _>(&holds, &key)? {
                check_owner(|| format!("pin {:?}", spec.pin_id), &owner, &spec.owner)?;
            }
            tables::put_json(&mut holds, &key, &hold)?;
        }
        tx.commit()?;
        self.pin_leases.insert(
            (frame, spec.pin_id.clone()),
            PinLease::new(
                spec.owner.clone(),
                spec.lease_ttl_ms,
                expires,
                now,
                now_inst,
            ),
        );
        Ok(hold)
    }

    /// Remove a pin.
    pub fn unpin_frame(&mut self, frame: FrameId, pin_id: &str, owner: &str) -> Result<()> {
        let probe = Hold::Pin {
            pin_id: pin_id.to_owned(),
            owner: String::new(),
            lease_ttl_ms: 0,
            expires_at_ms: 0,
        };
        let key = hold_key(&frame, &probe);
        let tx = begin_write(&self.db)?;
        {
            let mut holds = tx.open_table(HOLDS)?;
            match tables::get_json::<Hold, _>(&holds, &key)? {
                Some(Hold::Pin { owner: o, .. }) => {
                    check_owner(|| format!("pin {pin_id:?}"), &o, owner)?;
                }
                _ => {
                    return Err(MetaError::PinNotFound {
                        frame,
                        pin_id: pin_id.to_owned(),
                    });
                }
            }
            holds.remove(key.as_str())?;
        }
        tx.commit()?;
        self.pin_leases.remove(&(frame, pin_id.to_owned()));
        Ok(())
    }

    fn load_pin_lease(&mut self, frame: FrameId, pin_id: &str) -> Result<&mut PinLease> {
        let k = (frame, pin_id.to_owned());
        if !self.pin_leases.contains_key(&k) {
            let probe = Hold::Pin {
                pin_id: pin_id.to_owned(),
                owner: String::new(),
                lease_ttl_ms: 0,
                expires_at_ms: 0,
            };
            let tx = self.db.begin_read()?;
            let holds = tx.open_table(HOLDS)?;
            let Some(Hold::Pin {
                owner,
                lease_ttl_ms,
                expires_at_ms,
                ..
            }) = tables::get_json::<Hold, _>(&holds, &hold_key(&frame, &probe))?
            else {
                return Err(MetaError::PinNotFound {
                    frame,
                    pin_id: pin_id.to_owned(),
                });
            };
            let now = self.now_ms();
            let now_inst = self.clock.now_instant();
            self.pin_leases.insert(
                k.clone(),
                PinLease::new(owner, lease_ttl_ms, expires_at_ms, now, now_inst),
            );
        }
        Ok(self.pin_leases.get_mut(&k).expect("inserted above"))
    }

    /// Renew a pin lease. The renewal is kept in memory and only written to `redb` when the
    /// persisted expiry has less than half a TTL left or `pin_flush_interval_ms` has elapsed
    /// since the last flush.
    pub fn renew_pin_lease(&mut self, frame: FrameId, pin_id: &str, owner: &str) -> Result<PinRenewal> {
        let now = self.now_ms();
        let now_inst = self.clock.now_instant();
        let interval = Duration::from_millis(self.cfg.pin_flush_interval_ms);
        let (ttl_ms, new_expires_at, new_high, mut persisted, need_flush) = {
            let lease = self.load_pin_lease(frame, pin_id)?;
            check_owner(|| format!("pin {pin_id:?}"), &lease.owner, owner)?;
            if lease.expires_at <= now_inst {
                return Err(MetaError::PinNotFound {
                    frame,
                    pin_id: pin_id.to_owned(),
                });
            }
            let ttl_ms = lease.ttl_ms;
            let new_expires_at = now_inst + Duration::from_millis(ttl_ms);
            // Never allow backward wall-clock steps to shrink high_ms.
            let new_high = lease
                .high_ms
                .max(lease.persisted_ms)
                .max(now.saturating_add(ttl_ms));
            let need_flush = lease.persisted_ms.saturating_sub(now) < ttl_ms / 2
                || now_inst.saturating_duration_since(lease.last_flush_at) >= interval;
            (ttl_ms, new_expires_at, new_high, lease.persisted_ms, need_flush)
        };
        let _ = ttl_ms;
        if need_flush {
            if self.flush_pins(&[(frame, pin_id.to_owned(), new_high)])? == 0 {
                // Removed from redb behind our back (expired by GC / frame deleted).
                self.pin_leases.remove(&(frame, pin_id.to_owned()));
                return Err(MetaError::PinNotFound {
                    frame,
                    pin_id: pin_id.to_owned(),
                });
            }
            persisted = new_high;
        }
        if let Some(lease) = self.pin_leases.get_mut(&(frame, pin_id.to_owned())) {
            lease.expires_at = new_expires_at;
            lease.high_ms = lease.high_ms.max(new_high);
        }
        Ok(PinRenewal {
            expires_at_ms: new_high,
            persisted_expires_at_ms: persisted,
            flushed: need_flush,
        })
    }

    /// Persist every in-memory pin renewal not yet in `redb` (graceful shutdown / tests).
    pub fn flush_dirty_pins(&mut self) -> Result<usize> {
        let dirty: Vec<(FrameId, String, u64)> = self
            .pin_leases
            .iter()
            .filter(|(_, l)| l.high_ms > l.persisted_ms)
            .map(|(k, l)| (k.0, k.1.clone(), l.high_ms))
            .collect();
        self.flush_pins(&dirty)
    }

    fn flush_pins(&mut self, keys: &[(FrameId, String, u64)]) -> Result<usize> {
        if keys.is_empty() {
            return Ok(0);
        }
        let now_inst = self.clock.now_instant();
        let tx = begin_write(&self.db)?;
        let mut flushed = Vec::new();
        {
            let mut holds = tx.open_table(HOLDS)?;
            for (frame, pin_id, target_high) in keys {
                if !self.pin_leases.contains_key(&(*frame, pin_id.clone())) {
                    continue;
                }
                let probe = Hold::Pin {
                    pin_id: pin_id.clone(),
                    owner: String::new(),
                    lease_ttl_ms: 0,
                    expires_at_ms: 0,
                };
                let key = hold_key(frame, &probe);
                if let Some(Hold::Pin {
                    pin_id,
                    owner,
                    lease_ttl_ms,
                    expires_at_ms,
                }) = tables::get_json::<Hold, _>(&holds, &key)?
                {
                    let new_persisted = expires_at_ms.max(*target_high);
                    let updated = Hold::Pin {
                        pin_id: pin_id.clone(),
                        owner,
                        lease_ttl_ms,
                        expires_at_ms: new_persisted,
                    };
                    tables::put_json(&mut holds, &key, &updated)?;
                    flushed.push((*frame, pin_id, new_persisted));
                }
            }
        }
        tx.commit()?;
        for (frame, pin_id, new_persisted) in &flushed {
            if let Some(l) = self.pin_leases.get_mut(&(*frame, pin_id.clone())) {
                l.high_ms = l.high_ms.max(*new_persisted);
                l.persisted_ms = l.persisted_ms.max(*new_persisted);
                l.last_flush_at = now_inst;
            }
        }
        Ok(flushed.len())
    }
}
