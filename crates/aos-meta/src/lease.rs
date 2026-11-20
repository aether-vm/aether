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
    /// Latest renewal (memory only until flushed).
    pub(crate) high_ms: u64,
    /// Value currently stored in `redb`.
    persisted_ms: u64,
    last_flush_ms: u64,
}

impl PinLease {
    pub(crate) fn new(owner: String, ttl_ms: u64, expires_ms: u64, now_ms: u64) -> Self {
        Self {
            owner,
            ttl_ms,
            high_ms: expires_ms,
            persisted_ms: expires_ms,
            last_flush_ms: now_ms,
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
        if req.lease_ttl_ms == 0 {
            return Err(MetaError::InvalidArgument("lease_ttl_ms must be > 0".into()));
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
                return tables::load_world(&worlds, &id)?.ok_or(MetaError::WorldNotFound(id));
            }
            let frames = tx.open_table(FRAMES)?;
            let pending = tx.open_table(PENDING_RECLAIM)?;
            let mut holds = tx.open_table(HOLDS)?;
            let base = tables::load_frame(&frames, &req.base_frame)?
                .ok_or(MetaError::FrameNotFound(req.base_frame))?;
            let FrameState::Committed {
                durability,
                boot_id,
                ..
            } = &base.state
            else {
                return Err(wrong_state(req.base_frame, "Committed", &base.state));
            };
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

    fn live_lease(&self, world: WorldId, owner: &str, token: FencingToken) -> Result<&WorldLease> {
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
        let tx = begin_write(&self.db)?;
        let token = {
            let mut worlds = tx.open_table(WORLDS)?;
            let mut w =
                tables::load_world(&worlds, &world)?.ok_or(MetaError::WorldNotFound(world))?;
            check_owner(|| format!("world {world}"), &w.owner, owner)?;
            if !w.state.is_running() {
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
        let mut due: Vec<WorldId> = self
            .world_leases
            .iter()
            .filter(|(_, l)| l.expires_at <= now)
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
        validate_pin(spec)?;
        let now = self.now_ms();
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
            if !matches!(rec.state, FrameState::Committed { .. }) {
                return Err(wrong_state(frame, "Committed", &rec.state));
            }
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
            PinLease::new(spec.owner.clone(), spec.lease_ttl_ms, expires, now),
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
            self.pin_leases.insert(
                k.clone(),
                PinLease::new(owner, lease_ttl_ms, expires_at_ms, now),
            );
        }
        Ok(self.pin_leases.get_mut(&k).expect("inserted above"))
    }

    /// Renew a pin lease. The renewal is kept in memory and only written to `redb` when the
    /// persisted expiry has less than half a TTL left or `pin_flush_interval_ms` has elapsed
    /// since the last flush.
    pub fn renew_pin_lease(&mut self, frame: FrameId, pin_id: &str, owner: &str) -> Result<PinRenewal> {
        let now = self.now_ms();
        let interval = self.cfg.pin_flush_interval_ms;
        let lease = self.load_pin_lease(frame, pin_id)?;
        check_owner(|| format!("pin {pin_id:?}"), &lease.owner, owner)?;
        if lease.high_ms.max(lease.persisted_ms) <= now {
            return Err(MetaError::PinNotFound {
                frame,
                pin_id: pin_id.to_owned(),
            });
        }
        lease.high_ms = now.saturating_add(lease.ttl_ms);
        let need_flush = lease.persisted_ms.saturating_sub(now) < lease.ttl_ms / 2
            || now.saturating_sub(lease.last_flush_ms) >= interval;
        let (high, mut persisted) = (lease.high_ms, lease.persisted_ms);
        if need_flush {
            if self.flush_pins(&[(frame, pin_id.to_owned())])? == 0 {
                // Removed from redb behind our back (expired by GC / frame deleted).
                self.pin_leases.remove(&(frame, pin_id.to_owned()));
                return Err(MetaError::PinNotFound {
                    frame,
                    pin_id: pin_id.to_owned(),
                });
            }
            persisted = high;
        }
        Ok(PinRenewal {
            expires_at_ms: high,
            persisted_expires_at_ms: persisted,
            flushed: need_flush,
        })
    }

    /// Persist every in-memory pin renewal not yet in `redb` (graceful shutdown / tests).
    pub fn flush_dirty_pins(&mut self) -> Result<usize> {
        let dirty: Vec<(FrameId, String)> = self
            .pin_leases
            .iter()
            .filter(|(_, l)| l.high_ms > l.persisted_ms)
            .map(|(k, _)| k.clone())
            .collect();
        self.flush_pins(&dirty)
    }

    fn flush_pins(&mut self, keys: &[(FrameId, String)]) -> Result<usize> {
        if keys.is_empty() {
            return Ok(0);
        }
        let now = self.now_ms();
        let tx = begin_write(&self.db)?;
        let mut flushed = Vec::new();
        {
            let mut holds = tx.open_table(HOLDS)?;
            for (frame, pin_id) in keys {
                let Some(lease) = self.pin_leases.get(&(*frame, pin_id.clone())) else {
                    continue;
                };
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
                    let updated = Hold::Pin {
                        pin_id: pin_id.clone(),
                        owner,
                        lease_ttl_ms,
                        expires_at_ms: expires_at_ms.max(lease.high_ms),
                    };
                    tables::put_json(&mut holds, &key, &updated)?;
                    flushed.push((*frame, pin_id));
                }
            }
        }
        tx.commit()?;
        for k in &flushed {
            if let Some(l) = self.pin_leases.get_mut(k) {
                l.persisted_ms = l.persisted_ms.max(l.high_ms);
                l.last_flush_ms = now;
            }
        }
        Ok(flushed.len())
    }
}
