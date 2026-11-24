//! Epoch Fence Registry (`epoch.rs`, ARCHITECTURE_V2 §2.2, §4.2 R2, §7.4).
//!
//! Thread-safe binding registry mapping `(slot_id, world_id, daemon_epoch)` to an active
//! [`CapabilityPolicy`], compiled [`ReflectionScanner`], and in-flight [`CancellationToken`].
//!
//! When `agentd` restarts and runs R2 recovery, it invokes [`EpochFenceRegistry::advance_epoch`]
//! with the new monotonic `daemon_epoch`. All bindings with `epoch < new_epoch` are immediately
//! dropped from the registry and their cancellation tokens are triggered before `advance_epoch`
//! returns, terminating all in-flight proxied connections and rejecting stale registrations.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aos_types::{EpochId, WorldId};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::error::{GwError, Result};
use crate::policy::CapabilityPolicy;
use crate::reflection::ReflectionScanner;

/// Validated network slot identifier (e.g. `"slot-0"`, `"netns-42"`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SlotId(String);

impl SlotId {
    /// Construct a validated slot ID (`1..=64` ASCII alphanumeric / `-` / `_` bytes).
    pub fn new(raw: impl Into<String>) -> Result<Self> {
        let s = raw.into();
        if s.is_empty() || s.len() > 64 {
            return Err(GwError::InvalidSlotId(
                "slot id must be 1..=64 bytes".into(),
            ));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(GwError::InvalidSlotId(format!(
                "slot id contains invalid characters: {s:?}"
            )));
        }
        Ok(Self(s))
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for SlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Physical capability binding key `(slot_id, world_id, daemon_epoch)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BindingKey {
    /// Network slot / listener identifier.
    pub slot_id: SlotId,
    /// Owning world identifier.
    pub world_id: WorldId,
    /// Daemon epoch under which this binding was issued.
    pub epoch: EpochId,
}

impl BindingKey {
    /// Construct a new binding key.
    #[must_use]
    pub fn new(slot_id: SlotId, world_id: WorldId, epoch: EpochId) -> Self {
        Self {
            slot_id,
            world_id,
            epoch,
        }
    }
}

/// Active slot binding stored inside [`EpochFenceRegistry`].
#[derive(Debug)]
pub struct SlotBinding {
    key: BindingKey,
    policy: Arc<CapabilityPolicy>,
    scanner: Arc<ReflectionScanner>,
    cancel: CancellationToken,
    active_connections: AtomicUsize,
}

impl SlotBinding {
    /// The `(slot_id, world_id, epoch)` triple identifying this binding.
    #[must_use]
    pub fn key(&self) -> &BindingKey {
        &self.key
    }

    /// The capability policy governing this binding.
    #[must_use]
    pub fn policy(&self) -> &Arc<CapabilityPolicy> {
        &self.policy
    }

    /// Pre-compiled anti-reflection scanner covering every secret in `policy`.
    #[must_use]
    pub fn scanner(&self) -> &Arc<ReflectionScanner> {
        &self.scanner
    }

    /// Cancellation token fired immediately when this binding is revoked or fenced by an epoch advance.
    #[must_use]
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }

    /// Returns `true` if this binding has been revoked or fenced.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Current number of active in-flight connections tracked on this binding.
    #[must_use]
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Acquire)
    }

    /// Increment active connection counter and return an RAII guard that decrements on drop.
    #[must_use]
    pub fn track_connection(self: &Arc<Self>) -> ActiveConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::AcqRel);
        ActiveConnectionGuard {
            binding: Arc::clone(self),
        }
    }
}

/// RAII guard tracking an in-flight proxied connection against a [`SlotBinding`].
#[derive(Debug)]
pub struct ActiveConnectionGuard {
    binding: Arc<SlotBinding>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.binding
            .active_connections
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// Summary returned by [`EpochFenceRegistry::advance_epoch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochAdvanceReport {
    /// Previous current epoch before the call.
    pub previous_epoch: EpochId,
    /// New current epoch after the call.
    pub current_epoch: EpochId,
    /// Number of stale (`< current_epoch`) bindings invalidated and cancelled.
    pub revoked_bindings: usize,
}

#[derive(Debug)]
struct RegistryState {
    current_epoch: EpochId,
    slots: HashMap<SlotId, Arc<SlotBinding>>,
}

/// Thread-safe Epoch Fence Registry enforcing ARCHITECTURE_V2 §4.2 R2.
#[derive(Debug)]
pub struct EpochFenceRegistry {
    state: RwLock<RegistryState>,
}

impl EpochFenceRegistry {
    /// Create a new registry initialized at `initial_epoch`.
    #[must_use]
    pub fn new(initial_epoch: EpochId) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                current_epoch: initial_epoch,
                slots: HashMap::new(),
            }),
        }
    }

    /// Current monotonic gateway epoch.
    #[must_use]
    pub fn current_epoch(&self) -> EpochId {
        self.state
            .read()
            .expect("epoch fence registry lock poisoned")
            .current_epoch
    }

    /// Number of currently active slot bindings.
    #[must_use]
    pub fn active_binding_count(&self) -> usize {
        self.state
            .read()
            .expect("epoch fence registry lock poisoned")
            .slots
            .len()
    }

    /// Register a new `(slot_id, world_id, epoch)` capability binding.
    ///
    /// Rejects:
    /// - stale epochs (`key.epoch < current_epoch`) -> [`GwError::StaleEpoch`]
    /// - future epochs (`key.epoch > current_epoch`) -> [`GwError::FutureEpoch`]
    /// - already-registered active slots -> [`GwError::DuplicateSlot`]
    pub fn register(
        &self,
        key: BindingKey,
        policy: CapabilityPolicy,
    ) -> Result<Arc<SlotBinding>> {
        // Pre-compile the anti-reflection scanner outside the write lock.
        let scanner = ReflectionScanner::compile(
            policy.registered_secrets(),
            policy.reflection_action,
        )?;

        let mut guard = self
            .state
            .write()
            .expect("epoch fence registry lock poisoned");

        if key.epoch < guard.current_epoch {
            return Err(GwError::StaleEpoch {
                provided: key.epoch,
                current: guard.current_epoch,
            });
        }
        if key.epoch > guard.current_epoch {
            return Err(GwError::FutureEpoch {
                provided: key.epoch,
                current: guard.current_epoch,
            });
        }
        if guard.slots.contains_key(&key.slot_id) {
            return Err(GwError::DuplicateSlot {
                slot_id: key.slot_id.to_string(),
            });
        }

        let binding = Arc::new(SlotBinding {
            key: key.clone(),
            policy: Arc::new(policy),
            scanner: Arc::new(scanner),
            cancel: CancellationToken::new(),
            active_connections: AtomicUsize::new(0),
        });

        guard.slots.insert(key.slot_id, Arc::clone(&binding));
        Ok(binding)
    }

    /// Look up and verify an active binding for the exact `(slot_id, world_id, epoch)` triple.
    pub fn lookup(&self, key: &BindingKey) -> Result<Arc<SlotBinding>> {
        let guard = self
            .state
            .read()
            .expect("epoch fence registry lock poisoned");

        if key.epoch < guard.current_epoch {
            return Err(GwError::StaleEpoch {
                provided: key.epoch,
                current: guard.current_epoch,
            });
        }
        if key.epoch > guard.current_epoch {
            return Err(GwError::FutureEpoch {
                provided: key.epoch,
                current: guard.current_epoch,
            });
        }

        let Some(binding) = guard.slots.get(&key.slot_id) else {
            return Err(GwError::BindingNotFound {
                slot_id: key.slot_id.to_string(),
                world_id: key.world_id,
                epoch: key.epoch,
            });
        };

        if binding.key != *key || binding.is_revoked() {
            return Err(GwError::BindingNotFound {
                slot_id: key.slot_id.to_string(),
                world_id: key.world_id,
                epoch: key.epoch,
            });
        }

        Ok(Arc::clone(binding))
    }

    /// Revoke a single active slot binding and immediately cancel its in-flight connections.
    pub fn revoke_slot(&self, slot_id: &SlotId) -> bool {
        let removed = {
            let mut guard = self
                .state
                .write()
                .expect("epoch fence registry lock poisoned");
            guard.slots.remove(slot_id)
        };
        if let Some(binding) = removed {
            binding.cancel.cancel();
            true
        } else {
            false
        }
    }

    /// Revoke every active slot binding belonging to `world_id` and cancel in-flight connections.
    pub fn revoke_world(&self, world_id: WorldId) -> usize {
        let removed: Vec<Arc<SlotBinding>> = {
            let mut guard = self
                .state
                .write()
                .expect("epoch fence registry lock poisoned");
            let to_remove: Vec<SlotId> = guard
                .slots
                .iter()
                .filter(|&(_slot, b)| b.key.world_id == world_id)
                .map(|(slot, _b)| slot.clone())
                .collect();
            to_remove
                .into_iter()
                .filter_map(|slot| guard.slots.remove(&slot))
                .collect()
        };
        let count = removed.len();
        for binding in removed {
            binding.cancel.cancel();
        }
        count
    }

    /// Monotonically advance `current_epoch` to `new_epoch` (R2 gateway fence).
    ///
    /// - Rejects epoch regressions (`new_epoch < current_epoch`) with [`GwError::EpochRegression`].
    /// - Idempotent when `new_epoch == current_epoch` (safe for R2 startup/retry).
    /// - When `new_epoch > current_epoch`, atomically updates `current_epoch`, removes and drops
    ///   all bindings with `epoch < new_epoch`, and triggers their cancellation tokens before
    ///   returning `Ok`.
    pub fn advance_epoch(&self, new_epoch: EpochId) -> Result<EpochAdvanceReport> {
        let (previous_epoch, removed) = {
            let mut guard = self
                .state
                .write()
                .expect("epoch fence registry lock poisoned");
            let prev = guard.current_epoch;
            if new_epoch < prev {
                return Err(GwError::EpochRegression {
                    requested: new_epoch,
                    current: prev,
                });
            }
            guard.current_epoch = new_epoch;

            let stale_slots: Vec<SlotId> = guard
                .slots
                .iter()
                .filter(|&(_slot, b)| b.key.epoch < new_epoch)
                .map(|(slot, _b)| slot.clone())
                .collect();

            let removed: Vec<Arc<SlotBinding>> = stale_slots
                .into_iter()
                .filter_map(|slot| guard.slots.remove(&slot))
                .collect();

            (prev, removed)
        };

        let revoked_bindings = removed.len();
        for binding in removed {
            binding.cancel.cancel();
        }

        Ok(EpochAdvanceReport {
            previous_epoch,
            current_epoch: new_epoch,
            revoked_bindings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_lookup_duplicate_stale_and_advance_epoch() {
        let e1 = EpochId::FIRST;
        let e2 = e1.next().unwrap();
        let e3 = e2.next().unwrap();
        let w1 = WorldId::random();
        let w2 = WorldId::random();
        let s1 = SlotId::new("slot-1").unwrap();
        let s2 = SlotId::new("slot-2").unwrap();

        let reg = EpochFenceRegistry::new(e1);
        let k1 = BindingKey::new(s1.clone(), w1, e1);
        let b1 = reg.register(k1.clone(), CapabilityPolicy::deny_all()).unwrap();
        assert!(!b1.is_revoked());
        assert_eq!(reg.active_binding_count(), 1);

        // Duplicate slot registration is rejected (same world or different world).
        assert!(matches!(
            reg.register(k1.clone(), CapabilityPolicy::deny_all()),
            Err(GwError::DuplicateSlot { .. })
        ));
        assert!(matches!(
            reg.register(BindingKey::new(s1.clone(), w2, e1), CapabilityPolicy::deny_all()),
            Err(GwError::DuplicateSlot { .. })
        ));

        // Future epoch registration is rejected.
        assert!(matches!(
            reg.register(BindingKey::new(s2.clone(), w2, e2), CapabilityPolicy::deny_all()),
            Err(GwError::FutureEpoch { .. })
        ));

        // Lookup verifies full triple (wrong world_id fails).
        assert!(reg.lookup(&k1).is_ok());
        assert!(matches!(
            reg.lookup(&BindingKey::new(s1.clone(), w2, e1)),
            Err(GwError::BindingNotFound { .. })
        ));

        // Advance epoch e1 -> e2 immediately revokes & cancels b1.
        let report = reg.advance_epoch(e2).unwrap();
        assert_eq!(report.previous_epoch, e1);
        assert_eq!(report.current_epoch, e2);
        assert_eq!(report.revoked_bindings, 1);
        assert!(b1.is_revoked());
        assert_eq!(reg.active_binding_count(), 0);

        // Lookup and registration for stale epoch e1 are rejected.
        assert!(matches!(reg.lookup(&k1), Err(GwError::StaleEpoch { .. })));
        assert!(matches!(
            reg.register(k1, CapabilityPolicy::deny_all()),
            Err(GwError::StaleEpoch { .. })
        ));

        // Regression e2 -> e1 is rejected.
        assert!(matches!(
            reg.advance_epoch(e1),
            Err(GwError::EpochRegression { .. })
        ));

        // Idempotent advance to same epoch e2 succeeds without dropping e2 bindings.
        let k2 = BindingKey::new(s1.clone(), w2, e2);
        let b2 = reg.register(k2.clone(), CapabilityPolicy::deny_all()).unwrap();
        let idem = reg.advance_epoch(e2).unwrap();
        assert_eq!(idem.revoked_bindings, 0);
        assert!(!b2.is_revoked());
        assert!(reg.lookup(&k2).is_ok());

        // Advancing to e3 drops b2.
        let report3 = reg.advance_epoch(e3).unwrap();
        assert_eq!(report3.revoked_bindings, 1);
        assert!(b2.is_revoked());
    }
}
