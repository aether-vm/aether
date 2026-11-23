//! Explicit lifecycle state machine for `aos-guest`.
//!
//! Enforces strict linear capture & post-fork reseed ordering per
//! `docs/ARCHITECTURE_V2.md` §5.1 and §5.2:
//!
//! ```text
//! Ready ──begin_freeze──▶ Freezing ──complete_freeze──▶ Frozen { disk_clean }
//!   ▲                         │                                 │
//!   │                         └─abort_freeze (rollback ok)──┐   │ begin_reseed
//!   │                                                       ▼   ▼
//!   └───────────────complete_reseed──────────────────── Reseeding
//!                                                           │
//!             (unrecoverable rollback failure) ─────────▶ Faulted
//! ```

#![forbid(unsafe_code)]

use thiserror::Error;

use crate::protocol::{AgentState, ErrorCode};

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StateError {
    #[error("agent is frozen; operation requires Ready state")]
    AgentFrozen,
    #[error("agent is in terminal Faulted state")]
    AgentFaulted,
    #[error("invalid state transition from {from:?} for action '{action}'")]
    InvalidTransition {
        from: AgentState,
        action: &'static str,
    },
}

impl StateError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::AgentFrozen => ErrorCode::AgentFrozen,
            Self::AgentFaulted => ErrorCode::AgentFaulted,
            Self::InvalidTransition { .. } => ErrorCode::InvalidStateTransition,
        }
    }
}

/// Deterministic state machine tracking agent lifecycle and post-fork generation.
#[derive(Debug, Clone)]
pub struct AgentStateMachine {
    state: AgentState,
    epoch_generation: u64,
}

impl Default for AgentStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentStateMachine {
    pub fn new() -> Self {
        Self {
            state: AgentState::Ready,
            epoch_generation: 0,
        }
    }

    pub fn state(&self) -> AgentState {
        self.state
    }

    pub fn epoch_generation(&self) -> u64 {
        self.epoch_generation
    }

    /// Ensure `Exec` is permitted in the current state (`Ready` only).
    pub fn ensure_exec_allowed(&self) -> Result<(), StateError> {
        match self.state {
            AgentState::Ready => Ok(()),
            AgentState::Frozen { .. } => Err(StateError::AgentFrozen),
            AgentState::Faulted => Err(StateError::AgentFaulted),
            other => Err(StateError::InvalidTransition {
                from: other,
                action: "exec",
            }),
        }
    }

    /// Begin `FreezeAndSync`: `Ready -> Freezing`.
    pub fn begin_freeze(&mut self) -> Result<(), StateError> {
        match self.state {
            AgentState::Ready => {
                self.state = AgentState::Freezing;
                Ok(())
            }
            AgentState::Faulted => Err(StateError::AgentFaulted),
            other => Err(StateError::InvalidTransition {
                from: other,
                action: "freeze_and_sync",
            }),
        }
    }

    /// Finish `FreezeAndSync`: `Freezing -> Frozen { disk_clean }`.
    pub fn complete_freeze(&mut self, disk_clean: bool) -> Result<(), StateError> {
        match self.state {
            AgentState::Freezing => {
                self.state = AgentState::Frozen { disk_clean };
                Ok(())
            }
            other => Err(StateError::InvalidTransition {
                from: other,
                action: "complete_freeze",
            }),
        }
    }

    /// Roll back a failed `FreezeAndSync`:
    /// - If `rollback_unfrozen == true`, returns to `Ready`.
    /// - If `rollback_unfrozen == false`, transitions to `Faulted` so host knows
    ///   workload state is indeterminate and must destroy the VM.
    pub fn abort_freeze(&mut self, rollback_unfrozen: bool) {
        if rollback_unfrozen {
            self.state = AgentState::Ready;
        } else {
            self.state = AgentState::Faulted;
        }
    }

    /// Begin `PostForkReseed`: `Frozen -> Reseeding`.
    pub fn begin_reseed(&mut self) -> Result<bool, StateError> {
        match self.state {
            AgentState::Frozen { disk_clean } => {
                self.state = AgentState::Reseeding;
                Ok(disk_clean)
            }
            AgentState::Faulted => Err(StateError::AgentFaulted),
            other => Err(StateError::InvalidTransition {
                from: other,
                action: "post_fork_reseed",
            }),
        }
    }

    /// Complete `PostForkReseed`: `Reseeding -> Ready`, incrementing `epoch_generation`.
    pub fn complete_reseed(&mut self) -> Result<u64, StateError> {
        match self.state {
            AgentState::Reseeding => {
                self.epoch_generation = self.epoch_generation.saturating_add(1);
                self.state = AgentState::Ready;
                Ok(self.epoch_generation)
            }
            other => Err(StateError::InvalidTransition {
                from: other,
                action: "complete_reseed",
            }),
        }
    }

    /// Revert a failed `PostForkReseed` before unfreeze back to `Frozen { disk_clean }`,
    /// or to `Faulted` if unfreeze itself failed mid-way.
    pub fn abort_reseed(&mut self, still_cleanly_frozen: Option<bool>) {
        match still_cleanly_frozen {
            Some(disk_clean) => self.state = AgentState::Frozen { disk_clean },
            None => self.state = AgentState::Faulted,
        }
    }
}
