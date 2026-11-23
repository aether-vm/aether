//! Forkloom metadata engine (`aos-meta`): the `redb` single-writer **unique commit point** and
//! **rollback-only** crash recovery (ARCHITECTURE_V2 §4, §7.2, §7.3).
//!
//! | module | purpose |
//! | --- | --- |
//! | [`model`] | `PoolId`, `FencingToken`, managed object naming, frame / world state machines, holds, labels |
//! | [`config`] | `MetaConfig` (`meta_dir` outside the pool), injectable `Clock` |
//! | [`hooks`] | `RecoveryHooks` (gateway fence, cgroup kill, object destruction) + `FsArtifactBackend` |
//! | `pool` | R0: pool lock, `POOL_UUID` pairing, empty-database protection, same-filesystem guard |
//! | [`recovery`] | `MetaEngine::open_and_recover`: R1 epoch/boot/pins, R2 fencing, R3~R5 rollback, R6 quarantine |
//! | [`store`] | `Preparing -> Committed` (T1/T2) with typed durability proofs, timelines, delete, GC |
//! | [`lease`] | world leases (memory, monotonic), fencing tokens, label selectors, pin leases |
//! | `idempotency` | `(owner, request_id)` + SHA-256 request digest, written in the effect's transaction |
//!
//! Invariants:
//! * **I1** a frame is recorded as `Preparing` (durably) before any of its objects exist;
//! * **I2** durable frames commit only with `Persisted` proofs at the canonical pool paths;
//!   volatile memory images only with `Ephemeral` proofs of the current boot;
//! * **I3** `Committed` is reached in exactly one `Durability::Immediate` transaction;
//! * **I4** recovery destroys every non-committed frame; nothing is ever rolled forward.

#![forbid(unsafe_code)]

pub mod config;
mod digest;
pub mod error;
pub mod hooks;
mod idempotency;
pub mod lease;
pub mod model;
mod pool;
pub mod recovery;
pub mod store;
mod tables;

pub use config::{Clock, ManualClock, MetaConfig, SystemClock};
pub use error::{MetaError, Result};
pub use hooks::{FsArtifactBackend, RecoveryHooks};
pub use lease::{CreateWorldRequest, PinRenewal};
pub use model::{
    DeleteReason, FencingToken, FrameDurability, FrameRecord, FrameState, Hold, IdempotencyKey,
    Labels, ManagedObject, ObjectKind, ObjectLocation, PinSpec, PoolId, QuarantineRecord,
    WorldEndReason, WorldRecord, WorldState,
};
pub use recovery::RecoverySummary;
pub use store::{
    CommitFrameRequest, CommitProofBundle, CommittedFrame, DeleteOutcome, GcReport, MetaEngine,
    ObjectProof, PrepareFrameRequest, PreparedFrame, TimelineAdvance, TimelineTarget, WorldFence,
};
