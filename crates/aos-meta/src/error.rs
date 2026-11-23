//! Error type of the metadata engine.

use std::io;
use std::path::PathBuf;

use aos_types::{BootId, FrameId, WorldId};
use thiserror::Error;

use crate::model::{FencingToken, PoolId};

/// Result alias for this crate.
pub type Result<T, E = MetaError> = std::result::Result<T, E>;

/// Every failure the metadata engine can report.
#[derive(Debug, Error)]
pub enum MetaError {
    // ---------------------------------------------------------------- configuration / R0
    /// `meta_dir` and `pool_root` live on the same filesystem (Linux `st_dev` equal).
    #[error(
        "meta_dir {meta_dir} and pool_root {pool_root} are on the same filesystem; \
         forkloom.redb must live outside the pool (set allow_same_fs_for_testing only in tests)"
    )]
    SameFilesystemForbidden {
        /// Configured metadata directory.
        meta_dir: PathBuf,
        /// Configured pool root.
        pool_root: PathBuf,
    },
    /// Another process holds `pool_root/.lock`.
    #[error("pool is locked by another agentd instance: {path}")]
    PoolLocked {
        /// Lock file path.
        path: PathBuf,
    },
    /// `objects/` is non-empty but the metadata database is missing or unreadable.
    #[error(
        "refusing to start: {object_count} object(s) in pool but metadata {db_path} is missing \
         or unreadable ({reason}); never re-initialising an empty database over a live pool"
    )]
    MissingMetaForNonEmptyPool {
        /// Database path.
        db_path: PathBuf,
        /// Entries found in `objects/`.
        object_count: usize,
        /// Why the database could not be used.
        reason: String,
    },
    /// The metadata database exists but cannot be opened (pool is empty, still refused).
    #[error("metadata database {db_path} exists but is unreadable: {reason}")]
    MetaUnreadable {
        /// Database path.
        db_path: PathBuf,
        /// Underlying reason.
        reason: String,
    },
    /// `pool_root/POOL_UUID` and the database disagree (or one side is missing).
    #[error("POOL_UUID mismatch: pool says {pool:?}, metadata says {meta:?}")]
    PoolUuidMismatch {
        /// Content of `pool_root/POOL_UUID`.
        pool: Option<PoolId>,
        /// Value recorded in the database.
        meta: Option<PoolId>,
    },
    /// The database carries no (or an unknown) schema version.
    #[error("metadata schema {found:?} is not supported (expected {supported})")]
    UnsupportedSchema {
        /// Recorded schema version.
        found: Option<u32>,
        /// Version this build understands.
        supported: u32,
    },
    /// `POOL_UUID` content is not a canonical pool id.
    #[error("malformed POOL_UUID {0:?}")]
    MalformedPoolUuid(String),
    /// `daemon_epoch` would overflow `u64`.
    #[error("daemon epoch overflow")]
    EpochOverflow,
    /// A recovery / runtime hook failed.
    #[error("hook {stage} failed: {source}")]
    Hook {
        /// Which hook.
        stage: &'static str,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// R6 found too many orphans; nothing was moved or deleted.
    #[error(
        "orphan circuit breaker: {orphan_count} orphan(s) out of {total_objects} object(s); \
         refusing to start (was an old forkloom.redb backup restored?)"
    )]
    OrphanCircuitBreakerTriggered {
        /// Objects not referenced by any frame.
        orphan_count: usize,
        /// All entries in `objects/`.
        total_objects: usize,
    },
    /// R6 reverse check: a committed frame references a pool object that does not exist.
    #[error(
        "committed frame {frame_id} references missing pool object {object_name}; refusing to \
         start (pool and metadata diverged)"
    )]
    MissingCommittedObject {
        /// Frame.
        frame_id: FrameId,
        /// Missing `objects/` entry.
        object_name: String,
    },

    // ---------------------------------------------------------------- storage plumbing
    /// Filesystem error.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
    /// redb error (boxed: `redb::Error` would otherwise dominate the size of every `Result`).
    #[error("redb: {0}")]
    Db(Box<redb::Error>),
    /// A stored record could not be (de)serialized.
    #[error("record codec error: {0}")]
    Codec(String),

    // ---------------------------------------------------------------- frames / timelines
    /// No such frame.
    #[error("frame {0} not found")]
    FrameNotFound(FrameId),
    /// The frame is not in the state the operation requires.
    #[error("frame {frame} is {actual}, expected {expected}")]
    FrameWrongState {
        /// Frame.
        frame: FrameId,
        /// Required state.
        expected: &'static str,
        /// Observed state.
        actual: &'static str,
    },
    /// Replay of a `prepare_frame` whose frame was aborted or rolled back; use a new request id.
    #[error("prepared frame {0} was aborted; retry with a new idempotency key")]
    PreparedFrameAborted(FrameId),
    /// The frame has been requested for deletion; no new holds may be attached.
    #[error("frame {0} is marked for deletion")]
    FrameMarkedForDeletion(FrameId),
    /// A volatile frame belongs to another boot.
    #[error("frame {frame} is volatile for boot {recorded}, current boot is {current}")]
    StaleBoot {
        /// Frame.
        frame: FrameId,
        /// Boot it was created in.
        recorded: BootId,
        /// Current boot.
        current: BootId,
    },
    /// A timeline may only point at committed durable frames.
    #[error("frame {0} is volatile and must never become a timeline head")]
    VolatileInTimelineForbidden(FrameId),
    /// A durable child of a volatile parent must carry a full memory image.
    #[error("durable frame derived from volatile parent {parent} must promote the full memory image")]
    MemPromotionRequired {
        /// Volatile parent.
        parent: FrameId,
    },
    /// Commit proofs do not satisfy the durability contract (I2).
    #[error("commit proof rejected for frame {frame}: {reason}")]
    ProofRejected {
        /// Frame being committed.
        frame: FrameId,
        /// Why.
        reason: String,
    },
    /// Timeline compare-and-swap lost.
    #[error("timeline {timeline:?} CAS failed: expected {expected:?}, actual {actual:?}")]
    TimelineCasMismatch {
        /// Timeline name.
        timeline: String,
        /// Caller's expectation.
        expected: Option<FrameId>,
        /// Current head.
        actual: Option<FrameId>,
    },
    /// No such timeline.
    #[error("timeline {0:?} not found")]
    TimelineNotFound(String),
    /// No such pin.
    #[error("pin {pin_id:?} not found on frame {frame}")]
    PinNotFound {
        /// Frame.
        frame: FrameId,
        /// Pin id.
        pin_id: String,
    },

    // ---------------------------------------------------------------- worlds
    /// No such world.
    #[error("world {0} not found")]
    WorldNotFound(WorldId),
    /// The world is not running (destroyed, lost, or its lease is gone).
    #[error("world {0} is not running")]
    WorldNotRunning(WorldId),
    /// Fencing token is not the current one.
    #[error("world {world}: fenced out (presented token {presented}, current {current})")]
    FencedOut {
        /// World.
        world: WorldId,
        /// Token the caller sent.
        presented: FencingToken,
        /// Current token.
        current: FencingToken,
    },
    /// Batch selectors must not be empty.
    #[error("empty label selector is forbidden for batch operations")]
    EmptySelectorForbidden,

    // ---------------------------------------------------------------- authorization / input
    /// Caller does not own the resource.
    #[error("{resource} is not owned by {caller:?}")]
    OwnerMismatch {
        /// Resource description.
        resource: String,
        /// Caller.
        caller: String,
    },
    /// Invalid labels (count / length limits).
    #[error("invalid labels: {0}")]
    InvalidLabels(String),
    /// Any other malformed argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Same idempotency key reused for a different request.
    #[error("idempotency conflict for owner {owner:?} request {request_id:?}")]
    IdempotencyConflict {
        /// Key owner.
        owner: String,
        /// Request id.
        request_id: String,
    },
}

impl MetaError {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }
}

macro_rules! redb_from {
    ($($t:ty),*) => {$(
        impl From<$t> for MetaError {
            fn from(e: $t) -> Self {
                MetaError::Db(Box::new(redb::Error::from(e)))
            }
        }
    )*};
}
redb_from!(
    redb::Error,
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

impl From<serde_json::Error> for MetaError {
    fn from(e: serde_json::Error) -> Self {
        MetaError::Codec(e.to_string())
    }
}
