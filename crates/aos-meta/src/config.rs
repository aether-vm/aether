//! Engine configuration and injectable clocks.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// File name of the metadata database inside `meta_dir`.
pub const DB_FILE_NAME: &str = "forkloom.redb";
/// Pool identity file inside `pool_root`.
pub const POOL_UUID_FILE: &str = "POOL_UUID";
/// Process lock file inside `pool_root`.
pub const LOCK_FILE: &str = ".lock";
/// Managed object directory inside `pool_root`.
pub const OBJECTS_DIR: &str = "objects";
/// Quarantine directory inside `pool_root`.
pub const QUARANTINE_DIR: &str = "quarantine";

const DAY_MS: u64 = 24 * 3600 * 1000;

/// Engine configuration.
///
/// `meta_dir` (holding `forkloom.redb`) must live on a host `ext4`/`XFS` filesystem **outside**
/// the Btrfs pool at `pool_root` (`POOL_UUID`, `objects/`, `quarantine/`).
#[derive(Debug, Clone)]
pub struct MetaConfig {
    /// Directory holding `forkloom.redb`.
    pub meta_dir: PathBuf,
    /// Pool root.
    pub pool_root: PathBuf,
    /// Allow `meta_dir` and `pool_root` on one filesystem (unit tests only).
    pub allow_same_fs_for_testing: bool,
    /// R6 breaker: absolute orphan limit.
    pub max_orphan_count: usize,
    /// R6 breaker: orphan ratio limit (applied once the sample is large enough).
    pub max_orphan_ratio: f64,
    /// R6 breaker: minimum `objects/` population before the ratio rule applies. Below it the
    /// pool is "small" and `max_small_pool_orphans` is the limit instead.
    pub min_orphan_ratio_sample: usize,
    /// R6 breaker: orphan limit for small pools (`objects/` population below
    /// `min_orphan_ratio_sample`), where a ratio is meaningless.
    pub max_small_pool_orphans: usize,
    /// Grace period before quarantined orphans are purged. It runs on the wall clock and, for
    /// objects quarantined by this run, on the monotonic clock as well.
    pub quarantine_grace_ms: u64,
    /// Least uptime of this run before it purges quarantine it did not create itself (left by
    /// an earlier run, possibly days ago, or by a release without GC): the wall clock alone
    /// cannot be trusted across a restart.
    pub quarantine_min_uptime_ms: u64,
    /// How long destroyed / lost world tombstones stay queryable. Must be at least
    /// `idempotency_ttl_ms` so a replayed `create_world` / `destroy_world` finds its world.
    pub world_tombstone_ttl_ms: u64,
    /// How long idempotency records are kept.
    pub idempotency_ttl_ms: u64,
    /// Maximum interval between pin-lease flushes to `redb`.
    pub pin_flush_interval_ms: u64,
    /// Upper bound for a pin `lease_ttl_ms`.
    pub max_pin_ttl_ms: u64,
    /// Upper bound for a world `lease_ttl_ms`.
    pub max_world_lease_ttl_ms: u64,
}

impl MetaConfig {
    /// Production defaults for the given directories.
    pub fn new(meta_dir: impl Into<PathBuf>, pool_root: impl Into<PathBuf>) -> Self {
        Self {
            meta_dir: meta_dir.into(),
            pool_root: pool_root.into(),
            allow_same_fs_for_testing: false,
            max_orphan_count: 50,
            max_orphan_ratio: 0.10,
            min_orphan_ratio_sample: 20,
            max_small_pool_orphans: 2,
            quarantine_grace_ms: DAY_MS,
            quarantine_min_uptime_ms: 60 * 60 * 1000,
            world_tombstone_ttl_ms: DAY_MS,
            idempotency_ttl_ms: DAY_MS,
            pin_flush_interval_ms: 60 * 1000,
            max_pin_ttl_ms: 7 * DAY_MS,
            max_world_lease_ttl_ms: DAY_MS,
        }
    }

    /// `meta_dir/forkloom.redb`.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.meta_dir.join(DB_FILE_NAME)
    }

    /// `pool_root/objects`.
    #[must_use]
    pub fn objects_dir(&self) -> PathBuf {
        self.pool_root.join(OBJECTS_DIR)
    }

    /// `pool_root/quarantine`.
    #[must_use]
    pub fn quarantine_dir(&self) -> PathBuf {
        self.pool_root.join(QUARANTINE_DIR)
    }
}

/// Source of wall-clock (persisted timestamps) and monotonic (in-memory leases) time.
pub trait Clock: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
    /// Monotonic instant.
    fn now_instant(&self) -> Instant;
}

/// The real clocks.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn now_instant(&self) -> Instant {
        Instant::now()
    }
}

/// Manually driven clock for deterministic tests ([`Self::advance`] moves wall and monotonic
/// time together, [`Self::jump_wall`] only the wall clock).
#[derive(Debug)]
pub struct ManualClock {
    base: Instant,
    state: Mutex<(u64, Duration)>,
}

impl ManualClock {
    /// Start at `wall_ms`.
    #[must_use]
    pub fn new(wall_ms: u64) -> Self {
        Self {
            base: Instant::now(),
            state: Mutex::new((wall_ms, Duration::ZERO)),
        }
    }

    /// Advance both clocks.
    pub fn advance(&self, ms: u64) {
        let mut s = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        s.0 = s.0.saturating_add(ms);
        s.1 = s.1.saturating_add(Duration::from_millis(ms));
    }

    /// Step only the wall clock (NTP correction / manual `date -s`); monotonic time is unchanged.
    pub fn jump_wall(&self, ms: u64) {
        let mut s = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        s.0 = s.0.saturating_add(ms);
    }

    /// Step only the wall clock backward (or set it to an arbitrary timestamp); monotonic time is
    /// unchanged.
    pub fn set_wall(&self, wall_ms: u64) {
        let mut s = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        s.0 = wall_ms;
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).0
    }

    fn now_instant(&self) -> Instant {
        self.base + self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).1
    }
}
