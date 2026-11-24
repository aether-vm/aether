//! Error types for `aos-store`.

use std::io;
use std::path::PathBuf;

use aos_types::PatchPathError;
use thiserror::Error;

/// Crate result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Errors returned by `TreeStore` and its storage primitives.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Pool root is on a forbidden path or filesystem (e.g. WSL2 `/mnt/*` or 9p/DrvFs).
    #[error("forbidden pool root {path}: {reason}")]
    ForbiddenPoolRoot {
        /// Offending path.
        path: PathBuf,
        /// Explanation.
        reason: String,
    },

    /// Pool root is not on a Btrfs filesystem (Linux guardrail).
    #[error("pool root {path} is not Btrfs (f_type=0x{fs_magic:x})")]
    NotBtrfs {
        /// Pool path.
        path: PathBuf,
        /// Observed `statfs::f_type`.
        fs_magic: u64,
    },

    /// Btrfs qgroups are enabled on the pool (forbidden by ARCHITECTURE_V2 §3.1).
    #[error("btrfs qgroups are enabled on pool {pool_root}: {detail}")]
    QgroupsEnabled {
        /// Pool root.
        pool_root: PathBuf,
        /// Diagnostic detail.
        detail: String,
    },

    /// Unable to verify qgroups state (fail closed).
    #[error("could not verify btrfs qgroups are disabled on {pool_root}: {detail}")]
    QgroupsCheckFailed {
        /// Pool root.
        pool_root: PathBuf,
        /// Diagnostic detail.
        detail: String,
    },

    /// Btrfs `autodefrag` mount option is active on the pool (forbidden by ARCHITECTURE_V2 §3.1).
    #[error("btrfs autodefrag mount option is enabled for {pool_root} (mount {mount_point})")]
    AutodefragEnabled {
        /// Pool root.
        pool_root: PathBuf,
        /// Matched mount point.
        mount_point: PathBuf,
    },

    /// Could not locate or validate the mount entry for `pool_root` in `/proc/self/mountinfo`.
    #[error("mountinfo guardrail check failed for {pool_root}: {detail}")]
    MountInfoCheckFailed {
        /// Pool root.
        pool_root: PathBuf,
        /// Diagnostic detail.
        detail: String,
    },

    /// Pool ran out of space (`ENOSPC`).
    #[error("no space left on pool during {operation} (ballast_released={ballast_released}): {source}")]
    NoSpace {
        /// Operation that hit `ENOSPC`.
        operation: String,
        /// Whether the emergency ballast file was released during handling.
        ballast_released: bool,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// Invalid subvolume or target name.
    #[error("invalid name {name:?}: {reason}")]
    InvalidName {
        /// Offending name.
        name: String,
        /// Reason.
        reason: String,
    },

    /// Path escapes or violates pool boundaries.
    #[error("path {path} is outside managed pool boundaries: {reason}")]
    OutsidePool {
        /// Offending path.
        path: PathBuf,
        /// Reason.
        reason: String,
    },

    /// Target subvolume or object already exists.
    #[error("subvolume already exists: {path}")]
    AlreadyExists {
        /// Existing path.
        path: PathBuf,
    },

    /// Requested subvolume or object was not found.
    #[error("subvolume not found: {path}")]
    NotFound {
        /// Missing path.
        path: PathBuf,
    },

    /// Operation required a sealed read-only subvolume.
    #[error("subvolume {path} must be sealed read-only")]
    NotReadOnly {
        /// Offending path.
        path: PathBuf,
    },

    /// Untrusted tar archive contained a rejected entry or exceeded resource limits.
    #[error("unsafe tar entry {path:?}: {reason}")]
    UnsafeTarEntry {
        /// Entry path (or archive context).
        path: String,
        /// Why it was rejected.
        reason: String,
    },

    /// Exported patch failed zero-trust `PatchPathValidator` checks.
    #[error("exported patch rejected by zero-trust path validator: {0}")]
    PatchValidation(#[from] PatchPathError),

    /// Error computing tree diff during `export_patch`.
    #[error("patch diff error at {path:?}: {reason}")]
    DiffError {
        /// Offending relative path.
        path: String,
        /// Reason.
        reason: String,
    },

    /// Generic I/O failure with context.
    #[error("{context}: {source}")]
    Io {
        /// Operation description.
        context: String,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
}

impl StoreError {
    pub(crate) fn io(context: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            context: context.into(),
            source,
        }
    }

    pub(crate) fn io_or_enospc(context: impl Into<String>, source: io::Error) -> Self {
        if is_enospc(&source) {
            Self::NoSpace {
                operation: context.into(),
                ballast_released: false,
                source,
            }
        } else {
            Self::Io {
                context: context.into(),
                source,
            }
        }
    }
}

/// Returns `true` if `err` represents `ENOSPC` (`ErrorKind::StorageFull` or raw errno `ENOSPC`).
#[must_use]
pub fn is_enospc(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::StorageFull {
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ENOSPC) {
        return true;
    }
    false
}
