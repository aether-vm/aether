//! Side-effect hooks driven by recovery and garbage collection.

use std::io;
use std::path::{Path, PathBuf};

use aos_types::EpochId;

use crate::model::ManagedObject;

/// Physical side effects the metadata engine needs but does not own.
///
/// `NotFound` from any `destroy_*` / `purge_*` method is treated as success (deletion is
/// idempotent across crashes); any other error aborts the current step and leaves the
/// metadata in a state from which the step is retried.
pub trait RecoveryHooks: Send {
    /// R2: tell `aos-gw` to revoke every `(slot, world, epoch)` binding older than `epoch`.
    /// Must not return `Ok` before the gateway has acknowledged.
    fn fence_gateway(&mut self, epoch: EpochId) -> io::Result<()>;

    /// R2: `cgroup.kill` every `epoch-<n>` cgroup with `n < current`.
    fn kill_stale_epochs(&mut self, current: EpochId) -> io::Result<()>;

    /// Destroy a pool object located at `path` (`pool_root/objects/<name>`).
    fn destroy_pool_object(&mut self, path: &Path, object: &ManagedObject) -> io::Result<()>;

    /// Destroy a volatile (tmpfs) object.
    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()>;

    /// Physically purge a quarantined entry whose grace period has elapsed.
    fn purge_quarantined(&mut self, path: &Path) -> io::Result<()> {
        remove_path(path)
    }
}

/// Remove a file or directory tree without following symlinks.
pub fn remove_path(path: &Path) -> io::Result<()> {
    let md = std::fs::symlink_metadata(path)?;
    if md.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Plain filesystem implementation (local development and tests): objects are ordinary files
/// / directories, gateway fencing and cgroup killing are no-ops.
#[derive(Debug, Clone)]
pub struct FsArtifactBackend {
    volatile_root: PathBuf,
}

impl FsArtifactBackend {
    /// `volatile_root` is the tmpfs directory holding volatile memory images.
    pub fn new(volatile_root: impl Into<PathBuf>) -> Self {
        Self {
            volatile_root: volatile_root.into(),
        }
    }

    /// Path of a volatile object.
    #[must_use]
    pub fn volatile_path(&self, object: &ManagedObject) -> PathBuf {
        self.volatile_root.join(object.name())
    }
}

impl RecoveryHooks for FsArtifactBackend {
    fn fence_gateway(&mut self, _epoch: EpochId) -> io::Result<()> {
        Ok(())
    }

    fn kill_stale_epochs(&mut self, _current: EpochId) -> io::Result<()> {
        Ok(())
    }

    fn destroy_pool_object(&mut self, path: &Path, _object: &ManagedObject) -> io::Result<()> {
        remove_path(path)
    }

    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()> {
        remove_path(&self.volatile_path(object))
    }
}

pub(crate) fn ignore_not_found(r: io::Result<()>) -> io::Result<()> {
    match r {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}
