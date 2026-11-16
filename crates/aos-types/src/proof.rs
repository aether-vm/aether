//! Durability / liveness proofs.
//!
//! * [`PersistProof`] can only be obtained by *actually* calling `fsync` on a file and its parent
//!   directory ([`PersistProof::fsync_file_and_parent`]) or on a directory
//!   ([`PersistProof::fsync_dir`]). It has no public constructor and no `Default`/`Clone`.
//! * [`Persisted<T>`] pairs a value with such a proof.
//! * [`Ephemeral<T>`] binds a value to the current kernel [`BootId`]; access after a reboot
//!   yields [`ProofError::StaleBoot`]. The only escape hatch is
//!   [`Ephemeral::into_inner_for_cleanup`], intended for garbage collection of stale state.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::boot::{BootId, BootIdError};

/// What was fsynced to produce a [`PersistProof`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// A regular file and its parent directory entry.
    FileAndParent,
    /// A directory.
    Dir,
}

/// Evidence that a path has been `fsync`ed. Cannot be forged outside this module.
#[derive(Debug)]
#[must_use = "a PersistProof should be attached to the value it proves durable"]
pub struct PersistProof {
    kind: ProofKind,
    path: PathBuf,
}

impl PersistProof {
    /// `fsync` the file at `path`, then `fsync` its parent directory so the directory entry
    /// itself is durable.
    pub fn fsync_file_and_parent(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a regular file", path.display()),
            ));
        }
        file.sync_all()?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent)?.sync_all()?;
        Ok(Self {
            kind: ProofKind::FileAndParent,
            path: path.to_path_buf(),
        })
    }

    /// `fsync` the directory at `path`.
    pub fn fsync_dir(path: &Path) -> io::Result<Self> {
        let dir = File::open(path)?;
        if !dir.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a directory", path.display()),
            ));
        }
        dir.sync_all()?;
        Ok(Self {
            kind: ProofKind::Dir,
            path: path.to_path_buf(),
        })
    }

    /// What was synced.
    #[must_use]
    pub fn kind(&self) -> ProofKind {
        self.kind
    }

    /// Path that was synced.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Free-function form of [`PersistProof::fsync_file_and_parent`].
pub fn fsync_file_and_parent(path: &Path) -> io::Result<PersistProof> {
    PersistProof::fsync_file_and_parent(path)
}

/// Free-function form of [`PersistProof::fsync_dir`].
pub fn fsync_dir(path: &Path) -> io::Result<PersistProof> {
    PersistProof::fsync_dir(path)
}

/// A value that is backed by durable (fsynced) storage.
#[derive(Debug)]
pub struct Persisted<T> {
    value: T,
    proof: PersistProof,
}

impl<T> Persisted<T> {
    /// Attach a proof to a value.
    pub fn new(value: T, proof: PersistProof) -> Self {
        Self { value, proof }
    }

    /// Borrow the value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The proof of durability.
    #[must_use]
    pub fn proof(&self) -> &PersistProof {
        &self.proof
    }

    /// Consume, returning the value and its proof.
    #[must_use]
    pub fn into_parts(self) -> (T, PersistProof) {
        (self.value, self.proof)
    }

    /// Consume, returning the value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Errors accessing an [`Ephemeral`] value.
#[derive(Debug, Error)]
pub enum ProofError {
    /// The value was created during a previous kernel boot and must not be trusted.
    #[error("stale boot: value belongs to boot {recorded}, current boot is {current}")]
    StaleBoot {
        /// Boot the value was created in.
        recorded: BootId,
        /// Boot we are running in now.
        current: BootId,
    },
    /// The current boot id could not be determined.
    #[error(transparent)]
    Boot(#[from] BootIdError),
}

/// A value valid only for the kernel boot it was created in (e.g. a tmpfs-backed volatile frame).
#[derive(Debug)]
pub struct Ephemeral<T> {
    value: T,
    boot: BootId,
}

impl<T> Ephemeral<T> {
    /// Bind `value` to the current boot.
    pub fn new(value: T) -> Result<Self, BootIdError> {
        Ok(Self {
            value,
            boot: BootId::current()?,
        })
    }

    /// Bind `value` to an explicit boot (used when loading records persisted by an earlier run).
    pub fn new_for_boot(value: T, boot: BootId) -> Self {
        Self { value, boot }
    }

    /// The boot this value belongs to.
    #[must_use]
    pub fn boot_id(&self) -> BootId {
        self.boot
    }

    /// Borrow the value iff the current boot matches.
    pub fn get(&self) -> Result<&T, ProofError> {
        self.get_at(&BootId::current()?)
    }

    /// Like [`Self::get`] against an explicit "current" boot.
    pub fn get_at(&self, current: &BootId) -> Result<&T, ProofError> {
        if *current == self.boot {
            Ok(&self.value)
        } else {
            Err(ProofError::StaleBoot {
                recorded: self.boot,
                current: *current,
            })
        }
    }

    /// Consume the wrapper iff the current boot matches.
    pub fn into_inner(self) -> Result<T, ProofError> {
        let current = BootId::current()?;
        if current == self.boot {
            Ok(self.value)
        } else {
            Err(ProofError::StaleBoot {
                recorded: self.boot,
                current,
            })
        }
    }

    /// Consume the wrapper **without** checking the boot id.
    ///
    /// Only for garbage collection / quarantine of stale state: the returned value must never
    /// be treated as live.
    #[must_use]
    pub fn into_inner_for_cleanup(self) -> T {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    fn scratch_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "aos-types-proof-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const A: &str = "11111111-1111-1111-1111-111111111111";
    const B: &str = "22222222-2222-2222-2222-222222222222";

    #[test]
    fn fsync_file_and_parent_produces_proof() {
        let d = scratch_dir();
        let f = d.join("wal.bin");
        std::fs::write(&f, b"hello").unwrap();
        let proof = PersistProof::fsync_file_and_parent(&f).unwrap();
        assert_eq!(proof.kind(), ProofKind::FileAndParent);
        assert_eq!(proof.path(), f.as_path());
        let p = Persisted::new(7u32, proof);
        assert_eq!(*p.value(), 7);
        assert_eq!(p.proof().kind(), ProofKind::FileAndParent);
        let (v, _proof) = p.into_parts();
        assert_eq!(v, 7);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn fsync_dir_produces_proof_and_rejects_files() {
        let d = scratch_dir();
        let proof = fsync_dir(&d).unwrap();
        assert_eq!(proof.kind(), ProofKind::Dir);
        let f = d.join("f");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(
            PersistProof::fsync_dir(&f).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            PersistProof::fsync_file_and_parent(&d).unwrap_err().kind(),
            io::ErrorKind::InvalidInput,
            "a directory is not a valid 'file' proof"
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn no_proof_for_missing_paths() {
        let d = scratch_dir();
        assert_eq!(
            PersistProof::fsync_file_and_parent(&d.join("nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            fsync_dir(&d.join("nope")).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn ephemeral_same_boot_ok() {
        let boot = BootId::parse(A).unwrap();
        let e = Ephemeral::new_for_boot(String::from("frame"), boot);
        assert_eq!(e.boot_id(), boot);
        assert_eq!(e.get_at(&boot).unwrap(), "frame");
    }

    #[test]
    fn ephemeral_cross_boot_is_stale() {
        let old = BootId::parse(A).unwrap();
        let now = BootId::parse(B).unwrap();
        let e = Ephemeral::new_for_boot(vec![1, 2, 3], old);
        match e.get_at(&now) {
            Err(ProofError::StaleBoot { recorded, current }) => {
                assert_eq!(recorded, old);
                assert_eq!(current, now);
            }
            other => panic!("expected StaleBoot, got {other:?}"),
        }
        // real current boot is certainly not the fake "old" boot
        assert!(matches!(e.get(), Err(ProofError::StaleBoot { .. })));
    }

    #[test]
    fn ephemeral_into_inner_checks_boot_but_cleanup_does_not() {
        let fake = BootId::parse(A).unwrap();
        let stale = Ephemeral::new_for_boot(5u8, fake);
        assert!(matches!(stale.into_inner(), Err(ProofError::StaleBoot { .. })));
        let stale = Ephemeral::new_for_boot(5u8, fake);
        assert_eq!(stale.into_inner_for_cleanup(), 5);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ephemeral_new_binds_to_real_current_boot() {
        let e = Ephemeral::new("x").unwrap();
        assert_eq!(e.boot_id(), BootId::current().unwrap());
        assert_eq!(*e.get().unwrap(), "x");
        assert_eq!(e.into_inner().unwrap(), "x");
    }
}
