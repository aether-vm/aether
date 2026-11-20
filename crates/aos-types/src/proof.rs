//! Durability / liveness proofs.
//!
//! * [`PersistProof`] can only be obtained by *actually* calling `fsync` on a file and its parent
//!   directory ([`PersistProof::fsync_file_and_parent`]), on a directory
//!   ([`PersistProof::fsync_dir`]) or on a subvolume root and its parent
//!   ([`PersistProof::fsync_subvolume`]). It has no public constructor and no `Default`/`Clone`.
//!   Symlinks are never followed, and the proof remembers the identity of what it synced so
//!   [`PersistProof::verify_unchanged`] can detect later deletion / replacement / resizing.
//! * [`Persisted<T>`] pairs a value with such a proof.
//! * [`Ephemeral<T>`] binds a value to the current kernel [`BootId`]; access after a reboot
//!   yields [`ProofError::StaleBoot`]. The only escape hatch is
//!   [`Ephemeral::into_inner_for_cleanup`], intended for garbage collection of stale state.

use std::fs::{File, Metadata};
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
    /// The root directory of a (Btrfs) subvolume and its parent directory entry.
    Subvolume,
}

/// Identity of the synced object, re-checked by [`PersistProof::verify_unchanged`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    is_dir: bool,
    /// File length (`0` for directories, whose size is not meaningful).
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl Fingerprint {
    fn of(md: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            is_dir: md.is_dir(),
            len: if md.is_dir() { 0 } else { md.len() },
            #[cfg(unix)]
            dev: md.dev(),
            #[cfg(unix)]
            ino: md.ino(),
        }
    }
}

/// Evidence that a path has been `fsync`ed. Cannot be forged outside this module.
#[derive(Debug)]
#[must_use = "a PersistProof should be attached to the value it proves durable"]
pub struct PersistProof {
    kind: ProofKind,
    path: PathBuf,
    fingerprint: Fingerprint,
}

impl PersistProof {
    /// `fsync` the file at `path`, then `fsync` its parent directory so the directory entry
    /// itself is durable. `path` must not be a symlink.
    ///
    /// On Unix this is `fsync(file)` + `fsync(parent_dir)` through read-only `O_NOFOLLOW`
    /// descriptors, so sealed read-only (`0444`) artifacts can be proven without write
    /// permission. On non-Unix development hosts (Windows) the file is flushed through a write
    /// handle (required by `FlushFileBuffers`) and the parent directory is only checked to
    /// exist; the directory entry is **not** proven durable there.
    pub fn fsync_file_and_parent(path: &Path) -> io::Result<Self> {
        let before = lstat_no_symlink(path)?;
        if !before.is_file() {
            return Err(not_a("regular file", path));
        }
        let file = open_file_for_sync(path)?;
        let fingerprint = check_same_object(path, &before, &file.metadata()?)?;
        file.sync_all()?;
        sync_dir_handle(parent_of(path))?;
        Ok(Self {
            kind: ProofKind::FileAndParent,
            path: path.to_path_buf(),
            fingerprint,
        })
    }

    /// `fsync` the directory at `path` (which must not be a symlink).
    pub fn fsync_dir(path: &Path) -> io::Result<Self> {
        Ok(Self {
            kind: ProofKind::Dir,
            path: path.to_path_buf(),
            fingerprint: sync_dir_no_follow(path)?,
        })
    }

    /// `fsync` a subvolume root directory, then its parent directory so the subvolume's entry
    /// is durable. Whether `path` really is a Btrfs subvolume is the storage layer's contract;
    /// the distinct [`ProofKind::Subvolume`] lets the metadata layer insist that tree objects
    /// were proven through this path.
    pub fn fsync_subvolume(path: &Path) -> io::Result<Self> {
        let fingerprint = sync_dir_no_follow(path)?;
        sync_dir_handle(parent_of(path))?;
        Ok(Self {
            kind: ProofKind::Subvolume,
            path: path.to_path_buf(),
            fingerprint,
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

    /// Re-check that `path` still names the object that was synced: it exists, is not a
    /// symlink, has the same type, the same size (files) and, on Unix, the same `(dev, ino)`.
    ///
    /// Call this right before relying on the proof (e.g. at commit time).
    pub fn verify_unchanged(&self) -> io::Result<()> {
        let md = lstat_no_symlink(&self.path)?;
        let now = Fingerprint::of(&md);
        if now != self.fingerprint {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{} changed since it was proven durable ({:?} -> {:?})",
                    self.path.display(),
                    self.fingerprint,
                    now
                ),
            ));
        }
        Ok(())
    }
}

fn not_a(kind: &str, path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a {kind}", path.display()),
    )
}

fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// `lstat` that refuses symlinks.
fn lstat_no_symlink(path: &Path) -> io::Result<Metadata> {
    let md = std::fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symlink; proofs never follow symlinks", path.display()),
        ));
    }
    Ok(md)
}

/// Ensure the opened handle refers to the object `lstat` saw (closes the swap-in-a-symlink /
/// rename race between the check and the open).
fn check_same_object(path: &Path, before: &Metadata, opened: &Metadata) -> io::Result<Fingerprint> {
    let (a, b) = (Fingerprint::of(before), Fingerprint::of(opened));
    if a != b {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} was replaced while being proven", path.display()),
        ));
    }
    Ok(b)
}

/// Open without following a final symlink component.
#[cfg(unix)]
fn open_no_follow(path: &Path, directory: bool) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut flags = libc::O_NOFOLLOW;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
}

/// Open a regular file in a mode that permits `sync_all`.
#[cfg(unix)]
fn open_file_for_sync(path: &Path) -> io::Result<File> {
    open_no_follow(path, false)
}

/// Open a regular file in a mode that permits `sync_all`.
///
/// Windows `FlushFileBuffers` fails with `ERROR_ACCESS_DENIED` on a read-only handle, so the
/// file is opened for write (without truncation). The caller has already verified via `lstat`
/// that the path is a regular file and not a symlink.
#[cfg(not(unix))]
fn open_file_for_sync(path: &Path) -> io::Result<File> {
    std::fs::OpenOptions::new().write(true).open(path)
}

/// `fsync` a directory that must not be a symlink, returning its fingerprint.
#[cfg(unix)]
fn sync_dir_no_follow(path: &Path) -> io::Result<Fingerprint> {
    let before = lstat_no_symlink(path)?;
    if !before.is_dir() {
        return Err(not_a("directory", path));
    }
    let dir = open_no_follow(path, true)?;
    let fp = check_same_object(path, &before, &dir.metadata()?)?;
    dir.sync_all()?;
    Ok(fp)
}

/// Non-Unix: directories cannot be flushed through `std`; existence, type and "not a symlink"
/// are verified (development hosts only).
#[cfg(not(unix))]
fn sync_dir_no_follow(path: &Path) -> io::Result<Fingerprint> {
    let md = lstat_no_symlink(path)?;
    if !md.is_dir() {
        return Err(not_a("directory", path));
    }
    Ok(Fingerprint::of(&md))
}

/// `fsync` a parent directory (path components may legitimately be symlinks here).
#[cfg(unix)]
fn sync_dir_handle(path: &Path) -> io::Result<()> {
    let dir = File::open(path)?;
    if !dir.metadata()?.is_dir() {
        return Err(not_a("directory", path));
    }
    dir.sync_all()
}

/// Non-Unix hosts cannot `FlushFileBuffers` a directory opened through `std`; only existence
/// and type are verified. Non-Unix hosts are development-only: the parent directory entry is
/// **not** proven durable there.
#[cfg(not(unix))]
fn sync_dir_handle(path: &Path) -> io::Result<()> {
    if !std::fs::metadata(path)?.is_dir() {
        return Err(not_a("directory", path));
    }
    Ok(())
}

/// Free-function form of [`PersistProof::fsync_file_and_parent`].
pub fn fsync_file_and_parent(path: &Path) -> io::Result<PersistProof> {
    PersistProof::fsync_file_and_parent(path)
}

/// Free-function form of [`PersistProof::fsync_dir`].
pub fn fsync_dir(path: &Path) -> io::Result<PersistProof> {
    PersistProof::fsync_dir(path)
}

/// Free-function form of [`PersistProof::fsync_subvolume`].
pub fn fsync_subvolume(path: &Path) -> io::Result<PersistProof> {
    PersistProof::fsync_subvolume(path)
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
    pub fn proof(&self) -> &PersistProof {
        &self.proof
    }

    /// Consume, returning the value and its proof.
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
        self.into_inner_at(&BootId::current()?)
    }

    /// Like [`Self::into_inner`] against an explicit "current" boot (e.g. the boot id sampled
    /// once at the start of crash recovery).
    pub fn into_inner_at(self, current: &BootId) -> Result<T, ProofError> {
        if *current == self.boot {
            Ok(self.value)
        } else {
            Err(ProofError::StaleBoot {
                recorded: self.boot,
                current: *current,
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
    }

    #[test]
    fn ephemeral_into_inner_at_checks_boot_but_cleanup_does_not() {
        let fake = BootId::parse(A).unwrap();
        let now = BootId::parse(B).unwrap();
        let stale = Ephemeral::new_for_boot(5u8, fake);
        match stale.into_inner_at(&now) {
            Err(ProofError::StaleBoot { recorded, current }) => {
                assert_eq!(recorded, fake);
                assert_eq!(current, now);
            }
            other => panic!("expected StaleBoot, got {other:?}"),
        }
        let live = Ephemeral::new_for_boot(6u8, now);
        assert_eq!(live.into_inner_at(&now).unwrap(), 6);
        let stale = Ephemeral::new_for_boot(5u8, fake);
        assert_eq!(stale.into_inner_for_cleanup(), 5);
    }

    #[test]
    fn subvolume_proof_has_its_own_kind_and_rejects_files() {
        let d = scratch_dir();
        let sv = d.join("f-x-subvol");
        std::fs::create_dir(&sv).unwrap();
        let proof = fsync_subvolume(&sv).unwrap();
        assert_eq!(proof.kind(), ProofKind::Subvolume);
        proof.verify_unchanged().unwrap();
        let f = d.join("plain");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(
            fsync_subvolume(&f).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn verify_unchanged_detects_resize_deletion_and_type_change() {
        let d = scratch_dir();
        let f = d.join("disk.img");
        std::fs::write(&f, b"0123").unwrap();
        let proof = fsync_file_and_parent(&f).unwrap();
        proof.verify_unchanged().unwrap();

        std::fs::write(&f, b"0123456789").unwrap();
        assert_eq!(
            proof.verify_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::remove_file(&f).unwrap();
        assert_eq!(
            proof.verify_unchanged().unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        std::fs::create_dir(&f).unwrap();
        assert_eq!(
            proof.verify_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_never_followed_and_swaps_are_detected() {
        use std::os::unix::fs::symlink;
        let d = scratch_dir();
        let target = d.join("real.img");
        std::fs::write(&target, b"data").unwrap();
        let target_dir = d.join("real-dir");
        std::fs::create_dir(&target_dir).unwrap();
        let link = d.join("link.img");
        let link_dir = d.join("link-dir");
        symlink(&target, &link).unwrap();
        symlink(&target_dir, &link_dir).unwrap();
        for r in [
            fsync_file_and_parent(&link),
            fsync_dir(&link_dir),
            fsync_subvolume(&link_dir),
        ] {
            assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }

        // Same size, different inode: replacement is detected.
        let proof = fsync_file_and_parent(&target).unwrap();
        let tmp = d.join("swap.tmp");
        std::fs::write(&tmp, b"evil").unwrap();
        std::fs::rename(&tmp, &target).unwrap();
        assert_eq!(
            proof.verify_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // Replaced by a symlink.
        std::fs::remove_file(&target).unwrap();
        symlink(d.join("elsewhere"), &target).unwrap();
        assert_eq!(
            proof.verify_unchanged().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fsync_file_and_parent_accepts_read_only_sealed_file() {
        let d = scratch_dir();
        let f = d.join("f-sealed-mem.img");
        std::fs::write(&f, b"sealed").unwrap();
        let mut perms = std::fs::metadata(&f).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&f, perms).unwrap();
        let proof = PersistProof::fsync_file_and_parent(&f).unwrap();
        assert_eq!(proof.kind(), ProofKind::FileAndParent);
        assert_eq!(std::fs::read(&f).unwrap(), b"sealed", "proof must not modify the file");
        std::fs::remove_dir_all(d).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ephemeral_real_boot_checks_via_proc() {
        let fake = BootId::parse(A).unwrap();
        // the real current boot is certainly not the fake one
        let stale = Ephemeral::new_for_boot(vec![1, 2, 3], fake);
        assert!(matches!(stale.get(), Err(ProofError::StaleBoot { .. })));
        assert!(matches!(stale.into_inner(), Err(ProofError::StaleBoot { .. })));

        let e = Ephemeral::new("x").unwrap();
        assert_eq!(e.boot_id(), BootId::current().unwrap());
        assert_eq!(*e.get().unwrap(), "x");
        assert_eq!(e.into_inner().unwrap(), "x");
    }
}
