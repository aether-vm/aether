//! `TreeStore`: Btrfs subvolume storage engine for Phase 1 Namespace cold forks.
//!
//! Layout under `pool_root` (e.g. `/var/lib/forkloom/pool`):
//! * `objects/` — canonical `aos_meta::ManagedObject` read-only subvolumes (`f-<frame>-subvol`);
//! * `worlds/` — writable O(1) Btrfs snapshots for live `World`s (kept outside `objects/` so
//!   `aos-meta`'s R6 orphan scanner only sees canonical frame artifacts);
//! * `quarantine/` — orphan quarantine directory (managed by `aos-meta`, purged via `destroy_subvolume`);
//! * `ballast` — pre-allocated emergency reserve file released on `ENOSPC` during reclamation.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use aos_meta::{ManagedObject, ObjectKind, RecoveryHooks};
use aos_types::{EpochId, FrameId, PersistProof, Persisted};

#[cfg(target_os = "linux")]
use crate::error::is_enospc;
use crate::error::{Result, StoreError};
use crate::kind::SubvolHandle;
use crate::patch::{ExportPatchOptions, PatchBundle, export_patch_between_roots};
use crate::safe_tar::{TarImportOptions, unpack_tar_safely};

/// Subdirectory holding canonical `aos_meta::ManagedObject` frame subvolumes.
pub const OBJECTS_DIR: &str = "objects";
/// Subdirectory holding writable clones for live `World` instances.
pub const WORLDS_DIR: &str = "worlds";
/// Subdirectory holding quarantined orphans (`aos-meta` R6).
pub const QUARANTINE_DIR: &str = "quarantine";
/// Pre-allocated emergency ballast file name at `pool_root/ballast`.
pub const BALLAST_FILE: &str = "ballast";
/// Production default ballast size: 2 GiB (ARCHITECTURE_V2 §3.1).
pub const DEFAULT_BALLAST_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Configuration for opening a [`TreeStore`].
#[derive(Debug, Clone)]
pub struct TreeStoreConfig {
    /// Pool root directory (must live on a Btrfs mount on Linux in production).
    pub pool_root: PathBuf,
    /// Size in bytes of the `pool_root/ballast` emergency file (`0` disables pre-allocation).
    pub ballast_bytes: u64,
    /// Allow opening on a non-Btrfs filesystem (for unit tests only; defaults to `false`).
    pub allow_non_btrfs_for_testing: bool,
}

impl TreeStoreConfig {
    /// Production defaults: strict Btrfs guardrails + 2 GiB emergency ballast.
    pub fn new(pool_root: impl Into<PathBuf>) -> Self {
        Self {
            pool_root: pool_root.into(),
            ballast_bytes: DEFAULT_BALLAST_BYTES,
            allow_non_btrfs_for_testing: false,
        }
    }

    /// Builder helper to override the ballast size (e.g. smaller pools on WSL2).
    #[must_use]
    pub fn with_ballast_bytes(mut self, bytes: u64) -> Self {
        self.ballast_bytes = bytes;
        self
    }

    /// Test-only helper permitting non-Btrfs directories (cross-platform unit tests).
    #[must_use]
    pub fn for_testing(pool_root: impl Into<PathBuf>) -> Self {
        Self {
            pool_root: pool_root.into(),
            ballast_bytes: 0,
            allow_non_btrfs_for_testing: true,
        }
    }
}

/// Current state of the `pool_root/ballast` emergency file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallastStatus {
    /// Path to the ballast file.
    pub path: PathBuf,
    /// Configured target size in bytes.
    pub target_bytes: u64,
    /// Whether the file currently exists on disk.
    pub present: bool,
    /// Current file length in bytes (`0` if absent).
    pub actual_bytes: u64,
}

/// Directory-tree storage engine (`kind::Tree`) backed by a Btrfs storage pool.
#[derive(Debug, Clone)]
pub struct TreeStore {
    pool_root: PathBuf,
    ballast_bytes: u64,
    btrfs_backed: bool,
}

impl TreeStore {
    /// Open (and initialize subdirectories + ballast on) the storage pool.
    ///
    /// On Linux (unless `allow_non_btrfs_for_testing` is set), enforces:
    /// * `pool_root` is not on `/mnt/*` or 9p/DrvFs;
    /// * `pool_root` is on a real Btrfs filesystem (`BTRFS_SUPER_MAGIC`);
    /// * `autodefrag` mount option is NOT enabled;
    /// * Btrfs `qgroups` are disabled (fail closed).
    pub fn open(cfg: TreeStoreConfig) -> Result<Self> {
        if cfg.pool_root.as_os_str().is_empty() {
            return Err(StoreError::InvalidName {
                name: String::new(),
                reason: "pool_root must not be empty".into(),
            });
        }

        fs::create_dir_all(&cfg.pool_root).map_err(|e| {
            StoreError::io_or_enospc(
                format!("creating pool root {}", cfg.pool_root.display()),
                e,
            )
        })?;

        #[cfg(target_os = "linux")]
        let btrfs_backed = if cfg.allow_non_btrfs_for_testing {
            false
        } else {
            crate::btrfs::linux_impl::verify_btrfs_pool_guardrails(&cfg.pool_root)?;
            true
        };

        #[cfg(not(target_os = "linux"))]
        let btrfs_backed = false;

        for sub in [OBJECTS_DIR, WORLDS_DIR, QUARANTINE_DIR] {
            let dir = cfg.pool_root.join(sub);
            fs::create_dir_all(&dir).map_err(|e| {
                StoreError::io_or_enospc(format!("creating pool subdir {}", dir.display()), e)
            })?;
        }

        // Sandboxes write through idmapped mounts, so a file a world makes setuid is setuid-root
        // on disk. Only the pool owner may reach it.
        #[cfg(unix)]
        for dir in [PathBuf::new(), OBJECTS_DIR.into(), WORLDS_DIR.into(), QUARANTINE_DIR.into()] {
            use std::os::unix::fs::PermissionsExt;
            let dir = cfg.pool_root.join(dir);
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
                StoreError::io_or_enospc(format!("restricting {} to 0700", dir.display()), e)
            })?;
        }

        let store = Self {
            pool_root: cfg.pool_root,
            ballast_bytes: cfg.ballast_bytes,
            btrfs_backed,
        };

        if store.ballast_bytes > 0 {
            store.ensure_ballast()?;
        }

        Ok(store)
    }

    /// Pool root directory.
    #[must_use]
    pub fn pool_root(&self) -> &Path {
        &self.pool_root
    }

    /// Canonical frame objects directory (`pool_root/objects`).
    #[must_use]
    pub fn objects_dir(&self) -> PathBuf {
        self.pool_root.join(OBJECTS_DIR)
    }

    /// Active writable worlds directory (`pool_root/worlds`).
    #[must_use]
    pub fn worlds_dir(&self) -> PathBuf {
        self.pool_root.join(WORLDS_DIR)
    }

    /// Quarantine directory (`pool_root/quarantine`).
    #[must_use]
    pub fn quarantine_dir(&self) -> PathBuf {
        self.pool_root.join(QUARANTINE_DIR)
    }

    /// Emergency ballast file path (`pool_root/ballast`).
    #[must_use]
    pub fn ballast_path(&self) -> PathBuf {
        self.pool_root.join(BALLAST_FILE)
    }

    /// `true` when operating on a verified Linux Btrfs pool.
    #[must_use]
    pub fn is_btrfs_backed(&self) -> bool {
        self.btrfs_backed
    }

    /// Canonical path for a `ManagedObject` under `pool_root/objects/`.
    #[must_use]
    pub fn object_path(&self, obj: &ManagedObject) -> PathBuf {
        self.objects_dir().join(obj.name())
    }

    /// Canonical path for a frame's tree subvolume (`pool_root/objects/f-<frame>-subvol`).
    #[must_use]
    pub fn frame_subvol_path(&self, frame_id: FrameId) -> PathBuf {
        self.object_path(&ManagedObject::new(frame_id, ObjectKind::TreeSubvol))
    }

    /// Path for a writable world clone under `pool_root/worlds/<target_name>`.
    pub fn world_subvol_path(&self, target_name: &str) -> Result<PathBuf> {
        validate_single_name(target_name)?;
        Ok(self.worlds_dir().join(target_name))
    }

    /// Inspect current `pool_root/ballast` status.
    pub fn ballast_status(&self) -> Result<BallastStatus> {
        let path = self.ballast_path();
        match fs::symlink_metadata(&path) {
            Ok(md) => Ok(BallastStatus {
                path,
                target_bytes: self.ballast_bytes,
                present: true,
                actual_bytes: md.len(),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BallastStatus {
                path,
                target_bytes: self.ballast_bytes,
                present: false,
                actual_bytes: 0,
            }),
            Err(e) => Err(StoreError::io(format!("stat {}", path.display()), e)),
        }
    }

    /// Ensure `pool_root/ballast` is pre-allocated to `ballast_bytes` and flushed to disk.
    pub fn ensure_ballast(&self) -> Result<()> {
        if self.ballast_bytes == 0 {
            return Ok(());
        }
        let path = self.ballast_path();
        if let Ok(md) = fs::symlink_metadata(&path) {
            if md.file_type().is_symlink() || !md.is_file() {
                return Err(StoreError::io(
                    format!("ballast path {} is not a regular file", path.display()),
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid ballast file type"),
                ));
            }
            if md.len() >= self.ballast_bytes {
                return Ok(());
            }
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| StoreError::io_or_enospc(format!("opening ballast {}", path.display()), e))?;

        #[cfg(target_os = "linux")]
        {
            if let Err(e) = crate::btrfs::linux_impl::fallocate_ballast(&file, self.ballast_bytes) {
                drop(file);
                let _ = fs::remove_file(&path);
                return Err(StoreError::io_or_enospc(
                    format!("fallocate ballast {}", path.display()),
                    e,
                ));
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            if let Err(e) = file.set_len(self.ballast_bytes) {
                drop(file);
                let _ = fs::remove_file(&path);
                return Err(StoreError::io_or_enospc(
                    format!("allocating ballast {}", path.display()),
                    e,
                ));
            }
        }

        file.sync_all()
            .map_err(|e| StoreError::io_or_enospc(format!("fsync ballast {}", path.display()), e))?;
        drop(file);
        let _ = PersistProof::fsync_dir(&self.pool_root)
            .map_err(|e| StoreError::io(format!("fsync pool root {}", self.pool_root.display()), e))?;

        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let root_dir = crate::btrfs::linux_impl::open_dir_nofollow(&self.pool_root)
                .map_err(|e| StoreError::io("opening pool root for btrfs_sync", e))?;
            crate::btrfs::linux_impl::btrfs_sync(&root_dir)
                .map_err(|e| StoreError::io_or_enospc("btrfs_sync after ballast allocation", e))?;
        }

        Ok(())
    }

    /// Release `pool_root/ballast` to reclaim emergency space on `ENOSPC`.
    ///
    /// Returns `Ok(true)` if the ballast file existed and was removed, `Ok(false)` if already absent.
    pub fn release_ballast(&self) -> Result<bool> {
        let path = self.ballast_path();
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => {
                return Err(StoreError::io(
                    format!("removing ballast {}", path.display()),
                    e,
                ));
            }
        }
        let _ = PersistProof::fsync_dir(&self.pool_root);

        #[cfg(target_os = "linux")]
        if self.btrfs_backed
            && let Ok(root_dir) = crate::btrfs::linux_impl::open_dir_nofollow(&self.pool_root)
        {
            // Commit Btrfs transaction so unlinked ballast extents return to available space.
            let _ = crate::btrfs::linux_impl::btrfs_sync(&root_dir);
        }

        Ok(true)
    }

    /// Open a handle to an existing subvolume inside `pool_root/objects/` or `pool_root/worlds/`.
    pub fn open_subvolume(&self, path: &Path) -> Result<SubvolHandle> {
        let (name, in_objects) = self.validate_managed_subvol_path(path, false)?;
        let md = fs::symlink_metadata(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StoreError::NotFound {
                    path: path.to_path_buf(),
                }
            } else {
                StoreError::io(format!("lstat {}", path.display()), e)
            }
        })?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(StoreError::OutsidePool {
                path: path.to_path_buf(),
                reason: "target is not a directory subvolume".into(),
            });
        }
        #[cfg(target_os = "linux")]
        let readonly = if self.btrfs_backed {
            let f = crate::btrfs::linux_impl::open_dir_nofollow(path)
                .map_err(|e| StoreError::io(format!("opening subvol {}", path.display()), e))?;
            (crate::btrfs::linux_impl::btrfs_subvol_getflags(&f)
                .map_err(|e| StoreError::io(format!("BTRFS_IOC_SUBVOL_GETFLAGS {}", path.display()), e))?
                & crate::btrfs::BTRFS_SUBVOL_RDONLY)
                != 0
        } else {
            in_objects
        };
        #[cfg(not(target_os = "linux"))]
        let readonly = in_objects;

        let object = if in_objects {
            ManagedObject::parse_name(&name)
        } else {
            None
        };
        Ok(SubvolHandle::new(path.to_path_buf(), name, object, readonly))
    }

    /// Unpack an untrusted tar stream into a canonical read-only frame subvolume
    /// (`pool_root/objects/f-<frame>-subvol`), seal read-only, `syncfs` + parent `fsync`, and
    /// return [`Persisted<SubvolHandle>`] backed by [`PersistProof::fsync_subvolume`].
    ///
    /// On any unpack or sealing failure, the partial subvolume is destroyed before returning `Err`.
    pub fn import_tar<R: Read>(
        &self,
        frame_id: FrameId,
        reader: R,
        opts: &TarImportOptions,
    ) -> Result<Persisted<SubvolHandle>> {
        let obj = ManagedObject::new(frame_id, ObjectKind::TreeSubvol);
        self.import_tar_named(&obj.name(), reader, opts)
    }

    /// Unpack an untrusted tar stream into `pool_root/objects/<target_name>`, seal read-only,
    /// `syncfs` + parent `fsync`, and return [`Persisted<SubvolHandle>`].
    pub fn import_tar_named<R: Read>(
        &self,
        target_name: &str,
        reader: R,
        opts: &TarImportOptions,
    ) -> Result<Persisted<SubvolHandle>> {
        validate_single_name(target_name)?;
        let objects_dir = self.objects_dir();
        let dst = objects_dir.join(target_name);
        if path_exists_nofollow(&dst)? {
            return Err(StoreError::AlreadyExists { path: dst });
        }

        self.create_empty_subvolume(&objects_dir, target_name)?;

        let res = (|| -> Result<Persisted<SubvolHandle>> {
            unpack_tar_safely(&dst, reader, opts)?;
            self.seal_subvolume_readonly(&dst)?;
            let proof = PersistProof::fsync_subvolume(&dst).map_err(|e| {
                StoreError::io_or_enospc(format!("fsync_subvolume {}", dst.display()), e)
            })?;
            let object = ManagedObject::parse_name(target_name);
            Ok(Persisted::new(
                SubvolHandle::new(dst.clone(), target_name.to_owned(), object, true),
                proof,
            ))
        })();

        if res.is_err() {
            // Rollback partial/unsafe subvolume cleanly so no unsealed artifact lingers.
            let _ = self.destroy_subvolume(&dst);
        }
        res
    }

    /// Import a local host workspace directory into an immutable frame subvolume by streaming it
    /// through the exact same safe tar pipeline (`import_tar`), avoiding any live host mount
    /// (ARCHITECTURE_V2 §3.2).
    pub fn import_local_dir(
        &self,
        frame_id: FrameId,
        src_dir: &Path,
        opts: &TarImportOptions,
    ) -> Result<Persisted<SubvolHandle>> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            builder.follow_symlinks(false);
            builder.append_dir_all(".", src_dir).map_err(|e| {
                StoreError::io(
                    format!("packing local workspace {}", src_dir.display()),
                    e,
                )
            })?;
            builder
                .finish()
                .map_err(|e| StoreError::io("finishing workspace tar stream", e))?;
        }
        self.import_tar(frame_id, io::Cursor::new(tar_buf), opts)
    }

    /// Create an O(1) writable Btrfs snapshot of a sealed read-only `base_subvol` under
    /// `pool_root/worlds/<target_name>` for a live `World`.
    pub fn create_writable_clone(
        &self,
        base_subvol: &SubvolHandle,
        target_name: &str,
    ) -> Result<SubvolHandle> {
        validate_single_name(target_name)?;
        if !base_subvol.is_readonly() {
            return Err(StoreError::NotReadOnly {
                path: base_subvol.path().to_path_buf(),
            });
        }
        self.verify_subvol_exists_and_ro(base_subvol.path())?;

        let worlds_dir = self.worlds_dir();
        let dst = worlds_dir.join(target_name);
        if path_exists_nofollow(&dst)? {
            return Err(StoreError::AlreadyExists { path: dst });
        }

        self.create_snapshot(base_subvol.path(), &worlds_dir, target_name, false)?;
        let _ = PersistProof::fsync_dir(&worlds_dir);
        Ok(SubvolHandle::new(dst, target_name.to_owned(), None, false))
    }

    /// Take a sealed read-only Btrfs snapshot of `live_subvol` at `pool_root/objects/<target_name>`,
    /// returning [`Persisted<SubvolHandle>`] backed by [`PersistProof::fsync_subvolume`].
    pub fn snapshot_readonly(
        &self,
        live_subvol: &SubvolHandle,
        target_name: &str,
    ) -> Result<Persisted<SubvolHandle>> {
        validate_single_name(target_name)?;
        if !path_exists_nofollow(live_subvol.path())? {
            return Err(StoreError::NotFound {
                path: live_subvol.path().to_path_buf(),
            });
        }

        let objects_dir = self.objects_dir();
        let dst = objects_dir.join(target_name);
        if path_exists_nofollow(&dst)? {
            return Err(StoreError::AlreadyExists { path: dst });
        }

        // Create the snapshot before entering the rollback-on-error scope so a concurrent EEXIST
        // can never destroy another caller's subvolume.
        self.create_snapshot(live_subvol.path(), &objects_dir, target_name, true)?;

        let res = (|| -> Result<Persisted<SubvolHandle>> {
            self.sync_after_readonly_snapshot(&dst)?;
            let proof = PersistProof::fsync_subvolume(&dst).map_err(|e| {
                StoreError::io_or_enospc(format!("fsync_subvolume {}", dst.display()), e)
            })?;
            let object = ManagedObject::parse_name(target_name);
            Ok(Persisted::new(
                SubvolHandle::new(dst.clone(), target_name.to_owned(), object, true),
                proof,
            ))
        })();

        if res.is_err() {
            let _ = self.destroy_subvolume(&dst);
        }
        res
    }

    /// Take a sealed read-only snapshot using the canonical `ManagedObject` name for `frame_id`.
    pub fn snapshot_frame_readonly(
        &self,
        live_subvol: &SubvolHandle,
        frame_id: FrameId,
    ) -> Result<Persisted<SubvolHandle>> {
        let obj = ManagedObject::new(frame_id, ObjectKind::TreeSubvol);
        self.snapshot_readonly(live_subvol, &obj.name())
    }

    /// Destroy a subvolume (or quarantined entry) inside `pool_root`.
    ///
    /// * Refuses any path outside `pool_root/{objects,worlds,quarantine}/...`.
    /// * Idempotent on `NotFound` (returns `Ok(())`).
    /// * On Linux Btrfs: clears `BTRFS_SUBVOL_RDONLY` if set, calls `BTRFS_IOC_SNAP_DESTROY_V2`
    ///   (falling back to v1 on `ENOTTY`), and if `ENOSPC` occurs, automatically releases the
    ///   emergency `ballast` file and retries once.
    pub fn destroy_subvolume(&self, path: &Path) -> Result<()> {
        let (name, _in_objects) = self.validate_managed_subvol_path(path, true)?;
        let md = match fs::symlink_metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(StoreError::io(format!("lstat {}", path.display()), e)),
        };

        // Never follow symlinks: if a quarantined entry is itself a symlink, just unlink it.
        if md.file_type().is_symlink() || !md.is_dir() {
            match fs::remove_file(path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(StoreError::io(format!("removing {}", path.display()), e)),
            }
        }

        let parent = path.parent().ok_or_else(|| StoreError::OutsidePool {
            path: path.to_path_buf(),
            reason: "subvolume path has no parent".into(),
        })?;

        #[cfg(target_os = "linux")]
        if self.btrfs_backed
            && crate::btrfs::linux_impl::is_btrfs_subvolume(path).unwrap_or(false)
        {
            return self.destroy_btrfs_subvol_with_ballast(parent, path, &name);
        }

        let _ = name;
        remove_dir_tree_clearing_readonly(path)?;
        let _ = PersistProof::fsync_dir(parent);
        Ok(())
    }

    /// Compute a zero-trust diff between `base` and `target`, wrap in `Untrusted<RawPatchBundle>`,
    /// and unconditionally validate via [`aos_types::PatchPathValidator`] before returning
    /// [`PatchBundle`].
    pub fn export_patch(
        &self,
        base: &SubvolHandle,
        target: &SubvolHandle,
        opts: &ExportPatchOptions,
    ) -> Result<PatchBundle> {
        if !path_exists_nofollow(base.path())? {
            return Err(StoreError::NotFound {
                path: base.path().to_path_buf(),
            });
        }
        if !path_exists_nofollow(target.path())? {
            return Err(StoreError::NotFound {
                path: target.path().to_path_buf(),
            });
        }
        export_patch_between_roots(base.path(), target.path(), opts)
    }

    // ========================================================================= internals

    fn validate_managed_subvol_path(
        &self,
        path: &Path,
        allow_quarantine: bool,
    ) -> Result<(String, bool)> {
        let rel = path.strip_prefix(&self.pool_root).map_err(|_| StoreError::OutsidePool {
            path: path.to_path_buf(),
            reason: format!("not under pool_root {}", self.pool_root.display()),
        })?;
        let comps: Vec<_> = rel.components().collect();
        if comps.len() < 2 {
            return Err(StoreError::OutsidePool {
                path: path.to_path_buf(),
                reason: "must target a child inside objects/, worlds/, or quarantine/".into(),
            });
        }
        let top = comps[0].as_os_str().to_str().unwrap_or("");
        let in_objects = match top {
            OBJECTS_DIR if comps.len() == 2 => true,
            WORLDS_DIR if comps.len() == 2 => false,
            QUARANTINE_DIR if allow_quarantine && comps.len() == 3 => false,
            _ => {
                return Err(StoreError::OutsidePool {
                    path: path.to_path_buf(),
                    reason: format!("unexpected pool subpath {}", rel.display()),
                });
            }
        };
        for c in &comps {
            if !matches!(c, std::path::Component::Normal(_)) {
                return Err(StoreError::OutsidePool {
                    path: path.to_path_buf(),
                    reason: "non-normal path component".into(),
                });
            }
        }
        let leaf = comps
            .last()
            .and_then(|c| c.as_os_str().to_str())
            .ok_or_else(|| StoreError::InvalidName {
                name: path.display().to_string(),
                reason: "non-UTF-8 subvolume name".into(),
            })?;
        validate_single_name(leaf)?;
        Ok((leaf.to_owned(), in_objects))
    }

    fn create_empty_subvolume(&self, parent: &Path, name: &str) -> Result<()> {
        let dst = parent.join(name);
        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let parent_fd = crate::btrfs::linux_impl::open_dir_nofollow(parent)
                .map_err(|e| StoreError::io(format!("opening {}", parent.display()), e))?;
            return crate::btrfs::linux_impl::btrfs_subvol_create(&parent_fd, name).map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists { path: dst }
                } else {
                    StoreError::io_or_enospc(format!("BTRFS_IOC_SUBVOL_CREATE_V2 {name}"), e)
                }
            });
        }

        fs::create_dir(&dst).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                StoreError::AlreadyExists { path: dst }
            } else {
                StoreError::io_or_enospc(format!("creating dir {}", dst.display()), e)
            }
        })
    }

    fn seal_subvolume_readonly(&self, subvol_path: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let f = crate::btrfs::linux_impl::open_dir_nofollow(subvol_path).map_err(|e| {
                StoreError::io(format!("opening subvol {}", subvol_path.display()), e)
            })?;
            crate::btrfs::linux_impl::syncfs(&f)
                .map_err(|e| StoreError::io_or_enospc("syncfs before sealing subvolume", e))?;
            crate::btrfs::linux_impl::btrfs_subvol_set_readonly(&f, true).map_err(|e| {
                StoreError::io_or_enospc(
                    format!("BTRFS_IOC_SUBVOL_SETFLAGS RDONLY {}", subvol_path.display()),
                    e,
                )
            })?;
            crate::btrfs::linux_impl::btrfs_sync(&f)
                .map_err(|e| StoreError::io_or_enospc("btrfs_sync after sealing subvolume", e))?;
            crate::btrfs::linux_impl::syncfs(&f)
                .map_err(|e| StoreError::io_or_enospc("syncfs after sealing subvolume", e))?;
            return Ok(());
        }

        let _ = subvol_path;
        Ok(())
    }

    fn verify_subvol_exists_and_ro(&self, path: &Path) -> Result<()> {
        let md = fs::symlink_metadata(path).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                StoreError::NotFound {
                    path: path.to_path_buf(),
                }
            } else {
                StoreError::io(format!("lstat {}", path.display()), e)
            }
        })?;
        if md.file_type().is_symlink() || !md.is_dir() {
            return Err(StoreError::OutsidePool {
                path: path.to_path_buf(),
                reason: "base subvolume is not a directory".into(),
            });
        }
        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let f = crate::btrfs::linux_impl::open_dir_nofollow(path)
                .map_err(|e| StoreError::io(format!("opening {}", path.display()), e))?;
            let flags = crate::btrfs::linux_impl::btrfs_subvol_getflags(&f).map_err(|e| {
                StoreError::io(format!("BTRFS_IOC_SUBVOL_GETFLAGS {}", path.display()), e)
            })?;
            if (flags & crate::btrfs::BTRFS_SUBVOL_RDONLY) == 0 {
                return Err(StoreError::NotReadOnly {
                    path: path.to_path_buf(),
                });
            }
        }
        Ok(())
    }

    fn create_snapshot(
        &self,
        src_subvol: &Path,
        dst_parent: &Path,
        target_name: &str,
        readonly: bool,
    ) -> Result<()> {
        let dst = dst_parent.join(target_name);
        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let src_fd = crate::btrfs::linux_impl::open_dir_nofollow(src_subvol)
                .map_err(|e| StoreError::io(format!("opening source {}", src_subvol.display()), e))?;
            if readonly {
                // Flush dirty pages in live subvol before taking the sealed snapshot.
                crate::btrfs::linux_impl::syncfs(&src_fd).map_err(|e| {
                    StoreError::io_or_enospc("syncfs before readonly snapshot", e)
                })?;
            }
            let parent_fd = crate::btrfs::linux_impl::open_dir_nofollow(dst_parent).map_err(|e| {
                StoreError::io(format!("opening target parent {}", dst_parent.display()), e)
            })?;
            return crate::btrfs::linux_impl::btrfs_snap_create(
                &parent_fd,
                &src_fd,
                target_name,
                readonly,
            )
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    StoreError::AlreadyExists { path: dst }
                } else {
                    StoreError::io_or_enospc(format!("BTRFS_IOC_SNAP_CREATE_V2 {target_name}"), e)
                }
            });
        }

        copy_tree_nofollow(src_subvol, &dst)?;
        let _ = readonly;
        Ok(())
    }

    fn sync_after_readonly_snapshot(&self, dst: &Path) -> Result<()> {
        #[cfg(target_os = "linux")]
        if self.btrfs_backed {
            let f = crate::btrfs::linux_impl::open_dir_nofollow(dst)
                .map_err(|e| StoreError::io(format!("opening snapshot {}", dst.display()), e))?;
            crate::btrfs::linux_impl::btrfs_sync(&f)
                .map_err(|e| StoreError::io_or_enospc("btrfs_sync after snapshot", e))?;
            crate::btrfs::linux_impl::syncfs(&f)
                .map_err(|e| StoreError::io_or_enospc("syncfs after snapshot", e))?;
        }
        let _ = dst;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn destroy_btrfs_subvol_with_ballast(
        &self,
        parent: &Path,
        path: &Path,
        name: &str,
    ) -> Result<()> {
        let mut ballast_released = false;
        for attempt in 0..2 {
            // Clear RDONLY flag if set, then close the subvol fd before SNAP_DESTROY_V2.
            {
                match crate::btrfs::linux_impl::open_dir_nofollow(path) {
                    Ok(subvol_fd) => {
                        if let Err(e) =
                            crate::btrfs::linux_impl::btrfs_subvol_set_readonly(&subvol_fd, false)
                        {
                            if is_enospc(&e) && attempt == 0 && self.release_ballast()? {
                                ballast_released = true;
                                continue;
                            }
                            if e.kind() == io::ErrorKind::NotFound {
                                return Ok(());
                            }
                            return Err(if is_enospc(&e) {
                                StoreError::NoSpace {
                                    operation: format!("clearing RDONLY on {}", path.display()),
                                    ballast_released,
                                    source: e,
                                }
                            } else {
                                StoreError::io(
                                    format!("clearing RDONLY on {}", path.display()),
                                    e,
                                )
                            });
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                    Err(e) => {
                        return Err(StoreError::io(
                            format!("opening subvolume {} for destroy", path.display()),
                            e,
                        ));
                    }
                }
            }

            let parent_fd = crate::btrfs::linux_impl::open_dir_nofollow(parent)
                .map_err(|e| StoreError::io(format!("opening parent {}", parent.display()), e))?;
            match crate::btrfs::linux_impl::btrfs_snap_destroy(&parent_fd, name) {
                Ok(()) => {
                    let _ = PersistProof::fsync_dir(parent);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) if is_enospc(&e) && attempt == 0 && self.release_ballast()? => {
                    ballast_released = true;
                    continue;
                }
                Err(e) if is_enospc(&e) => {
                    return Err(StoreError::NoSpace {
                        operation: format!("destroying subvolume {}", path.display()),
                        ballast_released,
                        source: e,
                    });
                }
                Err(e) => {
                    return Err(StoreError::io(
                        format!("BTRFS_IOC_SNAP_DESTROY {}", path.display()),
                        e,
                    ));
                }
            }
        }
        Ok(())
    }
}

/// [`aos_meta::RecoveryHooks`] adapter delegating `TreeSubvol` and quarantine destruction to
/// [`TreeStore::destroy_subvolume`] (clearing Btrfs read-only flags and handling `ENOSPC` ballast
/// release automatically).
#[derive(Debug, Clone)]
pub struct TreeStoreRecoveryHooks {
    store: TreeStore,
    volatile_root: PathBuf,
}

impl TreeStoreRecoveryHooks {
    /// Construct recovery hooks backed by `store` and a volatile `tmpfs` root.
    pub fn new(store: TreeStore, volatile_root: impl Into<PathBuf>) -> Self {
        Self {
            store,
            volatile_root: volatile_root.into(),
        }
    }
}

impl RecoveryHooks for TreeStoreRecoveryHooks {
    fn fence_gateway(&mut self, _epoch: EpochId) -> io::Result<()> {
        Ok(())
    }

    fn kill_stale_epochs(&mut self, _current: EpochId) -> io::Result<()> {
        Ok(())
    }

    fn destroy_pool_object(&mut self, path: &Path, object: &ManagedObject) -> io::Result<()> {
        match object.kind {
            ObjectKind::TreeSubvol => self
                .store
                .destroy_subvolume(path)
                .map_err(|e| io::Error::other(e.to_string())),
            ObjectKind::DiskImage | ObjectKind::MemImage | ObjectKind::VmState => {
                aos_meta::hooks::remove_path(path)
            }
        }
    }

    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()> {
        aos_meta::hooks::remove_path(&self.volatile_root.join(object.name()))
    }

    fn purge_quarantined(&mut self, path: &Path) -> io::Result<()> {
        self.store
            .destroy_subvolume(path)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

fn validate_single_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
    {
        return Err(StoreError::InvalidName {
            name: name.to_owned(),
            reason: "name must be a single 1..=255 byte path component without '/', '\\', or NUL"
                .into(),
        });
    }
    Ok(())
}

fn path_exists_nofollow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(StoreError::io(format!("lstat {}", path.display()), e)),
    }
}

fn copy_tree_nofollow(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir(dst).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            StoreError::AlreadyExists {
                path: dst.to_path_buf(),
            }
        } else {
            StoreError::io_or_enospc(format!("creating dir {}", dst.display()), e)
        }
    })?;
    for entry in fs::read_dir(src)
        .map_err(|e| StoreError::io(format!("reading dir {}", src.display()), e))?
    {
        let entry = entry.map_err(|e| StoreError::io(format!("dir entry {}", src.display()), e))?;
        let src_child = entry.path();
        let dst_child = dst.join(entry.file_name());
        let md = fs::symlink_metadata(&src_child)
            .map_err(|e| StoreError::io(format!("lstat {}", src_child.display()), e))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            let target = fs::read_link(&src_child)
                .map_err(|e| StoreError::io(format!("read_link {}", src_child.display()), e))?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_child).map_err(|e| {
                StoreError::io_or_enospc(format!("symlink {}", dst_child.display()), e)
            })?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&target, &dst_child).map_err(|e| {
                StoreError::io_or_enospc(format!("symlink {}", dst_child.display()), e)
            })?;
        } else if ft.is_dir() {
            copy_tree_nofollow(&src_child, &dst_child)?;
        } else if ft.is_file() {
            fs::copy(&src_child, &dst_child).map_err(|e| {
                StoreError::io_or_enospc(
                    format!("copying {} -> {}", src_child.display(), dst_child.display()),
                    e,
                )
            })?;
        }
    }
    Ok(())
}

fn remove_dir_tree_clearing_readonly(path: &Path) -> Result<()> {
    clear_readonly_recursive(path);
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::io(format!("removing {}", path.display()), e)),
    }
}

fn clear_readonly_recursive(path: &Path) {
    let Ok(md) = fs::symlink_metadata(path) else {
        return;
    };
    if md.file_type().is_symlink() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = md.permissions().mode();
        if md.is_dir() && (mode & 0o700) != 0o700 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700));
        }
    }
    #[cfg(not(unix))]
    {
        let mut perms = md.permissions();
        if perms.readonly() {
            // Non-Unix (Windows) dev host only: clears the DOS read-only attribute before delete.
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
    if md.is_dir()
        && let Ok(rd) = fs::read_dir(path)
    {
        for entry in rd.flatten() {
            clear_readonly_recursive(&entry.path());
        }
    }
}
