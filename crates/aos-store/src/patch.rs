//! Zero-trust patch export (`export_patch`) with unconditional `Untrusted<RawPatchBundle>`
//! validation through [`aos_types::PatchPathValidator`] (ARCHITECTURE_V2 §3.4).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use aos_types::{
    BaseKind, BaseTree, PatchEntry, PatchPathError, PatchPathValidator, PatchSet, PathPolicy,
    Untrusted, Validator,
};
use serde::{Deserialize, Serialize};

use crate::error::{Result, StoreError};

/// Default cumulative byte limit for exported patch payloads (256 MiB).
pub const DEFAULT_MAX_PATCH_BYTES: u64 = 256 * 1024 * 1024;
/// Default maximum number of diff entries in a single exported patch.
pub const DEFAULT_MAX_PATCH_ENTRIES: usize = 100_000;

/// Options for [`crate::TreeStore::export_patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPatchOptions {
    /// Target path validation policy (defaults to [`PathPolicy::CrossPlatform`]).
    pub policy: PathPolicy,
    /// Explicit gitlink paths permitted in the patch (empty by default).
    pub allowed_gitlinks: Vec<String>,
    /// Maximum cumulative byte size of `PutFile` contents in the exported patch.
    pub max_patch_bytes: u64,
    /// Maximum number of change entries in the exported patch.
    pub max_patch_entries: usize,
}

impl Default for ExportPatchOptions {
    fn default() -> Self {
        Self {
            policy: PathPolicy::CrossPlatform,
            allowed_gitlinks: Vec::new(),
            max_patch_bytes: DEFAULT_MAX_PATCH_BYTES,
            max_patch_entries: DEFAULT_MAX_PATCH_ENTRIES,
        }
    }
}

/// One file or symlink change inside an exported patch bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchFileChange {
    /// Create or replace a regular file.
    PutFile {
        /// Repository-relative `/`-separated path.
        path: String,
        /// Exact file contents.
        contents: Vec<u8>,
        /// Whether the executable bit (`0o111`) is set.
        executable: bool,
        /// `true` if `path` existed in the base tree, `false` if newly added.
        modified: bool,
    },
    /// Create or replace a symbolic link.
    PutSymlink {
        /// Repository-relative `/`-separated path.
        path: String,
        /// Link target text.
        target: String,
        /// `true` if `path` existed in the base tree, `false` if newly added.
        modified: bool,
    },
    /// Remove an entry that existed in the base tree.
    Remove {
        /// Repository-relative `/`-separated path.
        path: String,
    },
}

impl PatchFileChange {
    /// Repository-relative path affected by this change.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            PatchFileChange::PutFile { path, .. }
            | PatchFileChange::PutSymlink { path, .. }
            | PatchFileChange::Remove { path } => path,
        }
    }

    fn to_patch_entry(&self) -> PatchEntry {
        match self {
            PatchFileChange::PutFile { path, .. } => PatchEntry::file(path.clone()),
            PatchFileChange::PutSymlink { path, target, .. } => {
                PatchEntry::symlink(path.clone(), target.clone())
            }
            PatchFileChange::Remove { path } => PatchEntry::remove(path.clone()),
        }
    }
}

/// Raw (unvalidated) patch bundle extracted from a sandbox tree.
///
/// Always wrapped in [`Untrusted<RawPatchBundle>`] at the trust boundary and consumed exclusively
/// through [`PatchBundleValidator`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawPatchBundle {
    /// Unvalidated changes.
    pub changes: Vec<PatchFileChange>,
}

/// A validated patch bundle that has unconditionally passed [`PatchPathValidator`].
///
/// Cannot be constructed outside [`PatchBundleValidator::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchBundle {
    changes: Vec<PatchFileChange>,
}

impl PatchBundle {
    /// Validated changes in deterministic path order.
    #[must_use]
    pub fn changes(&self) -> &[PatchFileChange] {
        &self.changes
    }

    /// Consume the bundle into its validated changes.
    #[must_use]
    pub fn into_changes(self) -> Vec<PatchFileChange> {
        self.changes
    }

    /// `true` iff the patch contains no changes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Number of changes in the patch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }
}

/// Zero-trust validator converting [`Untrusted<RawPatchBundle>`] into [`PatchBundle`] using
/// [`aos_types::PatchPathValidator`].
#[derive(Debug, Clone)]
pub struct PatchBundleValidator {
    path_validator: PatchPathValidator,
}

impl PatchBundleValidator {
    /// Construct from a configured [`PatchPathValidator`].
    #[must_use]
    pub fn new(path_validator: PatchPathValidator) -> Self {
        Self { path_validator }
    }
}

impl Validator<RawPatchBundle> for PatchBundleValidator {
    type Output = PatchBundle;
    type Error = PatchPathError;

    fn validate(&self, input: RawPatchBundle) -> std::result::Result<PatchBundle, PatchPathError> {
        let patch_set = PatchSet {
            entries: input
                .changes
                .iter()
                .map(PatchFileChange::to_patch_entry)
                .collect(),
        };
        let _validated = Untrusted::new(patch_set).validate(&self.path_validator)?;
        Ok(PatchBundle {
            changes: input.changes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TreeLeaf {
    File {
        size: u64,
        blake3: [u8; 32],
        executable: bool,
    },
    Symlink {
        target: String,
    },
}

/// Compute a diff between `base_root` and `target_root`, wrap it in `Untrusted<RawPatchBundle>`,
/// and validate unconditionally through `PatchPathValidator` (with `BaseTree`).
///
/// Neither tree walk ever follows symlinks or opens symlink targets, preventing host file
/// exfiltration via malicious symlinks inside `target_root`.
pub fn export_patch_between_roots(
    base_root: &Path,
    target_root: &Path,
    opts: &ExportPatchOptions,
) -> Result<PatchBundle> {
    let base_map = scan_tree(base_root)?;
    let target_map = scan_tree(target_root)?;

    // Build trusted `BaseTree` for base-collision and base-symlink checks.
    let mut base_tree = BaseTree::new();
    for (path, leaf) in &base_map {
        let kind = match leaf {
            TreeLeaf::File { .. } => BaseKind::File,
            TreeLeaf::Symlink { .. } => BaseKind::Symlink,
        };
        base_tree.insert(path.clone(), kind);
    }

    let mut changes: Vec<PatchFileChange> = Vec::new();
    let mut total_bytes: u64 = 0;

    // 1. Removals: leaves present in base but absent in target.
    for path in base_map.keys() {
        if !target_map.contains_key(path) {
            if changes.len() >= opts.max_patch_entries {
                return Err(StoreError::DiffError {
                    path: path.clone(),
                    reason: format!(
                        "patch exceeds max_patch_entries ({})",
                        opts.max_patch_entries
                    ),
                });
            }
            changes.push(PatchFileChange::Remove { path: path.clone() });
        }
    }

    // 2. Additions and modifications: leaves present in target.
    #[cfg(target_os = "linux")]
    let target_root_fd = crate::openat2::linux_impl::open_root_dir(target_root)
        .map_err(|e| StoreError::io(format!("opening target tree {}", target_root.display()), e))?;

    for (path, t_leaf) in &target_map {
        let base_leaf = base_map.get(path);
        if base_leaf == Some(t_leaf) {
            continue;
        }
        if changes.len() >= opts.max_patch_entries {
            return Err(StoreError::DiffError {
                path: path.clone(),
                reason: format!(
                    "patch exceeds max_patch_entries ({})",
                    opts.max_patch_entries
                ),
            });
        }
        let modified = base_leaf.is_some();
        match t_leaf {
            TreeLeaf::File {
                size, executable, ..
            } => {
                if total_bytes.saturating_add(*size) > opts.max_patch_bytes {
                    return Err(StoreError::DiffError {
                        path: path.clone(),
                        reason: format!(
                            "patch exceeds max_patch_bytes ({})",
                            opts.max_patch_bytes
                        ),
                    });
                }
                let budget = opts.max_patch_bytes - total_bytes;
                let contents = read_file_bytes_safe(
                    #[cfg(target_os = "linux")]
                    &target_root_fd,
                    #[cfg(not(target_os = "linux"))]
                    target_root,
                    path,
                    budget,
                )?;
                total_bytes = total_bytes.saturating_add(contents.len() as u64);
                changes.push(PatchFileChange::PutFile {
                    path: path.clone(),
                    contents,
                    executable: *executable,
                    modified,
                });
            }
            TreeLeaf::Symlink { target } => {
                changes.push(PatchFileChange::PutSymlink {
                    path: path.clone(),
                    target: target.clone(),
                    modified,
                });
            }
        }
    }

    // Sort deterministically by path.
    changes.sort_by(|a, b| a.path().cmp(b.path()));

    let untrusted = Untrusted::new(RawPatchBundle { changes });
    let mut path_validator = PatchPathValidator::new(opts.policy);
    for gl in &opts.allowed_gitlinks {
        path_validator = path_validator.allow_gitlink(gl.clone());
    }
    path_validator = path_validator.with_base_tree(base_tree);
    let bundle_validator = PatchBundleValidator::new(path_validator);

    let validated = untrusted.validate(&bundle_validator)?;
    Ok(validated)
}

fn hash_file_reader<R: Read>(reader: &mut R, path: &str) -> Result<(u64, [u8; 32])> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| StoreError::io(format!("reading {path:?} for diff"), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total = total.saturating_add(n as u64);
    }
    Ok((total, *hasher.finalize().as_bytes()))
}

#[cfg(target_os = "linux")]
fn scan_tree(root: &Path) -> Result<BTreeMap<String, TreeLeaf>> {
    let root_fd = crate::openat2::linux_impl::open_root_dir(root)
        .map_err(|e| StoreError::io(format!("opening tree root {}", root.display()), e))?;
    let mut out = BTreeMap::new();
    scan_dir_linux(&root_fd, "", &mut out)?;
    Ok(out)
}

#[cfg(target_os = "linux")]
fn scan_dir_linux(
    dir_fd: &std::os::fd::OwnedFd,
    prefix: &str,
    out: &mut BTreeMap<String, TreeLeaf>,
) -> Result<()> {
    use crate::openat2::linux_impl;

    let names = linux_impl::read_dir_names(dir_fd)
        .map_err(|e| StoreError::io(format!("reading directory {prefix:?}"), e))?;
    for raw_name in names {
        let name = raw_name.to_str().ok_or_else(|| StoreError::DiffError {
            path: if prefix.is_empty() {
                raw_name.to_string_lossy().into_owned()
            } else {
                format!("{prefix}/{}", raw_name.to_string_lossy())
            },
            reason: "non-UTF-8 filename in tree".into(),
        })?;
        let rel = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let st = linux_impl::lstat_in_dir(dir_fd, &raw_name)
            .map_err(|e| StoreError::io(format!("lstat {rel:?}"), e))?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let child_fd = linux_impl::open_child_dir(dir_fd, name)
                    .map_err(|e| StoreError::io(format!("openat2 dir {rel:?}"), e))?;
                scan_dir_linux(&child_fd, &rel, out)?;
            }
            libc::S_IFREG => {
                let mut f = linux_impl::open_child_file_readonly(dir_fd, name)
                    .map_err(|e| StoreError::io(format!("openat2 file {rel:?}"), e))?;
                let (size, blake3) = hash_file_reader(&mut f, &rel)?;
                let executable = (st.st_mode & 0o111) != 0;
                out.insert(
                    rel,
                    TreeLeaf::File {
                        size,
                        blake3,
                        executable,
                    },
                );
            }
            libc::S_IFLNK => {
                let raw_target = linux_impl::readlink_in_dir(dir_fd, &raw_name)
                    .map_err(|e| StoreError::io(format!("readlinkat {rel:?}"), e))?;
                let target = raw_target.into_string().map_err(|os| StoreError::DiffError {
                    path: rel.clone(),
                    reason: format!("non-UTF-8 symlink target: {}", os.to_string_lossy()),
                })?;
                out.insert(rel, TreeLeaf::Symlink { target });
            }
            other => {
                return Err(StoreError::DiffError {
                    path: rel,
                    reason: format!("unsupported special file type (mode=0o{other:o})"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn scan_tree(root: &Path) -> Result<BTreeMap<String, TreeLeaf>> {
    let mut out = BTreeMap::new();
    scan_dir_portable(root, "", &mut out)?;
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
fn scan_dir_portable(
    dir: &Path,
    prefix: &str,
    out: &mut BTreeMap<String, TreeLeaf>,
) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| StoreError::io(format!("reading dir {}", dir.display()), e))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| StoreError::io(format!("iterating dir {}", dir.display()), e))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for ent in entries {
        let raw_name = ent.file_name();
        let name = raw_name.to_str().ok_or_else(|| StoreError::DiffError {
            path: if prefix.is_empty() {
                raw_name.to_string_lossy().into_owned()
            } else {
                format!("{prefix}/{}", raw_name.to_string_lossy())
            },
            reason: "non-UTF-8 filename in tree".into(),
        })?;
        let rel = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        let child_path = ent.path();
        let md = std::fs::symlink_metadata(&child_path)
            .map_err(|e| StoreError::io(format!("lstat {}", child_path.display()), e))?;
        let ft = md.file_type();
        if ft.is_symlink() {
            let target_path = std::fs::read_link(&child_path)
                .map_err(|e| StoreError::io(format!("read_link {}", child_path.display()), e))?;
            let target = target_path
                .to_str()
                .ok_or_else(|| StoreError::DiffError {
                    path: rel.clone(),
                    reason: "non-UTF-8 symlink target".into(),
                })?
                .to_owned();
            out.insert(rel, TreeLeaf::Symlink { target });
        } else if ft.is_dir() {
            scan_dir_portable(&child_path, &rel, out)?;
        } else if ft.is_file() {
            let mut f = std::fs::File::open(&child_path)
                .map_err(|e| StoreError::io(format!("opening {}", child_path.display()), e))?;
            let (size, blake3) = hash_file_reader(&mut f, &rel)?;
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                (md.permissions().mode() & 0o111) != 0
            };
            #[cfg(not(unix))]
            let executable = false;
            out.insert(
                rel,
                TreeLeaf::File {
                    size,
                    blake3,
                    executable,
                },
            );
        } else {
            return Err(StoreError::DiffError {
                path: rel,
                reason: "unsupported special file in tree".into(),
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_file_bytes_safe(
    root_fd: &std::os::fd::OwnedFd,
    rel_path: &str,
    limit: u64,
) -> Result<Vec<u8>> {
    let f = crate::openat2::linux_impl::open_file_in_root_readonly(root_fd, rel_path)
        .map_err(|e| StoreError::io(format!("openat2 read {rel_path:?}"), e))?;
    read_bounded(f, rel_path, limit)
}

#[cfg(not(target_os = "linux"))]
fn read_file_bytes_safe(root: &Path, rel_path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut p = root.to_path_buf();
    for seg in rel_path.split('/') {
        p.push(seg);
    }
    let md = std::fs::symlink_metadata(&p)
        .map_err(|e| StoreError::io(format!("lstat {}", p.display()), e))?;
    if md.file_type().is_symlink() || !md.is_file() {
        return Err(StoreError::DiffError {
            path: rel_path.to_owned(),
            reason: "entry changed to non-regular file during patch export".into(),
        });
    }
    let f = std::fs::File::open(&p)
        .map_err(|e| StoreError::io(format!("opening {}", p.display()), e))?;
    read_bounded(f, rel_path, limit)
}

fn read_bounded<R: Read>(reader: R, path: &str, limit: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut limited = reader.take(limit.saturating_add(1));
    limited
        .read_to_end(&mut out)
        .map_err(|e| StoreError::io(format!("reading file {path:?}"), e))?;
    if out.len() as u64 > limit {
        return Err(StoreError::DiffError {
            path: path.to_owned(),
            reason: format!("file grew past max_patch_bytes limit ({limit})"),
        });
    }
    Ok(out)
}
