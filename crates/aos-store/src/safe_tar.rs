//! Safe, root-confined unpacking of untrusted tar streams.
//!
//! Never calls `tar::Entry::unpack`; every entry path, link target, file type, permission bit,
//! and byte count is validated before touching the filesystem. On Linux, every directory walk,
//! file creation, and hardlink lookup goes through [`crate::openat2::linux_impl`] using
//! `openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)` /
//! `RESOLVE_BENEATH` (failing closed on `ENOSYS`/`EPERM`).

use std::collections::{HashMap, HashSet};
#[cfg(not(target_os = "linux"))]
use std::io;
use std::io::{Read, Write};
use std::path::Path;

use aos_types::{PatchEntry, PatchPathValidator, PatchSet, PathPolicy, Untrusted};
use tar::{Archive, EntryType};

use crate::error::{Result, StoreError};

/// Default cumulative byte limit for `import_tar` (4 GiB).
pub const DEFAULT_MAX_IMPORT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Default single-file byte limit for `import_tar` (1 GiB).
pub const DEFAULT_MAX_IMPORT_FILE_BYTES: u64 = 1024 * 1024 * 1024;
/// Default maximum number of entries unpacked from a single tar stream.
pub const DEFAULT_MAX_IMPORT_ENTRIES: usize = 200_000;

/// Options controlling untrusted tar unpacking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarImportOptions {
    /// Maximum cumulative payload bytes across all unpacked files.
    pub max_total_bytes: u64,
    /// Maximum byte size of any single unpacked file.
    pub max_file_bytes: u64,
    /// Maximum number of tar entries processed.
    pub max_entries: usize,
    /// Path validation policy (`CrossPlatform` by default; use `PosixOnly` for Linux rootfs tars).
    pub path_policy: PathPolicy,
    /// Reject any `.git` (and cross-platform `.git` aliases) component anywhere in the tar.
    ///
    /// Defaults to `true`. Even when set to `false` (for explicitly trusted local Git workspace
    /// imports), symlinked `.git`, symlinked `.gitmodules`, and symlinks pointing into `.git` are
    /// still unconditionally rejected.
    pub reject_dotgit: bool,
}

impl Default for TarImportOptions {
    fn default() -> Self {
        Self {
            max_total_bytes: DEFAULT_MAX_IMPORT_BYTES,
            max_file_bytes: DEFAULT_MAX_IMPORT_FILE_BYTES,
            max_entries: DEFAULT_MAX_IMPORT_ENTRIES,
            path_policy: PathPolicy::CrossPlatform,
            reject_dotgit: true,
        }
    }
}

/// Normalize and validate an untrusted tar entry path.
///
/// Returns `Ok(None)` only for a benign root directory entry (`.` or `./`).
/// Strips benign leading `./` prefixes (produced by `tar -cf - .`) and a single trailing `/` on
/// directory entries, while rejecting absolute paths, backslashes, NUL bytes, `..`, inner `.`,
/// empty segments (`//`), overlong components, and `.git` variants (when `opts.reject_dotgit` is
/// enabled).
pub fn normalize_tar_path(
    raw_bytes: &[u8],
    is_dir: bool,
    opts: &TarImportOptions,
) -> Result<Option<String>> {
    let raw = std::str::from_utf8(raw_bytes).map_err(|_| StoreError::UnsafeTarEntry {
        path: String::from_utf8_lossy(raw_bytes).into_owned(),
        reason: "non-UTF-8 tar path".into(),
    })?;
    if raw.is_empty() {
        return Err(StoreError::UnsafeTarEntry {
            path: String::new(),
            reason: "empty tar path".into(),
        });
    }
    if raw.contains('\0') {
        return Err(StoreError::UnsafeTarEntry {
            path: raw.replace('\0', "\\0"),
            reason: "NUL byte in tar path".into(),
        });
    }
    if raw.contains('\\') {
        return Err(StoreError::UnsafeTarEntry {
            path: raw.to_owned(),
            reason: "backslash in tar path".into(),
        });
    }
    if raw.starts_with('/') {
        return Err(StoreError::UnsafeTarEntry {
            path: raw.to_owned(),
            reason: "absolute path in tar".into(),
        });
    }

    // Strip benign leading `./` segments emitted by `tar -C dir -cf - .`.
    let mut trimmed = raw;
    while let Some(rest) = trimmed.strip_prefix("./") {
        trimmed = rest;
    }
    if is_dir && let Some(stripped) = trimmed.strip_suffix('/') {
        trimmed = stripped;
    }
    if trimmed.is_empty() || trimmed == "." {
        if is_dir {
            return Ok(None);
        }
        return Err(StoreError::UnsafeTarEntry {
            path: raw.to_owned(),
            reason: "non-directory entry cannot target root '.'".into(),
        });
    }

    validate_normalized_path(trimmed, opts)?;
    Ok(Some(trimmed.to_owned()))
}

fn validate_normalized_path(norm: &str, opts: &TarImportOptions) -> Result<()> {
    let validator = PatchPathValidator::new(opts.path_policy);
    if opts.reject_dotgit {
        validator
            .check_path_syntax(norm)
            .map_err(|e| StoreError::UnsafeTarEntry {
                path: norm.to_owned(),
                reason: e.kind.to_string(),
            })?;
        return Ok(());
    }

    // When `reject_dotgit == false`, still enforce every other structural & policy rule from
    // `PatchPathValidator` by substituting exact `.git` components with a benign placeholder.
    let mut proxy_parts = Vec::new();
    for comp in norm.split('/') {
        if comp == ".git" {
            proxy_parts.push("__dotgit_placeholder__");
        } else {
            proxy_parts.push(comp);
        }
    }
    let proxy = proxy_parts.join("/");
    validator
        .check_path_syntax(&proxy)
        .map_err(|e| StoreError::UnsafeTarEntry {
            path: norm.to_owned(),
            reason: e.kind.to_string(),
        })?;
    Ok(())
}

fn check_symlink_entry(
    norm_path: &str,
    target: &str,
    opts: &TarImportOptions,
) -> Result<()> {
    // Symlinks are ALWAYS checked with `.git` protection active: never allow symlinked `.git`,
    // symlinked `.gitmodules`, or a symlink pointing into `.git` or escaping root.
    let validator = PatchPathValidator::new(opts.path_policy);
    let entry = PatchEntry::symlink(norm_path, target);
    let set = PatchSet {
        entries: vec![entry],
    };
    Untrusted::new(set)
        .validate(&validator)
        .map_err(|e| StoreError::UnsafeTarEntry {
            path: norm_path.to_owned(),
            reason: e.kind.to_string(),
        })?;
    Ok(())
}

fn fold_key(path: &str, policy: PathPolicy) -> String {
    match policy {
        PathPolicy::PosixOnly => path.to_owned(),
        PathPolicy::CrossPlatform => path.to_lowercase(),
    }
}

/// Unpack an untrusted tar stream into an empty target directory (`dest_root`).
///
/// On Linux, all operations are strictly confined to `dest_root` via `openat2`
/// (`RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS` and `RESOLVE_BENEATH`).
pub fn unpack_tar_safely<R: Read>(
    dest_root: &Path,
    reader: R,
    opts: &TarImportOptions,
) -> Result<()> {
    let mut archive = Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|e| StoreError::io("reading tar archive entries", e))?;

    #[cfg(target_os = "linux")]
    let root_fd = crate::openat2::linux_impl::open_root_dir(dest_root).map_err(|e| {
        StoreError::io(
            format!("opening unpack root {}", dest_root.display()),
            e,
        )
    })?;

    let mut entry_count: usize = 0;
    let mut total_bytes: u64 = 0;
    let mut created_dirs: HashSet<String> = HashSet::new();
    let mut created_files: HashSet<String> = HashSet::new();
    let mut created_symlinks: HashMap<String, (String, String)> = HashMap::new(); // folded -> (exact, target)
    let mut seen_non_dir_folded: HashMap<String, String> = HashMap::new();
    let mut deferred_dir_modes: Vec<(String, u32)> = Vec::new();
    let mut all_patch_entries: Vec<PatchEntry> = Vec::new();

    for raw_entry in entries {
        let mut entry = raw_entry.map_err(|e| StoreError::UnsafeTarEntry {
            path: "<archive>".into(),
            reason: format!("malformed tar entry: {e}"),
        })?;

        let etype = entry.header().entry_type();
        // Ignore PAX global extended headers (emitted by `git archive`).
        if etype.is_pax_global_extensions() {
            continue;
        }

        entry_count += 1;
        if entry_count > opts.max_entries {
            return Err(StoreError::UnsafeTarEntry {
                path: "<archive>".into(),
                reason: format!("tar exceeds maximum entry limit ({})", opts.max_entries),
            });
        }

        let is_dir = etype == EntryType::Directory;
        let path_bytes = entry.path_bytes().into_owned();
        let Some(norm_path) = normalize_tar_path(&path_bytes, is_dir, opts)? else {
            // Benign root directory entry `.` or `./`.
            continue;
        };

        let comps: Vec<&str> = norm_path.split('/').collect();
        let folded = fold_key(&norm_path, opts.path_policy);

        // Reject any entry whose parent prefix traverses a previously created symlink or file.
        let mut prefix = String::new();
        for (i, c) in comps[..comps.len() - 1].iter().enumerate() {
            if i > 0 {
                prefix.push('/');
            }
            prefix.push_str(c);
            let pkey = fold_key(&prefix, opts.path_policy);
            if let Some((link_path, _)) = created_symlinks.get(&pkey) {
                return Err(StoreError::UnsafeTarEntry {
                    path: norm_path.clone(),
                    reason: format!("path traverses symlink {link_path:?}"),
                });
            }
            if let Some(existing_file) = seen_non_dir_folded.get(&pkey) {
                return Err(StoreError::UnsafeTarEntry {
                    path: norm_path.clone(),
                    reason: format!("parent path conflicts with existing entry {existing_file:?}"),
                });
            }
        }

        let mode = entry.header().mode().unwrap_or(if is_dir { 0o755 } else { 0o644 }) & 0o777;

        match etype {
            EntryType::Directory => {
                if let Some(existing) = seen_non_dir_folded.get(&folded) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!("directory conflicts with existing non-directory {existing:?}"),
                    });
                }
                ensure_dirs_platform(
                    #[cfg(target_os = "linux")]
                    &root_fd,
                    #[cfg(not(target_os = "linux"))]
                    dest_root,
                    &comps,
                )?;
                record_dir_prefixes(&mut created_dirs, &comps, opts.path_policy);
                deferred_dir_modes.push((norm_path, mode));
            }

            EntryType::Regular | EntryType::GNUSparse => {
                if etype == EntryType::GNUSparse {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: "GNU sparse tar entries are not supported".into(),
                    });
                }
                if created_dirs.contains(&folded) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: "regular file conflicts with existing directory".into(),
                    });
                }
                if let Some(prev) = seen_non_dir_folded.insert(folded, norm_path.clone()) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!("duplicate or colliding entry with {prev:?}"),
                    });
                }

                let header_size = entry.header().size().map_err(|e| StoreError::UnsafeTarEntry {
                    path: norm_path.clone(),
                    reason: format!("invalid file size header: {e}"),
                })?;
                if header_size > opts.max_file_bytes {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!(
                            "file size {header_size} exceeds max_file_bytes ({})",
                            opts.max_file_bytes
                        ),
                    });
                }
                if total_bytes.saturating_add(header_size) > opts.max_total_bytes {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!(
                            "cumulative archive size exceeds max_total_bytes ({})",
                            opts.max_total_bytes
                        ),
                    });
                }

                let parents = &comps[..comps.len() - 1];
                if !parents.is_empty() {
                    ensure_dirs_platform(
                        #[cfg(target_os = "linux")]
                        &root_fd,
                        #[cfg(not(target_os = "linux"))]
                        dest_root,
                        parents,
                    )?;
                    record_dir_prefixes(&mut created_dirs, parents, opts.path_policy);
                }

                let written = write_regular_file_platform(
                    #[cfg(target_os = "linux")]
                    &root_fd,
                    #[cfg(not(target_os = "linux"))]
                    dest_root,
                    &norm_path,
                    &mut entry,
                    mode,
                    opts.max_file_bytes.min(opts.max_total_bytes - total_bytes),
                )?;
                total_bytes = total_bytes.saturating_add(written);
                created_files.insert(norm_path.clone());
                if opts.reject_dotgit {
                    all_patch_entries.push(PatchEntry::file(norm_path));
                }
            }

            EntryType::Symlink => {
                if created_dirs.contains(&folded) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: "symlink conflicts with existing directory".into(),
                    });
                }
                if let Some(prev) = seen_non_dir_folded.insert(folded.clone(), norm_path.clone()) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!("duplicate or colliding symlink with {prev:?}"),
                    });
                }
                let link_bytes = entry
                    .link_name_bytes()
                    .ok_or_else(|| StoreError::UnsafeTarEntry {
                        path: norm_path.clone(),
                        reason: "symlink entry missing link target".into(),
                    })?
                    .into_owned();
                let target =
                    std::str::from_utf8(&link_bytes).map_err(|_| StoreError::UnsafeTarEntry {
                        path: norm_path.clone(),
                        reason: "non-UTF-8 symlink target".into(),
                    })?;

                check_symlink_entry(&norm_path, target, opts)?;

                let parents = &comps[..comps.len() - 1];
                if !parents.is_empty() {
                    ensure_dirs_platform(
                        #[cfg(target_os = "linux")]
                        &root_fd,
                        #[cfg(not(target_os = "linux"))]
                        dest_root,
                        parents,
                    )?;
                    record_dir_prefixes(&mut created_dirs, parents, opts.path_policy);
                }

                create_symlink_platform(
                    #[cfg(target_os = "linux")]
                    &root_fd,
                    #[cfg(not(target_os = "linux"))]
                    dest_root,
                    &comps,
                    target,
                )?;
                created_symlinks.insert(folded, (norm_path.clone(), target.to_owned()));
                all_patch_entries.push(PatchEntry::symlink(norm_path, target.to_owned()));
            }

            EntryType::Link => {
                if created_dirs.contains(&folded) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: "hardlink conflicts with existing directory".into(),
                    });
                }
                if let Some(prev) = seen_non_dir_folded.insert(folded, norm_path.clone()) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!("duplicate or colliding hardlink with {prev:?}"),
                    });
                }
                let link_bytes = entry
                    .link_name_bytes()
                    .ok_or_else(|| StoreError::UnsafeTarEntry {
                        path: norm_path.clone(),
                        reason: "hardlink entry missing link target".into(),
                    })?
                    .into_owned();
                let target_norm = normalize_tar_path(&link_bytes, false, opts)?.ok_or_else(|| {
                    StoreError::UnsafeTarEntry {
                        path: norm_path.clone(),
                        reason: "hardlink cannot target root '.'".into(),
                    }
                })?;
                if !created_files.contains(&target_norm) {
                    return Err(StoreError::UnsafeTarEntry {
                        path: norm_path,
                        reason: format!(
                            "hardlink target {target_norm:?} does not refer to an already-unpacked regular file"
                        ),
                    });
                }

                let parents = &comps[..comps.len() - 1];
                if !parents.is_empty() {
                    ensure_dirs_platform(
                        #[cfg(target_os = "linux")]
                        &root_fd,
                        #[cfg(not(target_os = "linux"))]
                        dest_root,
                        parents,
                    )?;
                    record_dir_prefixes(&mut created_dirs, parents, opts.path_policy);
                }

                let src_comps: Vec<&str> = target_norm.split('/').collect();
                create_hardlink_platform(
                    #[cfg(target_os = "linux")]
                    &root_fd,
                    #[cfg(not(target_os = "linux"))]
                    dest_root,
                    &src_comps,
                    &comps,
                )?;
                created_files.insert(norm_path.clone());
                if opts.reject_dotgit {
                    all_patch_entries.push(PatchEntry::file(norm_path));
                }
            }

            EntryType::Fifo | EntryType::Char | EntryType::Block => {
                return Err(StoreError::UnsafeTarEntry {
                    path: norm_path,
                    reason: format!("special device/FIFO tar entry ({etype:?}) is forbidden"),
                });
            }

            other => {
                return Err(StoreError::UnsafeTarEntry {
                    path: norm_path,
                    reason: format!("unsupported tar entry type ({other:?})"),
                });
            }
        }
    }

    // Whole-archive validation pass: catches reverse-order symlink chains and Unicode-NFD /
    // case-folding collisions across all entries.
    if !all_patch_entries.is_empty() {
        let validator = PatchPathValidator::new(opts.path_policy);
        Untrusted::new(PatchSet {
            entries: all_patch_entries,
        })
        .validate(&validator)
        .map_err(|e| StoreError::UnsafeTarEntry {
            path: e.path,
            reason: e.kind.to_string(),
        })?;
    }

    // Apply deferred directory modes bottom-up (deepest paths first) so restrictive modes like
    // `0o555` do not block unpacking children.
    deferred_dir_modes.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
    for (dir_path, mode) in deferred_dir_modes {
        let comps: Vec<&str> = dir_path.split('/').collect();
        apply_dir_mode_platform(
            #[cfg(target_os = "linux")]
            &root_fd,
            #[cfg(not(target_os = "linux"))]
            dest_root,
            &comps,
            mode,
        )?;
    }

    Ok(())
}

fn record_dir_prefixes(dirs: &mut HashSet<String>, comps: &[&str], policy: PathPolicy) {
    let mut prefix = String::new();
    for (i, c) in comps.iter().enumerate() {
        if i > 0 {
            prefix.push('/');
        }
        prefix.push_str(c);
        dirs.insert(fold_key(&prefix, policy));
    }
}

fn copy_bounded<R: Read, W: Write>(reader: &mut R, writer: &mut W, limit: u64, path: &str) -> Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut written: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| StoreError::io(format!("reading tar payload for {path:?}"), e))?;
        if n == 0 {
            break;
        }
        written = written.saturating_add(n as u64);
        if written > limit {
            return Err(StoreError::UnsafeTarEntry {
                path: path.to_owned(),
                reason: format!("payload exceeded byte limit ({limit})"),
            });
        }
        writer
            .write_all(&buf[..n])
            .map_err(|e| StoreError::io_or_enospc(format!("writing tar file {path:?}"), e))?;
    }
    Ok(written)
}

#[cfg(target_os = "linux")]
fn ensure_dirs_platform(root_fd: &std::os::fd::OwnedFd, comps: &[&str]) -> Result<()> {
    crate::openat2::linux_impl::walk_or_create_dirs(root_fd, comps, true)
        .map(|_| ())
        .map_err(|e| StoreError::io_or_enospc(format!("creating directory {:?}", comps.join("/")), e))
}

#[cfg(not(target_os = "linux"))]
fn ensure_dirs_platform(dest_root: &Path, comps: &[&str]) -> Result<()> {
    let mut cur = dest_root.to_path_buf();
    for seg in comps {
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(md) => {
                if md.file_type().is_symlink() || !md.is_dir() {
                    return Err(StoreError::UnsafeTarEntry {
                        path: comps.join("/"),
                        reason: format!("path component {seg:?} is not a real directory"),
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur).map_err(|e| {
                    StoreError::io_or_enospc(format!("creating dir {}", cur.display()), e)
                })?;
            }
            Err(e) => {
                return Err(StoreError::io(format!("stat {}", cur.display()), e));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_regular_file_platform<R: Read>(
    root_fd: &std::os::fd::OwnedFd,
    norm_path: &str,
    reader: &mut R,
    mode: u32,
    limit: u64,
) -> Result<u64> {
    let mut file = crate::openat2::linux_impl::create_file_in_root(root_fd, norm_path)
        .map_err(|e| StoreError::io_or_enospc(format!("openat2 create {norm_path:?}"), e))?;
    let written = copy_bounded(reader, &mut file, limit, norm_path)?;
    crate::openat2::linux_impl::fchmod_sanitized(&file, mode)
        .map_err(|e| StoreError::io(format!("fchmod {norm_path:?}"), e))?;
    Ok(written)
}

#[cfg(not(target_os = "linux"))]
fn write_regular_file_platform<R: Read>(
    dest_root: &Path,
    norm_path: &str,
    reader: &mut R,
    mode: u32,
    limit: u64,
) -> Result<u64> {
    let dst = join_relative(dest_root, norm_path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&dst)
        .map_err(|e| StoreError::io_or_enospc(format!("creating file {}", dst.display()), e))?;
    let written = copy_bounded(reader, &mut file, limit, norm_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode & 0o777);
        file.set_permissions(perms)
            .map_err(|e| StoreError::io(format!("chmod {}", dst.display()), e))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(written)
}

#[cfg(target_os = "linux")]
fn create_symlink_platform(
    root_fd: &std::os::fd::OwnedFd,
    comps: &[&str],
    target: &str,
) -> Result<()> {
    let (&leaf, parents) = comps.split_last().ok_or_else(|| StoreError::UnsafeTarEntry {
        path: String::new(),
        reason: "empty symlink path".into(),
    })?;
    let parent_fd = crate::openat2::linux_impl::walk_or_create_dirs(root_fd, parents, false)
        .map_err(|e| StoreError::io(format!("opening symlink parent {:?}", parents.join("/")), e))?;
    crate::openat2::linux_impl::create_symlink_in_dir(&parent_fd, leaf, target).map_err(|e| {
        StoreError::io_or_enospc(format!("symlinkat {:?} -> {target:?}", comps.join("/")), e)
    })
}

#[cfg(not(target_os = "linux"))]
fn create_symlink_platform(dest_root: &Path, comps: &[&str], target: &str) -> Result<()> {
    let dst = join_components(dest_root, comps);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, &dst)
            .map_err(|e| StoreError::io_or_enospc(format!("symlink {}", dst.display()), e))
    }
    #[cfg(windows)]
    {
        // On Windows developer hosts without SeCreateSymbolicLinkPrivilege, symlink creation may
        // fail with ERROR_PRIVILEGE_NOT_HELD (1314). Surface the OS error clearly.
        std::os::windows::fs::symlink_file(target, &dst)
            .map_err(|e| StoreError::io_or_enospc(format!("symlink {}", dst.display()), e))
    }
}

#[cfg(target_os = "linux")]
fn create_hardlink_platform(
    root_fd: &std::os::fd::OwnedFd,
    src_comps: &[&str],
    dst_comps: &[&str],
) -> Result<()> {
    crate::openat2::linux_impl::create_hardlink_in_root(root_fd, src_comps, dst_comps).map_err(|e| {
        StoreError::io_or_enospc(
            format!("linkat {:?} -> {:?}", src_comps.join("/"), dst_comps.join("/")),
            e,
        )
    })
}

#[cfg(not(target_os = "linux"))]
fn create_hardlink_platform(
    dest_root: &Path,
    src_comps: &[&str],
    dst_comps: &[&str],
) -> Result<()> {
    let src = join_components(dest_root, src_comps);
    let dst = join_components(dest_root, dst_comps);
    let md = std::fs::symlink_metadata(&src)
        .map_err(|e| StoreError::io(format!("lstat hardlink target {}", src.display()), e))?;
    if !md.is_file() || md.file_type().is_symlink() {
        return Err(StoreError::UnsafeTarEntry {
            path: dst_comps.join("/"),
            reason: "hardlink target is not a regular file".into(),
        });
    }
    std::fs::hard_link(&src, &dst).map_err(|e| {
        StoreError::io_or_enospc(format!("hard_link {} -> {}", src.display(), dst.display()), e)
    })
}

#[cfg(target_os = "linux")]
fn apply_dir_mode_platform(
    root_fd: &std::os::fd::OwnedFd,
    comps: &[&str],
    mode: u32,
) -> Result<()> {
    let dir_fd = crate::openat2::linux_impl::walk_or_create_dirs(root_fd, comps, false)
        .map_err(|e| StoreError::io(format!("opening dir {:?} for chmod", comps.join("/")), e))?;
    crate::openat2::linux_impl::fchmod_sanitized(&dir_fd, mode)
        .map_err(|e| StoreError::io(format!("fchmod dir {:?}", comps.join("/")), e))
}

#[cfg(not(target_os = "linux"))]
fn apply_dir_mode_platform(_dest_root: &Path, _comps: &[&str], _mode: u32) -> Result<()> {
    // Non-Linux dev host (Windows): directory POSIX mode bits are not enforced.
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn join_relative(root: &Path, norm_path: &str) -> std::path::PathBuf {
    let mut p = root.to_path_buf();
    for seg in norm_path.split('/') {
        p.push(seg);
    }
    p
}

#[cfg(not(target_os = "linux"))]
fn join_components(root: &Path, comps: &[&str]) -> std::path::PathBuf {
    let mut p = root.to_path_buf();
    for seg in comps {
        p.push(seg);
    }
    p
}
