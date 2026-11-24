//! Clean storage (`TreeBackend`) and sandbox (`SandboxBackend`) trait interfaces for `agentd`,
//! designed so `aos-store`'s Btrfs `TreeStore` and `aos-sandbox`'s `NamespaceDriver` plug in
//! directly without changing control-plane orchestration.
//!
//! Also provides safe cross-platform local/in-memory implementations (`LocalDevTreeBackend`,
//! `InMemorySandboxBackend`) used by control-plane tests and development environments; even in
//! dev mode, `LocalDevTreeBackend` enforces `PersistProof::fsync_subvolume` and
//! `Untrusted<RawPatch>` -> `PatchPathValidator`!

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aos_types::patch_path::{BaseKind, BaseTree, PatchEntry, PatchPathValidator, PatchSet};
use aos_types::{PersistProof, Untrusted, WorldId};
use tokio::sync::mpsc;

use crate::error::BackendError;
use crate::proto::{BoundedOutput, DriverKind, OutputStreamKind};

/// One validated file change entry in an exported patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPatchEntry {
    /// Repository-relative POSIX path (validated through `PatchPathValidator`).
    pub path: String,
    /// `"add"` | `"modify"` | `"delete"`.
    pub kind: &'static str,
    /// Size in bytes (0 for deletes).
    pub size_bytes: u64,
}

/// Validated patch bundle returned by [`TreeBackend::export_patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPatchBundle {
    /// Unified diff text bytes.
    pub unified_diff: Vec<u8>,
    /// Validated per-file change summary.
    pub entries: Vec<ValidatedPatchEntry>,
    /// Hex-encoded BLAKE3 digest of `unified_diff`.
    pub blake3_hex: String,
}

/// Storage backend interface for `TreeStore` (Phase 1 cold fork).
pub trait TreeBackend: Send + Sync {
    /// Safely unpack a tar byte stream into a sealed subvolume at `target_path` and return its
    /// [`PersistProof`] (`ProofKind::Subvolume`).
    fn import_tar(&self, target_path: &Path, tar_bytes: &[u8]) -> Result<PersistProof, BackendError>;

    /// Create an O(1) writable clone of `base_path` for `world_id` and return the live root path.
    fn create_writable_clone(
        &self,
        base_path: &Path,
        world_id: WorldId,
    ) -> Result<PathBuf, BackendError>;

    /// Snapshot `live_path` into a sealed read-only subvolume at `target_path` and return its
    /// [`PersistProof`] (`ProofKind::Subvolume`).
    fn snapshot_readonly(
        &self,
        live_path: &Path,
        target_path: &Path,
    ) -> Result<PersistProof, BackendError>;

    /// Destroy a subvolume or writable world root (idempotent on `NotFound`).
    fn destroy_subvolume(&self, path: &Path) -> Result<(), BackendError>;

    /// Compute and validate a zero-trust patch bundle from `base_path` to `target_path`.
    /// Every implementation MUST validate all paths through `Untrusted` + `PatchPathValidator`.
    fn export_patch(
        &self,
        base_path: &Path,
        target_path: &Path,
    ) -> Result<ValidatedPatchBundle, BackendError>;
}

/// Specification handed to [`SandboxBackend::spawn_world`].
#[derive(Debug, Clone)]
pub struct SpawnWorldSpec {
    /// World id.
    pub world_id: WorldId,
    /// Requested driver (`Namespace` / `Firecracker`).
    pub driver: DriverKind,
    /// Writable rootfs path created by [`TreeBackend::create_writable_clone`].
    pub rootfs_path: PathBuf,
}

/// Command request handed to [`SandboxBackend::exec`].
#[derive(Debug, Clone)]
pub struct SandboxExecRequest {
    /// Unique exec id for sub-cgroup isolation.
    pub exec_id: String,
    /// Command argv (non-empty).
    pub argv: Vec<String>,
    /// Extra environment variables.
    pub env: BTreeMap<String, String>,
    /// Optional working directory inside the sandbox.
    pub cwd: Option<String>,
    /// Execution timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum retained bytes per output stream.
    pub max_output_bytes: usize,
    /// Whether to emit live [`SandboxOutputChunk`]s over the channel.
    pub stream: bool,
}

/// One streamed stdout/stderr chunk from `aos-guest`.
#[derive(Debug, Clone)]
pub struct SandboxOutputChunk {
    /// Stdout or stderr.
    pub stream: OutputStreamKind,
    /// Monotonic sequence number.
    pub seq: u64,
    /// Chunk bytes.
    pub data: Vec<u8>,
}

/// Terminal execution result returned by [`SandboxBackend::exec`].
#[derive(Debug, Clone)]
pub struct SandboxExecResult {
    /// Exec id.
    pub exec_id: String,
    /// Exit code, if exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal, if killed by signal.
    pub signal: Option<i32>,
    /// True iff killed due to timeout.
    pub timed_out: bool,
    /// True iff `cgroup.kill` actually terminated live processes or forced teardown ran.
    pub cgroup_killed: bool,
    /// Elapsed wall duration in ms.
    pub duration_ms: u64,
    /// Bounded stdout.
    pub stdout: BoundedOutput,
    /// Bounded stderr.
    pub stderr: BoundedOutput,
}

/// Sandbox driver interface (`NamespaceDriver` in Phase 1, `FirecrackerDriver` in Phase 2).
pub trait SandboxBackend: Send + Sync {
    /// Enabled driver names reported in `SystemService::NegotiateVersion`.
    fn enabled_drivers(&self) -> Vec<String>;

    /// Spawn a live sandbox for `spec` and verify `aos-guest` readiness (`Ping -> Pong`).
    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<(), BackendError>;

    /// Execute a command inside `world_id` via `aos-guest`, streaming chunks to `chunk_tx`.
    fn exec(
        &self,
        world_id: WorldId,
        req: SandboxExecRequest,
        chunk_tx: mpsc::Sender<SandboxOutputChunk>,
    ) -> Result<SandboxExecResult, BackendError>;

    /// Freeze workload cgroup and optionally flush dirty filesystem pages (`syncfs`).
    /// Returns `disk_clean` (`true` iff `perform_syncfs` was requested and succeeded).
    fn freeze_and_sync(&self, world_id: WorldId, perform_syncfs: bool) -> Result<bool, BackendError>;

    /// Unfreeze workload cgroup after snapshot capture completes (or fails).
    fn unfreeze(&self, world_id: WorldId) -> Result<(), BackendError>;

    /// Deterministically destroy the sandbox (`cgroup.kill` + `netns` teardown; idempotent).
    fn destroy_world(&self, world_id: WorldId) -> Result<(), BackendError>;
}

// ============================================================================
// LocalDevTreeBackend: safe cross-platform directory-based implementation
// ============================================================================

/// Cross-platform filesystem tree backend for control-plane integration tests and local dev
/// until `aos-store`'s Btrfs `TreeStore` is plugged in.
///
/// Enforces:
/// * Safe tar extraction (regular files & directories only; rejects `..`, absolute paths,
///   symlinks, hardlinks, device nodes, and `.git` via `PatchPathValidator`).
/// * Genuine `PersistProof::fsync_subvolume` on every imported/snapshotted frame.
/// * Mandatory `Untrusted<RawDiff>` -> `PatchPathValidator` validation on every `export_patch`.
#[derive(Debug, Clone)]
pub struct LocalDevTreeBackend {
    worlds_root: PathBuf,
}

impl LocalDevTreeBackend {
    /// Create a local tree backend storing writable world clones under `worlds_root`.
    pub fn new(worlds_root: impl Into<PathBuf>) -> Self {
        Self {
            worlds_root: worlds_root.into(),
        }
    }

    /// Canonical writable directory path for `world_id`.
    #[must_use]
    pub fn world_path(&self, world_id: WorldId) -> PathBuf {
        self.worlds_root.join(format!("w-{world_id}"))
    }
}

/// Minimal USTAR tar extractor supporting regular files (`0` / `\0`) and directories (`5`).
/// Rejects symlinks, hardlinks, devices, FIFOs, PAX global escape tricks, and unsafe paths.
fn extract_ustar_safely(target_dir: &Path, tar_bytes: &[u8]) -> Result<(), BackendError> {
    if tar_bytes.is_empty() {
        return Err(BackendError::InvalidArgument("empty tar stream".into()));
    }
    if !tar_bytes.len().is_multiple_of(512) {
        return Err(BackendError::InvalidArgument(format!(
            "tar stream length {} is not a multiple of 512 bytes",
            tar_bytes.len()
        )));
    }
    fs::create_dir_all(target_dir)
        .map_err(|e| BackendError::Internal(format!("create {}: {e}", target_dir.display())))?;

    let validator = PatchPathValidator::default();
    let mut entries = Vec::new();
    let mut parsed_files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut parsed_dirs: Vec<String> = Vec::new();

    let mut pos = 0usize;
    while pos + 512 <= tar_bytes.len() {
        let hdr = &tar_bytes[pos..pos + 512];
        pos += 512;
        if hdr.iter().all(|&b| b == 0) {
            break;
        }
        let name = read_cstr(&hdr[0..100]);
        let prefix = read_cstr(&hdr[345..500]);
        let full_raw = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let cleaned = full_raw
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_owned();

        let size_str = read_cstr(&hdr[124..136]);
        let size = parse_octal(&size_str)?;
        let padded = size.div_ceil(512) * 512;
        if pos + padded > tar_bytes.len() {
            return Err(BackendError::InvalidArgument(
                "truncated tar entry payload".into(),
            ));
        }
        let payload = &tar_bytes[pos..pos + size];
        pos += padded;

        let typeflag = hdr[156];
        match typeflag {
            b'5' => {
                if !cleaned.is_empty() && cleaned != "." {
                    entries.push(PatchEntry::file(format!("{cleaned}/.dircheck")));
                    parsed_dirs.push(cleaned);
                }
            }
            b'0' | 0 => {
                if cleaned.is_empty() || cleaned == "." {
                    return Err(BackendError::InvalidArgument(
                        "tar regular file entry has empty path".into(),
                    ));
                }
                entries.push(PatchEntry::file(cleaned.clone()));
                parsed_files.push((cleaned, payload.to_vec()));
            }
            other => {
                return Err(BackendError::UnsafePatch(format!(
                    "unsupported/unsafe tar entry type 0x{other:02x} for {full_raw:?}"
                )));
            }
        }
    }

    // Validate EVERY path through `Untrusted<PatchSet>` + `PatchPathValidator` BEFORE touching disk!
    let _validated = Untrusted::new(PatchSet { entries })
        .validate(&validator)
        .map_err(|e| BackendError::UnsafePatch(e.to_string()))?;

    for d in parsed_dirs {
        fs::create_dir_all(target_dir.join(&d))
            .map_err(|e| BackendError::Internal(format!("mkdir {d}: {e}")))?;
    }
    for (rel, data) in parsed_files {
        let dest = target_dir.join(&rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| BackendError::Internal(format!("mkdir parent of {rel}: {e}")))?;
        }
        fs::write(&dest, &data)
            .map_err(|e| BackendError::Internal(format!("write {rel}: {e}")))?;
    }
    Ok(())
}

fn read_cstr(slice: &[u8]) -> String {
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).trim().to_owned()
}

fn parse_octal(s: &str) -> Result<usize, BackendError> {
    let trimmed = s.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0');
    if trimmed.is_empty() {
        return Ok(0);
    }
    usize::from_str_radix(trimmed, 8)
        .map_err(|e| BackendError::InvalidArgument(format!("invalid tar octal size {s:?}: {e}")))
}

fn copy_dir_no_symlinks(src: &Path, dst: &Path) -> Result<(), BackendError> {
    fs::create_dir_all(dst)
        .map_err(|e| BackendError::Internal(format!("create {}: {e}", dst.display())))?;
    for entry in fs::read_dir(src)
        .map_err(|e| BackendError::Internal(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| BackendError::Internal(e.to_string()))?;
        let sp = entry.path();
        let dp = dst.join(entry.file_name());
        let md = fs::symlink_metadata(&sp)
            .map_err(|e| BackendError::Internal(format!("lstat {}: {e}", sp.display())))?;
        if md.file_type().is_symlink() {
            return Err(BackendError::UnsafePatch(format!(
                "refusing to copy symlink {}",
                sp.display()
            )));
        }
        if md.is_dir() {
            copy_dir_no_symlinks(&sp, &dp)?;
        } else if md.is_file() {
            fs::copy(&sp, &dp)
                .map_err(|e| BackendError::Internal(format!("copy {}: {e}", sp.display())))?;
        }
    }
    Ok(())
}

fn walk_regular_files(
    root: &Path,
    cur: &Path,
    out: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), BackendError> {
    if !cur.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(cur)
        .map_err(|e| BackendError::Internal(format!("read_dir {}: {e}", cur.display())))?
    {
        let entry = entry.map_err(|e| BackendError::Internal(e.to_string()))?;
        let p = entry.path();
        let md = fs::symlink_metadata(&p)
            .map_err(|e| BackendError::Internal(format!("lstat {}: {e}", p.display())))?;
        if md.file_type().is_symlink() {
            return Err(BackendError::UnsafePatch(format!(
                "symlink encountered during patch walk: {}",
                p.display()
            )));
        }
        if md.is_dir() {
            walk_regular_files(root, &p, out)?;
        } else if md.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| BackendError::Internal(e.to_string()))?;
            let posix = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let data = fs::read(&p)
                .map_err(|e| BackendError::Internal(format!("read {}: {e}", p.display())))?;
            out.insert(posix, data);
        }
    }
    Ok(())
}

impl TreeBackend for LocalDevTreeBackend {
    fn import_tar(&self, target_path: &Path, tar_bytes: &[u8]) -> Result<PersistProof, BackendError> {
        extract_ustar_safely(target_path, tar_bytes)?;
        PersistProof::fsync_subvolume(target_path)
            .map_err(|e| BackendError::Internal(format!("fsync_subvolume {}: {e}", target_path.display())))
    }

    fn create_writable_clone(
        &self,
        base_path: &Path,
        world_id: WorldId,
    ) -> Result<PathBuf, BackendError> {
        let dst = self.world_path(world_id);
        let _ = fs::remove_dir_all(&dst);
        copy_dir_no_symlinks(base_path, &dst)?;
        Ok(dst)
    }

    fn snapshot_readonly(
        &self,
        live_path: &Path,
        target_path: &Path,
    ) -> Result<PersistProof, BackendError> {
        let _ = fs::remove_dir_all(target_path);
        copy_dir_no_symlinks(live_path, target_path)?;
        PersistProof::fsync_subvolume(target_path)
            .map_err(|e| BackendError::Internal(format!("fsync_subvolume {}: {e}", target_path.display())))
    }

    fn destroy_subvolume(&self, path: &Path) -> Result<(), BackendError> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(BackendError::Internal(format!("remove {}: {e}", path.display()))),
        }
    }

    fn export_patch(
        &self,
        base_path: &Path,
        target_path: &Path,
    ) -> Result<ValidatedPatchBundle, BackendError> {
        let mut base_files = BTreeMap::new();
        let mut target_files = BTreeMap::new();
        walk_regular_files(base_path, base_path, &mut base_files)?;
        walk_regular_files(target_path, target_path, &mut target_files)?;

        let all_keys: BTreeSet<String> = base_files
            .keys()
            .chain(target_files.keys())
            .cloned()
            .collect();

        let mut raw_ops = Vec::new();
        let mut raw_entries = Vec::new();
        let mut diff = String::new();

        for path in all_keys {
            match (base_files.get(&path), target_files.get(&path)) {
                (None, Some(new_bytes)) => {
                    raw_ops.push(PatchEntry::file(path.clone()));
                    raw_entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind: "add",
                        size_bytes: new_bytes.len() as u64,
                    });
                    diff.push_str(&format!("--- /dev/null\n+++ b/{path}\n"));
                    for line in String::from_utf8_lossy(new_bytes).lines() {
                        diff.push('+');
                        diff.push_str(line);
                        diff.push('\n');
                    }
                }
                (Some(old_bytes), None) => {
                    raw_ops.push(PatchEntry::remove(path.clone()));
                    raw_entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind: "delete",
                        size_bytes: 0,
                    });
                    diff.push_str(&format!("--- a/{path}\n+++ /dev/null\n"));
                    for line in String::from_utf8_lossy(old_bytes).lines() {
                        diff.push('-');
                        diff.push_str(line);
                        diff.push('\n');
                    }
                }
                (Some(old_bytes), Some(new_bytes)) if old_bytes != new_bytes => {
                    raw_ops.push(PatchEntry::file(path.clone()));
                    raw_entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind: "modify",
                        size_bytes: new_bytes.len() as u64,
                    });
                    diff.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
                    for line in String::from_utf8_lossy(old_bytes).lines() {
                        diff.push('-');
                        diff.push_str(line);
                        diff.push('\n');
                    }
                    for line in String::from_utf8_lossy(new_bytes).lines() {
                        diff.push('+');
                        diff.push_str(line);
                        diff.push('\n');
                    }
                }
                _ => {}
            }
        }

        // Mandatory zero-trust validation through Untrusted<PatchSet> + PatchPathValidator (with base tree)!
        let base_tree = BaseTree::from_entries(base_files.keys().map(|p| (p.clone(), BaseKind::File)));
        let validator = PatchPathValidator::default().with_base_tree(base_tree);
        let _validated = Untrusted::new(PatchSet { entries: raw_ops })
            .validate(&validator)
            .map_err(|e| BackendError::UnsafePatch(e.to_string()))?;

        let diff_bytes = diff.into_bytes();
        let blake3_hex = blake3::hash(&diff_bytes).to_hex().to_string();
        Ok(ValidatedPatchBundle {
            unified_diff: diff_bytes,
            entries: raw_entries,
            blake3_hex,
        })
    }
}

/// Build a valid USTAR tar archive from `(path, content)` pairs (helper for tests & CLI).
#[must_use]
pub fn build_ustar_archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, data) in files {
        let mut hdr = [0u8; 512];
        let pbytes = path.as_bytes();
        let copy_len = pbytes.len().min(100);
        hdr[..copy_len].copy_from_slice(&pbytes[..copy_len]);
        hdr[100..108].copy_from_slice(b"0000644\0");
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");
        let size_oct = format!("{:011o}\0", data.len());
        hdr[124..136].copy_from_slice(size_oct.as_bytes());
        hdr[136..148].copy_from_slice(b"00000000000\0");
        hdr[148..156].copy_from_slice(b"        ");
        hdr[156] = b'0';
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        let csum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
        let csum_str = format!("{csum:06o}\0 ");
        hdr[148..156].copy_from_slice(csum_str.as_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
        let rem = data.len() % 512;
        if rem != 0 {
            out.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
    }
    out.extend(std::iter::repeat_n(0u8, 1024));
    out
}

// ============================================================================
// InMemorySandboxBackend: deterministic mock sandbox driver for control-plane tests
// ============================================================================

#[derive(Debug, Clone)]
struct LiveWorld {
    rootfs_path: PathBuf,
    frozen: bool,
}

/// Deterministic cross-platform sandbox backend for Phase 1 control-plane testing prior to
/// plugging in `aos-sandbox::NamespaceDriver`.
///
/// Supports synthetic commands inside the world's `rootfs_path`:
/// * `echo <args...>` -> streams joined args on stdout
/// * `write-file <rel_path> <content>` -> writes a file inside `rootfs_path` (for Checkpoint/ExportPatch tests!)
/// * `fail <exit_code>` -> emits stderr and exits non-zero
/// * any other argv -> echoes `exec: <argv>` on stdout
#[derive(Debug, Default)]
pub struct InMemorySandboxBackend {
    worlds: Mutex<BTreeMap<WorldId, LiveWorld>>,
}

impl InMemorySandboxBackend {
    /// Construct an empty sandbox backend advertising the `namespace` driver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SandboxBackend for InMemorySandboxBackend {
    fn enabled_drivers(&self) -> Vec<String> {
        vec!["namespace".to_owned()]
    }

    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<(), BackendError> {
        if spec.driver == DriverKind::Firecracker {
            return Err(BackendError::DriverUnavailable(
                "firecracker driver lands in Phase 2; use namespace driver in Phase 1".into(),
            ));
        }
        self.worlds.lock().unwrap().insert(
            spec.world_id,
            LiveWorld {
                rootfs_path: spec.rootfs_path,
                frozen: false,
            },
        );
        Ok(())
    }

    fn exec(
        &self,
        world_id: WorldId,
        req: SandboxExecRequest,
        chunk_tx: mpsc::Sender<SandboxOutputChunk>,
    ) -> Result<SandboxExecResult, BackendError> {
        let rootfs = {
            let worlds = self.worlds.lock().unwrap();
            let w = worlds
                .get(&world_id)
                .ok_or(BackendError::WorldNotRunning(world_id))?;
            if w.frozen {
                return Err(BackendError::InvalidArgument(
                    "world is currently frozen for checkpoint".into(),
                ));
            }
            w.rootfs_path.clone()
        };
        if req.argv.is_empty() {
            return Err(BackendError::InvalidArgument("argv must not be empty".into()));
        }

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut exit_code = 0i32;

        match req.argv[0].as_str() {
            "echo" => {
                stdout_bytes = format!("{}\n", req.argv[1..].join(" ")).into_bytes();
            }
            "write-file" => {
                if req.argv.len() < 3 {
                    return Err(BackendError::InvalidArgument(
                        "write-file requires <rel_path> <content>".into(),
                    ));
                }
                let rel = &req.argv[1];
                let content = req.argv[2..].join(" ");
                let validator = PatchPathValidator::default();
                validator
                    .validate_entries(&[PatchEntry::file(rel.clone())])
                    .map_err(|e| BackendError::UnsafePatch(e.to_string()))?;
                let dest = rootfs.join(rel);
                if let Some(p) = dest.parent() {
                    fs::create_dir_all(p)
                        .map_err(|e| BackendError::Internal(format!("mkdir: {e}")))?;
                }
                fs::write(&dest, content.as_bytes())
                    .map_err(|e| BackendError::Internal(format!("write: {e}")))?;
                stdout_bytes = format!("wrote {rel} ({} bytes)\n", content.len()).into_bytes();
            }
            "fail" => {
                exit_code = req
                    .argv
                    .get(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(1);
                stderr_bytes = format!("command failed with exit {exit_code}\n").into_bytes();
            }
            _ => {
                stdout_bytes = format!("exec: {}\n", req.argv.join(" ")).into_bytes();
            }
        }

        if req.stream {
            if !stdout_bytes.is_empty() {
                let _ = chunk_tx.try_send(SandboxOutputChunk {
                    stream: OutputStreamKind::OutputStreamStdout,
                    seq: 0,
                    data: stdout_bytes.clone(),
                });
            }
            if !stderr_bytes.is_empty() {
                let _ = chunk_tx.try_send(SandboxOutputChunk {
                    stream: OutputStreamKind::OutputStreamStderr,
                    seq: 1,
                    data: stderr_bytes.clone(),
                });
            }
        }

        let bound = |bytes: Vec<u8>| -> BoundedOutput {
            let total = bytes.len() as u64;
            if bytes.len() <= req.max_output_bytes || req.max_output_bytes == 0 {
                BoundedOutput {
                    head: bytes,
                    tail: Vec::new(),
                    total_bytes: total,
                    omitted_bytes: 0,
                    truncated: false,
                }
            } else {
                let half = req.max_output_bytes / 2;
                let head = bytes[..half].to_vec();
                let tail = bytes[bytes.len() - (req.max_output_bytes - half)..].to_vec();
                let omitted = total - (head.len() + tail.len()) as u64;
                BoundedOutput {
                    head,
                    tail,
                    total_bytes: total,
                    omitted_bytes: omitted,
                    truncated: true,
                }
            }
        };

        Ok(SandboxExecResult {
            exec_id: req.exec_id,
            exit_code: Some(exit_code),
            signal: None,
            timed_out: false,
            cgroup_killed: false,
            duration_ms: 1,
            stdout: bound(stdout_bytes),
            stderr: bound(stderr_bytes),
        })
    }

    fn freeze_and_sync(&self, world_id: WorldId, perform_syncfs: bool) -> Result<bool, BackendError> {
        let mut worlds = self.worlds.lock().unwrap();
        let w = worlds
            .get_mut(&world_id)
            .ok_or(BackendError::WorldNotRunning(world_id))?;
        w.frozen = true;
        Ok(perform_syncfs)
    }

    fn unfreeze(&self, world_id: WorldId) -> Result<(), BackendError> {
        if let Some(w) = self.worlds.lock().unwrap().get_mut(&world_id) {
            w.frozen = false;
        }
        Ok(())
    }

    fn destroy_world(&self, world_id: WorldId) -> Result<(), BackendError> {
        self.worlds.lock().unwrap().remove(&world_id);
        Ok(())
    }
}
