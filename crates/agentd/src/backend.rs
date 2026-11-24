//! Clean storage (`TreeBackend`) and sandbox (`SandboxBackend`) trait interfaces for `agentd`,
//! designed so `aos-store`'s Btrfs `TreeStore` and `aos-sandbox`'s `NamespaceDriver` plug in
//! directly without changing control-plane orchestration.
//!
//! Also provides safe cross-platform local/in-memory implementations (`LocalDevTreeBackend`,
//! `InMemorySandboxBackend`) used by control-plane tests and development environments; even in
//! dev mode, `LocalDevTreeBackend` enforces `PersistProof::fsync_subvolume` and
//! `Untrusted<RawPatch>` -> `PatchPathValidator`!

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aos_guest::OutputStream;
use aos_meta::{ManagedObject, RecoveryHooks};
use aos_sandbox::{
    ExecRequest as SbxExecRequest, FreezeOptions, GuestAgentSource, NamespaceDriver, NetnsMode,
    SandboxDriver, SandboxError, SeccompPolicy, SpawnWorldSpec as DriverSpawnSpec, WorldHandle,
    DEFAULT_CGROUP_SLICE_ROOT, DEFAULT_HANDSHAKE_TIMEOUT,
};
use aos_store::{
    ExportPatchOptions, PatchFileChange, StoreError, TarImportOptions, TreeStore,
    TreeStoreRecoveryHooks,
};
use aos_types::patch_path::{BaseKind, BaseTree, PatchEntry, PatchPathValidator, PatchSet};
use aos_types::{EpochId, PersistProof, Untrusted, WorldId};
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

// ============================================================================
// Production Phase 1 Backends: TreeStoreBackend + ProductionRecoveryHooks + NamespaceSandboxBackend
// ============================================================================

/// Convert an [`aos_store::StoreError`] into a control-plane [`BackendError`].
#[must_use]
pub fn map_store_error(err: StoreError) -> BackendError {
    match err {
        StoreError::UnsafeTarEntry { .. }
        | StoreError::PatchValidation(_)
        | StoreError::OutsidePool { .. } => BackendError::UnsafePatch(err.to_string()),
        StoreError::NoSpace { .. } => BackendError::ResourceExhausted(err.to_string()),
        StoreError::InvalidName { .. } | StoreError::NotReadOnly { .. } => {
            BackendError::InvalidArgument(err.to_string())
        }
        StoreError::ForbiddenPoolRoot { .. }
        | StoreError::NotBtrfs { .. }
        | StoreError::QgroupsEnabled { .. }
        | StoreError::QgroupsCheckFailed { .. }
        | StoreError::AutodefragEnabled { .. }
        | StoreError::MountInfoCheckFailed { .. }
        | StoreError::AlreadyExists { .. }
        | StoreError::NotFound { .. }
        | StoreError::DiffError { .. }
        | StoreError::Io { .. } => BackendError::Internal(err.to_string()),
    }
}

/// Convert an [`aos_sandbox::SandboxError`] into a control-plane [`BackendError`].
#[must_use]
pub fn map_sandbox_error(err: SandboxError) -> BackendError {
    match err {
        SandboxError::UnsupportedPlatform(msg) => BackendError::DriverUnavailable(msg.to_owned()),
        SandboxError::InvalidConfig(msg) => BackendError::InvalidArgument(msg),
        SandboxError::WorldDestroyed => BackendError::Internal("world already destroyed".into()),
        SandboxError::SpawnFailed { .. }
        | SandboxError::Cgroup { .. }
        | SandboxError::HandshakeFailed(_)
        | SandboxError::ProtocolViolation(_)
        | SandboxError::GuestError { .. }
        | SandboxError::Codec(_)
        | SandboxError::Io(_) => BackendError::Internal(err.to_string()),
    }
}

/// Production [`TreeBackend`] wrapping [`aos_store::TreeStore`] (Btrfs subvolumes, `openat2`
/// confined tar unpack, O(1) writable snapshots, read-only checkpoints, and zero-trust
/// `export_patch`).
#[derive(Debug, Clone)]
pub struct TreeStoreBackend {
    store: TreeStore,
    tar_opts: TarImportOptions,
    patch_opts: ExportPatchOptions,
}

impl TreeStoreBackend {
    /// Construct a production tree backend around an open [`TreeStore`].
    pub fn new(store: TreeStore) -> Self {
        Self {
            store,
            tar_opts: TarImportOptions::default(),
            patch_opts: ExportPatchOptions::default(),
        }
    }

    /// Construct with custom tar import and patch export options.
    pub fn with_options(
        store: TreeStore,
        tar_opts: TarImportOptions,
        patch_opts: ExportPatchOptions,
    ) -> Self {
        Self {
            store,
            tar_opts,
            patch_opts,
        }
    }

    /// Underlying [`TreeStore`].
    #[must_use]
    pub fn store(&self) -> &TreeStore {
        &self.store
    }
}

impl TreeBackend for TreeStoreBackend {
    fn import_tar(&self, target_path: &Path, tar_bytes: &[u8]) -> Result<PersistProof, BackendError> {
        if tar_bytes.is_empty() {
            return Err(BackendError::InvalidArgument("empty tar stream".into()));
        }
        let target_name = target_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                BackendError::InvalidArgument(format!(
                    "invalid subvolume target path {}",
                    target_path.display()
                ))
            })?;
        let persisted = self
            .store
            .import_tar_named(target_name, io::Cursor::new(tar_bytes), &self.tar_opts)
            .map_err(map_store_error)?;
        Ok(persisted.into_parts().1)
    }

    fn create_writable_clone(
        &self,
        base_path: &Path,
        world_id: WorldId,
    ) -> Result<PathBuf, BackendError> {
        let base = self.store.open_subvolume(base_path).map_err(map_store_error)?;
        let target_name = format!("w-{world_id}");
        let clone = self
            .store
            .create_writable_clone(&base, &target_name)
            .map_err(map_store_error)?;
        Ok(clone.path().to_path_buf())
    }

    fn snapshot_readonly(
        &self,
        live_path: &Path,
        target_path: &Path,
    ) -> Result<PersistProof, BackendError> {
        let live = self.store.open_subvolume(live_path).map_err(map_store_error)?;
        let target_name = target_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                BackendError::InvalidArgument(format!(
                    "invalid snapshot target path {}",
                    target_path.display()
                ))
            })?;
        let persisted = self
            .store
            .snapshot_readonly(&live, target_name)
            .map_err(map_store_error)?;
        Ok(persisted.into_parts().1)
    }

    fn destroy_subvolume(&self, path: &Path) -> Result<(), BackendError> {
        self.store.destroy_subvolume(path).map_err(map_store_error)
    }

    fn export_patch(
        &self,
        base_path: &Path,
        target_path: &Path,
    ) -> Result<ValidatedPatchBundle, BackendError> {
        let base = self.store.open_subvolume(base_path).map_err(map_store_error)?;
        let target = self
            .store
            .open_subvolume(target_path)
            .map_err(map_store_error)?;
        let bundle = self
            .store
            .export_patch(&base, &target, &self.patch_opts)
            .map_err(map_store_error)?;

        let mut entries = Vec::with_capacity(bundle.len());
        let mut diff = String::new();
        for change in bundle.changes() {
            match change {
                PatchFileChange::PutFile {
                    path,
                    contents,
                    modified,
                    ..
                } => {
                    let kind = if *modified { "modify" } else { "add" };
                    entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind,
                        size_bytes: contents.len() as u64,
                    });
                    if *modified {
                        diff.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
                    } else {
                        diff.push_str(&format!("--- /dev/null\n+++ b/{path}\n"));
                    }
                    for line in String::from_utf8_lossy(contents).lines() {
                        diff.push('+');
                        diff.push_str(line);
                        diff.push('\n');
                    }
                }
                PatchFileChange::PutSymlink {
                    path,
                    target,
                    modified,
                } => {
                    let kind = if *modified { "modify" } else { "add" };
                    entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind,
                        size_bytes: target.len() as u64,
                    });
                    if *modified {
                        diff.push_str(&format!("--- a/{path}\n+++ b/{path}\n+{target}\n"));
                    } else {
                        diff.push_str(&format!("--- /dev/null\n+++ b/{path}\n+{target}\n"));
                    }
                }
                PatchFileChange::Remove { path } => {
                    entries.push(ValidatedPatchEntry {
                        path: path.clone(),
                        kind: "delete",
                        size_bytes: 0,
                    });
                    diff.push_str(&format!("--- a/{path}\n+++ /dev/null\n"));
                }
            }
        }

        let unified_diff = diff.into_bytes();
        let blake3_hex = blake3::hash(&unified_diff).to_hex().to_string();
        Ok(ValidatedPatchBundle {
            unified_diff,
            entries,
            blake3_hex,
        })
    }
}

/// Composite [`aos_meta::RecoveryHooks`] combining:
/// * **R2**: Stale-epoch cgroup v2 `cgroup.kill` (`<cgroup_root>/epoch-<n>` for `n < current`) +
///   stale writable world subvolume reclamation under `pool_root/worlds/`;
/// * **R3–R6**: Btrfs subvolume and volatile artifact cleanup via [`TreeStoreRecoveryHooks`].
#[derive(Debug, Clone)]
pub struct ProductionRecoveryHooks {
    store: TreeStore,
    tree_hooks: TreeStoreRecoveryHooks,
    cgroup_root: PathBuf,
}

impl ProductionRecoveryHooks {
    /// Construct production recovery hooks for `store`, `volatile_root`, and `cgroup_root`.
    pub fn new(
        store: TreeStore,
        volatile_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
    ) -> Self {
        let tree_hooks = TreeStoreRecoveryHooks::new(store.clone(), volatile_root);
        Self {
            store,
            tree_hooks,
            cgroup_root: cgroup_root.into(),
        }
    }
}

impl RecoveryHooks for ProductionRecoveryHooks {
    fn fence_gateway(&mut self, _epoch: EpochId) -> io::Result<()> {
        Ok(())
    }

    fn kill_stale_epochs(&mut self, current: EpochId) -> io::Result<()> {
        // 1. R2: Terminate and remove any `<cgroup_root>/epoch-<n>` cgroups where `n < current`.
        if self.cgroup_root.exists()
            && let Ok(entries) = fs::read_dir(&self.cgroup_root)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Some(num_str) = name.strip_prefix("epoch-") else {
                    continue;
                };
                let Ok(epoch_num) = num_str.parse::<u64>() else {
                    continue;
                };
                if epoch_num < current.get() {
                    kill_and_remove_epoch_cgroup_tree(&path);
                }
            }
        }

        // 2. Reclaim any leftover writable world subvolumes from prior epochs under `pool/worlds/`.
        let worlds_dir = self.store.worlds_dir();
        if worlds_dir.exists()
            && let Ok(entries) = fs::read_dir(&worlds_dir)
        {
            for entry in entries.flatten() {
                let _ = self.store.destroy_subvolume(&entry.path());
            }
        }
        Ok(())
    }

    fn destroy_pool_object(&mut self, path: &Path, object: &ManagedObject) -> io::Result<()> {
        self.tree_hooks.destroy_pool_object(path, object)
    }

    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()> {
        self.tree_hooks.destroy_volatile_object(object)
    }

    fn purge_quarantined(&mut self, path: &Path) -> io::Result<()> {
        self.tree_hooks.purge_quarantined(path)
    }
}

fn kill_and_remove_epoch_cgroup_tree(epoch_dir: &Path) {
    let _ = fs::write(epoch_dir.join("cgroup.kill"), b"1\n");
    let _ = fs::write(epoch_dir.join("cgroup.freeze"), b"0\n");
    if let Ok(children) = fs::read_dir(epoch_dir) {
        for child in children.flatten() {
            let child_path = child.path();
            if child_path.is_dir() {
                let _ = fs::write(child_path.join("cgroup.kill"), b"1\n");
                let _ = fs::write(child_path.join("cgroup.freeze"), b"0\n");
                let _ = fs::write(child_path.join("cgroup.kill"), b"1\n");
                for _ in 0..50 {
                    let empty = fs::read_to_string(child_path.join("cgroup.procs"))
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true);
                    if empty && fs::remove_dir(&child_path).is_ok() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let _ = fs::remove_dir(&child_path);
            }
        }
    }
    let _ = fs::remove_dir(epoch_dir);
}

/// Configuration for [`NamespaceSandboxBackend`].
#[derive(Debug, Clone)]
pub struct NamespaceSandboxConfig {
    /// Current `agentd` daemon epoch.
    pub epoch: EpochId,
    /// How `aos-guest` is located inside spawned worlds.
    pub guest_agent: GuestAgentSource,
    /// Host cgroup v2 slice root (`/sys/fs/cgroup/forkloom.slice`).
    pub cgroup_root: PathBuf,
    /// Enable `clone3(CLONE_INTO_CGROUP)` + `cgroup.kill`.
    pub enable_cgroup: bool,
    /// Enable `CLONE_NEWUSER`.
    pub enable_userns: bool,
    /// Network namespace mode.
    pub netns_mode: NetnsMode,
    /// Seccomp-BPF policy.
    pub seccomp_policy: SeccompPolicy,
    /// Initial `Ping -> Pong` handshake timeout.
    pub handshake_timeout: Duration,
}

impl NamespaceSandboxConfig {
    /// Production defaults for `epoch` with `aos-guest` at `/sbin/init` inside rootfs.
    pub fn new(epoch: EpochId) -> Self {
        Self {
            epoch,
            guest_agent: GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
            cgroup_root: PathBuf::from(DEFAULT_CGROUP_SLICE_ROOT),
            enable_cgroup: true,
            enable_userns: true,
            netns_mode: NetnsMode::IsolatedLoopback,
            seccomp_policy: SeccompPolicy::StrictBaseline,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

/// Production [`SandboxBackend`] wrapping [`aos_sandbox::NamespaceDriver`].
pub struct NamespaceSandboxBackend {
    driver: NamespaceDriver,
    cfg: NamespaceSandboxConfig,
    worlds: Mutex<HashMap<WorldId, Arc<Mutex<WorldHandle>>>>,
}

impl NamespaceSandboxBackend {
    /// Construct a production namespace sandbox backend.
    pub fn new(cfg: NamespaceSandboxConfig) -> Self {
        Self {
            driver: NamespaceDriver::new(),
            cfg,
            worlds: Mutex::new(HashMap::new()),
        }
    }

    fn get_world(&self, world_id: WorldId) -> Result<Arc<Mutex<WorldHandle>>, BackendError> {
        self.worlds
            .lock()
            .unwrap()
            .get(&world_id)
            .cloned()
            .ok_or(BackendError::WorldNotRunning(world_id))
    }
}

impl SandboxBackend for NamespaceSandboxBackend {
    fn enabled_drivers(&self) -> Vec<String> {
        vec![self.driver.driver_name().to_owned()]
    }

    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<(), BackendError> {
        if spec.driver != DriverKind::Namespace && spec.driver != DriverKind::Unspecified {
            return Err(BackendError::DriverUnavailable(format!(
                "driver {:?} is not supported by NamespaceSandboxBackend",
                spec.driver
            )));
        }

        let mut drv_spec = DriverSpawnSpec::new(
            spec.world_id,
            self.cfg.epoch,
            &spec.rootfs_path,
            self.cfg.guest_agent.clone(),
        );
        drv_spec.cgroup_root = self.cfg.cgroup_root.clone();
        drv_spec.enable_cgroup = self.cfg.enable_cgroup;
        drv_spec.enable_userns = self.cfg.enable_userns;
        drv_spec.netns_mode = self.cfg.netns_mode;
        drv_spec.seccomp_policy = self.cfg.seccomp_policy;
        drv_spec.handshake_timeout = self.cfg.handshake_timeout;

        let handle = self
            .driver
            .spawn_world(drv_spec)
            .map_err(map_sandbox_error)?;
        self.worlds
            .lock()
            .unwrap()
            .insert(spec.world_id, Arc::new(Mutex::new(handle)));
        Ok(())
    }

    fn exec(
        &self,
        world_id: WorldId,
        req: SandboxExecRequest,
        chunk_tx: mpsc::Sender<SandboxOutputChunk>,
    ) -> Result<SandboxExecResult, BackendError> {
        let world_arc = self.get_world(world_id)?;
        let mut handle = world_arc.lock().unwrap();

        let mut sbx_req = SbxExecRequest::new(req.exec_id.clone(), req.argv);
        sbx_req.env = req.env;
        sbx_req.cwd = req.cwd;
        sbx_req.timeout = Some(Duration::from_millis(req.timeout_ms));
        sbx_req.max_output_bytes = Some(req.max_output_bytes);
        sbx_req.stream = req.stream;

        let reply = if req.stream {
            handle
                .exec_streaming(sbx_req, |chunk| {
                    let stream = match chunk.stream {
                        OutputStream::Stdout => OutputStreamKind::OutputStreamStdout,
                        OutputStream::Stderr => OutputStreamKind::OutputStreamStderr,
                    };
                    let _ = chunk_tx.try_send(SandboxOutputChunk {
                        stream,
                        seq: chunk.seq,
                        data: chunk.data,
                    });
                })
                .map_err(map_sandbox_error)?
        } else {
            handle.exec(sbx_req).map_err(map_sandbox_error)?
        };

        let map_bounded = |b: aos_guest::BoundedOutput| BoundedOutput {
            head: b.head.0,
            tail: b.tail.0,
            total_bytes: b.total_bytes,
            omitted_bytes: b.omitted_bytes,
            truncated: b.truncated,
        };

        Ok(SandboxExecResult {
            exec_id: reply.exec_id,
            exit_code: reply.exit_code,
            signal: reply.signal,
            timed_out: reply.timed_out,
            cgroup_killed: reply.cgroup_killed,
            duration_ms: reply.duration_ms,
            stdout: map_bounded(reply.stdout),
            stderr: map_bounded(reply.stderr),
        })
    }

    fn freeze_and_sync(&self, world_id: WorldId, perform_syncfs: bool) -> Result<bool, BackendError> {
        let world_arc = self.get_world(world_id)?;
        let mut handle = world_arc.lock().unwrap();
        let opts = if perform_syncfs {
            FreezeOptions::disk_clean()
        } else {
            FreezeOptions::default()
        };
        let reply = handle.freeze_and_sync(opts).map_err(map_sandbox_error)?;
        Ok(reply.disk_clean)
    }

    fn unfreeze(&self, world_id: WorldId) -> Result<(), BackendError> {
        let world_arc = self.get_world(world_id)?;
        let mut handle = world_arc.lock().unwrap();
        handle
            .unfreeze(Duration::from_secs(5))
            .map_err(map_sandbox_error)
    }

    fn destroy_world(&self, world_id: WorldId) -> Result<(), BackendError> {
        if let Some(world_arc) = self.worlds.lock().unwrap().remove(&world_id) {
            let mut handle = world_arc.lock().unwrap();
            handle.destroy().map_err(map_sandbox_error)?;
        }
        Ok(())
    }
}
