//! Configuration and request/response types for `aos-sandbox`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use aos_guest::{AgentState, BoundedOutput, OutputStream};
use aos_types::{EpochId, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::SandboxError;

/// Default host cgroup v2 slice root for Forkloom sandboxes (`ARCHITECTURE_V2.md` §4.2 R2).
pub const DEFAULT_CGROUP_SLICE_ROOT: &str = "/sys/fs/cgroup/forkloom.slice";

/// Default handshake timeout waiting for the spawned `aos-guest` `Pong`.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Single UID/GID mapping entry for Linux user namespaces (`<inside> <outside> <count>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdMapRange {
    pub inside_id: u32,
    pub outside_id: u32,
    pub count: u32,
}

impl IdMapRange {
    pub const fn new(inside_id: u32, outside_id: u32, count: u32) -> Self {
        Self {
            inside_id,
            outside_id,
            count,
        }
    }

    /// Format in Linux `/proc/<pid>/{uid,gid}_map` syntax.
    pub fn format_proc_line(&self) -> String {
        format!("{} {} {}\n", self.inside_id, self.outside_id, self.count)
    }
}

/// How the static `aos-guest` binary is located inside a spawned `NamespaceDriver` world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestAgentSource {
    /// Binary already resides inside `rootfs_dir` (e.g. `/sbin/init` or `/usr/bin/aos-guest`).
    /// Host NEVER touches `rootfs_dir` files.
    InRootfs(PathBuf),

    /// Bind-mount a host static `aos-guest` binary read-only onto `guest_mount_path`
    /// inside the sandbox's private `mountns` before `pivot_root`.
    /// `guest_mount_path` must be an absolute path inside the rootfs whose target file
    /// already exists as a mountpoint.
    BindMountHostBinary {
        host_path: PathBuf,
        guest_mount_path: PathBuf,
    },
}

/// Seccomp-BPF policy applied before `execve(aos-guest)` in `NamespaceDriver`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeccompPolicy {
    /// Strict `ARCHITECTURE_V2.md` §7.4 + §5.1 baseline:
    /// - Blocks nested `userns` (`CLONE_NEWUSER` / `unshare` / `setns`), `mount` family,
    ///   `io_uring_*`, `bpf`, `ptrace`, `kexec_*`.
    /// - Returns `EOPNOTSUPP` (NOT `SIGSYS`) on `ioctl` with `BTRFS_IOCTL_MAGIC` (`0x94`).
    /// - Returns `ENOSYS` on `clone3` so glibc/musl threads fall back to `clone(2)` cleanly.
    StrictBaseline,

    /// Disable seccomp (for debugging only; forbidden in production).
    Disabled,
}

/// Network namespace isolation mode for `NamespaceDriver`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetnsMode {
    /// Create a fresh `CLONE_NEWNET` with loopback `lo` raised UP and ZERO external routes.
    IsolatedLoopback,
    /// Inherit host netns (only for restricted environments where `CLONE_NEWNET` is unavailable).
    InheritHost,
}

/// Specification for spawning a `World` under `NamespaceDriver`.
#[derive(Debug, Clone)]
pub struct SpawnWorldSpec {
    pub world_id: WorldId,
    pub epoch: EpochId,
    /// Writable root filesystem directory (e.g., Btrfs subvolume from `TreeStore`).
    pub rootfs_dir: PathBuf,
    /// Static `aos-guest` binary location.
    pub guest_agent: GuestAgentSource,
    /// Host cgroup v2 slice root (world cgroup is `<cgroup_root>/epoch-<epoch>/w-<world_id>`).
    pub cgroup_root: PathBuf,
    /// Enable `clone3(CLONE_INTO_CGROUP)` + `cgroup.kill` lifecycle management.
    pub enable_cgroup: bool,
    /// Enable `CLONE_NEWUSER` user namespace isolation.
    pub enable_userns: bool,
    /// Explicit UID mappings when `enable_userns == true` (defaults to `0 <euid> 1`).
    pub uid_map: Vec<IdMapRange>,
    /// Explicit GID mappings when `enable_userns == true` (defaults to `0 <egid> 1`).
    pub gid_map: Vec<IdMapRange>,
    /// Network namespace mode (defaults to [`NetnsMode::IsolatedLoopback`]).
    pub netns_mode: NetnsMode,
    /// Seccomp-BPF policy (defaults to [`SeccompPolicy::StrictBaseline`]).
    pub seccomp_policy: SeccompPolicy,
    /// Optional UTS hostname inside the sandbox (defaults to `fl-<world_id>`).
    pub hostname: Option<String>,
    /// Maximum wait for initial `Ping -> Pong` handshake over the control `socketpair`.
    pub handshake_timeout: Duration,
    /// Additional CLI arguments passed to `aos-guest` (besides `--socketpair-fd 3`).
    pub extra_guest_args: Vec<String>,
}

impl SpawnWorldSpec {
    /// Construct a production-hardened spec using §7.4 defaults.
    pub fn new(
        world_id: WorldId,
        epoch: EpochId,
        rootfs_dir: impl Into<PathBuf>,
        guest_agent: GuestAgentSource,
    ) -> Self {
        Self {
            world_id,
            epoch,
            rootfs_dir: rootfs_dir.into(),
            guest_agent,
            cgroup_root: PathBuf::from(DEFAULT_CGROUP_SLICE_ROOT),
            enable_cgroup: true,
            enable_userns: true,
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            netns_mode: NetnsMode::IsolatedLoopback,
            seccomp_policy: SeccompPolicy::StrictBaseline,
            hostname: None,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            extra_guest_args: vec!["--no-cgroup".to_owned()],
        }
    }

    /// Compute the deterministic per-epoch, per-world cgroup path:
    /// `<cgroup_root>/epoch-<epoch>/w-<world_id>`.
    pub fn world_cgroup_path(&self) -> PathBuf {
        self.cgroup_root
            .join(self.epoch.cgroup_dir_name())
            .join(format!("w-{}", self.world_id))
    }

    /// Compute the effective UTS hostname (`<= 64` ASCII chars).
    pub fn effective_hostname(&self) -> String {
        let raw = self
            .hostname
            .clone()
            .unwrap_or_else(|| format!("fl-{}", self.world_id));
        raw.chars().take(63).collect()
    }

    /// Validate spec fields before spawning any OS resources.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.rootfs_dir.as_os_str().is_empty() {
            return Err(SandboxError::InvalidConfig(
                "rootfs_dir must be non-empty".to_owned(),
            ));
        }
        match &self.guest_agent {
            GuestAgentSource::InRootfs(p) => {
                validate_guest_abs_path(p, "InRootfs guest_agent")?;
            }
            GuestAgentSource::BindMountHostBinary {
                host_path,
                guest_mount_path,
            } => {
                if host_path.as_os_str().is_empty() {
                    return Err(SandboxError::InvalidConfig(
                        "BindMountHostBinary host_path must be non-empty".to_owned(),
                    ));
                }
                validate_guest_abs_path(guest_mount_path, "BindMountHostBinary guest_mount_path")?;
            }
        }
        for r in self.uid_map.iter().chain(self.gid_map.iter()) {
            if r.count == 0 {
                return Err(SandboxError::InvalidConfig(
                    "uid_map / gid_map range count must be >= 1".to_owned(),
                ));
            }
        }
        let host = self.effective_hostname();
        if host.is_empty() || host.bytes().any(|b| b == 0) {
            return Err(SandboxError::InvalidConfig(
                "hostname must be non-empty and NUL-free".to_owned(),
            ));
        }
        if self.handshake_timeout.is_zero() {
            return Err(SandboxError::InvalidConfig(
                "handshake_timeout must be > 0".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Validate a guest-internal absolute POSIX path, rejecting relative paths,
/// backslashes, NUL bytes, `.` (`CurDir`), and `..` (`ParentDir`) traversal.
fn validate_guest_abs_path(path: &std::path::Path, label: &str) -> Result<(), SandboxError> {
    use std::path::Component;

    let raw = path.to_string_lossy();
    if !raw.starts_with('/') {
        return Err(SandboxError::InvalidConfig(format!(
            "{label} path must be absolute POSIX path starting with '/', got {:?}",
            path
        )));
    }
    if raw.contains('\0') || raw.contains('\\') {
        return Err(SandboxError::InvalidConfig(format!(
            "{label} path contains forbidden NUL or backslash: {:?}",
            path
        )));
    }
    for seg in raw.split('/') {
        if seg == "." || seg == ".." {
            return Err(SandboxError::InvalidConfig(format!(
                "{label} path must not contain '.' or '..' traversal components: {:?}",
                path
            )));
        }
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir | Component::CurDir) {
            return Err(SandboxError::InvalidConfig(format!(
                "{label} path must not contain '.' or '..' components: {:?}",
                path
            )));
        }
    }
    if raw.trim_matches('/').is_empty() {
        return Err(SandboxError::InvalidConfig(format!(
            "{label} path must name a file inside rootfs, not '/': {:?}",
            path
        )));
    }
    Ok(())
}

/// Host-side parameters for running a command inside a `World` via `aos-guest`.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub exec_id: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub timeout: Option<Duration>,
    pub max_output_bytes: Option<usize>,
    pub stream_chunk_bytes: Option<usize>,
    pub stream: bool,
}

impl ExecRequest {
    pub fn new(exec_id: impl Into<String>, argv: Vec<String>) -> Self {
        Self {
            exec_id: exec_id.into(),
            argv,
            env: BTreeMap::new(),
            cwd: None,
            timeout: None,
            max_output_bytes: None,
            stream_chunk_bytes: None,
            stream: false,
        }
    }
}

/// Live streaming chunk emitted during `WorldHandle::exec_streaming`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutputChunk {
    pub exec_id: String,
    pub stream: OutputStream,
    pub seq: u64,
    pub data: Vec<u8>,
}

/// Result of a completed `Exec` returned by `aos-guest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecReply {
    pub exec_id: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cgroup_killed: bool,
    pub duration_ms: u64,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
}

/// Result of a `Ping` probe returned by `aos-guest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingReply {
    pub nonce: u64,
    pub state: AgentState,
    pub uptime_ms: u64,
    pub pid: u32,
    pub epoch_generation: u64,
}

/// Options for `FreezeAndSync`.
#[derive(Debug, Clone, Default)]
pub struct FreezeOptions {
    pub pre_freeze_hook: Option<Vec<String>>,
    pub freeze_timeout: Option<Duration>,
    pub sync_paths: Vec<String>,
    pub perform_syncfs: bool,
}

impl FreezeOptions {
    pub fn disk_clean() -> Self {
        Self {
            pre_freeze_hook: None,
            freeze_timeout: None,
            sync_paths: vec!["/".to_owned()],
            perform_syncfs: true,
        }
    }
}

/// Result of a `FreezeAndSync` request returned by `aos-guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreezeReply {
    pub disk_clean: bool,
    pub frozen_elapsed_ms: u64,
    pub syncfs_elapsed_ms: u64,
    pub synced_paths: usize,
}

/// Metadata describing a live spawned `World`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldInfo {
    pub world_id: WorldId,
    pub epoch: EpochId,
    pub driver_name: &'static str,
    pub host_pid: Option<u32>,
    pub cgroup_path: Option<PathBuf>,
    pub seccomp_enabled: bool,
    pub userns_enabled: bool,
    pub netns_isolated: bool,
}
