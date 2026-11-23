//! Cgroup v2 parsing, path validation, and safe controller helpers for `aos-guest`.
//!
//! Per `docs/ARCHITECTURE_V2.md` §5.1 and §7.1:
//! - Workload processes live under `aos.workload` (`cgroup.freeze` / `cgroup.events`).
//! - Each foreground `Exec` runs in a dedicated sub-cgroup `aos.workload/exec-<id>`
//!   and is terminated via `cgroup.kill` on completion or timeout to prevent
//!   double-fork orphan escapes.

#![forbid(unsafe_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default cgroup v2 directory for guest workload processes.
pub const DEFAULT_WORKLOAD_CGROUP: &str = "/sys/fs/cgroup/aos.workload";

/// Maximum allowed `exec_id` length for sub-cgroup naming.
pub const MAX_EXEC_ID_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CgroupError {
    #[error("invalid exec_id '{0}': must be 1..=64 ASCII [A-Za-z0-9._-] chars and not '.' or '..'")]
    InvalidExecId(String),
    #[error("malformed cgroup.events content: missing required '{0}' key")]
    MissingEventsKey(&'static str),
    #[error("malformed cgroup.events value for '{key}': '{value}'")]
    InvalidEventsValue { key: String, value: String },
    #[error("timed out waiting for cgroup frozen={expected} after {elapsed_ms}ms")]
    FreezeWaitTimeout { expected: bool, elapsed_ms: u64 },
    #[error("cgroup filesystem I/O error at {path}: {message}")]
    Io { path: PathBuf, message: String },
}

impl CgroupError {
    fn io(path: impl Into<PathBuf>, err: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            message: err.to_string(),
        }
    }
}

/// Parsed fields from Linux cgroup v2 `cgroup.events`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CgroupEvents {
    pub populated: bool,
    pub frozen: bool,
}

/// Parse Linux cgroup v2 `cgroup.events` content (key-value lines such as `populated 1\nfrozen 0\n`).
pub fn parse_cgroup_events(content: &str) -> Result<CgroupEvents, CgroupError> {
    let mut populated = None;
    let mut frozen = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(val) = parts.next() else {
            return Err(CgroupError::InvalidEventsValue {
                key: key.to_owned(),
                value: String::new(),
            });
        };

        let parse_bool = |k: &str, v: &str| -> Result<bool, CgroupError> {
            match v {
                "0" => Ok(false),
                "1" => Ok(true),
                other => Err(CgroupError::InvalidEventsValue {
                    key: k.to_owned(),
                    value: other.to_owned(),
                }),
            }
        };

        match key {
            "populated" => populated = Some(parse_bool(key, val)?),
            "frozen" => frozen = Some(parse_bool(key, val)?),
            _ => {}
        }
    }

    Ok(CgroupEvents {
        populated: populated.ok_or(CgroupError::MissingEventsKey("populated"))?,
        frozen: frozen.ok_or(CgroupError::MissingEventsKey("frozen"))?,
    })
}

/// Validate `exec_id` before using it in a sub-cgroup directory name.
///
/// Rejects empty strings, `.` / `..`, path separators, NUL bytes, whitespace,
/// and strings longer than [`MAX_EXEC_ID_LEN`].
pub fn validate_exec_id(exec_id: &str) -> Result<(), CgroupError> {
    if exec_id.is_empty()
        || exec_id.len() > MAX_EXEC_ID_LEN
        || exec_id == "."
        || exec_id == ".."
        || !exec_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(CgroupError::InvalidExecId(exec_id.to_owned()));
    }
    Ok(())
}

/// Construct a validated per-exec sub-cgroup path `<workload_root>/exec-<exec_id>`.
pub fn sub_cgroup_path(workload_root: &Path, exec_id: &str) -> Result<PathBuf, CgroupError> {
    validate_exec_id(exec_id)?;
    Ok(workload_root.join(format!("exec-{exec_id}")))
}

/// Filesystem-backed cgroup v2 controller operating on a workload root directory.
///
/// Because this uses standard file I/O on `cgroup.freeze`, `cgroup.events`,
/// `cgroup.procs`, and `cgroup.kill`, its freeze/poll/sub-cgroup logic is directly
/// testable against temporary directories on non-Linux hosts as well as real
/// `/sys/fs/cgroup/aos.workload` on Linux.
#[derive(Debug, Clone)]
pub struct CgroupV2Controller {
    workload_root: PathBuf,
}

impl CgroupV2Controller {
    pub fn new(workload_root: impl Into<PathBuf>) -> Self {
        Self {
            workload_root: workload_root.into(),
        }
    }

    pub fn workload_root(&self) -> &Path {
        &self.workload_root
    }

    /// Ensure the workload root cgroup directory exists.
    pub fn ensure_root(&self) -> Result<(), CgroupError> {
        fs::create_dir_all(&self.workload_root)
            .map_err(|e| CgroupError::io(&self.workload_root, e))
    }

    /// Write `"1"` or `"0"` to `<workload_root>/cgroup.freeze`.
    pub fn write_freeze(&self, freeze: bool) -> Result<(), CgroupError> {
        let path = self.workload_root.join("cgroup.freeze");
        let val = if freeze { "1" } else { "0" };
        fs::write(&path, val).map_err(|e| CgroupError::io(path, e))
    }

    /// Read and parse `<workload_root>/cgroup.events`.
    pub fn read_events(&self) -> Result<CgroupEvents, CgroupError> {
        self.read_events_at(&self.workload_root)
    }

    /// Read and parse `<dir>/cgroup.events`.
    pub fn read_events_at(&self, dir: &Path) -> Result<CgroupEvents, CgroupError> {
        let path = dir.join("cgroup.events");
        let raw = fs::read_to_string(&path).map_err(|e| CgroupError::io(path, e))?;
        parse_cgroup_events(&raw)
    }

    /// Write `cgroup.freeze` and poll `cgroup.events` until `frozen == target` or `timeout` elapses.
    pub fn set_freeze_and_wait(
        &self,
        target: bool,
        timeout: Duration,
    ) -> Result<Duration, CgroupError> {
        let start = Instant::now();
        self.write_freeze(target)?;

        let mut backoff = Duration::from_millis(1);
        let max_backoff = Duration::from_millis(10);

        loop {
            let ev = self.read_events()?;
            if ev.frozen == target {
                return Ok(start.elapsed());
            }
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(CgroupError::FreezeWaitTimeout {
                    expected: target,
                    elapsed_ms: elapsed.as_millis() as u64,
                });
            }
            let remaining = timeout.saturating_sub(elapsed);
            thread::sleep(backoff.min(remaining));
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Create the dedicated sub-cgroup directory for an `Exec` invocation.
    ///
    /// Uses `create_dir` (not `create_dir_all`) after ensuring the workload root exists
    /// so colliding or stale `exec_id` directories fail explicitly instead of silently
    /// sharing a cgroup across executions.
    pub fn create_exec_subcgroup(&self, exec_id: &str) -> Result<PathBuf, CgroupError> {
        self.ensure_root()?;
        let dir = sub_cgroup_path(&self.workload_root, exec_id)?;
        fs::create_dir(&dir).map_err(|e| CgroupError::io(&dir, e))?;
        Ok(dir)
    }

    /// Best-effort write `"1"` or `"0"` to `<dir>/cgroup.freeze` on a specific sub-cgroup.
    pub fn write_freeze_at(&self, dir: &Path, freeze: bool) -> Result<(), CgroupError> {
        let path = dir.join("cgroup.freeze");
        let val = if freeze { "1" } else { "0" };
        fs::write(&path, val).map_err(|e| CgroupError::io(path, e))
    }

    /// Kill all remaining processes in a sub-cgroup using `cgroup.kill` (Linux >= 5.14).
    ///
    /// Returns `Ok(true)` if `cgroup.kill` succeeded, or `Ok(false)` if `cgroup.kill`
    /// is missing (caller may fall back to reading `cgroup.procs` and signaling PIDs).
    pub fn trigger_cgroup_kill(&self, dir: &Path) -> Result<bool, CgroupError> {
        let kill_path = dir.join("cgroup.kill");
        match fs::write(&kill_path, "1") {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(CgroupError::io(kill_path, e)),
        }
    }

    /// Read all numeric PIDs currently listed in `<dir>/cgroup.procs`.
    pub fn read_pids(&self, dir: &Path) -> Result<Vec<i32>, CgroupError> {
        let procs_path = dir.join("cgroup.procs");
        let raw = match fs::read_to_string(&procs_path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(CgroupError::io(procs_path, e)),
        };
        let mut pids = Vec::new();
        for line in raw.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(pid) = trimmed.parse::<i32>()
                && pid > 0
            {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    /// Remove an empty sub-cgroup directory, ignoring `NotFound`.
    pub fn remove_subcgroup(&self, dir: &Path) -> Result<(), CgroupError> {
        match fs::remove_dir(dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CgroupError::io(dir, e)),
        }
    }
}
