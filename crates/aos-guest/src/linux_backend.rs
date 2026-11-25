//! Safe Linux [`GuestBackend`] implementation composing `cgroup`, `netlink_tcp`, and `linux_sys`.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::cgroup::{CgroupV2Controller, DEFAULT_WORKLOAD_CGROUP};
use crate::linux_sys;
use crate::netlink_tcp::{
    AF_INET, AF_INET6, ParsedNetlinkMsg, SocketAction, build_tcp_destroy_request,
    build_tcp_dump_request, classify_tcp_socket, parse_netlink_frames, ss_kill_fallback_args,
};
use crate::protocol::{BoundedOutput, ErrorCode, OutputStream, RESEED_ENTROPY_LEN};
use crate::server::{
    BackendError, ExecOutcome, ExecSpec, GuestBackend, SocketKillReport, SyncOutcome,
};
use crate::truncation::drain_stream;

static PREFREEZE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Exec cgroups created and owned by the host, reachable only through inherited fds.
///
/// The sandbox has no cgroupfs, and the files belong to an unmapped host id, so workloads can
/// neither leave their cgroup nor reopen the fds through `/proc/1/fd`.
#[derive(Debug)]
struct InheritedExecCgroup {
    /// `cgroup.procs`, opened read-write.
    procs: File,
    /// `cgroup.kill`, opened write-only.
    kill: File,
    /// `cgroup.procs` of the cgroup for detached commands, opened write-only.
    detached_procs: File,
}

impl InheritedExecCgroup {
    fn is_empty(&self) -> io::Result<bool> {
        let mut buf = [0u8; 16];
        Ok(self.procs.read_at(&mut buf, 0)? == 0)
    }

    /// Kill every process left in the cgroup; returns `true` only if there were any (or
    /// `forced_kill` is set).
    fn kill_all(&self, forced_kill: bool) -> io::Result<bool> {
        let had_live_procs = forced_kill || !self.is_empty()?;
        if had_live_procs {
            self.kill.write_at(b"1", 0)?;
            let deadline = Instant::now() + Duration::from_millis(250);
            while !self.is_empty()? && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(had_live_procs)
    }
}

/// Production Linux backend for `aos-guest` (Firecracker `vsock` and `NamespaceDriver` `socketpair`).
#[derive(Debug, Clone)]
pub struct LinuxGuestBackend {
    cgroup: CgroupV2Controller,
    enable_cgroup_isolation: bool,
    inherited_exec: Option<Arc<InheritedExecCgroup>>,
}

impl Default for LinuxGuestBackend {
    fn default() -> Self {
        Self::new(DEFAULT_WORKLOAD_CGROUP, true)
    }
}

impl LinuxGuestBackend {
    pub fn new(workload_cgroup: impl Into<PathBuf>, enable_cgroup_isolation: bool) -> Self {
        Self {
            cgroup: CgroupV2Controller::new(workload_cgroup),
            enable_cgroup_isolation,
            inherited_exec: None,
        }
    }

    /// Run every `Exec` in the host-owned cgroup behind the given inherited fds
    /// (`NamespaceDriver`) instead of in guest-created sub-cgroups.
    pub fn with_inherited_exec_cgroup(
        procs_fd: RawFd,
        kill_fd: RawFd,
        detached_procs_fd: RawFd,
    ) -> io::Result<Self> {
        let mut backend = Self::new(DEFAULT_WORKLOAD_CGROUP, false);
        backend.inherited_exec = Some(Arc::new(InheritedExecCgroup {
            procs: linux_sys::file_from_inherited_fd(procs_fd)?,
            kill: linux_sys::file_from_inherited_fd(kill_fd)?,
            detached_procs: linux_sys::file_from_inherited_fd(detached_procs_fd)?,
        }));
        Ok(backend)
    }

    /// Start `spec` outside the per-`Exec` cgroup and leave it to the PID-1 orphan reaper.
    fn spawn_detached(&self, spec: &ExecSpec) -> Result<ExecOutcome, BackendError> {
        let start = Instant::now();
        let failed = |e: &dyn std::fmt::Display| {
            BackendError::new(
                ErrorCode::ExecFailed,
                format!("spawn detached '{}' failed: {e}", spec.argv[0]),
            )
        };
        let mut cmd = Command::new(&spec.argv[0]);
        cmd.args(&spec.argv[1..])
            .envs(&spec.env)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        if let Some(cg) = &self.inherited_exec {
            linux_sys::attach_child_to_cgroup_fd(&mut cmd, cg.detached_procs.as_raw_fd());
        } else if self.enable_cgroup_isolation {
            let dir = self.cgroup.workload_root().join("detached");
            std::fs::create_dir_all(&dir).map_err(|e| failed(&e))?;
            linux_sys::attach_child_to_cgroup(&mut cmd, dir.join("cgroup.procs"))
                .map_err(|e| failed(&e))?;
        }
        let spawn_guard = linux_sys::begin_child_spawn();
        let spawned = cmd.spawn();
        drop(spawn_guard);
        spawned.map_err(|e| failed(&e))?;
        Ok(ExecOutcome {
            exit_code: None,
            signal: None,
            timed_out: false,
            cgroup_killed: false,
            duration: start.elapsed(),
            stdout: BoundedOutput::default(),
            stderr: BoundedOutput::default(),
        })
    }

    /// Kill whatever is left of the current `Exec`.
    fn kill_exec(&self, sub_cgroup: Option<&Path>, forced_kill: bool) -> bool {
        if let Some(cg) = &self.inherited_exec {
            // The host re-checks and kills the cgroup after every Exec, so an error here only
            // delays cleanup.
            return cg.kill_all(forced_kill).unwrap_or(false);
        }
        sub_cgroup.is_some_and(|dir| self.kill_and_cleanup_subcgroup(dir, forced_kill))
    }

    pub fn cgroup(&self) -> &CgroupV2Controller {
        &self.cgroup
    }

    /// Terminate every remaining process inside `dir` (using `cgroup.kill`, or a
    /// fork-bomb-safe freeze + repeated SIGKILL loop when `cgroup.kill` is absent)
    /// and remove `dir`.
    ///
    /// Returns `true` ONLY if live processes were actually present before teardown
    /// (or `forced_kill` is true, e.g. timeout) and were terminated — never `true`
    /// for a clean exit with zero surviving descendants.
    fn kill_and_cleanup_subcgroup(&self, dir: &Path, forced_kill: bool) -> bool {
        let had_live_procs = forced_kill
            || self
                .cgroup
                .read_pids(dir)
                .map(|pids| !pids.is_empty())
                .unwrap_or(false);

        let mut killed = false;
        match self.cgroup.trigger_cgroup_kill(dir) {
            Ok(true) => {
                if had_live_procs {
                    killed = true;
                }
            }
            Ok(false) | Err(_) => {
                // Fork-bomb-safe fallback: freeze sub-cgroup first so no new tasks can
                // spawn while we drain `cgroup.procs`, then repeatedly SIGKILL until empty.
                let froze = self.cgroup.write_freeze_at(dir, true).is_ok();
                let kill_deadline = Instant::now() + Duration::from_millis(500);
                while Instant::now() < kill_deadline {
                    let Ok(pids) = self.cgroup.read_pids(dir) else {
                        break;
                    };
                    if pids.is_empty() {
                        break;
                    }
                    for pid in pids {
                        if linux_sys::kill_pid_sigkill(pid).is_ok() {
                            killed = true;
                        }
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                if froze {
                    let _ = self.cgroup.write_freeze_at(dir, false);
                }
            }
        }

        // Best-effort wait for empty sub-cgroup before rmdir.
        let deadline = Instant::now() + Duration::from_millis(250);
        while Instant::now() < deadline {
            if self.cgroup.remove_subcgroup(dir).is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        killed
    }

    fn kill_external_tcp_netlink(&self) -> io::Result<SocketKillReport> {
        let sock = linux_sys::NetlinkSockDiag::open()?;
        let mut report = SocketKillReport::default();
        let mut seq = 1u32;
        let mut recv_buf = vec![0u8; 64 * 1024];
        let mut first_destroy_err: Option<io::Error> = None;

        for family in [AF_INET, AF_INET6] {
            let dump_seq = seq;
            seq = seq.wrapping_add(1);
            let dump_req = build_tcp_dump_request(family, dump_seq);
            sock.send(&dump_req)?;

            let mut to_kill = Vec::new();
            let mut done = false;
            let mut skip_family = false;

            while !done {
                let n = sock.recv(&mut recv_buf)?;
                if n == 0 {
                    break;
                }
                let frames = parse_netlink_frames(&recv_buf[..n]).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("netlink parse: {e}"))
                })?;
                for frame in frames {
                    if frame.seq != dump_seq {
                        continue;
                    }
                    match frame.body {
                        ParsedNetlinkMsg::Done => {
                            done = true;
                            break;
                        }
                        ParsedNetlinkMsg::Error(0) | ParsedNetlinkMsg::Noop => {}
                        ParsedNetlinkMsg::Error(neg_errno) => {
                            let errno = -neg_errno;
                            // If IPv6 is disabled (`ipv6.disable=1`), skip AF_INET6 cleanly.
                            if family == AF_INET6
                                && matches!(errno, libc::EAFNOSUPPORT | libc::ENOENT)
                            {
                                skip_family = true;
                                done = true;
                                break;
                            }
                            return Err(io::Error::from_raw_os_error(errno));
                        }
                        ParsedNetlinkMsg::InetDiag(diag) => match classify_tcp_socket(&diag) {
                            SocketAction::Kill => to_kill.push(diag),
                            SocketAction::PreserveLoopback => {
                                report.preserved_loopback_sockets += 1;
                            }
                            SocketAction::SkipState => {}
                        },
                    }
                }
            }

            if skip_family {
                continue;
            }

            // Attempt SOCK_DESTROY for every external socket; never abort remaining
            // sockets if one transitioning socket returns a per-socket error.
            for diag in to_kill {
                let destroy_seq = seq;
                seq = seq.wrapping_add(1);
                let destroy_req = build_tcp_destroy_request(&diag, destroy_seq);
                sock.send(&destroy_req)?;

                'ack_loop: loop {
                    let n = sock.recv(&mut recv_buf)?;
                    if n == 0 {
                        break;
                    }
                    let acks = parse_netlink_frames(&recv_buf[..n]).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("netlink ack parse: {e}"),
                        )
                    })?;
                    for ack in acks {
                        if ack.seq != destroy_seq {
                            continue;
                        }
                        if let ParsedNetlinkMsg::Error(code) = ack.body {
                            if code == 0 {
                                report.killed_tcp_sockets += 1;
                            } else {
                                let errno = -code;
                                match errno {
                                    // Already closed between dump and destroy.
                                    libc::ENOENT => {}
                                    // Transitioning / non-destroyable socket state: record if
                                    // kernel lacks SOCK_DESTROY, otherwise keep destroying others.
                                    libc::EINVAL | libc::EBUSY => {}
                                    _ => {
                                        if first_destroy_err.is_none() {
                                            first_destroy_err =
                                                Some(io::Error::from_raw_os_error(errno));
                                        }
                                    }
                                }
                            }
                            break 'ack_loop;
                        }
                    }
                }
            }
        }

        if let Some(err) = first_destroy_err {
            return Err(err);
        }
        Ok(report)
    }

    fn kill_external_tcp_ss_fallback(&self) -> Result<SocketKillReport, BackendError> {
        let args = ss_kill_fallback_args();
        let _spawn_guard = linux_sys::begin_child_spawn();
        let output = Command::new("ss")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                BackendError::new(
                    ErrorCode::SocketKillFailed,
                    format!("failed to execute fallback `ss`: {e}"),
                )
            })?;
        if !output.status.success() {
            let stderr_msg = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::new(
                ErrorCode::SocketKillFailed,
                format!(
                    "fallback `ss {args:?}` exited with status {} ({})",
                    output.status,
                    stderr_msg.trim()
                ),
            ));
        }
        Ok(SocketKillReport::default())
    }
}

impl GuestBackend for LinuxGuestBackend {
    fn run_exec(
        &self,
        spec: ExecSpec,
        on_chunk: &mut dyn FnMut(OutputStream, &[u8]) -> io::Result<()>,
    ) -> Result<ExecOutcome, BackendError> {
        if spec.detached {
            return self.spawn_detached(&spec);
        }
        let start = Instant::now();
        let sub_cgroup = if self.enable_cgroup_isolation {
            let dir = self
                .cgroup
                .create_exec_subcgroup(&spec.exec_id)
                .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;
            Some(dir)
        } else {
            None
        };

        let mut cmd = Command::new(&spec.argv[0]);
        if spec.argv.len() > 1 {
            cmd.args(&spec.argv[1..]);
        }
        cmd.envs(&spec.env);
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(dir) = &sub_cgroup {
            linux_sys::attach_child_to_cgroup(&mut cmd, dir.join("cgroup.procs"))
                .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;
        }
        if let Some(cg) = &self.inherited_exec {
            linux_sys::attach_child_to_cgroup_fd(&mut cmd, cg.procs.as_raw_fd());
        }
        linux_sys::prefer_child_for_oom_kill(&mut cmd);

        let spawn_guard = linux_sys::begin_child_spawn();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                drop(spawn_guard);
                if let Some(dir) = &sub_cgroup {
                    let _ = self.cgroup.remove_subcgroup(dir);
                }
                return Err(BackendError::new(
                    ErrorCode::ExecFailed,
                    format!("spawn '{}' failed: {e}", spec.argv[0]),
                ));
            }
        };
        let _active_child = spawn_guard.register_pid(child.id());

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();

        // Drain stdout and stderr concurrently using scoped threads and forward
        // chunks over a bounded sync_channel so the calling thread invokes `on_chunk`
        // without requiring `on_chunk: Send` or holding locks across I/O.
        let (tx, rx) = mpsc::sync_channel::<(OutputStream, Vec<u8>)>(16);

        let mut timed_out = false;
        let mut cgroup_killed = false;
        let mut stream_err: Option<io::Error> = None;

        let scoped = thread::scope(|scope| {
            let tx_out = tx.clone();
            let max_bytes = spec.max_output_bytes;
            let chunk_bytes = spec.stream_chunk_bytes;
            // The workload shares `pids.max` with aos-guest, so thread creation can fail here;
            // `scope.spawn` would panic and take PID 1 (and the world) down with it.
            let mut abort = |e: io::Error| {
                self.kill_exec(sub_cgroup.as_deref(), true);
                let _ = child.kill();
                let _ = child.wait();
                // A drain thread that did start ends at EOF once its chunks are taken.
                while rx.recv().is_ok() {}
                Err(e)
            };

            let stdout_handle = match thread::Builder::new().spawn_scoped(scope, move || -> io::Result<BoundedOutput> {
                let res = match stdout_pipe {
                    Some(pipe) => drain_stream(pipe, max_bytes, chunk_bytes, |chunk| {
                        // Ignore send error if receiver dropped; keep draining pipe to EOF.
                        let _ = tx_out.send((OutputStream::Stdout, chunk.to_vec()));
                        Ok(())
                    }),
                    None => Ok(BoundedOutput::default()),
                };
                drop(tx_out);
                res
            }) {
                Ok(h) => h,
                Err(e) => {
                    drop(tx);
                    return abort(e);
                }
            };

            let tx_err = tx;
            let stderr_handle = match thread::Builder::new().spawn_scoped(scope, move || -> io::Result<BoundedOutput> {
                let res = match stderr_pipe {
                    Some(pipe) => drain_stream(pipe, max_bytes, chunk_bytes, |chunk| {
                        let _ = tx_err.send((OutputStream::Stderr, chunk.to_vec()));
                        Ok(())
                    }),
                    None => Ok(BoundedOutput::default()),
                };
                drop(tx_err);
                res
            }) {
                Ok(h) => h,
                Err(e) => return abort(e),
            };

            let deadline = spec.timeout.map(|limit| Instant::now() + limit);
            let mut exited_status: Option<io::Result<std::process::ExitStatus>> = None;

            // Pump streamed chunks while polling child exit & timeout.
            loop {
                let mut channel_closed = false;
                match rx.recv_timeout(Duration::from_millis(5)) {
                    Ok((out_stream, data)) => {
                        if stream_err.is_none()
                            && let Err(e) = on_chunk(out_stream, &data)
                        {
                            stream_err = Some(e);
                        }
                        // Drain any immediately queued chunks before checking timers.
                        while let Ok((s, d)) = rx.try_recv() {
                            if stream_err.is_none()
                                && let Err(e) = on_chunk(s, &d)
                            {
                                stream_err = Some(e);
                            }
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        channel_closed = true;
                    }
                }

                if exited_status.is_none() {
                    match child.try_wait() {
                        Ok(Some(st)) => {
                            cgroup_killed = self.kill_exec(sub_cgroup.as_deref(), false);
                            exited_status = Some(Ok(st));
                        }
                        Ok(None) => {
                            if let Some(dl) = deadline
                                && Instant::now() >= dl
                            {
                                timed_out = true;
                                cgroup_killed = self.kill_exec(sub_cgroup.as_deref(), true);
                                let _ = child.kill();
                                exited_status = Some(child.wait());
                            }
                        }
                        Err(e) => {
                            cgroup_killed = self.kill_exec(sub_cgroup.as_deref(), true);
                            exited_status = Some(Err(e));
                        }
                    }
                }

                if channel_closed && exited_status.is_some() {
                    break;
                }
            }

            let status = exited_status.unwrap_or_else(|| child.wait());
            let out_res = stdout_handle
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("stdout drain thread panicked")));
            let err_res = stderr_handle
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("stderr drain thread panicked")));

            Ok((out_res, err_res, status))
        });
        let (stdout_res, stderr_res, status_res) = scoped.map_err(|e| {
            BackendError::new(
                ErrorCode::ExecFailed,
                format!("cannot start an output drain thread: {e}"),
            )
        })?;

        if let Some(cb_err) = stream_err {
            return Err(BackendError::new(
                ErrorCode::ExecFailed,
                format!("output stream write failed: {cb_err}"),
            ));
        }

        let status = status_res
            .map_err(|e| BackendError::new(ErrorCode::ExecFailed, format!("wait failed: {e}")))?;
        let stdout = stdout_res.map_err(|e| {
            BackendError::new(ErrorCode::ExecFailed, format!("stdout drain failed: {e}"))
        })?;
        let stderr = stderr_res.map_err(|e| {
            BackendError::new(ErrorCode::ExecFailed, format!("stderr drain failed: {e}"))
        })?;

        Ok(ExecOutcome {
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            cgroup_killed,
            duration: start.elapsed(),
            stdout,
            stderr,
        })
    }

    fn run_pre_freeze_hook(&self, argv: &[String], timeout: Duration) -> Result<(), BackendError> {
        let hook_id = format!(
            "prefreeze-{}",
            PREFREEZE_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let sub_cgroup = if self.enable_cgroup_isolation {
            let dir = self.cgroup.create_exec_subcgroup(&hook_id).map_err(|e| {
                BackendError::new(
                    ErrorCode::PreFreezeHookFailed,
                    format!("create pre_freeze sub-cgroup failed: {e}"),
                )
            })?;
            Some(dir)
        } else {
            None
        };

        let mut cmd = Command::new(&argv[0]);
        if argv.len() > 1 {
            cmd.args(&argv[1..]);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(dir) = &sub_cgroup {
            linux_sys::attach_child_to_cgroup(&mut cmd, dir.join("cgroup.procs")).map_err(|e| {
                BackendError::new(ErrorCode::PreFreezeHookFailed, e.to_string())
            })?;
        }
        linux_sys::prefer_child_for_oom_kill(&mut cmd);

        let spawn_guard = linux_sys::begin_child_spawn();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                drop(spawn_guard);
                if let Some(dir) = &sub_cgroup {
                    let _ = self.cgroup.remove_subcgroup(dir);
                }
                return Err(BackendError::new(
                    ErrorCode::PreFreezeHookFailed,
                    format!("pre_freeze hook '{}' failed to spawn: {e}", argv[0]),
                ));
            }
        };
        let _active_child = spawn_guard.register_pid(child.id());

        let deadline = Instant::now() + timeout;
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Ok(st),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        if let Some(dir) = &sub_cgroup {
                            self.kill_and_cleanup_subcgroup(dir, true);
                        }
                        let _ = child.kill();
                        break child.wait();
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => break Err(e),
            }
        };

        if let Some(dir) = &sub_cgroup
            && !timed_out
        {
            self.kill_and_cleanup_subcgroup(dir, false);
        }

        if timed_out {
            return Err(BackendError::new(
                ErrorCode::PreFreezeHookFailed,
                format!("pre_freeze hook timed out after {}ms", timeout.as_millis()),
            ));
        }

        let status = status.map_err(|e| {
            BackendError::new(
                ErrorCode::PreFreezeHookFailed,
                format!("wait for pre_freeze hook failed: {e}"),
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(BackendError::new(
                ErrorCode::PreFreezeHookFailed,
                format!("pre_freeze hook exited with {status}"),
            ))
        }
    }

    fn freeze_workload(&self, timeout: Duration) -> Result<Duration, BackendError> {
        self.cgroup
            .set_freeze_and_wait(true, timeout)
            .map_err(|e| BackendError::new(ErrorCode::FreezeTimeout, e.to_string()))
    }

    fn unfreeze_workload(&self, timeout: Duration) -> Result<Duration, BackendError> {
        self.cgroup
            .set_freeze_and_wait(false, timeout)
            .map_err(|e| BackendError::new(ErrorCode::UnfreezeFailed, e.to_string()))
    }

    fn sync_filesystems(&self, paths: &[String]) -> Result<SyncOutcome, BackendError> {
        let start = Instant::now();
        for p in paths {
            let file = File::open(p).map_err(|e| {
                BackendError::new(ErrorCode::SyncFailed, format!("open '{p}' for syncfs: {e}"))
            })?;
            linux_sys::syncfs_file(&file).map_err(|e| {
                BackendError::new(ErrorCode::SyncFailed, format!("syncfs('{p}') failed: {e}"))
            })?;
        }
        Ok(SyncOutcome {
            synced_paths: paths.len(),
            elapsed: start.elapsed(),
        })
    }

    fn reseed_entropy(&self, entropy: &[u8; RESEED_ENTROPY_LEN]) -> Result<(), BackendError> {
        linux_sys::inject_entropy_and_reseed(entropy)
            .map_err(|e| BackendError::new(ErrorCode::ReseedFailed, e.to_string()))
    }

    fn sync_clock_realtime(&self, secs: i64, nanos: u32) -> Result<(), BackendError> {
        linux_sys::set_clock_realtime(secs, nanos)
            .map_err(|e| BackendError::new(ErrorCode::ClockSyncFailed, e.to_string()))
    }

    fn kill_external_tcp(&self) -> Result<SocketKillReport, BackendError> {
        match self.kill_external_tcp_netlink() {
            Ok(report) => Ok(report),
            Err(nl_err) => {
                // Fall back to `ss -K` if netlink returned EOPNOTSUPP/ENOSYS/EPERM.
                self.kill_external_tcp_ss_fallback().map_err(|ss_err| {
                    BackendError::new(
                        ErrorCode::SocketKillFailed,
                        format!("netlink SOCK_DESTROY failed ({nl_err}); {ss_err}"),
                    )
                })
            }
        }
    }
}
