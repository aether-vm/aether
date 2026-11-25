//! Cross-platform unit and integration tests for `aos-sandbox`.
//!
//! Runs natively on Windows, macOS, and Linux with zero `unsafe` code:
//! - Exhaustively verifies the compiled `x86_64` seccomp-BPF bytecode via our
//!   pure-Rust cBPF VM evaluator (`eval_filter`).
//! - Verifies `SpawnWorldSpec` validation, cgroup path formatting, and `IdMapRange`.
//! - Verifies full `GuestRpcClient` + `WorldHandle` round-trips against a live
//!   in-memory `aos_guest::AgentServer` (Ping, streaming Exec, FreezeAndSync,
//!   idempotent destroy, post-destroy rejection).

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use aos_guest::{
    AgentServer, AgentState, BackendError, ErrorCode, ExecOutcome, ExecSpec, GuestBackend,
    OutputStream, RESEED_ENTROPY_LEN, SocketKillReport, SyncOutcome, drain_stream,
};
use aos_sandbox::seccomp::{
    CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME,
    CLONE_NEWUTS, nr,
};
use aos_sandbox::{
    AUDIT_ARCH_X86_64, BLOCKED_EPERM_SYSCALLS, CLONE_NEWUSER, ENOSYS, EOPNOTSUPP, EPERM,
    ExecOutputChunk, ExecReply, ExecRequest, FreezeOptions, FreezeReply, GuestAgentSource,
    GuestRpcClient, IdMapRange, PingReply, RpcWorldBackend, SECCOMP_RET_ALLOW,
    SECCOMP_RET_KILL_PROCESS, SandboxError, SeccompData, SpawnWorldSpec, WorldBackend,
    WorldHandle, WorldInfo, build_x86_64_baseline_filter, eval_filter, ret_errno,
};
#[cfg(not(target_os = "linux"))]
use aos_sandbox::{NamespaceDriver, SandboxDriver};
use aos_types::{EpochId, WorldId};

// ---------------------------------------------------------------------------
// 1. Seccomp-BPF Bytecode Verification (Pure-Rust cBPF VM)
// ---------------------------------------------------------------------------

#[test]
fn seccomp_filter_verifies_arch_and_blocks_x32() {
    let filter = build_x86_64_baseline_filter();

    // Non-x86_64 arch (e.g. i386 = 0x4000_0003) MUST kill process.
    let i386 = SeccompData {
        nr: 1,
        arch: 0x4000_0003,
        instruction_pointer: 0,
        args: [0; 6],
    };
    assert_eq!(eval_filter(&filter, &i386).unwrap(), SECCOMP_RET_KILL_PROCESS);

    // x32 ABI syscall (bit 30 set) MUST kill process.
    let x32 = SeccompData::x86_64(0x4000_0000 | 1, [0; 6]);
    assert_eq!(eval_filter(&filter, &x32).unwrap(), SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn seccomp_filter_btrfs_ioctl_returns_eopnotsupp_not_kill() {
    let filter = build_x86_64_baseline_filter();

    // FICLONE = _IOW(0x94, 9, int) = 0x4004_9409
    // BTRFS_IOC_SUBVOL_CREATE = _IOW(0x94, 14, ...) = 0x5000_940E
    // BTRFS_IOC_SUBVOL_SETFLAGS = _IOW(0x94, 26, __u64) = 0x4008_941A
    // BTRFS_IOC_SNAP_DESTROY_V2 = _IOW(0x94, 63, ...) = 0x5000_943F
    for btrfs_cmd in [0x4004_9409u64, 0x5000_940Eu64, 0x4008_941Au64, 0x5000_943Fu64] {
        let data = SeccompData::x86_64(nr::IOCTL, [3, btrfs_cmd, 0, 0, 0, 0]);
        assert_eq!(
            eval_filter(&filter, &data).unwrap(),
            ret_errno(EOPNOTSUPP),
            "Btrfs ioctl 0x{btrfs_cmd:x} must return EOPNOTSUPP (not SIGSYS/KILL)"
        );
    }

    // Standard non-Btrfs ioctls (TIOCGWINSZ, TCGETS, FIONBIO, SIOCGIFFLAGS) MUST be allowed.
    for safe_cmd in [0x5413u64, 0x5401u64, 0x5421u64, 0x8913u64] {
        let data = SeccompData::x86_64(nr::IOCTL, [1, safe_cmd, 0, 0, 0, 0]);
        assert_eq!(
            eval_filter(&filter, &data).unwrap(),
            SECCOMP_RET_ALLOW,
            "non-Btrfs ioctl 0x{safe_cmd:x} should be allowed"
        );
    }
}

#[test]
fn seccomp_filter_blocks_nested_namespaces_mounts_iouring_bpf_ptrace_kexec() {
    let filter = build_x86_64_baseline_filter();

    // Every unconditionally blocked §7.4 syscall returns EPERM.
    for &sys_nr in BLOCKED_EPERM_SYSCALLS {
        let data = SeccompData::x86_64(sys_nr, [0; 6]);
        assert_eq!(
            eval_filter(&filter, &data).unwrap(),
            ret_errno(EPERM),
            "syscall nr {sys_nr} must return EPERM"
        );
    }

    // clone3 returns ENOSYS so glibc/musl pthread_create falls back cleanly to clone(2).
    assert_eq!(
        eval_filter(&filter, &SeccompData::x86_64(nr::CLONE3, [0; 6])).unwrap(),
        ret_errno(ENOSYS)
    );

    // clone(2) with ANY CLONE_NEW* bit (including CLONE_NEWTIME) returns EPERM.
    for ns_flag in [
        CLONE_NEWTIME,
        CLONE_NEWUSER,
        CLONE_NEWNS,
        CLONE_NEWPID,
        CLONE_NEWNET,
        CLONE_NEWIPC,
        CLONE_NEWUTS,
        CLONE_NEWCGROUP,
        CLONE_NEWUSER | 17, // CLONE_NEWUSER | SIGCHLD
    ] {
        let data = SeccompData::x86_64(nr::CLONE, [u64::from(ns_flag), 0, 0, 0, 0, 0]);
        assert_eq!(
            eval_filter(&filter, &data).unwrap(),
            ret_errno(EPERM),
            "clone with flag 0x{ns_flag:x} must return EPERM"
        );
    }

    // Normal thread clone (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD = 0x10f00)
    // and normal fork clone (SIGCHLD = 17) MUST be allowed!
    for ok_flags in [0x0001_0F00u64, 17u64, 0x003D_0F00u64] {
        let data = SeccompData::x86_64(nr::CLONE, [ok_flags, 0, 0, 0, 0, 0]);
        assert_eq!(
            eval_filter(&filter, &data).unwrap(),
            SECCOMP_RET_ALLOW,
            "normal clone flags 0x{ok_flags:x} should be allowed"
        );
    }

    // Standard workload syscalls MUST be allowed.
    for ok_nr in [0u32, 1, 2, 3, 9, 59, 41, 42, 202, 257] {
        let data = SeccompData {
            nr: ok_nr,
            arch: AUDIT_ARCH_X86_64,
            instruction_pointer: 0x7fff_1234,
            args: [0; 6],
        };
        assert_eq!(eval_filter(&filter, &data).unwrap(), SECCOMP_RET_ALLOW);
    }
}

// ---------------------------------------------------------------------------
// 2. Spec Validation & Cgroup Path Formatting
// ---------------------------------------------------------------------------

#[test]
fn spawn_spec_validation_and_cgroup_path_layout() {
    let wid = WorldId::random();
    let epoch = EpochId::new(7).unwrap();
    let spec = SpawnWorldSpec::new(
        wid,
        epoch,
        "/var/lib/forkloom/pool/objects/w-rootfs",
        GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
    );
    spec.validate().unwrap();

    let cg = spec.world_cgroup_path();
    let cg_str = cg.to_string_lossy().replace('\\', "/");
    assert!(
        cg_str.ends_with(&format!("forkloom.slice/epoch-7/w-{wid}")),
        "unexpected cgroup path: {cg_str}"
    );
    assert_eq!(IdMapRange::new(0, 1000, 1).format_proc_line(), "0 1000 1\n");

    // Reject empty rootfs_dir.
    let mut bad = spec.clone();
    bad.rootfs_dir = PathBuf::new();
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    // Reject relative InRootfs path and traversal (`..` / `.`) in guest paths.
    let mut bad = spec.clone();
    bad.guest_agent = GuestAgentSource::InRootfs(PathBuf::from("sbin/init"));
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    let mut bad = spec.clone();
    bad.guest_agent = GuestAgentSource::InRootfs(PathBuf::from("/sbin/../etc/passwd"));
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    let mut bad = spec.clone();
    bad.guest_agent = GuestAgentSource::BindMountHostBinary {
        host_path: PathBuf::from("/usr/bin/aos-guest"),
        guest_mount_path: PathBuf::from("/usr/bin/../../../etc/passwd"),
    };
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    let mut bad = spec.clone();
    bad.guest_agent = GuestAgentSource::BindMountHostBinary {
        host_path: PathBuf::from("/usr/bin/aos-guest"),
        guest_mount_path: PathBuf::from("/usr/./bin/aos-guest"),
    };
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    // Reject zero resource limits.
    let mut bad = spec.clone();
    bad.limits.pids_max = Some(0);
    assert!(matches!(
        bad.validate(),
        Err(SandboxError::InvalidConfig(_))
    ));

    // Reject zero-count uid_map.
    let mut bad = spec.clone();
    bad.uid_map = vec![IdMapRange::new(0, 1000, 0)];
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));

    // Reject zero handshake timeout.
    let mut bad = spec;
    bad.handshake_timeout = Duration::ZERO;
    assert!(matches!(bad.validate(), Err(SandboxError::InvalidConfig(_))));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn namespace_driver_returns_unsupported_platform_on_non_linux() {
    let driver = NamespaceDriver::new();
    assert_eq!(driver.driver_name(), "namespace");
    let spec = SpawnWorldSpec::new(
        WorldId::random(),
        EpochId::new(1).unwrap(),
        "/tmp/fake-rootfs",
        GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
    );
    assert!(matches!(
        driver.spawn_world(spec),
        Err(SandboxError::UnsupportedPlatform(_))
    ));
}

// ---------------------------------------------------------------------------
// 3. Bidirectional In-Memory Transport Round-Trip with Real `aos_guest::AgentServer`
// ---------------------------------------------------------------------------

struct PipeInner {
    buf: VecDeque<u8>,
    closed: bool,
}

fn in_mem_pipe() -> (InMemReader, InMemWriter) {
    let state = Arc::new((
        Mutex::new(PipeInner {
            buf: VecDeque::new(),
            closed: false,
        }),
        Condvar::new(),
    ));
    (
        InMemReader {
            state: Arc::clone(&state),
        },
        InMemWriter { state },
    )
}

struct InMemReader {
    state: Arc<(Mutex<PipeInner>, Condvar)>,
}

impl Read for InMemReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().unwrap();
        while guard.buf.is_empty() && !guard.closed {
            guard = cvar.wait(guard).unwrap();
        }
        let mut n = 0;
        while n < out.len() {
            let Some(b) = guard.buf.pop_front() else {
                break;
            };
            out[n] = b;
            n += 1;
        }
        Ok(n)
    }
}

struct InMemWriter {
    state: Arc<(Mutex<PipeInner>, Condvar)>,
}

impl Write for InMemWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().unwrap();
        if guard.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"));
        }
        guard.buf.extend(data);
        cvar.notify_all();
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for InMemWriter {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut guard = lock.lock().unwrap();
        guard.closed = true;
        cvar.notify_all();
    }
}

struct FakeGuestBackend;

impl GuestBackend for FakeGuestBackend {
    fn run_exec(
        &self,
        spec: ExecSpec,
        on_chunk: &mut dyn FnMut(OutputStream, &[u8]) -> io::Result<()>,
    ) -> Result<ExecOutcome, BackendError> {
        let out_bytes = format!("ran:{}", spec.argv.join(" ")).into_bytes();
        let err_bytes = b"stderr-note".to_vec();
        let stdout = drain_stream(
            Cursor::new(out_bytes),
            spec.max_output_bytes,
            spec.stream_chunk_bytes,
            |c| on_chunk(OutputStream::Stdout, c),
        )
        .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;
        let stderr = drain_stream(
            Cursor::new(err_bytes),
            spec.max_output_bytes,
            spec.stream_chunk_bytes,
            |c| on_chunk(OutputStream::Stderr, c),
        )
        .map_err(|e| BackendError::new(ErrorCode::ExecFailed, e.to_string()))?;

        Ok(ExecOutcome {
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            cgroup_killed: false,
            duration: Duration::from_millis(1),
            stdout,
            stderr,
        })
    }

    fn run_pre_freeze_hook(&self, _argv: &[String], _timeout: Duration) -> Result<(), BackendError> {
        Ok(())
    }

    fn freeze_workload(&self, _timeout: Duration) -> Result<Duration, BackendError> {
        Ok(Duration::from_millis(1))
    }

    fn unfreeze_workload(&self, _timeout: Duration) -> Result<Duration, BackendError> {
        Ok(Duration::from_millis(1))
    }

    fn sync_filesystems(&self, paths: &[String]) -> Result<SyncOutcome, BackendError> {
        Ok(SyncOutcome {
            synced_paths: paths.len(),
            elapsed: Duration::from_millis(1),
        })
    }

    fn reseed_entropy(&self, _entropy: &[u8; RESEED_ENTROPY_LEN]) -> Result<(), BackendError> {
        Ok(())
    }

    fn sync_clock_realtime(&self, _secs: i64, _nanos: u32) -> Result<(), BackendError> {
        Ok(())
    }

    fn kill_external_tcp(&self) -> Result<SocketKillReport, BackendError> {
        Ok(SocketKillReport::default())
    }
}

#[test]
fn world_handle_roundtrips_ping_streaming_exec_freeze_and_idempotent_destroy() {
    let (mut srv_rd, cli_wr) = in_mem_pipe();
    let (cli_rd, mut srv_wr) = in_mem_pipe();

    let server_thread = thread::spawn(move || {
        let mut srv = AgentServer::new(FakeGuestBackend);
        srv.serve_connection(&mut srv_rd, &mut srv_wr).unwrap();
    });

    let destroy_count = Arc::new(AtomicUsize::new(0));
    let destroy_count_cb = Arc::clone(&destroy_count);

    let info = WorldInfo {
        world_id: WorldId::random(),
        epoch: EpochId::new(1).unwrap(),
        driver_name: "in-memory-test",
        host_pid: Some(4242),
        cgroup_path: None,
        seccomp_enabled: true,
        userns_enabled: true,
        netns_isolated: true,
    };

    let client = GuestRpcClient::new(cli_rd, cli_wr);
    let backend = RpcWorldBackend::new(info, client, move || {
        destroy_count_cb.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let mut handle = WorldHandle::from_backend(Box::new(backend));

    // 1. Ping
    let pong = handle.ping(777).unwrap();
    assert_eq!(pong.nonce, 777);
    assert_eq!(pong.state, AgentState::Ready);

    // 2. Streaming Exec
    let mut req = ExecRequest::new("e1", vec!["echo".into(), "hello-sandbox".into()]);
    req.stream_chunk_bytes = Some(4);
    let mut streamed_out = Vec::new();
    let mut streamed_err = Vec::new();
    let reply = handle
        .exec_streaming(req, |chunk| match chunk.stream {
            OutputStream::Stdout => streamed_out.extend_from_slice(&chunk.data),
            OutputStream::Stderr => streamed_err.extend_from_slice(&chunk.data),
        })
        .unwrap();
    assert_eq!(reply.exit_code, Some(0));
    assert!(!reply.cgroup_killed);
    assert_eq!(streamed_out, b"ran:echo hello-sandbox");
    assert_eq!(streamed_err, b"stderr-note");
    assert_eq!(reply.stdout.head.as_slice(), b"ran:echo hello-sandbox");

    // 3. FreezeAndSync -> FrozenAck { disk_clean: true }
    let freeze = handle.freeze_and_sync(FreezeOptions::disk_clean()).unwrap();
    assert!(freeze.disk_clean);
    assert_eq!(freeze.synced_paths, 1);

    // 4. Exec while frozen -> GuestError(AgentFrozen)
    let err = handle
        .exec(ExecRequest::new("e2", vec!["/bin/true".into()]))
        .unwrap_err();
    assert!(matches!(
        err,
        SandboxError::GuestError {
            code: ErrorCode::AgentFrozen,
            ..
        }
    ));

    // 5. Idempotent destroy & post-destroy guard
    handle.destroy().unwrap();
    handle.destroy().unwrap();
    assert_eq!(destroy_count.load(Ordering::SeqCst), 1);
    assert!(matches!(handle.ping(1), Err(SandboxError::WorldDestroyed)));
    assert!(matches!(
        handle.unfreeze(Duration::from_secs(1)),
        Err(SandboxError::WorldDestroyed)
    ));

    drop(handle);
    assert_eq!(destroy_count.load(Ordering::SeqCst), 1);
    server_thread.join().unwrap();
}

struct StatefulFreezeMockBackend {
    info: WorldInfo,
    frozen: bool,
    disk_clean: bool,
    unfreeze_calls: usize,
}

impl WorldBackend for StatefulFreezeMockBackend {
    fn info(&self) -> &WorldInfo {
        &self.info
    }

    fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError> {
        let state = if self.frozen {
            AgentState::Frozen {
                disk_clean: self.disk_clean,
            }
        } else {
            AgentState::Ready
        };
        Ok(PingReply {
            nonce,
            state,
            uptime_ms: 10,
            pid: 1,
            epoch_generation: 0,
        })
    }

    fn exec_streaming(
        &mut self,
        req: ExecRequest,
        _on_chunk: &mut dyn FnMut(ExecOutputChunk),
    ) -> Result<ExecReply, SandboxError> {
        if self.frozen {
            return Err(SandboxError::GuestError {
                code: ErrorCode::AgentFrozen,
                message: "world is frozen".to_owned(),
            });
        }
        Ok(ExecReply {
            exec_id: req.exec_id,
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            cgroup_killed: false,
            duration_ms: 1,
            stdout: Default::default(),
            stderr: Default::default(),
        })
    }

    fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError> {
        if self.frozen {
            return Err(SandboxError::GuestError {
                code: ErrorCode::InvalidStateTransition,
                message: "already frozen".to_owned(),
            });
        }
        self.frozen = true;
        self.disk_clean = opts.perform_syncfs;
        Ok(FreezeReply {
            disk_clean: opts.perform_syncfs,
            frozen_elapsed_ms: 1,
            syncfs_elapsed_ms: 1,
            synced_paths: usize::from(opts.perform_syncfs),
        })
    }

    fn unfreeze(&mut self, timeout: Duration) -> Result<(), SandboxError> {
        if !self.frozen {
            return Err(SandboxError::GuestError {
                code: ErrorCode::InvalidStateTransition,
                message: "world is not frozen".to_owned(),
            });
        }
        if timeout.is_zero() {
            return Err(SandboxError::InvalidConfig(
                "unfreeze timeout must be > 0".to_owned(),
            ));
        }
        self.frozen = false;
        self.disk_clean = false;
        self.unfreeze_calls += 1;
        Ok(())
    }

    fn destroy(&mut self) -> Result<(), SandboxError> {
        Ok(())
    }
}

#[test]
fn world_handle_freeze_unfreeze_resume_exec_lifecycle() {
    let info = WorldInfo {
        world_id: WorldId::random(),
        epoch: EpochId::new(2).unwrap(),
        driver_name: "stateful-mock",
        host_pid: Some(100),
        cgroup_path: None,
        seccomp_enabled: true,
        userns_enabled: true,
        netns_isolated: true,
    };
    let backend = StatefulFreezeMockBackend {
        info,
        frozen: false,
        disk_clean: false,
        unfreeze_calls: 0,
    };
    let mut handle = WorldHandle::from_backend(Box::new(backend));

    // Unfreeze before freeze -> InvalidStateTransition.
    let err = handle.unfreeze(Duration::from_secs(5)).unwrap_err();
    assert!(matches!(
        err,
        SandboxError::GuestError {
            code: ErrorCode::InvalidStateTransition,
            ..
        }
    ));

    // Exec -> FreezeAndSync -> Exec blocked (AgentFrozen) -> Ping Frozen.
    assert_eq!(
        handle
            .exec(ExecRequest::new("pre-freeze", vec!["/bin/true".into()]))
            .unwrap()
            .exit_code,
        Some(0)
    );
    let f = handle.freeze_and_sync(FreezeOptions::disk_clean()).unwrap();
    assert!(f.disk_clean);
    assert!(matches!(
        handle.ping(10).unwrap().state,
        AgentState::Frozen { disk_clean: true }
    ));
    assert!(matches!(
        handle.exec(ExecRequest::new("blocked", vec!["/bin/true".into()])),
        Err(SandboxError::GuestError {
            code: ErrorCode::AgentFrozen,
            ..
        })
    ));

    // Unfreeze -> Ping Ready -> subsequent Exec succeeds!
    handle.unfreeze(Duration::from_secs(5)).unwrap();
    assert_eq!(handle.ping(11).unwrap().state, AgentState::Ready);
    assert_eq!(
        handle
            .exec(ExecRequest::new("post-unfreeze", vec!["/bin/true".into()]))
            .unwrap()
            .exit_code,
        Some(0)
    );
}
