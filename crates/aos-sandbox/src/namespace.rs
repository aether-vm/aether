//! Phase 1 `NamespaceDriver` cold-fork implementation.
//!
//! Composes `config`, `client`, `seccomp`, and (on Linux) `linux_sys` with zero
//! `unsafe` code in this module.

#![forbid(unsafe_code)]

use crate::config::SpawnWorldSpec;
use crate::driver::{SandboxDriver, WorldHandle};
use crate::error::SandboxError;

/// Phase 1 Linux namespace-isolated cold-fork sandbox driver.
///
/// Isolates each `World` in fresh `userns`, `mountns` (`pivot_root`), `pidns`,
/// `ipcns`, `utsns`, and isolated `netns`, places it directly into
/// `<cgroup_root>/epoch-<e>/w-<id>` via `clone3(CLONE_INTO_CGROUP)`, drops all
/// capabilities, sets `PR_SET_NO_NEW_PRIVS`, installs the strict §7.4 / §5.1
/// `seccomp-bpf` filter, spawns static `aos-guest` over an inherited `socketpair`,
/// and verifies `Ping -> Pong` before returning [`WorldHandle`].
#[derive(Debug, Clone, Default)]
pub struct NamespaceDriver;

impl NamespaceDriver {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxDriver for NamespaceDriver {
    fn driver_name(&self) -> &'static str {
        "namespace"
    }

    #[cfg(target_os = "linux")]
    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<WorldHandle, SandboxError> {
        linux_impl::spawn_world_linux(spec)
    }

    #[cfg(not(target_os = "linux"))]
    fn spawn_world(&self, spec: SpawnWorldSpec) -> Result<WorldHandle, SandboxError> {
        spec.validate()?;
        Err(SandboxError::UnsupportedPlatform(
            "NamespaceDriver requires Linux (userns/mountns/clone3/seccomp/cgroup2)",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux_impl {
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    use aos_guest::{AgentState, CgroupV2Controller, ErrorCode};

    use crate::client::GuestRpcClient;
    use crate::config::{
        DEFAULT_USERNS_HOST_BASE, DEFAULT_USERNS_ID_COUNT, ExecOutputChunk, ExecReply, ExecRequest, FreezeOptions, FreezeReply, GuestAgentSource,
        IdMapRange, NetnsMode, PingReply, ResourceLimits, SeccompPolicy, SpawnWorldSpec,
        WorldInfo,
    };
    use crate::driver::{WorldBackend, WorldHandle};
    use crate::error::SandboxError;
    use crate::linux_sys::{
        self, AgentBindSource, ChildLaunchPlan, ChildStage, GUEST_CONTROL_FD,
    };
    use crate::seccomp::build_x86_64_baseline_filter;

    const HANDSHAKE_NONCE: u64 = 0x464C_4F4F_4D01;
    const EXEC_SOCKET_TIMEOUT_GRACE: Duration = Duration::from_secs(2);
    const DEFAULT_FREEZE_TIMEOUT: Duration = Duration::from_secs(5);

    struct NamespaceWorldBackend {
        info: WorldInfo,
        client: GuestRpcClient<File, File>,
        sock_raw_fd: RawFd,
        child_pid: i32,
        world_cgroup: Option<PathBuf>,
        rootfs_dir: PathBuf,
        frozen: bool,
        frozen_disk_clean: bool,
        poisoned: bool,
        destroyed: bool,
    }

    impl NamespaceWorldBackend {
        fn check_usable(&self) -> Result<(), SandboxError> {
            if self.destroyed {
                return Err(SandboxError::WorldDestroyed);
            }
            if self.poisoned {
                return Err(SandboxError::ProtocolViolation(
                    "sandbox control transport was poisoned after an I/O or timeout error"
                        .to_owned(),
                ));
            }
            Ok(())
        }
    }

    impl WorldBackend for NamespaceWorldBackend {
        fn info(&self) -> &WorldInfo {
            &self.info
        }

        fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError> {
            self.check_usable()?;
            if self.frozen {
                // `aos-guest` itself is frozen inside `w-<id>`, so return the host-authoritative
                // Frozen state without blocking on the frozen socketpair.
                return Ok(PingReply {
                    nonce,
                    state: AgentState::Frozen {
                        disk_clean: self.frozen_disk_clean,
                    },
                    uptime_ms: 0,
                    pid: 1,
                    epoch_generation: 0,
                });
            }
            match self.client.ping(nonce) {
                Ok(reply) => Ok(reply),
                Err(err @ (SandboxError::Codec(_) | SandboxError::Io(_))) => {
                    self.poisoned = true;
                    Err(err)
                }
                Err(err) => Err(err),
            }
        }

        fn exec_streaming(
            &mut self,
            req: ExecRequest,
            on_chunk: &mut dyn FnMut(ExecOutputChunk),
        ) -> Result<ExecReply, SandboxError> {
            self.check_usable()?;
            if self.frozen {
                return Err(SandboxError::GuestError {
                    code: ErrorCode::AgentFrozen,
                    message: "world cgroup is frozen; exec is rejected".to_owned(),
                });
            }

            if let Some(t) = req.timeout {
                let sock_timeout = t.saturating_add(EXEC_SOCKET_TIMEOUT_GRACE);
                linux_sys::set_socket_timeout(self.sock_raw_fd, Some(sock_timeout))?;
            }

            let res = self.client.exec_streaming(req, on_chunk);

            // Always reset host socket timeout afterward.
            let _ = linux_sys::set_socket_timeout(self.sock_raw_fd, None);

            match res {
                Ok(reply) => Ok(reply),
                Err(err @ (SandboxError::Codec(_) | SandboxError::Io(_))) => {
                    // Poison transport so a late frame from a timed-out guest cannot
                    // desynchronize subsequent req_ids.
                    self.poisoned = true;
                    Err(err)
                }
                Err(err) => Err(err),
            }
        }

        fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError> {
            self.check_usable()?;
            if self.frozen {
                return Err(SandboxError::GuestError {
                    code: ErrorCode::InvalidStateTransition,
                    message: "world is already frozen".to_owned(),
                });
            }

            let timeout = opts.freeze_timeout.unwrap_or(DEFAULT_FREEZE_TIMEOUT);

            // 1. Optional pre_freeze_hook runs inside the sandbox BEFORE host freezes w-<id>.
            if let Some(argv) = opts.pre_freeze_hook {
                if argv.is_empty() || argv[0].is_empty() {
                    return Err(SandboxError::InvalidConfig(
                        "pre_freeze_hook argv must be non-empty when provided".to_owned(),
                    ));
                }
                let mut hook_req = ExecRequest::new("pre-freeze-hook", argv);
                hook_req.timeout = Some(timeout);
                let reply = self
                    .exec_streaming(hook_req, &mut |_| {})
                    .map_err(|e| SandboxError::GuestError {
                        code: ErrorCode::PreFreezeHookFailed,
                        message: format!("pre_freeze_hook execution failed: {e}"),
                    })?;
                if reply.timed_out || reply.exit_code != Some(0) {
                    return Err(SandboxError::GuestError {
                        code: ErrorCode::PreFreezeHookFailed,
                        message: format!(
                            "pre_freeze_hook failed (exit={:?}, timed_out={})",
                            reply.exit_code, reply.timed_out
                        ),
                    });
                }
            }

            // 2. Host freezes the world cgroup `w-<id>` (which contains both workload and aos-guest).
            let cg = self.world_cgroup.as_ref().ok_or_else(|| {
                SandboxError::InvalidConfig(
                    "freeze_and_sync requires enable_cgroup=true on NamespaceDriver".to_owned(),
                )
            })?;
            let ctrl = CgroupV2Controller::new(cg);
            let frozen_elapsed = match ctrl.set_freeze_and_wait(true, timeout) {
                Ok(d) => d,
                Err(e) => {
                    let _ = ctrl.set_freeze_and_wait(false, timeout);
                    return Err(SandboxError::GuestError {
                        code: ErrorCode::FreezeTimeout,
                        message: e.to_string(),
                    });
                }
            };

            // 3. While frozen, flush the sandbox rootfs filesystem via host `syncfs(2)`.
            let (syncfs_elapsed, synced_paths) = if opts.perform_syncfs {
                let t_sync = Instant::now();
                if let Err(e) = linux_sys::syncfs_dir_nofollow(&self.rootfs_dir) {
                    let _ = ctrl.set_freeze_and_wait(false, timeout);
                    return Err(SandboxError::GuestError {
                        code: ErrorCode::SyncFailed,
                        message: format!("syncfs({:?}) failed: {e}", self.rootfs_dir),
                    });
                }
                (t_sync.elapsed(), 1usize)
            } else {
                (Duration::ZERO, 0usize)
            };

            self.frozen = true;
            self.frozen_disk_clean = opts.perform_syncfs;

            Ok(FreezeReply {
                disk_clean: opts.perform_syncfs,
                frozen_elapsed_ms: frozen_elapsed.as_millis() as u64,
                syncfs_elapsed_ms: syncfs_elapsed.as_millis() as u64,
                synced_paths,
            })
        }

        fn unfreeze(&mut self, timeout: Duration) -> Result<(), SandboxError> {
            self.check_usable()?;
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
            let cg = self.world_cgroup.as_ref().ok_or_else(|| {
                SandboxError::InvalidConfig(
                    "unfreeze requires enable_cgroup=true on NamespaceDriver".to_owned(),
                )
            })?;
            let ctrl = CgroupV2Controller::new(cg);
            ctrl.set_freeze_and_wait(false, timeout).map_err(|e| {
                SandboxError::GuestError {
                    code: ErrorCode::UnfreezeFailed,
                    message: e.to_string(),
                }
            })?;
            self.frozen = false;
            self.frozen_disk_clean = false;
            Ok(())
        }

        fn destroy(&mut self) -> Result<(), SandboxError> {
            if self.destroyed {
                return Ok(());
            }
            self.destroyed = true;
            teardown_world_resources(self.child_pid, self.world_cgroup.as_deref())
        }
    }

    pub fn spawn_world_linux(spec: SpawnWorldSpec) -> Result<WorldHandle, SandboxError> {
        spec.validate()?;

        let remap_root = remaps_root_ids(&spec);
        let (uid_map, gid_map) = effective_id_maps(&spec)?;

        // Refuse symlinked rootfs_dir itself (P0-2).
        let root_meta = fs::symlink_metadata(&spec.rootfs_dir).map_err(|e| {
            SandboxError::InvalidConfig(format!(
                "failed to stat rootfs_dir {:?}: {e}",
                spec.rootfs_dir
            ))
        })?;
        if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
            return Err(SandboxError::InvalidConfig(format!(
                "rootfs_dir must be a real non-symlink directory: {:?}",
                spec.rootfs_dir
            )));
        }

        // 1. Prepare per-epoch / per-world cgroup v2 directory.
        let world_cgroup = if spec.enable_cgroup {
            let path = spec.world_cgroup_path();
            let epoch_dir = path.parent().ok_or_else(|| {
                SandboxError::InvalidConfig("world cgroup path missing parent".to_owned())
            })?;
            fs::create_dir_all(epoch_dir).map_err(|e| SandboxError::cgroup(epoch_dir, e))?;
            enable_cgroup_controllers(epoch_dir, &spec.limits)?;
            // Leaf world cgroup MUST use `create_dir` (never silently reuse a colliding world).
            fs::create_dir(&path).map_err(|e| SandboxError::cgroup(&path, e))?;
            // Limits are in place before `clone3` puts the first task into the world.
            if let Err(e) = write_cgroup_limits(&path, &spec.limits) {
                let _ = fs::remove_dir(&path);
                return Err(e);
            }
            Some(path)
        } else {
            None
        };

        let cgroup_dirfd = match &world_cgroup {
            Some(path) => match linux_sys::open_dir_nofollow_cloexec(path) {
                Ok(fd) => Some(fd),
                Err(e) => {
                    let _ = fs::remove_dir(path);
                    return Err(SandboxError::cgroup(path, e));
                }
            },
            None => None,
        };

        // 2. Build async-signal-safe ChildLaunchPlan in parent BEFORE `clone3`.
        let (plan, idmapped_mounts) = match build_launch_plan(&spec) {
            Ok(p) => p,
            Err(e) => {
                drop(cgroup_dirfd);
                if let Some(cg) = &world_cgroup {
                    let _ = fs::remove_dir(cg);
                }
                return Err(e);
            }
        };

        // 3. Create CLOEXEC control socketpair + parent->child sync pipe + child->parent error pipe.
        let (host_sock, guest_sock) = linux_sys::create_cloexec_socketpair()?;
        let (sync_rd, sync_wr) = linux_sys::create_cloexec_pipe()?;
        let (err_rd, err_wr) = linux_sys::create_cloexec_pipe()?;

        // 4. Spawn isolated child via `clone3(CLONE_INTO_CGROUP | CLONE_NEW*)`.
        let child_pid = match linux_sys::spawn_isolated_child(
            &plan,
            cgroup_dirfd.as_ref().map(|fd| fd.as_raw_fd()),
            guest_sock.as_raw_fd(),
            sync_rd.as_raw_fd(),
            err_wr.as_raw_fd(),
        ) {
            Ok(pid) => pid,
            Err(e) => {
                drop(cgroup_dirfd);
                if let Some(cg) = &world_cgroup {
                    let _ = fs::remove_dir(cg);
                }
                return Err(SandboxError::spawn("clone3", e));
            }
        };

        // Parent immediately closes child-only ends and cgroup dirfd.
        drop(guest_sock);
        drop(sync_rd);
        drop(err_wr);
        drop(cgroup_dirfd);

        let cleanup_on_error = |cg: Option<&PathBuf>| {
            let _ = teardown_world_resources(child_pid, cg.map(|p| p.as_path()));
        };

        // 5. Configure UID/GID maps if userns is enabled, then idmap the still-detached mounts
        //    (shared with the child through inherited fds) with the child's user namespace.
        if spec.enable_userns
            && let Err(e) = configure_userns_maps(child_pid, &uid_map, &gid_map, remap_root)
                .and_then(|()| idmap_detached_mounts(child_pid, &idmapped_mounts))
        {
            drop(sync_wr);
            cleanup_on_error(world_cgroup.as_ref());
            return Err(e);
        }
        drop(idmapped_mounts);

        // 6. Release child to execute pivot_root, cap drop, seccomp, and execve.
        {
            let mut sync_file = File::from(sync_wr);
            if let Err(e) = sync_file.write_all(b"G") {
                cleanup_on_error(world_cgroup.as_ref());
                return Err(SandboxError::spawn("sync_pipe_write", e));
            }
        }

        // 7. Read child error pipe until EOF (FD_CLOEXEC closes it automatically on execve).
        let mut err_buf = Vec::new();
        {
            let mut err_file = File::from(err_rd);
            if let Err(e) = err_file.read_to_end(&mut err_buf) {
                cleanup_on_error(world_cgroup.as_ref());
                return Err(SandboxError::spawn("err_pipe_read", e));
            }
        }
        if !err_buf.is_empty() {
            cleanup_on_error(world_cgroup.as_ref());
            if err_buf.len() >= 8 {
                let stage_num = u32::from_ne_bytes([err_buf[0], err_buf[1], err_buf[2], err_buf[3]]);
                let errno = i32::from_ne_bytes([err_buf[4], err_buf[5], err_buf[6], err_buf[7]]);
                let os_err = io::Error::from_raw_os_error(errno);
                return Err(SandboxError::SpawnFailed {
                    stage: ChildStage::from_u32(stage_num),
                    message: format!("{os_err} (errno={errno})"),
                });
            }
            return Err(SandboxError::spawn(
                "child_setup",
                format!("unexpected {} bytes on child error pipe", err_buf.len()),
            ));
        }

        // 8. Perform initial framed v1 `Ping -> Pong` handshake with bounded timeout.
        if let Err(e) =
            linux_sys::set_socket_timeout(host_sock.as_raw_fd(), Some(spec.handshake_timeout))
        {
            cleanup_on_error(world_cgroup.as_ref());
            return Err(SandboxError::HandshakeFailed(format!(
                "failed to set handshake timeout: {e}"
            )));
        }

        let (reader, writer) = match linux_sys::split_owned_fd(host_sock) {
            Ok(pair) => pair,
            Err(e) => {
                cleanup_on_error(world_cgroup.as_ref());
                return Err(SandboxError::Io(e));
            }
        };
        let sock_raw_fd = reader.as_raw_fd();
        let mut client = GuestRpcClient::new(reader, writer);

        let pong = match client.ping(HANDSHAKE_NONCE) {
            Ok(p) => p,
            Err(e) => {
                drop(client);
                cleanup_on_error(world_cgroup.as_ref());
                return Err(SandboxError::HandshakeFailed(e.to_string()));
            }
        };
        if pong.state != AgentState::Ready {
            drop(client);
            cleanup_on_error(world_cgroup.as_ref());
            return Err(SandboxError::HandshakeFailed(format!(
                "expected guest Ready state on spawn, got {:?}",
                pong.state
            )));
        }

        // Clear handshake timeout; per-Exec timeouts are applied dynamically in `exec_streaming`.
        let _ = linux_sys::set_socket_timeout(sock_raw_fd, None);

        let info = WorldInfo {
            world_id: spec.world_id,
            epoch: spec.epoch,
            driver_name: "namespace",
            host_pid: Some(child_pid as u32),
            cgroup_path: world_cgroup.clone(),
            seccomp_enabled: spec.seccomp_policy == SeccompPolicy::StrictBaseline,
            userns_enabled: spec.enable_userns,
            netns_isolated: spec.netns_mode == NetnsMode::IsolatedLoopback,
        };

        let backend = NamespaceWorldBackend {
            info,
            client,
            sock_raw_fd,
            child_pid,
            world_cgroup,
            rootfs_dir: spec.rootfs_dir,
            frozen: false,
            frozen_disk_clean: false,
            poisoned: false,
            destroyed: false,
        };

        Ok(WorldHandle::from_backend(Box::new(backend)))
    }

    /// Delegate the controllers `limits` needs from the cgroup v2 mount root down to `dir`.
    fn enable_cgroup_controllers(dir: &Path, limits: &ResourceLimits) -> Result<(), SandboxError> {
        let wanted: Vec<&str> = [
            (limits.memory_max_bytes.is_some(), "memory"),
            (limits.pids_max.is_some(), "pids"),
            (limits.cpu_max_percent.is_some(), "cpu"),
        ]
        .into_iter()
        .filter_map(|(needed, name)| needed.then_some(name))
        .collect();
        let chain: Vec<&Path> = dir
            .ancestors()
            .take_while(|p| p.join("cgroup.controllers").exists())
            .collect();
        for parent in chain.into_iter().rev() {
            let path = parent.join("cgroup.subtree_control");
            let enabled =
                fs::read_to_string(&path).map_err(|e| SandboxError::cgroup(&path, e))?;
            for name in &wanted {
                if !enabled.split_whitespace().any(|c| c == *name) {
                    fs::write(&path, format!("+{name}"))
                        .map_err(|e| SandboxError::cgroup(&path, format!("+{name}: {e}")))?;
                }
            }
        }
        Ok(())
    }

    fn write_cgroup_limits(world_cg: &Path, limits: &ResourceLimits) -> Result<(), SandboxError> {
        let write = |file: &str, value: String| {
            let path = world_cg.join(file);
            fs::write(&path, value).map_err(|e| SandboxError::cgroup(&path, e))
        };
        if let Some(bytes) = limits.memory_max_bytes {
            write("memory.max", bytes.to_string())?;
            // The file is absent on kernels without swap accounting.
            if world_cg.join("memory.swap.max").exists() {
                write("memory.swap.max", "0".to_owned())?;
            }
        }
        if let Some(n) = limits.pids_max {
            write("pids.max", n.to_string())?;
        }
        if let Some(percent) = limits.cpu_max_percent {
            write("cpu.max", format!("{} 100000", u64::from(percent) * 1000))?;
        }
        Ok(())
    }

    /// Reject any symlink component along `rel_path` under `rootfs_dir` (P0-2).
    fn reject_symlinks_along(rootfs_dir: &Path, rel_path: &Path) -> Result<(), SandboxError> {
        let mut cur = rootfs_dir.to_path_buf();
        for comp in rel_path.components() {
            cur.push(comp.as_os_str());
            match fs::symlink_metadata(&cur) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return Err(SandboxError::InvalidConfig(format!(
                            "refusing symlink in rootfs mount path: {:?}",
                            cur
                        )));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => {
                    return Err(SandboxError::InvalidConfig(format!(
                        "failed to stat rootfs component {:?}: {e}",
                        cur
                    )));
                }
            }
        }
        Ok(())
    }

    /// A root `agentd` must back sandbox ids with unprivileged host ids. On-disk ownership stays
    /// unshifted: the rootfs is attached as an idmapped mount instead of being chowned.
    fn remaps_root_ids(spec: &SpawnWorldSpec) -> bool {
        spec.enable_userns && linux_sys::current_euid_egid().0 == 0
    }

    fn effective_id_maps(
        spec: &SpawnWorldSpec,
    ) -> Result<(Vec<IdMapRange>, Vec<IdMapRange>), SandboxError> {
        let (euid, egid) = linux_sys::current_euid_egid();
        let remap_root = remaps_root_ids(spec);
        let pick = |explicit: &[IdMapRange], own_id: u32| {
            if !explicit.is_empty() {
                explicit.to_vec()
            } else if remap_root {
                vec![IdMapRange::new(0, DEFAULT_USERNS_HOST_BASE, DEFAULT_USERNS_ID_COUNT)]
            } else {
                vec![IdMapRange::new(0, own_id, 1)]
            }
        };
        let uid_map = pick(&spec.uid_map, euid);
        let gid_map = pick(&spec.gid_map, egid);
        if remap_root && uid_map.iter().chain(&gid_map).any(|r| r.outside_id == 0) {
            return Err(SandboxError::InvalidConfig(
                "uid_map / gid_map must not map sandbox ids onto host id 0".to_owned(),
            ));
        }
        Ok((uid_map, gid_map))
    }

    fn idmap_detached_mounts(child_pid: i32, mounts: &[OwnedFd]) -> Result<(), SandboxError> {
        if mounts.is_empty() {
            return Ok(());
        }
        let userns = File::open(format!("/proc/{child_pid}/ns/user"))
            .map_err(|e| SandboxError::spawn("open_child_userns", e))?;
        for mnt in mounts {
            linux_sys::idmap_mount(mnt.as_raw_fd(), userns.as_raw_fd())
                .map_err(|e| SandboxError::spawn("idmap_mount", e))?;
        }
        Ok(())
    }

    /// Returns the plan plus the detached mounts its fds refer to; the caller must keep the
    /// latter open until `clone3` has returned and the mounts have been idmapped.
    fn build_launch_plan(
        spec: &SpawnWorldSpec,
    ) -> Result<(ChildLaunchPlan, Vec<OwnedFd>), SandboxError> {
        // Verify no symlinks at mount targets inside untrusted rootfs (P0-2).
        for rel in ["proc", "tmp", "dev", "dev/shm"] {
            reject_symlinks_along(&spec.rootfs_dir, Path::new(rel))?;
        }

        let rootfs = ChildLaunchPlan::path_to_cstr(&spec.rootfs_dir)?;

        let mut idmapped_mounts = Vec::new();
        let rootfs_mount_fd = if remaps_root_ids(spec) {
            let mnt = linux_sys::clone_detached_mount(&spec.rootfs_dir, false)
                .map_err(|e| SandboxError::spawn("clone_rootfs_mount", e))?;
            let fd = mnt.as_raw_fd();
            idmapped_mounts.push(mnt);
            Some(fd)
        } else {
            None
        };

        let mut dev_binds = Vec::new();
        for node in ["null", "zero", "urandom", "random", "full"] {
            reject_symlinks_along(&spec.rootfs_dir, &PathBuf::from("dev").join(node))?;
            let src_path = PathBuf::from("/dev").join(node);
            if src_path.exists() {
                let src = ChildLaunchPlan::path_to_cstr(&src_path)?;
                let dst = ChildLaunchPlan::path_to_cstr(&PathBuf::from("dev").join(node))?;
                dev_binds.push((src, dst));
            }
        }

        let (exec_inside_path, agent_bind) = match &spec.guest_agent {
            GuestAgentSource::InRootfs(p) => (p.clone(), None),
            GuestAgentSource::BindMountHostBinary {
                host_path,
                guest_mount_path,
            } => {
                if !host_path.is_file() {
                    return Err(SandboxError::InvalidConfig(format!(
                        "BindMountHostBinary host_path is not an existing file: {:?}",
                        host_path
                    )));
                }
                let rel = guest_mount_path
                    .strip_prefix("/")
                    .unwrap_or(guest_mount_path.as_path());
                reject_symlinks_along(&spec.rootfs_dir, rel)?;
                let dst_on_host = spec.rootfs_dir.join(rel);
                if !dst_on_host.exists() {
                    return Err(SandboxError::InvalidConfig(format!(
                        "BindMountHostBinary mountpoint does not exist inside rootfs: {:?}",
                        dst_on_host
                    )));
                }
                let dst_c = ChildLaunchPlan::path_to_cstr(rel)?;
                let src = if rootfs_mount_fd.is_some() {
                    let mnt = linux_sys::clone_detached_mount(host_path, true)
                        .map_err(|e| SandboxError::spawn("clone_agent_mount", e))?;
                    let fd = mnt.as_raw_fd();
                    idmapped_mounts.push(mnt);
                    AgentBindSource::DetachedMount(fd)
                } else {
                    AgentBindSource::HostPath(ChildLaunchPlan::path_to_cstr(host_path)?)
                };
                (guest_mount_path.clone(), Some((src, dst_c)))
            }
        };

        let exec_path = ChildLaunchPlan::path_to_cstr(&exec_inside_path)?;

        let mut argv_storage = Vec::with_capacity(4 + spec.extra_guest_args.len());
        argv_storage.push(exec_path.clone());
        argv_storage.push(
            CString::new("--socketpair-fd")
                .map_err(|e| SandboxError::InvalidConfig(e.to_string()))?,
        );
        argv_storage.push(
            CString::new(GUEST_CONTROL_FD.to_string())
                .map_err(|e| SandboxError::InvalidConfig(e.to_string()))?,
        );
        for extra in &spec.extra_guest_args {
            argv_storage.push(
                CString::new(extra.as_str())
                    .map_err(|e| SandboxError::InvalidConfig(e.to_string()))?,
            );
        }
        let mut argv_ptrs: Vec<*const libc::c_char> =
            argv_storage.iter().map(|s| s.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());

        let envp_storage = vec![
            CString::new("PATH=/sbin:/usr/sbin:/bin:/usr/bin").expect("static env"),
            CString::new("HOME=/root").expect("static env"),
            CString::new("TERM=dumb").expect("static env"),
        ];
        let mut envp_ptrs: Vec<*const libc::c_char> =
            envp_storage.iter().map(|s| s.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());

        let seccomp_filter = match spec.seccomp_policy {
            SeccompPolicy::StrictBaseline => Some(build_x86_64_baseline_filter()),
            SeccompPolicy::Disabled => None,
        };

        let plan = ChildLaunchPlan {
            enable_userns: spec.enable_userns,
            drop_groups: remaps_root_ids(spec),
            rootfs_mount_fd,
            isolate_netns: spec.netns_mode == NetnsMode::IsolatedLoopback,
            rootfs,
            dev_binds,
            agent_bind,
            hostname: spec.effective_hostname().into_bytes(),
            exec_path,
            argv_storage,
            argv_ptrs,
            envp_storage,
            envp_ptrs,
            seccomp_filter,
        };
        Ok((plan, idmapped_mounts))
    }

    fn configure_userns_maps(
        child_pid: i32,
        uid_map: &[IdMapRange],
        gid_map: &[IdMapRange],
        remap_root: bool,
    ) -> Result<(), SandboxError> {
        let proc_dir = PathBuf::from(format!("/proc/{child_pid}"));

        // Deny setgroups when unprivileged (required by Linux before writing gid_map without
        // CAP_SETGID in the parent userns). Under a root agentd it stays allowed so the child
        // can drop the supplementary groups it inherited from the host.
        if !remap_root {
            fs::write(proc_dir.join("setgroups"), "deny")
                .map_err(|e| SandboxError::spawn("write_setgroups", e))?;
        }

        let uid_text: String = uid_map.iter().map(IdMapRange::format_proc_line).collect();
        fs::write(proc_dir.join("uid_map"), uid_text)
            .map_err(|e| SandboxError::spawn("write_uid_map", e))?;

        let gid_text: String = gid_map.iter().map(IdMapRange::format_proc_line).collect();
        fs::write(proc_dir.join("gid_map"), gid_text)
            .map_err(|e| SandboxError::spawn("write_gid_map", e))?;

        Ok(())
    }

    /// Deterministically kill the entire world process tree (`cgroup.kill` + fallback
    /// freeze/SIGKILL loop + unfreeze), reap `child_pid` (destroying its private `netns`),
    /// and remove the empty world cgroup directory.
    fn teardown_world_resources(
        child_pid: i32,
        world_cgroup: Option<&Path>,
    ) -> Result<(), SandboxError> {
        if let Some(cg) = world_cgroup {
            let ctrl = CgroupV2Controller::new(cg);
            match ctrl.trigger_cgroup_kill(cg) {
                Ok(true) => {
                    // Ensure frozen cgroup is unfrozen so killed tasks finish exiting cleanly.
                    let _ = ctrl.write_freeze_at(cg, false);
                }
                Ok(false) | Err(_) => {
                    let _ = ctrl.write_freeze_at(cg, true);
                    let deadline = Instant::now() + Duration::from_millis(500);
                    while Instant::now() < deadline {
                        let Ok(pids) = ctrl.read_pids(cg) else {
                            break;
                        };
                        if pids.is_empty() {
                            break;
                        }
                        for pid in pids {
                            let _ = linux_sys::kill_pid_sigkill(pid);
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                    let _ = ctrl.write_freeze_at(cg, false);
                }
            }
        }

        let _ = linux_sys::kill_pid_sigkill(child_pid);
        linux_sys::reap_child_blocking(child_pid)?;

        if let Some(cg) = world_cgroup {
            let deadline = Instant::now() + Duration::from_millis(500);
            loop {
                match fs::remove_dir(cg) {
                    Ok(()) => break,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                    Err(_) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => return Err(SandboxError::cgroup(cg, e)),
                }
            }
        }

        Ok(())
    }
}
