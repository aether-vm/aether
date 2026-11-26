//! Minimal, isolated Linux syscall wrappers for `NamespaceDriver`.
//!
//! This is the ONLY module in `aos-sandbox` permitted to contain `unsafe` code,
//! and it is compiled exclusively on `target_os = "linux"`.
//!
//! CRITICAL INVARIANT: Everything executed in the child process after `clone3`
//! returns `0` is strictly async-signal-safe (zero heap allocations, zero locks,
//! zero Rust std I/O). All `CString`s, pointer arrays, and BPF filter buffers
//! are prepared in the parent BEFORE `clone3` is invoked.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

use crate::seccomp::{
    CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWUSER, CLONE_NEWUTS, SockFilter,
};

// Linux x86_64 syscall numbers & constants (verified against scout #52).
const SYS_CLONE3: libc::c_long = 435;
const SYS_CLOSE_RANGE: libc::c_long = 436;
const SYS_PIVOT_ROOT: libc::c_long = 155;
const SYS_CAPSET: libc::c_long = 126;
const SYS_SECCOMP: libc::c_long = 317;
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_MOUNT_SETATTR: libc::c_long = 442;

const OPEN_TREE_CLONE: libc::c_uint = 1;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

const CLONE_INTO_CGROUP: u64 = 0x0002_0000_0000;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAPBSET_DROP: libc::c_int = 24;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

/// Control socketpair fd number inherited by `aos-guest --socketpair-fd 3`.
pub const GUEST_CONTROL_FD: RawFd = 3;

/// Linux `struct clone_args` (88 bytes, `<uapi/linux/sched.h>`).
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// Linux `struct mount_attr` (32 bytes, `<uapi/linux/mount.h>`).
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Linux `struct sock_fprog` (`<uapi/linux/filter.h>`).
#[repr(C)]
struct SockFprog {
    len: libc::c_ushort,
    filter: *const SockFilter,
}

/// Linux `struct __user_cap_header_struct` (`<uapi/linux/capability.h>`).
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

/// Linux `struct __user_cap_data_struct` (`<uapi/linux/capability.h>`).
#[repr(C)]
#[derive(Clone, Copy)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Numeric child setup stage codes reported back over `err_pipe` on failure.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildStage {
    WaitParentSync = 1,
    SetResGid = 2,
    SetResUid = 3,
    RaiseLoopback = 4,
    SetHostname = 5,
    MountRootPrivate = 6,
    BindRootfs = 7,
    MountProc = 8,
    MountTmp = 9,
    MountDev = 10,
    BindDevNode = 11,
    BindAgentBinary = 12,
    ChdirRootfs = 13,
    PivotRoot = 14,
    UmountOldRoot = 15,
    ChdirNewRoot = 16,
    DupControlFd = 17,
    DropCaps = 18,
    NoNewPrivs = 19,
    InstallSeccomp = 20,
    ExecGuest = 21,
    MountDevShm = 22,
    CloseRange = 23,
    SetGroups = 24,
}

impl ChildStage {
    pub fn from_u32(v: u32) -> &'static str {
        match v {
            1 => "wait_parent_sync",
            2 => "setresgid",
            3 => "setresuid",
            4 => "raise_loopback",
            5 => "sethostname",
            6 => "mount_root_private",
            7 => "bind_rootfs",
            8 => "mount_proc",
            9 => "mount_tmp",
            10 => "mount_dev",
            11 => "bind_dev_node",
            12 => "bind_agent_binary",
            13 => "chdir_rootfs",
            14 => "pivot_root",
            15 => "umount_old_root",
            16 => "chdir_new_root",
            17 => "dup_control_fd",
            18 => "drop_caps",
            19 => "pr_set_no_new_privs",
            20 => "install_seccomp",
            21 => "execve_aos_guest",
            22 => "mount_dev_shm",
            23 => "close_range_cloexec",
            24 => "setgroups",
            _ => "unknown_child_stage",
        }
    }
}

/// Source of the read-only `aos-guest` bind mount.
pub enum AgentBindSource {
    /// Host path bind-mounted by the child itself (unprivileged `agentd`).
    HostPath(CString),
    /// Detached read-only idmapped mount prepared by the parent (root `agentd`).
    DetachedMount(RawFd),
}

/// Pre-allocated, async-signal-safe launch plan built in the parent BEFORE `clone3`.
pub struct ChildLaunchPlan {
    pub enable_userns: bool,
    /// Drop inherited host supplementary groups (requires `setgroups` to be allowed).
    pub drop_groups: bool,
    pub isolate_netns: bool,
    pub rootfs: CString,
    /// Detached idmapped clone of `rootfs`; `None` bind-mounts `rootfs` onto itself instead.
    pub rootfs_mount_fd: Option<RawFd>,
    /// `(host source, target relative to rootfs)`.
    pub dev_binds: Vec<(CString, CString)>,
    /// `(source, target relative to rootfs)`.
    pub agent_bind: Option<(AgentBindSource, CString)>,
    pub hostname: Vec<u8>,
    /// Fds (all above [`GUEST_CONTROL_FD`]) left open across `execve` for `aos-guest`.
    pub inherit_fds: Vec<RawFd>,
    pub exec_path: CString,
    pub argv_storage: Vec<CString>,
    pub argv_ptrs: Vec<*const libc::c_char>,
    pub envp_storage: Vec<CString>,
    pub envp_ptrs: Vec<*const libc::c_char>,
    pub seccomp_filter: Option<Vec<SockFilter>>,
}

impl ChildLaunchPlan {
    /// Convert a path to a `CString` losslessly via `OsStrExt::as_bytes()`.
    pub fn path_to_cstr(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path contains NUL byte: {:?}", path),
            )
        })
    }
}

/// Create an `AF_UNIX` `SOCK_STREAM` socketpair with `SOCK_CLOEXEC` set on both ends.
pub fn create_cloexec_socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-element output array for `socketpair(2)`.
    let rc = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Both descriptors were freshly created by `socketpair`.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Create a pipe with `O_CLOEXEC` on both ends (`(read_end, write_end)`).
pub fn create_cloexec_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-element output array for `pipe2(2)`.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Both descriptors were freshly created by `pipe2`.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Read `fd` to EOF, failing with `TimedOut` once `timeout` has passed.
pub fn read_to_end_within(fd: OwnedFd, timeout: Duration) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let deadline = Instant::now() + timeout;
    let mut file = File::from(fd);
    let mut out = Vec::new();
    let mut buf = [0u8; 64];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut pfd = libc::pollfd {
            fd: file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        // SAFETY: `pfd` is one valid `pollfd` for the duration of the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if rc == 0 {
            continue;
        }
        match file.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Open a directory fd with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`.
pub fn open_dir_nofollow_cloexec(path: &Path) -> io::Result<OwnedFd> {
    let cpath = ChildLaunchPlan::path_to_cstr(path)?;
    // SAFETY: `cpath` is a NUL-terminated path string; `open(2)` returns a fresh fd or -1.
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened valid directory fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Flush the filesystem hosting `dir` via `open(O_DIRECTORY | O_NOFOLLOW)` + `syncfs(2)`.
pub fn syncfs_dir_nofollow(dir: &Path) -> io::Result<()> {
    let fd = open_dir_nofollow_cloexec(dir)?;
    // SAFETY: `fd` is a valid open directory descriptor owned by `OwnedFd`; `syncfs` takes
    // only an integer fd.
    let rc = unsafe { libc::syncfs(fd.as_raw_fd()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set or clear `SO_RCVTIMEO` and `SO_SNDTIMEO` on a socket fd.
pub fn set_socket_timeout(fd: RawFd, timeout: Option<Duration>) -> io::Result<()> {
    let tv = match timeout {
        Some(d) => libc::timeval {
            tv_sec: d.as_secs() as _,
            tv_usec: d.subsec_micros() as _,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `fd` is an open socket and `&tv` is a properly initialized `libc::timeval`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&tv as *const libc::timeval).cast::<libc::c_void>(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Convert an [`OwnedFd`] into a pair of `(reader, writer)` [`File`] handles sharing the fd.
pub fn split_owned_fd(fd: OwnedFd) -> io::Result<(File, File)> {
    let reader = File::from(fd);
    let writer = reader.try_clone()?;
    Ok((reader, writer))
}

/// Duplicate `fd` (`FD_CLOEXEC`) to a number the child's 0..=3 rewiring cannot collide with.
pub fn dup_above_control_fd(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl` takes no pointers here.
    let new = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

/// Clone the mount at `path` (never following a trailing symlink) into a detached, private mount.
///
/// Private propagation keeps the sandbox's own sub-mounts out of the host mount namespace.
pub fn clone_detached_mount(path: &Path, readonly: bool) -> io::Result<OwnedFd> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: `c_path` is a valid NUL-terminated string that outlives the call.
    let fd = unsafe {
        libc::syscall(
            SYS_OPEN_TREE,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            OPEN_TREE_CLONE | (libc::O_CLOEXEC | libc::AT_SYMLINK_NOFOLLOW) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned this fd and nothing else owns it.
    let mnt = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    mount_setattr_fd(
        mnt.as_raw_fd(),
        &MountAttr {
            attr_set: if readonly { MOUNT_ATTR_RDONLY } else { 0 },
            attr_clr: 0,
            propagation: libc::MS_PRIVATE,
            userns_fd: 0,
        },
    )?;
    Ok(mnt)
}

/// Apply the id mapping of `userns_fd` to a detached mount.
pub fn idmap_mount(mnt_fd: RawFd, userns_fd: RawFd) -> io::Result<()> {
    mount_setattr_fd(
        mnt_fd,
        &MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns_fd as u64,
        },
    )
}

fn mount_setattr_fd(mnt_fd: RawFd, attr: &MountAttr) -> io::Result<()> {
    // SAFETY: the empty path with `AT_EMPTY_PATH` targets `mnt_fd`; `attr` has the exact
    // `struct mount_attr` layout and outlives the call.
    let rc = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            mnt_fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            attr as *const MountAttr,
            mem::size_of::<MountAttr>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Return current process effective UID and GID.
pub fn current_euid_egid() -> (u32, u32) {
    // SAFETY: `geteuid` and `getegid` are always safe and cannot fail.
    unsafe { (libc::geteuid(), libc::getegid()) }
}

/// Send `SIGKILL` to a positive child PID, ignoring `ESRCH`.
pub fn kill_pid_sigkill(pid: i32) -> io::Result<()> {
    if pid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to SIGKILL protected pid {pid}"),
        ));
    }
    // SAFETY: `pid > 1` validated above; `kill(2)` takes no pointers.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(err)
        }
    }
}

/// Blocking `waitpid(pid, &mut status, 0)` retrying `EINTR` and ignoring `ECHILD`.
pub fn reap_child_blocking(pid: i32) -> io::Result<()> {
    if pid <= 0 {
        return Ok(());
    }
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `waitpid` writes only into our stack `status` integer.
        let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
        if rc >= 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if err.raw_os_error() == Some(libc::ECHILD) {
            return Ok(());
        }
        return Err(err);
    }
}

// ---------------------------------------------------------------------------
// Async-signal-safe child setup (runs strictly after `clone3` returns 0)
// ---------------------------------------------------------------------------

#[inline]
unsafe fn raw_errno() -> i32 {
    // SAFETY: Reading thread-local errno via `io::Error::last_os_error()` performs
    // no heap allocation.
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

unsafe fn fail_child(err_fd: RawFd, stage: ChildStage, errno: i32) -> ! {
    let mut payload = [0u8; 8];
    let s = (stage as u32).to_ne_bytes();
    let e = errno.to_ne_bytes();
    payload[0..4].copy_from_slice(&s);
    payload[4..8].copy_from_slice(&e);
    // SAFETY: `write` and `_exit` are async-signal-safe; `payload` is stack-allocated.
    unsafe {
        let _ = libc::write(err_fd, payload.as_ptr().cast::<libc::c_void>(), payload.len());
        libc::_exit(127);
    }
}

unsafe fn child_make_root_private(err_wr_fd: RawFd) {
    // SAFETY: `mount` is a raw syscall on a static path; `fail_child` diverges.
    unsafe {
        if libc::mount(
            ptr::null(),
            c"/".as_ptr(),
            ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            ptr::null(),
        ) != 0
        {
            fail_child(err_wr_fd, ChildStage::MountRootPrivate, raw_errno());
        }
    }
}

/// Attach the detached mount `mnt_fd` at `target`; returns the raw syscall result.
unsafe fn child_move_mount(mnt_fd: RawFd, target: *const libc::c_char) -> libc::c_long {
    // SAFETY: `target` points into the pre-allocated launch plan; the source path is static.
    unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            mnt_fd,
            c"".as_ptr(),
            libc::AT_FDCWD,
            target,
            MOVE_MOUNT_F_EMPTY_PATH,
        )
    }
}

unsafe fn child_raise_loopback() -> i32 {
    // SAFETY: All calls (`socket`, `ioctl`, `close`) are async-signal-safe raw syscalls.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return raw_errno();
        }
        let mut ifr: libc::ifreq = mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;

        if libc::ioctl(fd, SIOCGIFFLAGS as _, &mut ifr as *mut libc::ifreq) != 0 {
            let e = raw_errno();
            libc::close(fd);
            return e;
        }
        if (ifr.ifr_ifru.ifru_flags & libc::IFF_UP as libc::c_short) == 0 {
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(fd, SIOCSIFFLAGS as _, &ifr as *const libc::ifreq) != 0 {
                let e = raw_errno();
                libc::close(fd);
                return e;
            }
        }
        libc::close(fd);
        0
    }
}

unsafe fn child_drop_all_caps() -> i32 {
    // SAFETY: `prctl` and `SYS_capset` are async-signal-safe syscalls operating on stack PODs.
    unsafe {
        // Drop all bounding capabilities (0..=63; ignore EINVAL beyond kernel's last_cap).
        for cap in 0..=63u64 {
            let rc = libc::prctl(PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
            if rc != 0 {
                let e = raw_errno();
                if e != libc::EINVAL && e != libc::EPERM {
                    return e;
                }
            }
        }
        // Clear ambient capabilities (ignore EINVAL on older kernels).
        let _ = libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);

        let hdr = CapUserHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapUserData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            };
            2
        ];
        let rc = libc::syscall(
            SYS_CAPSET,
            &hdr as *const CapUserHeader,
            data.as_ptr(),
        );
        if rc != 0 {
            return raw_errno();
        }
        0
    }
}

unsafe fn run_child_setup(
    plan: &ChildLaunchPlan,
    mut guest_sock_fd: RawFd,
    sync_rd_fd: RawFd,
    mut err_wr_fd: RawFd,
) -> ! {
    // SAFETY: Runs exclusively in the freshly cloned child before `execve`. Every pointer
    // borrowed from `plan` was pre-allocated in the parent before `clone3` and stays valid
    // until `execve` replaces the address space.
    unsafe {
        // 1. Wait for parent to finish writing uid_map / gid_map and send 1 sync byte.
        let mut go = [0u8; 1];
        loop {
            let n = libc::read(sync_rd_fd, go.as_mut_ptr().cast::<libc::c_void>(), 1);
            if n == 1 {
                break;
            }
            if n < 0 && raw_errno() == libc::EINTR {
                continue;
            }
            fail_child(err_wr_fd, ChildStage::WaitParentSync, raw_errno());
        }
        libc::close(sync_rd_fd);

        // Attach the idmapped rootfs while still holding the parent's uid: after `setresuid` the
        // host-side ancestors of `rootfs` may no longer be traversable.
        let slash = c"/";
        if let Some(root_fd) = plan.rootfs_mount_fd {
            child_make_root_private(err_wr_fd);
            if child_move_mount(root_fd, plan.rootfs.as_ptr()) != 0 {
                fail_child(err_wr_fd, ChildStage::BindRootfs, raw_errno());
            }
        }

        // 2. Enter UID 0 / GID 0 inside the new user namespace. Raw syscalls: the glibc wrappers
        //    synchronize all threads of the process and would wait forever for threads that
        //    exist only in the parent.
        if plan.drop_groups && libc::syscall(libc::SYS_setgroups, 0, ptr::null::<libc::gid_t>()) != 0 {
            fail_child(err_wr_fd, ChildStage::SetGroups, raw_errno());
        }
        if plan.enable_userns {
            if libc::syscall(libc::SYS_setresgid, 0, 0, 0) != 0 {
                fail_child(err_wr_fd, ChildStage::SetResGid, raw_errno());
            }
            if libc::syscall(libc::SYS_setresuid, 0, 0, 0) != 0 {
                fail_child(err_wr_fd, ChildStage::SetResUid, raw_errno());
            }
        }

        // 3. Raise loopback interface inside isolated netns while we still hold netns CAP_NET_ADMIN.
        if plan.isolate_netns {
            let rc = child_raise_loopback();
            if rc != 0 {
                fail_child(err_wr_fd, ChildStage::RaiseLoopback, rc);
            }
        }

        // 4. Set isolated UTS hostname.
        if !plan.hostname.is_empty()
            && libc::sethostname(
                plan.hostname.as_ptr().cast::<libc::c_char>(),
                plan.hostname.len(),
            ) != 0
        {
            fail_child(err_wr_fd, ChildStage::SetHostname, raw_errno());
        }

        // 5-6. Without an idmapped rootfs: make mount propagation private so sandbox mounts never
        //      propagate to host, then bind-mount rootfs_dir onto itself so it is a mountpoint
        //      for pivot_root. Either way, continue with cwd = new root and relative paths.
        if let Some(root_fd) = plan.rootfs_mount_fd {
            if libc::fchdir(root_fd) != 0 {
                fail_child(err_wr_fd, ChildStage::ChdirRootfs, raw_errno());
            }
        } else {
            child_make_root_private(err_wr_fd);
            if libc::mount(
                plan.rootfs.as_ptr(),
                plan.rootfs.as_ptr(),
                ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                ptr::null(),
            ) != 0
            {
                fail_child(err_wr_fd, ChildStage::BindRootfs, raw_errno());
            }
            if libc::chdir(plan.rootfs.as_ptr()) != 0 {
                fail_child(err_wr_fd, ChildStage::ChdirRootfs, raw_errno());
            }
        }

        // 7. Mount fresh minimal `/dev` tmpfs and bind-mount standard safe device nodes
        //    (must happen before pivot_root while host `/dev/*` is accessible; host already
        //    verified `<rootfs>/dev` is not a symlink).
        let fstype_tmpfs = c"tmpfs";
        let rel_dev = c"dev";
        let _ = libc::mkdir(rel_dev.as_ptr(), 0o755);
        let dev_opts = c"mode=0755,size=64k";
        if libc::mount(
            fstype_tmpfs.as_ptr(),
            rel_dev.as_ptr(),
            fstype_tmpfs.as_ptr(),
            libc::MS_NOSUID | libc::MS_STRICTATIME,
            dev_opts.as_ptr().cast::<libc::c_void>(),
        ) != 0
        {
            fail_child(err_wr_fd, ChildStage::MountDev, raw_errno());
        }

        for (src, dst) in &plan.dev_binds {
            let fd = libc::open(
                dst.as_ptr(),
                libc::O_CREAT | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o666,
            );
            if fd < 0 {
                fail_child(err_wr_fd, ChildStage::BindDevNode, raw_errno());
            }
            libc::close(fd);
            if libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                ptr::null(),
                libc::MS_BIND,
                ptr::null(),
            ) != 0
            {
                fail_child(err_wr_fd, ChildStage::BindDevNode, raw_errno());
            }
        }

        // Optional read-only bind-mount of host static `aos-guest` binary.
        // Preserves locked mount flags from `statvfs` so `MS_REMOUNT | MS_RDONLY`
        // succeeds cleanly inside `CLONE_NEWUSER` and fails closed on error.
        if let Some((AgentBindSource::DetachedMount(fd), dst_bin)) = &plan.agent_bind
            && child_move_mount(*fd, dst_bin.as_ptr()) != 0
        {
            fail_child(err_wr_fd, ChildStage::BindAgentBinary, raw_errno());
        }
        if let Some((AgentBindSource::HostPath(host_bin), dst_bin)) = &plan.agent_bind {
            if libc::mount(
                host_bin.as_ptr(),
                dst_bin.as_ptr(),
                ptr::null(),
                libc::MS_BIND,
                ptr::null(),
            ) != 0
            {
                fail_child(err_wr_fd, ChildStage::BindAgentBinary, raw_errno());
            }
            let mut st: libc::statvfs = mem::zeroed();
            if libc::statvfs(dst_bin.as_ptr(), &mut st) != 0 {
                fail_child(err_wr_fd, ChildStage::BindAgentBinary, raw_errno());
            }
            let preserved = (st.f_flag as libc::c_ulong)
                & (libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC
                    | libc::MS_RELATIME
                    | libc::MS_NOATIME
                    | libc::MS_NODIRATIME);
            if libc::mount(
                ptr::null(),
                dst_bin.as_ptr(),
                ptr::null(),
                preserved | libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                ptr::null(),
            ) != 0
            {
                fail_child(err_wr_fd, ChildStage::BindAgentBinary, raw_errno());
            }
        }

        // 8. Pivot root using `pivot_root(".", ".")` (zero `.put_old` left in rootfs!).
        let dot = c".";
        if libc::syscall(SYS_PIVOT_ROOT, dot.as_ptr(), dot.as_ptr()) != 0 {
            fail_child(err_wr_fd, ChildStage::PivotRoot, raw_errno());
        }

        // Mount fresh `/proc` inside the pivoted new root BEFORE detaching old root `.`
        // so Linux `fs_fully_visible(proc)` succeeds inside `CLONE_NEWUSER` while `/proc`
        // resolves strictly within the sandbox root.
        let fstype_proc = c"proc";
        let new_proc = c"/proc";
        let _ = libc::mkdir(new_proc.as_ptr(), 0o555);
        if libc::mount(
            fstype_proc.as_ptr(),
            new_proc.as_ptr(),
            fstype_proc.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            ptr::null(),
        ) != 0
        {
            fail_child(err_wr_fd, ChildStage::MountProc, raw_errno());
        }

        // Detach old host root completely and chdir to new `/`.
        if libc::umount2(dot.as_ptr(), libc::MNT_DETACH) != 0 {
            fail_child(err_wr_fd, ChildStage::UmountOldRoot, raw_errno());
        }
        if libc::chdir(slash.as_ptr()) != 0 {
            fail_child(err_wr_fd, ChildStage::ChdirNewRoot, raw_errno());
        }

        // Mount bounded `/tmp` and `/dev/shm` strictly inside the pivoted sandbox root
        // (per `ARCHITECTURE_V2.md` §7.4).
        let new_tmp = c"/tmp";
        let _ = libc::mkdir(new_tmp.as_ptr(), 0o1777);
        let tmp_opts = c"mode=1777,size=64m";
        if libc::mount(
            fstype_tmpfs.as_ptr(),
            new_tmp.as_ptr(),
            fstype_tmpfs.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            tmp_opts.as_ptr().cast::<libc::c_void>(),
        ) != 0
        {
            fail_child(err_wr_fd, ChildStage::MountTmp, raw_errno());
        }

        let new_shm = c"/dev/shm";
        let _ = libc::mkdir(new_shm.as_ptr(), 0o1777);
        let shm_opts = c"mode=1777,size=64m";
        if libc::mount(
            fstype_tmpfs.as_ptr(),
            new_shm.as_ptr(),
            fstype_tmpfs.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            shm_opts.as_ptr().cast::<libc::c_void>(),
        ) != 0
        {
            fail_child(err_wr_fd, ChildStage::MountDevShm, raw_errno());
        }

        // 9. Relocate `err_wr_fd` and `guest_sock_fd` away from 0..=3 to prevent any
        //    FD collision when duping `/dev/null` -> 0..=2 and `guest_sock_fd` -> 3.
        if err_wr_fd <= GUEST_CONTROL_FD {
            let moved = libc::fcntl(err_wr_fd, libc::F_DUPFD_CLOEXEC, GUEST_CONTROL_FD + 1);
            if moved < 0 {
                fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
            }
            libc::close(err_wr_fd);
            err_wr_fd = moved;
        }
        if guest_sock_fd <= 2 {
            let moved = libc::fcntl(guest_sock_fd, libc::F_DUPFD_CLOEXEC, GUEST_CONTROL_FD + 1);
            if moved < 0 {
                fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
            }
            libc::close(guest_sock_fd);
            guest_sock_fd = moved;
        }

        // Redirect stdin/stdout/stderr to `/dev/null`.
        let devnull = c"/dev/null";
        let null_fd = libc::open(devnull.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if null_fd < 0 {
            fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
        }
        for target in 0..=2 {
            if null_fd == target {
                let flags = libc::fcntl(target, libc::F_GETFD);
                if flags < 0 || libc::fcntl(target, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
                }
            } else if libc::dup2(null_fd, target) < 0 {
                fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
            }
        }
        if null_fd > 2 {
            libc::close(null_fd);
        }

        // Wire control socketpair onto GUEST_CONTROL_FD (fd 3, WITHOUT FD_CLOEXEC).
        if guest_sock_fd == GUEST_CONTROL_FD {
            let flags = libc::fcntl(guest_sock_fd, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(guest_sock_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
            {
                fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
            }
        } else {
            if libc::dup2(guest_sock_fd, GUEST_CONTROL_FD) < 0 {
                fail_child(err_wr_fd, ChildStage::DupControlFd, raw_errno());
            }
            libc::close(guest_sock_fd);
        }

        // Mark EVERY fd >= 4 (including err_wr_fd and any non-CLOEXEC parent fds) as
        // FD_CLOEXEC atomically so zero parent fds can leak across execve.
        let cr_rc = libc::syscall(
            SYS_CLOSE_RANGE,
            (GUEST_CONTROL_FD + 1) as libc::c_uint,
            u32::MAX as libc::c_uint,
            CLOSE_RANGE_CLOEXEC,
        );
        if cr_rc != 0 {
            fail_child(err_wr_fd, ChildStage::CloseRange, raw_errno());
        }
        for fd in &plan.inherit_fds {
            if libc::fcntl(*fd, libc::F_SETFD, 0) != 0 {
                fail_child(err_wr_fd, ChildStage::CloseRange, raw_errno());
            }
        }

        // 10. Drop all workload capabilities.
        let cap_rc = child_drop_all_caps();
        if cap_rc != 0 {
            fail_child(err_wr_fd, ChildStage::DropCaps, cap_rc);
        }

        // 11. Set PR_SET_NO_NEW_PRIVS (required for unprivileged seccomp and prevents setuid escalation).
        if libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail_child(err_wr_fd, ChildStage::NoNewPrivs, raw_errno());
        }

        // 12. Install strict seccomp-BPF filter right before execve.
        if let Some(filter) = &plan.seccomp_filter {
            let fprog = SockFprog {
                len: filter.len() as libc::c_ushort,
                filter: filter.as_ptr(),
            };
            if libc::syscall(
                SYS_SECCOMP,
                SECCOMP_SET_MODE_FILTER,
                0 as libc::c_uint,
                &fprog as *const SockFprog,
            ) != 0
            {
                fail_child(err_wr_fd, ChildStage::InstallSeccomp, raw_errno());
            }
        }

        // 13. Exec static `aos-guest` (FD_CLOEXEC closes `err_wr_fd` automatically on success!).
        libc::execve(
            plan.exec_path.as_ptr(),
            plan.argv_ptrs.as_ptr(),
            plan.envp_ptrs.as_ptr(),
        );
        fail_child(err_wr_fd, ChildStage::ExecGuest, raw_errno());
    }
}

/// Spawn an isolated child directly into `cgroup_dirfd` (when `Some`) via `clone3(2)`.
///
/// Returns the child's host PID (`> 0`) in the parent.
pub fn spawn_isolated_child(
    plan: &ChildLaunchPlan,
    cgroup_dirfd: Option<RawFd>,
    guest_sock_fd: RawFd,
    sync_rd_fd: RawFd,
    err_wr_fd: RawFd,
) -> io::Result<i32> {
    let mut flags: u64 =
        u64::from(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWUTS);
    if plan.enable_userns {
        flags |= u64::from(CLONE_NEWUSER);
    }
    if plan.isolate_netns {
        flags |= u64::from(CLONE_NEWNET);
    }
    let cgroup_fd_u64 = match cgroup_dirfd {
        Some(fd) => {
            flags |= CLONE_INTO_CGROUP;
            fd as u64
        }
        None => 0,
    };

    let args = CloneArgs {
        flags,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: cgroup_fd_u64,
    };

    // SAFETY: `args` has exact Linux `struct clone_args` layout (88 bytes). On return == 0
    // (child), `run_child_setup` executes ONLY async-signal-safe raw syscalls using
    // pre-allocated data in `plan` and never returns to Rust parent stack frames.
    let pid = unsafe {
        libc::syscall(
            SYS_CLONE3,
            &args as *const CloneArgs,
            mem::size_of::<CloneArgs>(),
        )
    };

    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: We are in the cloned child; `run_child_setup` diverges via `execve` or `_exit`.
        unsafe { run_child_setup(plan, guest_sock_fd, sync_rd_fd, err_wr_fd) };
    }
    Ok(pid as i32)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn read_to_end_within_stops_at_the_deadline_while_the_writer_stays_open() {
        let (rd, wr) = create_cloexec_pipe().unwrap();
        let start = std::time::Instant::now();
        let err = read_to_end_within(rd, Duration::from_millis(100)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(wr);

        let (rd, wr) = create_cloexec_pipe().unwrap();
        File::from(wr).write_all(b"stage").unwrap();
        assert_eq!(read_to_end_within(rd, Duration::from_secs(5)).unwrap(), b"stage");
    }
}
