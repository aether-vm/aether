//! Minimal, isolated Linux syscall / ioctl wrappers for `aos-guest`.
//!
//! This is the ONLY module in `aos-guest` permitted to contain `unsafe` code,
//! and it is compiled exclusively on `target_os = "linux"`.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use crate::netlink_tcp::NETLINK_SOCK_DIAG;
use crate::protocol::RESEED_ENTROPY_LEN;

/// Linux `RNDADDENTROPY = _IOW('R', 0x03, int[2])` from `include/uapi/linux/random.h`.
const RNDADDENTROPY: libc::c_ulong = 0x4008_5203;

/// Linux `RNDRESEEDCRNG = _IO('R', 0x07)` from `include/uapi/linux/random.h`.
const RNDRESEEDCRNG: libc::c_ulong = 0x0000_5207;

/// Linux `AF_VSOCK` address family and `VMADDR_CID_ANY`.
const AF_VSOCK: libc::c_int = 40;
const VMADDR_CID_ANY: u32 = u32::MAX;

/// Linux `SIOCGIFFLAGS` / `SIOCSIFFLAGS` ioctls (`include/uapi/linux/sockios.h`).
const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

#[repr(C)]
struct RandPoolInfo64 {
    entropy_count: libc::c_int,
    buf_size: libc::c_int,
    buf: [u8; RESEED_ENTROPY_LEN],
}

#[repr(C)]
struct SockAddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_flags: u8,
    svm_zero: [u8; 3],
}

// ---------------------------------------------------------------------------
// Race-free PID-1 Orphan Reaper Coordination
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ActiveChildren {
    /// Number of in-flight `Command::spawn()` / `Command::output()` calls whose
    /// child PID is not yet registered. While `> 0`, the PID-1 reaper pauses so
    /// it can never race between `fork()` and `pids.insert(pid)`.
    spawning_count: usize,
    /// Direct child PIDs owned by `std::process::Child::wait()` / `try_wait()`.
    pids: HashSet<i32>,
}

fn active_children() -> &'static Mutex<ActiveChildren> {
    static TRACKER: OnceLock<Mutex<ActiveChildren>> = OnceLock::new();
    TRACKER.get_or_init(|| Mutex::new(ActiveChildren::default()))
}

/// RAII guard held across `Command::spawn()` (or `Command::output()`) to prevent
/// the PID-1 orphan reaper from racing with a newly forked direct child.
pub struct ChildSpawnGuard {
    released: bool,
}

impl ChildSpawnGuard {
    /// Transition from an in-flight spawn to tracking a concrete direct child PID.
    pub fn register_pid(mut self, pid: u32) -> ActiveChildGuard {
        let pid_i32 = pid as i32;
        let mut guard = active_children()
            .lock()
            .expect("active_children mutex poisoned");
        guard.spawning_count = guard.spawning_count.saturating_sub(1);
        guard.pids.insert(pid_i32);
        self.released = true;
        ActiveChildGuard { pid: pid_i32 }
    }
}

impl Drop for ChildSpawnGuard {
    fn drop(&mut self) {
        if !self.released {
            let mut guard = active_children()
                .lock()
                .expect("active_children mutex poisoned");
            guard.spawning_count = guard.spawning_count.saturating_sub(1);
        }
    }
}

/// RAII guard keeping a direct child PID protected from the PID-1 orphan reaper
/// until AFTER `Child::wait()` / `try_wait()` has consumed its exit status.
pub struct ActiveChildGuard {
    pid: i32,
}

impl Drop for ActiveChildGuard {
    fn drop(&mut self) {
        let mut guard = active_children()
            .lock()
            .expect("active_children mutex poisoned");
        guard.pids.remove(&self.pid);
    }
}

/// Pause PID-1 orphan reaping while spawning a direct child process.
pub fn begin_child_spawn() -> ChildSpawnGuard {
    let mut guard = active_children()
        .lock()
        .expect("active_children mutex poisoned");
    guard.spawning_count += 1;
    ChildSpawnGuard { released: false }
}

/// Reap exited orphaned grandchildren without EVER stealing exit status from
/// active direct `Exec` / `pre_freeze_hook` / `ss` children.
///
/// Uses `waitid(P_ALL, 0, &mut siginfo, WEXITED | WNOHANG | WNOWAIT)` to peek
/// at a waitable zombie non-destructively while holding the `ActiveChildren` lock,
/// then reaps via `waitpid(pid, ..., WNOHANG)` ONLY if `pid` is not an active
/// direct child.
pub fn reap_orphans_nonblocking() -> usize {
    let mut reaped = 0usize;
    loop {
        let guard = active_children()
            .lock()
            .expect("active_children mutex poisoned");
        if guard.spawning_count > 0 {
            // A direct child is mid-spawn; wait for the next tick.
            break;
        }

        // SAFETY: `siginfo_t` is a POD C struct zero-initialized before passing to `waitid`.
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        // SAFETY: `waitid` with `WNOWAIT | WNOHANG` peeks at an exited child without
        // removing its zombie entry, writing only into our stack `info`.
        let rc = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut info as *mut libc::siginfo_t,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc != 0 {
            break;
        }

        // SAFETY: On Linux, when `waitid` succeeds with a waitable child, `si_pid()`
        // returns the child's PID (> 0), or 0 when no waitable child exists.
        let pid = unsafe { info.si_pid() };
        if pid <= 0 {
            break;
        }

        if guard.pids.contains(&pid) {
            // Owned by an active `Child::wait()`/`try_wait()`; do not touch it.
            break;
        }

        let mut status: libc::c_int = 0;
        // SAFETY: `pid > 0` is confirmed NOT in `guard.pids` while we hold `guard`;
        // reaping this specific orphan PID cannot race with any direct child.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        drop(guard);

        if waited > 0 {
            reaped += 1;
        } else {
            break;
        }
    }
    reaped
}

// ---------------------------------------------------------------------------
// Core Syscalls & Ioctls
// ---------------------------------------------------------------------------

/// Flush all dirty pages and metadata for the filesystem hosting `file` via `syncfs(2)`.
pub fn syncfs_file(file: &File) -> io::Result<()> {
    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid open file descriptor borrowed from `file`; `syncfs` takes
    // only an integer fd and performs no pointer dereferences.
    let rc = unsafe { libc::syncfs(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Inject 64 bytes of host CSPRNG entropy into `/dev/urandom` via `RNDADDENTROPY`
/// (crediting 512 entropy bits) and force immediate CRNG reseed via `RNDRESEEDCRNG`.
///
/// Requires `CAP_SYS_ADMIN` (always held by PID-1 `aos-guest` inside Firecracker).
pub fn inject_entropy_and_reseed(entropy: &[u8; RESEED_ENTROPY_LEN]) -> io::Result<()> {
    let urandom = OpenOptions::new().write(true).open("/dev/urandom")?;
    let fd = urandom.as_raw_fd();

    let info = RandPoolInfo64 {
        entropy_count: (RESEED_ENTROPY_LEN * 8) as libc::c_int,
        buf_size: RESEED_ENTROPY_LEN as libc::c_int,
        buf: *entropy,
    };

    // SAFETY: `fd` is an open `/dev/urandom` descriptor and `&info` points to a properly
    // initialized `struct rand_pool_info` whose `buf_size` matches `info.buf.len()`.
    let add_rc = unsafe { libc::ioctl(fd, RNDADDENTROPY as _, &info as *const RandPoolInfo64) };
    if add_rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `RNDRESEEDCRNG` is an `_IO` ioctl taking no pointer argument on `/dev/urandom`.
    let reseed_rc = unsafe { libc::ioctl(fd, RNDRESEEDCRNG as _, 0 as libc::c_ulong) };
    if reseed_rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set kernel wall-clock time (`CLOCK_REALTIME`) via `clock_settime(2)`.
pub fn set_clock_realtime(secs: i64, nanos: u32) -> io::Result<()> {
    let ts = libc::timespec {
        tv_sec: secs as _,
        tv_nsec: nanos as libc::c_long,
    };
    // SAFETY: `&ts` is a valid initialized `libc::timespec` with `0 <= tv_nsec < 1_000_000_000`.
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts as *const libc::timespec) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Send `SIGKILL` to a specific positive PID (used as fallback if `cgroup.kill` is unavailable).
pub fn kill_pid_sigkill(pid: i32) -> io::Result<()> {
    if pid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to SIGKILL protected pid {pid}"),
        ));
    }
    // SAFETY: `pid > 1` is validated above; `kill(2)` is signal-safe and takes no pointers.
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

/// Open and bind a `NETLINK_SOCK_DIAG` datagram socket for querying and destroying TCP sockets.
pub struct NetlinkSockDiag {
    fd: OwnedFd,
}

impl NetlinkSockDiag {
    pub fn open() -> io::Result<Self> {
        // SAFETY: `socket(2)` with constant valid parameters returns a fresh fd or -1.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_SOCK_DIAG,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a newly created valid fd owned exclusively by `OwnedFd`.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: `sockaddr_nl` is a POD C struct.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = 0;
        addr.nl_groups = 0;

        // SAFETY: `fd` is valid and `addr` is a properly sized `sockaddr_nl`.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
                mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    pub fn send(&self, msg: &[u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `fd` is valid and `msg` points to `msg.len()` readable bytes.
            let n = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    msg.as_ptr().cast::<libc::c_void>(),
                    msg.len(),
                    0,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: `fd` is valid and `buf` points to `buf.len()` writable bytes.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                )
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
}

/// Listening `AF_VSOCK` stream socket accepting host connections from Firecracker.
pub struct VsockListener {
    fd: OwnedFd,
}

impl VsockListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        // SAFETY: `socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0)` creates a fresh fd or -1.
        let raw = unsafe { libc::socket(AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a newly created owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let addr = SockAddrVm {
            svm_family: AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: VMADDR_CID_ANY,
            svm_flags: 0,
            svm_zero: [0; 3],
        };

        // SAFETY: `fd` is valid and `addr` has the exact layout of Linux `struct sockaddr_vm`.
        let bind_rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const SockAddrVm).cast::<libc::sockaddr>(),
                mem::size_of::<SockAddrVm>() as libc::socklen_t,
            )
        };
        if bind_rc != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `fd` is bound and valid.
        let listen_rc = unsafe { libc::listen(fd.as_raw_fd(), 16) };
        if listen_rc != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    /// Accept the next host vsock connection as a pair of `(reader, writer)` [`File`] handles.
    pub fn accept(&self) -> io::Result<(File, File)> {
        loop {
            // SAFETY: `accept4` with `SOCK_CLOEXEC` and null peer addr returns a valid cloexec fd or -1.
            let conn = unsafe {
                libc::accept4(
                    self.fd.as_raw_fd(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if conn >= 0 {
                // SAFETY: `conn` is a freshly accepted fd owned exclusively by `reader`.
                let reader = unsafe { File::from_raw_fd(conn) };
                let writer = reader.try_clone()?;
                return Ok((reader, writer));
            }
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
}

/// Adopt an inherited `socketpair` file descriptor passed by `NamespaceDriver`.
///
/// Explicitly sets `FD_CLOEXEC` on `fd` before wrapping so untrusted `Exec` child
/// processes can never inherit the host control channel.
pub fn stream_from_inherited_fd(fd: RawFd) -> io::Result<(File, File)> {
    let reader = file_from_inherited_fd(fd)?;
    // `File::try_clone()` uses `F_DUPFD_CLOEXEC` on Unix so `writer` is also `FD_CLOEXEC`.
    let writer = reader.try_clone()?;
    Ok((reader, writer))
}

/// Make this process non-dumpable so same-uid workloads can neither write its memory nor reopen
/// its fds through `/proc`, whatever `kernel.yama.ptrace_scope` is. `execve` resets this.
pub fn set_non_dumpable() -> io::Result<()> {
    // SAFETY: `prctl(PR_SET_DUMPABLE)` takes no pointers.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Adopt an inherited file descriptor, setting `FD_CLOEXEC` so `Exec` children never see it.
pub fn file_from_inherited_fd(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("negative inherited fd {fd}"),
        ));
    }
    // Validate the fd is actually open before taking ownership.
    // SAFETY: `fcntl(fd, F_GETFD)` checks fd validity without modifying state.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if (flags & libc::FD_CLOEXEC) == 0 {
        // SAFETY: `fd` is validated open; setting `FD_CLOEXEC` prevents leaking the
        // control channel to untrusted `Exec` children.
        let set_rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        if set_rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: `fd` is validated open, marked `FD_CLOEXEC`, and dedicated to this agent.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Bring up the loopback interface (`lo`) with `IFF_UP | IFF_RUNNING` during PID-1 init.
///
/// The Linux kernel leaves `lo` in `DOWN` state until userspace raises `IFF_UP`;
/// raising it causes `devinet`/`addrconf` to automatically attach `127.0.0.1/8` and `::1/128`.
pub fn bring_up_loopback() -> io::Result<()> {
    // SAFETY: `socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0)` returns a fresh fd or -1.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a newly created owned fd.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: `libc::ifreq` is a POD C struct zero-initialized before setting `ifr_name`.
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;

    // SAFETY: `fd` is a valid AF_INET socket and `&mut ifr` is a properly aligned `ifreq`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), SIOCGIFFLAGS as _, &mut ifr as *mut libc::ifreq) } != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `SIOCGIFFLAGS` populated `ifr.ifr_ifru.ifru_flags` in the union.
    let already_up = unsafe { (ifr.ifr_ifru.ifru_flags & libc::IFF_UP as libc::c_short) != 0 };
    if already_up {
        return Ok(());
    }

    // SAFETY: `SIOCGIFFLAGS` populated `ifr.ifr_ifru.ifru_flags` in the union.
    unsafe {
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }

    // SAFETY: `fd` is valid and `ifr` holds the updated `ifru_flags` for `"lo"`.
    if unsafe { libc::ioctl(fd.as_raw_fd(), SIOCSIFFLAGS as _, &ifr as *const libc::ifreq) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Best-effort PID-1 virtual filesystem mounts (`/proc`, `/sys`, `/dev`, `/sys/fs/cgroup`).
pub fn mount_pid1_filesystems() {
    let mounts: [(&str, &str, &str, libc::c_ulong); 4] = [
        ("proc", "/proc", "proc", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC),
        ("sysfs", "/sys", "sysfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC),
        ("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID),
        (
            "cgroup2",
            "/sys/fs/cgroup",
            "cgroup2",
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        ),
    ];

    for (src, target, fstype, flags) in mounts {
        let _ = std::fs::create_dir_all(target);
        let (Ok(c_src), Ok(c_target), Ok(c_fstype)) = (
            CString::new(src),
            CString::new(target),
            CString::new(fstype),
        ) else {
            continue;
        };
        // SAFETY: All three CStrings are NUL-terminated and live for the duration of `mount(2)`.
        let _ = unsafe {
            libc::mount(
                c_src.as_ptr(),
                c_target.as_ptr(),
                c_fstype.as_ptr(),
                flags,
                ptr::null(),
            )
        };
    }
}

/// Attach a `pre_exec` hook moving the forked child into the cgroup whose `cgroup.procs` the
/// host opened as `procs_fd`; `procs_fd` must stay open until the command has been spawned.
pub fn attach_child_to_cgroup_fd(cmd: &mut Command, procs_fd: RawFd) {
    // SAFETY: The closure runs between `fork` and `exec` and only invokes the async-signal-safe
    // `pwrite` syscall with a static payload. `pwrite` leaves the offset shared with aos-guest
    // alone.
    unsafe {
        cmd.pre_exec(move || write_all_at_start(procs_fd, b"0\n"));
    }
}

/// Value the workload gets in `/proc/self/oom_score_adj`, so a world-wide OOM picks it before
/// aos-guest (whose death ends the world) even when its own RSS is small.
const WORKLOAD_OOM_SCORE_ADJ: &[u8] = b"500\n";

/// Attach a `pre_exec` hook raising the child's `oom_score_adj` to [`WORKLOAD_OOM_SCORE_ADJ`].
/// Without `CAP_SYS_RESOURCE` the child cannot go below the floor (`oom_score_adj_min`) it
/// inherits through aos-guest from whoever last set the score with that capability, e.g.
/// systemd's `OOMScoreAdjust=`. A floor above 500 makes 500 fail with `EACCES`; the child then
/// takes the maximum, 1000, which still ranks it above aos-guest.
pub fn prefer_child_for_oom_kill(cmd: &mut Command) {
    // SAFETY: The closure runs between `fork` and `exec` and invokes only async-signal-safe
    // syscalls (`open`, `pwrite`, `close`) on a static path and payloads.
    unsafe {
        cmd.pre_exec(|| {
            let fd = libc::open(
                c"/proc/self/oom_score_adj".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut res = write_all_at_start(fd, WORKLOAD_OOM_SCORE_ADJ);
            if matches!(&res, Err(e) if e.raw_os_error() == Some(libc::EACCES)) {
                res = write_all_at_start(fd, b"1000\n");
            }
            libc::close(fd);
            res
        });
    }
}

/// `pwrite(fd, payload, 0)` until it is complete, retrying `EINTR`. Async-signal-safe.
fn write_all_at_start(fd: RawFd, payload: &[u8]) -> io::Result<()> {
    loop {
        // SAFETY: `payload` is a valid slice for the duration of the call.
        let written = unsafe {
            libc::pwrite(fd, payload.as_ptr().cast::<libc::c_void>(), payload.len(), 0)
        };
        if written < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if written as usize != payload.len() {
            // `io::Error::new` would allocate, which is not safe after `fork`.
            return Err(io::ErrorKind::WriteZero.into());
        }
        return Ok(());
    }
}

/// Attach a `pre_exec` hook placing the forked child into `<sub_cgroup>/cgroup.procs`
/// before `execve` runs so the entire process tree is contained from its first instruction.
pub fn attach_child_to_cgroup(cmd: &mut Command, cgroup_procs_path: PathBuf) -> io::Result<()> {
    let c_path = CString::new(cgroup_procs_path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup.procs path contains NUL byte",
        )
    })?;

    // SAFETY: The closure runs between `fork` and `exec` and invokes only async-signal-safe
    // syscalls (`open`, `pwrite`, `close`) with pre-allocated `c_path` and a static byte slice.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::open(c_path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let res = write_all_at_start(fd, b"0\n");
            libc::close(fd);
            res
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gives the child an `oom_score_adj` floor of 600, the way a privileged ancestor such as
    /// systemd's `OOMScoreAdjust=600` does, then drops `CAP_SYS_RESOURCE` (a new user namespace
    /// has no capabilities in the initial one) as aos-guest has.
    fn with_oom_floor_600(cmd: &mut Command) {
        // SAFETY: Runs between `fork` and `exec` and invokes only async-signal-safe syscalls on a
        // static path and payload.
        unsafe {
            cmd.pre_exec(|| {
                let fd = libc::open(
                    c"/proc/self/oom_score_adj".as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC,
                );
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let res = write_all_at_start(fd, b"600\n");
                libc::close(fd);
                res?;
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[test]
    fn a_workload_starts_under_an_inherited_oom_floor_above_500() {
        // Only a writer with CAP_SYS_RESOURCE sets the floor.
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping oom floor test: needs root to set an oom_score_adj floor");
            return;
        }
        // The floor is real: without the privilege it was set with, 500 is refused.
        let mut lower = Command::new("/bin/sh");
        lower.args(["-c", "echo 500 > /proc/self/oom_score_adj"]);
        with_oom_floor_600(&mut lower);
        assert!(!lower.status().expect("spawn sh").success(), "the floor must hold");

        let mut cmd = Command::new("/bin/cat");
        cmd.arg("/proc/self/oom_score_adj");
        with_oom_floor_600(&mut cmd);
        prefer_child_for_oom_kill(&mut cmd);
        let out = cmd.output().expect("the workload must still start");
        assert!(out.status.success());
        let adj: i32 = String::from_utf8(out.stdout).unwrap().trim().parse().unwrap();
        assert!(adj > 600, "the workload must still rank above aos-guest, got {adj}");
    }
}
