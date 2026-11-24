//! Linux `openat2(2)` (`SYS_openat2 = 437`) safe root-confined filesystem helpers.
//!
//! `struct open_how` and the `RESOLVE_*` bitmask constants are compiled on all targets so ABI
//! assertions run cross-platform. The actual Linux syscall wrappers live in [`linux_impl`] and
//! **fail closed** on `ENOSYS`/`EPERM` (never falling back to unconfined `openat`).

/// Linux `SYS_openat2` syscall number (`x86_64` and `aarch64` both use `437`).
pub const SYS_OPENAT2: i64 = 437;

/// Do not cross mount points (`RESOLVE_NO_XDEV`).
pub const RESOLVE_NO_XDEV: u64 = 0x01;
/// Disallow traversal of magic links such as `/proc/<pid>/fd/*` (`RESOLVE_NO_MAGICLINKS`).
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
/// Disallow traversal of any symlink (`RESOLVE_NO_SYMLINKS`).
pub const RESOLVE_NO_SYMLINKS: u64 = 0x04;
/// Reject any path that escapes `dirfd` (`RESOLVE_BENEATH`).
pub const RESOLVE_BENEATH: u64 = 0x08;
/// Treat `dirfd` as the root directory for `/` and `..` (`RESOLVE_IN_ROOT`).
pub const RESOLVE_IN_ROOT: u64 = 0x10;

/// Exact Linux `<uapi/linux/openat2.h>` `struct open_how` (24 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OpenHow {
    /// `O_*` flags.
    pub flags: u64,
    /// Creation mode (must be `0` unless `O_CREAT` or `O_TMPFILE` is set).
    pub mode: u64,
    /// `RESOLVE_*` bitmask.
    pub resolve: u64,
}

/// Linux `openat2` + `*at` confined operations.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub mod linux_impl {
    use std::ffi::{CString, OsString};
    use std::fs::File;
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::Path;

    use super::{
        OpenHow, RESOLVE_BENEATH, RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS, RESOLVE_NO_SYMLINKS,
        SYS_OPENAT2,
    };

    fn to_cstring(s: &str) -> io::Result<CString> {
        CString::new(s.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in path component")
        })
    }

    fn to_cstring_os(s: &std::ffi::OsStr) -> io::Result<CString> {
        CString::new(s.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in path component")
        })
    }

    /// Raw `openat2(2)` syscall wrapper. **Fails closed** (no fallback to `openat`).
    pub fn openat2_raw(
        dirfd: libc::c_int,
        path: &CString,
        how: &OpenHow,
    ) -> io::Result<OwnedFd> {
        // SAFETY: `path` is NUL-terminated, `how` is a valid 24-byte `repr(C)` `struct open_how`,
        // and `size_of::<OpenHow>() == 24`. Return value >= 0 is a freshly owned file descriptor.
        let fd = unsafe {
            libc::syscall(
                SYS_OPENAT2 as libc::c_long,
                dirfd,
                path.as_ptr(),
                std::ptr::from_ref(how),
                size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: kernel just returned a new unique fd >= 0.
            Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
        }
    }

    /// Open the subvolume root directory itself (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`).
    pub fn open_root_dir(path: &Path) -> io::Result<OwnedFd> {
        let c = to_cstring_os(path.as_os_str())?;
        // SAFETY: `c` is NUL-terminated; returns a new fd or -1.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: fresh owned fd.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    /// Open a single child directory component beneath `parent_fd` with
    /// `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`.
    pub fn open_child_dir(parent_fd: &OwnedFd, segment: &str) -> io::Result<OwnedFd> {
        let c = to_cstring(segment)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        openat2_raw(parent_fd.as_raw_fd(), &c, &how)
    }

    /// Walk (and optionally create) directory components relative to `root_fd`, strictly
    /// component-by-component using `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)`.
    ///
    /// Never passes multi-segment paths to `mkdirat`, and never follows symlinks or magiclinks.
    pub fn walk_or_create_dirs(
        root_fd: &OwnedFd,
        components: &[&str],
        create_missing: bool,
    ) -> io::Result<OwnedFd> {
        // Duplicate root_fd so we always return an OwnedFd cleanly.
        let mut cur = dup_cloexec(root_fd)?;
        for seg in components {
            match open_child_dir(&cur, seg) {
                Ok(next) => cur = next,
                Err(e) if create_missing && e.kind() == io::ErrorKind::NotFound => {
                    let c = to_cstring(seg)?;
                    // SAFETY: `cur` is a valid directory fd; `c` is a single validated segment.
                    // Create with 0o700 during unpack so subsequent entries inside restrictive
                    // directories succeed; final modes are applied bottom-up after unpack.
                    let rc = unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
                    if rc != 0 {
                        let mk_err = io::Error::last_os_error();
                        if mk_err.kind() != io::ErrorKind::AlreadyExists {
                            return Err(mk_err);
                        }
                    }
                    // Immediately re-open with openat2 to verify it is a real directory, not a symlink.
                    cur = open_child_dir(&cur, seg)?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(cur)
    }

    /// Create a brand-new regular file relative to `root_fd` using
    /// `openat2(O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)`.
    ///
    /// Opens with mode `0o600` during write; caller applies the sanitized final mode via `fchmod`.
    pub fn create_file_in_root(root_fd: &OwnedFd, rel_path: &str) -> io::Result<File> {
        let c = to_cstring(rel_path)?;
        let how = OpenHow {
            flags: (libc::O_CREAT
                | libc::O_EXCL
                | libc::O_WRONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC) as u64,
            mode: 0o600,
            resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = openat2_raw(root_fd.as_raw_fd(), &c, &how)?;
        Ok(File::from(fd))
    }

    /// Open an existing regular file relative to `root_fd` read-only using
    /// `openat2(O_RDONLY | O_NOFOLLOW | O_CLOEXEC, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)`.
    pub fn open_file_in_root_readonly(root_fd: &OwnedFd, rel_path: &str) -> io::Result<File> {
        let c = to_cstring(rel_path)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = openat2_raw(root_fd.as_raw_fd(), &c, &how)?;
        Ok(File::from(fd))
    }

    /// Open an existing regular file inside `parent_fd` read-only using
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)`.
    pub fn open_child_file_readonly(parent_fd: &OwnedFd, leaf: &str) -> io::Result<File> {
        let c = to_cstring(leaf)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = openat2_raw(parent_fd.as_raw_fd(), &c, &how)?;
        Ok(File::from(fd))
    }

    /// Apply sanitized permission bits (`mode & 0o777`, stripping setuid/setgid/sticky) via `fchmod`.
    pub fn fchmod_sanitized(fd: &impl AsRawFd, mode: u32) -> io::Result<()> {
        let clean = (mode & 0o777) as libc::mode_t;
        // SAFETY: `fd` is a valid open descriptor.
        let rc = unsafe { libc::fchmod(fd.as_raw_fd(), clean) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Create a symlink at single component `leaf` inside `parent_fd` (`symlinkat`).
    pub fn create_symlink_in_dir(parent_fd: &OwnedFd, leaf: &str, target: &str) -> io::Result<()> {
        let c_leaf = to_cstring(leaf)?;
        let c_target = to_cstring(target)?;
        // SAFETY: `parent_fd` is a valid directory fd; `c_leaf` and `c_target` are NUL-terminated.
        let rc = unsafe { libc::symlinkat(c_target.as_ptr(), parent_fd.as_raw_fd(), c_leaf.as_ptr()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Create a hardlink from `src_parent/src_leaf` to `dst_parent/dst_leaf` strictly within `root_fd`.
    ///
    /// Both parent directories are resolved component-by-component with `openat2`, the source leaf
    /// is verified via `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS)`
    /// and `fstat` to be a regular file (`S_IFREG`) on the same device as `root_fd`, and `linkat`
    /// is invoked with `flags = 0` (never `AT_SYMLINK_FOLLOW`).
    pub fn create_hardlink_in_root(
        root_fd: &OwnedFd,
        src_comps: &[&str],
        dst_comps: &[&str],
    ) -> io::Result<()> {
        let (&src_leaf, src_parents) = src_comps.split_last().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "empty hardlink source path")
        })?;
        let (&dst_leaf, dst_parents) = dst_comps.split_last().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "empty hardlink dest path")
        })?;

        let root_st = fstat_fd(root_fd)?;
        let src_dir = walk_or_create_dirs(root_fd, src_parents, false)?;
        let src_file = open_child_file_readonly(&src_dir, src_leaf)?;
        let src_st = fstat_fd(&src_file)?;
        if (src_st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hardlink target is not a regular file",
            ));
        }
        if src_st.st_dev != root_st.st_dev {
            return Err(io::Error::new(
                io::ErrorKind::CrossesDevices,
                "hardlink target crosses device boundary",
            ));
        }

        let dst_dir = walk_or_create_dirs(root_fd, dst_parents, true)?;
        let c_src = to_cstring(src_leaf)?;
        let c_dst = to_cstring(dst_leaf)?;
        // SAFETY: `src_dir` and `dst_dir` are valid directory fds inside `root_fd`; `flags = 0`
        // ensures `linkat` never follows symlinks.
        let rc = unsafe {
            libc::linkat(
                src_dir.as_raw_fd(),
                c_src.as_ptr(),
                dst_dir.as_raw_fd(),
                c_dst.as_ptr(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `readlinkat(2)` on a single leaf component inside `parent_fd`.
    pub fn readlink_in_dir(parent_fd: &OwnedFd, leaf: &std::ffi::OsStr) -> io::Result<OsString> {
        let c_leaf = to_cstring_os(leaf)?;
        let mut buf = vec![0u8; 4096];
        loop {
            // SAFETY: `parent_fd` is valid, `c_leaf` is NUL-terminated, `buf` is writable.
            let n = unsafe {
                libc::readlinkat(
                    parent_fd.as_raw_fd(),
                    c_leaf.as_ptr(),
                    buf.as_mut_ptr().cast::<libc::c_char>(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n < buf.len() {
                buf.truncate(n);
                return Ok(OsString::from_vec(buf));
            }
            if buf.len() >= 65_536 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "symlink target exceeds 64 KiB",
                ));
            }
            buf.resize(buf.len() * 2, 0);
        }
    }

    /// `fstatat(parent_fd, leaf, AT_SYMLINK_NOFOLLOW)`.
    pub fn lstat_in_dir(parent_fd: &OwnedFd, leaf: &std::ffi::OsStr) -> io::Result<libc::stat> {
        let c_leaf = to_cstring_os(leaf)?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `parent_fd` is valid, `c_leaf` is NUL-terminated, `st` is writable.
        let rc = unsafe {
            libc::fstatat(
                parent_fd.as_raw_fd(),
                c_leaf.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc == 0 {
            Ok(st)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `fstat(fd)`.
    pub fn fstat_fd(fd: &impl AsRawFd) -> io::Result<libc::stat> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `fd` is valid, `st` is writable.
        let rc = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) };
        if rc == 0 {
            Ok(st)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// List immediate child entry names of `dir_fd` (excluding `.` and `..`), sorted.
    pub fn read_dir_names(dir_fd: &OwnedFd) -> io::Result<Vec<OsString>> {
        let dup = dup_cloexec(dir_fd)?;
        // SAFETY: `fdopendir` takes ownership of `dup`.
        let dirp = unsafe { libc::fdopendir(std::os::fd::IntoRawFd::into_raw_fd(dup)) };
        if dirp.is_null() {
            return Err(io::Error::last_os_error());
        }
        struct DirGuard(*mut libc::DIR);
        impl Drop for DirGuard {
            fn drop(&mut self) {
                // SAFETY: `self.0` was returned by `fdopendir` and is closed exactly once.
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let guard = DirGuard(dirp);
        let mut names = Vec::new();
        loop {
            // Reset errno before readdir to distinguish end-of-stream from error.
            // SAFETY: `__errno_location` is standard Linux/glibc/musl thread-local errno pointer;
            // we use `nix::errno::Errno::clear()` to avoid libc target differences.
            nix::errno::Errno::clear();
            // SAFETY: `guard.0` is a valid `DIR*`.
            let ent = unsafe { libc::readdir(guard.0) };
            if ent.is_null() {
                let err = io::Error::last_os_error();
                if err.raw_os_error().unwrap_or(0) != 0 {
                    return Err(err);
                }
                break;
            }
            // SAFETY: `d_name` is a NUL-terminated C string inside the returned `dirent`.
            let cname = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) };
            let bytes = cname.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
        names.sort();
        Ok(names)
    }

    fn dup_cloexec(fd: &OwnedFd) -> io::Result<OwnedFd> {
        // SAFETY: `F_DUPFD_CLOEXEC` duplicates an open fd with `O_CLOEXEC`.
        let dup = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: kernel returned a fresh fd.
            Ok(unsafe { OwnedFd::from_raw_fd(dup) })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn open_how_abi_layout_is_locked() {
        assert_eq!(size_of::<OpenHow>(), 24);
        assert_eq!(align_of::<OpenHow>(), 8);
        assert_eq!(SYS_OPENAT2, 437);
        assert_eq!(RESOLVE_NO_XDEV, 0x01);
        assert_eq!(RESOLVE_NO_MAGICLINKS, 0x02);
        assert_eq!(RESOLVE_NO_SYMLINKS, 0x04);
        assert_eq!(RESOLVE_BENEATH, 0x08);
        assert_eq!(RESOLVE_IN_ROOT, 0x10);
    }
}
