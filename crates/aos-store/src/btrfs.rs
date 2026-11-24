//! Btrfs uapi ioctl wrappers and pool guardrail parsers.
//!
//! Pure ABI constants, `#[repr(C)]` struct definitions, `/proc/self/mountinfo` parsing, and
//! `btrfs qgroup show` output interpretation are compiled on **all** targets so unit tests lock
//! every request code, struct size, and parser edge case on Windows and Linux alike.
//!
//! Only the small `linux_impl` submodule uses `unsafe` for direct Linux ioctl / `syncfs` /
//! `posix_fallocate` calls; every call is documented with explicit `// SAFETY:` invariants.

use std::mem::size_of;
use std::path::{Path, PathBuf};

/// Linux `BTRFS_SUPER_MAGIC` (`0x9123683E`).
pub const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
/// Linux `V9FS_MAGIC` (`0x01021997`, WSL2 9p / DrvFs).
pub const V9FS_MAGIC: u64 = 0x0102_1997;
/// Btrfs ioctl magic (`0x94`).
pub const BTRFS_IOCTL_MAGIC: u8 = 0x94;
/// Inode number of every Btrfs subvolume root (`BTRFS_FIRST_FREE_OBJECTID`).
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

/// `BTRFS_SUBVOL_RDONLY` (`1ULL << 1`).
pub const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
/// `BTRFS_SUBVOL_NAME_MAX` (uapi/linux/btrfs.h).
pub const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
/// `BTRFS_PATH_NAME_MAX` (uapi/linux/btrfs.h).
pub const BTRFS_PATH_NAME_MAX: usize = 4087;

const IOC_NONE: u64 = 0;
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;

/// Linux generic `_IOC` encoding (x86_64 / aarch64): `dir:2 | size:14 | type:8 | nr:8`.
#[must_use]
pub const fn linux_ioc(dir: u64, ty: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | (ty << 8) | nr
}

/// `BTRFS_IOC_SYNC = _IO(0x94, 8)` (`0x0000_9408`).
pub const BTRFS_IOC_SYNC_REQ: u64 = linux_ioc(IOC_NONE, 0x94, 8, 0);
/// `BTRFS_IOC_SNAP_DESTROY = _IOW(0x94, 15, struct btrfs_ioctl_vol_args)` (`0x5000_940f`).
pub const BTRFS_IOC_SNAP_DESTROY_REQ: u64 =
    linux_ioc(IOC_WRITE, 0x94, 15, size_of::<BtrfsIoctlVolArgs>());
/// `BTRFS_IOC_SNAP_CREATE_V2 = _IOW(0x94, 23, struct btrfs_ioctl_vol_args_v2)` (`0x5000_9417`).
pub const BTRFS_IOC_SNAP_CREATE_V2_REQ: u64 =
    linux_ioc(IOC_WRITE, 0x94, 23, size_of::<BtrfsIoctlVolArgsV2>());
/// `BTRFS_IOC_SUBVOL_CREATE_V2 = _IOW(0x94, 24, struct btrfs_ioctl_vol_args_v2)` (`0x5000_9418`).
pub const BTRFS_IOC_SUBVOL_CREATE_V2_REQ: u64 =
    linux_ioc(IOC_WRITE, 0x94, 24, size_of::<BtrfsIoctlVolArgsV2>());
/// `BTRFS_IOC_SUBVOL_GETFLAGS = _IOR(0x94, 25, __u64)` (`0x8008_9419`).
pub const BTRFS_IOC_SUBVOL_GETFLAGS_REQ: u64 =
    linux_ioc(IOC_READ, 0x94, 25, size_of::<u64>());
/// `BTRFS_IOC_SUBVOL_SETFLAGS = _IOW(0x94, 26, __u64)` (`0x4008_941a`).
pub const BTRFS_IOC_SUBVOL_SETFLAGS_REQ: u64 =
    linux_ioc(IOC_WRITE, 0x94, 26, size_of::<u64>());
/// `BTRFS_IOC_SNAP_DESTROY_V2 = _IOW(0x94, 63, struct btrfs_ioctl_vol_args_v2)` (`0x5000_943f`).
pub const BTRFS_IOC_SNAP_DESTROY_V2_REQ: u64 =
    linux_ioc(IOC_WRITE, 0x94, 63, size_of::<BtrfsIoctlVolArgsV2>());

/// `struct btrfs_ioctl_vol_args` (4096 bytes).
#[repr(C)]
pub struct BtrfsIoctlVolArgs {
    /// Source fd (unused for destroy).
    pub fd: i64,
    /// NUL-terminated subvolume name.
    pub name: [u8; BTRFS_PATH_NAME_MAX + 1],
}

/// `struct btrfs_ioctl_vol_args_v2` (4096 bytes per `uapi/linux/btrfs.h`).
#[repr(C)]
pub struct BtrfsIoctlVolArgsV2 {
    /// Source subvolume fd (for snapshot).
    pub fd: i64,
    /// Transaction id (out).
    pub transid: u64,
    /// Flags (e.g. `BTRFS_SUBVOL_RDONLY`).
    pub flags: u64,
    /// Union field (`size`).
    pub size: u64,
    /// Union field (`qgroup_inherit`), always null.
    pub qgroup_inherit: u64,
    /// Remaining 16 bytes of `u64 unused[4]` union.
    pub _u1_pad: [u64; 2],
    /// NUL-terminated subvolume name.
    pub name: [u8; BTRFS_SUBVOL_NAME_MAX + 1],
}

impl BtrfsIoctlVolArgsV2 {
    /// Heap-allocate zeroed 4 KiB struct (avoids large stack frames).
    #[must_use]
    pub fn boxed() -> Box<Self> {
        Box::new(Self {
            fd: 0,
            transid: 0,
            flags: 0,
            size: 0,
            qgroup_inherit: 0,
            _u1_pad: [0; 2],
            name: [0; BTRFS_SUBVOL_NAME_MAX + 1],
        })
    }
}

impl BtrfsIoctlVolArgs {
    /// Heap-allocate zeroed 4 KiB struct.
    #[must_use]
    pub fn boxed() -> Box<Self> {
        Box::new(Self {
            fd: 0,
            name: [0; BTRFS_PATH_NAME_MAX + 1],
        })
    }
}

/// Copy a validated single-component subvolume name into a fixed-size C buffer.
pub fn copy_subvol_name(dst: &mut [u8], name: &str) -> std::io::Result<()> {
    let b = name.as_bytes();
    if b.is_empty()
        || b.len() >= dst.len()
        || b.contains(&0)
        || b.contains(&b'/')
        || name == "."
        || name == ".."
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid btrfs subvolume name {name:?}"),
        ));
    }
    dst[..b.len()].copy_from_slice(b);
    dst[b.len()] = 0;
    Ok(())
}

/// Parsed entry from `/proc/self/mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfoEntry {
    /// Mount point path (octal escapes decoded).
    pub mount_point: PathBuf,
    /// Per-mount options (field 6, comma-separated).
    pub mount_options: Vec<String>,
    /// Filesystem type (first field after ` - `).
    pub fs_type: String,
    /// Per-superblock options (third field after ` - `, comma-separated).
    pub super_options: Vec<String>,
}

impl MountInfoEntry {
    /// `true` iff exact option token `"autodefrag"` appears in either mount or super options.
    #[must_use]
    pub fn has_autodefrag(&self) -> bool {
        self.mount_options.iter().any(|o| o == "autodefrag")
            || self.super_options.iter().any(|o| o == "autodefrag")
    }
}

/// Decode `/proc/self/mountinfo` octal escapes (`\040`, `\011`, `\012`, `\134`, etc.).
#[must_use]
pub fn unescape_mountinfo_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d1 = bytes[i + 1];
            let d2 = bytes[i + 2];
            let d3 = bytes[i + 3];
            if (b'0'..=b'3').contains(&d1)
                && (b'0'..=b'7').contains(&d2)
                && (b'0'..=b'7').contains(&d3)
            {
                let val = ((d1 - b'0') << 6) | ((d2 - b'0') << 3) | (d3 - b'0');
                out.push(val);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo` text and find the active mount covering `canonical_path`.
///
/// Selects the longest matching mount-point prefix; when multiple mounts share the exact same
/// mount point (overmounts), the later line in `mountinfo` wins.
#[must_use]
pub fn find_mount_for_path(mountinfo: &str, canonical_path: &Path) -> Option<MountInfoEntry> {
    let mut best: Option<(usize, MountInfoEntry)> = None;
    for line in mountinfo.lines() {
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let pre_fields: Vec<&str> = pre.split(' ').collect();
        if pre_fields.len() < 6 {
            continue;
        }
        let post_fields: Vec<&str> = post.split(' ').collect();
        if post_fields.len() < 3 {
            continue;
        }
        let mp_str = unescape_mountinfo_field(pre_fields[4]);
        let mp = PathBuf::from(&mp_str);
        if !canonical_path.starts_with(&mp) {
            continue;
        }
        let depth = mp.components().count();
        let replace = match &best {
            None => true,
            Some((best_depth, _)) => depth >= *best_depth,
        };
        if replace {
            let mount_options = pre_fields[5]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            let fs_type = post_fields[0].to_owned();
            let super_options = post_fields[2]
                .split(',')
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            best = Some((
                depth,
                MountInfoEntry {
                    mount_point: mp,
                    mount_options,
                    fs_type,
                    super_options,
                },
            ));
        }
    }
    best.map(|(_, e)| e)
}

/// Outcome of interpreting `btrfs qgroup show <pool_root>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QgroupCheckOutcome {
    /// Quotas are provably disabled.
    Disabled,
    /// Quotas are enabled (must refuse pool open).
    Enabled(String),
    /// Could not determine quota state (must fail closed).
    CheckFailed(String),
}

/// Interpret exit status + stdout + stderr of `btrfs qgroup show <path>`.
#[must_use]
pub fn interpret_qgroup_show_output(
    success: bool,
    exit_code: Option<i32>,
    stdout: &str,
    stderr: &str,
) -> QgroupCheckOutcome {
    if success {
        let summary = stdout
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" | ");
        return QgroupCheckOutcome::Enabled(if summary.is_empty() {
            "btrfs qgroup show exited 0 (quotas active)".into()
        } else {
            summary
        });
    }
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("quotas not enabled") || lower.contains("quota not enabled") {
        QgroupCheckOutcome::Disabled
    } else {
        QgroupCheckOutcome::CheckFailed(format!(
            "btrfs qgroup show exited {:?}: {}",
            exit_code,
            stderr.trim()
        ))
    }
}

/// Linux Btrfs syscalls and guardrails.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub mod linux_impl {
    use std::fs::{File, OpenOptions};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::process::Command;

    use nix::{ioctl_none, ioctl_read, ioctl_write_ptr};

    use super::{
        BTRFS_FIRST_FREE_OBJECTID, BTRFS_SUBVOL_RDONLY, BTRFS_SUPER_MAGIC, BtrfsIoctlVolArgs,
        BtrfsIoctlVolArgsV2, QgroupCheckOutcome, V9FS_MAGIC, copy_subvol_name, find_mount_for_path,
        interpret_qgroup_show_output,
    };
    use crate::error::{Result, StoreError};

    mod raw {
        use super::*;

        ioctl_none!(btrfs_sync, 0x94, 8);
        ioctl_write_ptr!(btrfs_snap_destroy_v1, 0x94, 15, BtrfsIoctlVolArgs);
        ioctl_write_ptr!(btrfs_snap_create_v2, 0x94, 23, BtrfsIoctlVolArgsV2);
        ioctl_write_ptr!(btrfs_subvol_create_v2, 0x94, 24, BtrfsIoctlVolArgsV2);
        ioctl_read!(btrfs_subvol_getflags, 0x94, 25, u64);
        ioctl_write_ptr!(btrfs_subvol_setflags, 0x94, 26, u64);
        ioctl_write_ptr!(btrfs_snap_destroy_v2, 0x94, 63, BtrfsIoctlVolArgsV2);
    }

    fn cvt<T>(r: nix::Result<T>) -> io::Result<T> {
        r.map_err(io::Error::from)
    }

    /// Open a directory without following symlinks (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`).
    pub fn open_dir_nofollow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    /// Call `syncfs(2)` on the filesystem containing `f`.
    pub fn syncfs(f: &File) -> io::Result<()> {
        // SAFETY: `f` is a valid open file descriptor; `syncfs` takes an fd by value.
        let rc = unsafe { libc::syncfs(f.as_raw_fd()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// `BTRFS_IOC_SYNC`: commit the current Btrfs transaction.
    pub fn btrfs_sync(f: &File) -> io::Result<()> {
        // SAFETY: `f` is a valid open fd; `BTRFS_IOC_SYNC` takes no pointer argument.
        cvt(unsafe { raw::btrfs_sync(f.as_raw_fd()) }).map(|_| ())
    }

    /// `BTRFS_IOC_SUBVOL_CREATE_V2`: create empty writable subvolume `parent/name`.
    pub fn btrfs_subvol_create(parent: &File, name: &str) -> io::Result<()> {
        let mut a = BtrfsIoctlVolArgsV2::boxed();
        copy_subvol_name(&mut a.name, name)?;
        // SAFETY: `parent` is a valid directory fd and `a` is a valid 4096-byte `repr(C)` struct
        // with a NUL-terminated name and null `qgroup_inherit`.
        cvt(unsafe { raw::btrfs_subvol_create_v2(parent.as_raw_fd(), &*a) }).map(|_| ())
    }

    /// `BTRFS_IOC_SNAP_CREATE_V2`: snapshot `src_subvol` as `parent/name`.
    pub fn btrfs_snap_create(
        parent: &File,
        src_subvol: &File,
        name: &str,
        readonly: bool,
    ) -> io::Result<()> {
        let mut a = BtrfsIoctlVolArgsV2::boxed();
        a.fd = i64::from(src_subvol.as_raw_fd());
        if readonly {
            a.flags |= BTRFS_SUBVOL_RDONLY;
        }
        copy_subvol_name(&mut a.name, name)?;
        // SAFETY: `parent` and `src_subvol` are valid fds for the call duration; `a` is a valid
        // 4096-byte `repr(C)` struct with a NUL-terminated name.
        cvt(unsafe { raw::btrfs_snap_create_v2(parent.as_raw_fd(), &*a) }).map(|_| ())
    }

    /// `BTRFS_IOC_SUBVOL_GETFLAGS`: read subvolume flags (`BTRFS_SUBVOL_RDONLY`, etc.).
    pub fn btrfs_subvol_getflags(subvol: &File) -> io::Result<u64> {
        let mut flags: u64 = 0;
        // SAFETY: `subvol` is a valid subvolume fd and `flags` is a writable `u64`.
        cvt(unsafe { raw::btrfs_subvol_getflags(subvol.as_raw_fd(), &mut flags) })?;
        Ok(flags)
    }

    /// `BTRFS_IOC_SUBVOL_SETFLAGS`: write subvolume flags.
    pub fn btrfs_subvol_setflags(subvol: &File, flags: u64) -> io::Result<()> {
        // SAFETY: `subvol` is a valid subvolume fd and `&flags` is a readable `u64`.
        cvt(unsafe { raw::btrfs_subvol_setflags(subvol.as_raw_fd(), &flags) }).map(|_| ())
    }

    /// Set or clear `BTRFS_SUBVOL_RDONLY` on an open subvolume directory.
    pub fn btrfs_subvol_set_readonly(subvol: &File, readonly: bool) -> io::Result<()> {
        let cur = btrfs_subvol_getflags(subvol)?;
        let next = if readonly {
            cur | BTRFS_SUBVOL_RDONLY
        } else {
            cur & !BTRFS_SUBVOL_RDONLY
        };
        if next != cur {
            btrfs_subvol_setflags(subvol, next)?;
        }
        Ok(())
    }

    /// Destroy subvolume `parent/name` (`BTRFS_IOC_SNAP_DESTROY_V2`, falling back to v1 on `ENOTTY`).
    pub fn btrfs_snap_destroy(parent: &File, name: &str) -> io::Result<()> {
        let mut a = BtrfsIoctlVolArgsV2::boxed();
        copy_subvol_name(&mut a.name, name)?;
        // SAFETY: `parent` is a valid directory fd and `a` is a valid 4096-byte `repr(C)` struct.
        match cvt(unsafe { raw::btrfs_snap_destroy_v2(parent.as_raw_fd(), &*a) }) {
            Ok(_) => Ok(()),
            Err(e) if e.raw_os_error() == Some(libc::ENOTTY) => {
                let mut v1 = BtrfsIoctlVolArgs::boxed();
                copy_subvol_name(&mut v1.name, name)?;
                // SAFETY: `v1` is a valid 4096-byte `repr(C)` struct.
                cvt(unsafe { raw::btrfs_snap_destroy_v1(parent.as_raw_fd(), &*v1) }).map(|_| ())
            }
            Err(e) => Err(e),
        }
    }

    /// Returns `true` iff `path` is a Btrfs subvolume root (directory with `ino == 256` on Btrfs).
    pub fn is_btrfs_subvolume(path: &Path) -> io::Result<bool> {
        let md = std::fs::symlink_metadata(path)?;
        if !md.is_dir() || md.ino() != BTRFS_FIRST_FREE_OBJECTID {
            return Ok(false);
        }
        let st = nix::sys::statfs::statfs(path).map_err(io::Error::from)?;
        let magic = st.filesystem_type().0 as u64 & 0xffff_ffff;
        Ok(magic == BTRFS_SUPER_MAGIC)
    }

    /// Allocate `len` real bytes for a ballast file via `posix_fallocate`.
    pub fn fallocate_ballast(f: &File, len: u64) -> io::Result<()> {
        let len_i64 = i64::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "ballast size exceeds i64::MAX")
        })?;
        nix::fcntl::posix_fallocate(f.as_raw_fd(), 0, len_i64).map_err(io::Error::from)
    }

    /// Verify all Linux Btrfs pool guardrails on `pool_root`:
    /// 1. Not under `/mnt` and not 9p/DrvFs (`V9FS_MAGIC`).
    /// 2. `statfs` reports `BTRFS_SUPER_MAGIC`.
    /// 3. `/proc/self/mountinfo` confirms `btrfs` without `autodefrag`.
    /// 4. `btrfs qgroup show` confirms qgroups are disabled (fail closed).
    pub fn verify_btrfs_pool_guardrails(pool_root: &Path) -> Result<()> {
        if pool_root.starts_with("/mnt") {
            return Err(StoreError::ForbiddenPoolRoot {
                path: pool_root.to_path_buf(),
                reason: "pool root must not live under /mnt (WSL2 9p/DrvFs)".into(),
            });
        }
        let canon = pool_root
            .canonicalize()
            .map_err(|e| StoreError::io(format!("canonicalizing {}", pool_root.display()), e))?;
        if canon.starts_with("/mnt") {
            return Err(StoreError::ForbiddenPoolRoot {
                path: canon,
                reason: "pool root resolves under /mnt (WSL2 9p/DrvFs)".into(),
            });
        }
        let st = nix::sys::statfs::statfs(&canon).map_err(|e| {
            StoreError::io(
                format!("statfs {}", canon.display()),
                io::Error::from(e),
            )
        })?;
        let magic = st.filesystem_type().0 as u64 & 0xffff_ffff;
        if magic == V9FS_MAGIC {
            return Err(StoreError::ForbiddenPoolRoot {
                path: canon,
                reason: format!("9p/DrvFs filesystem (f_type=0x{magic:x}) is forbidden"),
            });
        }
        if magic != BTRFS_SUPER_MAGIC {
            return Err(StoreError::NotBtrfs {
                path: canon,
                fs_magic: magic,
            });
        }

        // Check /proc/self/mountinfo for autodefrag.
        let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| StoreError::io("reading /proc/self/mountinfo", e))?;
        let entry = find_mount_for_path(&mountinfo, &canon).ok_or_else(|| {
            StoreError::MountInfoCheckFailed {
                pool_root: canon.clone(),
                detail: "no matching mount entry in /proc/self/mountinfo".into(),
            }
        })?;
        if entry.fs_type != "btrfs" {
            return Err(StoreError::MountInfoCheckFailed {
                pool_root: canon,
                detail: format!(
                    "expected fs_type \"btrfs\" at {}, found {:?}",
                    entry.mount_point.display(),
                    entry.fs_type
                ),
            });
        }
        if entry.has_autodefrag() {
            return Err(StoreError::AutodefragEnabled {
                pool_root: canon,
                mount_point: entry.mount_point,
            });
        }

        // Check qgroups disabled (fail closed).
        let out = Command::new("btrfs")
            .args(["qgroup", "show"])
            .arg(&canon)
            .output()
            .map_err(|e| StoreError::QgroupsCheckFailed {
                pool_root: canon.clone(),
                detail: format!("failed to invoke `btrfs qgroup show`: {e}"),
            })?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        match interpret_qgroup_show_output(out.status.success(), out.status.code(), &stdout, &stderr)
        {
            QgroupCheckOutcome::Disabled => Ok(()),
            QgroupCheckOutcome::Enabled(detail) => Err(StoreError::QgroupsEnabled {
                pool_root: canon,
                detail,
            }),
            QgroupCheckOutcome::CheckFailed(detail) => Err(StoreError::QgroupsCheckFailed {
                pool_root: canon,
                detail,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn btrfs_uapi_struct_sizes_and_request_codes_locked() {
        assert_eq!(size_of::<BtrfsIoctlVolArgs>(), 4096);
        assert_eq!(size_of::<BtrfsIoctlVolArgsV2>(), 4096);
        assert_eq!(align_of::<BtrfsIoctlVolArgsV2>(), 8);

        assert_eq!(BTRFS_IOC_SYNC_REQ, 0x0000_9408);
        assert_eq!(BTRFS_IOC_SNAP_DESTROY_REQ, 0x5000_940f);
        assert_eq!(BTRFS_IOC_SNAP_CREATE_V2_REQ, 0x5000_9417);
        assert_eq!(BTRFS_IOC_SUBVOL_CREATE_V2_REQ, 0x5000_9418);
        assert_eq!(BTRFS_IOC_SUBVOL_GETFLAGS_REQ, 0x8008_9419);
        assert_eq!(BTRFS_IOC_SUBVOL_SETFLAGS_REQ, 0x4008_941a);
        assert_eq!(BTRFS_IOC_SNAP_DESTROY_V2_REQ, 0x5000_943f);
        assert_eq!(BTRFS_SUBVOL_RDONLY, 0x02);
    }

    #[test]
    fn mountinfo_parser_detects_autodefrag_nested_and_escaped_paths() {
        let sample = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
89 22 0:45 / /var/lib/forkloom/pool rw,noatime shared:2 - btrfs /dev/loop0 rw,space_cache=v2,subvol=/
90 89 0:46 / /var/lib/forkloom/pool/defrag\\040test rw,noatime shared:3 - btrfs /dev/loop1 rw,autodefrag,space_cache=v2
91 22 0:47 / /var/lib/forkloom/overmount rw,noatime - btrfs /dev/loop2 rw,autodefrag
92 22 0:48 / /var/lib/forkloom/overmount rw,noatime - btrfs /dev/loop3 rw,noautodefrag
";
        let clean = find_mount_for_path(sample, Path::new("/var/lib/forkloom/pool/objects")).unwrap();
        assert_eq!(clean.mount_point, PathBuf::from("/var/lib/forkloom/pool"));
        assert_eq!(clean.fs_type, "btrfs");
        assert!(!clean.has_autodefrag());

        let defrag = find_mount_for_path(
            sample,
            Path::new("/var/lib/forkloom/pool/defrag test/sub"),
        )
        .unwrap();
        assert_eq!(
            defrag.mount_point,
            PathBuf::from("/var/lib/forkloom/pool/defrag test")
        );
        assert!(defrag.has_autodefrag());

        // Later overmount at identical mount point takes precedence, and `noautodefrag` is NOT `autodefrag`.
        let over = find_mount_for_path(sample, Path::new("/var/lib/forkloom/overmount")).unwrap();
        assert!(!over.has_autodefrag());
    }

    #[test]
    fn qgroup_output_interpreter_fails_closed() {
        assert_eq!(
            interpret_qgroup_show_output(
                false,
                Some(1),
                "",
                "ERROR: can't list qgroups: quotas not enabled\n"
            ),
            QgroupCheckOutcome::Disabled
        );
        assert!(matches!(
            interpret_qgroup_show_output(true, Some(0), "qgroupid rfer excl\n0/5 16KiB 16KiB\n", ""),
            QgroupCheckOutcome::Enabled(_)
        ));
        assert!(matches!(
            interpret_qgroup_show_output(false, Some(1), "", "ERROR: permission denied\n"),
            QgroupCheckOutcome::CheckFailed(_)
        ));
    }

    #[test]
    fn subvol_name_copy_rejects_bad_inputs() {
        let mut buf = [0u8; 16];
        assert!(copy_subvol_name(&mut buf, "f-abc-subvol").is_ok());
        assert_eq!(&buf[..13], b"f-abc-subvol\0");
        for bad in ["", ".", "..", "a/b", "a\0b", "0123456789abcdef"] {
            assert!(copy_subvol_name(&mut buf, bad).is_err(), "accepted {bad:?}");
        }
    }
}
