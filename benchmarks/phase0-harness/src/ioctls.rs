//! Exact Linux ioctl wrappers used by the Phase 0 suite.
//!
//! Every request code and `repr(C)` struct size is locked by unit tests at the bottom of this
//! file (a wrong size silently yields `ENOTTY` from the kernel, which is the classic way an
//! "unsupported feature" gets falsely reported).
//!
//! Notable kernel quirks encoded here:
//!
//! * `FS_IOC_GETFLAGS` / `FS_IOC_SETFLAGS` are *declared* as `_IOR/_IOW('f', 1|2, long)` so the
//!   request code embeds an **8-byte** size (`0x80086601` / `0x40086602`), yet the kernel reads and
//!   writes a **4-byte** `int`. They therefore use the `*_bad!` macro flavours with a `c_int`.
//! * `FIEMAP` may merge physically adjacent extents; for an exact count of Btrfs file extent items
//!   [`btrfs_count_extent_items`] walks `BTRFS_IOC_TREE_SEARCH` for `BTRFS_EXTENT_DATA_KEY` (108).
//! * `BTRFS_IOC_SNAP_DESTROY_V2` (63) needs Linux >= 5.7; [`btrfs_snap_destroy`] falls back to the v1
//!   ioctl (15).

use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

use nix::libc::{c_int, c_ulong};
use nix::{
    ioctl_none, ioctl_read, ioctl_read_bad, ioctl_readwrite, ioctl_write_int, ioctl_write_ptr,
    ioctl_write_ptr_bad,
};

// ---------------------------------------------------------------------------------------------
// constants
// ---------------------------------------------------------------------------------------------

/// `FS_NOCOW_FL` (`chattr +C`).
pub const FS_NOCOW_FL: c_int = 0x0080_0000;
/// Btrfs ioctl magic.
pub const BTRFS_IOCTL_MAGIC: u8 = 0x94;
/// `BTRFS_EXTENT_DATA_KEY`.
pub const BTRFS_EXTENT_DATA_KEY: u32 = 108;
/// `BTRFS_SUBVOL_RDONLY` flag in `btrfs_ioctl_vol_args_v2.flags`.
pub const BTRFS_SUBVOL_RDONLY: u64 = 1 << 1;
/// `BTRFS_SUBVOL_NAME_MAX`.
pub const BTRFS_SUBVOL_NAME_MAX: usize = 4039;
/// `BTRFS_PATH_NAME_MAX`.
pub const BTRFS_PATH_NAME_MAX: usize = 4087;
/// `FIEMAP_FLAG_SYNC`: flush delalloc before mapping.
pub const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
/// `FIEMAP_MAX_OFFSET`.
pub const FIEMAP_MAX_OFFSET: u64 = u64::MAX;

const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

/// Linux generic `_IOC` encoding (x86_64/aarch64): `dir:2 | size:14 | type:8 | nr:8`.
#[must_use]
pub const fn ioc(dir: u32, ty: u32, nr: u32, size: usize) -> c_ulong {
    ((dir as c_ulong) << 30) | ((size as c_ulong) << 16) | ((ty as c_ulong) << 8) | nr as c_ulong
}

/// `FICLONE = _IOW(0x94, 9, int)`.
pub const FICLONE_REQ: c_ulong = ioc(IOC_WRITE, 0x94, 9, size_of::<c_int>());
/// `FS_IOC_GETFLAGS = _IOR('f', 1, long)` (8-byte size encoding, 4-byte payload).
pub const FS_IOC_GETFLAGS_REQ: c_ulong = ioc(IOC_READ, b'f' as u32, 1, size_of::<std::ffi::c_long>());
/// `FS_IOC_SETFLAGS = _IOW('f', 2, long)` (8-byte size encoding, 4-byte payload).
pub const FS_IOC_SETFLAGS_REQ: c_ulong = ioc(IOC_WRITE, b'f' as u32, 2, size_of::<std::ffi::c_long>());
/// `FS_IOC_FSGETXATTR = _IOR('X', 31, struct fsxattr)`.
pub const FS_IOC_FSGETXATTR_REQ: c_ulong = ioc(IOC_READ, b'X' as u32, 31, size_of::<FsXattr>());
/// `FS_IOC_FIEMAP = _IOWR('f', 11, struct fiemap)` (32-byte header).
pub const FS_IOC_FIEMAP_REQ: c_ulong =
    ioc(IOC_READ | IOC_WRITE, b'f' as u32, 11, size_of::<FiemapHeader>());
/// `BTRFS_IOC_SUBVOL_CREATE_V2 = _IOW(0x94, 24, struct btrfs_ioctl_vol_args_v2)`.
pub const BTRFS_IOC_SUBVOL_CREATE_V2_REQ: c_ulong =
    ioc(IOC_WRITE, 0x94, 24, size_of::<BtrfsIoctlVolArgsV2>());
/// `BTRFS_IOC_SNAP_CREATE_V2 = _IOW(0x94, 23, struct btrfs_ioctl_vol_args_v2)`.
pub const BTRFS_IOC_SNAP_CREATE_V2_REQ: c_ulong =
    ioc(IOC_WRITE, 0x94, 23, size_of::<BtrfsIoctlVolArgsV2>());
/// `BTRFS_IOC_SNAP_DESTROY_V2 = _IOW(0x94, 63, struct btrfs_ioctl_vol_args_v2)`.
pub const BTRFS_IOC_SNAP_DESTROY_V2_REQ: c_ulong =
    ioc(IOC_WRITE, 0x94, 63, size_of::<BtrfsIoctlVolArgsV2>());
/// `BTRFS_IOC_SNAP_DESTROY = _IOW(0x94, 15, struct btrfs_ioctl_vol_args)` (v1).
pub const BTRFS_IOC_SNAP_DESTROY_REQ: c_ulong = ioc(IOC_WRITE, 0x94, 15, size_of::<BtrfsIoctlVolArgs>());
/// `BTRFS_IOC_SYNC = _IO(0x94, 8)`.
pub const BTRFS_IOC_SYNC_REQ: c_ulong = ioc(IOC_NONE, 0x94, 8, 0);
/// `BTRFS_IOC_FS_INFO = _IOR(0x94, 31, struct btrfs_ioctl_fs_info_args)`.
pub const BTRFS_IOC_FS_INFO_REQ: c_ulong = ioc(IOC_READ, 0x94, 31, size_of::<BtrfsIoctlFsInfoArgs>());
/// `BTRFS_IOC_TREE_SEARCH = _IOWR(0x94, 17, struct btrfs_ioctl_search_args)`.
pub const BTRFS_IOC_TREE_SEARCH_REQ: c_ulong =
    ioc(IOC_READ | IOC_WRITE, 0x94, 17, size_of::<BtrfsIoctlSearchArgs>());

// ---------------------------------------------------------------------------------------------
// uapi structs
// ---------------------------------------------------------------------------------------------

/// `struct fsxattr` (28 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FsXattr {
    /// `fsx_xflags`.
    pub fsx_xflags: u32,
    /// `fsx_extsize`.
    pub fsx_extsize: u32,
    /// `fsx_nextents` - number of data extents (XFS exact).
    pub fsx_nextents: u32,
    /// `fsx_projid`.
    pub fsx_projid: u32,
    /// `fsx_cowextsize`.
    pub fsx_cowextsize: u32,
    /// `fsx_pad`.
    pub fsx_pad: [u8; 8],
}

/// `struct fiemap` header (32 bytes, no trailing extents; `fm_extent_count = 0` => count only).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FiemapHeader {
    /// `fm_start`.
    pub fm_start: u64,
    /// `fm_length`.
    pub fm_length: u64,
    /// `fm_flags`.
    pub fm_flags: u32,
    /// `fm_mapped_extents` (out).
    pub fm_mapped_extents: u32,
    /// `fm_extent_count`.
    pub fm_extent_count: u32,
    /// `fm_reserved`.
    pub fm_reserved: u32,
}

/// `struct fiemap_extent` (56 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FiemapExtent {
    /// `fe_logical`.
    pub fe_logical: u64,
    /// `fe_physical`.
    pub fe_physical: u64,
    /// `fe_length`.
    pub fe_length: u64,
    /// `fe_reserved64`.
    pub fe_reserved64: [u64; 2],
    /// `fe_flags`.
    pub fe_flags: u32,
    /// `fe_reserved`.
    pub fe_reserved: [u32; 3],
}

/// `struct btrfs_ioctl_vol_args` (4096 bytes).
#[repr(C)]
pub struct BtrfsIoctlVolArgs {
    /// `fd`.
    pub fd: i64,
    /// `name[BTRFS_PATH_NAME_MAX + 1]`.
    pub name: [u8; BTRFS_PATH_NAME_MAX + 1],
}

/// `struct btrfs_ioctl_vol_args_v2` (4096 bytes per Linux uapi/linux/btrfs.h: `u64 unused[4]` in union).
#[repr(C)]
pub struct BtrfsIoctlVolArgsV2 {
    /// `fd`.
    pub fd: i64,
    /// `transid` (out).
    pub transid: u64,
    /// `flags`.
    pub flags: u64,
    /// `size` (union member).
    pub size: u64,
    /// `qgroup_inherit` pointer (union member), unused.
    pub qgroup_inherit: u64,
    /// remaining 16 bytes of `u64 unused[4]` union in kernel struct.
    pub _u1_pad: [u64; 2],
    /// `name[BTRFS_SUBVOL_NAME_MAX + 1]`.
    pub name: [u8; BTRFS_SUBVOL_NAME_MAX + 1],
}

/// `struct btrfs_ioctl_search_key` (104 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BtrfsIoctlSearchKey {
    /// `tree_id` (0 = tree of the subvolume containing the fd's inode).
    pub tree_id: u64,
    /// `min_objectid`.
    pub min_objectid: u64,
    /// `max_objectid`.
    pub max_objectid: u64,
    /// `min_offset`.
    pub min_offset: u64,
    /// `max_offset`.
    pub max_offset: u64,
    /// `min_transid`.
    pub min_transid: u64,
    /// `max_transid`.
    pub max_transid: u64,
    /// `min_type`.
    pub min_type: u32,
    /// `max_type`.
    pub max_type: u32,
    /// `nr_items` (in: max wanted, out: found).
    pub nr_items: u32,
    /// `unused`.
    pub unused: u32,
    /// `unused1..4`.
    pub unused1: [u64; 3],
    /// `unused4`.
    pub unused4: u64,
}

/// Size of the result buffer in `btrfs_ioctl_search_args`.
pub const BTRFS_SEARCH_ARGS_BUF_SIZE: usize = 4096 - size_of::<BtrfsIoctlSearchKey>();

/// `struct btrfs_ioctl_search_args` (4096 bytes).
#[repr(C)]
pub struct BtrfsIoctlSearchArgs {
    /// Search key.
    pub key: BtrfsIoctlSearchKey,
    /// Result buffer.
    pub buf: [u8; BTRFS_SEARCH_ARGS_BUF_SIZE],
}

/// `struct btrfs_ioctl_fs_info_args` (1024 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BtrfsIoctlFsInfoArgs {
    /// `max_id`.
    pub max_id: u64,
    /// `num_devices`.
    pub num_devices: u64,
    /// `fsid`.
    pub fsid: [u8; 16],
    /// `nodesize`.
    pub nodesize: u32,
    /// `sectorsize`.
    pub sectorsize: u32,
    /// `clone_alignment`.
    pub clone_alignment: u32,
    /// `csum_type`.
    pub csum_type: u16,
    /// `csum_size`.
    pub csum_size: u16,
    /// `flags`.
    pub flags: u64,
    /// `generation`.
    pub generation: u64,
    /// `metadata_uuid`.
    pub metadata_uuid: [u8; 16],
    /// `reserved`.
    pub reserved: [u8; 944],
}

impl BtrfsIoctlVolArgsV2 {
    fn boxed() -> Box<Self> {
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
    fn boxed() -> Box<Self> {
        Box::new(Self { fd: 0, name: [0; BTRFS_PATH_NAME_MAX + 1] })
    }
}

impl BtrfsIoctlSearchArgs {
    fn boxed() -> Box<Self> {
        Box::new(Self { key: BtrfsIoctlSearchKey::default(), buf: [0; BTRFS_SEARCH_ARGS_BUF_SIZE] })
    }
}

// ---------------------------------------------------------------------------------------------
// raw (unsafe) ioctl functions generated by nix
// ---------------------------------------------------------------------------------------------

mod raw {
    use super::*;

    ioctl_write_int!(ficlone, 0x94, 9);
    ioctl_read_bad!(fs_getflags, 0x8008_6601u32 as nix::sys::ioctl::ioctl_num_type, c_int);
    ioctl_write_ptr_bad!(fs_setflags, 0x4008_6602u32 as nix::sys::ioctl::ioctl_num_type, c_int);
    ioctl_read!(fs_fsgetxattr, b'X', 31, FsXattr);
    ioctl_readwrite!(fs_fiemap, b'f', 11, FiemapHeader);
    ioctl_readwrite!(btrfs_tree_search, 0x94, 17, BtrfsIoctlSearchArgs);
    ioctl_write_ptr!(btrfs_subvol_create_v2, 0x94, 24, BtrfsIoctlVolArgsV2);
    ioctl_write_ptr!(btrfs_snap_create_v2, 0x94, 23, BtrfsIoctlVolArgsV2);
    ioctl_write_ptr!(btrfs_snap_destroy_v2, 0x94, 63, BtrfsIoctlVolArgsV2);
    ioctl_write_ptr!(btrfs_snap_destroy_v1, 0x94, 15, BtrfsIoctlVolArgs);
    ioctl_none!(btrfs_sync, 0x94, 8);
    ioctl_read!(btrfs_fs_info, 0x94, 31, BtrfsIoctlFsInfoArgs);
}

fn cvt<T>(r: nix::Result<T>) -> io::Result<T> {
    r.map_err(io::Error::from)
}

// ---------------------------------------------------------------------------------------------
// safe wrappers
// ---------------------------------------------------------------------------------------------

/// `FICLONE`: make `dst` share all extents of `src` (whole-file reflink).
pub fn ficlone(dst: &File, src: &File) -> io::Result<()> {
    // SAFETY: both descriptors are valid for the whole call; FICLONE takes the source fd by value.
    cvt(unsafe { raw::ficlone(dst.as_raw_fd(), src.as_raw_fd() as _) }).map(|_| ())
}

/// `FS_IOC_GETFLAGS` (reads a 4-byte `int` although the request encodes `long`).
pub fn get_flags(f: &File) -> io::Result<c_int> {
    let mut v: c_int = 0;
    // SAFETY: `v` is a valid, writable 4-byte int, which is what the kernel stores.
    cvt(unsafe { raw::fs_getflags(f.as_raw_fd(), &mut v) })?;
    Ok(v)
}

/// `FS_IOC_SETFLAGS` (writes a 4-byte `int`).
pub fn set_flags(f: &File, flags: c_int) -> io::Result<()> {
    // SAFETY: `flags` is a valid readable 4-byte int, which is what the kernel loads.
    cvt(unsafe { raw::fs_setflags(f.as_raw_fd(), &flags) }).map(|_| ())
}

/// Set `FS_NOCOW_FL` (`chattr +C`) preserving other flags. Must be done on an **empty** file.
pub fn set_nocow(f: &File) -> io::Result<()> {
    let cur = get_flags(f)?;
    set_flags(f, cur | FS_NOCOW_FL)
}

/// `true` if `FS_NOCOW_FL` is set.
pub fn is_nocow(f: &File) -> io::Result<bool> {
    Ok(get_flags(f)? & FS_NOCOW_FL != 0)
}

/// `FS_IOC_FSGETXATTR` (XFS/ext4/btrfs fsxattr; `fsx_nextents` is exact on XFS).
pub fn fsgetxattr(f: &File) -> io::Result<FsXattr> {
    let mut x = FsXattr::default();
    // SAFETY: `x` is a valid `repr(C)` out buffer of exactly `sizeof(struct fsxattr)`.
    cvt(unsafe { raw::fs_fsgetxattr(f.as_raw_fd(), &mut x) })?;
    Ok(x)
}

/// Number of extents reported by `FS_IOC_FIEMAP` (count-only call; flushes delalloc first).
/// Note FIEMAP may merge adjacent extents; use the filesystem specific exact counters when available.
pub fn fiemap_count(f: &File) -> io::Result<u32> {
    let mut h = FiemapHeader {
        fm_start: 0,
        fm_length: FIEMAP_MAX_OFFSET,
        fm_flags: FIEMAP_FLAG_SYNC,
        fm_mapped_extents: 0,
        fm_extent_count: 0,
        fm_reserved: 0,
    };
    // SAFETY: `h` is a valid `repr(C)` struct with `fm_extent_count == 0`, so the kernel writes
    // only the 32-byte header.
    cvt(unsafe { raw::fs_fiemap(f.as_raw_fd(), &mut h) })?;
    Ok(h.fm_mapped_extents)
}

/// Header of one item in a `BTRFS_IOC_TREE_SEARCH` result buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchItemHeader {
    /// `transid`.
    pub transid: u64,
    /// `objectid`.
    pub objectid: u64,
    /// `offset`.
    pub offset: u64,
    /// key type.
    pub item_type: u32,
    /// payload length following the 32-byte header.
    pub len: u32,
}

/// Size of `struct btrfs_ioctl_search_header`.
pub const SEARCH_HEADER_SIZE: usize = 32;

/// Parse up to `n` items out of a tree-search result buffer. Stops (without panicking) on
/// truncated buffers.
#[must_use]
pub fn parse_search_items(buf: &[u8], n: u32) -> Vec<SearchItemHeader> {
    let mut out = Vec::with_capacity(n as usize);
    let mut off = 0usize;
    for _ in 0..n {
        if off + SEARCH_HEADER_SIZE > buf.len() {
            break;
        }
        let rd64 = |o: usize| u64::from_ne_bytes(buf[off + o..off + o + 8].try_into().unwrap());
        let rd32 = |o: usize| u32::from_ne_bytes(buf[off + o..off + o + 4].try_into().unwrap());
        let h = SearchItemHeader {
            transid: rd64(0),
            objectid: rd64(8),
            offset: rd64(16),
            item_type: rd32(24),
            len: rd32(28),
        };
        let next = off + SEARCH_HEADER_SIZE + h.len as usize;
        if next > buf.len() {
            break;
        }
        out.push(h);
        off = next;
    }
    out
}

/// Exact number of `BTRFS_EXTENT_DATA_KEY` items of the file behind `f` (Btrfs only, needs
/// `CAP_SYS_ADMIN`). Unlike FIEMAP this never merges adjacent extents.
pub fn btrfs_count_extent_items(f: &File) -> io::Result<u64> {
    let ino = f.metadata()?.ino();
    let mut args = BtrfsIoctlSearchArgs::boxed();
    let mut min_offset = 0u64;
    let mut total = 0u64;
    loop {
        args.key = BtrfsIoctlSearchKey {
            tree_id: 0,
            min_objectid: ino,
            max_objectid: ino,
            min_offset,
            max_offset: u64::MAX,
            min_transid: 0,
            max_transid: u64::MAX,
            min_type: BTRFS_EXTENT_DATA_KEY,
            max_type: BTRFS_EXTENT_DATA_KEY,
            nr_items: 4096,
            ..Default::default()
        };
        // SAFETY: `args` is a valid, exclusively borrowed 4096-byte `repr(C)` struct.
        cvt(unsafe { raw::btrfs_tree_search(f.as_raw_fd(), &mut *args) })?;
        let found = args.key.nr_items;
        if found == 0 {
            break;
        }
        let items = parse_search_items(&args.buf, found);
        if items.is_empty() {
            break;
        }
        total += items.len() as u64;
        let last = items[items.len() - 1].offset;
        if last == u64::MAX {
            break;
        }
        min_offset = last + 1;
    }
    Ok(total)
}

fn copy_name(dst: &mut [u8], name: &str) -> io::Result<()> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() >= dst.len() || b.contains(&0) || b.contains(&b'/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid btrfs subvolume name {name:?}"),
        ));
    }
    dst[..b.len()].copy_from_slice(b);
    dst[b.len()] = 0;
    Ok(())
}

/// `BTRFS_IOC_SUBVOL_CREATE_V2`: create subvolume `name` inside directory `parent`.
pub fn btrfs_subvol_create(parent: &File, name: &str) -> io::Result<()> {
    let mut a = BtrfsIoctlVolArgsV2::boxed();
    copy_name(&mut a.name, name)?;
    // SAFETY: `a` is a valid 4096-byte `repr(C)` struct; NUL-terminated name; null qgroup pointer.
    cvt(unsafe { raw::btrfs_subvol_create_v2(parent.as_raw_fd(), &*a) }).map(|_| ())
}

/// `BTRFS_IOC_SNAP_CREATE_V2`: snapshot subvolume `src_subvol` as `parent/name`.
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
    copy_name(&mut a.name, name)?;
    // SAFETY: as above; `fd` is a valid subvolume root descriptor for the call duration.
    cvt(unsafe { raw::btrfs_snap_create_v2(parent.as_raw_fd(), &*a) }).map(|_| ())
}

/// Which destroy ioctl actually served the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyApi {
    /// `BTRFS_IOC_SNAP_DESTROY_V2` (63).
    V2,
    /// Legacy `BTRFS_IOC_SNAP_DESTROY` (15) after the kernel answered `ENOTTY` to v2.
    V1Fallback,
}

/// Destroy subvolume `parent/name` (v2, falling back to v1 on `ENOTTY`).
pub fn btrfs_snap_destroy(parent: &File, name: &str) -> io::Result<DestroyApi> {
    let mut a = BtrfsIoctlVolArgsV2::boxed();
    copy_name(&mut a.name, name)?;
    // SAFETY: as above.
    match cvt(unsafe { raw::btrfs_snap_destroy_v2(parent.as_raw_fd(), &*a) }) {
        Ok(_) => Ok(DestroyApi::V2),
        Err(e) if e.raw_os_error() == Some(libc::ENOTTY) => {
            let mut v1 = BtrfsIoctlVolArgs::boxed();
            copy_name(&mut v1.name, name)?;
            // SAFETY: valid 4096-byte `repr(C)` struct.
            cvt(unsafe { raw::btrfs_snap_destroy_v1(parent.as_raw_fd(), &*v1) })?;
            Ok(DestroyApi::V1Fallback)
        }
        Err(e) => Err(e),
    }
}

/// `BTRFS_IOC_SYNC`: commit the current transaction of the filesystem containing `f`.
pub fn btrfs_sync(f: &File) -> io::Result<()> {
    // SAFETY: no argument.
    cvt(unsafe { raw::btrfs_sync(f.as_raw_fd()) }).map(|_| ())
}

/// Selected fields of `BTRFS_IOC_FS_INFO`.
#[derive(Debug, Clone)]
pub struct BtrfsFsInfo {
    /// Highest device id.
    pub max_id: u64,
    /// Number of devices.
    pub num_devices: u64,
    /// Filesystem UUID (hex).
    pub fsid: String,
    /// Metadata node size.
    pub nodesize: u32,
    /// Sector size.
    pub sectorsize: u32,
    /// Clone alignment.
    pub clone_alignment: u32,
    /// Current transaction generation.
    pub generation: u64,
}

/// `BTRFS_IOC_FS_INFO`.
pub fn btrfs_fs_info(f: &File) -> io::Result<BtrfsFsInfo> {
    let mut a = Box::new(BtrfsIoctlFsInfoArgs {
        max_id: 0,
        num_devices: 0,
        fsid: [0; 16],
        nodesize: 0,
        sectorsize: 0,
        clone_alignment: 0,
        csum_type: 0,
        csum_size: 0,
        flags: 0,
        generation: 0,
        metadata_uuid: [0; 16],
        reserved: [0; 944],
    });
    // SAFETY: valid 1024-byte `repr(C)` out buffer.
    cvt(unsafe { raw::btrfs_fs_info(f.as_raw_fd(), &mut *a) })?;
    Ok(BtrfsFsInfo {
        max_id: a.max_id,
        num_devices: a.num_devices,
        fsid: a.fsid.iter().map(|b| format!("{b:02x}")).collect(),
        nodesize: a.nodesize,
        sectorsize: a.sectorsize,
        clone_alignment: a.clone_alignment,
        generation: a.generation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn uapi_struct_sizes_are_locked() {
        assert_eq!(size_of::<FsXattr>(), 28);
        assert_eq!(size_of::<FiemapHeader>(), 32);
        assert_eq!(size_of::<FiemapExtent>(), 56);
        assert_eq!(size_of::<BtrfsIoctlVolArgs>(), 4096);
        assert_eq!(size_of::<BtrfsIoctlVolArgsV2>(), 4096);
        assert_eq!(size_of::<BtrfsIoctlSearchKey>(), 104);
        assert_eq!(size_of::<BtrfsIoctlSearchArgs>(), 4096);
        assert_eq!(BTRFS_SEARCH_ARGS_BUF_SIZE, 3992);
        assert_eq!(size_of::<BtrfsIoctlFsInfoArgs>(), 1024);
        assert_eq!(align_of::<BtrfsIoctlVolArgsV2>(), 8);
    }

    #[test]
    fn request_codes_are_locked_to_known_kernel_values() {
        assert_eq!(FICLONE_REQ, 0x4004_9409);
        assert_eq!(FS_IOC_GETFLAGS_REQ, 0x8008_6601, "GETFLAGS encodes sizeof(long) == 8");
        assert_eq!(FS_IOC_SETFLAGS_REQ, 0x4008_6602, "SETFLAGS encodes sizeof(long) == 8");
        assert_eq!(FS_IOC_FSGETXATTR_REQ, 0x801c_581f);
        assert_eq!(FS_IOC_FIEMAP_REQ, 0xc020_660b);
        assert_eq!(BTRFS_IOC_SUBVOL_CREATE_V2_REQ, 0x5000_9418);
        assert_eq!(BTRFS_IOC_SNAP_CREATE_V2_REQ, 0x5000_9417);
        assert_eq!(BTRFS_IOC_SNAP_DESTROY_V2_REQ, 0x5000_943f);
        assert_eq!(BTRFS_IOC_SNAP_DESTROY_REQ, 0x5000_940f);
        assert_eq!(BTRFS_IOC_SYNC_REQ, 0x9408);
        assert_eq!(BTRFS_IOC_FS_INFO_REQ, 0x8400_941f);
        assert_eq!(BTRFS_IOC_TREE_SEARCH_REQ, 0xd000_9411);
        assert_eq!(FS_NOCOW_FL, 0x0080_0000);
        assert_eq!(BTRFS_EXTENT_DATA_KEY, 108);
    }

    #[test]
    fn own_ioc_encoding_matches_nix_request_code_macros() {
        // The nix macros are what the generated ioctl functions use internally.
        assert_eq!(
            nix::request_code_write!(0x94, 9, size_of::<c_int>()) as u64,
            FICLONE_REQ as u64
        );
        assert_eq!(
            nix::request_code_read!(b'X', 31, size_of::<FsXattr>()) as u64,
            FS_IOC_FSGETXATTR_REQ as u64
        );
        assert_eq!(
            nix::request_code_readwrite!(b'f', 11, size_of::<FiemapHeader>()) as u64,
            FS_IOC_FIEMAP_REQ as u64
        );
        assert_eq!(
            nix::request_code_write!(0x94, 24, size_of::<BtrfsIoctlVolArgsV2>()) as u64,
            BTRFS_IOC_SUBVOL_CREATE_V2_REQ as u64
        );
        assert_eq!(
            nix::request_code_write!(0x94, 23, size_of::<BtrfsIoctlVolArgsV2>()) as u64,
            BTRFS_IOC_SNAP_CREATE_V2_REQ as u64
        );
        assert_eq!(
            nix::request_code_write!(0x94, 63, size_of::<BtrfsIoctlVolArgsV2>()) as u64,
            BTRFS_IOC_SNAP_DESTROY_V2_REQ as u64
        );
        assert_eq!(
            nix::request_code_write!(0x94, 15, size_of::<BtrfsIoctlVolArgs>()) as u64,
            BTRFS_IOC_SNAP_DESTROY_REQ as u64
        );
        assert_eq!(nix::request_code_none!(0x94, 8) as u64, BTRFS_IOC_SYNC_REQ as u64);
        assert_eq!(
            nix::request_code_read!(0x94, 31, size_of::<BtrfsIoctlFsInfoArgs>()) as u64,
            BTRFS_IOC_FS_INFO_REQ as u64
        );
        assert_eq!(
            nix::request_code_readwrite!(0x94, 17, size_of::<BtrfsIoctlSearchArgs>()) as u64,
            BTRFS_IOC_TREE_SEARCH_REQ as u64
        );
    }

    #[test]
    fn flags_payload_is_int_but_request_size_is_long() {
        assert_eq!(size_of::<c_int>(), 4);
        assert_eq!(size_of::<std::ffi::c_long>(), 8);
        // 0x0008 << 16 in the request word => embedded size 8
        assert_eq!((FS_IOC_GETFLAGS_REQ >> 16) & 0x3fff, 8);
        assert_eq!((FS_IOC_SETFLAGS_REQ >> 16) & 0x3fff, 8);
    }

    #[test]
    fn parse_search_items_walks_variable_length_payloads() {
        fn item(buf: &mut Vec<u8>, objectid: u64, offset: u64, ty: u32, payload: &[u8]) {
            buf.extend_from_slice(&1u64.to_ne_bytes());
            buf.extend_from_slice(&objectid.to_ne_bytes());
            buf.extend_from_slice(&offset.to_ne_bytes());
            buf.extend_from_slice(&ty.to_ne_bytes());
            buf.extend_from_slice(&(payload.len() as u32).to_ne_bytes());
            buf.extend_from_slice(payload);
        }
        let mut b = Vec::new();
        item(&mut b, 257, 0, 108, &[0u8; 53]);
        item(&mut b, 257, 4096, 108, &[0u8; 21]);
        item(&mut b, 257, 8192, 108, &[]);
        let items = parse_search_items(&b, 3);
        assert_eq!(items.len(), 3);
        assert_eq!(items[1].offset, 4096);
        assert_eq!(items[1].len, 21);
        assert_eq!(items[2].item_type, 108);
        // asking for more than present / truncated buffers never panics
        assert_eq!(parse_search_items(&b, 10).len(), 3);
        assert_eq!(parse_search_items(&b[..b.len() - 1], 3).len(), 2);
        assert!(parse_search_items(&[], 5).is_empty());
    }

    #[test]
    fn subvol_name_validation() {
        let mut buf = [0u8; 16];
        assert!(copy_name(&mut buf, "snap-0001").is_ok());
        assert_eq!(&buf[..10], b"snap-0001\0");
        assert!(copy_name(&mut buf, "").is_err());
        assert!(copy_name(&mut buf, "a/b").is_err());
        assert!(copy_name(&mut buf, "a\0b").is_err());
        assert!(copy_name(&mut buf, &"x".repeat(16)).is_err(), "must leave room for the NUL");
        assert!(copy_name(&mut buf, &"x".repeat(15)).is_ok());
    }

    #[test]
    fn ficlone_on_ordinary_fs_is_not_enotty() {
        // On non-reflink filesystems the kernel answers EOPNOTSUPP/EXDEV/EINVAL, never ENOTTY
        // (ENOTTY would mean our request code is wrong).
        let dir = std::env::temp_dir().join(format!("p0-ioctl-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("a"))
            .unwrap();
        let b = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join("b"))
            .unwrap();
        match ficlone(&b, &a) {
            Ok(()) => {} // reflink-capable tmp (btrfs/xfs): fine
            Err(e) => assert_ne!(e.raw_os_error(), Some(libc::ENOTTY), "bad FICLONE request code: {e}"),
        }
        if let Ok(f) = get_flags(&a) {
            assert_eq!(f & FS_NOCOW_FL, 0);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
