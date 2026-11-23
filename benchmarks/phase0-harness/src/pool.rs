//! `ScratchPool`: a loop-device backed Btrfs/XFS filesystem with hard safety rails.
//!
//! * refuses `/mnt/*` (WSL2 9p / DrvFs) and any 9p/drvfs-typed root;
//! * hard limit: pool size `<= min(max_pool_gib, 12)` GiB (never trust the 950G WSL virtual disk);
//! * `losetup --find --show --direct-io=on` (falls back to buffered loop and records it);
//! * `Drop` unmounts, detaches the loop device and deletes the image; [`cleanup`] is the
//!   belt-and-braces sweeper for crashed runs.

use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Serialize;

use crate::util::{is_root, run, run_any, MIB};

/// Absolute upper bound for any pool, regardless of CLI flags (AGENTS.md red line #1 / Phase 0 doc 1.1).
pub const HARD_MAX_POOL_GIB: u64 = 12;
/// Minimum size we accept (XFS needs >= 300 MiB).
pub const MIN_POOL_MIB: u64 = 512;

const V9FS_MAGIC: u64 = 0x0102_1997;

/// Filesystem under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FsKind {
    /// Btrfs (default mkfs options; qgroups disabled).
    Btrfs,
    /// XFS with `reflink=1`.
    Xfs,
}

impl FsKind {
    /// Name usable in `mount -t`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            FsKind::Btrfs => "btrfs",
            FsKind::Xfs => "xfs",
        }
    }
}

/// Reject roots that are on `/mnt/*` or on a 9p-style filesystem.
pub fn validate_root(root: &Path) -> Result<()> {
    ensure!(root.is_absolute(), "pool root must be absolute: {}", root.display());
    ensure!(
        !root.starts_with("/mnt"),
        "refusing pool root {} under /mnt (WSL2 9p/DrvFs): use a native Linux path such as /var/lib/forkloom/phase0",
        root.display()
    );
    std::fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
    let canon = root.canonicalize()?;
    ensure!(
        !canon.starts_with("/mnt"),
        "pool root {} resolves to {} under /mnt - refusing",
        root.display(),
        canon.display()
    );
    let st = nix::sys::statfs::statfs(&canon)?;
    let magic = st.filesystem_type().0 as u64 & 0xffff_ffff;
    ensure!(
        magic != V9FS_MAGIC,
        "pool root {} is on a 9p filesystem (f_type 0x{magic:x}) - refusing",
        canon.display()
    );
    Ok(())
}

/// A mounted scratch filesystem. Dropping it tears everything down.
#[derive(Debug)]
pub struct ScratchPool {
    kind: FsKind,
    img: PathBuf,
    mnt: PathBuf,
    loop_dev: Option<String>,
    mounted: bool,
    /// Whether `--direct-io=on` was accepted for the loop device.
    pub direct_io: bool,
    /// Pool size in MiB.
    pub size_mib: u64,
}

impl ScratchPool {
    /// Create image, loop device, filesystem and mount. Requires root.
    pub fn create(
        root: &Path,
        label: &str,
        kind: FsKind,
        size_mib: u64,
        max_pool_gib: u64,
    ) -> Result<Self> {
        ensure!(max_pool_gib >= 1, "max-pool-gib must be >= 1");
        let cap_gib = max_pool_gib.min(HARD_MAX_POOL_GIB);
        ensure!(
            size_mib <= cap_gib * 1024,
            "pool size {size_mib} MiB exceeds the hard limit of {cap_gib} GiB (--max-pool-gib, never > {HARD_MAX_POOL_GIB})"
        );
        ensure!(size_mib >= MIN_POOL_MIB, "pool size {size_mib} MiB < minimum {MIN_POOL_MIB} MiB");
        ensure!(is_root(), "ScratchPool needs root (losetup/mount): run via `sudo -E`");
        validate_root(root)?;

        let pid = std::process::id();
        let img = root.join(format!("{label}-{pid}.img"));
        let mnt = root.join(format!("mnt-{label}-{pid}"));
        let mut pool = Self {
            kind,
            img,
            mnt,
            loop_dev: None,
            mounted: false,
            direct_io: false,
            size_mib,
        };

        // sparse image (O_EXCL: never clobber)
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pool.img)
            .with_context(|| format!("create {}", pool.img.display()))?;
        f.set_len(size_mib * MIB)?;
        drop(f);

        let img_s = pool.img.to_str().ok_or_else(|| anyhow!("non-utf8 image path"))?.to_owned();
        let dev = match run("losetup", &["--find", "--show", "--direct-io=on", &img_s]) {
            Ok(o) => {
                pool.direct_io = true;
                String::from_utf8_lossy(&o.stdout).trim().to_owned()
            }
            Err(e) => {
                eprintln!("note: losetup --direct-io=on failed ({e:#}); falling back to buffered loop");
                let o = run("losetup", &["--find", "--show", &img_s])?;
                String::from_utf8_lossy(&o.stdout).trim().to_owned()
            }
        };
        ensure!(dev.starts_with("/dev/loop"), "unexpected losetup output {dev:?}");
        pool.loop_dev = Some(dev.clone());

        match kind {
            FsKind::Btrfs => {
                run("mkfs.btrfs", &["-f", "-q", &dev])?;
            }
            FsKind::Xfs => {
                run("mkfs.xfs", &["-f", "-q", "-m", "reflink=1", "-m", "crc=1", &dev])?;
            }
        }
        std::fs::create_dir_all(&pool.mnt)?;
        let mnt_s = pool.mnt.to_str().ok_or_else(|| anyhow!("non-utf8 mount path"))?.to_owned();
        run("mount", &["-t", kind.name(), "-o", "noatime", &dev, &mnt_s])?;
        pool.mounted = true;
        Ok(pool)
    }

    /// Mount point.
    #[must_use]
    pub fn mnt(&self) -> &Path {
        &self.mnt
    }

    /// Image path.
    #[must_use]
    pub fn img(&self) -> &Path {
        &self.img
    }

    /// Loop device.
    #[must_use]
    pub fn loop_dev(&self) -> Option<&str> {
        self.loop_dev.as_deref()
    }

    /// Filesystem kind.
    #[must_use]
    pub fn kind(&self) -> FsKind {
        self.kind
    }

    /// Explicit teardown (also run by `Drop`; idempotent).
    pub fn teardown(&mut self) -> Result<()> {
        let mut problems: Vec<String> = Vec::new();
        if self.mounted {
            let mnt = self.mnt.to_string_lossy().into_owned();
            let mut ok = false;
            for _ in 0..10 {
                if run_any("umount", &[&mnt]).is_ok_and(|o| o.status.success()) {
                    ok = true;
                    break;
                }
                sleep(Duration::from_millis(300));
            }
            if !ok {
                // lazy detach as a last resort so the loop device can still be released
                let _ = run_any("umount", &["-l", &mnt]);
                problems.push(format!("umount {mnt} needed -l fallback"));
            }
            self.mounted = false;
        }
        if let Some(dev) = self.loop_dev.take() {
            let mut ok = false;
            for _ in 0..10 {
                if run_any("losetup", &["-d", &dev]).is_ok_and(|o| o.status.success()) {
                    ok = true;
                    break;
                }
                sleep(Duration::from_millis(300));
            }
            if !ok {
                problems.push(format!("losetup -d {dev} failed"));
            }
        }
        if self.img.exists() {
            if let Err(e) = std::fs::remove_file(&self.img) {
                problems.push(format!("remove {}: {e}", self.img.display()));
            }
        }
        if self.mnt.exists() {
            if let Err(e) = std::fs::remove_dir(&self.mnt) {
                problems.push(format!("rmdir {}: {e}", self.mnt.display()));
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            bail!("pool teardown problems: {}", problems.join("; "))
        }
    }
}

impl Drop for ScratchPool {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            eprintln!("warning: {e:#} (run `phase0-harness cleanup`)");
        }
    }
}

/// What [`cleanup`] found and did.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CleanupReport {
    /// Mount points unmounted.
    pub unmounted: Vec<String>,
    /// Loop devices detached.
    pub loops_detached: Vec<String>,
    /// Files removed (images, host-side meta dirs).
    pub removed: Vec<String>,
    /// Mounts still present under the root afterwards (must be empty).
    pub residual_mounts: Vec<String>,
    /// Loop devices still backed by files under the root (must be empty).
    pub residual_loops: Vec<String>,
    /// `*.img` files still present under the root (must be empty).
    pub residual_images: Vec<String>,
    /// Bytes of `*.img` left (must be 0).
    pub residual_image_bytes: u64,
}

impl CleanupReport {
    /// `true` when nothing is left behind.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.residual_mounts.is_empty()
            && self.residual_loops.is_empty()
            && self.residual_images.is_empty()
    }
}

fn mounts_under(root: &Path) -> Vec<String> {
    let text = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mut v: Vec<String> = text
        .lines()
        .filter_map(|l| l.split(' ').nth(4))
        .map(|s| s.replace("\\040", " "))
        .filter(|mp| Path::new(mp).starts_with(root) && Path::new(mp) != root)
        .collect();
    v.sort_by_key(|m| std::cmp::Reverse(m.len()));
    v
}

fn loops_under(root: &Path) -> Vec<(String, String)> {
    let out = match run_any("losetup", &["-a"]) {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return vec![],
    };
    out.lines()
        .filter_map(|l| {
            let dev = l.split(':').next()?.to_owned();
            let start = l.find(" (")? + 2;
            let mut back = l[start..].trim_end_matches(')').to_owned();
            if let Some(i) = back.rfind(" (deleted") {
                back.truncate(i);
            }
            Path::new(&back).starts_with(root).then_some((dev, back))
        })
        .collect()
}

fn images_under(root: &Path) -> Vec<(PathBuf, u64)> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "img") {
                // allocated bytes, not apparent size (images are sparse)
                let len = e.metadata().map(|m| m.blocks() * 512).unwrap_or(0);
                v.push((p, len));
            }
        }
    }
    v
}

/// Unmount everything under `root`, detach its loop devices, delete leftover images and scratch
/// directories, and report what is still left (should be nothing).
pub fn cleanup(root: &Path) -> Result<CleanupReport> {
    ensure!(!root.starts_with("/mnt"), "refusing to clean under /mnt");
    let mut rep = CleanupReport::default();
    if !root.exists() {
        return Ok(rep);
    }
    for mp in mounts_under(root) {
        if run_any("umount", &[&mp]).is_ok_and(|o| o.status.success()) {
            rep.unmounted.push(mp);
        } else if run_any("umount", &["-l", &mp]).is_ok_and(|o| o.status.success()) {
            rep.unmounted.push(format!("{mp} (lazy)"));
        }
    }
    for (dev, _) in loops_under(root) {
        if run_any("losetup", &["-d", &dev]).is_ok_and(|o| o.status.success()) {
            rep.loops_detached.push(dev);
        }
    }
    let still_mounted = !mounts_under(root).is_empty();
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let is_img = p.extension().is_some_and(|x| x == "img");
            let is_mnt_dir = name.starts_with("mnt-") && p.is_dir();
            let is_scratch_dir = (name.starts_with("hostmeta-") || name.starts_with("scratch-")) && p.is_dir();
            if is_img && std::fs::remove_file(&p).is_ok() {
                rep.removed.push(p.display().to_string());
            } else if is_mnt_dir && std::fs::remove_dir(&p).is_ok() {
                rep.removed.push(p.display().to_string());
            } else if is_scratch_dir && !still_mounted && std::fs::remove_dir_all(&p).is_ok() {
                rep.removed.push(p.display().to_string());
            }
        }
    }
    rep.residual_mounts = mounts_under(root);
    rep.residual_loops = loops_under(root).into_iter().map(|(d, b)| format!("{d} -> {b}")).collect();
    for (p, bytes) in images_under(root) {
        rep.residual_image_bytes += bytes;
        rep.residual_images.push(p.display().to_string());
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mnt_roots() {
        for p in ["/mnt/c/work", "/mnt/wsl/x", "/mnt"] {
            let e = validate_root(Path::new(p)).unwrap_err().to_string();
            assert!(e.contains("/mnt"), "{e}");
        }
        assert!(validate_root(Path::new("relative/path")).is_err());
        assert!(cleanup(Path::new("/mnt/c/anything")).is_err());
    }

    #[test]
    fn hard_limit_is_enforced_before_any_side_effect() {
        let root = std::env::temp_dir().join("p0-pool-limit-test-never-created");
        for gib in [13u64, 16, 950] {
            let e = ScratchPool::create(&root, "t", FsKind::Btrfs, gib * 1024, 64).unwrap_err().to_string();
            assert!(e.contains("hard limit"), "{e}");
        }
        let e = ScratchPool::create(&root, "t", FsKind::Btrfs, 5 * 1024, 4).unwrap_err().to_string();
        assert!(e.contains("hard limit"), "{e}");
        let e = ScratchPool::create(&root, "t", FsKind::Btrfs, 100, 4).unwrap_err().to_string();
        assert!(e.contains("minimum"), "{e}");
        assert!(!root.exists(), "nothing may be created when limits are violated");
    }

    #[test]
    fn mountinfo_parsing_only_matches_children_of_root() {
        // never reports the root itself nor unrelated paths
        let m = mounts_under(Path::new("/definitely/not/a/mount/root"));
        assert!(m.is_empty());
    }

    #[test]
    fn cleanup_report_clean_flag() {
        let mut r = CleanupReport::default();
        assert!(r.is_clean());
        r.residual_images.push("x.img".into());
        assert!(!r.is_clean());
    }
}
