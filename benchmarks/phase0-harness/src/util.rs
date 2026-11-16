//! Misc helpers: command execution, PRNG, time formatting, filesystem probes.

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// Deterministic SplitMix64 PRNG (workload shaping only; **not** cryptographic).
#[derive(Debug, Clone)]
pub struct SplitMix64(u64);

impl SplitMix64 {
    /// Seeded generator.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish value in `0..n` (`n > 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        assert!(n > 0);
        self.next_u64() % n
    }

    /// Fill `buf` with pseudo-random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let b = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

/// One MiB in bytes.
pub const MIB: u64 = 1024 * 1024;
/// One GiB in bytes.
pub const GIB: u64 = 1024 * MIB;

/// Run a command; fail with stderr on non-zero exit.
pub fn run(cmd: &str, args: &[&str]) -> Result<Output> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn `{cmd} {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`{cmd} {}` exited with {}: {}{}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
    Ok(out)
}

/// Run a command and return trimmed stdout.
pub fn run_stdout(cmd: &str, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8_lossy(&run(cmd, args)?.stdout).trim().to_owned())
}

/// Run a command and return its output regardless of exit status.
pub fn run_any(cmd: &str, args: &[&str]) -> Result<Output> {
    Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn `{cmd} {}`", args.join(" ")))
}

/// Best-effort first line of `cmd args` (stdout, falling back to stderr), or `"unavailable"`.
#[must_use]
pub fn tool_version(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(o) => {
            let s = if o.stdout.is_empty() { &o.stderr } else { &o.stdout };
            String::from_utf8_lossy(s).lines().next().unwrap_or("").trim().to_owned()
        }
        Err(_) => "unavailable".to_owned(),
    }
}

/// Time a closure.
pub fn timed<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let t0 = Instant::now();
    let v = f();
    (v, t0.elapsed())
}

/// `true` when running as euid 0.
#[must_use]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// `sync(2)` then drop clean page cache, dentries and inodes (needs root).
pub fn drop_caches() -> Result<()> {
    nix::unistd::sync();
    std::fs::write("/proc/sys/vm/drop_caches", b"3\n").context("write /proc/sys/vm/drop_caches")
}

/// Bytes available to unprivileged users on the filesystem holding `path`.
pub fn avail_bytes(path: &Path) -> Result<u64> {
    let s = nix::sys::statvfs::statvfs(path).with_context(|| format!("statvfs {}", path.display()))?;
    Ok(s.blocks_available() as u64 * s.fragment_size() as u64)
}

/// Total bytes of the filesystem holding `path`.
pub fn total_bytes(path: &Path) -> Result<u64> {
    let s = nix::sys::statvfs::statvfs(path).with_context(|| format!("statvfs {}", path.display()))?;
    Ok(s.blocks() as u64 * s.fragment_size() as u64)
}

/// `Dirty:` value of `/proc/meminfo` in KiB (0 if unreadable).
#[must_use]
pub fn dirty_kib() -> u64 {
    meminfo_kib("Dirty:")
}

/// Look up a `/proc/meminfo` key (including the colon) in KiB (0 if absent).
#[must_use]
pub fn meminfo_kib(key: &str) -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix(key)
                    .and_then(|r| r.trim().trim_end_matches("kB").trim().parse().ok())
            })
        })
        .unwrap_or(0)
}

/// Current wall clock as Unix seconds.
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
#[must_use]
pub fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Format `ms` with sensible precision.
#[must_use]
pub fn fmt_ms(us: f64) -> String {
    let ms = us / 1e3;
    if ms >= 100.0 {
        format!("{ms:.0}")
    } else if ms >= 10.0 {
        format!("{ms:.1}")
    } else {
        format!("{ms:.3}")
    }
}

/// `true` when `err` (or any source) is `ENOSPC`.
#[must_use]
pub fn is_enospc(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::ENOSPC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_known_values() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn prng_is_deterministic_and_shuffle_is_permutation() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut v: Vec<u32> = (0..1000).collect();
        a.shuffle(&mut v);
        let mut s = v.clone();
        s.sort_unstable();
        assert_eq!(s, (0..1000).collect::<Vec<_>>());
        assert_ne!(v, s);
        let mut buf = [0u8; 13];
        a.fill(&mut buf);
        assert!(buf.iter().any(|&x| x != 0));
    }

    #[test]
    fn enospc_detection() {
        assert!(is_enospc(&std::io::Error::from_raw_os_error(libc::ENOSPC)));
        assert!(!is_enospc(&std::io::Error::from_raw_os_error(libc::EIO)));
    }
}
