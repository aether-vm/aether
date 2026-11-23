//! F0-5: Firecracker end-to-end snapshot restore -> first `vsock` command latency.
//!
//! Per `docs/PHASE0_FALSIFICATION.md` (F0-5) and Iron Law 2:
//! * Lock VM memory size (e.g. 512 MiB / 2048 MiB) and measure **total** latency from issuing
//!   `PUT /snapshot/load` (and including `posix_fadvise(WILLNEED)` prewarm for the prefetch tier)
//!   until the guest `aos-guest` agent returns a real framed v1 `Pong` (and optional `ExecResult`)
//!   over `virtio-vsock` (NEVER substitute pure VMM API return time for guest-available latency).
//! * Measure strictly across three page-cache tiers:
//!   1. `cold_cache`: `drop_caches` (`sync` + `3 > /proc/sys/vm/drop_caches`) before restore.
//!   2. `hot_cache`: host page cache fully warm before restore.
//!   3. `mincore_willneed`: `drop_caches`, spawn VMM, then issue `posix_fadvise(WILLNEED)` over
//!      the coalesced working-set extents captured from a cold-cache `mincore(2)` probe, and
//!      report BOTH `vsock_ready_us` (restore-only) AND `total_with_prewarm_us = fadvise + restore`
//!      (used as the honest headline speedup numerator/denominator).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::report::{dist_row, ExpOutput, DIST_HEADER};
use crate::stats::Dist;

/// CLI / runner parameters for F0-5.
#[derive(Debug, Clone)]
pub struct Args {
    /// Path to `firecracker` binary (v1.10+ / v1.11+).
    pub firecracker_bin: PathBuf,
    /// Path to the `vmstate` snapshot file.
    pub snapshot_path: PathBuf,
    /// Path to the guest memory snapshot file.
    pub mem_file_path: PathBuf,
    /// Relative or absolute path to Firecracker's host `virtio-vsock` UDS (e.g. `./v.sock`).
    pub vsock_uds: PathBuf,
    /// Guest `AF_VSOCK` port where `aos-guest` listens.
    pub vsock_port: u32,
    /// Optional command argv executed via `aos-guest` v1 `Exec` right after `Ping` (empty = `Ping` only).
    pub probe_argv: Vec<String>,
    /// Declared VM memory size in MiB (512 or 2048 per F0-5 spec).
    pub vm_mem_mib: u64,
    /// Repetitions per cache tier.
    pub reps: usize,
    /// Optional pre-recorded `mincore` working-set profile JSON (if omitted, sampled after `drop_caches`).
    pub mincore_profile: Option<PathBuf>,
    /// Per-restore vsock readiness timeout in milliseconds.
    pub vsock_timeout_ms: u64,
}

/// Page-cache precondition tier for F0-5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTier {
    /// `drop_caches` before restore (measures full page-fault storm penalty).
    ColdCache,
    /// Host page cache fully populated before restore.
    HotCache,
    /// `drop_caches` followed by `posix_fadvise(WILLNEED)` over the `mincore` working set.
    MincoreWillneed,
}

impl CacheTier {
    /// Human-readable label for tables.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ColdCache => "cold_cache (drop_caches)",
            Self::HotCache => "hot_cache (warm page cache)",
            Self::MincoreWillneed => "mincore + fadvise(WILLNEED)",
        }
    }
}

/// A contiguous resident byte extent inside a guest memory snapshot file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkingSetExtent {
    /// Byte offset from the start of the memory file (page-aligned).
    pub offset: u64,
    /// Length in bytes (multiple of `page_size`).
    pub len: u64,
}

/// Captured `mincore(2)` working-set bitmap compressed into contiguous byte extents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MincoreProfile {
    /// Host page size in bytes (typically 4096).
    pub page_size: u64,
    /// Total file size in bytes.
    pub file_bytes: u64,
    /// Total number of pages in the file.
    pub total_pages: usize,
    /// Resident page count (bit 0 set in `mincore` vector).
    pub resident_pages: usize,
    /// Fraction of pages resident (`0.0..=1.0`).
    pub resident_ratio: f64,
    /// Coalesced resident byte extents to feed to `posix_fadvise(POSIX_FADV_WILLNEED)`.
    pub extents: Vec<WorkingSetExtent>,
}

impl MincoreProfile {
    /// Build a coalesced extent profile from raw `mincore(2)` output bytes (bit 0 == resident).
    #[must_use]
    pub fn from_vec(vec: &[u8], page_size: u64, file_bytes: u64) -> Self {
        let mut extents = Vec::new();
        let mut resident_pages = 0usize;
        let mut run_start: Option<usize> = None;

        for (idx, &byte) in vec.iter().enumerate() {
            let resident = (byte & 1) != 0;
            if resident {
                resident_pages += 1;
                if run_start.is_none() {
                    run_start = Some(idx);
                }
            } else if let Some(start) = run_start.take() {
                let offset = start as u64 * page_size;
                let end = (idx as u64 * page_size).min(file_bytes);
                if end > offset {
                    extents.push(WorkingSetExtent {
                        offset,
                        len: end - offset,
                    });
                }
            }
        }
        if let Some(start) = run_start {
            let offset = start as u64 * page_size;
            let end = (vec.len() as u64 * page_size).min(file_bytes);
            if end > offset {
                extents.push(WorkingSetExtent {
                    offset,
                    len: end - offset,
                });
            }
        }

        let total_pages = vec.len();
        #[allow(clippy::cast_precision_loss)]
        let resident_ratio = if total_pages == 0 {
            0.0
        } else {
            resident_pages as f64 / total_pages as f64
        };
        Self {
            page_size,
            file_bytes,
            total_pages,
            resident_pages,
            resident_ratio,
            extents,
        }
    }

    /// Total resident bytes represented by all extents.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        self.extents.iter().map(|e| e.len).sum()
    }
}

/// One restore-to-first-vsock-command trial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreSample {
    /// Cache tier.
    pub tier: CacheTier,
    /// Iteration index within the tier.
    pub rep: usize,
    /// `posix_fadvise(WILLNEED)` duration in microseconds (0 for cold/hot).
    pub fadvise_prewarm_us: f64,
    /// `PUT /snapshot/load` API completion latency in microseconds (VMM only — NOT readiness).
    pub api_load_us: f64,
    /// Latency from `PUT /snapshot/load` start to first `aos-guest` framed reply in microseconds.
    pub vsock_ready_us: f64,
    /// Honest total latency including prewarm: `fadvise_prewarm_us + vsock_ready_us`.
    pub total_with_prewarm_us: f64,
    /// Summary of verified `aos-guest` reply (e.g. `pong(pid=1,epoch=2)`).
    pub guest_reply: String,
}

/// Aggregated statistics for one cache tier.
#[derive(Debug, Clone, Serialize)]
pub struct TierSummary {
    /// Cache tier.
    pub tier: CacheTier,
    /// `fadvise(WILLNEED)` prewarm latency distribution (us).
    pub fadvise_prewarm: Dist,
    /// VMM `PUT /snapshot/load` latency distribution (us).
    pub api_load: Dist,
    /// Post-prewarm restore -> first `vsock` reply latency distribution (us).
    pub vsock_ready: Dist,
    /// Honest total cold-start latency including `fadvise(WILLNEED)` prewarm (us).
    pub total_with_prewarm: Dist,
}

/// Complete F0-5 report payload.
#[derive(Debug, Clone, Serialize)]
pub struct F05Report {
    /// Declared VM memory size in MiB.
    pub vm_mem_mib: u64,
    /// Repetitions per tier.
    pub reps: usize,
    /// Working-set profile used for `MincoreWillneed`.
    pub mincore_profile: MincoreProfile,
    /// Tier-by-tier latency summaries.
    pub tiers: Vec<TierSummary>,
    /// `cold_cache.total_with_prewarm.p50 / hot_cache.total_with_prewarm.p50`.
    pub page_fault_penalty_ratio: Option<f64>,
    /// Honest speedup including prewarm cost: `cold.total_with_prewarm.p50 / willneed.total_with_prewarm.p50`.
    pub willneed_speedup_ratio: Option<f64>,
    /// Restore-only speedup (excluding prewarm, for transparency): `cold.vsock_ready.p50 / willneed.vsock_ready.p50`.
    pub willneed_restore_only_speedup_ratio: Option<f64>,
    /// Raw per-trial samples.
    pub samples: Vec<RestoreSample>,
}

/// Aggregate samples and render standard JSON + Markdown `ExpOutput` for F0-5.
#[must_use]
pub fn build_report(
    vm_mem_mib: u64,
    reps: usize,
    mincore_profile: MincoreProfile,
    samples: Vec<RestoreSample>,
) -> ExpOutput {
    let mut tiers = Vec::new();
    for tier in [
        CacheTier::ColdCache,
        CacheTier::HotCache,
        CacheTier::MincoreWillneed,
    ] {
        let matching: Vec<&RestoreSample> = samples.iter().filter(|s| s.tier == tier).collect();
        if matching.is_empty() {
            continue;
        }
        let fadvise_prewarm = Dist::from_us(matching.iter().map(|s| s.fadvise_prewarm_us).collect());
        let api_load = Dist::from_us(matching.iter().map(|s| s.api_load_us).collect());
        let vsock_ready = Dist::from_us(matching.iter().map(|s| s.vsock_ready_us).collect());
        let total_with_prewarm =
            Dist::from_us(matching.iter().map(|s| s.total_with_prewarm_us).collect());
        tiers.push(TierSummary {
            tier,
            fadvise_prewarm,
            api_load,
            vsock_ready,
            total_with_prewarm,
        });
    }

    let total_p50 = |t: CacheTier| -> Option<f64> {
        tiers
            .iter()
            .find(|s| s.tier == t && s.total_with_prewarm.n > 0)
            .map(|s| s.total_with_prewarm.p50_us)
    };
    let restore_p50 = |t: CacheTier| -> Option<f64> {
        tiers
            .iter()
            .find(|s| s.tier == t && s.vsock_ready.n > 0)
            .map(|s| s.vsock_ready.p50_us)
    };

    let page_fault_penalty_ratio = match (total_p50(CacheTier::ColdCache), total_p50(CacheTier::HotCache)) {
        (Some(c), Some(h)) if h > 0.0 => Some(c / h),
        _ => None,
    };
    let willneed_speedup_ratio = match (
        total_p50(CacheTier::ColdCache),
        total_p50(CacheTier::MincoreWillneed),
    ) {
        (Some(c), Some(w)) if w > 0.0 => Some(c / w),
        _ => None,
    };
    let willneed_restore_only_speedup_ratio = match (
        restore_p50(CacheTier::ColdCache),
        restore_p50(CacheTier::MincoreWillneed),
    ) {
        (Some(c), Some(w)) if w > 0.0 => Some(c / w),
        _ => None,
    };

    let report = F05Report {
        vm_mem_mib,
        reps,
        mincore_profile,
        tiers,
        page_fault_penalty_ratio,
        willneed_speedup_ratio,
        willneed_restore_only_speedup_ratio,
        samples,
    };

    let mut md = String::new();
    md.push_str("## F0-5: Firecracker Restore -> First `aos-guest` vsock Command Latency\n\n");
    md.push_str(&format!(
        "- VM memory: **{} MiB**, repetitions/tier: **{}**\n",
        report.vm_mem_mib, report.reps
    ));
    md.push_str(&format!(
        "- Cold-restore `mincore` working set: **{} / {}** pages ({:.1}%, {} extents, {:.2} MiB)\n",
        report.mincore_profile.resident_pages,
        report.mincore_profile.total_pages,
        report.mincore_profile.resident_ratio * 100.0,
        report.mincore_profile.extents.len(),
        report.mincore_profile.resident_bytes() as f64 / (1024.0 * 1024.0),
    ));
    if let Some(r) = report.page_fault_penalty_ratio {
        md.push_str(&format!("- Cold vs Hot page-fault penalty (p50): **{r:.2}x**\n"));
    }
    if let Some(r) = report.willneed_speedup_ratio {
        md.push_str(&format!(
            "- `mincore + fadvise(WILLNEED)` honest total speedup including prewarm (p50): **{r:.2}x**\n"
        ));
    }
    if let Some(r) = report.willneed_restore_only_speedup_ratio {
        md.push_str(&format!(
            "- `mincore + fadvise(WILLNEED)` restore-only speedup excluding prewarm (p50): **{r:.2}x**\n"
        ));
    }
    md.push_str("\n### Honest Total Cold-to-Ready Latency (`fadvise_prewarm + restore -> first vsock reply`)\n\n");
    md.push_str(DIST_HEADER);
    for t in &report.tiers {
        md.push_str(&dist_row(t.tier.label(), &t.total_with_prewarm));
    }
    md.push_str("\n### Post-Prewarm Restore -> First vsock Reply Latency (`PUT /snapshot/load -> reply`)\n\n");
    md.push_str(DIST_HEADER);
    for t in &report.tiers {
        md.push_str(&dist_row(t.tier.label(), &t.vsock_ready));
    }
    md.push_str("\n### VMM `PUT /snapshot/load` API Return Time (NOT guest readiness)\n\n");
    md.push_str(DIST_HEADER);
    for t in &report.tiers {
        md.push_str(&dist_row(t.tier.label(), &t.api_load));
    }
    md.push('\n');

    ExpOutput {
        id: "F0-5",
        slug: "f0-5-fc-restore",
        json: json!(report),
        md,
    }
}

/// Execute F0-5 against a real Firecracker v1.10/v1.11 binary, `aos-guest` framed v1 protocol,
/// and KVM host (Linux only).
#[cfg(target_os = "linux")]
pub fn run(ctx: &crate::Ctx, args: &Args) -> anyhow::Result<ExpOutput> {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use anyhow::{ensure, Context};

    use crate::firecracker::linux::{vsock_exchange_framed, FcClient, FcProcess};
    use crate::firecracker::{
        guest_exec_request, guest_ping_request, parse_guest_exec_result, parse_guest_pong,
        SnapshotLoadParams,
    };
    use crate::util::drop_caches;

    ensure!(
        Path::new("/dev/kvm").exists(),
        "F0-5 requires /dev/kvm on a Linux KVM host"
    );
    ensure!(
        args.snapshot_path.exists(),
        "snapshot_path does not exist: {}",
        args.snapshot_path.display()
    );
    ensure!(
        args.mem_file_path.exists(),
        "mem_file_path does not exist: {}",
        args.mem_file_path.display()
    );
    ensure!(args.reps >= 1, "--reps must be >= 1");

    let work_root = ctx.root.join("f0-5");
    std::fs::create_dir_all(&work_root)?;

    // Acquire or capture cold-restore mincore working-set profile.
    // MUST drop_caches() BEFORE profile-probe so mincore captures ONLY pages faulted by restore,
    // never a pre-warmed ~100% file (Iron Law 2).
    let profile = if let Some(p) = &args.mincore_profile {
        let raw = std::fs::read_to_string(p)
            .with_context(|| format!("read mincore profile {}", p.display()))?;
        serde_json::from_str::<MincoreProfile>(&raw)?
    } else {
        drop_caches()?;
        let probe_dir = work_root.join("profile-probe");
        let _ = run_single_restore(args, &probe_dir, CacheTier::ColdCache, 0, None)?;
        let prof = capture_mincore(&args.mem_file_path)?;
        let _ = std::fs::remove_dir_all(&probe_dir);
        prof
    };

    let mut samples = Vec::with_capacity(args.reps * 3);
    for tier in [
        CacheTier::ColdCache,
        CacheTier::HotCache,
        CacheTier::MincoreWillneed,
    ] {
        for rep in 0..args.reps {
            let prewarm_profile = match tier {
                CacheTier::ColdCache => {
                    drop_caches()?;
                    None
                }
                CacheTier::HotCache => {
                    warm_file_sequential(&args.mem_file_path)?;
                    None
                }
                CacheTier::MincoreWillneed => {
                    drop_caches()?;
                    Some(&profile)
                }
            };
            let iter_dir = work_root.join(format!("{:?}-r{rep}", tier));
            let sample = run_single_restore(args, &iter_dir, tier, rep, prewarm_profile)?;
            samples.push(sample);
            let _ = std::fs::remove_dir_all(&iter_dir);
        }
    }

    return Ok(build_report(args.vm_mem_mib, args.reps, profile, samples));

    fn warm_file_sequential(path: &Path) -> anyhow::Result<()> {
        let mut f = File::open(path)?;
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        while f.read(&mut buf)? > 0 {}
        Ok(())
    }

    fn capture_mincore(path: &Path) -> anyhow::Result<MincoreProfile> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let file_bytes = file.metadata()?.len();
        ensure!(file_bytes > 0, "memory snapshot file is empty");
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        ensure!(page_size > 0, "invalid sysconf(_SC_PAGESIZE)");
        let total_pages = file_bytes.div_ceil(page_size) as usize;
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                file_bytes as usize,
                libc::PROT_READ,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(
            ptr != libc::MAP_FAILED,
            "mmap failed for mincore: {}",
            std::io::Error::last_os_error()
        );
        let mut vec = vec![0u8; total_pages];
        let rc = unsafe { libc::mincore(ptr, file_bytes as usize, vec.as_mut_ptr()) };
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::munmap(ptr, file_bytes as usize);
        }
        ensure!(rc == 0, "mincore(2) failed: {err}");
        Ok(MincoreProfile::from_vec(&vec, page_size, file_bytes))
    }

    fn apply_fadvise_willneed(path: &Path, profile: &MincoreProfile) -> anyhow::Result<()> {
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let fd = file.as_raw_fd();
        for ext in &profile.extents {
            let rc = unsafe {
                libc::posix_fadvise(
                    fd,
                    ext.offset as libc::off_t,
                    ext.len as libc::off_t,
                    libc::POSIX_FADV_WILLNEED,
                )
            };
            ensure!(
                rc == 0,
                "posix_fadvise(WILLNEED, offset={}, len={}) failed: {}",
                ext.offset,
                ext.len,
                std::io::Error::from_raw_os_error(rc)
            );
        }
        Ok(())
    }

    fn run_single_restore(
        args: &Args,
        iter_dir: &Path,
        tier: CacheTier,
        rep: usize,
        prewarm_profile: Option<&MincoreProfile>,
    ) -> anyhow::Result<RestoreSample> {
        let _ = std::fs::remove_dir_all(iter_dir);
        std::fs::create_dir_all(iter_dir)?;
        let api_sock = iter_dir.join("fc.api.sock");
        let _fc = FcProcess::spawn(
            &args.firecracker_bin,
            &api_sock,
            iter_dir,
            Duration::from_secs(5),
        )?;
        let client = FcClient::new(&api_sock);
        let load_params = SnapshotLoadParams::file_backend(
            &args.snapshot_path,
            &args.mem_file_path,
            false,
            true,
        );
        let vsock_path = if args.vsock_uds.is_absolute() {
            args.vsock_uds.clone()
        } else {
            iter_dir.join(&args.vsock_uds)
        };

        // Run WILLNEED AFTER FcProcess::spawn so it gets no hidden I/O head-start during VMM boot.
        let t_total_start = Instant::now();
        let fadvise_prewarm_us = if let Some(prof) = prewarm_profile {
            let t_pf = Instant::now();
            apply_fadvise_willneed(&args.mem_file_path, prof)?;
            t_pf.elapsed().as_secs_f64() * 1e6
        } else {
            0.0
        };

        let t_load_start = Instant::now();
        client.load_snapshot(&load_params)?;
        let api_load_us = t_load_start.elapsed().as_secs_f64() * 1e6;

        let req_id = (rep as u64) + 1;
        let nonce = 0xF005_0000 + req_id;
        let ping_req = guest_ping_request(req_id, nonce)?;
        let (pong_bytes, _host_port) = vsock_exchange_framed(
            &vsock_path,
            args.vsock_port,
            &ping_req,
            Duration::from_millis(args.vsock_timeout_ms),
        )?;
        let pong = parse_guest_pong(&pong_bytes, req_id, nonce)?;

        let guest_reply = if args.probe_argv.is_empty() {
            format!(
                "pong(pid={},epoch={},state={})",
                pong.pid, pong.epoch_generation, pong.state_json
            )
        } else {
            let exec_req_id = req_id + 10_000;
            let exec_req = guest_exec_request(
                exec_req_id,
                &format!("f05-probe-{rep}"),
                &args.probe_argv,
                args.vsock_timeout_ms,
            )?;
            let (exec_bytes, _) = vsock_exchange_framed(
                &vsock_path,
                args.vsock_port,
                &exec_req,
                Duration::from_millis(args.vsock_timeout_ms),
            )?;
            let exec_res = parse_guest_exec_result(&exec_bytes, exec_req_id)?;
            ensure!(
                exec_res.exit_code == Some(0),
                "F0-5 guest probe command exited with {:?}: {}",
                exec_res.exit_code,
                String::from_utf8_lossy(&exec_res.stderr)
            );
            format!(
                "exec(exit=0,stdout={:?})",
                String::from_utf8_lossy(&exec_res.stdout).trim()
            )
        };

        let vsock_ready_us = t_load_start.elapsed().as_secs_f64() * 1e6;
        let total_with_prewarm_us = t_total_start.elapsed().as_secs_f64() * 1e6;

        Ok(RestoreSample {
            tier,
            rep,
            fadvise_prewarm_us,
            api_load_us,
            vsock_ready_us,
            total_with_prewarm_us,
            guest_reply,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mincore_coalesces_contiguous_resident_extents() {
        let raw = vec![1u8, 3, 0, 1, 2, 1, 1, 1];
        let profile = MincoreProfile::from_vec(&raw, 4096, 30_000);
        assert_eq!(profile.total_pages, 8);
        assert_eq!(profile.resident_pages, 6);
        assert_eq!(
            profile.extents,
            vec![
                WorkingSetExtent { offset: 0, len: 8192 },
                WorkingSetExtent { offset: 12_288, len: 4096 },
                WorkingSetExtent { offset: 20_480, len: 30_000 - 20_480 },
            ]
        );
        assert_eq!(profile.resident_bytes(), 8192 + 4096 + (30_000 - 20_480));
        assert!((profile.resident_ratio - 0.75).abs() < 1e-9);
    }

    #[test]
    fn f0_5_report_includes_prewarm_in_honest_willneed_speedup() {
        let profile = MincoreProfile::from_vec(&[1, 1, 0, 0], 4096, 16_384);
        let samples = vec![
            RestoreSample {
                tier: CacheTier::ColdCache,
                rep: 0,
                fadvise_prewarm_us: 0.0,
                api_load_us: 3_000.0,
                vsock_ready_us: 120_000.0,
                total_with_prewarm_us: 120_000.0,
                guest_reply: "pong(pid=1)".into(),
            },
            RestoreSample {
                tier: CacheTier::HotCache,
                rep: 0,
                fadvise_prewarm_us: 0.0,
                api_load_us: 2_500.0,
                vsock_ready_us: 12_000.0,
                total_with_prewarm_us: 12_000.0,
                guest_reply: "pong(pid=1)".into(),
            },
            RestoreSample {
                tier: CacheTier::MincoreWillneed,
                rep: 0,
                fadvise_prewarm_us: 16_000.0,
                api_load_us: 2_600.0,
                vsock_ready_us: 24_000.0,
                total_with_prewarm_us: 40_000.0,
                guest_reply: "pong(pid=1)".into(),
            },
        ];
        let out = build_report(512, 1, profile, samples);
        assert_eq!(out.id, "F0-5");
        assert_eq!(out.slug, "f0-5-fc-restore");
        // Cold/Hot = 120/12 = 10x; honest WILLNEED = 120/40 = 3x; restore-only = 120/24 = 5x.
        assert!((out.json["page_fault_penalty_ratio"].as_f64().unwrap() - 10.0).abs() < 1e-9);
        assert!((out.json["willneed_speedup_ratio"].as_f64().unwrap() - 3.0).abs() < 1e-9);
        assert!(
            (out.json["willneed_restore_only_speedup_ratio"]
                .as_f64()
                .unwrap()
                - 5.0)
                .abs()
                < 1e-9
        );
        assert!(out.md.contains("Honest Total Cold-to-Ready Latency"));
    }
}
