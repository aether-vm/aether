//! F0-6: Memory snapshot capture time (`Durable` pool vs quota `tmpfs`) & `MAP_PRIVATE` physical
//! memory sharing (`PSS` vs `Private_Dirty` from `/proc/<pid>/smaps_rollup`).
//!
//! Per `docs/PHASE0_FALSIFICATION.md` (F0-6):
//! 1. Measure snapshot capture write latency for 512 MiB / 2 GiB VMs onto disk pool (`Durable`,
//!    with `fsync`) vs quota-limited `tmpfs` (`Volatile`), using a dedicated volatile capture
//!    `tmpfs` sized `volatile_tmpfs_mib` (default `vm_mem_mib + 128`) and an independent quota
//!    overrun `tmpfs` (`tmpfs_quota_mib`) verifying graceful `ENOSPC` and zero host OOM kills
//!    (`/proc/vmstat` `oom_kill` delta == 0). All `tmpfs` mounts use an RAII `Drop` guard.
//! 2. Restore `N` clones (4-8 on WSL2, 16 on bare metal) from the same snapshot via Firecracker
//!    `File` backend (`MAP_PRIVATE`), verify `aos-guest` framed v1 `Ping` when `vsock_uds` is set,
//!    and parse `/proc/<pid>/smaps_rollup` to prove clean physical page sharing
//!    (`sum(PSS) < sum(RSS)` and `Shared_Clean > 0`).

use std::path::PathBuf;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::report::{dist_row, ExpOutput, DIST_HEADER};
use crate::stats::Dist;

/// CLI / runner parameters for F0-6.
#[derive(Debug, Clone)]
pub struct Args {
    /// Path to `firecracker` binary (v1.10+ / v1.11+).
    pub firecracker_bin: PathBuf,
    /// Path to the `vmstate` snapshot file.
    pub snapshot_path: PathBuf,
    /// Path to the guest memory snapshot file.
    pub mem_file_path: PathBuf,
    /// Optional API UDS of a running mother VM for Part A snapshot-capture benchmarking.
    pub mother_api_sock: Option<PathBuf>,
    /// Declared VM memory size in MiB (512 or 2048).
    pub vm_mem_mib: u64,
    /// Number of concurrent `File`-backend clones to restore for `smaps_rollup` measurement.
    pub clones: usize,
    /// Dedicated `tmpfs` size in MiB for Part A volatile snapshot capture (defaults to `vm_mem_mib + 128`).
    pub volatile_tmpfs_mib: Option<u64>,
    /// Quota size in MiB for the independent `tmpfs` quota-overrun `ENOSPC` / zero-OOM probe.
    pub tmpfs_quota_mib: u64,
    /// Capture repetitions for Part A (if `mother_api_sock` is supplied).
    pub capture_reps: usize,
    /// Optional vsock UDS (relative to clone dir) to verify `aos-guest` v1 `Ping` on each clone.
    pub vsock_uds: Option<PathBuf>,
    /// Guest vsock port for `aos-guest` `Ping` verification.
    pub vsock_port: u32,
}

/// Parsed fields of Linux `/proc/<pid>/smaps_rollup` (values in KiB).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmapsRollup {
    /// Resident Set Size (`Rss:`).
    pub rss_kib: u64,
    /// Proportional Set Size (`Pss:`).
    pub pss_kib: u64,
    /// Anonymous PSS (`Pss_Anon:`), if present.
    pub pss_anon_kib: u64,
    /// File-backed PSS (`Pss_File:`), if present.
    pub pss_file_kib: u64,
    /// Shared clean pages (`Shared_Clean:`).
    pub shared_clean_kib: u64,
    /// Shared dirty pages (`Shared_Dirty:`).
    pub shared_dirty_kib: u64,
    /// Private clean pages (`Private_Clean:`).
    pub private_clean_kib: u64,
    /// Private dirty pages (`Private_Dirty:`).
    pub private_dirty_kib: u64,
    /// Anonymous pages (`Anonymous:`).
    pub anonymous_kib: u64,
    /// Swapped PSS (`SwapPss:`).
    pub swap_pss_kib: u64,
}

/// Parse `/proc/<pid>/smaps_rollup` text into [`SmapsRollup`].
pub fn parse_smaps_rollup(text: &str) -> Result<SmapsRollup> {
    let mut out = SmapsRollup::default();
    let mut saw_rss = false;
    let mut saw_pss = false;

    for line in text.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let val_kib = || -> Result<u64> {
            let num = rest
                .trim()
                .strip_suffix("kB")
                .unwrap_or(rest.trim())
                .trim();
            num.parse::<u64>()
                .with_context(|| format!("parse KiB value for {key:?} in line {line:?}"))
        };
        match key.trim() {
            "Rss" => {
                out.rss_kib = val_kib()?;
                saw_rss = true;
            }
            "Pss" => {
                out.pss_kib = val_kib()?;
                saw_pss = true;
            }
            "Pss_Anon" => out.pss_anon_kib = val_kib()?,
            "Pss_File" => out.pss_file_kib = val_kib()?,
            "Shared_Clean" => out.shared_clean_kib = val_kib()?,
            "Shared_Dirty" => out.shared_dirty_kib = val_kib()?,
            "Private_Clean" => out.private_clean_kib = val_kib()?,
            "Private_Dirty" => out.private_dirty_kib = val_kib()?,
            "Anonymous" => out.anonymous_kib = val_kib()?,
            "SwapPss" => out.swap_pss_kib = val_kib()?,
            _ => {}
        }
    }
    ensure!(
        saw_rss && saw_pss,
        "smaps_rollup missing required Rss/Pss fields"
    );
    Ok(out)
}

/// Extract `oom_kill <count>` from `/proc/vmstat`.
#[must_use]
pub fn parse_vmstat_oom_kills(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        if parts.next()? == "oom_kill" {
            parts.next()?.parse().ok()
        } else {
            None
        }
    })
}

/// Memory sample for one restored clone VMM process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloneMemSample {
    /// Clone index (`0..clones`).
    pub clone_idx: usize,
    /// Firecracker VMM PID.
    pub pid: u32,
    /// Snapshot load API time (us).
    pub load_us: f64,
    /// Parsed `smaps_rollup`.
    pub smaps: SmapsRollup,
}

/// Aggregate physical sharing summary across `N` clones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingSummary {
    /// Number of clones sampled.
    pub clone_count: usize,
    /// Sum of `Rss` across all clones (KiB).
    pub sum_rss_kib: u64,
    /// Sum of `Pss` across all clones (KiB) — approximates true physical RAM consumed.
    pub sum_pss_kib: u64,
    /// Sum of `Shared_Clean` across all clones (KiB).
    pub sum_shared_clean_kib: u64,
    /// Sum of `Private_Dirty` across all clones (KiB).
    pub sum_private_dirty_kib: u64,
    /// Effective deduplication ratio (`sum_rss / sum_pss`, > 1.0 means physical sharing).
    pub dedup_factor: f64,
    /// Percentage of RSS saved via page sharing (`(sum_rss - sum_pss) / sum_rss * 100`).
    pub physical_savings_pct: f64,
    /// True iff `clone_count >= 2`, `sum_shared_clean_kib > 0`, and `sum_pss_kib < sum_rss_kib`.
    pub sharing_verified: bool,
}

impl SharingSummary {
    /// Compute aggregate physical sharing statistics from per-clone samples.
    #[must_use]
    pub fn compute(samples: &[CloneMemSample]) -> Self {
        let clone_count = samples.len();
        let sum_rss_kib: u64 = samples.iter().map(|s| s.smaps.rss_kib).sum();
        let sum_pss_kib: u64 = samples.iter().map(|s| s.smaps.pss_kib).sum();
        let sum_shared_clean_kib: u64 = samples.iter().map(|s| s.smaps.shared_clean_kib).sum();
        let sum_private_dirty_kib: u64 = samples.iter().map(|s| s.smaps.private_dirty_kib).sum();

        #[allow(clippy::cast_precision_loss)]
        let dedup_factor = if sum_pss_kib > 0 {
            sum_rss_kib as f64 / sum_pss_kib as f64
        } else {
            0.0
        };
        #[allow(clippy::cast_precision_loss)]
        let physical_savings_pct = if sum_rss_kib > 0 {
            ((sum_rss_kib.saturating_sub(sum_pss_kib)) as f64 / sum_rss_kib as f64) * 100.0
        } else {
            0.0
        };
        let sharing_verified =
            clone_count >= 2 && sum_shared_clean_kib > 0 && sum_pss_kib < sum_rss_kib;

        Self {
            clone_count,
            sum_rss_kib,
            sum_pss_kib,
            sum_shared_clean_kib,
            sum_private_dirty_kib,
            dedup_factor,
            physical_savings_pct,
            sharing_verified,
        }
    }
}

/// Outcome of the `tmpfs` quota overrun guard test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TmpfsQuotaProbe {
    /// Configured tmpfs quota in MiB.
    pub quota_mib: u64,
    /// Attempted write size in MiB.
    pub attempted_mib: u64,
    /// Whether `ENOSPC` (or clean quota rejection) was returned without process death.
    pub graceful_enospc: bool,
    /// Host `/proc/vmstat` `oom_kill` delta during the probe (must be 0).
    pub oom_kill_delta: u64,
    /// Detail message.
    pub detail: String,
}

/// Complete F0-6 report payload.
#[derive(Debug, Clone, Serialize)]
pub struct F06Report {
    /// Declared VM memory size in MiB.
    pub vm_mem_mib: u64,
    /// Durable pool snapshot capture latency distribution (us), if Part A ran.
    pub durable_capture: Option<Dist>,
    /// Volatile tmpfs snapshot capture latency distribution (us), if Part A ran.
    pub volatile_capture: Option<Dist>,
    /// `tmpfs` quota overrun / zero-OOM probe result (REQUIRED for `passed == true`).
    pub tmpfs_quota_probe: Option<TmpfsQuotaProbe>,
    /// Aggregate physical sharing summary across restored clones.
    pub sharing: SharingSummary,
    /// Per-clone `smaps_rollup` samples.
    pub clones: Vec<CloneMemSample>,
    /// Overall pass verdict.
    pub passed: bool,
}

/// Build JSON + Markdown `ExpOutput` for F0-6.
///
/// Fails closed if `tmpfs_quota_probe` is `None`: F0-6 requires verifying both `MAP_PRIVATE`
/// physical sharing AND graceful `tmpfs` `ENOSPC` with `oom_kill_delta == 0`.
#[must_use]
pub fn build_report(
    vm_mem_mib: u64,
    durable_capture: Option<Dist>,
    volatile_capture: Option<Dist>,
    tmpfs_quota_probe: Option<TmpfsQuotaProbe>,
    clones: Vec<CloneMemSample>,
) -> ExpOutput {
    let sharing = SharingSummary::compute(&clones);
    let quota_ok = tmpfs_quota_probe
        .as_ref()
        .is_some_and(|p| p.graceful_enospc && p.oom_kill_delta == 0);
    let passed = sharing.sharing_verified && quota_ok;

    let report = F06Report {
        vm_mem_mib,
        durable_capture,
        volatile_capture,
        tmpfs_quota_probe,
        sharing,
        clones,
        passed,
    };

    let mut md = String::new();
    md.push_str("## F0-6: Snapshot Capture Latency & MAP_PRIVATE Physical Sharing\n\n");
    md.push_str(&format!(
        "- Verdict: **{}** (VM memory: **{} MiB**, clones: **{}**)\n",
        if report.passed { "PASS" } else { "FAIL" },
        report.vm_mem_mib,
        report.sharing.clone_count
    ));
    md.push_str(&format!(
        "- Aggregate memory: Sum RSS = **{:.1} MiB**, Sum PSS = **{:.1} MiB**, Shared_Clean = **{:.1} MiB**, Private_Dirty = **{:.1} MiB**\n",
        report.sharing.sum_rss_kib as f64 / 1024.0,
        report.sharing.sum_pss_kib as f64 / 1024.0,
        report.sharing.sum_shared_clean_kib as f64 / 1024.0,
        report.sharing.sum_private_dirty_kib as f64 / 1024.0,
    ));
    md.push_str(&format!(
        "- Physical sharing: dedup factor = **{:.2}x**, physical RAM saved = **{:.1}%**\n",
        report.sharing.dedup_factor, report.sharing.physical_savings_pct
    ));
    match &report.tmpfs_quota_probe {
        Some(q) => md.push_str(&format!(
            "- `tmpfs` quota probe ({} MiB quota, {} MiB attempted): graceful_enospc={}, oom_kill_delta={} ({})\n",
            q.quota_mib, q.attempted_mib, q.graceful_enospc, q.oom_kill_delta, q.detail
        )),
        None => md.push_str("- `tmpfs` quota probe: **MISSING (FAIL)**\n"),
    }
    if report.durable_capture.is_some() || report.volatile_capture.is_some() {
        md.push_str("\n### Snapshot Capture Latency\n\n");
        md.push_str(DIST_HEADER);
        if let Some(d) = &report.durable_capture {
            md.push_str(&dist_row("Durable (disk pool + fsync)", d));
        }
        if let Some(v) = &report.volatile_capture {
            md.push_str(&dist_row("Volatile (quota tmpfs)", v));
        }
    }
    md.push_str("\n### Per-Clone `/proc/<pid>/smaps_rollup`\n\n");
    md.push_str("| Clone | PID | Load (ms) | RSS (KiB) | PSS (KiB) | Shared_Clean (KiB) | Private_Dirty (KiB) |\n");
    md.push_str("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for c in &report.clones {
        md.push_str(&format!(
            "| {} | {} | {:.2} | {} | {} | {} | {} |\n",
            c.clone_idx,
            c.pid,
            c.load_us / 1e3,
            c.smaps.rss_kib,
            c.smaps.pss_kib,
            c.smaps.shared_clean_kib,
            c.smaps.private_dirty_kib
        ));
    }
    md.push('\n');

    ExpOutput {
        id: "F0-6",
        slug: "f0-6-mem-sharing",
        json: json!(report),
        md,
    }
}

/// Read and parse `/proc/<pid>/smaps_rollup`.
pub fn read_smaps_rollup_pid(pid: u32) -> Result<SmapsRollup> {
    let path = format!("/proc/{pid}/smaps_rollup");
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {path}"))?;
    parse_smaps_rollup(&raw).map_err(|e| anyhow!("{path}: {e}"))
}

/// Execute F0-6 on Linux + KVM.
#[cfg(target_os = "linux")]
pub fn run(ctx: &crate::Ctx, args: &Args) -> Result<ExpOutput> {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use aos_types::PersistProof;

    use crate::firecracker::linux::{vsock_exchange_framed, FcClient, FcProcess};
    use crate::firecracker::{
        guest_ping_request, parse_guest_pong, SnapshotCreateParams, SnapshotLoadParams,
    };
    use crate::util::{is_enospc, run as run_cmd, run_any, MIB};

    /// RAII guard for a mounted `tmpfs` so errors never leak mounts.
    struct TmpfsGuard {
        mount_point: PathBuf,
    }

    impl TmpfsGuard {
        fn mount(mount_point: PathBuf, size_mib: u64) -> Result<Self> {
            std::fs::create_dir_all(&mount_point)?;
            let opts = format!("size={}M,mode=0700", size_mib.max(16));
            run_cmd(
                "mount",
                &[
                    "-t",
                    "tmpfs",
                    "-o",
                    &opts,
                    "tmpfs",
                    &mount_point.display().to_string(),
                ],
            )
            .with_context(|| format!("mount tmpfs ({opts}) at {}", mount_point.display()))?;
            Ok(Self { mount_point })
        }

        fn path(&self) -> &Path {
            &self.mount_point
        }
    }

    impl Drop for TmpfsGuard {
        fn drop(&mut self) {
            let p = self.mount_point.display().to_string();
            if run_cmd("umount", &[&p]).is_err() {
                let _ = run_any("umount", &["-l", &p]);
            }
        }
    }

    ensure!(
        Path::new("/dev/kvm").exists(),
        "F0-6 requires /dev/kvm on a Linux KVM host"
    );
    ensure!(args.clones >= 2, "--clones must be >= 2 to measure sharing");
    ensure!(
        args.snapshot_path.exists() && args.mem_file_path.exists(),
        "snapshot_path and mem_file_path must exist"
    );

    let work_root = ctx.root.join("f0-6");
    let _ = std::fs::remove_dir_all(&work_root);
    std::fs::create_dir_all(&work_root)?;

    // Part A (when mother_api_sock is supplied): Durable vs Volatile capture timing.
    // Volatile capture uses its own tmpfs sized `vm_mem_mib + 128` (decoupled from the small
    // quota-overrun probe tmpfs so defaults actually benchmark volatile capture!).
    let mut durable_us = Vec::new();
    let mut volatile_us = Vec::new();
    if let Some(mother_sock) = &args.mother_api_sock {
        let client = FcClient::new(mother_sock);
        let durable_dir = work_root.join("durable-snaps");
        std::fs::create_dir_all(&durable_dir)?;
        let vol_cap_mib = args.volatile_tmpfs_mib.unwrap_or(args.vm_mem_mib + 128);
        let vol_guard = TmpfsGuard::mount(work_root.join("tmpfs-capture"), vol_cap_mib)?;

        for rep in 0..args.capture_reps.max(1) {
            let vmstate = durable_dir.join(format!("snap-{rep}.vmstate"));
            let mem = durable_dir.join(format!("snap-{rep}.mem"));
            let t0 = Instant::now();
            client.pause_vm()?;
            client.create_snapshot(&SnapshotCreateParams::full(&vmstate, &mem))?;
            let _ = PersistProof::fsync_file_and_parent(&mem)?;
            let _ = PersistProof::fsync_file_and_parent(&vmstate)?;
            client.resume_vm()?;
            durable_us.push(t0.elapsed().as_secs_f64() * 1e6);
            let _ = std::fs::remove_file(&vmstate);
            let _ = std::fs::remove_file(&mem);

            let v_vmstate = vol_guard.path().join(format!("v-{rep}.vmstate"));
            let v_mem = vol_guard.path().join(format!("v-{rep}.mem"));
            let t1 = Instant::now();
            client.pause_vm()?;
            client.create_snapshot(&SnapshotCreateParams::full(&v_vmstate, &v_mem))?;
            client.resume_vm()?;
            volatile_us.push(t1.elapsed().as_secs_f64() * 1e6);
            let _ = std::fs::remove_file(&v_vmstate);
            let _ = std::fs::remove_file(&v_mem);
        }
        drop(vol_guard);
    }

    // Mandatory tmpfs quota overrun guard probe (fails run() if mount fails; RAII umount on drop).
    let tmpfs_quota_probe = {
        let quota_guard = TmpfsGuard::mount(work_root.join("tmpfs-quota"), args.tmpfs_quota_mib)?;
        let oom_before = std::fs::read_to_string("/proc/vmstat")
            .ok()
            .and_then(|s| parse_vmstat_oom_kills(&s))
            .unwrap_or(0);
        let attempted_mib = args.tmpfs_quota_mib + 32;
        let probe_file = quota_guard.path().join("quota-overrun.bin");
        let chunk = vec![0xA5u8; MIB as usize];
        let mut f = File::create(&probe_file)?;
        let mut written_mib = 0u64;
        let mut graceful_enospc = false;
        let mut detail = String::new();
        for _ in 0..attempted_mib {
            match f.write_all(&chunk) {
                Ok(()) => written_mib += 1,
                Err(e) if is_enospc(&e) => {
                    graceful_enospc = true;
                    detail = format!("hit ENOSPC cleanly after {written_mib} MiB");
                    break;
                }
                Err(e) => {
                    detail = format!("unexpected I/O error after {written_mib} MiB: {e}");
                    break;
                }
            }
        }
        if detail.is_empty() {
            detail = format!("wrote full {written_mib} MiB without hitting ENOSPC");
        }
        drop(f);
        let _ = std::fs::remove_file(&probe_file);
        let oom_after = std::fs::read_to_string("/proc/vmstat")
            .ok()
            .and_then(|s| parse_vmstat_oom_kills(&s))
            .unwrap_or(oom_before);
        drop(quota_guard);
        Some(TmpfsQuotaProbe {
            quota_mib: args.tmpfs_quota_mib,
            attempted_mib,
            graceful_enospc,
            oom_kill_delta: oom_after.saturating_sub(oom_before),
            detail,
        })
    };

    // Part B: Restore N clones concurrently with File Backend (MAP_PRIVATE) and sample smaps_rollup.
    let mut guards = Vec::with_capacity(args.clones);
    let mut load_times = Vec::with_capacity(args.clones);

    for idx in 0..args.clones {
        let clone_dir = work_root.join(format!("clone-{idx}"));
        std::fs::create_dir_all(&clone_dir)?;
        let api_sock = clone_dir.join("fc.api.sock");
        let fc = FcProcess::spawn(
            &args.firecracker_bin,
            &api_sock,
            &clone_dir,
            Duration::from_secs(5),
        )?;
        let client = FcClient::new(&api_sock);
        let t0 = Instant::now();
        client.load_snapshot(&SnapshotLoadParams::file_backend(
            &args.snapshot_path,
            &args.mem_file_path,
            false,
            true,
        ))?;
        let load_us = t0.elapsed().as_secs_f64() * 1e6;

        if let Some(uds) = &args.vsock_uds {
            let p = if uds.is_absolute() {
                uds.clone()
            } else {
                clone_dir.join(uds)
            };
            let req_id = (idx as u64) + 1;
            let nonce = 0xF006_0000 + req_id;
            let ping = guest_ping_request(req_id, nonce)?;
            let (resp, _) = vsock_exchange_framed(&p, args.vsock_port, &ping, Duration::from_secs(5))
                .with_context(|| format!("clone {idx} aos-guest Ping failed"))?;
            let _ = parse_guest_pong(&resp, req_id, nonce)?;
        }

        guards.push(fc);
        load_times.push(load_us);
    }

    // Sample all clones while all N VMMs are simultaneously resident so PSS reflects true sharing.
    let mut clones = Vec::with_capacity(guards.len());
    for (idx, fc) in guards.iter().enumerate() {
        let smaps = read_smaps_rollup_pid(fc.pid())?;
        clones.push(CloneMemSample {
            clone_idx: idx,
            pid: fc.pid(),
            load_us: load_times[idx],
            smaps,
        });
    }
    drop(guards);

    Ok(build_report(
        args.vm_mem_mib,
        (!durable_us.is_empty()).then(|| Dist::from_us(durable_us)),
        (!volatile_us.is_empty()).then(|| Dist::from_us(volatile_us)),
        tmpfs_quota_probe,
        clones,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SMAPS: &str = "\
55d4c2000000-7fff9c123000 ---p 00000000 00:00 0                          [rollup]
Rss:              524288 kB
Pss:              135168 kB
Pss_Dirty:          4096 kB
Pss_Anon:           4096 kB
Pss_File:         131072 kB
Pss_Shmem:             0 kB
Shared_Clean:     520192 kB
Shared_Dirty:          0 kB
Private_Clean:         0 kB
Private_Dirty:      4096 kB
Referenced:       524288 kB
Anonymous:          4096 kB
SwapPss:               0 kB
";

    #[test]
    fn parses_smaps_rollup_and_requires_tmpfs_quota_probe() {
        let s = parse_smaps_rollup(SAMPLE_SMAPS).unwrap();
        assert_eq!(s.rss_kib, 524_288);
        assert_eq!(s.pss_kib, 135_168);
        assert_eq!(s.shared_clean_kib, 520_192);
        assert_eq!(s.private_dirty_kib, 4096);
        assert_eq!(s.pss_file_kib, 131_072);

        let clones: Vec<CloneMemSample> = (0..4)
            .map(|i| CloneMemSample {
                clone_idx: i,
                pid: 1000 + i as u32,
                load_us: 4200.0,
                smaps: s,
            })
            .collect();
        let summary = SharingSummary::compute(&clones);
        assert!(summary.sharing_verified);
        assert!(summary.dedup_factor > 3.8);
        assert!(summary.physical_savings_pct > 70.0);

        // Missing tmpfs_quota_probe MUST FAIL closed!
        let missing = build_report(512, None, None, None, clones.clone());
        assert_eq!(missing.json["passed"], false);

        // Complete sharing + clean ENOSPC + 0 OOM kills passes.
        let out = build_report(
            512,
            Some(Dist::from_us(vec![95_000.0, 102_000.0])),
            Some(Dist::from_us(vec![24_000.0, 26_000.0])),
            Some(TmpfsQuotaProbe {
                quota_mib: 256,
                attempted_mib: 288,
                graceful_enospc: true,
                oom_kill_delta: 0,
                detail: "hit ENOSPC cleanly after 256 MiB".into(),
            }),
            clones,
        );
        assert_eq!(out.id, "F0-6");
        assert_eq!(out.slug, "f0-6-mem-sharing");
        assert_eq!(out.json["passed"], true);
        assert!(out.md.contains("PASS"));
        assert!(out.md.contains("Durable (disk pool + fsync)"));
    }

    #[test]
    fn parses_vmstat_oom_kill_counter() {
        let vmstat = "nr_free_pages 12345\noom_kill 0\npgfault 999\n";
        assert_eq!(parse_vmstat_oom_kills(vmstat), Some(0));
        let vmstat2 = "oom_kill 3\n";
        assert_eq!(parse_vmstat_oom_kills(vmstat2), Some(3));
    }
}
