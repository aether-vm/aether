//! F0-2: `FICLONE + fsync` pause time of a fragmented image file on three backends:
//! Btrfs CoW, Btrfs `chattr +C` (NOCOW) and XFS (`reflink=1`), for several extent counts and
//! amounts of dirty page cache.
//!
//! Pivot gate: Btrfs-CoW image clone at ~50k extents > 100 ms while XFS is markedly better
//! => `BlockStore` becomes a dedicated XFS backend.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::ioctls;
use crate::pool::{FsKind, ScratchPool};
use crate::report::{ExpOutput};
use crate::stats::Dist;
use crate::util::{dirty_kib, fmt_ms, SplitMix64, MIB};
use crate::Ctx;

/// Parameters.
#[derive(Debug, Clone)]
pub struct Args {
    /// Pool size in MiB (one Btrfs pool and one XFS pool of this size are used one after another).
    pub pool_mib: u64,
    /// Target extent counts of the source image.
    pub extents: Vec<u64>,
    /// Dirty page-cache amounts (MiB) to leave on the source image at clone time.
    pub dirty_mib: Vec<u64>,
    /// Repetitions per cell.
    pub reps: usize,
}

const STRIDE: u64 = 8192; // 4 KiB data + 4 KiB hole => one extent per write, never merged

/// One (backend, extents, dirty) measurement.
#[derive(Debug, Clone, Serialize)]
pub struct Cell {
    /// Backend label.
    pub backend: &'static str,
    /// Requested extents.
    pub extents_requested: u64,
    /// Exact extent count before dirtying (Btrfs: tree-search items; XFS: `fsx_nextents`).
    pub extents_exact_before: Option<u64>,
    /// FIEMAP count before dirtying.
    pub extents_fiemap_before: Option<u32>,
    /// Exact extent count after the cell's reps (includes the dirty tail region).
    pub extents_exact_after: Option<u64>,
    /// Dirty MiB written before each clone.
    pub dirty_mib: u64,
    /// System-wide `Dirty:` KiB right before the clone (max across reps).
    pub dirty_kib_before_clone_max: u64,
    /// Repetitions that succeeded.
    pub reps_ok: usize,
    /// `FICLONE` ioctl only.
    pub clone: Option<Dist>,
    /// `fsync(dst)` after the clone.
    pub fsync: Option<Dist>,
    /// `FICLONE + fsync` (the guest-pause-relevant number).
    pub total: Option<Dist>,
    /// NOCOW flag observed on the source (backend `btrfs-nocow` must be true).
    pub nocow_flag: Option<bool>,
    /// First error encountered, if any.
    pub error: Option<String>,
}

fn open_rw_create(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).create_new(true).open(path)
}

fn exact_extents(kind: FsKind, f: &File) -> Option<u64> {
    match kind {
        FsKind::Btrfs => ioctls::btrfs_count_extent_items(f).ok(),
        FsKind::Xfs => ioctls::fsgetxattr(f).ok().map(|x| u64::from(x.fsx_nextents)),
    }
}

fn build_source(path: &Path, nocow: bool, extents: u64, tail_mib: u64, rng: &mut SplitMix64) -> Result<(File, u64)> {
    let f = open_rw_create(path)?;
    if nocow {
        ioctls::set_nocow(&f).map_err(|e| anyhow!("FS_IOC_SETFLAGS(+C): {e}"))?;
    }
    let tail_off = ((extents * STRIDE + 4 * MIB) / MIB + 1) * MIB;
    f.set_len(tail_off + tail_mib * MIB)?;
    let mut idx: Vec<u64> = (0..extents).collect();
    rng.shuffle(&mut idx);
    let mut buf = vec![0u8; 4096];
    rng.fill(&mut buf);
    for (n, i) in idx.iter().enumerate() {
        buf[..8].copy_from_slice(&(n as u64).to_le_bytes());
        f.write_all_at(&buf, i * STRIDE)?;
    }
    f.sync_all()?;
    Ok((f, tail_off))
}

#[allow(clippy::too_many_arguments)]
fn measure_cell(
    dir: &Path,
    kind: FsKind,
    backend: &'static str,
    nocow: bool,
    src: &File,
    tail_off: u64,
    extents: u64,
    before: (Option<u64>, Option<u32>),
    dirty_mib: u64,
    reps: usize,
    rng: &mut SplitMix64,
) -> Cell {
    let mut clone_us = Vec::new();
    let mut fsync_us = Vec::new();
    let mut total_us = Vec::new();
    let mut error = None;
    let mut dirty_max = 0u64;
    let mut chunk = vec![0u8; MIB as usize];
    for rep in 0..reps {
        if dirty_mib > 0 {
            for m in 0..dirty_mib {
                rng.fill(&mut chunk);
                if let Err(e) = src.write_all_at(&chunk, tail_off + m * MIB) {
                    error = Some(format!("dirtying source: {e}"));
                    break;
                }
            }
            if error.is_some() {
                break;
            }
        }
        dirty_max = dirty_max.max(dirty_kib());
        let dst_path = dir.join(format!("clone-{extents}-{dirty_mib}-{rep}.raw"));
        let dst = match open_rw_create(&dst_path) {
            Ok(f) => f,
            Err(e) => {
                error = Some(format!("create dst: {e}"));
                break;
            }
        };
        if nocow {
            if let Err(e) = ioctls::set_nocow(&dst) {
                error = Some(format!("set NOCOW on dst: {e}"));
                break;
            }
        }
        let t0 = Instant::now();
        let r = ioctls::ficlone(&dst, src);
        let t1 = Instant::now();
        if let Err(e) = r {
            error = Some(format!("FICLONE: {e} (errno {:?})", e.raw_os_error()));
            drop(dst);
            let _ = std::fs::remove_file(&dst_path);
            break;
        }
        let sync_r = dst.sync_all();
        let t2 = Instant::now();
        if let Err(e) = sync_r {
            error = Some(format!("fsync(dst): {e}"));
        }
        clone_us.push((t1 - t0).as_secs_f64() * 1e6);
        fsync_us.push((t2 - t1).as_secs_f64() * 1e6);
        total_us.push((t2 - t0).as_secs_f64() * 1e6);
        drop(dst);
        let _ = std::fs::remove_file(&dst_path);
    }
    let reps_ok = total_us.len();
    let after = exact_extents(kind, src);
    Cell {
        backend,
        extents_requested: extents,
        extents_exact_before: before.0,
        extents_fiemap_before: before.1,
        extents_exact_after: after,
        dirty_mib,
        dirty_kib_before_clone_max: dirty_max,
        reps_ok,
        clone: (reps_ok > 0).then(|| Dist::from_us(clone_us)),
        fsync: (reps_ok > 0).then(|| Dist::from_us(fsync_us)),
        total: (reps_ok > 0).then(|| Dist::from_us(total_us)),
        nocow_flag: if nocow { ioctls::is_nocow(src).ok() } else { None },
        error,
    }
}

fn run_backend_set(
    ctx: &Ctx,
    a: &Args,
    kind: FsKind,
    backends: &[(&'static str, bool)],
    rng: &mut SplitMix64,
    cells: &mut Vec<Cell>,
    pool_notes: &mut Vec<Value>,
) -> Result<()> {
    let label = match kind {
        FsKind::Btrfs => "f02b",
        FsKind::Xfs => "f02x",
    };
    let pool = ScratchPool::create(&ctx.root, label, kind, a.pool_mib, ctx.max_pool_gib)?;
    pool_notes.push(json!({ "kind": kind.name(), "size_mib": a.pool_mib, "direct_io": pool.direct_io }));
    let max_dirty = a.dirty_mib.iter().copied().max().unwrap_or(0);
    for &(backend, nocow) in backends {
        let dir = pool.mnt().join(backend);
        std::fs::create_dir_all(&dir)?;
        for &n in &a.extents {
            let src_path = dir.join(format!("img-{n}.raw"));
            let (src, tail_off) = match build_source(&src_path, nocow, n, max_dirty, rng) {
                Ok(v) => v,
                Err(e) => {
                    cells.push(Cell {
                        backend,
                        extents_requested: n,
                        extents_exact_before: None,
                        extents_fiemap_before: None,
                        extents_exact_after: None,
                        dirty_mib: 0,
                        dirty_kib_before_clone_max: 0,
                        reps_ok: 0,
                        clone: None,
                        fsync: None,
                        total: None,
                        nocow_flag: None,
                        error: Some(format!("build source: {e:#}")),
                    });
                    let _ = std::fs::remove_file(&src_path);
                    continue;
                }
            };
            let before = (exact_extents(kind, &src), ioctls::fiemap_count(&src).ok());
            eprintln!("  [{backend}] built {n}-extent source: exact={:?} fiemap={:?}", before.0, before.1);
            for &d in &a.dirty_mib {
                let cell = measure_cell(&dir, kind, backend, nocow, &src, tail_off, n, before, d, a.reps, rng);
                eprintln!(
                    "  [{backend}] extents={n} dirty={d}MiB -> total p50 {} ms ({} reps ok){}",
                    cell.total.as_ref().map_or("n/a".into(), |t| fmt_ms(t.p50_us)),
                    cell.reps_ok,
                    cell.error.as_deref().map_or(String::new(), |e| format!(" ERROR: {e}"))
                );
                cells.push(cell);
            }
            drop(src);
            let _ = std::fs::remove_file(&src_path);
            nix::unistd::sync();
        }
    }
    Ok(())
}

fn median_total_ms(cells: &[Cell], backend: &str, extents: u64, dirty: u64) -> Option<f64> {
    cells
        .iter()
        .find(|c| c.backend == backend && c.extents_requested == extents && c.dirty_mib == dirty)
        .and_then(|c| c.total.as_ref())
        .map(|t| t.p50_us / 1e3)
}

/// Run F0-2.
pub fn run(ctx: &Ctx, a: &Args) -> Result<ExpOutput> {
    let mut rng = SplitMix64::new(ctx.seed);
    let mut cells = Vec::new();
    let mut pool_notes = Vec::new();
    run_backend_set(ctx, a, FsKind::Btrfs, &[("btrfs-cow", false), ("btrfs-nocow", true)], &mut rng, &mut cells, &mut pool_notes)?;
    run_backend_set(ctx, a, FsKind::Xfs, &[("xfs-reflink", false)], &mut rng, &mut cells, &mut pool_notes)?;

    // Gate: largest requested extent count >= 50k (or the largest available), dirty = 0
    let gate_extents = a.extents.iter().copied().filter(|&e| e >= 50_000).min().or_else(|| a.extents.iter().copied().max()).unwrap_or(0);
    let gate_dirty = *a.dirty_mib.first().unwrap_or(&0);
    let b = median_total_ms(&cells, "btrfs-cow", gate_extents, gate_dirty);
    let x = median_total_ms(&cells, "xfs-reflink", gate_extents, gate_dirty);
    let verdict = match (b, x) {
        (Some(b), Some(x)) => {
            let pivot = b > 100.0 && x < b * 0.5;
            format!(
                "Gate cell: {gate_extents} extents, dirty {gate_dirty} MiB: Btrfs-CoW p50 {b:.1} ms vs XFS p50 {x:.1} ms (threshold: Btrfs > 100 ms AND XFS significantly lower, i.e. < 50 % of Btrfs). \
                 => **{}** (advisory, WSL2 loop-on-ext4-on-VHDX; re-verify on bare metal).",
                if pivot { "PIVOT TRIGGERED: BlockStore -> dedicated XFS backend" } else { "no pivot triggered" }
            )
        }
        _ => "Gate cell incomplete (see per-cell errors).".to_owned(),
    };

    let mut md = String::new();
    md.push_str("# F0-2 - `FICLONE + fsync` pause on fragmented block images\n\n## Parameters\n\n");
    md.push_str(&format!(
        "- pools: Btrfs and XFS (`reflink=1`, crc=1), {} MiB each, loop `direct_io` = {}\n- source image: `N` extents = N x 4 KiB random-order writes at 8 KiB stride (holes prevent merging); extents verified by `BTRFS_IOC_TREE_SEARCH` (key 108) / `fsx_nextents` and cross-checked with FIEMAP\n- dirty page cache: the last `D` MiB of the source image rewritten (not synced) before every clone; system `Dirty:` sampled right before the clone\n- repetitions per cell: {}; extents {:?}; dirty MiB {:?}\n- `btrfs-nocow`: `FS_IOC_SETFLAGS(+FS_NOCOW_FL)` applied to the empty source *and* destination before any data (Btrfs refuses clone between NOCOW and COW inodes)\n- not measured here: ext4 *inside* the image (irrelevant to extent layout), 100k extents and 1 GiB dirty (pool-size / laptop safety), XFS `cowextsize` hint (default used)\n\n",
        a.pool_mib,
        pool_notes.iter().all(|p| p["direct_io"] == true),
        a.reps, a.extents, a.dirty_mib
    ));
    md.push_str("## Results (milliseconds)\n\n| Backend | extents req. | exact extents (before / after) | FIEMAP before | dirty MiB | Dirty KiB max | reps ok | FICLONE p50 | fsync p50 | **total p50** | total p99 | total max |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for c in &cells {
        let f = |d: &Option<Dist>, g: fn(&Dist) -> f64| d.as_ref().map_or("n/a".into(), |d| fmt_ms(g(d)));
        md.push_str(&format!(
            "| {} | {} | {} / {} | {} | {} | {} | {} | {} | {} | **{}** | {} | {} |\n",
            c.backend,
            c.extents_requested,
            c.extents_exact_before.map_or("?".into(), |v| v.to_string()),
            c.extents_exact_after.map_or("?".into(), |v| v.to_string()),
            c.extents_fiemap_before.map_or("?".into(), |v| v.to_string()),
            c.dirty_mib,
            c.dirty_kib_before_clone_max,
            c.reps_ok,
            f(&c.clone, |d| d.p50_us),
            f(&c.fsync, |d| d.p50_us),
            f(&c.total, |d| d.p50_us),
            f(&c.total, |d| d.p99_us),
            f(&c.total, |d| d.max_us),
        ));
    }
    let errs: Vec<String> = cells
        .iter()
        .filter_map(|c| c.error.as_ref().map(|e| format!("- `{}` extents={} dirty={}: {e}", c.backend, c.extents_requested, c.dirty_mib)))
        .collect();
    if !errs.is_empty() {
        md.push_str("\n## Errors / anomalies\n\n");
        md.push_str(&errs.join("\n"));
        md.push('\n');
    }
    md.push_str(&format!("\n## Verdict\n\n{verdict}\n"));

    let json = json!({
        "params": { "pool_mib": a.pool_mib, "extents": a.extents, "dirty_mib": a.dirty_mib, "reps": a.reps, "stride_bytes": STRIDE, "seed": ctx.seed },
        "pools": pool_notes,
        "cells": cells,
        "gate": { "extents": gate_extents, "dirty_mib": gate_dirty, "btrfs_cow_p50_ms": b, "xfs_p50_ms": x, "btrfs_threshold_ms": 100 },
        "verdict": verdict,
    });
    Ok(ExpOutput { id: "F0-2", slug: "f0-2-ficlone-matrix", json, md })
}
