//! F0-1: Btrfs concurrent subvolume snapshot / destroy throughput, with `redb` commit latency
//! measured on the **same pool** (and on the host ext4 as control) while a random-write load runs.
//!
//! Pivot gate: if same-pool `redb` commit P99 > 50 ms during snapshot churn, `meta/aether.redb`
//! must move off the Btrfs pool.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use redb::{Database, TableDefinition};
use serde_json::{json, Value};

use crate::ioctls::{self, DestroyApi};
use crate::pool::{FsKind, ScratchPool};
use crate::report::{dist_row, ExpOutput, DIST_HEADER};
use crate::stats::Dist;
use crate::util::{avail_bytes, run_any, timed, SplitMix64, MIB};
use crate::Ctx;

const KV: TableDefinition<u64, &[u8]> = TableDefinition::new("kv");

/// Parameters.
#[derive(Debug, Clone)]
pub struct Args {
    /// Pool size in MiB.
    pub pool_mib: u64,
    /// Number of subvolumes to create then destroy.
    pub subvols: usize,
    /// Size of the background random-write file in MiB.
    pub load_mib: u64,
    /// Seconds of baseline (load + redb, no snapshots).
    pub baseline_secs: u64,
    /// Pause between redb commits in ms (per DB).
    pub commit_interval_ms: u64,
}

const PHASE_BASELINE: u8 = 0;
const PHASE_CREATE: u8 = 1;
const PHASE_DESTROY: u8 = 2;
const PHASE_SETTLE: u8 = 3;
const PHASE_NAMES: [&str; 4] = ["baseline", "create", "destroy", "settle"];

type Samples = Vec<(u8, f64)>;

fn redb_thread(
    path: PathBuf,
    stop: Arc<AtomicBool>,
    phase: Arc<AtomicU8>,
    interval: Duration,
) -> JoinHandle<Result<Samples>> {
    thread::spawn(move || -> Result<Samples> {
        let db = Database::create(&path).with_context(|| format!("redb create {}", path.display()))?;
        let value = [0xA5u8; 128];
        let mut samples = Vec::new();
        let mut counter = 0u64;
        while !stop.load(Ordering::Relaxed) {
            let ph = phase.load(Ordering::Relaxed);
            let t0 = Instant::now();
            let w = db.begin_write()?;
            {
                let mut t = w.open_table(KV)?;
                t.insert(counter % 4096, value.as_slice())?;
            }
            w.commit()?;
            samples.push((ph, t0.elapsed().as_secs_f64() * 1e6));
            counter += 1;
            thread::sleep(interval);
        }
        Ok(samples)
    })
}

fn load_thread(
    path: PathBuf,
    size: u64,
    stop: Arc<AtomicBool>,
    seed: u64,
    ops: Arc<AtomicU64>,
) -> JoinHandle<Result<()>> {
    thread::spawn(move || -> Result<()> {
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path)?;
        f.set_len(size)?;
        let mut rng = SplitMix64::new(seed);
        let mut buf = vec![0u8; 4096];
        rng.fill(&mut buf);
        let blocks = size / 4096;
        let mut n = 0u64;
        while !stop.load(Ordering::Relaxed) {
            let off = rng.below(blocks) * 4096;
            buf[..8].copy_from_slice(&n.to_le_bytes());
            f.write_all_at(&buf, off)?;
            n += 1;
            if n % 64 == 0 {
                f.sync_data()?;
            }
            ops.store(n, Ordering::Relaxed);
        }
        f.sync_data()?;
        Ok(())
    })
}

fn populate_template(dir: &Path) -> Result<()> {
    let mut rng = SplitMix64::new(7);
    let mut buf = vec![0u8; 16 * 1024];
    for i in 0..200 {
        rng.fill(&mut buf);
        std::fs::write(dir.join(format!("file-{i:04}.dat")), &buf)?;
    }
    Ok(())
}

fn by_phase(samples: &Samples, phase: u8) -> Dist {
    Dist::from_us(samples.iter().filter(|(p, _)| *p == phase).map(|(_, us)| *us).collect())
}

fn count_over(samples: &Samples, phase: u8, threshold_us: f64) -> usize {
    samples.iter().filter(|(p, us)| *p == phase && *us > threshold_us).count()
}

fn open_dir(p: &Path) -> Result<File> {
    File::open(p).with_context(|| format!("open dir {}", p.display()))
}

/// Run F0-1.
pub fn run(ctx: &Ctx, a: &Args) -> Result<ExpOutput> {
    let pool = ScratchPool::create(&ctx.root, "f01", FsKind::Btrfs, a.pool_mib, ctx.max_pool_gib)?;
    let mnt = pool.mnt().to_path_buf();
    let host_meta_dir = ctx.root.join(format!("hostmeta-f01-{}", std::process::id()));
    std::fs::create_dir_all(&host_meta_dir)?;

    let top = open_dir(&mnt)?;
    let fs_info = ioctls::btrfs_fs_info(&top).map_err(|e| anyhow!("BTRFS_IOC_FS_INFO: {e}"))?;
    let qgroup = run_any("btrfs", &["qgroup", "show", mnt.to_str().unwrap()])?;
    let qgroup_text = format!(
        "{}{}",
        String::from_utf8_lossy(&qgroup.stdout),
        String::from_utf8_lossy(&qgroup.stderr)
    )
    .trim()
    .to_owned();
    let qgroups_disabled = !qgroup.status.success() && qgroup_text.to_lowercase().contains("quota");

    ioctls::btrfs_subvol_create(&top, "tmpl").map_err(|e| anyhow!("SUBVOL_CREATE_V2: {e}"))?;
    populate_template(&mnt.join("tmpl"))?;
    std::fs::create_dir_all(mnt.join("load"))?;
    std::fs::create_dir_all(mnt.join("meta"))?;
    ioctls::btrfs_sync(&top)?;
    let tmpl = open_dir(&mnt.join("tmpl"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(AtomicU8::new(PHASE_BASELINE));
    let load_ops = Arc::new(AtomicU64::new(0));
    let interval = Duration::from_millis(a.commit_interval_ms);
    let h_load = load_thread(mnt.join("load/rand.dat"), a.load_mib * MIB, stop.clone(), ctx.seed, load_ops.clone());
    let h_pool = redb_thread(mnt.join("meta/aether.redb"), stop.clone(), phase.clone(), interval);
    let h_host = redb_thread(host_meta_dir.join("aether.redb"), stop.clone(), phase.clone(), interval);

    // Phase 0: baseline (load + redb only)
    thread::sleep(Duration::from_secs(a.baseline_secs));

    // Phase 1: create N snapshots (alternating read-only / writable)
    phase.store(PHASE_CREATE, Ordering::Relaxed);
    let free_before = avail_bytes(&mnt)?;
    let mut create_lat: Vec<Duration> = Vec::with_capacity(a.subvols);
    let mut create_ro: Vec<Duration> = Vec::new();
    let mut create_rw: Vec<Duration> = Vec::new();
    let t_create0 = Instant::now();
    for i in 0..a.subvols {
        let ro = i % 2 == 0;
        let name = format!("snap-{i:04}");
        let (r, d) = timed(|| ioctls::btrfs_snap_create(&top, &tmpl, &name, ro));
        r.map_err(|e| anyhow!("SNAP_CREATE_V2 #{i}: {e}"))?;
        create_lat.push(d);
        if ro { create_ro.push(d) } else { create_rw.push(d) }
    }
    let create_total = t_create0.elapsed();
    let free_after_create = avail_bytes(&mnt)?;

    // Phase 2: destroy them all
    phase.store(PHASE_DESTROY, Ordering::Relaxed);
    let mut destroy_lat: Vec<Duration> = Vec::with_capacity(a.subvols);
    let mut destroy_api = DestroyApi::V2;
    let t_destroy0 = Instant::now();
    for i in 0..a.subvols {
        let name = format!("snap-{i:04}");
        let (r, d) = timed(|| ioctls::btrfs_snap_destroy(&top, &name));
        destroy_api = r.map_err(|e| anyhow!("SNAP_DESTROY #{i}: {e}"))?;
        destroy_lat.push(d);
    }
    let destroy_total = t_destroy0.elapsed();

    // Phase 3: wait for the async cleaner to drain deleted subvolumes
    phase.store(PHASE_SETTLE, Ordering::Relaxed);
    let (_, drain) = timed(|| run_any("btrfs", &["subvolume", "sync", mnt.to_str().unwrap()]));
    let free_after_drain = avail_bytes(&mnt)?;
    thread::sleep(Duration::from_secs(1));

    stop.store(true, Ordering::Relaxed);
    h_load.join().map_err(|_| anyhow!("load thread panicked"))??;
    let s_pool = h_pool.join().map_err(|_| anyhow!("redb(pool) thread panicked"))??;
    let s_host = h_host.join().map_err(|_| anyhow!("redb(host) thread panicked"))??;

    let d_create = Dist::from_durations(&create_lat);
    let d_create_ro = Dist::from_durations(&create_ro);
    let d_create_rw = Dist::from_durations(&create_rw);
    let d_destroy = Dist::from_durations(&destroy_lat);

    let mut per_phase = serde_json::Map::new();
    let mut md_redb = String::new();
    md_redb.push_str(DIST_HEADER);
    for (ph, name) in PHASE_NAMES.iter().enumerate() {
        let ph = ph as u8;
        let dp = by_phase(&s_pool, ph);
        let dh = by_phase(&s_host, ph);
        md_redb.push_str(&dist_row(&format!("redb on **pool** (btrfs) / {name}"), &dp));
        md_redb.push_str(&dist_row(&format!("redb on host (ext4 control) / {name}"), &dh));
        per_phase.insert(
            (*name).to_owned(),
            json!({
                "redb_pool": dp,
                "redb_host": dh,
                "pool_commits_over_50ms": count_over(&s_pool, ph, 50_000.0),
                "host_commits_over_50ms": count_over(&s_host, ph, 50_000.0),
            }),
        );
    }
    let p99_pool_create = by_phase(&s_pool, PHASE_CREATE).p99_us;
    let p99_pool_destroy = by_phase(&s_pool, PHASE_DESTROY).p99_us;
    let p99_pool_base = by_phase(&s_pool, PHASE_BASELINE).p99_us;
    let worst_pool_p99_ms = p99_pool_create.max(p99_pool_destroy) / 1e3;
    let pivot = worst_pool_p99_ms > 50.0;

    let verdict = if pivot {
        format!(
            "**PIVOT TRIGGERED (advisory, WSL2)**: same-pool redb commit P99 reached {worst_pool_p99_ms:.1} ms (> 50 ms) \
             during snapshot churn -> `meta/aether.redb` must live outside the Btrfs data pool."
        )
    } else {
        format!(
            "**No pivot (advisory, WSL2)**: worst same-pool redb commit P99 during snapshot churn = {worst_pool_p99_ms:.1} ms (<= 50 ms gate); \
             baseline P99 = {:.1} ms. Re-verify on bare metal before relaxing the meta-off-pool option.",
            p99_pool_base / 1e3
        )
    };

    let md = format!(
        "# F0-1 - Btrfs concurrent snapshot / destroy vs same-pool `redb` commits\n\n\
         ## Parameters\n\n\
         - pool: Btrfs on loop (`direct_io={}`), {} MiB; subvolumes: {} (alternating read-only/writable); template subvol: 200 x 16 KiB files\n\
         - background load: 4 KiB random `pwrite` into a {} MiB file with `fdatasync` every 64 writes ({} writes total)\n\
         - redb: one commit per {} ms per DB (128 B value, `Durability::Immediate`); DB#1 on the Btrfs pool, DB#2 on host ext4 (control)\n\
         - qgroups disabled: **{}** (`btrfs qgroup show`: `{}`)\n\
         - Btrfs FS_INFO: nodesize {}, sectorsize {}, clone_alignment {}, devices {}, generation {}\n\
         - destroy API used: {:?}\n\n\
         ## Snapshot / destroy call latency\n\n{}{}{}{}{}\n\
         - total create wall time: {:.2} s ({:.0} snaps/s); total destroy wall time: {:.2} s ({:.0} destroys/s)\n\
         - async cleaner drain (`btrfs subvolume sync`): {:.2} s\n\
         - free space: before {} MiB, after create {} MiB, after drain {} MiB\n\n\
         ## `redb` commit latency by phase\n\n{}\n\
         ## Verdict\n\n{}\n",
        pool.direct_io,
        a.pool_mib,
        a.subvols,
        a.load_mib,
        load_ops.load(Ordering::Relaxed),
        a.commit_interval_ms,
        qgroups_disabled,
        qgroup_text.replace('\n', " "),
        fs_info.nodesize,
        fs_info.sectorsize,
        fs_info.clone_alignment,
        fs_info.num_devices,
        fs_info.generation,
        destroy_api,
        DIST_HEADER,
        dist_row("SNAP_CREATE_V2 (all)", &d_create),
        dist_row("SNAP_CREATE_V2 (read-only)", &d_create_ro),
        dist_row("SNAP_CREATE_V2 (writable)", &d_create_rw),
        dist_row("SNAP_DESTROY_V2", &d_destroy),
        create_total.as_secs_f64(),
        a.subvols as f64 / create_total.as_secs_f64(),
        destroy_total.as_secs_f64(),
        a.subvols as f64 / destroy_total.as_secs_f64(),
        drain.as_secs_f64(),
        free_before / MIB,
        free_after_create / MIB,
        free_after_drain / MIB,
        md_redb,
        verdict
    );

    let result: Value = json!({
        "params": { "pool_mib": a.pool_mib, "subvols": a.subvols, "load_mib": a.load_mib,
                     "baseline_secs": a.baseline_secs, "commit_interval_ms": a.commit_interval_ms, "seed": ctx.seed },
        "pool": { "kind": "btrfs", "direct_io": pool.direct_io, "qgroups_disabled": qgroups_disabled, "qgroup_show_output": qgroup_text },
        "btrfs_fs_info": { "nodesize": fs_info.nodesize, "sectorsize": fs_info.sectorsize,
                            "clone_alignment": fs_info.clone_alignment, "num_devices": fs_info.num_devices,
                            "generation": fs_info.generation, "fsid": fs_info.fsid },
        "destroy_api": format!("{destroy_api:?}"),
        "snap_create": d_create, "snap_create_readonly": d_create_ro, "snap_create_writable": d_create_rw,
        "snap_destroy": d_destroy,
        "create_total_s": create_total.as_secs_f64(), "destroy_total_s": destroy_total.as_secs_f64(),
        "cleaner_drain_s": drain.as_secs_f64(),
        "free_mib": { "before": free_before / MIB, "after_create": free_after_create / MIB, "after_drain": free_after_drain / MIB },
        "background_load_writes": load_ops.load(Ordering::Relaxed),
        "redb_by_phase": per_phase,
        "gate": { "threshold_ms": 50, "worst_pool_p99_ms": worst_pool_p99_ms, "pivot_triggered": pivot },
        "verdict": verdict,
    });

    drop(tmpl);
    drop(top);
    let _ = std::fs::remove_dir_all(&host_meta_dir);
    drop(pool);
    Ok(ExpOutput { id: "F0-1", slug: "f0-1-btrfs-snap", json: result, md })
}
