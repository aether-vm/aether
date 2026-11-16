//! F0-4: pool-full (`ENOSPC`) deadlock probe and ballast recovery drill on Btrfs.
//!
//! Questions answered:
//! 1. At true `ENOSPC`, can a `redb` living in the **same pool** still commit a (small) tombstone
//!    transaction? What about a transaction that must grow the file?
//! 2. Can a subvolume be destroyed / small files unlinked while full?
//! 3. After deleting the pre-allocated `ballast` file, do `redb` commits and subvolume destroy work
//!    again, and is all space reclaimed?
//!
//! Pivot gate: if same-pool `redb` cannot commit a tombstone txn at ENOSPC, `meta/` must be on a
//! separate disk.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use redb::{Database, TableDefinition};
use serde::Serialize;
use serde_json::json;

use crate::ioctls;
use crate::pool::{FsKind, ScratchPool};
use crate::report::ExpOutput;
use crate::util::{avail_bytes, is_enospc, run_any, timed, SplitMix64, MIB};
use crate::Ctx;

const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");

/// Parameters.
#[derive(Debug, Clone)]
pub struct Args {
    /// Pool size in MiB.
    pub pool_mib: u64,
    /// Ballast file size in MiB.
    pub ballast_mib: u64,
    /// Total size of the two victim subvolumes in MiB.
    pub victim_mib: u64,
}

/// One probe outcome.
#[derive(Debug, Clone, Serialize)]
pub struct Probe {
    /// Probe name.
    pub name: String,
    /// Did it succeed?
    pub ok: bool,
    /// Details (error text or counts).
    pub detail: String,
}

fn probe(name: &str, ok: bool, detail: impl Into<String>) -> Probe {
    Probe { name: name.to_owned(), ok, detail: detail.into() }
}

fn write_counting(f: &mut File, buf: &[u8], max: u64) -> (u64, Option<io::Error>) {
    let mut written = 0u64;
    while written < max {
        let n = (max - written).min(buf.len() as u64) as usize;
        match f.write(&buf[..n]) {
            Ok(0) => return (written, Some(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))),
            Ok(k) => written += k as u64,
            Err(e) => return (written, Some(e)),
        }
    }
    (written, None)
}

/// Fill the filesystem in three stages: bulk data, 4 KiB data, then tiny (inline) files.
fn fill_to_enospc(dir: &Path, rng: &mut SplitMix64) -> Result<serde_json::Value> {
    std::fs::create_dir_all(dir)?;
    let mut buf = vec![0u8; MIB as usize];
    let t0 = Instant::now();
    // stage 1: 1 MiB writes, 64 MiB files
    let (mut bytes1, mut files1) = (0u64, 0u64);
    let stage1_err;
    loop {
        rng.fill(&mut buf);
        let mut f = match OpenOptions::new().write(true).create_new(true).open(dir.join(format!("bulk-{files1:05}"))) {
            Ok(f) => f,
            Err(e) => {
                stage1_err = e;
                break;
            }
        };
        files1 += 1;
        let (w, err) = write_counting(&mut f, &buf, 64 * MIB);
        bytes1 += w;
        if let Some(e) = err {
            stage1_err = e;
            break;
        }
    }
    // stage 2: 4 KiB writes into one file
    let mut bytes2 = 0u64;
    let stage2_err: Option<std::io::Error>;
    {
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(dir.join("bulk-4k"))?;
        let chunk = &buf[..4096];
        loop {
            match f.write(chunk) {
                Ok(k) => bytes2 += k as u64,
                Err(e) => {
                    stage2_err = Some(e);
                    break;
                }
            }
        }
    }
    // stage 3: tiny files until create/write fails (exhausts metadata)
    let tiny = &buf[..900];
    let mut tiny_files = 0u64;
    let mut stage3_err = None;
    for i in 0..400_000u64 {
        let p = dir.join(format!("tiny-{i:06}"));
        match OpenOptions::new().write(true).create_new(true).open(&p).and_then(|mut f| f.write_all(tiny)) {
            Ok(()) => tiny_files += 1,
            Err(e) => {
                stage3_err = Some(e);
                break;
            }
        }
    }
    Ok(json!({
        "stage1_bulk": { "bytes": bytes1, "files": files1, "ended_with": stage1_err.to_string(), "enospc": is_enospc(&stage1_err) },
        "stage2_4k": { "bytes": bytes2, "ended_with": stage2_err.as_ref().map(ToString::to_string), "enospc": stage2_err.as_ref().is_some_and(is_enospc) },
        "stage3_tiny": { "files": tiny_files, "ended_with": stage3_err.as_ref().map(ToString::to_string), "enospc": stage3_err.as_ref().is_some_and(is_enospc) },
        "fill_seconds": t0.elapsed().as_secs_f64(),
    }))
}

fn tombstone_txn(db: &Database, i: u32, value_len: usize) -> std::result::Result<(), String> {
    let run = || -> Result<()> {
        let w = db.begin_write()?;
        {
            let mut t = w.open_table(STATE)?;
            t.remove(format!("frame/{i:04}").as_str())?;
            let v = vec![0xEEu8; value_len];
            t.insert(format!("tomb/{i:04}").as_str(), v.as_slice())?;
        }
        w.commit()?;
        Ok(())
    };
    run().map_err(|e| format!("{e:#}"))
}

fn batch(db: &Database, range: std::ops::Range<u32>, value_len: usize) -> (usize, usize, Option<String>) {
    let (mut ok, mut fail, mut first) = (0, 0, None);
    for i in range {
        match tombstone_txn(db, i, value_len) {
            Ok(()) => ok += 1,
            Err(e) => {
                fail += 1;
                first.get_or_insert(e);
            }
        }
    }
    (ok, fail, first)
}

fn wait_avail_at_least(path: &Path, target: u64, max: Duration) -> Result<Duration> {
    let t0 = Instant::now();
    while t0.elapsed() < max {
        if avail_bytes(path)? >= target {
            break;
        }
        sleep(Duration::from_millis(200));
    }
    Ok(t0.elapsed())
}

/// Run F0-4.
pub fn run(ctx: &Ctx, a: &Args) -> Result<ExpOutput> {
    let pool = ScratchPool::create(&ctx.root, "f04", FsKind::Btrfs, a.pool_mib, ctx.max_pool_gib)?;
    let mnt = pool.mnt().to_path_buf();
    let top = File::open(&mnt)?;
    let mut rng = SplitMix64::new(ctx.seed);
    let a0 = avail_bytes(&mnt)?;

    // meta/ with an open redb (as agentd would keep it)
    std::fs::create_dir_all(mnt.join("meta"))?;
    let db_path = mnt.join("meta/aether.redb");
    let db = Database::create(&db_path)?;
    {
        let w = db.begin_write()?;
        {
            let mut t = w.open_table(STATE)?;
            let v = [0x11u8; 256];
            for i in 0..2000u32 {
                t.insert(format!("frame/{i:04}").as_str(), v.as_slice())?;
            }
        }
        w.commit()?;
    }

    // two victim subvolumes (so there is something to destroy), a ballast, then fill
    let victim_each = a.victim_mib / 2;
    for name in ["victim-a", "victim-b"] {
        ioctls::btrfs_subvol_create(&top, name).map_err(|e| anyhow!("SUBVOL_CREATE_V2 {name}: {e}"))?;
        let dir = mnt.join(name);
        let mut buf = vec![0u8; MIB as usize];
        for i in 0..victim_each {
            rng.fill(&mut buf);
            std::fs::write(dir.join(format!("blob-{i:04}")), &buf)?;
        }
    }
    let ballast_path = mnt.join("ballast");
    {
        let b = OpenOptions::new().write(true).create_new(true).open(&ballast_path)?;
        nix::fcntl::posix_fallocate(b.as_raw_fd(), 0, (a.ballast_mib * MIB) as i64)
            .map_err(|e| anyhow!("posix_fallocate ballast: {e}"))?;
        b.sync_all()?;
    }
    ioctls::btrfs_sync(&top)?;
    let avail_with_victims_and_ballast = avail_bytes(&mnt)?;

    let fill = fill_to_enospc(&mnt.join("fill"), &mut rng)?;
    let _ = ioctls::btrfs_sync(&top); // may itself fail with ENOSPC; recorded below
    let avail_full = avail_bytes(&mnt)?;
    let df_full = String::from_utf8_lossy(&run_any("btrfs", &["filesystem", "df", "-b", mnt.to_str().unwrap()])?.stdout).into_owned();

    let mut probes_full = Vec::new();

    // (1) redb at ENOSPC: realistic tiny tombstones, then a file-growing transaction
    let (ok, fail, first) = batch(&db, 0..20, 64);
    probes_full.push(probe(
        "redb tombstone txns (64 B values) x20 at ENOSPC",
        fail == 0,
        format!("{ok} committed, {fail} failed{}", first.map_or(String::new(), |e| format!("; first error: {e}"))),
    ));
    let tomb_small_failed = fail;
    let (ok, fail, first) = batch(&db, 20..25, 2 * MIB as usize);
    probes_full.push(probe(
        "redb growth txns (2 MiB values) x5 at ENOSPC",
        fail == 0,
        format!("{ok} committed, {fail} failed{}", first.map_or(String::new(), |e| format!("; first error: {e}"))),
    ));
    // can a *new* redb file be created in meta/ ?
    let r = Database::create(mnt.join("meta/second.redb")).map(|_| ()).map_err(|e| e.to_string());
    probes_full.push(probe("create a second redb file at ENOSPC", r.is_ok(), r.err().unwrap_or_else(|| "ok".into())));

    // (2) subvolume destroy and unlink while full
    let r = ioctls::btrfs_snap_destroy(&top, "victim-a");
    probes_full.push(probe("destroy subvolume victim-a at ENOSPC (before releasing ballast)", r.is_ok(), match &r { Ok(api) => format!("ok via {api:?}"), Err(e) => e.to_string() }));
    let victim_a_destroyed_early = r.is_ok();
    let r = std::fs::remove_file(mnt.join("fill/tiny-000000"));
    probes_full.push(probe("unlink a tiny file at ENOSPC", r.is_ok(), r.map_or_else(|e| e.to_string(), |()| "ok".into())));
    let r = OpenOptions::new().write(true).create_new(true).open(mnt.join("fill/new-small")).and_then(|mut f| f.write_all(&[1u8; 900]));
    probes_full.push(probe("create+write a new 900 B file at ENOSPC (control: expected to fail)", r.is_ok(), r.map_or_else(|e| e.to_string(), |()| "ok".into())));

    // (3) release the ballast
    let avail_before_release = avail_bytes(&mnt)?;
    std::fs::remove_file(&ballast_path)?;
    let sync_res = ioctls::btrfs_sync(&top);
    let waited = wait_avail_at_least(&mnt, avail_before_release + a.ballast_mib * MIB / 2, Duration::from_secs(60))?;
    let avail_after_release = avail_bytes(&mnt)?;
    let released = avail_after_release.saturating_sub(avail_before_release);

    // reopen redb (a failed commit may leave the handle poisoned) and verify integrity
    drop(db);
    let reopen: std::result::Result<(bool, usize), String> = (|| {
        let mut d = Database::open(&db_path).map_err(|e| e.to_string())?;
        let ok = d.check_integrity().map_err(|e| e.to_string())?;
        let rtxn = d.begin_read().map_err(|e| e.to_string())?;
        let t = rtxn.open_table(STATE).map_err(|e| e.to_string())?;
        let n = redb::ReadableTableMetadata::len(&t).map_err(|e| e.to_string())? as usize;
        Ok((ok, n as usize))
    })();
    let db = Database::open(&db_path)?;

    let mut probes_after = Vec::new();
    probes_after.push(probe(
        "BTRFS_IOC_SYNC after unlinking ballast",
        sync_res.is_ok(),
        format!("{:?}; avail +{} MiB after {:.2}s (ballast {} MiB)", sync_res.as_ref().err(), released / MIB, waited.as_secs_f64(), a.ballast_mib),
    ));
    probes_after.push(probe(
        "redb reopen + integrity check after the failed-commit episode",
        reopen.as_ref().is_ok_and(|(ok, _)| *ok),
        match &reopen { Ok((ok, n)) => format!("integrity={ok}, {n} keys"), Err(e) => e.clone() },
    ));
    let (ok, fail, first) = batch(&db, 25..45, 64);
    probes_after.push(probe(
        "redb tombstone txns x20 after ballast release",
        fail == 0,
        format!("{ok} committed, {fail} failed{}", first.map_or(String::new(), |e| format!("; first error: {e}"))),
    ));
    let mut destroy_after = Vec::new();
    for name in ["victim-a", "victim-b"] {
        if name == "victim-a" && victim_a_destroyed_early {
            continue;
        }
        let r = ioctls::btrfs_snap_destroy(&top, name);
        destroy_after.push(r.is_ok());
        probes_after.push(probe(&format!("destroy subvolume {name} after ballast release"), r.is_ok(), match &r { Ok(api) => format!("ok via {api:?}"), Err(e) => e.to_string() }));
    }
    let (_, drain) = timed(|| run_any("btrfs", &["subvolume", "sync", mnt.to_str().unwrap()]));
    let avail_after_destroy = avail_bytes(&mnt)?;

    // reclaim the filler and compare with the pristine free space
    let (r, rm_t) = timed(|| std::fs::remove_dir_all(mnt.join("fill")));
    probes_after.push(probe("remove the filler tree", r.is_ok(), r.map_or_else(|e| e.to_string(), |()| format!("{:.1}s", rm_t.as_secs_f64()))));
    let _ = ioctls::btrfs_sync(&top);
    let (_, drain2) = timed(|| run_any("btrfs", &["subvolume", "sync", mnt.to_str().unwrap()]));
    sleep(Duration::from_secs(2));
    let avail_final = avail_bytes(&mnt)?;
    let recovered_pct = 100.0 * (avail_final as f64) / (a0 as f64);

    // final functional sanity
    let sanity_subvol = ioctls::btrfs_subvol_create(&top, "post-recovery").is_ok();
    let sanity_redb = tombstone_txn(&db, 45, 64).is_ok();
    let sanity_file = std::fs::write(mnt.join("post-recovery-file"), vec![7u8; 1 << 20]).is_ok();
    probes_after.push(probe("post-recovery: create subvolume / redb commit / write 1 MiB", sanity_subvol && sanity_redb && sanity_file, format!("subvol={sanity_subvol} redb={sanity_redb} file={sanity_file}")));

    let pivot = tomb_small_failed > 0;
    let verdict = if pivot {
        "**PIVOT TRIGGERED**: a tombstone-sized redb transaction failed at ENOSPC on the same pool -> `meta/` MUST live on a separate disk/filesystem from the data pool.".to_owned()
    } else {
        let growth_failed = probes_full.iter().any(|p| p.name.starts_with("redb growth") && !p.ok);
        format!(
            "**Pivot NOT triggered by the tombstone probe**: all 20 tombstone-sized redb txns committed at ENOSPC. File-growing redb txns {} at ENOSPC. \
             Recommendation: keep `meta/` off the data pool anyway when possible (growth txns / WAL-style growth are not safe at ENOSPC); the pre-allocated ballast is the guaranteed escape hatch if it shares the pool.",
            if growth_failed { "FAILED" } else { "also succeeded" }
        )
    };

    let all_after_ok = probes_after.iter().all(|p| p.ok);
    let mut md = String::new();
    md.push_str("# F0-4 - pool-full (`ENOSPC`) and ballast recovery drill (Btrfs)\n\n## Parameters\n\n");
    md.push_str(&format!(
        "- pool: Btrfs on loop (`direct_io={}`), {} MiB; ballast {} MiB (`posix_fallocate`); 2 victim subvolumes ({} MiB total); `redb` in `meta/` on the same pool\n- fill: 1 MiB writes into 64 MiB files, then 4 KiB writes, then up to 400k tiny (900 B, inline) files until the first failure\n\n",
        pool.direct_io, a.pool_mib, a.ballast_mib, a.victim_mib
    ));
    md.push_str("## Space accounting (MiB available per `statvfs`)\n\n| moment | avail MiB |\n| --- | ---: |\n");
    for (k, v) in [
        ("pristine (after mount)", a0),
        ("after victims + ballast", avail_with_victims_and_ballast),
        ("pool full", avail_full),
        ("full, just before ballast release", avail_before_release),
        ("after ballast release (+sync)", avail_after_release),
        ("after victim subvolumes destroyed + cleaner drained", avail_after_destroy),
        ("after filler removed (final)", avail_final),
    ] {
        md.push_str(&format!("| {k} | {} |\n", v / MIB));
    }
    md.push_str(&format!("\nFinal free space = **{recovered_pct:.2} %** of pristine (cleaner drain: destroy {:.1}s, final {:.1}s; redb file + `post-recovery*` objects account for the remainder).\n\n", drain.as_secs_f64(), drain2.as_secs_f64()));
    md.push_str(&format!("## Fill outcome\n\n```json\n{}\n```\n\n`btrfs filesystem df -b` at ENOSPC:\n\n```\n{}\n```\n\n", serde_json::to_string_pretty(&fill)?, df_full.trim()));
    md.push_str("## Probes while the pool is full (ballast still present)\n\n| probe | result | detail |\n| --- | :---: | --- |\n");
    for p in &probes_full {
        md.push_str(&format!("| {} | {} | {} |\n", p.name, if p.ok { "OK" } else { "FAIL" }, p.detail.replace('|', "\\|").replace('\n', " ")));
    }
    md.push_str("\n## Recovery after releasing the ballast\n\n| probe | result | detail |\n| --- | :---: | --- |\n");
    for p in &probes_after {
        md.push_str(&format!("| {} | {} | {} |\n", p.name, if p.ok { "OK" } else { "FAIL" }, p.detail.replace('|', "\\|").replace('\n', " ")));
    }
    md.push_str(&format!("\n## Verdict\n\n{verdict}\n\nRecovery after ballast release fully functional: **{all_after_ok}**.\n"));

    let json = json!({
        "params": { "pool_mib": a.pool_mib, "ballast_mib": a.ballast_mib, "victim_mib": a.victim_mib, "seed": ctx.seed, "direct_io": pool.direct_io },
        "avail_bytes": { "pristine": a0, "with_victims_and_ballast": avail_with_victims_and_ballast, "full": avail_full,
                          "before_release": avail_before_release, "after_release": avail_after_release,
                          "after_destroy": avail_after_destroy, "final": avail_final },
        "recovered_pct_of_pristine": recovered_pct,
        "fill": fill,
        "btrfs_df_at_enospc": df_full,
        "probes_full": probes_full,
        "probes_after_release": probes_after,
        "gate": { "tombstone_failures_at_enospc": tomb_small_failed, "pivot_triggered": pivot },
        "recovery_fully_functional": all_after_ok,
        "verdict": verdict,
    });

    drop(db);
    drop(top);
    drop(pool);
    Ok(ExpOutput { id: "F0-4", slug: "f0-4-enospc-ballast", json, md })
}
