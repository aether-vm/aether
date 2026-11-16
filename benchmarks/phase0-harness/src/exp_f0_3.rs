//! F0-3: many-small-file import (`node_modules` + Git repo), mount-free materialisation with
//! `mkfs.ext4 -d`, UID/GID/mode fidelity, and first `git status` behaviour after a Btrfs
//! subvolume fork (does `st_dev` / `ctime` change trigger a full re-hash?).

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::ioctls;
use crate::pool::{FsKind, ScratchPool};
use crate::report::ExpOutput;
use crate::util::{drop_caches, fmt_ms, run as run_cmd, run_any, timed, SplitMix64, MIB};
use crate::Ctx;

/// Parameters.
#[derive(Debug, Clone)]
pub struct Args {
    /// Pool size in MiB.
    pub pool_mib: u64,
    /// File counts to test.
    pub files: Vec<u64>,
}

const OWNERS: [u32; 4] = [0, 1000, 1234, 65534];

/// Result for one file count.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Row {
    /// Files created (regular files only).
    pub files: u64,
    /// Directories created (incl. `.git`).
    pub dirs_total: u64,
    /// Entries in `.git`.
    pub git_entries: u64,
    /// Bytes of file data (apparent, excl. `.git`).
    pub data_bytes: u64,
    /// Time to generate the tree (ms).
    pub populate_ms: f64,
    /// `git add -A && git commit` (ms).
    pub git_add_commit_ms: f64,
    /// `tar -cf` of the tree (not a measured quantity, ms).
    pub tar_create_ms: f64,
    /// `tar -xpf --numeric-owner` unpack into a fresh subvolume (ms).
    pub unpack_ms: f64,
    /// `mkfs.ext4 -d` materialisation (ms).
    pub mkfs_d_ms: f64,
    /// Image size (MiB).
    pub image_mib: u64,
    /// Inodes requested for the image.
    pub image_inodes: u64,
    /// `e2fsck -fn` exit status of the image.
    pub e2fsck_exit: i32,
    /// UID/GID/mode samples checked via `debugfs`.
    pub uid_samples: usize,
    /// Samples whose uid/gid/mode did not match the source.
    pub uid_mismatches: usize,
    /// Btrfs snapshot (fork) latency (ms).
    pub fork_snapshot_ms: f64,
    /// Warm `git status` in the original (ms), 2nd run.
    pub status_orig_warm_ms: f64,
    /// First `git status` in the fork (ms).
    pub status_fork_first_ms: f64,
    /// Second `git status` in the fork (ms).
    pub status_fork_second_ms: f64,
    /// First `git status` in the fork after `drop_caches` (cold) (ms).
    pub status_fork_cold_ms: f64,
    /// `git status --porcelain` produced output in the fork (should be empty).
    pub status_fork_dirty_output: bool,
    /// Did the first `git status` in the fork rewrite `.git/index` (stat refresh happened)?
    pub index_rewritten_by_first_fork_status: bool,
    /// Index entries sampled for stat comparison.
    pub stat_samples: usize,
    /// Per-field mismatch counts between the index's cached stat and the fork's real stat.
    pub stat_mismatch: HashMap<String, usize>,
}

fn rd_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn git(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .args([
            "-c", "safe.directory=*", "-c", "user.name=phase0", "-c", "user.email=phase0@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "gc.auto=0", "-c", "core.fsmonitor=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("HOME", "/root");
    c
}

fn git_ok(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    let o = git(dir, args).output().with_context(|| format!("spawn git {args:?}"))?;
    if !o.status.success() {
        bail!("git {args:?} in {}: {}", dir.display(), String::from_utf8_lossy(&o.stderr));
    }
    Ok(o)
}

/// Generate `n` small files under `dir/node_modules/pkg-XXXXX/lib/`, uid/gid by package.
fn populate(dir: &Path, n: u64, rng: &mut SplitMix64) -> Result<(u64, u64, Vec<PathBuf>)> {
    let per_dir = 20u64;
    let pkgs = n.div_ceil(per_dir);
    let mut lorem = vec![0u8; 16 * 1024];
    for (i, b) in lorem.iter_mut().enumerate() {
        *b = b"abcdefghijklmnopqrstuvwxyz0123456789 \n;(){}"[(i * 7 + i / 13) % 43];
    }
    std::fs::create_dir_all(dir.join("node_modules"))?;
    let mut created = 0u64;
    let mut bytes = 0u64;
    let mut sample = Vec::new();
    let mut dirs = 1u64;
    for p in 0..pkgs {
        let owner = OWNERS[(p % 4) as usize];
        let pdir = dir.join(format!("node_modules/pkg-{p:05}"));
        let ldir = pdir.join("lib");
        std::fs::create_dir_all(&ldir)?;
        dirs += 2;
        let _ = dirs;
        chown(&pdir, Some(owner), Some(owner))?;
        chown(&ldir, Some(owner), Some(owner))?;
        for j in 0..per_dir {
            if created == n {
                break;
            }
            let size = 256 + rng.below(7936) as usize;
            let start = rng.below(8192) as usize;
            let mut data = format!("// pkg-{p:05} file-{j:02}\n").into_bytes();
            data.extend_from_slice(&lorem[start..start + size.min(8192)]);
            let path = ldir.join(format!("f{j:02}.js"));
            std::fs::write(&path, &data)?;
            chown(&path, Some(owner), Some(owner))?;
            let mode = if created % 10 == 0 { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
            bytes += data.len() as u64;
            if created % 997 == 0 {
                sample.push(path);
            }
            created += 1;
        }
    }
    Ok((created, bytes, sample))
}

fn walk_stats(dir: &Path) -> (u64, u64, u64) {
    // (blocks_bytes, entries, dirs)
    let mut stack = vec![dir.to_path_buf()];
    let (mut bytes, mut entries, mut dirs) = (0u64, 0u64, 0u64);
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        dirs += 1;
        for e in rd.flatten() {
            entries += 1;
            let Ok(md) = e.metadata() else { continue };
            if md.is_dir() {
                stack.push(e.path());
                bytes += 4096;
            } else {
                bytes += md.len().div_ceil(4096) * 4096;
            }
        }
    }
    (bytes, entries, dirs)
}

#[derive(Debug, Clone, Copy)]
struct IndexStat {
    ctime: (u32, u32),
    mtime: (u32, u32),
    dev: u32,
    ino: u32,
    uid: u32,
    gid: u32,
    size: u32,
}

/// Parse `git ls-files --debug` output: `path\n  ctime: s:ns\n  mtime: s:ns\n  dev: D\tino: I\n  uid: U\tgid: G\n  size: S\tflags: F`.
fn parse_ls_files_debug(text: &str) -> Vec<(String, IndexStat)> {
    fn pair(s: &str) -> (u32, u32) {
        let mut it = s.trim().split(':');
        (it.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0), it.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0))
    }
    fn kv(line: &str) -> Vec<(&str, u32)> {
        line.split('\t')
            .filter_map(|p| p.trim().split_once(':').map(|(k, v)| (k.trim(), v.trim().parse().unwrap_or(0))))
            .collect()
    }
    let mut out = Vec::new();
    let mut cur: Option<(String, IndexStat)> = None;
    for line in text.lines() {
        if !line.starts_with("  ") {
            if let Some(c) = cur.take() {
                out.push(c);
            }
            cur = Some((
                line.to_owned(),
                IndexStat { ctime: (0, 0), mtime: (0, 0), dev: 0, ino: 0, uid: 0, gid: 0, size: 0 },
            ));
        } else if let Some((_, st)) = cur.as_mut() {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("ctime:") {
                st.ctime = pair(v);
            } else if let Some(v) = t.strip_prefix("mtime:") {
                st.mtime = pair(v);
            } else if t.starts_with("dev:") {
                for (k, v) in kv(t) {
                    match k {
                        "dev" => st.dev = v,
                        "ino" => st.ino = v,
                        _ => {}
                    }
                }
            } else if t.starts_with("uid:") {
                for (k, v) in kv(t) {
                    match k {
                        "uid" => st.uid = v,
                        "gid" => st.gid = v,
                        _ => {}
                    }
                }
            } else if t.starts_with("size:") {
                for (k, v) in kv(t) {
                    if k == "size" {
                        st.size = v;
                    }
                }
            }
        }
    }
    if let Some(c) = cur.take() {
        out.push(c);
    }
    out
}

fn compare_index_stat(fork: &Path, sample_every: usize) -> Result<(usize, HashMap<String, usize>)> {
    let o = git_ok(fork, &["ls-files", "--debug"])?;
    let entries = parse_ls_files_debug(&String::from_utf8_lossy(&o.stdout));
    let mut mism: HashMap<String, usize> = ["dev", "ino", "ctime", "mtime", "uid", "gid", "size"]
        .iter()
        .map(|k| ((*k).to_owned(), 0))
        .collect();
    let mut n = 0;
    for (path, st) in entries.iter().step_by(sample_every.max(1)) {
        let Ok(md) = std::fs::symlink_metadata(fork.join(path)) else { continue };
        n += 1;
        let mut bump = |k: &str, differs: bool| {
            if differs {
                *mism.get_mut(k).unwrap() += 1;
            }
        };
        bump("dev", st.dev != md.dev() as u32);
        bump("ino", st.ino != md.ino() as u32);
        bump("ctime", st.ctime != (md.ctime() as u32, md.ctime_nsec() as u32));
        bump("mtime", st.mtime != (md.mtime() as u32, md.mtime_nsec() as u32));
        bump("uid", st.uid != md.uid());
        bump("gid", st.gid != md.gid());
        bump("size", st.size != md.size() as u32);
    }
    Ok((n, mism))
}

fn verify_uids(img: &Path, src_root: &Path, sample: &[PathBuf]) -> Result<(usize, usize)> {
    // one debugfs invocation, one `stat` per sampled file
    let mut script = String::new();
    let mut expect = Vec::new();
    for p in sample {
        let rel = p.strip_prefix(src_root)?;
        script.push_str(&format!("stat /{}\n", rel.display()));
        let md = std::fs::metadata(p)?;
        expect.push((md.uid(), md.gid(), md.mode() & 0o7777));
    }
    let cmd_file = img.with_extension("debugfs");
    std::fs::write(&cmd_file, script)?;
    let o = run_any("debugfs", &["-f", cmd_file.to_str().unwrap(), img.to_str().unwrap()])?;
    let _ = std::fs::remove_file(&cmd_file);
    let text = String::from_utf8_lossy(&o.stdout);
    let mut got = Vec::new();
    let mut mode = None;
    for line in text.lines() {
        // "Inode: 12   Type: regular    Mode:  0644   Flags: 0x80000"
        if let Some(i) = line.find("Mode:") {
            let m = line[i + 5..].split_whitespace().next().unwrap_or("0");
            mode = u32::from_str_radix(m, 8).ok();
        }
        // "User:  1234   Group:  1234   Project:     0   Size: 1234"
        if line.starts_with("User:") {
            let f: Vec<&str> = line.split_whitespace().collect();
            let uid = f.get(1).and_then(|x| x.parse::<u32>().ok());
            let gid = f.get(3).and_then(|x| x.parse::<u32>().ok());
            if let (Some(u), Some(g), Some(m)) = (uid, gid, mode.take()) {
                got.push((u, g, m));
            }
        }
    }
    if got.len() != expect.len() {
        bail!("debugfs returned {} stat blocks for {} samples:\n{}", got.len(), expect.len(), &text[..text.len().min(600)]);
    }
    let mism = got.iter().zip(&expect).filter(|(g, e)| g != e).count();
    Ok((expect.len(), mism))
}

fn status_time(dir: &Path) -> Result<(Duration, bool)> {
    let t0 = Instant::now();
    let o = git_ok(dir, &["status", "--porcelain"])?;
    Ok((t0.elapsed(), !o.stdout.is_empty()))
}

fn one(ctx: &Ctx, pool: &ScratchPool, n: u64) -> Result<Row> {
    let mnt = pool.mnt();
    let top = File::open(mnt)?;
    let mut rng = SplitMix64::new(ctx.seed ^ n);
    let mut row = Row { files: n, ..Default::default() };
    let src = mnt.join(format!("src-{n}"));
    ioctls::btrfs_subvol_create(&top, &format!("src-{n}")).map_err(|e| anyhow!("SUBVOL_CREATE_V2: {e}"))?;

    // 1. populate (stand-in for unpacking a tarball) + git repo
    let (res, d) = timed(|| populate(&src, n, &mut rng));
    let (created, data_bytes, _sample) = res?;
    row.files = created;
    row.data_bytes = data_bytes;
    row.populate_ms = rd_ms(d);
    git_ok(&src, &["init", "-q"])?;
    let (r, d) = timed(|| -> Result<()> {
        git_ok(&src, &["add", "-A"])?;
        git_ok(&src, &["commit", "-q", "-m", "import"])?;
        Ok(())
    });
    r?;
    row.git_add_commit_ms = rd_ms(d);
    let (_, git_entries, git_dirs) = walk_stats(&src.join(".git"));
    row.git_entries = git_entries;
    let (_, _, tree_dirs) = walk_stats(&src);
    row.dirs_total = tree_dirs;
    let _ = git_dirs;

    // 2. tar -> unpack into a fresh subvolume (preserving numeric owners), then mkfs.ext4 -d
    let tar = mnt.join(format!("src-{n}.tar"));
    let (r, d) = timed(|| run_cmd("tar", &["-C", src.to_str().unwrap(), "--numeric-owner", "-cf", tar.to_str().unwrap(), "."]));
    r?;
    row.tar_create_ms = rd_ms(d);
    ioctls::btrfs_subvol_create(&top, &format!("unpack-{n}")).map_err(|e| anyhow!("SUBVOL_CREATE_V2: {e}"))?;
    let unpack = mnt.join(format!("unpack-{n}"));
    let (r, d) = timed(|| run_cmd("tar", &["-C", unpack.to_str().unwrap(), "--numeric-owner", "-xpf", tar.to_str().unwrap()]));
    r?;
    row.unpack_ms = rd_ms(d);
    std::fs::remove_file(&tar)?;

    let (used, entries, _) = walk_stats(&unpack);
    let inodes = ((entries as f64) * 1.3) as u64 + 2048;
    let image_mib = ((used as f64 * 1.35) as u64 / MIB) + inodes * 256 / MIB + 64;
    row.image_mib = image_mib;
    row.image_inodes = inodes;
    let img = mnt.join(format!("rootfs-{n}.ext4"));
    File::create(&img)?.set_len(image_mib * MIB)?;
    let (r, d) = timed(|| {
        run_cmd(
            "mkfs.ext4",
            &["-q", "-F", "-N", &inodes.to_string(), "-d", unpack.to_str().unwrap(), img.to_str().unwrap()],
        )
    });
    r?;
    row.mkfs_d_ms = rd_ms(d);
    let fsck = run_any("e2fsck", &["-fn", img.to_str().unwrap()])?;
    row.e2fsck_exit = fsck.status.code().unwrap_or(-1);
    // uid check on a sample of the *unpacked* tree
    let mut s2 = Vec::new();
    for e in std::fs::read_dir(unpack.join("node_modules"))?.flatten().take(64) {
        let f = e.path().join("lib/f01.js");
        if f.exists() {
            s2.push(f);
        }
    }
    let (n_s, mism) = verify_uids(&img, &unpack, &s2)?;
    row.uid_samples = n_s;
    row.uid_mismatches = mism;
    std::fs::remove_file(&img)?;
    drop(top);

    // 3. fork the original repo subvolume and look at git's behaviour
    let top = File::open(mnt)?;
    let srcdir = File::open(&src)?;
    let (_, _) = status_time(&src)?; // first run refreshes racy entries
    let (warm, _) = status_time(&src)?;
    row.status_orig_warm_ms = rd_ms(warm);
    nix::unistd::sync();
    let fork_name = format!("fork-{n}");
    let (r, d) = timed(|| ioctls::btrfs_snap_create(&top, &srcdir, &fork_name, false));
    r.map_err(|e| anyhow!("SNAP_CREATE_V2: {e}"))?;
    row.fork_snapshot_ms = rd_ms(d);
    let fork = mnt.join(&fork_name);
    let (nstat, mism) = compare_index_stat(&fork, ((n / 2000).max(1)) as usize)?;
    row.stat_samples = nstat;
    row.stat_mismatch = mism;
    let idx_before = std::fs::read(fork.join(".git/index"))?;
    let (first, dirty) = status_time(&fork)?;
    row.status_fork_first_ms = rd_ms(first);
    row.status_fork_dirty_output = dirty;
    let idx_after = std::fs::read(fork.join(".git/index"))?;
    row.index_rewritten_by_first_fork_status = idx_before != idx_after;
    let (second, _) = status_time(&fork)?;
    row.status_fork_second_ms = rd_ms(second);
    drop_caches()?;
    let (cold, _) = status_time(&fork)?;
    row.status_fork_cold_ms = rd_ms(cold);

    // cleanup for the next size
    drop(srcdir);
    for name in [fork_name, format!("unpack-{n}"), format!("src-{n}")] {
        ioctls::btrfs_snap_destroy(&top, &name).map_err(|e| anyhow!("destroy {name}: {e}"))?;
    }
    let _ = run_any("btrfs", &["subvolume", "sync", mnt.to_str().unwrap()]);
    Ok(row)
}

/// Run F0-3.
pub fn run(ctx: &Ctx, a: &Args) -> Result<ExpOutput> {
    let mut pool = ScratchPool::create(&ctx.root, "f03", FsKind::Btrfs, a.pool_mib, ctx.max_pool_gib)?;
    let mut rows = Vec::new();
    for &n in &a.files {
        eprintln!("  [f0-3] {n} files ...");
        rows.push(one(ctx, &pool, n)?);
    }
    let direct_io = pool.direct_io;
    pool.teardown()?;

    // linear coefficients between the smallest and largest run
    let coef = |f: fn(&Row) -> f64| -> Option<f64> {
        let (lo, hi) = (rows.first()?, rows.last()?);
        (hi.files > lo.files).then(|| (f(hi) - f(lo)) * 1e3 / (hi.files - lo.files) as f64)
    };
    let c_mkfs = coef(|r| r.mkfs_d_ms);
    let c_unpack = coef(|r| r.unpack_ms);
    let c_pop = coef(|r| r.populate_ms);

    let uid_ok = rows.iter().all(|r| r.uid_mismatches == 0 && r.uid_samples > 0);
    let fork_rehash = rows.iter().any(|r| {
        r.index_rewritten_by_first_fork_status
            || r.status_fork_first_ms > r.status_orig_warm_ms * 3.0 + 50.0
            || r.stat_mismatch.iter().any(|(k, v)| k != "dev" && *v > 0)
    });
    let dev_changed = rows.iter().any(|r| r.stat_mismatch.get("dev").copied().unwrap_or(0) > 0);

    let mut md = String::new();
    md.push_str("# F0-3 - small-file import, mount-free `mkfs.ext4 -d` materialisation, `git status` after fork\n\n## Parameters\n\n");
    md.push_str(&format!(
        "- pool: Btrfs on loop (`direct_io={direct_io}`), {} MiB; file counts {:?}\n- tree: `node_modules/pkg-NNNNN/lib/fNN.js`, 20 files/pkg, sizes 256 B - 8 KiB, owners cycle through uid:gid 0, 1000, 1234, 65534 per package; every 10th file 0755; plus a real Git repository (`git add -A && git commit`)\n- \"unpack\" = `tar -xpf --numeric-owner` of the tree into a fresh subvolume as root; materialisation = `mkfs.ext4 -d` of that tree (no mount of the image); UID/GID/mode verified via `debugfs stat` on sampled files\n- fork = `BTRFS_IOC_SNAP_CREATE_V2` of the Git subvolume; stat-compat checked with `git ls-files --debug` vs real `lstat`\n\n",
        a.pool_mib, a.files
    ));
    md.push_str("## Results\n\n| files | dirs | data (MiB) | populate (ms) | git add+commit (ms) | tar unpack (ms) | **mkfs.ext4 -d (ms)** | image (MiB) | e2fsck | uid/gid/mode mismatches |\n| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for r in &rows {
        md.push_str(&format!(
            "| {} | {} | {:.1} | {} | {} | {} | **{}** | {} | {} | {}/{} |\n",
            r.files, r.dirs_total, r.data_bytes as f64 / MIB as f64, fmt_ms(r.populate_ms * 1e3), fmt_ms(r.git_add_commit_ms * 1e3),
            fmt_ms(r.unpack_ms * 1e3), fmt_ms(r.mkfs_d_ms * 1e3), r.image_mib, r.e2fsck_exit, r.uid_mismatches, r.uid_samples
        ));
    }
    md.push_str("\n### Linear cost coefficients (largest vs smallest run)\n\n");
    md.push_str(&format!(
        "- `mkfs.ext4 -d`: {} us/file; tar unpack: {} us/file; tree generation: {} us/file\n\n",
        c_mkfs.map_or("n/a".into(), |v| format!("{v:.1}")),
        c_unpack.map_or("n/a".into(), |v| format!("{v:.1}")),
        c_pop.map_or("n/a".into(), |v| format!("{v:.1}"))
    ));
    md.push_str("### `git status` after a subvolume fork\n\n| files | warm status in original (ms) | **first status in fork (ms)** | second (ms) | cold (drop_caches) (ms) | index rewritten by 1st fork status | porcelain dirty | snapshot (ms) |\n| ---: | ---: | ---: | ---: | ---: | :---: | :---: | ---: |\n");
    for r in &rows {
        md.push_str(&format!(
            "| {} | {} | **{}** | {} | {} | {} | {} | {} |\n",
            r.files, fmt_ms(r.status_orig_warm_ms * 1e3), fmt_ms(r.status_fork_first_ms * 1e3), fmt_ms(r.status_fork_second_ms * 1e3),
            fmt_ms(r.status_fork_cold_ms * 1e3), r.index_rewritten_by_first_fork_status, r.status_fork_dirty_output, fmt_ms(r.fork_snapshot_ms * 1e3)
        ));
    }
    md.push_str("\n### Index-cached stat vs real stat in the fork (sampled entries; mismatch counts)\n\n| files | samples | dev | ino | ctime | mtime | uid | gid | size |\n| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for r in &rows {
        let g = |k: &str| r.stat_mismatch.get(k).copied().unwrap_or(0);
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            r.files, r.stat_samples, g("dev"), g("ino"), g("ctime"), g("mtime"), g("uid"), g("gid"), g("size")
        ));
    }
    let verdict = format!(
        "- UID/GID/mode fidelity of `mkfs.ext4 -d` from a root-unpacked tree: **{}** (zero offset expected when the unpack preserves numeric owners).\n- Btrfs fork changes `st_dev` of every file: **{}** (git ignores `st_dev` on Linux unless `core.checkStat`/`USE_STDEV` says otherwise); other stat fields (`ino`/`ctime`/`mtime`/`uid`/`gid`/`size`) preserved by the snapshot: **{}**.\n- First `git status` in the fork triggers a full re-hash / index rewrite: **{}**. {}\n",
        if uid_ok { "OK (0 mismatches)" } else { "MISMATCH - investigate" },
        dev_changed,
        rows.iter().all(|r| r.stat_mismatch.iter().all(|(k, v)| k == "dev" || *v == 0)),
        fork_rehash,
        if fork_rehash {
            "Engineering countermeasure: pre-refresh the Git index (`git update-index --refresh` / `git status`) at import time and again right after fork materialisation."
        } else {
            "No countermeasure needed on this setup; still run one `git update-index --refresh` after import to clear racy-git entries."
        }
    );
    md.push_str(&format!("\n## Findings\n\n{verdict}\n"));

    let json: Value = json!({
        "params": { "pool_mib": a.pool_mib, "files": a.files, "seed": ctx.seed, "direct_io": direct_io },
        "rows": rows,
        "coefficients_us_per_file": { "mkfs_ext4_d": c_mkfs, "tar_unpack": c_unpack, "populate": c_pop },
        "uid_fidelity_ok": uid_ok,
        "fork_changes_st_dev": dev_changed,
        "fork_triggers_rehash_or_index_rewrite": fork_rehash,
        "findings": verdict,
    });
    Ok(ExpOutput { id: "F0-3", slug: "f0-3-mkfs-git", json, md })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_git_ls_files_debug() {
        let text = "node_modules/a/f.js\n  ctime: 1700000000:123\n  mtime: 1700000001:456\n  dev: 64769\tino: 257\n  uid: 1000\tgid: 1000\n  size: 4096\tflags: 0\nb.txt\n  ctime: 1:2\n  mtime: 3:4\n  dev: 5\tino: 6\n  uid: 7\tgid: 8\n  size: 9\tflags: 0\n";
        let v = parse_ls_files_debug(text);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, "node_modules/a/f.js");
        assert_eq!(v[0].1.ctime, (1_700_000_000, 123));
        assert_eq!(v[0].1.mtime, (1_700_000_001, 456));
        assert_eq!((v[0].1.dev, v[0].1.ino, v[0].1.uid, v[0].1.gid, v[0].1.size), (64769, 257, 1000, 1000, 4096));
        assert_eq!((v[1].1.dev, v[1].1.ino, v[1].1.uid, v[1].1.gid, v[1].1.size), (5, 6, 7, 8, 9));
    }
}
