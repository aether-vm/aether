//! F0-8: Multi-process `kill -9` random fault injection & zero-orphan recovery wired to real
//! `aos-meta` (`MetaEngine::open_and_recover`, `prepare_frame`, `commit_frame`, `delete_frame`,
//! `create_world`, `collect_garbage`).
//!
//! Per `docs/PHASE0_FALSIFICATION.md` (F0-8):
//! * Parent spawns a real child worker process executing rapid `Preparing` -> `Committed` ->
//!   `Deleting` + `create_world` cycles against a real `meta/` + `pool/` + `tmpfs/` layout, then
//!   sends uncatchable `SIGKILL` (`kill -9` on Linux; `TerminateProcess` via `Child::kill` on
//!   Windows) at pseudo-random times across `rounds` iterations (default 100).
//! * On Linux with `--cgroup-root`, the worker joins `<cgroup_root>/epoch-<n>` and spawns a live
//!   sandbox sleeper grandchild inside that cgroup; after the parent `SIGKILL`s the worker, the
//!   grandchild stays alive until `MetaEngine::open_and_recover` runs R2
//!   `F08RecoveryHooks::kill_stale_epochs` -> `cgroup.kill = 1`, exercising real live-orphan
//!   termination.
//! * After every crash, parent runs `MetaEngine::open_and_recover` (R0~R6) and asserts:
//!   1. **Zero leaked child / grandchild processes** (cgroup `cgroup.procs` + OS PID liveness check).
//!   2. **Zero `Preparing` or `Deleting` frames remaining** in `redb` (I4 rollback-only invariant).
//!   3. **Zero lost committed frames** (every `commit_frame` acknowledged by the child before kill
//!      and not started for deletion survives recovery, except `Volatile` frames across a boot change,
//!      when `tmpfs_dir` is also wiped to simulate real volatile memory loss).
//!   4. **Zero unrecorded orphan objects** in `pool/objects/`, `tmpfs/`, or `pool/quarantine/`.
//!   5. **Zero surviving `Running` worlds** (all prior-epoch worlds marked `Lost` in R2).
//!   6. **R6 orphan circuit-breaker** trips cleanly without mutating objects when wild orphans exceed threshold.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, ensure, Context, Result};
use aos_meta::{
    Clock, CommitFrameRequest, CommitProofBundle, CreateWorldRequest, DeleteOutcome,
    FrameDurability, FrameState, FsArtifactBackend, Labels, ManagedObject, ManualClock, MetaConfig,
    MetaEngine, MetaError, ObjectKind, ObjectLocation, PrepareFrameRequest, RecoveryHooks,
    RecoverySummary,
};
use aos_types::{BootId, EpochId, Ephemeral, FrameId, PersistProof, Persisted};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::report::{dist_row, ExpOutput, DIST_HEADER};
use crate::stats::Dist;
use crate::util::SplitMix64;

const BOOT_A_STR: &str = "11111111-1111-4111-8111-111111111111";
const BOOT_B_STR: &str = "22222222-2222-4222-8222-222222222222";
const BASE_TIME_MS: u64 = 1_750_000_000_000;
const OWNER: &str = "f0-8-stress";
const MAX_CAPTURED_STDERR_BYTES: usize = 64 * 1024;

const KINDS: [ObjectKind; 4] = [
    ObjectKind::TreeSubvol,
    ObjectKind::DiskImage,
    ObjectKind::MemImage,
    ObjectKind::VmState,
];

/// Parent-side driver arguments for `f0-8-kill9-recovery`.
#[derive(Debug, Clone)]
pub struct Args {
    /// Number of crash-and-recover rounds (default 100).
    pub rounds: usize,
    /// Directory for `forkloom.redb` (outside `pool_dir` in production).
    pub meta_dir: PathBuf,
    /// Directory for the storage pool (`POOL_UUID`, `objects/`, `quarantine/`, `.lock`).
    pub pool_dir: PathBuf,
    /// Directory backing volatile memory objects (`tmpfs` on Linux).
    pub tmpfs_dir: PathBuf,
    /// Maximum random delay in ms before sending `SIGKILL` to the child worker.
    pub max_kill_delay_ms: u64,
    /// Simulate a host `boot_id` change every N rounds (`0` disables).
    pub reboot_every: usize,
    /// Allow `meta_dir` and `pool_dir` to reside on the same filesystem.
    pub allow_same_fs: bool,
    /// Optional cgroup v2 parent directory on Linux for live `epoch-<n>/cgroup.kill` verification.
    pub cgroup_root: Option<PathBuf>,
    /// Optional explicit worker executable path (defaults to `std::env::current_exe()`).
    pub worker_exe: Option<PathBuf>,
}

/// Child-side worker arguments for the hidden `f0-8-worker` subcommand.
#[derive(Debug, Clone)]
pub struct WorkerArgs {
    /// Metadata directory (`forkloom.redb`).
    pub meta_dir: PathBuf,
    /// Pool root directory.
    pub pool_dir: PathBuf,
    /// Volatile tmpfs directory.
    pub tmpfs_dir: PathBuf,
    /// Simulated or real host `boot_id`.
    pub boot_id: String,
    /// Deterministic PRNG seed for this round.
    pub seed: u64,
    /// Round index.
    pub round: usize,
    /// Monotonic wall-clock timestamp (ms) forwarded from the parent clock.
    pub now_ms: u64,
    /// Allow same-fs config.
    pub allow_same_fs: bool,
    /// Optional cgroup v2 parent directory on Linux; worker joins `epoch-<n>` and spawns a live
    /// sleeper grandchild so R2 `cgroup.kill` terminates a real surviving process.
    pub cgroup_root: Option<PathBuf>,
}

/// Per-round verification summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundReport {
    /// Round index (`0..rounds`).
    pub round: usize,
    /// Child PID that was `SIGKILL`ed.
    pub killed_pid: u32,
    /// Epoch assigned by `MetaEngine::open_and_recover`.
    pub recovered_epoch: u64,
    /// Whether this round simulated a host reboot (`boot_id` flip + `tmpfs_dir` wipe).
    pub simulated_reboot: bool,
    /// `Preparing` frames rolled back in R3.
    pub preparing_rolled_back: usize,
    /// `Deleting` / expired volatile / reclaimed frames finalized in R4/R5.
    pub deleting_completed: usize,
    /// Prior-epoch `Running` worlds marked `Lost` in R2.
    pub worlds_marked_lost: usize,
    /// Wild orphans quarantined in R6.
    pub orphans_quarantined: usize,
    /// Recovery duration in microseconds.
    pub recovery_us: f64,
    /// Number of surviving `Committed` frames after recovery.
    pub surviving_committed: usize,
}

/// Outcome of the standalone R6 orphan circuit-breaker verification probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakerProbe {
    /// Number of wild orphan files injected above threshold.
    pub injected_orphans: usize,
    /// Whether `MetaEngine::open_and_recover` returned `OrphanCircuitBreakerTriggered`.
    pub breaker_tripped: bool,
    /// Whether all existing objects were left completely untouched when breaker tripped.
    pub objects_untouched: bool,
}

/// Complete F0-8 report payload.
#[derive(Debug, Clone, Serialize)]
pub struct F08Report {
    /// Rounds requested and completed.
    pub rounds_completed: usize,
    /// Whether `meta_dir` and `pool_dir` were permitted on the same filesystem.
    pub allow_same_fs: bool,
    /// Whether Linux cgroup v2 `cgroup.kill` actively killed stale epoch cgroups.
    pub cgroup_v2_active: bool,
    /// Number of live sandbox grandchild processes terminated via R2 `cgroup.kill` / PID reaper.
    pub live_orphans_killed_by_r2: usize,
    /// Total `Preparing` frames rolled back across all rounds.
    pub total_preparing_rolled_back: usize,
    /// Total `Deleting` frames completed across all rounds.
    pub total_deleting_completed: usize,
    /// Total running worlds marked `Lost` across all rounds.
    pub total_worlds_marked_lost: usize,
    /// Total injected wild orphans quarantined across all rounds.
    pub total_orphans_quarantined: usize,
    /// Total simulated reboots executed.
    pub total_reboots: usize,
    /// Final surviving committed frames.
    pub final_committed_frames: usize,
    /// Invariant counters (ALL must be 0 to pass!).
    pub leaked_processes: usize,
    /// Residual `netns`/`veth` count (Linux check; must be 0).
    pub leaked_netns: usize,
    /// Unrecorded orphan objects in `pool/objects/`, `tmpfs/`, or `quarantine/` (must be 0).
    pub unrecorded_orphans: usize,
    /// Committed frames lost across crash/recovery (must be 0).
    pub lost_committed_frames: usize,
    /// Surviving non-committed frames (`Preparing`/`Deleting`) after recovery (must be 0).
    pub non_committed_survivors: usize,
    /// Surviving `Running` worlds after recovery (must be 0).
    pub running_worlds_after_recovery: usize,
    /// Missing objects for committed frames (must be 0).
    pub missing_committed_objects: usize,
    /// R6 orphan circuit-breaker probe.
    pub breaker_probe: BreakerProbe,
    /// Recovery latency distribution across all rounds (us).
    pub recovery_latency: Dist,
    /// Overall pass verdict.
    pub passed: bool,
    /// Failure reasons, if any.
    pub failures: Vec<String>,
    /// Per-round records.
    pub rounds: Vec<RoundReport>,
}

/// Recovery hooks used by F0-8 parent recovery: enforces gateway epoch fencing, triggers Linux
/// `cgroup.kill = 1` on stale `epoch-<n>` cgroups (terminating live grandchildren), and kills
/// any tracked stale PIDs as a belt-and-suspenders check.
struct F08RecoveryHooks {
    inner: FsArtifactBackend,
    cgroup_root: Option<PathBuf>,
    stale_pids: Arc<Mutex<Vec<u32>>>,
    fenced_epochs: Arc<Mutex<Vec<EpochId>>>,
    killed_cgroups: Arc<Mutex<Vec<String>>>,
    live_orphans_killed: Arc<Mutex<usize>>,
}

impl RecoveryHooks for F08RecoveryHooks {
    fn fence_gateway(&mut self, epoch: EpochId) -> io::Result<()> {
        self.fenced_epochs.lock().unwrap().push(epoch);
        self.inner.fence_gateway(epoch)
    }

    fn kill_stale_epochs(&mut self, current: EpochId) -> io::Result<()> {
        // 1. On Linux with cgroup v2, trigger `cgroup.kill` on every `epoch-<n>` with n < current
        //    and wait briefly until `cgroup.procs` drains to empty.
        #[cfg(target_os = "linux")]
        if let Some(root) = &self.cgroup_root
            && let Ok(rd) = std::fs::read_dir(root)
        {
            for entry in rd.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if let Some(ep) = EpochId::from_cgroup_dir_name(&name)
                        && ep < current
                    {
                        let procs_path = entry.path().join("cgroup.procs");
                        let live_before = std::fs::read_to_string(&procs_path)
                            .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                            .unwrap_or(0);
                        let kill_path = entry.path().join("cgroup.kill");
                        if kill_path.exists() {
                            std::fs::write(&kill_path, b"1")?;
                            self.killed_cgroups.lock().unwrap().push(name);
                            *self.live_orphans_killed.lock().unwrap() += live_before;
                            let deadline = Instant::now() + Duration::from_millis(500);
                            while Instant::now() < deadline {
                                let rem = std::fs::read_to_string(&procs_path)
                                    .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
                                    .unwrap_or(0);
                                if rem == 0 {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(5));
                            }
                        }
                    }
                }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (&self.cgroup_root, &self.killed_cgroups, &self.live_orphans_killed, current);

        // 2. Kill any tracked stale PIDs (fallback / cross-platform verification).
        let pids: Vec<u32> = std::mem::take(&mut *self.stale_pids.lock().unwrap());
        for pid in pids {
            if is_pid_alive(pid) {
                kill_pid_hard(pid);
                *self.live_orphans_killed.lock().unwrap() += 1;
            }
        }
        Ok(())
    }

    fn destroy_pool_object(&mut self, path: &Path, object: &ManagedObject) -> io::Result<()> {
        self.inner.destroy_pool_object(path, object)
    }

    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()> {
        self.inner.destroy_volatile_object(object)
    }
}

/// Hard-kill a PID (`SIGKILL` on Linux).
fn kill_pid_hard(pid: u32) {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = pid;
}

/// Check if an OS process is still alive (Linux `kill(pid, 0)`).
#[cfg(target_os = "linux")]
fn is_pid_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    let err = io::Error::last_os_error().raw_os_error();
    err == Some(libc::EPERM)
}

#[cfg(not(target_os = "linux"))]
fn is_pid_alive(_pid: u32) -> bool {
    // On Windows the parent owns the `Child` handle and explicitly reaps it via `child.wait()`.
    false
}

/// Count residual processes in stale `epoch-<n>` cgroups on Linux (`0` if no cgroup_root).
fn count_leaked_cgroup_procs(cgroup_root: Option<&Path>, current_epoch: EpochId) -> usize {
    #[cfg(target_os = "linux")]
    if let Some(root) = cgroup_root {
        let mut leaked = 0usize;
        if let Ok(rd) = std::fs::read_dir(root) {
            for entry in rd.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(ep) = EpochId::from_cgroup_dir_name(&name)
                    && ep < current_epoch
                    && let Ok(procs) = std::fs::read_to_string(entry.path().join("cgroup.procs"))
                {
                    leaked += procs.lines().filter(|l| !l.trim().is_empty()).count();
                }
            }
        }
        return leaked;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (cgroup_root, current_epoch);
    0
}

/// Check for any leaked `fl-f08-*` network namespaces on Linux.
fn count_leaked_netns() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(rd) = std::fs::read_dir("/var/run/netns") {
            return rd
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("fl-f08-"))
                .count();
        }
    }
    0
}

/// Wipe all entries inside `dir` (without removing `dir` itself) to simulate tmpfs loss on reboot.
fn wipe_dir_contents(dir: &Path) -> io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        let md = std::fs::symlink_metadata(&p)?;
        if md.is_dir() {
            std::fs::remove_dir_all(&p)?;
        } else {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(())
}

/// Events emitted synchronously on stdout by `f0-8-worker` so the parent maintains an exact
/// ground-truth crash oracle across asynchronous `SIGKILL`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    /// Child completed `open_and_recover` and is entering the stress loop.
    Ready { epoch: u64 },
    /// Child joined `<cgroup_root>/epoch-<n>` on Linux.
    CgroupJoined { epoch: u64 },
    /// Child spawned a live sandbox sleeper grandchild inside the epoch cgroup.
    SandboxPid { pid: u32 },
    /// Child durably committed a frame (`commit_frame` returned `Ok`).
    Committed {
        frame_id: FrameId,
        durability: FrameDurability,
    },
    /// Child is about to invoke `delete_frame` (frame is delete-in-flight if killed now).
    DeleteStart { frame_id: FrameId },
    /// Child finished `delete_frame` with `DeleteOutcome::Deleted`.
    Deleted { frame_id: FrameId },
    /// Child created a world via `create_world`.
    WorldCreated { base_frame: FrameId },
}

impl WorkerEvent {
    /// Parse a single stdout event line emitted by `f0-8-worker`.
    #[must_use]
    pub fn parse_line(line: &str) -> Option<Self> {
        let mut parts = line.split_whitespace();
        match parts.next()? {
            "READY" => Some(Self::Ready {
                epoch: parts.next()?.parse().ok()?,
            }),
            "CGROUP_JOINED" => Some(Self::CgroupJoined {
                epoch: parts.next()?.parse().ok()?,
            }),
            "SANDBOX_PID" => Some(Self::SandboxPid {
                pid: parts.next()?.parse().ok()?,
            }),
            "COMMITTED" => {
                let frame_id = FrameId::from_base32(parts.next()?).ok()?;
                let durability = match parts.next()? {
                    "durable" => FrameDurability::Durable,
                    "volatile" => FrameDurability::Volatile,
                    _ => return None,
                };
                Some(Self::Committed {
                    frame_id,
                    durability,
                })
            }
            "DELETE_START" => Some(Self::DeleteStart {
                frame_id: FrameId::from_base32(parts.next()?).ok()?,
            }),
            "DELETED" => Some(Self::Deleted {
                frame_id: FrameId::from_base32(parts.next()?).ok()?,
            }),
            "WORLD" => Some(Self::WorldCreated {
                base_frame: FrameId::from_base32(parts.next()?).ok()?,
            }),
            _ => None,
        }
    }
}

/// Materialize an object on disk (directory for `TreeSubvol`, regular file otherwise).
fn create_object_artifact(
    cfg: &MetaConfig,
    tmpfs_dir: &Path,
    obj: &ManagedObject,
    durability: FrameDurability,
) -> io::Result<PathBuf> {
    let path = match obj.location(durability) {
        ObjectLocation::Pool => cfg.objects_dir().join(obj.name()),
        ObjectLocation::VolatileTmpfs => tmpfs_dir.join(obj.name()),
    };
    if obj.kind == ObjectKind::TreeSubvol {
        std::fs::create_dir_all(path.join("etc"))?;
        std::fs::write(path.join("etc").join("hostname"), b"forkloom-f08\n")?;
    } else {
        std::fs::write(&path, format!("f0-8 payload {obj}\n"))?;
    }
    Ok(path)
}

/// Build strict durability proofs matching `aos-meta` Gate 2 contract (`ProofKind::Subvolume` for
/// `TreeSubvol`, `ProofKind::FileAndParent` for pool files, `Ephemeral` ONLY for `VolatileTmpfs`).
fn build_proof_bundle(
    cfg: &MetaConfig,
    tmpfs_dir: &Path,
    expected: &[ManagedObject],
    durability: FrameDurability,
    boot: BootId,
) -> io::Result<CommitProofBundle> {
    let mut bundle = CommitProofBundle::new();
    for obj in expected {
        let path = create_object_artifact(cfg, tmpfs_dir, obj, durability)?;
        bundle = match obj.location(durability) {
            ObjectLocation::Pool => {
                let proof = if obj.kind == ObjectKind::TreeSubvol {
                    PersistProof::fsync_subvolume(&path)?
                } else {
                    PersistProof::fsync_file_and_parent(&path)?
                };
                bundle.with_persisted(Persisted::new(*obj, proof))
            }
            ObjectLocation::VolatileTmpfs => {
                bundle.with_ephemeral(Ephemeral::new_for_boot(*obj, boot))
            }
        };
    }
    Ok(bundle)
}

fn list_dir_names(dir: &Path) -> BTreeSet<String> {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

fn list_quarantine_entries(qroot: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for epoch_dir in list_dir_names(qroot) {
        for name in list_dir_names(&qroot.join(&epoch_dir)) {
            out.insert(format!("{epoch_dir}/{name}"));
        }
    }
    out
}

/// Entrypoint for the hidden `f0-8-worker` child process.
///
/// Opens `MetaEngine::open_and_recover` and loops rapidly through `prepare_frame`, object creation,
/// `commit_frame` (strict `ProofKind::Subvolume` / `FileAndParent` / `Ephemeral`), `delete_frame`,
/// and `create_world` until terminated by `SIGKILL`.
pub fn run_worker(args: &WorkerArgs) -> Result<()> {
    let mut cfg = MetaConfig::new(&args.meta_dir, &args.pool_dir);
    cfg.allow_same_fs_for_testing = args.allow_same_fs;
    std::fs::create_dir_all(&args.tmpfs_dir)?;

    let boot = BootId::parse(&args.boot_id)
        .map_err(|e| anyhow!("invalid worker boot_id {:?}: {e}", args.boot_id))?;
    let clock = Arc::new(ManualClock::new(args.now_ms));

    let (mut engine, _summary) = MetaEngine::open_and_recover(
        cfg.clone(),
        boot,
        Box::new(FsArtifactBackend::new(&args.tmpfs_dir)),
        clock,
    )
    .map_err(|e| anyhow!("worker open_and_recover failed: {e}"))?;

    let mut stdout = io::stdout().lock();

    // On Linux with `--cgroup-root`, move ourselves into `<cgroup_root>/epoch-<n>` and spawn a
    // live sleeper grandchild so that when the parent `SIGKILL`s us, the grandchild survives
    // inside `epoch-<n>` and R2 `cgroup.kill = 1` is genuinely exercised on a live process!
    #[cfg(target_os = "linux")]
    let mut spawned_sandbox_sleeper = false;
    #[cfg(target_os = "linux")]
    if let Some(cg_root) = &args.cgroup_root {
        let ep = engine.daemon_epoch();
        let cg_dir = cg_root.join(ep.cgroup_dir_name());
        if std::fs::create_dir_all(&cg_dir).is_ok()
            && std::fs::write(cg_dir.join("cgroup.procs"), format!("{}\n", std::process::id())).is_ok()
        {
            writeln!(stdout, "CGROUP_JOINED {}", ep.get())?;
            if let Ok(sleeper) = Command::new("sleep")
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                writeln!(stdout, "SANDBOX_PID {}", sleeper.id())?;
                // Deliberately forget the Child handle so the grandchild outlives our SIGKILL
                // and must be terminated by parent's R2 `cgroup.kill = 1`.
                std::mem::forget(sleeper);
                spawned_sandbox_sleeper = true;
            }
        }
    }
    #[cfg(target_os = "linux")]
    let _ = spawned_sandbox_sleeper;

    writeln!(stdout, "READY {}", engine.daemon_epoch().get())?;
    stdout.flush()?;

    let mut rng = SplitMix64::new(args.seed ^ ((args.round as u64 + 1).wrapping_mul(0x9E37_79B9)));
    let mut known_committed: Vec<(FrameId, FrameDurability)> = engine
        .frames()
        .map_err(|e| anyhow!("worker frames(): {e}"))?
        .into_iter()
        .filter_map(|r| match r.state {
            FrameState::Committed { durability, .. } => Some((r.frame_id, durability)),
            _ => None,
        })
        .collect();

    loop {
        match rng.below(10) {
            // 0..=3: Full Preparing -> materialize -> fsync -> Committed cycle (Durable or Volatile).
            0..=3 => {
                let durability = if rng.below(3) == 0 {
                    FrameDurability::Volatile
                } else {
                    FrameDurability::Durable
                };
                let kinds: Vec<ObjectKind> = if durability == FrameDurability::Volatile {
                    vec![
                        ObjectKind::DiskImage,
                        ObjectKind::MemImage,
                        ObjectKind::VmState,
                    ]
                } else {
                    let mut ks: Vec<ObjectKind> =
                        KINDS.iter().copied().filter(|_| rng.below(2) == 0).collect();
                    if ks.is_empty() {
                        ks.push(ObjectKind::DiskImage);
                    }
                    ks
                };
                let parent = if durability == FrameDurability::Durable {
                    let durables: Vec<FrameId> = known_committed
                        .iter()
                        .filter(|(_, d)| *d == FrameDurability::Durable)
                        .map(|(id, _)| *id)
                        .collect();
                    if durables.is_empty() {
                        None
                    } else {
                        Some(durables[rng.below(durables.len() as u64) as usize])
                    }
                } else {
                    None
                };

                let prepared = engine
                    .prepare_frame(
                        &PrepareFrameRequest {
                            owner: OWNER.to_owned(),
                            durability,
                            parent,
                            object_kinds: kinds,
                            labels: Labels::new(),
                            source_world: None,
                        },
                        None,
                    )
                    .map_err(|e| anyhow!("prepare_frame failed: {e}"))?;

                let bundle = build_proof_bundle(
                    &cfg,
                    &args.tmpfs_dir,
                    &prepared.expected_objects,
                    durability,
                    boot,
                )?;
                engine
                    .commit_frame(
                        &CommitFrameRequest {
                            frame_id: prepared.frame_id,
                            owner: OWNER.to_owned(),
                            disk_clean: true,
                            fence: None,
                            pin: None,
                            timeline: None,
                        },
                        bundle,
                        None,
                    )
                    .map_err(|e| anyhow!("commit_frame failed: {e}"))?;

                let dur_tag = match durability {
                    FrameDurability::Durable => "durable",
                    FrameDurability::Volatile => "volatile",
                };
                writeln!(stdout, "COMMITTED {} {dur_tag}", prepared.frame_id.to_base32())?;
                stdout.flush()?;
                known_committed.push((prepared.frame_id, durability));
            }
            // 4..=5: Deliberate Preparing + partial object write window (never committed if killed).
            4..=5 => {
                let durability = if rng.below(2) == 0 {
                    FrameDurability::Durable
                } else {
                    FrameDurability::Volatile
                };
                let prepared = engine
                    .prepare_frame(
                        &PrepareFrameRequest {
                            owner: OWNER.to_owned(),
                            durability,
                            parent: None,
                            object_kinds: KINDS.to_vec(),
                            labels: Labels::new(),
                            source_world: None,
                        },
                        None,
                    )
                    .map_err(|e| anyhow!("in-flight prepare_frame failed: {e}"))?;
                for obj in &prepared.expected_objects {
                    if rng.below(2) == 0 {
                        let _ = create_object_artifact(&cfg, &args.tmpfs_dir, obj, durability);
                    }
                }
                thread::sleep(Duration::from_millis(1));
            }
            // 6..=7: Delete an existing committed frame (exercises Deleting state).
            6..=7 => {
                if known_committed.len() <= 2 {
                    continue;
                }
                let idx = rng.below(known_committed.len() as u64) as usize;
                let (fid, _) = known_committed[idx];
                writeln!(stdout, "DELETE_START {}", fid.to_base32())?;
                stdout.flush()?;
                match engine.delete_frame(fid, OWNER, None) {
                    Ok(DeleteOutcome::Deleted) => {
                        writeln!(stdout, "DELETED {}", fid.to_base32())?;
                        stdout.flush()?;
                        known_committed.swap_remove(idx);
                    }
                    Ok(DeleteOutcome::Deferred { .. }) => {
                        // Frame is held by a running world; leave in ledger until world loses hold.
                    }
                    Err(MetaError::FrameNotFound(_)) => {
                        known_committed.swap_remove(idx);
                    }
                    Err(e) => return Err(anyhow!("delete_frame failed: {e}")),
                }
            }
            // 8..=9: Create a running world referencing a committed base frame (exercises R2 Lost + WorldBase hold).
            _ => {
                if known_committed.is_empty() {
                    continue;
                }
                let idx = rng.below(known_committed.len() as u64) as usize;
                let (fid, _) = known_committed[idx];
                let mut labels = Labels::new();
                labels.insert("round".to_owned(), args.round.to_string());
                if engine
                    .create_world(
                        &CreateWorldRequest {
                            owner: OWNER.to_owned(),
                            base_frame: fid,
                            labels,
                            lease_ttl_ms: 60_000,
                            driver: "namespace".into(),
                        },
                        None,
                    )
                    .is_ok()
                {
                    writeln!(stdout, "WORLD {}", fid.to_base32())?;
                    stdout.flush()?;
                }
            }
        }
    }
}

/// Standalone verification that R6 orphan circuit-breaker refuses to start and leaves objects
/// untouched when wild orphans exceed `max_orphan_count`.
pub fn run_breaker_probe(scratch_root: &Path) -> Result<BreakerProbe> {
    let probe_dir = scratch_root.join("breaker-probe");
    let _ = std::fs::remove_dir_all(&probe_dir);
    let meta = probe_dir.join("meta");
    let pool = probe_dir.join("pool");
    let tmpfs = probe_dir.join("tmpfs");
    std::fs::create_dir_all(&tmpfs)?;

    let mut cfg = MetaConfig::new(&meta, &pool);
    cfg.allow_same_fs_for_testing = true;
    cfg.max_orphan_count = 5;
    let boot = BootId::parse(BOOT_A_STR).unwrap();
    let clock = Arc::new(ManualClock::new(BASE_TIME_MS));

    {
        let (engine, _) = MetaEngine::open_and_recover(
            cfg.clone(),
            boot,
            Box::new(FsArtifactBackend::new(&tmpfs)),
            clock.clone(),
        )
        .map_err(|e| anyhow!("breaker probe init failed: {e}"))?;
        drop(engine);
    }

    let injected = cfg.max_orphan_count + 3;
    for i in 0..injected {
        std::fs::write(cfg.objects_dir().join(format!("wild-breaker-{i}")), b"x")?;
    }

    let res = MetaEngine::open_and_recover(
        cfg.clone(),
        boot,
        Box::new(FsArtifactBackend::new(&tmpfs)),
        clock,
    );
    let breaker_tripped = matches!(
        res,
        Err(MetaError::OrphanCircuitBreakerTriggered { orphan_count, .. })
            if orphan_count == injected
    );
    let surviving = list_dir_names(&cfg.objects_dir()).len();
    let quarantine_empty = list_quarantine_entries(&cfg.quarantine_dir()).is_empty();
    let objects_untouched = surviving == injected && quarantine_empty;

    let _ = std::fs::remove_dir_all(&probe_dir);
    Ok(BreakerProbe {
        injected_orphans: injected,
        breaker_tripped,
        objects_untouched,
    })
}

/// Execute the full multi-process F0-8 `kill -9` crash-injection benchmark and return JSON + MD.
pub fn run(ctx: &crate::Ctx, args: &Args) -> Result<ExpOutput> {
    ensure!(args.rounds >= 1, "--rounds must be >= 1");
    let worker_exe = match &args.worker_exe {
        Some(p) => p.clone(),
        None => std::env::current_exe().context("resolve current_exe for f0-8-worker")?,
    };

    // Start from a clean meta/pool/tmpfs layout for this run.
    let _ = std::fs::remove_dir_all(&args.meta_dir);
    let _ = std::fs::remove_dir_all(&args.pool_dir);
    let _ = std::fs::remove_dir_all(&args.tmpfs_dir);
    std::fs::create_dir_all(&args.meta_dir)?;
    std::fs::create_dir_all(&args.pool_dir)?;
    std::fs::create_dir_all(&args.tmpfs_dir)?;

    let mut cfg = MetaConfig::new(&args.meta_dir, &args.pool_dir);
    cfg.allow_same_fs_for_testing = args.allow_same_fs;

    let boot_a = BootId::parse(BOOT_A_STR).unwrap();
    let boot_b = BootId::parse(BOOT_B_STR).unwrap();
    let mut current_boot = boot_a;
    let clock = Arc::new(ManualClock::new(BASE_TIME_MS));

    // Seed initial empty pool and drop engine before round 0.
    {
        let (engine, _) = MetaEngine::open_and_recover(
            cfg.clone(),
            current_boot,
            Box::new(FsArtifactBackend::new(&args.tmpfs_dir)),
            clock.clone(),
        )
        .map_err(|e| anyhow!("initial open_and_recover failed: {e}"))?;
        drop(engine);
    }

    let mut rng = SplitMix64::new(ctx.seed ^ 0xF008_u64);
    let mut confirmed_committed: BTreeMap<FrameId, FrameDurability> = BTreeMap::new();
    let mut round_reports = Vec::with_capacity(args.rounds);
    let mut recovery_latencies_us = Vec::with_capacity(args.rounds);

    let mut total_preparing_rolled_back = 0usize;
    let mut total_deleting_completed = 0usize;
    let mut total_worlds_marked_lost = 0usize;
    let mut total_orphans_quarantined = 0usize;
    let mut total_reboots = 0usize;
    let mut live_orphans_killed_by_r2 = 0usize;

    let mut leaked_processes = 0usize;
    let mut leaked_netns = 0usize;
    let mut unrecorded_orphans = 0usize;
    let mut lost_committed_frames = 0usize;
    let mut non_committed_survivors = 0usize;
    let mut running_worlds_after_recovery = 0usize;
    let mut missing_committed_objects = 0usize;
    let mut failures = Vec::new();
    let mut cgroup_v2_active = false;

    for round in 0..args.rounds {
        // Advance parent clock monotonically before spawning worker and pass `--now-ms` so the
        // worker clock never drifts backwards behind quarantine/GC advances.
        clock.advance(5_000);
        let worker_now_ms = clock.now_ms();

        let mut cmd = Command::new(&worker_exe);
        cmd.arg("f0-8-worker")
            .arg("--meta-dir")
            .arg(&args.meta_dir)
            .arg("--pool-dir")
            .arg(&args.pool_dir)
            .arg("--tmpfs-dir")
            .arg(&args.tmpfs_dir)
            .arg("--boot-id")
            .arg(current_boot.to_string())
            .arg("--seed")
            .arg(rng.next_u64().to_string())
            .arg("--round")
            .arg(round.to_string())
            .arg("--now-ms")
            .arg(worker_now_ms.to_string());
        if !args.allow_same_fs {
            cmd.arg("--allow-same-fs=false");
        }
        if let Some(cg) = &args.cgroup_root {
            cmd.arg("--cgroup-root").arg(cg);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn f0-8-worker ({}) round {round}", worker_exe.display()))?;
        let child_pid = child.id();

        let stdout = child.stdout.take().context("child stdout missing")?;
        let stderr = child.stderr.take().context("child stderr missing")?;

        // Continuously drain worker stderr in a background thread (capped in memory) so a chatty
        // worker can never block on a full 64 KiB pipe, and surface stderr on READY failure.
        let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stderr_writer = stderr_buf.clone();
        let stderr_thread = thread::spawn(move || {
            let mut r = stderr;
            let mut tmp = [0u8; 4096];
            while let Ok(n) = r.read(&mut tmp) {
                if n == 0 {
                    break;
                }
                let mut guard = stderr_writer.lock().unwrap();
                let remain = MAX_CAPTURED_STDERR_BYTES.saturating_sub(guard.len());
                if remain > 0 {
                    guard.extend_from_slice(&tmp[..n.min(remain)]);
                }
            }
        });

        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<u64>();
        let events_buf = Arc::new(Mutex::new(Vec::<WorkerEvent>::new()));
        let events_writer = events_buf.clone();
        let reader_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            let mut sent_ready = false;
            for line in reader.lines().map_while(Result::ok) {
                if let Some(ev) = WorkerEvent::parse_line(&line) {
                    if let WorkerEvent::Ready { epoch } = ev
                        && !sent_ready
                    {
                        let _ = ready_tx.send(epoch);
                        sent_ready = true;
                    }
                    events_writer.lock().unwrap().push(ev);
                }
            }
        });

        // Wait for worker READY so we crash it during active operations.
        let worker_epoch = match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(ep) => ep,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader_thread.join();
                let _ = stderr_thread.join();
                let err_txt = String::from_utf8_lossy(&stderr_buf.lock().unwrap()).into_owned();
                anyhow::bail!(
                    "round {round}: f0-8-worker failed before READY ({e}); stderr: {err_txt}"
                );
            }
        };
        let _ = worker_epoch;

        // Sleep a pseudo-random interval, then deliver uncatchable SIGKILL / TerminateProcess.
        let delay_ms = if args.max_kill_delay_ms == 0 {
            0
        } else {
            1 + rng.below(args.max_kill_delay_ms)
        };
        thread::sleep(Duration::from_millis(delay_ms));

        #[cfg(target_os = "linux")]
        unsafe {
            let _ = libc::kill(child_pid as libc::pid_t, libc::SIGKILL);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = child.kill();
        }
        let _exit_status = child.wait().context("wait killed f0-8-worker")?;
        let _ = reader_thread.join();
        let _ = stderr_thread.join();

        if is_pid_alive(child_pid) {
            leaked_processes += 1;
            failures.push(format!("round {round}: killed child PID {child_pid} still alive"));
        }

        // Apply worker ground-truth events to our independent oracle.
        let mut delete_in_flight = BTreeSet::new();
        let mut tracked_sandbox_pids = Vec::new();
        for ev in events_buf.lock().unwrap().iter() {
            match ev {
                WorkerEvent::Committed {
                    frame_id,
                    durability,
                } => {
                    confirmed_committed.insert(*frame_id, *durability);
                }
                WorkerEvent::DeleteStart { frame_id } => {
                    delete_in_flight.insert(*frame_id);
                }
                WorkerEvent::Deleted { frame_id } => {
                    confirmed_committed.remove(frame_id);
                    delete_in_flight.remove(frame_id);
                }
                WorkerEvent::CgroupJoined { .. } => {
                    cgroup_v2_active = true;
                }
                WorkerEvent::SandboxPid { pid } => {
                    tracked_sandbox_pids.push(*pid);
                }
                WorkerEvent::Ready { .. } | WorkerEvent::WorldCreated { .. } => {}
            }
        }
        // Any frame whose deletion started before SIGKILL may legitimately be either Committed or Deleted.
        for fid in &delete_in_flight {
            confirmed_committed.remove(fid);
        }

        // Occasionally inject 1 wild orphan file to exercise real R6 quarantine under breaker limits.
        let inject_wild_orphan = round % 10 == 4;
        if inject_wild_orphan {
            std::fs::write(
                cfg.objects_dir().join(format!("wild-f08-r{round}")),
                b"injected-orphan",
            )?;
        }

        // Periodically simulate a host reboot: flip boot_id AND wipe tmpfs_dir so R1/R5 tests
        // real `NotFound` cleanup of vanished volatile memory images after reboot!
        let simulated_reboot = args.reboot_every > 0 && (round + 1) % args.reboot_every == 0;
        if simulated_reboot {
            current_boot = if current_boot == boot_a { boot_b } else { boot_a };
            wipe_dir_contents(&args.tmpfs_dir)
                .with_context(|| format!("round {round}: wipe tmpfs_dir on simulated reboot"))?;
            confirmed_committed.retain(|_, d| *d == FrameDurability::Durable);
            total_reboots += 1;
        }

        clock.advance(5_000);

        let mut stale_list = vec![child_pid];
        stale_list.extend(tracked_sandbox_pids.iter().copied());
        let stale_pids = Arc::new(Mutex::new(stale_list));
        let fenced_epochs = Arc::new(Mutex::new(Vec::new()));
        let killed_cgroups = Arc::new(Mutex::new(Vec::new()));
        let round_live_killed = Arc::new(Mutex::new(0usize));
        let t0 = Instant::now();
        let (mut engine, summary): (MetaEngine, RecoverySummary) = open_with_lock_retry(
            cfg.clone(),
            current_boot,
            || {
                Box::new(F08RecoveryHooks {
                    inner: FsArtifactBackend::new(&args.tmpfs_dir),
                    cgroup_root: args.cgroup_root.clone(),
                    stale_pids: stale_pids.clone(),
                    fenced_epochs: fenced_epochs.clone(),
                    killed_cgroups: killed_cgroups.clone(),
                    live_orphans_killed: round_live_killed.clone(),
                })
            },
            clock.clone(),
        )
        .with_context(|| format!("round {round}: MetaEngine::open_and_recover failed"))?;
        let recovery_us = t0.elapsed().as_secs_f64() * 1e6;
        recovery_latencies_us.push(recovery_us);

        live_orphans_killed_by_r2 += *round_live_killed.lock().unwrap();
        if !killed_cgroups.lock().unwrap().is_empty() {
            cgroup_v2_active = true;
        }

        // Verify R2 gateway fence fired for the new epoch.
        if !fenced_epochs.lock().unwrap().contains(&summary.new_epoch) {
            failures.push(format!(
                "round {round}: R2 fence_gateway did not fire for epoch {}",
                summary.new_epoch
            ));
        }

        // Verify zero leaked sandbox grandchildren, cgroup processes, and netns.
        for &spid in &tracked_sandbox_pids {
            if is_pid_alive(spid) {
                leaked_processes += 1;
                failures.push(format!(
                    "round {round}: sandbox grandchild PID {spid} survived R2 cgroup.kill"
                ));
            }
        }
        let cg_leaks = count_leaked_cgroup_procs(args.cgroup_root.as_deref(), summary.new_epoch);
        if cg_leaks > 0 {
            leaked_processes += cg_leaks;
            failures.push(format!("round {round}: {cg_leaks} leaked cgroup processes"));
        }
        let netns_leaks = count_leaked_netns();
        if netns_leaks > 0 {
            leaked_netns += netns_leaks;
            failures.push(format!("round {round}: {netns_leaks} leaked netns"));
        }

        // Verify R6 quarantined exactly the injected wild orphan (0 otherwise).
        let expected_orphans = usize::from(inject_wild_orphan);
        if summary.orphans_quarantined != expected_orphans {
            failures.push(format!(
                "round {round}: expected {expected_orphans} quarantined orphans, got {}",
                summary.orphans_quarantined
            ));
        }

        // Inspect surviving frames & worlds in redb and cross-check against filesystem reality.
        let frames = engine.frames().map_err(|e| anyhow!("frames(): {e}"))?;
        let mut expected_pool_objs = BTreeSet::new();
        let mut expected_tmpfs_objs = BTreeSet::new();
        let mut surviving_ids = BTreeMap::new();

        for rec in &frames {
            match &rec.state {
                FrameState::Committed {
                    durability,
                    objects,
                    ..
                } => {
                    surviving_ids.insert(rec.frame_id, *durability);
                    for obj in objects {
                        match obj.location(*durability) {
                            ObjectLocation::Pool => {
                                expected_pool_objs.insert(obj.name());
                            }
                            ObjectLocation::VolatileTmpfs => {
                                expected_tmpfs_objs.insert(obj.name());
                            }
                        }
                    }
                }
                other => {
                    non_committed_survivors += 1;
                    failures.push(format!(
                        "round {round}: non-committed frame {} survived in state {}",
                        rec.frame_id,
                        other.name()
                    ));
                }
            }
        }

        // 1) Zero lost committed frames.
        for (&fid, &dur) in &confirmed_committed {
            if !surviving_ids.contains_key(&fid) {
                lost_committed_frames += 1;
                failures.push(format!(
                    "round {round}: LOST committed {dur:?} frame {fid}"
                ));
            }
        }
        confirmed_committed = surviving_ids;

        // 2) Zero unrecorded orphan objects in pool/objects and tmpfs, and zero missing objects.
        let actual_pool_objs = list_dir_names(&cfg.objects_dir());
        let actual_tmpfs_objs = list_dir_names(&args.tmpfs_dir);

        for extra in actual_pool_objs.difference(&expected_pool_objs) {
            unrecorded_orphans += 1;
            failures.push(format!("round {round}: unrecorded pool orphan {extra}"));
        }
        for extra in actual_tmpfs_objs.difference(&expected_tmpfs_objs) {
            unrecorded_orphans += 1;
            failures.push(format!("round {round}: unrecorded tmpfs orphan {extra}"));
        }
        for missing in expected_pool_objs.difference(&actual_pool_objs) {
            missing_committed_objects += 1;
            failures.push(format!("round {round}: missing committed pool object {missing}"));
        }
        for missing in expected_tmpfs_objs.difference(&actual_tmpfs_objs) {
            missing_committed_objects += 1;
            failures.push(format!("round {round}: missing committed tmpfs object {missing}"));
        }

        // 3) Every quarantined file on disk must have a matching QuarantineRecord in redb.
        let disk_q = list_quarantine_entries(&cfg.quarantine_dir());
        let db_q: BTreeSet<String> = engine
            .quarantine_records()
            .map_err(|e| anyhow!("quarantine_records(): {e}"))?
            .into_iter()
            .map(|r| format!("{}/{}", r.quarantined_epoch.cgroup_dir_name(), r.name))
            .collect();
        for extra in disk_q.difference(&db_q) {
            unrecorded_orphans += 1;
            failures.push(format!("round {round}: unrecorded quarantine file {extra}"));
        }

        // 4) Zero surviving Running worlds after recovery.
        let worlds = engine.worlds().map_err(|e| anyhow!("worlds(): {e}"))?;
        let still_running = worlds.iter().filter(|w| w.state.is_running()).count();
        if still_running > 0 {
            running_worlds_after_recovery += still_running;
            failures.push(format!(
                "round {round}: {still_running} worlds still Running after R2 recovery"
            ));
        }

        // Periodically purge quarantined entries after grace period (propagate GC errors!).
        if !db_q.is_empty() && round % 20 == 19 {
            clock.advance(cfg.quarantine_grace_ms);
            let now = clock.now_ms();
            let gc = engine
                .collect_garbage(now)
                .map_err(|e| anyhow!("round {round}: collect_garbage failed: {e}"))?;
            if !gc.failures.is_empty() {
                return Err(anyhow!("round {round}: gc failures: {:?}", gc.failures));
            }
        }

        total_preparing_rolled_back += summary.preparing_rolled_back;
        total_deleting_completed += summary.deleting_completed;
        total_worlds_marked_lost += summary.worlds_marked_lost;
        total_orphans_quarantined += summary.orphans_quarantined;

        round_reports.push(RoundReport {
            round,
            killed_pid: child_pid,
            recovered_epoch: summary.new_epoch.get(),
            simulated_reboot,
            preparing_rolled_back: summary.preparing_rolled_back,
            deleting_completed: summary.deleting_completed,
            worlds_marked_lost: summary.worlds_marked_lost,
            orphans_quarantined: summary.orphans_quarantined,
            recovery_us,
            surviving_committed: confirmed_committed.len(),
        });

        drop(engine);
    }

    // Standalone R6 circuit-breaker probe in an isolated subdirectory.
    let breaker_parent = args
        .pool_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("f0-8-breaker");
    let breaker_probe = run_breaker_probe(&breaker_parent)?;
    if !breaker_probe.breaker_tripped || !breaker_probe.objects_untouched {
        failures.push(format!(
            "R6 orphan circuit breaker failed: tripped={} untouched={}",
            breaker_probe.breaker_tripped, breaker_probe.objects_untouched
        ));
    }

    let passed = failures.is_empty()
        && leaked_processes == 0
        && leaked_netns == 0
        && unrecorded_orphans == 0
        && lost_committed_frames == 0
        && non_committed_survivors == 0
        && running_worlds_after_recovery == 0
        && missing_committed_objects == 0
        && breaker_probe.breaker_tripped
        && breaker_probe.objects_untouched;

    let report = F08Report {
        rounds_completed: round_reports.len(),
        allow_same_fs: args.allow_same_fs,
        cgroup_v2_active,
        live_orphans_killed_by_r2,
        total_preparing_rolled_back,
        total_deleting_completed,
        total_worlds_marked_lost,
        total_orphans_quarantined,
        total_reboots,
        final_committed_frames: confirmed_committed.len(),
        leaked_processes,
        leaked_netns,
        unrecorded_orphans,
        lost_committed_frames,
        non_committed_survivors,
        running_worlds_after_recovery,
        missing_committed_objects,
        breaker_probe,
        recovery_latency: Dist::from_us(recovery_latencies_us),
        passed,
        failures,
        rounds: round_reports,
    };

    Ok(render_report(&report))
}

/// Open and recover `MetaEngine`, retrying briefly ONLY on transient `MetaError::PoolLocked`
/// right after hard process termination.
fn open_with_lock_retry(
    cfg: MetaConfig,
    boot: BootId,
    make_hooks: impl Fn() -> Box<dyn RecoveryHooks>,
    clock: Arc<ManualClock>,
) -> Result<(MetaEngine, RecoverySummary)> {
    const MAX_LOCK_ATTEMPTS: usize = 5;
    for attempt in 0..MAX_LOCK_ATTEMPTS {
        match MetaEngine::open_and_recover(cfg.clone(), boot, make_hooks(), clock.clone()) {
            Ok(ok) => return Ok(ok),
            Err(MetaError::PoolLocked { .. }) if attempt + 1 < MAX_LOCK_ATTEMPTS => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(anyhow!("MetaEngine::open_and_recover: {e}")),
        }
    }
    unreachable!()
}

/// Render [`F08Report`] into standard JSON + Markdown [`ExpOutput`].
#[must_use]
pub fn render_report(report: &F08Report) -> ExpOutput {
    let mut md = String::new();
    md.push_str("## F0-8: `kill -9` Fault Injection & Zero-Orphan Recovery (`aos-meta` R0~R6)\n\n");
    md.push_str(&format!(
        "- Verdict: **{}** ({} rounds completed, cgroup_v2_active={}, live_orphans_killed_by_r2={}, allow_same_fs={})\n",
        if report.passed { "PASS" } else { "FAIL" },
        report.rounds_completed,
        report.cgroup_v2_active,
        report.live_orphans_killed_by_r2,
        report.allow_same_fs
    ));
    md.push_str(&format!(
        "- Recovery activity: preparing_rolled_back=**{}**, deleting_completed=**{}**, worlds_marked_lost=**{}**, orphans_quarantined=**{}**, simulated_reboots=**{}**, final_committed=**{}**\n",
        report.total_preparing_rolled_back,
        report.total_deleting_completed,
        report.total_worlds_marked_lost,
        report.total_orphans_quarantined,
        report.total_reboots,
        report.final_committed_frames,
    ));
    md.push_str(&format!(
        "- R6 circuit-breaker probe ({} injected wild orphans): tripped=**{}**, objects_untouched=**{}**\n\n",
        report.breaker_probe.injected_orphans,
        report.breaker_probe.breaker_tripped,
        report.breaker_probe.objects_untouched
    ));
    md.push_str("### Zero-Leak Invariants\n\n");
    md.push_str("| Invariant | Observed | Required |\n| --- | ---: | ---: |\n");
    md.push_str(&format!("| Leaked child processes | {} | 0 |\n", report.leaked_processes));
    md.push_str(&format!("| Leaked netns/veth | {} | 0 |\n", report.leaked_netns));
    md.push_str(&format!("| Unrecorded orphan objects | {} | 0 |\n", report.unrecorded_orphans));
    md.push_str(&format!("| Lost committed frames | {} | 0 |\n", report.lost_committed_frames));
    md.push_str(&format!("| Non-committed survivors | {} | 0 |\n", report.non_committed_survivors));
    md.push_str(&format!("| Running worlds after recovery | {} | 0 |\n", report.running_worlds_after_recovery));
    md.push_str(&format!("| Missing committed objects | {} | 0 |\n\n", report.missing_committed_objects));

    md.push_str("### `MetaEngine::open_and_recover` Latency\n\n");
    md.push_str(DIST_HEADER);
    md.push_str(&dist_row("open_and_recover (R0~R6)", &report.recovery_latency));
    if !report.failures.is_empty() {
        md.push_str("\n### Failures\n\n");
        for f in &report.failures {
            md.push_str(&format!("- {f}\n"));
        }
    }
    md.push('\n');

    ExpOutput {
        id: "F0-8",
        slug: "f0-8-kill9-recovery",
        json: json!(report),
        md,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_worker_event_protocol_lines() {
        let fid = FrameId::random();
        let b32 = fid.to_base32();
        assert_eq!(
            WorkerEvent::parse_line("READY 7\n"),
            Some(WorkerEvent::Ready { epoch: 7 })
        );
        assert_eq!(
            WorkerEvent::parse_line("CGROUP_JOINED 7\n"),
            Some(WorkerEvent::CgroupJoined { epoch: 7 })
        );
        assert_eq!(
            WorkerEvent::parse_line("SANDBOX_PID 4242\n"),
            Some(WorkerEvent::SandboxPid { pid: 4242 })
        );
        assert_eq!(
            WorkerEvent::parse_line(&format!("COMMITTED {b32} durable")),
            Some(WorkerEvent::Committed {
                frame_id: fid,
                durability: FrameDurability::Durable
            })
        );
        assert_eq!(
            WorkerEvent::parse_line(&format!("COMMITTED {b32} volatile")),
            Some(WorkerEvent::Committed {
                frame_id: fid,
                durability: FrameDurability::Volatile
            })
        );
        assert_eq!(
            WorkerEvent::parse_line(&format!("DELETE_START {b32}")),
            Some(WorkerEvent::DeleteStart { frame_id: fid })
        );
        assert_eq!(
            WorkerEvent::parse_line(&format!("DELETED {b32}")),
            Some(WorkerEvent::Deleted { frame_id: fid })
        );
        assert_eq!(
            WorkerEvent::parse_line(&format!("WORLD {b32}")),
            Some(WorkerEvent::WorldCreated { base_frame: fid })
        );
        assert_eq!(WorkerEvent::parse_line("noise line"), None);
    }

    #[test]
    fn r6_orphan_circuit_breaker_probe_trips_and_preserves_objects() {
        let scratch = std::env::temp_dir().join(format!(
            "p0-f08-breaker-{}",
            std::process::id()
        ));
        let probe = run_breaker_probe(&scratch).unwrap();
        assert!(probe.breaker_tripped);
        assert!(probe.objects_untouched);
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
