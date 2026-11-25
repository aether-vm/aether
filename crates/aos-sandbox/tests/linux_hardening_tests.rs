//! Live Linux `NamespaceDriver` privilege-isolation and resource-limit tests (`R-001`).
//!
//! Must run as root on Linux with `/var/lib/forkloom/guest-image/rootfs-stage` present.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aos_sandbox::{
    DEFAULT_CGROUP_SLICE_ROOT, ExecReply, ExecRequest, GuestAgentSource, IdMapRange, NamespaceDriver, ResourceLimits,
    SandboxDriver, SandboxError, SpawnWorldSpec, WorldHandle,
};
use aos_types::{EpochId, WorldId};

const ROOTFS_STAGE: &str = "/var/lib/forkloom/guest-image/rootfs-stage";

/// Scratch rootfs under a root-only (`0700`) parent, removed on drop.
struct Scratch {
    base: PathBuf,
    cgroup_root: PathBuf,
}

impl Scratch {
    fn new(prefix: &str) -> Option<Self> {
        if !Path::new(ROOTFS_STAGE).is_dir()
            || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        {
            eprintln!("skipping live hardening test: {ROOTFS_STAGE} or cgroup v2 not present");
            return None;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("aos-sandbox-{prefix}-{}-{nanos}", std::process::id());
        let base = std::env::temp_dir().join(&name);
        let cgroup_root = Path::new(DEFAULT_CGROUP_SLICE_ROOT).join(&name);
        fs::create_dir_all(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let ok = Command::new("cp")
            .args(["-a", ROOTFS_STAGE])
            .arg(base.join("rootfs"))
            .status()
            .unwrap()
            .success();
        assert!(ok, "copying rootfs-stage failed");
        Some(Self { base, cgroup_root })
    }

    fn rootfs(&self) -> PathBuf {
        self.base.join("rootfs")
    }

    fn spec(&self) -> SpawnWorldSpec {
        let mut spec = SpawnWorldSpec::new(
            WorldId::random(),
            EpochId::new(98).unwrap(),
            self.rootfs(),
            GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
        );
        spec.cgroup_root = self.cgroup_root.clone();
        spec
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir(self.cgroup_root.join("epoch-98"));
        let _ = fs::remove_dir(&self.cgroup_root);
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn sh(world: &mut WorldHandle, id: &str, script: &str) -> ExecReply {
    world
        .exec(ExecRequest::new(
            id,
            vec!["/bin/sh".into(), "-c".into(), script.into()],
        ))
        .unwrap_or_else(|e| panic!("exec {id} failed: {e}"))
}

fn stdout(reply: &ExecReply) -> String {
    String::from_utf8_lossy(reply.stdout.head.as_slice())
        .trim()
        .to_owned()
}

/// `/proc/<pid>/status` field as whitespace-separated host ids.
fn status_ids(pid: u32, key: &str) -> Vec<u32> {
    let raw = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    raw.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}:")))
        .unwrap_or_else(|| panic!("missing {key} in /proc/{pid}/status"))
        .split_whitespace()
        .map(|v| v.parse().unwrap())
        .collect()
}

fn assert_unprivileged_on_host(pid: u32) {
    let uids = status_ids(pid, "Uid");
    let gids = status_ids(pid, "Gid");
    assert!(
        uids.iter().all(|u| *u != 0),
        "sandbox uid 0 must not be host uid 0, got {uids:?}"
    );
    assert!(
        gids.iter().all(|g| *g != 0),
        "sandbox gid 0 must not be host gid 0, got {gids:?}"
    );
    let groups = status_ids(pid, "Groups");
    assert!(
        groups.is_empty(),
        "sandbox must not inherit host supplementary groups, got {groups:?}"
    );
}

#[test]
fn root_agentd_maps_sandbox_root_to_unprivileged_host_ids() {
    let Some(scratch) = Scratch::new("uid") else {
        return;
    };
    // Root-owned, root-only content must stay usable by sandbox root.
    fs::create_dir_all(scratch.rootfs().join("private")).unwrap();
    fs::set_permissions(
        scratch.rootfs().join("private"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::write(scratch.rootfs().join("private/seed"), "seed").unwrap();

    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    assert_unprivileged_on_host(world.info().host_pid.unwrap());

    // Inside the sandbox the workload is still uid 0 and owns the imported tree.
    let who = sh(&mut world, "id", "id -u; id -g; stat -c %u:%g /private/seed");
    assert_eq!(stdout(&who), "0\n0\n0:0");
    let write = sh(
        &mut world,
        "write",
        "cat /private/seed && echo changed > /private/seed && echo new > /private/added && mkdir /made",
    );
    assert_eq!(
        write.exit_code,
        Some(0),
        "sandbox root must be able to modify its rootfs: {}",
        String::from_utf8_lossy(write.stderr.head.as_slice())
    );

    // Sandbox mounts must not propagate into the host mount namespace.
    let host_mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        !host_mounts.contains(scratch.base.to_str().unwrap()),
        "sandbox mounts leaked into host mountinfo:\n{host_mounts}"
    );
    world.destroy().unwrap();

    // On-disk ownership is unshifted, so checkpoints and re-forks are range-independent.
    for rel in ["private/seed", "private/added", "made"] {
        let m = fs::metadata(scratch.rootfs().join(rel)).unwrap();
        assert_eq!((m.uid(), m.gid()), (0, 0), "{rel} on-disk owner shifted");
    }
    assert_eq!(
        fs::read_to_string(scratch.rootfs().join("private/seed")).unwrap(),
        "changed\n"
    );
}

#[test]
fn bind_mounted_host_agent_works_from_root_only_dir_and_stays_readonly() {
    let Some(scratch) = Scratch::new("agent") else {
        return;
    };
    let host_dir = scratch.base.join("host-bin");
    fs::create_dir(&host_dir).unwrap();
    fs::set_permissions(&host_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let host_bin = host_dir.join("aos-guest");
    fs::copy(scratch.rootfs().join("sbin/init"), &host_bin).unwrap();
    fs::set_permissions(&host_bin, fs::Permissions::from_mode(0o700)).unwrap();
    let before = fs::read(&host_bin).unwrap();

    let mut spec = scratch.spec();
    spec.guest_agent = GuestAgentSource::BindMountHostBinary {
        host_path: host_bin.clone(),
        guest_mount_path: PathBuf::from("/sbin/init"),
    };
    let mut world = NamespaceDriver::new().spawn_world(spec).unwrap();
    assert_unprivileged_on_host(world.info().host_pid.unwrap());
    let w = sh(
        &mut world,
        "tamper",
        "echo x >> /sbin/init || chmod 777 /sbin/init",
    );
    assert_ne!(w.exit_code, Some(0), "host aos-guest must be read-only");
    world.destroy().unwrap();
    assert_eq!(fs::read(&host_bin).unwrap(), before);
    assert_eq!(
        fs::metadata(&host_bin).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn explicit_map_to_host_root_is_rejected_for_root_agentd() {
    let Some(scratch) = Scratch::new("map0") else {
        return;
    };
    for (uid, gid) in [(0, 5000), (5000, 0)] {
        let mut spec = scratch.spec();
        spec.uid_map = vec![IdMapRange::new(0, uid, 1)];
        spec.gid_map = vec![IdMapRange::new(0, gid, 1)];
        let err = NamespaceDriver::new().spawn_world(spec).err();
        assert!(
            matches!(err, Some(SandboxError::InvalidConfig(_))),
            "mapping to host id 0 must be rejected, got {err:?}"
        );
    }
}

#[test]
fn default_limits_are_enforced_on_the_world_cgroup() {
    let Some(scratch) = Scratch::new("limits") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    let cg = world.info().cgroup_path.clone().unwrap();
    let read = |f: &str| {
        fs::read_to_string(cg.join(f))
            .unwrap_or_else(|e| panic!("{f} unavailable on world cgroup: {e}"))
            .trim()
            .to_owned()
    };
    assert_eq!(read("memory.max"), (2u64 << 30).to_string());
    assert_eq!(read("memory.swap.max"), "0");
    assert_eq!(read("pids.max"), "512");
    world.destroy().unwrap();
}

#[test]
fn default_pids_limit_contains_a_fork_bomb() {
    let Some(scratch) = Scratch::new("pids") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    let cg = world.info().cgroup_path.clone().unwrap();
    // `setsid` execs, so the sleepers do not keep busybox's saved copies of the exec pipes open.
    sh(
        &mut world,
        "bomb",
        "i=0; while [ $i -lt 700 ]; do setsid sleep 60 >/dev/null 2>&1 & i=$((i+1)); done; true",
    );
    // The bomb itself is gone once its Exec ended, so look at what the kernel recorded.
    let peak: u64 = fs::read_to_string(cg.join("pids.peak"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(peak > 100, "fork bomb did not run, peak {peak}");
    assert!(peak <= 512, "fork bomb reached {peak} tasks");
    let events = fs::read_to_string(cg.join("pids.events")).unwrap();
    assert!(!events.contains("max 0"), "pids.max was never hit: {events}");
    assert_eq!(world.ping(7).expect("world survives").nonce, 7);
    world.destroy().unwrap();
}

#[test]
fn explicit_limits_contain_memory_hog_and_write_cpu_max() {
    let Some(scratch) = Scratch::new("mem") else {
        return;
    };
    let mut spec = scratch.spec();
    spec.limits = ResourceLimits {
        memory_max_bytes: Some(48 << 20),
        pids_max: Some(64),
        cpu_max_percent: Some(150),
    };
    let mut world = NamespaceDriver::new().spawn_world(spec).unwrap();
    let cg = world.info().cgroup_path.clone().unwrap();
    assert_eq!(
        fs::read_to_string(cg.join("cpu.max")).unwrap().trim(),
        "150000 100000"
    );
    // `tail -c` buffers everything it might have to print.
    let hog = sh(
        &mut world,
        "hog",
        "head -c 200000000 /dev/zero | tail -c 150000000 | wc -c",
    );
    let events = fs::read_to_string(cg.join("memory.events")).unwrap();
    let oom_kills: u64 = events
        .lines()
        .find_map(|l| l.strip_prefix("oom_kill "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(oom_kills >= 1, "expected an OOM kill, got {events} ({hog:?})");
    assert_ne!(stdout(&hog), "150000000", "hog escaped memory.max");
    assert_eq!(world.ping(9).expect("aos-guest survives OOM").nonce, 9);
    world.destroy().unwrap();
}

#[test]
fn none_limits_stay_unlimited() {
    let Some(scratch) = Scratch::new("nolimit") else {
        return;
    };
    let mut spec = scratch.spec();
    spec.limits = ResourceLimits {
        memory_max_bytes: None,
        pids_max: None,
        cpu_max_percent: None,
    };
    let mut world = NamespaceDriver::new().spawn_world(spec).unwrap();
    let cg = world.info().cgroup_path.clone().unwrap();
    for file in ["memory.max", "pids.max"] {
        let v = fs::read_to_string(cg.join(file)).unwrap_or_else(|_| "max".to_owned());
        assert_eq!(v.trim(), "max", "{file}");
    }
    world.destroy().unwrap();
}

fn exec_with_timeout(
    world: &mut WorldHandle,
    id: &str,
    script: &str,
    timeout: Duration,
) -> ExecReply {
    let mut req = ExecRequest::new(id, vec!["/bin/sh".into(), "-c".into(), script.into()]);
    req.timeout = Some(timeout);
    world
        .exec(req)
        .unwrap_or_else(|e| panic!("exec {id} failed: {e}"))
}

/// Host pids of every task in the world cgroup subtree.
fn world_pids(world: &WorldHandle) -> Vec<u32> {
    let cg = world.info().cgroup_path.clone().unwrap();
    let mut pids = Vec::new();
    for dir in [cg.clone(), cg.join("exec")] {
        let raw = fs::read_to_string(dir.join("cgroup.procs")).unwrap_or_default();
        pids.extend(raw.lines().map(|l| l.trim().parse::<u32>().unwrap()));
    }
    pids
}

#[test]
fn exec_timeout_kills_background_descendants_and_keeps_the_world_usable() {
    let Some(scratch) = Scratch::new("exec-timeout") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    let agent = world.info().host_pid.unwrap();
    for (id, script) in [
        ("direct", "sleep 30"),
        ("grandchild", "sleep 30 & wait"),
        ("setsid", "setsid sleep 30 & wait"),
    ] {
        let start = Instant::now();
        let r = exec_with_timeout(&mut world, id, script, Duration::from_millis(500));
        assert!(r.timed_out, "{id}: {r:?}");
        assert!(r.cgroup_killed, "{id}: {r:?}");
        assert!(start.elapsed() < Duration::from_secs(2), "{id} hung");
        assert_eq!(world_pids(&world), vec![agent], "{id} left processes behind");
        assert_eq!(world.ping(3).expect("world stays usable").nonce, 3);
    }
    world.destroy().unwrap();
}

#[test]
fn foreground_exec_returns_and_leaves_no_processes_behind() {
    let Some(scratch) = Scratch::new("exec-end") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    let agent = world.info().host_pid.unwrap();
    for (id, script, leftovers) in [
        ("clean", "echo hi", false),
        ("pipe-holder", "sleep 30 & echo hi", true),
        (
            "daemon",
            "setsid sleep 30 </dev/null >/dev/null 2>&1 & echo hi",
            true,
        ),
        // Re-running right after a kill must not be hit by the previous exec's kill.
        ("again", "echo hi", false),
    ] {
        let start = Instant::now();
        let r = exec_with_timeout(&mut world, id, script, Duration::from_secs(10));
        assert_eq!(r.exit_code, Some(0), "{id}: {r:?}");
        assert!(!r.timed_out, "{id}: {r:?}");
        assert_eq!(stdout(&r), "hi", "{id}");
        assert!(start.elapsed() < Duration::from_secs(3), "{id} hung");
        // The daemon may not have left the fork yet, so only its absence afterwards is certain.
        if !leftovers {
            assert!(!r.cgroup_killed, "{id}: {r:?}");
        }
        assert_eq!(world_pids(&world), vec![agent], "{id} left processes behind");
    }
    world.destroy().unwrap();
}

#[test]
fn workload_cannot_reach_the_exec_cgroup_controls() {
    let Some(scratch) = Scratch::new("exec-fd") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    // Neither inherited fds nor reopening aos-guest's fds may move the workload out of `exec`.
    let r = exec_with_timeout(
        &mut world,
        "escape",
        "ls /proc/self/fd; for f in /proc/1/fd/*; do echo 0 > $f && echo WROTE $f; done 2>/dev/null; \
         cat /proc/self/cgroup",
        Duration::from_secs(5),
    );
    let out = stdout(&r);
    assert!(
        out.lines().any(|l| l.starts_with("0::") && l.ends_with("/exec")),
        "workload must run in and stay inside the exec cgroup:\n{out}"
    );
    for line in out.lines().filter(|l| l.starts_with("WROTE")) {
        let fd: u32 = line.rsplit('/').next().unwrap().parse().unwrap();
        assert!(fd < 10, "workload reopened a cgroup control fd: {out}");
    }
    assert!(
        !out.lines().any(|l| l.parse::<u32>().is_ok_and(|fd| fd >= 10)),
        "cgroup control fds leaked into the workload:\n{out}"
    );
    world.destroy().unwrap();
}

#[test]
fn workload_cannot_inspect_or_modify_aos_guest() {
    let Some(scratch) = Scratch::new("guest-mem") else {
        return;
    };
    let mut world = NamespaceDriver::new().spawn_world(scratch.spec()).unwrap();
    // `environ` and fd links only need PTRACE_MODE_READ, so unlike `mem` they are not masked by
    // `kernel.yama.ptrace_scope=1` and prove that the dumpable check itself rejects the workload.
    for probe in [
        "cat /proc/1/environ",
        "readlink /proc/1/fd/3",
        "exec 3<>/proc/1/mem",
    ] {
        let r = sh(&mut world, "probe", probe);
        assert_ne!(r.exit_code, Some(0), "{probe} must be denied: {r:?}");
    }
    // The workload itself stays dumpable.
    let own = sh(&mut world, "own", "cat /proc/self/environ >/dev/null && readlink /proc/self/fd/0");
    assert_eq!(own.exit_code, Some(0));
    world.destroy().unwrap();
}

#[test]
fn spawn_world_does_not_deadlock_while_other_threads_start() {
    let Some(scratch) = Scratch::new("spawn-race") else {
        return;
    };
    let stop = std::sync::atomic::AtomicBool::new(false);
    let (tx, rx) = std::sync::mpsc::channel();
    let stuck = std::thread::scope(|scope| {
        // glibc's set*id wrappers wait for threads that are just starting; after `clone3` those
        // threads do not exist in the child.
        for _ in 0..4 {
            scope.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::thread::spawn(|| {}).join();
                }
            });
        }
        scope.spawn(|| {
            for i in 0..150 {
                let spawned = NamespaceDriver::new().spawn_world(scratch.spec());
                let _ = tx.send(i);
                // A world killed by the watchdog below ends the loop.
                let Ok(mut world) = spawned else { break };
                world.destroy().unwrap();
            }
        });
        let mut stuck = None;
        for i in 0..150 {
            if rx.recv_timeout(Duration::from_secs(10)).is_err() {
                stuck = Some(i);
                // Release the blocked spawn so the scope can end.
                let _ = fs::write(scratch.cgroup_root.join("epoch-98/cgroup.kill"), "1");
                break;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        stuck
    });
    assert_eq!(stuck, None, "spawn_world deadlocked");
}
