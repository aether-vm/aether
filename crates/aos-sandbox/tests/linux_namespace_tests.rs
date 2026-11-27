//! Live Linux `NamespaceDriver` hardening integration tests.
//!
//! Exercises real kernel isolation inside a native Linux environment (such as
//! `wsl -d Forkloom-Dev` with `/var/lib/forkloom/guest-image/rootfs-stage` and
//! `/var/lib/forkloom/guest-image/out/aos-guest`):
//! - `clone3(CLONE_INTO_CGROUP)` placing sandbox into `/sys/fs/cgroup/forkloom.slice/epoch-<e>/w-<id>`
//! - `userns` + `mountns` (`pivot_root`) + `pidns` + `ipcns` + `utsns` + isolated `netns`
//! - `PR_SET_NO_NEW_PRIVS`, zero capabilities (`CapEff == 0`, `CapPrm == 0`, `CapBnd == 0`), `Seccomp: 2`
//! - `BTRFS_IOCTL_MAGIC` (`FICLONE = 0x40049409`) returning `EOPNOTSUPP` (errno 95, NOT `SIGSYS`!)
//! - Nested `unshare(CLONE_NEWUSER)` blocked (`EPERM`)
//! - `destroy()` executing `cgroup.kill` leaving ZERO surviving descendant processes

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_guest::{AgentState, ErrorCode, OutputStream};
use aos_sandbox::{
    ExecRequest, FreezeOptions, GuestAgentSource, NamespaceDriver, NetnsMode, SandboxDriver,
    SandboxError, SeccompPolicy, SpawnWorldSpec,
};
use aos_types::{EpochId, WorldId};

const DEFAULT_ROOTFS_STAGE: &str = "/var/lib/forkloom/guest-image/rootfs-stage";

fn unique_test_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = PathBuf::from("/tmp").join(format!(
        "aos-sandbox-{prefix}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    // A root agentd only accepts rootfs dirs that other host users cannot reach.
    fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    dir
}

/// Compile a tiny static C probe inside `dst_path` testing:
/// - `ioctl(fd, FICLONE=0x40049409, fd)` -> must return -1 with errno == EOPNOTSUPP (95) and NOT die from SIGSYS!
/// - `unshare(CLONE_NEWUSER)` -> must return -1 with errno == EPERM (1)
/// - `mount("none", "/", "tmpfs", 0, NULL)` -> must return -1 with errno == EPERM (1)
/// - `syscall(SYS_io_uring_setup=425, 1, NULL)` -> must return -1 with errno == EPERM (1)
/// - `pthread_create` (thread via clone3->ENOSYS->clone fallback) -> must succeed!
fn build_static_seccomp_probe(dst_path: &Path) -> bool {
    let src_path = dst_path.with_extension("c");
    let c_code = r#"
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

static void *thread_fn(void *arg) {
    *(int *)arg = 12345;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--spawn-daemon") == 0) {
        pid_t p = fork();
        if (p < 0) { perror("fork"); return 20; }
        if (p == 0) {
            setsid();
            pid_t p2 = fork();
            if (p2 > 0) _exit(0);
            if (p2 == 0) {
                for (int fd = 0; fd < 64; fd++) close(fd);
                pause();
                _exit(0);
            }
            _exit(21);
        }
        printf("DAEMON_SPAWNED\n");
        fflush(stdout);
        return 0;
    }

    int fd = open("/tmp/probe.tmp", O_CREAT | O_RDWR, 0600);
    if (fd < 0) { perror("open"); return 10; }

    errno = 0;
    int rc_ficlone = ioctl(fd, 0x40049409UL, fd);
    int err_ficlone = errno;
    close(fd);

    errno = 0;
    int rc_unshare = unshare(CLONE_NEWUSER);
    int err_unshare = errno;

    errno = 0;
    int rc_mount = mount("none", "/tmp", "tmpfs", 0, NULL);
    int err_mount = errno;

    errno = 0;
    long rc_uring = syscall(425, 1, NULL);
    int err_uring = errno;

    int thread_val = 0;
    pthread_t tid;
    int rc_thread = pthread_create(&tid, NULL, thread_fn, &thread_val);
    if (rc_thread == 0) {
        pthread_join(tid, NULL);
    }

    printf("ficlone=%d:%d unshare=%d:%d mount=%d:%d uring=%ld:%d thread=%d:%d\n",
           rc_ficlone, err_ficlone,
           rc_unshare, err_unshare,
           rc_mount, err_mount,
           rc_uring, err_uring,
           rc_thread, thread_val);

    /* Calls on PID 1 only re-apply its current values, so they are harmless if they get through. */
    struct rlimit rl;
    errno = 0;
    long rc_prl1 = syscall(SYS_prlimit64, 1, RLIMIT_NOFILE, NULL, &rl);
    int err_prl1 = errno;
    errno = 0;
    long rc_prl0 = syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, &rl);
    int err_prl0 = errno;
    errno = 0;
    int rc_prio1 = setpriority(PRIO_PROCESS, 1, 0);
    int err_prio1 = errno;
    errno = 0;
    int rc_prio0 = setpriority(PRIO_PROCESS, 0, 1);
    int err_prio0 = errno;
    cpu_set_t cpus;
    sched_getaffinity(0, sizeof cpus, &cpus);
    errno = 0;
    int rc_aff1 = sched_setaffinity(1, sizeof cpus, &cpus);
    int err_aff1 = errno;
    errno = 0;
    long rc_io1 = syscall(SYS_ioprio_set, 1, 1, 0);
    int err_io1 = errno;
    errno = 0;
    long rc_key = syscall(SYS_keyctl, 0, -4, 0);
    int err_key = errno;
    printf("prlimit1=%ld:%d prlimit0=%ld:%d prio1=%d:%d prio0=%d:%d aff1=%d:%d ioprio1=%ld:%d keyctl=%ld:%d\n",
           rc_prl1, err_prl1, rc_prl0, err_prl0, rc_prio1, err_prio1, rc_prio0, err_prio0,
           rc_aff1, err_aff1, rc_io1, err_io1, rc_key, err_key);
    return 0;
}
"#;
    if fs::write(&src_path, c_code).is_err() {
        return false;
    }
    let ok = Command::new("gcc")
        .args(["-static", "-O2", "-pthread"])
        .arg(&src_path)
        .arg("-o")
        .arg(dst_path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = fs::remove_file(&src_path);
    ok
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    let status = Command::new("cp")
        .args(["-a"])
        .arg(src)
        .arg(dst)
        .status()
        .expect("cp -a rootfs");
    assert!(status.success(), "failed to copy test rootfs");
}

#[test]
fn live_linux_namespace_driver_hardening_and_cgroup_kill() {
    let stage = PathBuf::from(DEFAULT_ROOTFS_STAGE);
    if !stage.is_dir() || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        eprintln!(
            "skipping live NamespaceDriver test: {} or cgroup v2 not present",
            DEFAULT_ROOTFS_STAGE
        );
        return;
    }

    // Prepare an isolated scratch copy of the minimal rootfs (contains static /sbin/init = aos-guest).
    let work = unique_test_dir("ns-live");
    let rootfs = work.join("rootfs");
    copy_dir_recursive(&stage, &rootfs);

    // Compile our static C seccomp probe inside the scratch rootfs so we can verify
    // exact kernel errnos (EOPNOTSUPP=95 on FICLONE, EPERM=1 on unshare/mount/io_uring,
    // and pthread_create succeeding via clone3->ENOSYS->clone!).
    let probe_host = rootfs.join("usr/bin/seccomp-probe");
    let have_probe = build_static_seccomp_probe(&probe_host);
    assert!(have_probe, "gcc -static must build seccomp-probe in Forkloom-Dev");

    let driver = NamespaceDriver::new();
    let world_id = WorldId::random();
    let epoch = EpochId::new(99).unwrap();
    let mut spec = SpawnWorldSpec::new(
        world_id,
        epoch,
        &rootfs,
        GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
    );
    spec.hostname = Some("fl-live-test".to_owned());
    spec.seccomp_policy = SeccompPolicy::StrictBaseline;
    spec.netns_mode = NetnsMode::IsolatedLoopback;
    spec.handshake_timeout = Duration::from_secs(5);

    let mut world = driver
        .spawn_world(spec)
        .expect("NamespaceDriver::spawn_world must succeed on Linux");

    // 1. Verify world metadata, PID 1 inside pidns, and cgroup v2 membership.
    let info = world.info().clone();
    assert_eq!(info.driver_name, "namespace");
    assert!(info.seccomp_enabled);
    assert!(info.userns_enabled);
    assert!(info.netns_isolated);
    let host_pid = info.host_pid.expect("host_pid present");
    let world_cg = info.cgroup_path.clone().expect("world cgroup present");

    let cg_procs = fs::read_to_string(world_cg.join("cgroup.procs")).expect("read cgroup.procs");
    assert!(
        cg_procs.lines().any(|l| l.trim() == host_pid.to_string()),
        "host_pid {host_pid} must live in {:?} (procs={cg_procs:?})",
        world_cg
    );

    let pong = world.ping(1234).expect("Ping on live namespace world");
    assert_eq!(pong.pid, 1, "aos-guest must be PID 1 inside new pidns");
    assert_eq!(pong.state, AgentState::Ready);

    // 2. Verify isolated UTS hostname, loopback-only netns, NoNewPrivs, Seccomp=2, and 0 caps.
    let mut streamed = Vec::new();
    let mut status_req = ExecRequest::new(
        "check-hardening",
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo HOST=$(hostname); echo IFACES=$(ls /sys/class/net 2>/dev/null || ip -o link show | awk -F': ' '{print $2}' | tr '\n' ','); grep -E '^(NoNewPrivs|Seccomp|CapEff|CapPrm|CapInh|CapBnd):' /proc/self/status".into(),
        ],
    );
    status_req.stream_chunk_bytes = Some(64);
    let status_reply = world
        .exec_streaming(status_req, |chunk| {
            if chunk.stream == OutputStream::Stdout {
                streamed.extend_from_slice(&chunk.data);
            }
        })
        .expect("exec check-hardening");
    assert_eq!(status_reply.exit_code, Some(0));
    let out = String::from_utf8_lossy(&streamed);
    assert!(out.contains("HOST=fl-live-test"), "hostname mismatch:\n{out}");
    assert!(out.contains("NoNewPrivs:\t1"), "NoNewPrivs not set:\n{out}");
    assert!(out.contains("Seccomp:\t2"), "Seccomp filter mode (2) not active:\n{out}");
    assert!(
        out.contains("CapEff:\t0000000000000000"),
        "CapEff not zero:\n{out}"
    );
    assert!(
        out.contains("CapPrm:\t0000000000000000"),
        "CapPrm not zero:\n{out}"
    );
    assert!(
        out.contains("CapBnd:\t0000000000000000"),
        "CapBnd not zero:\n{out}"
    );

    // Verify isolated netns has loopback UP and no external interfaces.
    let lo_reply = world
        .exec(ExecRequest::new(
            "check-net",
            vec!["/usr/bin/ip".into(), "-o".into(), "link".into(), "show".into()],
        ))
        .expect("exec ip link show");
    assert_eq!(lo_reply.exit_code, Some(0));
    let lo_out = String::from_utf8_lossy(lo_reply.stdout.head.as_slice());
    let iface_lines: Vec<&str> = lo_out.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        iface_lines.len(),
        1,
        "isolated netns must expose only lo, got:\n{lo_out}"
    );
    assert!(
        iface_lines[0].contains("lo:") && iface_lines[0].contains("UP"),
        "lo must be UP in isolated netns:\n{lo_out}"
    );

    // 3. Verify seccomp-bpf live kernel behavior:
    //    - FICLONE (0x40049409) -> -1 with errno=95 (EOPNOTSUPP), process NOT killed by SIGSYS!
    //    - unshare(CLONE_NEWUSER) -> -1 with errno=1 (EPERM)
    //    - mount(...) -> -1 with errno=1 (EPERM)
    //    - io_uring_setup(...) -> -1 with errno=1 (EPERM)
    //    - pthread_create -> succeeds (0, thread_val=12345) via clone3(ENOSYS)->clone!
    let probe_reply = world
        .exec(ExecRequest::new(
            "run-seccomp-probe",
            vec!["/usr/bin/seccomp-probe".into()],
        ))
        .expect("exec seccomp-probe");
    assert_eq!(
        probe_reply.exit_code,
        Some(0),
        "seccomp-probe died (signal={:?}, stderr={})",
        probe_reply.signal,
        String::from_utf8_lossy(probe_reply.stderr.head.as_slice())
    );
    let probe_out = String::from_utf8_lossy(probe_reply.stdout.head.as_slice());
    assert!(
        probe_out.contains("ficlone=-1:95"),
        "BTRFS FICLONE must return EOPNOTSUPP (95), got: {probe_out}"
    );
    assert!(
        probe_out.contains("unshare=-1:1"),
        "nested CLONE_NEWUSER must return EPERM (1), got: {probe_out}"
    );
    assert!(
        probe_out.contains("mount=-1:1"),
        "mount must return EPERM (1), got: {probe_out}"
    );
    assert!(
        probe_out.contains("uring=-1:1"),
        "io_uring_setup must return EPERM (1), got: {probe_out}"
    );
    assert!(
        probe_out.contains("thread=0:12345"),
        "normal pthread_create must succeed via clone3(ENOSYS)->clone, got: {probe_out}"
    );
    // The workload shares PID 1's uid: limits, priorities and affinity of PID 1 stay out of reach,
    // its own stay usable; keyrings are off.
    for expect in [
        "prlimit1=-1:1 ",
        "prlimit0=0:0 ",
        "prio1=-1:1 ",
        "prio0=0:0 ",
        "aff1=-1:1 ",
        "ioprio1=-1:1 ",
        "keyctl=-1:1\n",
    ] {
        assert!(probe_out.contains(expect), "expected {expect:?} in: {probe_out}");
    }

    // 4. Verify /dev/shm bounded tmpfs mount exists inside pivoted rootfs (§7.4).
    let shm_reply = world
        .exec(ExecRequest::new(
            "check-shm",
            vec!["/bin/sh".into(), "-c".into(), "grep ' /dev/shm tmpfs ' /proc/mounts".into()],
        ))
        .expect("exec check-shm");
    assert_eq!(shm_reply.exit_code, Some(0), "/dev/shm tmpfs must be mounted");

    // 5. Spawn a real double-forked daemon (closing all fds 0..64) inside the sandbox and verify
    //    it does not outlive its foreground Exec (§7.1), then test live host-side `freeze_and_sync` (P0-1) + `AgentFrozen` rejection,
    //    then `destroy()` and verify `cgroup.kill` kills the frozen world cleanly!
    let bg_reply = world
        .exec(ExecRequest::new(
            "spawn-daemon",
            vec!["/usr/bin/seccomp-probe".into(), "--spawn-daemon".into()],
        ))
        .expect("exec spawn-daemon");
    assert_eq!(bg_reply.exit_code, Some(0));
    let exec_cg = world_cg.join("exec");
    assert_eq!(
        fs::read_to_string(exec_cg.join("cgroup.procs")).expect("read exec cgroup.procs"),
        "",
        "double-forked daemon must not outlive its Exec"
    );

    // Put a straggler into the exec cgroup from the host: freeze and destroy must cover it too.
    let mut straggler = Command::new("sleep").arg("300").spawn().expect("sleep");
    fs::write(exec_cg.join("cgroup.procs"), straggler.id().to_string())
        .expect("move straggler into exec cgroup");

    // Unfreeze before freeze MUST be rejected with InvalidStateTransition.
    let pre_unfreeze_err = world.unfreeze(Duration::from_secs(5)).unwrap_err();
    assert!(
        matches!(
            pre_unfreeze_err,
            SandboxError::GuestError {
                code: ErrorCode::InvalidStateTransition,
                ..
            }
        ),
        "expected InvalidStateTransition when unfreezing non-frozen world, got {pre_unfreeze_err:?}"
    );

    // FreezeAndSync on live NamespaceDriver world (host freezes w-<id> + syncfs rootfs).
    let freeze = world
        .freeze_and_sync(FreezeOptions::disk_clean())
        .expect("live NamespaceDriver freeze_and_sync must succeed");
    assert!(freeze.disk_clean, "disk_clean must be true after syncfs");
    assert_eq!(freeze.synced_paths, 1);

    let cg_events = fs::read_to_string(world_cg.join("cgroup.events")).expect("read cgroup.events");
    assert!(
        cg_events.lines().any(|l| l.trim() == "frozen 1"),
        "w-<id>/cgroup.events must report 'frozen 1', got:\n{cg_events}"
    );

    // Exec while frozen MUST be rejected with AgentFrozen.
    let frozen_err = world
        .exec(ExecRequest::new("blocked-while-frozen", vec!["/bin/true".into()]))
        .unwrap_err();
    assert!(
        matches!(
            frozen_err,
            SandboxError::GuestError {
                code: ErrorCode::AgentFrozen,
                ..
            }
        ),
        "expected AgentFrozen while frozen, got {frozen_err:?}"
    );

    // Unfreeze (agentd Checkpoint resume path): verify frozen 0 -> Ping Ready -> Exec succeeds!
    world
        .unfreeze(Duration::from_secs(5))
        .expect("live NamespaceDriver unfreeze must succeed");

    let cg_events_unfrozen =
        fs::read_to_string(world_cg.join("cgroup.events")).expect("read cgroup.events after unfreeze");
    assert!(
        cg_events_unfrozen.lines().any(|l| l.trim() == "frozen 0"),
        "w-<id>/cgroup.events must report 'frozen 0' after unfreeze, got:\n{cg_events_unfrozen}"
    );

    let post_unfreeze_pong = world.ping(9999).expect("Ping after unfreeze");
    assert_eq!(post_unfreeze_pong.state, AgentState::Ready);

    let post_unfreeze_exec = world
        .exec(ExecRequest::new(
            "after-unfreeze",
            vec!["/bin/sh".into(), "-c".into(), "echo AFTER_UNFREEZE_OK".into()],
        ))
        .expect("Exec after unfreeze must succeed");
    assert_eq!(post_unfreeze_exec.exit_code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(post_unfreeze_exec.stdout.head.as_slice()).trim(),
        "AFTER_UNFREEZE_OK"
    );

    // The Exec above cleared the exec cgroup, straggler included; add another one.
    let first = straggler.wait().expect("wait first straggler");
    assert!(!first.success());
    let mut straggler = Command::new("sleep").arg("300").spawn().expect("sleep");
    fs::write(exec_cg.join("cgroup.procs"), straggler.id().to_string())
        .expect("move straggler into exec cgroup");

    // Re-freeze and verify destroy() cleanly kills & removes a frozen world with a straggler!
    let freeze2 = world
        .freeze_and_sync(FreezeOptions::disk_clean())
        .expect("second freeze_and_sync must succeed");
    assert!(freeze2.disk_clean);

    // Destroy MUST cleanly kill & remove the frozen world cgroup with 0 surviving PIDs!
    world.destroy().expect("world.destroy must succeed on frozen world");
    assert!(
        !world_cg.exists(),
        "world cgroup {:?} must be removed after destroy",
        world_cg
    );

    // Verify aos-guest and the straggler were both killed.
    assert!(
        !PathBuf::from(format!("/proc/{host_pid}")).exists(),
        "aos-guest pid {host_pid} survived cgroup.kill!"
    );
    let straggler_status = straggler
        .try_wait()
        .expect("wait straggler")
        .expect("straggler survived cgroup.kill!");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&straggler_status),
        Some(9)
    );

    // 6. Verify P0-2 symlink rejection in untrusted rootfs before pivot_root!
    let bad_rootfs = work.join("symlink-rootfs");
    copy_dir_recursive(&stage, &bad_rootfs);
    let _ = fs::remove_dir_all(bad_rootfs.join("dev"));
    std::os::unix::fs::symlink("/tmp", bad_rootfs.join("dev")).unwrap();
    let bad_spec = SpawnWorldSpec::new(
        WorldId::random(),
        EpochId::new(99).unwrap(),
        &bad_rootfs,
        GuestAgentSource::InRootfs(PathBuf::from("/sbin/init")),
    );
    let sym_err = driver
        .spawn_world(bad_spec)
        .err()
        .expect("symlinked rootfs/dev must be rejected");
    assert!(
        matches!(sym_err, SandboxError::InvalidConfig(_)),
        "expected InvalidConfig for symlinked rootfs/dev, got {sym_err:?}"
    );

    // Fails harmlessly while another world of this epoch is still alive.
    let _ = fs::remove_dir(world_cg.parent().unwrap());
    let _ = fs::remove_dir_all(&work);
}
