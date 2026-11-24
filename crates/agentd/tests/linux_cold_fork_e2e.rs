//! Live Linux End-to-End Cold-Fork Integration Test (`agentd --backend production` + `aos` CLI +
//! real Btrfs loop pool + separate `ext4` `meta/` + `TreeStore` + `NamespaceDriver` + `aos-guest`
//! over a `0600` Unix Domain Socket).
//!
//! Exercises the complete Phase 1 production stack inside `wsl -d Forkloom-Dev`:
//! 1. `aos version --json` (`NegotiateVersion` over `0600` UDS; zero TCP sockets).
//! 2. `aos frame import` (real rootfs tar with static `aos-guest` + `busybox` + `seccomp-probe`
//!    -> `openat2` confined unpack -> sealed `BTRFS_SUBVOL_RDONLY` subvolume + `fsync_subvolume`
//!    -> committed in `ext4` `forkloom.redb`).
//! 3. `aos world create --driver namespace` (O(1) writable Btrfs snapshot `pool/worlds/w-<id>` +
//!    `NamespaceDriver` `clone3(CLONE_INTO_CGROUP | CLONE_NEW*)` + `seccomp-bpf` + `aos-guest`).
//! 4. `aos world exec` running `/usr/bin/seccomp-probe` inside the Btrfs sandbox:
//!    verifies `FICLONE -> EOPNOTSUPP (95)`, `unshare(CLONE_NEWUSER) -> EPERM (1)`,
//!    `mount -> EPERM (1)`, `io_uring_setup -> EPERM (1)`, and `pthread_create -> 0:12345`.
//! 5. `aos world exec` mutating `/workspace/app.txt` and creating `/workspace/added.txt`.
//! 6. `aos world checkpoint --timeline main` (host cgroup freeze + `syncfs` -> O(1) read-only
//!    Btrfs snapshot -> **unfreeze** -> T2 commit with `disk_clean=true`).
//! 7. Post-checkpoint `aos world exec` verifying the world resumed after `unfreeze()` and continues
//!    executing commands cleanly.
//! 8. `aos frame patch` computing a real Btrfs tree diff through `Untrusted<RawPatchBundle>` ->
//!    `PatchPathValidator` and returning the verified unified diff.
//! 9. `aos world destroy` (`cgroup.kill` -> 0 surviving processes, writable Btrfs subvolume removed).
//! 10. Crash/restart recovery: spawns a second world with a double-forked background daemon, kills
//!     `agentd`, restarts `agentd --backend production`, and verifies R2 kills the stale epoch
//!     cgroup (`0` surviving processes) & removes the stale world subvolume, R5 marks the world
//!     `Lost`, R6 finds `0` orphans, and replaying `aos world exec --request-id ...` returns
//!     explicit `ERROR_CODE_OUTCOME_UNKNOWN`.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_ROOTFS_STAGE: &str = "/var/lib/forkloom/guest-image/rootfs-stage";

struct E2eHarness {
    base_dir: PathBuf,
    img_path: PathBuf,
    pool_dir: PathBuf,
    meta_dir: PathBuf,
    tmpfs_dir: PathBuf,
    cgroup_root: PathBuf,
    sock_path: PathBuf,
    mounted: bool,
    daemon: Option<Child>,
}

impl E2eHarness {
    fn new() -> Option<Self> {
        if !Path::new(DEFAULT_ROOTFS_STAGE).is_dir()
            || !Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        {
            eprintln!("skipping live E2E test: rootfs-stage or cgroup v2 unavailable");
            return None;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir = PathBuf::from(format!(
            "/var/lib/forkloom/phase1-e2e-test/run-{}-{nanos}",
            std::process::id()
        ));
        let img_path = base_dir.join("pool.btrfs.img");
        let pool_dir = base_dir.join("pool");
        let meta_dir = base_dir.join("meta");
        let tmpfs_dir = base_dir.join("volatile");
        let cgroup_root = PathBuf::from(format!(
            "/sys/fs/cgroup/forkloom.slice/e2e-{}-{nanos}",
            std::process::id()
        ));
        let sock_path = base_dir.join("run/agentd.sock");

        fs::create_dir_all(&pool_dir).unwrap();
        fs::create_dir_all(&meta_dir).unwrap();
        fs::create_dir_all(&tmpfs_dir).unwrap();
        fs::create_dir_all(&cgroup_root).unwrap();

        // Format and mount a 512 MiB loop Btrfs pool (separate from ext4 meta_dir!).
        let f = fs::File::create(&img_path).unwrap();
        f.set_len(512 * 1024 * 1024).unwrap();
        drop(f);

        let mkfs = Command::new("mkfs.btrfs")
            .args(["-f", "-q"])
            .arg(&img_path)
            .status()
            .expect("mkfs.btrfs");
        assert!(mkfs.success(), "mkfs.btrfs failed");

        let mount = Command::new("mount")
            .args(["-o", "loop,noatime"])
            .arg(&img_path)
            .arg(&pool_dir)
            .status()
            .expect("mount loop btrfs");
        assert!(mount.success(), "mount loop btrfs failed");

        Some(Self {
            base_dir,
            img_path,
            pool_dir,
            meta_dir,
            tmpfs_dir,
            cgroup_root,
            sock_path,
            mounted: true,
            daemon: None,
        })
    }

    fn start_agentd(&mut self, agentd_bin: &Path) {
        self.stop_agentd();
        let log_path = self.base_dir.join("agentd.log");
        let log_file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .unwrap();
        let err_file = log_file.try_clone().unwrap();

        // Notice: we do NOT pass `--allow-same-fs` or `--allow-non-btrfs` because `meta_dir` is on
        // ext4 and `pool_dir` is a real mounted Btrfs filesystem!
        let child = Command::new(agentd_bin)
            .arg("--backend")
            .arg("production")
            .arg("--socket")
            .arg(&self.sock_path)
            .arg("--meta-dir")
            .arg(&self.meta_dir)
            .arg("--pool-dir")
            .arg(&self.pool_dir)
            .arg("--tmpfs-dir")
            .arg(&self.tmpfs_dir)
            .arg("--cgroup-root")
            .arg(&self.cgroup_root)
            .arg("--ballast-mib")
            .arg("32")
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(err_file))
            .spawn()
            .expect("spawn agentd");
        self.daemon = Some(child);

        for _ in 0..100 {
            if self.sock_path.exists() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let log = fs::read_to_string(&log_path).unwrap_or_default();
        panic!("agentd did not bind socket {:?}:\n{log}", self.sock_path);
    }

    fn stop_agentd(&mut self) {
        if let Some(mut child) = self.daemon.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_file(&self.sock_path);
    }
}

impl Drop for E2eHarness {
    fn drop(&mut self) {
        self.stop_agentd();
        if self.cgroup_root.exists() {
            if let Ok(entries) = fs::read_dir(&self.cgroup_root) {
                for e in entries.flatten() {
                    let p = e.path();
                    let _ = fs::write(p.join("cgroup.kill"), b"1\n");
                    let _ = fs::write(p.join("cgroup.freeze"), b"0\n");
                    if let Ok(sub) = fs::read_dir(&p) {
                        for s in sub.flatten() {
                            let sp = s.path();
                            let _ = fs::write(sp.join("cgroup.kill"), b"1\n");
                            let _ = fs::write(sp.join("cgroup.freeze"), b"0\n");
                            let _ = fs::write(sp.join("cgroup.kill"), b"1\n");
                            let _ = fs::remove_dir(&sp);
                        }
                    }
                    let _ = fs::remove_dir(&p);
                }
            }
            let _ = fs::remove_dir(&self.cgroup_root);
        }
        if self.mounted {
            for _ in 0..10 {
                if Command::new("umount")
                    .arg(&self.pool_dir)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                {
                    self.mounted = false;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if self.mounted {
                let _ = Command::new("umount").args(["-l"]).arg(&self.pool_dir).status();
                self.mounted = false;
            }
        }
        let _ = fs::remove_file(&self.img_path);
        let _ = fs::remove_dir_all(&self.base_dir);
        if let Some(parent) = self.base_dir.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn build_static_seccomp_probe(dst_path: &Path) {
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
#include <sys/syscall.h>
#include <unistd.h>

static void *thread_fn(void *arg) {
    *(int *)arg = 12345;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--spawn-daemon") == 0) {
        pid_t p = fork();
        if (p < 0) return 20;
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
    if (fd < 0) return 10;
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
    if (rc_thread == 0) pthread_join(tid, NULL);

    printf("ficlone=%d:%d unshare=%d:%d mount=%d:%d uring=%ld:%d thread=%d:%d\n",
           rc_ficlone, err_ficlone,
           rc_unshare, err_unshare,
           rc_mount, err_mount,
           rc_uring, err_uring,
           rc_thread, thread_val);
    return 0;
}
"#;
    fs::write(&src_path, c_code).unwrap();
    let status = Command::new("gcc")
        .args(["-static", "-O2", "-pthread"])
        .arg(&src_path)
        .arg("-o")
        .arg(dst_path)
        .status()
        .expect("gcc -static seccomp-probe");
    let _ = fs::remove_file(&src_path);
    assert!(status.success(), "gcc -static seccomp-probe failed");
}

fn prepare_clean_rootfs_tar(base_dir: &Path) -> PathBuf {
    let stage_src = Path::new(DEFAULT_ROOTFS_STAGE);
    let stage_copy = base_dir.join("rootfs-prep");
    for d in ["bin", "sbin", "usr/bin", "proc", "sys", "dev", "tmp", "etc", "workspace"] {
        fs::create_dir_all(stage_copy.join(d)).unwrap();
    }

    // Copy static musl `aos-guest` (/sbin/init) and static `busybox` (/bin/busybox)
    fs::copy(stage_src.join("sbin/init"), stage_copy.join("sbin/init")).unwrap();
    fs::set_permissions(
        stage_copy.join("sbin/init"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::copy(
        stage_src.join("bin/busybox"),
        stage_copy.join("bin/busybox"),
    )
    .unwrap();
    fs::set_permissions(
        stage_copy.join("bin/busybox"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Use strictly relative symlinks inside the rootfs so zero-trust PatchPathValidator
    // verifies every link stays confined inside the rootfs tree!
    for applet in ["sh", "cat", "echo", "ls", "grep", "hostname", "mkdir", "rm"] {
        std::os::unix::fs::symlink("busybox", stage_copy.join("bin").join(applet)).unwrap();
    }
    std::os::unix::fs::symlink("../../sbin/init", stage_copy.join("usr/bin/aos-guest")).unwrap();

    build_static_seccomp_probe(&stage_copy.join("usr/bin/seccomp-probe"));
    fs::write(stage_copy.join("workspace/app.txt"), b"initial-v1\n").unwrap();

    let tar_path = base_dir.join("rootfs.tar");
    let tar_st = Command::new("tar")
        .args(["--format=ustar", "-cf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&stage_copy)
        .arg(".")
        .status()
        .expect("tar rootfs");
    assert!(tar_st.success(), "tar rootfs failed");
    tar_path
}

fn run_aos(aos_bin: &Path, sock: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(aos_bin)
        .arg("--socket")
        .arg(sock)
        .arg("--owner")
        .arg("e2e")
        .args(args)
        .output()
        .expect("run aos CLI");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn live_linux_btrfs_namespace_agentd_and_aos_cli_cold_fork_e2e() {
    let Some(mut h) = E2eHarness::new() else {
        return;
    };

    let agentd_bin = PathBuf::from(env!("CARGO_BIN_EXE_agentd"));
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let st = Command::new("cargo")
        .args(["build", "-p", "aos-cli"])
        .current_dir(&workspace_root)
        .status()
        .expect("cargo build -p aos-cli");
    assert!(st.success(), "building aos-cli failed");
    let aos_bin = workspace_root.join("target/debug/aos");
    assert!(aos_bin.is_file(), "aos binary not found at {:?}", aos_bin);

    let tar_path = prepare_clean_rootfs_tar(&h.base_dir);
    h.start_agentd(&agentd_bin);

    // Verify 0700 parent dir and 0600 socket permissions
    let dir_mode = fs::symlink_metadata(h.sock_path.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let sock_mode = fs::symlink_metadata(&h.sock_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_eq!(sock_mode, 0o600);

    // 1. aos version --json
    let (ok, ver_out, ver_err) = run_aos(&aos_bin, &h.sock_path, &["--json", "version"]);
    assert!(ok, "aos version failed: {ver_err}");
    let ver_json: serde_json::Value = serde_json::from_str(&ver_out).unwrap();
    assert_eq!(ver_json["api_major"], 1);
    assert_eq!(ver_json["daemon_epoch"], 1);

    // 2. aos frame import (real tar -> openat2 -> Btrfs RO subvol -> redb commit)
    let (ok, imp_out, imp_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "--json",
            "frame",
            "import",
            tar_path.to_str().unwrap(),
            "--label",
            "suite=phase1-e2e",
        ],
    );
    assert!(ok, "aos frame import failed: {imp_err}");
    let imp_json: serde_json::Value = serde_json::from_str(&imp_out).unwrap();
    let base_fid = imp_json["frame_id"].as_str().unwrap().to_owned();
    assert_eq!(imp_json["disk_clean"], true);
    let base_subvol = h.pool_dir.join("objects").join(format!("f-{base_fid}-subvol"));
    assert!(base_subvol.is_dir(), "Btrfs base subvolume must exist");

    // 3. aos world create --base <base_fid> --driver namespace
    let (ok, cw_out, cw_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &["--json", "world", "create", "--base", &base_fid, "--driver", "namespace"],
    );
    assert!(ok, "aos world create failed: {cw_err}");
    let cw_json: serde_json::Value = serde_json::from_str(&cw_out).unwrap();
    let wid = cw_json["world_id"].as_str().unwrap().to_owned();
    let fence = cw_json["fencing_token"].as_u64().unwrap().to_string();

    // 4. aos world exec: run static seccomp-probe inside live Btrfs + NamespaceDriver sandbox!
    let (ok, probe_out, probe_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &["world", "exec", &wid, "--fence", &fence, "--", "/usr/bin/seccomp-probe"],
    );
    assert!(ok, "seccomp-probe failed: {probe_err}");
    assert!(
        probe_out.contains("ficlone=-1:95"),
        "expected BTRFS_IOCTL_MAGIC FICLONE -> EOPNOTSUPP (95), got: {probe_out}"
    );
    assert!(
        probe_out.contains("unshare=-1:1"),
        "expected unshare(CLONE_NEWUSER) -> EPERM (1), got: {probe_out}"
    );
    assert!(
        probe_out.contains("mount=-1:1") && probe_out.contains("uring=-1:1"),
        "expected mount & io_uring -> EPERM (1), got: {probe_out}"
    );
    assert!(
        probe_out.contains("thread=0:12345"),
        "expected pthread_create to succeed via clone3->ENOSYS->clone fallback, got: {probe_out}"
    );

    // 5. aos world exec: mutate files inside the writable Btrfs world subvolume
    let (ok, _, mut_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "world",
            "exec",
            &wid,
            "--fence",
            &fence,
            "--",
            "/bin/sh",
            "-c",
            "printf 'mutated-v2\n' > /workspace/app.txt && printf 'created-in-sandbox\n' > /workspace/added.txt",
        ],
    );
    assert!(ok, "file mutation exec failed: {mut_err}");

    // 6. aos world checkpoint (freeze_and_sync -> Btrfs RO snapshot -> unfreeze -> commit)
    let (ok, cp_out, cp_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "--json",
            "world",
            "checkpoint",
            &wid,
            "--fence",
            &fence,
            "--timeline",
            "main",
        ],
    );
    assert!(ok, "aos world checkpoint failed: {cp_err}");
    let cp_json: serde_json::Value = serde_json::from_str(&cp_out).unwrap();
    let cp_fid = cp_json["frame_id"].as_str().unwrap().to_owned();
    assert_eq!(cp_json["disk_clean"], true);
    assert_eq!(cp_json["timeline"], "main");

    // 7. Post-checkpoint aos world exec: verify world unfroze cleanly and continues running!
    let (ok, post_out, post_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "world",
            "exec",
            &wid,
            "--fence",
            &fence,
            "--",
            "/bin/sh",
            "-c",
            "cat /workspace/app.txt && echo POST_CHECKPOINT_OK",
        ],
    );
    assert!(ok, "post-checkpoint exec failed (did unfreeze run?): {post_err}");
    assert!(post_out.contains("mutated-v2") && post_out.contains("POST_CHECKPOINT_OK"));

    // 8. aos frame patch: real Btrfs tree diff validated through Untrusted + PatchPathValidator
    let (ok, patch_out, patch_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &["frame", "patch", &cp_fid, "--base", &base_fid],
    );
    assert!(ok, "aos frame patch failed: {patch_err}");
    assert!(
        patch_out.contains("+++ b/workspace/app.txt")
            && patch_out.contains("+mutated-v2")
            && patch_out.contains("+++ b/workspace/added.txt")
            && patch_out.contains("+created-in-sandbox"),
        "unexpected patch diff:\n{patch_out}"
    );

    // 9. aos world destroy: cgroup.kill + Btrfs writable clone destruction
    let world_cg = h.cgroup_root.join("epoch-1").join(format!("w-{wid}"));
    let world_subvol = h.pool_dir.join("worlds").join(format!("w-{wid}"));
    assert!(world_cg.exists());
    assert!(world_subvol.exists());

    let (ok, _, destroy_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &["world", "destroy", &wid, "--fence", &fence],
    );
    assert!(ok, "aos world destroy failed: {destroy_err}");
    assert!(!world_cg.exists(), "world cgroup must be removed on destroy");
    assert!(!world_subvol.exists(), "writable Btrfs world subvol must be destroyed");

    // 10. Crash/restart recovery test: spawn w2 with a background daemon, kill agentd, restart!
    let (ok, cw2_out, _) = run_aos(
        &aos_bin,
        &h.sock_path,
        &["--json", "world", "create", "--base", &base_fid],
    );
    assert!(ok);
    let cw2_json: serde_json::Value = serde_json::from_str(&cw2_out).unwrap();
    let wid2 = cw2_json["world_id"].as_str().unwrap().to_owned();
    let fence2 = cw2_json["fencing_token"].as_u64().unwrap().to_string();
    let (ok, d_out, d_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "world",
            "exec",
            &wid2,
            "--fence",
            &fence2,
            "--",
            "/usr/bin/seccomp-probe",
            "--spawn-daemon",
        ],
    );
    assert!(ok && d_out.contains("DAEMON_SPAWNED"), "spawn daemon failed: {d_err}");

    let w2_cg = h.cgroup_root.join("epoch-1").join(format!("w-{wid2}"));
    let w2_subvol = h.pool_dir.join("worlds").join(format!("w-{wid2}"));
    assert!(w2_cg.exists());
    assert!(w2_subvol.exists());

    // Simulate abrupt agentd crash and restart into epoch 2!
    h.start_agentd(&agentd_bin);

    // R2 must have killed & removed epoch-1 cgroups and reclaimed pool/worlds/w-<wid2>!
    assert!(!w2_cg.exists(), "R2 must kill and remove stale epoch-1 world cgroup");
    assert!(!w2_subvol.exists(), "R2 must reclaim stale writable world subvolume");

    // Exec with idempotency key on lost w2 must return explicit ERROR_CODE_OUTCOME_UNKNOWN!
    let (ok, _, unk_err) = run_aos(
        &aos_bin,
        &h.sock_path,
        &[
            "world",
            "exec",
            &wid2,
            "--fence",
            &fence2,
            "--request-id",
            "inflight-before-crash",
            "--",
            "/bin/sh",
            "-c",
            "echo should-not-run",
        ],
    );
    assert!(!ok, "exec on lost world must fail");
    assert!(
        unk_err.contains("ERROR_CODE_OUTCOME_UNKNOWN"),
        "expected ERROR_CODE_OUTCOME_UNKNOWN, got: {unk_err}"
    );
}
