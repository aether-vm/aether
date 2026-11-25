//! Live Linux `NamespaceDriver` privilege-isolation and resource-limit tests (`R-001`).
//!
//! Must run as root on Linux with `/var/lib/forkloom/guest-image/rootfs-stage` present.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox::{
    DEFAULT_CGROUP_SLICE_ROOT, ExecReply, ExecRequest, GuestAgentSource, IdMapRange, NamespaceDriver, SandboxDriver,
    SandboxError, SpawnWorldSpec, WorldHandle,
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
