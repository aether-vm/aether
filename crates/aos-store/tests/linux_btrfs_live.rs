//! Live Linux + real Btrfs integration tests for `aos-store`.
//!
//! Runs inside `wsl -d Forkloom-Dev` (as root) against a temporary `<= 2 GiB` loop-mounted Btrfs
//! image under `/var/lib/forkloom/phase1-store-test/`, unmounted and deleted unconditionally on
//! teardown (never touches `/mnt/*`).
//!
//! Run with:
//! `cargo test -p aos-store --test linux_btrfs_live -- --ignored --nocapture`

#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::Duration;

use aos_meta::{
    CommitFrameRequest, CommitProofBundle, FrameDurability, MetaConfig, MetaEngine, ObjectKind,
    PrepareFrameRequest, SystemClock,
};
use aos_store::btrfs::{BTRFS_FIRST_FREE_OBJECTID, BTRFS_SUBVOL_RDONLY, linux_impl as btrfs_sys};
use aos_store::{
    ExportPatchOptions, PatchFileChange, StoreError, SubvolHandle, TarImportOptions, TreeStore,
    TreeStoreConfig, TreeStoreRecoveryHooks,
};
use aos_types::{BootId, FrameId, PatchPathViolation, ProofKind};

const TEST_ROOT: &str = "/var/lib/forkloom/phase1-store-test";
const MIB: u64 = 1024 * 1024;
const HARD_MAX_POOL_MIB: u64 = 2048; // <= 2 GiB per assignment guardrail

static SEQ: AtomicU64 = AtomicU64::new(0);

fn run(cmd: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {cmd} {args:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd} {args:?} failed (code={:?}):\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Self-cleaning temporary loop Btrfs mount under `/var/lib/forkloom/phase1-store-test/`.
struct TempBtrfsPool {
    img: PathBuf,
    mnt: PathBuf,
    loop_dev: Option<String>,
    mounted: bool,
}

impl TempBtrfsPool {
    fn create(label: &str, size_mib: u64, mount_opts: &str) -> Self {
        assert!(size_mib <= HARD_MAX_POOL_MIB, "pool size must be <= 2 GiB");
        assert!(
            !Path::new(TEST_ROOT).starts_with("/mnt"),
            "never touch /mnt/*"
        );
        fs::create_dir_all(TEST_ROOT).unwrap();
        let id = SEQ.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let img = Path::new(TEST_ROOT).join(format!("{label}-{pid}-{id}.img"));
        let mnt = Path::new(TEST_ROOT).join(format!("mnt-{label}-{pid}-{id}"));

        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&img)
            .unwrap();
        f.set_len(size_mib * MIB).unwrap();
        drop(f);

        let img_s = img.to_str().unwrap();
        let out = run("losetup", &["--find", "--show", img_s]);
        let dev = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        assert!(dev.starts_with("/dev/loop"), "unexpected loop dev: {dev:?}");

        let mut pool = Self {
            img,
            mnt,
            loop_dev: Some(dev.clone()),
            mounted: false,
        };

        run("mkfs.btrfs", &["-f", "-q", &dev]);
        fs::create_dir_all(&pool.mnt).unwrap();
        run(
            "mount",
            &["-t", "btrfs", "-o", mount_opts, &dev, pool.mnt.to_str().unwrap()],
        );
        pool.mounted = true;
        pool
    }

    fn mnt(&self) -> &Path {
        &self.mnt
    }
}

impl Drop for TempBtrfsPool {
    fn drop(&mut self) {
        if self.mounted {
            let mnt_s = self.mnt.to_str().unwrap();
            let mut ok = false;
            for _ in 0..10 {
                if Command::new("umount")
                    .arg(mnt_s)
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    ok = true;
                    break;
                }
                sleep(Duration::from_millis(200));
            }
            if !ok {
                let _ = Command::new("umount").args(["-l", mnt_s]).status();
            }
            self.mounted = false;
        }
        if let Some(dev) = self.loop_dev.take() {
            for _ in 0..10 {
                if Command::new("losetup")
                    .args(["-d", &dev])
                    .status()
                    .is_ok_and(|s| s.success())
                {
                    break;
                }
                sleep(Duration::from_millis(200));
            }
        }
        let _ = fs::remove_file(&self.img);
        let _ = fs::remove_dir(&self.mnt);
    }
}

fn build_tar<F>(f: F) -> Vec<u8>
where
    F: FnOnce(&mut tar::Builder<Vec<u8>>),
{
    let mut builder = tar::Builder::new(Vec::new());
    f(&mut builder);
    builder.into_inner().unwrap()
}

fn append_regular(b: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8], mode: u32) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(data.len() as u64);
    header.set_mode(mode);
    header.set_cksum();
    b.append_data(&mut header, path, data).unwrap();
}

#[test]
#[ignore = "requires root + live Linux Btrfs loop mount in Forkloom-Dev"]
fn btrfs_guardrails_reject_non_btrfs_mnt_autodefrag_and_qgroups() {
    // 1. Refuse /mnt/*
    let err = TreeStore::open(TreeStoreConfig::new("/mnt/c/forbidden-pool").with_ballast_bytes(0))
        .unwrap_err();
    assert!(matches!(err, StoreError::ForbiddenPoolRoot { .. }), "got {err:?}");

    // 2. Refuse non-Btrfs (ext4 / tmpfs under TEST_ROOT)
    fs::create_dir_all(TEST_ROOT).unwrap();
    let non_btrfs = Path::new(TEST_ROOT).join(format!("ext4-check-{}", std::process::id()));
    let err = TreeStore::open(TreeStoreConfig::new(&non_btrfs).with_ballast_bytes(0)).unwrap_err();
    let _ = fs::remove_dir_all(&non_btrfs);
    assert!(matches!(err, StoreError::NotBtrfs { .. }), "got {err:?}");

    // 3. Refuse autodefrag mount option
    {
        let pool = TempBtrfsPool::create("autodefrag", 512, "noatime,autodefrag");
        let err = TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(0))
            .unwrap_err();
        assert!(
            matches!(err, StoreError::AutodefragEnabled { .. }),
            "expected AutodefragEnabled, got {err:?}"
        );
    }

    // 4. Refuse qgroups enabled, then succeed after disabling qgroups
    {
        let pool = TempBtrfsPool::create("qgroups", 512, "noatime");
        run("btrfs", &["quota", "enable", pool.mnt().to_str().unwrap()]);
        let err = TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(0))
            .unwrap_err();
        assert!(
            matches!(err, StoreError::QgroupsEnabled { .. }),
            "expected QgroupsEnabled, got {err:?}"
        );

        run("btrfs", &["quota", "disable", pool.mnt().to_str().unwrap()]);
        let store =
            TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(8 * MIB)).unwrap();
        assert!(store.is_btrfs_backed());
        let st = store.ballast_status().unwrap();
        assert!(st.present);
        assert_eq!(st.actual_bytes, 8 * MIB);
    }
}

#[test]
#[ignore = "requires root + live Linux Btrfs loop mount in Forkloom-Dev"]
fn btrfs_full_cold_fork_openat2_tar_patch_export_and_meta_integration() {
    let pool = TempBtrfsPool::create("coldfork", 1024, "noatime");
    let store =
        TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(16 * MIB)).unwrap();
    assert!(store.is_btrfs_backed());

    // 1. Safe tar import via real openat2(RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)
    //    Includes: setuid bit (must be stripped), restrictive dir 0o555 with child file,
    //    safe relative symlink, and valid intra-root hardlink.
    let tar_bytes = build_tar(|b| {
        let mut ro_dir = tar::Header::new_gnu();
        ro_dir.set_entry_type(tar::EntryType::Directory);
        ro_dir.set_size(0);
        ro_dir.set_mode(0o555);
        ro_dir.set_cksum();
        b.append_data(&mut ro_dir, "locked_dir", &[][..]).unwrap();

        append_regular(b, "locked_dir/data.txt", b"inside ro dir\n", 0o644);
        append_regular(b, "bin/tool", b"#!/bin/sh\necho hi\n", 0o4755);
        append_regular(b, "src/lib.rs", b"pub fn v() -> u32 { 1 }\n", 0o644);

        let mut sl = tar::Header::new_gnu();
        sl.set_entry_type(tar::EntryType::Symlink);
        sl.set_size(0);
        sl.set_mode(0o777);
        sl.set_link_name("lib.rs").unwrap();
        sl.set_cksum();
        b.append_data(&mut sl, "src/lib_alias.rs", &[][..]).unwrap();

        let mut hl = tar::Header::new_gnu();
        hl.set_entry_type(tar::EntryType::Link);
        hl.set_size(0);
        hl.set_mode(0o644);
        hl.set_link_name("src/lib.rs").unwrap();
        hl.set_cksum();
        b.append_data(&mut hl, "src/lib_hard.rs", &[][..]).unwrap();
    });

    // Wire up real aos-meta on host ext4 (separate filesystem from Btrfs pool!)
    let meta_dir = Path::new(TEST_ROOT).join(format!("meta-{}", std::process::id()));
    let vol_dir = Path::new(TEST_ROOT).join(format!("vol-{}", std::process::id()));
    fs::create_dir_all(&meta_dir).unwrap();
    fs::create_dir_all(&vol_dir).unwrap();

    let (mut meta, _summary) = MetaEngine::open_and_recover(
        MetaConfig::new(&meta_dir, pool.mnt()),
        BootId::current().unwrap(),
        Box::new(TreeStoreRecoveryHooks::new(store.clone(), &vol_dir)),
        Arc::new(SystemClock),
    )
    .unwrap();

    let prep1 = meta
        .prepare_frame(
            &PrepareFrameRequest {
                owner: "store-test".into(),
                durability: FrameDurability::Durable,
                parent: None,
                object_kinds: vec![ObjectKind::TreeSubvol],
                labels: Default::default(),
                source_world: None,
            },
            None,
        )
        .unwrap();

    let persisted_base = store
        .import_tar(
            prep1.frame_id,
            Cursor::new(tar_bytes),
            &TarImportOptions::default(),
        )
        .unwrap();
    assert_eq!(persisted_base.proof().kind(), ProofKind::Subvolume);
    persisted_base.proof().verify_unchanged().unwrap();

    let base_path = persisted_base.value().path().to_path_buf();
    // Verify real Btrfs subvolume root inode (256) and RDONLY flag!
    assert_eq!(fs::symlink_metadata(&base_path).unwrap().ino(), BTRFS_FIRST_FREE_OBJECTID);
    let subvol_fd = btrfs_sys::open_dir_nofollow(&base_path).unwrap();
    assert_ne!(
        btrfs_sys::btrfs_subvol_getflags(&subvol_fd).unwrap() & BTRFS_SUBVOL_RDONLY,
        0,
        "imported subvolume MUST be sealed BTRFS_SUBVOL_RDONLY"
    );
    drop(subvol_fd);
    // Writing into sealed RO subvolume MUST fail with EROFS
    let write_err = fs::write(base_path.join("mutated"), b"no").unwrap_err();
    assert_eq!(write_err.raw_os_error(), Some(libc::EROFS));

    // Verify setuid bit was stripped (0o4755 -> 0o755)
    let tool_mode = fs::symlink_metadata(base_path.join("bin/tool"))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(tool_mode, 0o755, "setuid/setgid must be stripped");

    // Verify hardlink shares exact inode
    assert_eq!(
        fs::symlink_metadata(base_path.join("src/lib.rs")).unwrap().ino(),
        fs::symlink_metadata(base_path.join("src/lib_hard.rs")).unwrap().ino()
    );

    // Commit frame 1 into redb using PersistProof from TreeStore
    let base_handle = store.open_subvolume(&base_path).unwrap();
    assert!(base_handle.is_readonly());
    let managed_proof1 = SubvolHandle::into_managed_proof(persisted_base).unwrap();
    meta.commit_frame(
        &CommitFrameRequest {
            frame_id: prep1.frame_id,
            owner: "store-test".into(),
            disk_clean: true,
            fence: None,
            pin: None,
            timeline: None,
        },
        CommitProofBundle::new().with_persisted(managed_proof1),
        None,
    )
    .unwrap();

    // 2. O(1) writable Btrfs clone -> mutate -> snapshot_frame_readonly -> export_patch
    let world = store.create_writable_clone(&base_handle, "w-live-1").unwrap();
    assert!(!world.is_readonly());
    assert_eq!(fs::symlink_metadata(world.path()).unwrap().ino(), BTRFS_FIRST_FREE_OBJECTID);

    fs::write(world.path().join("src/lib.rs"), b"pub fn v() -> u32 { 2 }\n").unwrap();
    fs::write(world.path().join("added.txt"), b"fresh\n").unwrap();
    fs::remove_file(world.path().join("src/lib_hard.rs")).unwrap();

    let prep2 = meta
        .prepare_frame(
            &PrepareFrameRequest {
                owner: "store-test".into(),
                durability: FrameDurability::Durable,
                parent: Some(prep1.frame_id),
                object_kinds: vec![ObjectKind::TreeSubvol],
                labels: Default::default(),
                source_world: None,
            },
            None,
        )
        .unwrap();
    let persisted_snap = store.snapshot_frame_readonly(&world, prep2.frame_id).unwrap();
    let snap_path = persisted_snap.value().path().to_path_buf();
    assert_eq!(
        fs::write(snap_path.join("nope"), b"x").unwrap_err().raw_os_error(),
        Some(libc::EROFS)
    );
    let snap_handle = store.open_subvolume(&snap_path).unwrap();
    let managed_proof2 = SubvolHandle::into_managed_proof(persisted_snap).unwrap();
    meta.commit_frame(
        &CommitFrameRequest {
            frame_id: prep2.frame_id,
            owner: "store-test".into(),
            disk_clean: true,
            fence: None,
            pin: None,
            timeline: None,
        },
        CommitProofBundle::new().with_persisted(managed_proof2),
        None,
    )
    .unwrap();

    let patch = store
        .export_patch(&base_handle, &snap_handle, &ExportPatchOptions::default())
        .unwrap();
    assert_eq!(
        patch.changes(),
        &[
            PatchFileChange::PutFile {
                path: "added.txt".into(),
                contents: b"fresh\n".to_vec(),
                executable: false,
                modified: false,
            },
            PatchFileChange::PutFile {
                path: "src/lib.rs".into(),
                contents: b"pub fn v() -> u32 { 2 }\n".to_vec(),
                executable: false,
                modified: true,
            },
            PatchFileChange::Remove {
                path: "src/lib_hard.rs".into(),
            },
        ]
    );

    // 3. Real filesystem attacks in writable clone rejected by export_patch
    //    (a) symlink to /etc/shadow (never read, rejected with SymlinkEscape)
    let w_evil = store.create_writable_clone(&base_handle, "w-evil-symlink").unwrap();
    std::os::unix::fs::symlink("/etc/shadow", w_evil.path().join("leak")).unwrap();
    let err = store
        .export_patch(&base_handle, &w_evil, &ExportPatchOptions::default())
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::PatchValidation(ref e) if matches!(e.kind, PatchPathViolation::SymlinkEscape { .. })
    ));
    store.destroy_subvolume(w_evil.path()).unwrap();

    //    (b) case-folding collision on case-sensitive Btrfs (Foo.rs + foo.rs)
    let w_fold = store.create_writable_clone(&base_handle, "w-evil-fold").unwrap();
    fs::write(w_fold.path().join("Foo.rs"), b"1").unwrap();
    fs::write(w_fold.path().join("foo.rs"), b"2").unwrap();
    let err = store
        .export_patch(&base_handle, &w_fold, &ExportPatchOptions::default())
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::PatchValidation(ref e) if matches!(e.kind, PatchPathViolation::FoldCollision { .. })
    ));
    store.destroy_subvolume(w_fold.path()).unwrap();

    // 4. Destroy live world + delete committed frames through MetaEngine -> TreeStoreRecoveryHooks
    store.destroy_subvolume(world.path()).unwrap();
    store.destroy_subvolume(world.path()).unwrap(); // idempotent on NotFound

    meta.delete_frame(prep2.frame_id, "store-test", None).unwrap();
    meta.delete_frame(prep1.frame_id, "store-test", None).unwrap();
    assert!(!snap_path.exists());
    assert!(!base_path.exists());

    drop(meta);
    let _ = fs::remove_dir_all(&meta_dir);
    let _ = fs::remove_dir_all(&vol_dir);
}

#[test]
#[ignore = "requires root + live Linux Btrfs loop mount in Forkloom-Dev"]
fn btrfs_enospc_ballast_release_unblocks_subvolume_reclamation() {
    // Small 512 MiB Btrfs loop pool with 64 MiB emergency ballast.
    let pool = TempBtrfsPool::create("enospc", 512, "noatime");
    let store =
        TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(64 * MIB)).unwrap();

    // Create a victim RO subvolume (~32 MiB incompressible data)
    let mut payload = vec![0u8; 4 * MIB as usize];
    let mut state: u64 = 0xdead_beef_cafe_babe;
    for chunk in payload.as_chunks_mut::<8>().0 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *chunk = state.to_ne_bytes();
    }
    let tar_bytes = build_tar(|b| {
        for i in 0..8 {
            append_regular(b, &format!("blob-{i}.bin"), &payload, 0o644);
        }
    });
    let victim = store
        .import_tar(
            FrameId::random(),
            Cursor::new(tar_bytes),
            &TarImportOptions::default(),
        )
        .unwrap()
        .into_inner();

    // Fill the pool until real ENOSPC inside worlds/filler
    let fill_dir = store.worlds_dir().join("filler");
    fs::create_dir_all(&fill_dir).unwrap();
    let mut hit_enospc = false;
    for i in 0..2000u32 {
        let p = fill_dir.join(format!("f-{i:04}"));
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(&payload)
                    && aos_store::is_enospc(&e)
                {
                    hit_enospc = true;
                    break;
                }
            }
            Err(e) if aos_store::is_enospc(&e) => {
                hit_enospc = true;
                break;
            }
            Err(_) => break,
        }
    }
    assert!(hit_enospc, "must actually reach ENOSPC on the 512 MiB Btrfs pool");
    assert!(store.ballast_status().unwrap().present);

    // Releasing emergency ballast + BTRFS_IOC_SYNC unblocks subvolume destruction from ENOSPC.
    assert!(store.release_ballast().unwrap());
    assert!(!store.ballast_status().unwrap().present);
    store.destroy_subvolume(victim.path()).unwrap();
    assert!(!victim.path().exists());

    // Cleanup filler and re-arm ballast
    let _ = fs::remove_dir_all(&fill_dir);
    let root_fd = btrfs_sys::open_dir_nofollow(pool.mnt()).unwrap();
    let _ = btrfs_sys::btrfs_sync(&root_fd);
    store.ensure_ballast().unwrap();
    let rearmed = store.ballast_status().unwrap();
    assert!(rearmed.present);
    assert_eq!(rearmed.actual_bytes, 64 * MIB);
}

#[test]
#[ignore = "requires root + live Linux Btrfs loop mount in Forkloom-Dev"]
fn r6_quarantines_a_sealed_subvolume_on_a_full_pool_and_keeps_it_sealed() {
    use aos_meta::RecoveryHooks;
    let pool = TempBtrfsPool::create("q-enospc", 512, "noatime");
    let store =
        TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(64 * MIB)).unwrap();
    let mut payload = vec![0u8; 4 * MIB as usize];
    let mut state: u64 = 0x0123_4567_89ab_cdef;
    for chunk in payload.as_chunks_mut::<8>().0 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *chunk = state.to_ne_bytes();
    }
    let tar_bytes = build_tar(|b| {
        for i in 0..4 {
            append_regular(b, &format!("blob-{i}.bin"), &payload, 0o644);
        }
    });
    // A sealed frame subvolume that redb no longer knows about.
    let orphan = store
        .import_tar(FrameId::random(), Cursor::new(tar_bytes), &TarImportOptions::default())
        .unwrap()
        .into_inner();
    let ro = |p: &Path| {
        btrfs_sys::btrfs_subvol_getflags(&btrfs_sys::open_dir_nofollow(p).unwrap()).unwrap()
            & BTRFS_SUBVOL_RDONLY
            != 0
    };
    assert!(ro(orphan.path()));

    let fill_dir = store.worlds_dir().join("filler");
    fs::create_dir_all(&fill_dir).unwrap();
    let mut hit_enospc = false;
    for i in 0..2000u32 {
        let p = fill_dir.join(format!("f-{i:04}"));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .and_then(|mut f| f.write_all(&payload));
        match written {
            Ok(()) => {}
            Err(e) if aos_store::is_enospc(&e) => {
                hit_enospc = true;
                break;
            }
            Err(e) => panic!("filling the pool: {e}"),
        }
    }
    assert!(hit_enospc, "must actually reach ENOSPC on the 512 MiB Btrfs pool");
    let root_fd = btrfs_sys::open_dir_nofollow(pool.mnt()).unwrap();
    let _ = btrfs_sys::btrfs_sync(&root_fd);

    let qdir = pool.mnt().join("quarantine/epoch-9");
    fs::create_dir_all(&qdir).unwrap();
    let to = qdir.join(orphan.name());
    let mut hooks = TreeStoreRecoveryHooks::new(store.clone(), pool.mnt().join("volatile"));
    hooks
        .quarantine_object(orphan.path(), &to)
        .expect("R6 must get past a full pool by releasing the ballast");
    assert!(!orphan.path().exists(), "moved out of objects/");
    assert!(ro(&to), "still sealed in quarantine");
    assert_eq!(fs::read(to.join("blob-3.bin")).unwrap(), payload, "content unchanged");

    // R6 spent the ballast and the pool may have no room to re-create it (a ballast larger than
    // the pool stands in for that, since Btrfs frees some space on the next commit). A restart
    // must still come up, without a ballast, so agentd can serve DeleteFrame and run GC; a new
    // pool that cannot hold its ballast is still refused.
    let too_big = 1024 * MIB;
    let reopened = TreeStore::open(TreeStoreConfig::new(pool.mnt()).with_ballast_bytes(too_big))
        .expect("a pool whose ballast R6 spent must still open");
    assert!(!reopened.ballast_status().unwrap().present);
    match TreeStore::open(TreeStoreConfig::new(pool.mnt().join("fresh")).with_ballast_bytes(too_big))
    {
        Err(StoreError::NoSpace { .. }) => {}
        other => panic!("a new pool without room for its ballast: {:?}", other.err()),
    }
    let _ = fs::remove_dir_all(&fill_dir);
}
