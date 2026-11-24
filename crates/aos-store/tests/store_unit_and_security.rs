//! Cross-platform unit and security tests for `aos-store` (Windows & Linux).

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use aos_meta::{
    CommitFrameRequest, CommitProofBundle, FrameDurability, MetaConfig, MetaEngine, ObjectKind,
    PrepareFrameRequest, SystemClock,
};
use aos_types::{
    BaseKind, BaseTree, BootId, FrameId, PatchPathValidator, PatchPathViolation, PathPolicy,
    ProofKind, Untrusted,
};
use aos_store::{
    ExportPatchOptions, PatchBundleValidator, PatchFileChange, RawPatchBundle, StoreError,
    SubvolHandle, TarImportOptions, TreeStore, TreeStoreConfig, TreeStoreRecoveryHooks,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!(
        "aos-store-test-{label}-{}-{n}",
        std::process::id()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
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

/// Build a raw tar entry whose path or linkname can contain arbitrary illegal sequences (`..`, `/`,
/// backslashes, etc.) that `tar::Builder::append_data` would otherwise reject on creation.
fn raw_tar_entry(
    entry_type: tar::EntryType,
    raw_path: &[u8],
    raw_linkname: Option<&[u8]>,
    payload: &[u8],
    mode: u32,
) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(payload.len() as u64);
    header.set_mode(mode);
    {
        let raw = header.as_mut_bytes();
        // USTAR/GNU name field is bytes [0..100]
        assert!(raw_path.len() < 100);
        raw[..100].fill(0);
        raw[..raw_path.len()].copy_from_slice(raw_path);
        if let Some(link) = raw_linkname {
            // linkname field is bytes [157..257]
            assert!(link.len() < 100);
            raw[157..257].fill(0);
            raw[157..157 + link.len()].copy_from_slice(link);
        }
    }
    header.set_cksum();

    let mut out = Vec::new();
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(payload);
    let rem = payload.len() % 512;
    if rem != 0 {
        out.resize(out.len() + (512 - rem), 0);
    }
    // Two 512-byte zero blocks terminate a tar archive.
    out.resize(out.len() + 1024, 0);
    out
}

#[test]
fn import_clone_snapshot_export_patch_and_destroy_lifecycle() {
    let root = scratch_dir("lifecycle");
    let pool_root = root.join("pool");
    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root).with_ballast_bytes(4096))
        .unwrap();

    // Ballast pre-allocated on open
    let st = store.ballast_status().unwrap();
    assert!(st.present);
    assert_eq!(st.actual_bytes, 4096);
    assert!(store.release_ballast().unwrap());
    assert!(!store.release_ballast().unwrap(), "second release is idempotent false");
    assert!(!store.ballast_status().unwrap().present);
    store.ensure_ballast().unwrap();
    assert!(store.ballast_status().unwrap().present);

    // Import tar with benign leading `./` entries (like `tar -C repo -cf - .`), nested dirs, and hardlink
    let archive = build_tar(|b| {
        let mut dh = tar::Header::new_gnu();
        dh.set_entry_type(tar::EntryType::Directory);
        dh.set_size(0);
        dh.set_mode(0o755);
        dh.set_cksum();
        b.append_data(&mut dh, ".", &[][..]).unwrap();

        append_regular(b, "./README.md", b"hello forkloom\n", 0o644);
        append_regular(b, "./src/lib.rs", b"pub fn answer() -> u32 { 41 }\n", 0o644);
        append_regular(b, "obsolete.txt", b"delete me\n", 0o644);

        let mut hl = tar::Header::new_gnu();
        hl.set_entry_type(tar::EntryType::Link);
        hl.set_size(0);
        hl.set_mode(0o644);
        hl.set_link_name("./README.md").unwrap();
        hl.set_cksum();
        b.append_data(&mut hl, "README-hardlink.md", &[][..]).unwrap();
    });

    let f1 = FrameId::random();
    let persisted_base = store
        .import_tar(f1, Cursor::new(archive), &TarImportOptions::default())
        .unwrap();
    assert_eq!(persisted_base.proof().kind(), ProofKind::Subvolume);
    persisted_base.proof().verify_unchanged().unwrap();
    assert!(persisted_base.value().is_readonly());
    assert_eq!(
        persisted_base.value().path(),
        store.frame_subvol_path(f1).as_path()
    );
    assert_eq!(
        std::fs::read_to_string(persisted_base.value().path().join("README-hardlink.md")).unwrap(),
        "hello forkloom\n"
    );

    let base_handle = persisted_base.into_inner();

    // Writable clone for a World
    let world = store
        .create_writable_clone(&base_handle, "w-test-001")
        .unwrap();
    assert!(!world.is_readonly());
    assert!(world.path().starts_with(store.worlds_dir()));
    // Cloning a writable handle must be refused
    assert!(matches!(
        store.create_writable_clone(&world, "w-bad-clone"),
        Err(StoreError::NotReadOnly { .. })
    ));

    // Mutate world clone; base must remain untouched
    std::fs::write(
        world.path().join("src/lib.rs"),
        b"pub fn answer() -> u32 { 42 }\n",
    )
    .unwrap();
    std::fs::write(world.path().join("src/new.rs"), b"pub const X: i32 = 1;\n").unwrap();
    std::fs::remove_file(world.path().join("obsolete.txt")).unwrap();

    assert_eq!(
        std::fs::read_to_string(base_handle.path().join("src/lib.rs")).unwrap(),
        "pub fn answer() -> u32 { 41 }\n"
    );
    assert!(base_handle.path().join("obsolete.txt").exists());

    // Snapshot readonly
    let f2 = FrameId::random();
    let persisted_snap = store.snapshot_frame_readonly(&world, f2).unwrap();
    assert_eq!(persisted_snap.proof().kind(), ProofKind::Subvolume);
    persisted_snap.proof().verify_unchanged().unwrap();
    let snap_handle = persisted_snap.into_inner();

    // Zero-trust patch export
    let patch = store
        .export_patch(&base_handle, &snap_handle, &ExportPatchOptions::default())
        .unwrap();
    assert_eq!(patch.len(), 3);
    assert_eq!(
        patch.changes(),
        &[
            PatchFileChange::Remove {
                path: "obsolete.txt".into()
            },
            PatchFileChange::PutFile {
                path: "src/lib.rs".into(),
                contents: b"pub fn answer() -> u32 { 42 }\n".to_vec(),
                executable: false,
                modified: true,
            },
            PatchFileChange::PutFile {
                path: "src/new.rs".into(),
                contents: b"pub const X: i32 = 1;\n".to_vec(),
                executable: false,
                modified: false,
            },
        ]
    );

    // Identical trees produce empty patch
    let empty = store
        .export_patch(&base_handle, &base_handle, &ExportPatchOptions::default())
        .unwrap();
    assert!(empty.is_empty());

    // Destroy subvolumes (and verify idempotent on NotFound)
    store.destroy_subvolume(world.path()).unwrap();
    assert!(!world.path().exists());
    store.destroy_subvolume(world.path()).unwrap();

    store.destroy_subvolume(snap_handle.path()).unwrap();
    store.destroy_subvolume(base_handle.path()).unwrap();

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn meta_engine_integration_with_persisted_subvol_proof_and_recovery_hooks() {
    let root = scratch_dir("meta-int");
    let pool_root = root.join("pool");
    let meta_dir = root.join("meta");
    let volatile_dir = root.join("volatile");
    std::fs::create_dir_all(&volatile_dir).unwrap();

    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root)).unwrap();
    let mut cfg = MetaConfig::new(&meta_dir, &pool_root);
    cfg.allow_same_fs_for_testing = true;

    let boot = BootId::parse("11111111-1111-1111-1111-111111111111").unwrap();
    let hooks = Box::new(TreeStoreRecoveryHooks::new(store.clone(), &volatile_dir));
    let (mut meta, _summary) =
        MetaEngine::open_and_recover(cfg, boot, hooks, Arc::new(SystemClock)).unwrap();

    // T1: prepare frame in redb before creating physical subvolume
    let prep = meta
        .prepare_frame(
            &PrepareFrameRequest {
                owner: "alice".into(),
                durability: FrameDurability::Durable,
                parent: None,
                object_kinds: vec![ObjectKind::TreeSubvol],
                labels: Default::default(),
                source_world: None,
            },
            None,
        )
        .unwrap();

    // Import tar into canonical pool_root/objects/f-<frame>-subvol
    let tar_data = build_tar(|b| append_regular(b, "main.rs", b"fn main() {}\n", 0o644));
    let persisted = store
        .import_tar(
            prep.frame_id,
            Cursor::new(tar_data),
            &TarImportOptions::default(),
        )
        .unwrap();
    let subvol_path = persisted.value().path().to_path_buf();
    let managed_proof = SubvolHandle::into_managed_proof(persisted).unwrap();

    // T2: commit with real PersistProof::fsync_subvolume
    let committed = meta
        .commit_frame(
            &CommitFrameRequest {
                frame_id: prep.frame_id,
                owner: "alice".into(),
                disk_clean: true,
                fence: None,
                pin: None,
                timeline: None,
            },
            CommitProofBundle::new().with_persisted(managed_proof),
            None,
        )
        .unwrap();
    assert_eq!(committed.frame_id, prep.frame_id);
    assert!(subvol_path.exists());

    // Delete frame -> MetaEngine drives TreeStoreRecoveryHooks::destroy_pool_object
    meta.delete_frame(prep.frame_id, "alice", None).unwrap();
    assert!(!subvol_path.exists(), "TreeStoreRecoveryHooks must destroy subvolume");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn import_local_dir_streams_workspace_through_safe_tar() {
    let root = scratch_dir("local-dir");
    let pool_root = root.join("pool");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(workspace.join("pkg")).unwrap();
    std::fs::write(workspace.join("pkg/app.py"), b"print('hi')\n").unwrap();

    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root)).unwrap();
    let frame = FrameId::random();
    let persisted = store
        .import_local_dir(frame, &workspace, &TarImportOptions::default())
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(persisted.value().path().join("pkg/app.py")).unwrap(),
        "print('hi')\n"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn import_tar_rejects_all_malicious_payloads_and_leaves_no_partial_subvolume() {
    let root = scratch_dir("malicious-tar");
    let pool_root = root.join("pool");
    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root)).unwrap();

    let bad_tars: Vec<(&str, Vec<u8>)> = vec![
        (
            "dotdot escape",
            raw_tar_entry(tar::EntryType::Regular, b"../escape.txt", None, b"pwn", 0o644),
        ),
        (
            "nested dotdot",
            raw_tar_entry(tar::EntryType::Regular, b"a/../../escape.txt", None, b"pwn", 0o644),
        ),
        (
            "absolute path",
            raw_tar_entry(tar::EntryType::Regular, b"/etc/passwd", None, b"pwn", 0o644),
        ),
        (
            "backslash path",
            raw_tar_entry(tar::EntryType::Regular, b"a\\..\\b", None, b"pwn", 0o644),
        ),
        (
            "symlink absolute escape",
            raw_tar_entry(tar::EntryType::Symlink, b"link", Some(b"/etc/passwd"), b"", 0o777),
        ),
        (
            "symlink relative escape",
            raw_tar_entry(tar::EntryType::Symlink, b"a/link", Some(b"../../outside"), b"", 0o777),
        ),
        (
            "symlink to .git",
            raw_tar_entry(tar::EntryType::Symlink, b"hook", Some(b".git/hooks"), b"", 0o777),
        ),
        (
            "symlinked .gitmodules",
            raw_tar_entry(tar::EntryType::Symlink, b".gitmodules", Some(b"other"), b"", 0o777),
        ),
        (
            "hardlink to outside",
            raw_tar_entry(tar::EntryType::Link, b"hl", Some(b"../../etc/passwd"), b"", 0o644),
        ),
        (
            "hardlink to missing file",
            raw_tar_entry(tar::EntryType::Link, b"hl", Some(b"nonexistent.txt"), b"", 0o644),
        ),
        (
            "fifo node",
            raw_tar_entry(tar::EntryType::Fifo, b"evil.fifo", None, b"", 0o644),
        ),
        (
            "char device node",
            raw_tar_entry(tar::EntryType::Char, b"evil.char", None, b"", 0o644),
        ),
        (
            "block device node",
            raw_tar_entry(tar::EntryType::Block, b"evil.blk", None, b"", 0o644),
        ),
        (
            "dotgit hooks",
            raw_tar_entry(tar::EntryType::Regular, b".git/hooks/pre-commit", None, b"#!/bin/sh", 0o755),
        ),
        (
            "dotgit uppercase variant",
            raw_tar_entry(tar::EntryType::Regular, b".GIT/config", None, b"bad", 0o644),
        ),
        (
            "dotgit NTFS shortname",
            raw_tar_entry(tar::EntryType::Regular, b"GIT~1/config", None, b"bad", 0o644),
        ),
        (
            "windows reserved device name",
            raw_tar_entry(tar::EntryType::Regular, b"dir/CON.txt", None, b"bad", 0o644),
        ),
    ];

    for (label, bytes) in bad_tars {
        let frame = FrameId::random();
        let expected_path = store.frame_subvol_path(frame);
        let err = store
            .import_tar(frame, Cursor::new(bytes), &TarImportOptions::default())
            .expect_err(&format!("tar attack {label:?} MUST be rejected"));
        assert!(
            matches!(err, StoreError::UnsafeTarEntry { .. }),
            "attack {label:?} returned unexpected error: {err:?}"
        );
        assert!(
            !expected_path.exists(),
            "partial subvolume leaked after rejected tar {label:?}"
        );
    }

    // Also test tar bomb limits (max_total_bytes and max_entries)
    let big = build_tar(|b| {
        append_regular(b, "a.bin", &[0u8; 2048], 0o644);
        append_regular(b, "b.bin", &[0u8; 2048], 0o644);
    });
    let small_opts = TarImportOptions {
        max_total_bytes: 3000,
        ..Default::default()
    };
    let frame = FrameId::random();
    assert!(matches!(
        store.import_tar(frame, Cursor::new(&big), &small_opts),
        Err(StoreError::UnsafeTarEntry { .. })
    ));
    assert!(!store.frame_subvol_path(frame).exists());

    let entry_opts = TarImportOptions {
        max_entries: 1,
        ..Default::default()
    };
    let frame2 = FrameId::random();
    assert!(matches!(
        store.import_tar(frame2, Cursor::new(&big), &entry_opts),
        Err(StoreError::UnsafeTarEntry { .. })
    ));
    assert!(!store.frame_subvol_path(frame2).exists());

    // Case-folding collision inside one tar archive
    let fold_tar = build_tar(|b| {
        append_regular(b, "Foo.rs", b"a", 0o644);
        append_regular(b, "foo.rs", b"b", 0o644);
    });
    let frame3 = FrameId::random();
    assert!(matches!(
        store.import_tar(frame3, Cursor::new(fold_tar), &TarImportOptions::default()),
        Err(StoreError::UnsafeTarEntry { .. })
    ));
    assert!(!store.frame_subvol_path(frame3).exists());

    // Verify objects/ directory is completely empty after all failed imports
    assert_eq!(std::fs::read_dir(store.objects_dir()).unwrap().count(), 0);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn destroy_subvolume_refuses_paths_outside_managed_pool_boundaries() {
    let root = scratch_dir("destroy-guard");
    let pool_root = root.join("pool");
    let outside = root.join("precious");
    std::fs::create_dir_all(&outside).unwrap();
    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root)).unwrap();

    for forbidden in [
        outside.clone(),
        pool_root.clone(),
        store.objects_dir(),
        store.worlds_dir(),
        store.quarantine_dir(),
        store.objects_dir().join("..").join("precious"),
        store.objects_dir().join("nested").join("deep"),
    ] {
        assert!(
            matches!(
                store.destroy_subvolume(&forbidden),
                Err(StoreError::OutsidePool { .. })
            ),
            "destroy_subvolume MUST refuse {}",
            forbidden.display()
        );
    }
    assert!(outside.exists(), "outside directory must remain intact");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn export_patch_blocks_dotgit_windows_reserved_symlink_and_fold_attacks() {
    let root = scratch_dir("export-guard");
    let pool_root = root.join("pool");
    let store = TreeStore::open(TreeStoreConfig::for_testing(&pool_root)).unwrap();

    let base_tar = build_tar(|b| {
        append_regular(b, "src/Main.rs", b"fn main() {}\n", 0o644);
    });
    let base = store
        .import_tar(
            FrameId::random(),
            Cursor::new(base_tar),
            &TarImportOptions::default(),
        )
        .unwrap()
        .into_inner();

    // 1. Live tree adds .git/hooks/pre-commit -> export_patch MUST reject with DotGit
    let w_git = store.create_writable_clone(&base, "w-dotgit").unwrap();
    std::fs::create_dir_all(w_git.path().join(".git/hooks")).unwrap();
    std::fs::write(w_git.path().join(".git/hooks/pre-commit"), b"evil").unwrap();
    let err = store
        .export_patch(&base, &w_git, &ExportPatchOptions::default())
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::PatchValidation(ref e) if matches!(e.kind, PatchPathViolation::DotGit { .. })
        ),
        "expected DotGit violation, got {err:?}"
    );

    // 2. Live tree adds GIT~1/config -> export_patch MUST reject with DotGit under CrossPlatform
    let w_git_alias = store.create_writable_clone(&base, "w-git-alias").unwrap();
    std::fs::create_dir_all(w_git_alias.path().join("GIT~1")).unwrap();
    std::fs::write(w_git_alias.path().join("GIT~1/config"), b"evil").unwrap();
    let err = store
        .export_patch(&base, &w_git_alias, &ExportPatchOptions::default())
        .unwrap_err();
    assert!(matches!(
        err,
        StoreError::PatchValidation(ref e) if matches!(e.kind, PatchPathViolation::DotGit { .. })
    ));

    // 3. PatchBundleValidator directly verifies Untrusted<RawPatchBundle> boundary across all
    //    attack vectors (including ones that cannot even be materialized on Windows NTFS).
    let mut base_tree = BaseTree::new();
    base_tree.insert("src/Main.rs", BaseKind::File);
    base_tree.insert("existing_link", BaseKind::Symlink);
    let validator = PatchBundleValidator::new(
        PatchPathValidator::new(PathPolicy::CrossPlatform).with_base_tree(base_tree),
    );

    let untrusted_debug = format!("{:?}", Untrusted::new(RawPatchBundle::default()));
    assert_eq!(untrusted_debug, "Untrusted(<redacted>)");

    type AttackCase = (&'static str, Vec<PatchFileChange>, fn(&PatchPathViolation) -> bool);
    let attacks: Vec<AttackCase> = vec![
        (
            "path traversal",
            vec![PatchFileChange::PutFile {
                path: "../etc/passwd".into(),
                contents: vec![],
                executable: false,
                modified: false,
            }],
            |v| matches!(v, PatchPathViolation::NonCanonical { .. }),
        ),
        (
            "symlink escape",
            vec![PatchFileChange::PutSymlink {
                path: "a/link".into(),
                target: "../../etc/shadow".into(),
                modified: false,
            }],
            |v| matches!(v, PatchPathViolation::SymlinkEscape { .. }),
        ),
        (
            "symlink chain traversal",
            vec![
                PatchFileChange::PutSymlink {
                    path: "a".into(),
                    target: "b".into(),
                    modified: false,
                },
                PatchFileChange::PutSymlink {
                    path: "b".into(),
                    target: "a".into(),
                    modified: false,
                },
            ],
            |v| matches!(v, PatchPathViolation::PathThroughSymlink { .. }),
        ),
        (
            "path through base symlink",
            vec![PatchFileChange::PutFile {
                path: "existing_link/pwn.txt".into(),
                contents: vec![],
                executable: false,
                modified: false,
            }],
            |v| matches!(v, PatchPathViolation::PathThroughSymlink { .. }),
        ),
        (
            "windows reserved name",
            vec![PatchFileChange::PutFile {
                path: "dir/CON.txt".into(),
                contents: vec![],
                executable: false,
                modified: false,
            }],
            |v| matches!(v, PatchPathViolation::ReservedDeviceName { .. }),
        ),
        (
            "in-patch case collision",
            vec![
                PatchFileChange::PutFile {
                    path: "Foo.ts".into(),
                    contents: vec![],
                    executable: false,
                    modified: false,
                },
                PatchFileChange::PutFile {
                    path: "foo.ts".into(),
                    contents: vec![],
                    executable: false,
                    modified: false,
                },
            ],
            |v| matches!(v, PatchPathViolation::FoldCollision { .. }),
        ),
        (
            "base-tree case collision",
            vec![PatchFileChange::PutFile {
                path: "src/main.rs".into(),
                contents: vec![],
                executable: false,
                modified: false,
            }],
            |v| matches!(v, PatchPathViolation::BaseCollision { .. }),
        ),
    ];

    for (label, changes, pred) in attacks {
        let res = Untrusted::new(RawPatchBundle { changes }).validate(&validator);
        let err = res.expect_err(&format!("validator MUST reject {label}"));
        assert!(
            pred(&err.kind),
            "attack {label} got unexpected violation: {:?}",
            err.kind
        );
    }

    // 4. Patch byte-budget enforcement
    let w_big = store.create_writable_clone(&base, "w-big").unwrap();
    std::fs::write(w_big.path().join("blob.bin"), vec![0xAAu8; 4096]).unwrap();
    let small_patch_opts = ExportPatchOptions {
        max_patch_bytes: 1024,
        ..Default::default()
    };
    assert!(matches!(
        store.export_patch(&base, &w_big, &small_patch_opts),
        Err(StoreError::DiffError { .. })
    ));

    let _ = Path::new(".");
    std::fs::remove_dir_all(root).unwrap();
}
