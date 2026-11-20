//! Shared harness: scratch pool / meta / tmpfs directories, a manual clock and hooks with
//! failure injection.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use aos_meta::{
    CommitFrameRequest, CommitProofBundle, FrameDurability, FsArtifactBackend, Labels,
    ManagedObject, ManualClock, MetaConfig, MetaEngine, ObjectKind, ObjectLocation,
    PrepareFrameRequest, PreparedFrame, RecoveryHooks, RecoverySummary,
};
use aos_types::{BootId, EpochId, Ephemeral, FrameId, PersistProof, Persisted};

pub const BOOT_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub const BOOT_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub const T0: u64 = 1_700_000_000_000;

pub fn boot_a() -> BootId {
    BootId::parse(BOOT_A).unwrap()
}

pub fn boot_b() -> BootId {
    BootId::parse(BOOT_B).unwrap()
}

/// Failure switches and a call log shared between the harness and every hook instance.
#[derive(Debug, Default)]
pub struct HookCtl {
    pub fail_fence: AtomicBool,
    pub fail_kill: AtomicBool,
    pub fail_destroy: AtomicBool,
    pub calls: Mutex<Vec<String>>,
}

impl HookCtl {
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn log(&self, s: String) {
        self.calls.lock().unwrap().push(s);
    }
}

pub struct TestHooks {
    inner: FsArtifactBackend,
    ctl: Arc<HookCtl>,
}

fn injected(what: &str) -> io::Error {
    io::Error::other(format!("injected {what} failure"))
}

impl RecoveryHooks for TestHooks {
    fn fence_gateway(&mut self, epoch: EpochId) -> io::Result<()> {
        self.ctl.log(format!("fence:{epoch}"));
        if self.ctl.fail_fence.load(Ordering::SeqCst) {
            return Err(injected("fence"));
        }
        self.inner.fence_gateway(epoch)
    }

    fn kill_stale_epochs(&mut self, current: EpochId) -> io::Result<()> {
        self.ctl.log(format!("kill:{current}"));
        if self.ctl.fail_kill.load(Ordering::SeqCst) {
            return Err(injected("kill"));
        }
        self.inner.kill_stale_epochs(current)
    }

    fn destroy_pool_object(&mut self, path: &Path, object: &ManagedObject) -> io::Result<()> {
        self.ctl.log(format!("destroy_pool:{object}"));
        if self.ctl.fail_destroy.load(Ordering::SeqCst) {
            return Err(injected("destroy"));
        }
        self.inner.destroy_pool_object(path, object)
    }

    fn destroy_volatile_object(&mut self, object: &ManagedObject) -> io::Result<()> {
        self.ctl.log(format!("destroy_volatile:{object}"));
        if self.ctl.fail_destroy.load(Ordering::SeqCst) {
            return Err(injected("destroy"));
        }
        self.inner.destroy_volatile_object(object)
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct Harness {
    pub root: PathBuf,
    pub cfg: MetaConfig,
    pub vol: PathBuf,
    pub clock: Arc<ManualClock>,
    pub ctl: Arc<HookCtl>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

impl Harness {
    pub fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aos-meta-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut cfg = MetaConfig::new(root.join("meta"), root.join("pool"));
        cfg.allow_same_fs_for_testing = true;
        let vol = root.join("tmpfs");
        std::fs::create_dir_all(&vol).unwrap();
        Self {
            root,
            cfg,
            vol,
            clock: Arc::new(ManualClock::new(T0)),
            ctl: Arc::new(HookCtl::default()),
        }
    }

    pub fn try_open(&self, boot: BootId) -> aos_meta::Result<(MetaEngine, RecoverySummary)> {
        MetaEngine::open_and_recover(
            self.cfg.clone(),
            boot,
            Box::new(TestHooks {
                inner: FsArtifactBackend::new(&self.vol),
                ctl: self.ctl.clone(),
            }),
            self.clock.clone(),
        )
    }

    pub fn open(&self, boot: BootId) -> (MetaEngine, RecoverySummary) {
        self.try_open(boot).expect("open_and_recover")
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.cfg.objects_dir()
    }

    pub fn path_of(&self, o: &ManagedObject, d: FrameDurability) -> PathBuf {
        match o.location(d) {
            ObjectLocation::Pool => self.objects_dir().join(o.name()),
            ObjectLocation::VolatileTmpfs => self.vol.join(o.name()),
        }
    }

    /// Materialize an object the way a producer would (subvolume = directory with content).
    pub fn create_object(&self, o: &ManagedObject, d: FrameDurability) -> PathBuf {
        let p = self.path_of(o, d);
        if o.kind == ObjectKind::TreeSubvol {
            std::fs::create_dir_all(p.join("etc")).unwrap();
            std::fs::write(p.join("etc").join("hostname"), b"world").unwrap();
        } else {
            std::fs::write(&p, format!("payload of {o}")).unwrap();
        }
        p
    }

    pub fn persisted(&self, o: &ManagedObject) -> Persisted<ManagedObject> {
        let p = self.objects_dir().join(o.name());
        let proof = if o.kind == ObjectKind::TreeSubvol {
            PersistProof::fsync_dir(&p).unwrap()
        } else {
            PersistProof::fsync_file_and_parent(&p).unwrap()
        };
        Persisted::new(*o, proof)
    }

    /// Correct proofs for every object of a prepared frame (creating the objects first).
    pub fn produce(&self, prepared: &PreparedFrame, boot: BootId) -> CommitProofBundle {
        let mut bundle = CommitProofBundle::new();
        for o in &prepared.expected_objects {
            self.create_object(o, prepared.durability);
            bundle = match o.location(prepared.durability) {
                ObjectLocation::Pool => bundle.with_persisted(self.persisted(o)),
                ObjectLocation::VolatileTmpfs => {
                    bundle.with_ephemeral(Ephemeral::new_for_boot(*o, boot))
                }
            };
        }
        bundle
    }

    pub fn commit_req(frame_id: FrameId, owner: &str) -> CommitFrameRequest {
        CommitFrameRequest {
            frame_id,
            owner: owner.into(),
            disk_clean: true,
            fence: None,
            pin: None,
            timeline: None,
        }
    }

    pub fn prepare_req(
        owner: &str,
        durability: FrameDurability,
        parent: Option<FrameId>,
        kinds: &[ObjectKind],
    ) -> PrepareFrameRequest {
        PrepareFrameRequest {
            owner: owner.into(),
            durability,
            parent,
            object_kinds: kinds.to_vec(),
            labels: Labels::new(),
            source_world: None,
        }
    }

    /// prepare + produce + commit.
    pub fn commit_frame(
        &self,
        e: &mut MetaEngine,
        durability: FrameDurability,
        parent: Option<FrameId>,
        kinds: &[ObjectKind],
    ) -> FrameId {
        let prepared = e
            .prepare_frame(&Self::prepare_req("alice", durability, parent, kinds), None)
            .unwrap();
        let bundle = self.produce(&prepared, e.current_boot());
        e.commit_frame(&Self::commit_req(prepared.frame_id, "alice"), bundle, None)
            .unwrap();
        prepared.frame_id
    }

    pub fn durable(&self, e: &mut MetaEngine) -> FrameId {
        self.commit_frame(
            e,
            FrameDurability::Durable,
            None,
            &[ObjectKind::DiskImage, ObjectKind::VmState],
        )
    }

    pub fn volatile(&self, e: &mut MetaEngine) -> FrameId {
        self.commit_frame(
            e,
            FrameDurability::Volatile,
            None,
            &[ObjectKind::DiskImage, ObjectKind::MemImage, ObjectKind::VmState],
        )
    }

    pub fn pool_objects(&self) -> BTreeSet<String> {
        list(&self.objects_dir())
    }

    pub fn tmpfs_objects(&self) -> BTreeSet<String> {
        list(&self.vol)
    }

    /// `epoch-<n>/<name>` for every quarantined entry.
    pub fn quarantine_entries(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for epoch in list(&self.cfg.quarantine_dir()) {
            for name in list(&self.cfg.quarantine_dir().join(&epoch)) {
                out.insert(format!("{epoch}/{name}"));
            }
        }
        out
    }

    pub fn add_orphan(&self, name: &str) {
        std::fs::write(self.objects_dir().join(name), b"orphan").unwrap();
    }
}

pub fn list(dir: &Path) -> BTreeSet<String> {
    match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

pub fn names(e: &MetaEngine, f: FrameId) -> Vec<String> {
    e.frame(f)
        .unwrap()
        .expect("frame exists")
        .state
        .objects()
        .iter()
        .map(ManagedObject::name)
        .collect()
}

pub fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}
