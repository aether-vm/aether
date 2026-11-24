//! Compile-time dual-storage separation (ARCHITECTURE_V2 §0, §3.3).
//!
//! Forkloom strictly separates host-owned directory trees ([`Tree`], served by
//! `TreeStore` for Namespace cold forks) from guest-owned raw block images ([`Block`],
//! reserved for Phase 2 `BlockStore` / Firecracker hot forks). The host kernel **never** mounts
//! an untrusted `Block` image, and the type system prevents passing a [`BlockImageHandle`] where
//! a [`SubvolHandle`] is required:
//!
//! ```compile_fail
//! use aos_store::{BlockImageHandle, TreeStore};
//!
//! fn check(store: &TreeStore, block: &BlockImageHandle) {
//!     // Compile error: expected `&SubvolHandle` (`StoreObject<kind::Tree>`),
//!     // found `&BlockImageHandle` (`StoreObject<kind::Block>`).
//!     let _ = store.create_writable_clone(block, "world-1");
//! }
//! ```

use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use aos_meta::ManagedObject;
use aos_types::Persisted;

use crate::error::{Result, StoreError};

/// Host-kernel-owned directory tree (Btrfs subvolume for Namespace cold fork).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tree {}

/// Guest-kernel-owned raw block image (Firecracker `virtio-blk` hot fork; host never mounts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Block {}

mod private {
    pub trait Sealed {}
    impl Sealed for super::Tree {}
    impl Sealed for super::Block {}
}

/// Sealed marker trait implemented only for [`Tree`] and [`Block`].
pub trait StorageKind: private::Sealed {}
impl StorageKind for Tree {}
impl StorageKind for Block {}

/// A handle to a storage object, statically tagged with its [`StorageKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreObject<K: StorageKind> {
    path: PathBuf,
    name: String,
    object: Option<ManagedObject>,
    readonly: bool,
    _kind: PhantomData<K>,
}

/// Handle to a managed Btrfs directory-tree subvolume (`kind::Tree`).
pub type SubvolHandle = StoreObject<Tree>;

/// Handle to a raw block image (`kind::Block`, Phase 2 `BlockStore`).
///
/// No host-side mount API exists for this type.
pub type BlockImageHandle = StoreObject<Block>;

impl<K: StorageKind> StoreObject<K> {
    pub(crate) fn new(
        path: PathBuf,
        name: String,
        object: Option<ManagedObject>,
        readonly: bool,
    ) -> Self {
        Self {
            path,
            name,
            object,
            readonly,
            _kind: PhantomData,
        }
    }

    /// Filesystem path of the object inside the pool.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Single-component name of the object within its parent pool directory.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Canonical [`ManagedObject`] identity, present for frame artifacts under `pool_root/objects/`.
    #[must_use]
    pub fn object(&self) -> Option<ManagedObject> {
        self.object
    }

    /// Whether this handle refers to a sealed read-only artifact.
    #[must_use]
    pub fn is_readonly(&self) -> bool {
        self.readonly
    }
}

impl SubvolHandle {
    /// Convert a [`Persisted<SubvolHandle>`] whose subvolume has a canonical [`ManagedObject`]
    /// name (`f-<frame>-subvol`) into a [`Persisted<ManagedObject>`] ready for
    /// [`aos_meta::CommitProofBundle::with_persisted`].
    pub fn into_managed_proof(persisted: Persisted<Self>) -> Result<Persisted<ManagedObject>> {
        let (handle, proof) = persisted.into_parts();
        let obj = handle.object.ok_or_else(|| StoreError::InvalidName {
            name: handle.name.clone(),
            reason: "subvolume does not have a canonical ManagedObject name".into(),
        })?;
        Ok(Persisted::new(obj, proof))
    }
}
