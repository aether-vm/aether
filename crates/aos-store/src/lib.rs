//! Forkloom Phase 1 type-safe storage engine (`aos-store`).
//!
//! | module | purpose |
//! | --- | --- |
//! | [`kind`] | Compile-time separation between `kind::Tree` (`TreeStore`) and `kind::Block` (`BlockStore`) |
//! | [`btrfs`] | Linux Btrfs uapi ioctl wrappers + `/proc/self/mountinfo` (`autodefrag`) & `qgroups` guardrails |
//! | [`openat2`] | Linux `openat2(2)` (`RESOLVE_IN_ROOT \| RESOLVE_NO_MAGICLINKS`) confined unpacking helpers |
//! | [`safe_tar`] | Untrusted tar stream unpacking (symlink/hardlink/special-node/traversal/`.git`/limit guards) |
//! | [`patch`] | Zero-trust `export_patch` (`Untrusted<RawPatchBundle>` -> `PatchPathValidator` -> `PatchBundle`) |
//! | [`tree_store`] | `TreeStore`: Btrfs pool guardrails, ballast management, cold-fork snapshots, subvolume destroy |
//!
//! All core logic is `#![deny(unsafe_code)]`; minimal Linux syscall wrappers are isolated in
//! `btrfs::linux_impl` and `openat2::linux_impl` with explicit `// SAFETY:` comments and locked
//! ABI layout tests.

#![deny(unsafe_code)]

pub mod btrfs;
pub mod error;
pub mod kind;
pub mod openat2;
pub mod patch;
pub mod safe_tar;
pub mod tree_store;

pub use error::{Result, StoreError, is_enospc};
pub use kind::{BlockImageHandle, StorageKind, StoreObject, SubvolHandle};
pub use patch::{
    DEFAULT_MAX_PATCH_BYTES, DEFAULT_MAX_PATCH_ENTRIES, ExportPatchOptions, PatchBundle,
    PatchBundleValidator, PatchFileChange, RawPatchBundle,
};
pub use safe_tar::{
    DEFAULT_MAX_IMPORT_BYTES, DEFAULT_MAX_IMPORT_ENTRIES, DEFAULT_MAX_IMPORT_FILE_BYTES,
    TarImportOptions,
};
pub use tree_store::{
    BALLAST_FILE, BallastStatus, DEFAULT_BALLAST_BYTES, OBJECTS_DIR, QUARANTINE_DIR, TreeStore,
    TreeStoreConfig, TreeStoreRecoveryHooks, WORLDS_DIR,
};
