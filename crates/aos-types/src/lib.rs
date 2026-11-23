//! Forkloom foundational types (`aos-types`).
//!
//! Everything in this crate is `#![forbid(unsafe_code)]`.
//!
//! | module | purpose |
//! | --- | --- |
//! | [`id`] | 128-bit random `WorldId` / `FrameId` with *canonical-only* text encodings, monotonic `EpochId` |
//! | [`boot`] | `BootId` read from `/proc/sys/kernel/random/boot_id` with strict UUID validation |
//! | [`proof`] | `PersistProof` (real fsync only), `Persisted<T>`, boot-bound `Ephemeral<T>` |
//! | [`untrusted`] | `Untrusted<T>`: the only way out is `validate(&Validator)` |
//! | [`patch_path`] | `PatchPathValidator`: path-traversal / `.git` / case-fold / symlink-escape defence for sandbox patches |

#![forbid(unsafe_code)]

pub mod boot;
pub mod id;
pub mod patch_path;
pub mod proof;
pub mod untrusted;

pub use boot::{BootId, BootIdError};
pub use id::{EpochId, FrameId, IdGenError, IdParseError, WorldId};
pub use patch_path::{
    BaseKind, BaseTree, EntryKind, PatchEntry, PatchOp, PatchPathError, PatchPathValidator,
    PatchPathViolation, PatchSet, PathPolicy, ValidatedPatch,
};
pub use proof::{Ephemeral, PersistProof, Persisted, ProofError, ProofKind};
pub use untrusted::{Untrusted, Validator};
