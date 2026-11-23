//! Persistent data model: identifiers, frame / world state machines, holds and labels.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;

use aos_types::{BootId, EpochId, FrameId, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::{MetaError, Result};

// ============================================================================ PoolId

/// 128-bit identity of a storage pool, written to `pool_root/POOL_UUID` and to the metadata
/// database. Canonical text form: lowercase `8-4-4-4-12` hex (UUID layout).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PoolId([u8; 16]);

impl PoolId {
    /// Fresh random id from the OS CSPRNG.
    pub fn random() -> Result<Self> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(|e| {
            MetaError::io("generating pool id", std::io::Error::other(e.to_string()))
        })?;
        Ok(Self(b))
    }

    /// Construct from raw bytes.
    #[must_use]
    pub const fn from_bytes(b: [u8; 16]) -> Self {
        Self(b)
    }

    /// Raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Strictly parse the canonical form (no braces, no whitespace, no uppercase).
    pub fn parse(s: &str) -> Result<Self> {
        let bad = || MetaError::MalformedPoolUuid(s.chars().take(64).collect());
        if s.len() != 36 {
            return Err(bad());
        }
        let mut out = [0u8; 16];
        let mut n = 0usize;
        for (i, c) in s.bytes().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(bad());
                }
                continue;
            }
            let v = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                _ => return Err(bad()),
            };
            out[n / 2] |= if n.is_multiple_of(2) { v << 4 } else { v };
            n += 1;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PoolId({self})")
    }
}

impl FromStr for PoolId {
    type Err = MetaError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for PoolId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PoolId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================ FencingToken

/// Monotonic per-world ownership token. A caller presenting anything but the current token is
/// [`MetaError::FencedOut`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FencingToken(NonZeroU64);

impl FencingToken {
    /// Token handed out at world creation.
    pub const FIRST: FencingToken = FencingToken(NonZeroU64::MIN);

    /// Construct from a raw value (`0` is invalid).
    #[must_use]
    pub fn new(n: u64) -> Option<Self> {
        NonZeroU64::new(n).map(Self)
    }

    /// Raw value.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0.get()
    }

    /// Next token, `None` on overflow.
    #[must_use]
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for FencingToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================ objects

/// Persistence class of a frame (ARCHITECTURE_V2 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FrameDurability {
    /// All artifacts fsynced into the pool; survives host reboot.
    Durable,
    /// Memory image in quota-limited tmpfs, valid for one host boot only.
    Volatile,
}

/// Kind of managed artifact belonging to a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ObjectKind {
    /// Read-only Btrfs subvolume (`TreeStore`).
    TreeSubvol,
    /// Sealed block image (`BlockStore`).
    DiskImage,
    /// Guest memory image.
    MemImage,
    /// Firecracker `vmstate`.
    VmState,
}

impl ObjectKind {
    /// All kinds.
    pub const ALL: [ObjectKind; 4] = [
        ObjectKind::TreeSubvol,
        ObjectKind::DiskImage,
        ObjectKind::MemImage,
        ObjectKind::VmState,
    ];

    /// Name suffix after `f-<frame>-`.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            ObjectKind::TreeSubvol => "subvol",
            ObjectKind::DiskImage => "disk.img",
            ObjectKind::MemImage => "mem.img",
            ObjectKind::VmState => "vmstate",
        }
    }

    /// Whether the artifact is a directory (subvolume) rather than a regular file.
    #[must_use]
    pub const fn is_dir(self) -> bool {
        matches!(self, ObjectKind::TreeSubvol)
    }
}

/// Where an object physically lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectLocation {
    /// `pool_root/objects/<name>`.
    Pool,
    /// The quota-limited tmpfs for volatile memory images.
    VolatileTmpfs,
}

/// A managed pool / tmpfs object, identified by its owning frame and kind.
///
/// Canonical name: `f-<frame base32>-<suffix>`; [`ManagedObject::parse_name`] accepts nothing
/// else, so every managed name maps to exactly one `(frame, kind)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ManagedObject {
    /// Owning frame.
    pub frame: FrameId,
    /// Kind.
    pub kind: ObjectKind,
}

impl ManagedObject {
    /// Construct.
    #[must_use]
    pub const fn new(frame: FrameId, kind: ObjectKind) -> Self {
        Self { frame, kind }
    }

    /// Canonical file / directory name.
    #[must_use]
    pub fn name(&self) -> String {
        format!("f-{}-{}", self.frame.to_base32(), self.kind.suffix())
    }

    /// Strictly parse a canonical name.
    #[must_use]
    pub fn parse_name(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("f-")?;
        let (b32, suffix) = (rest.get(..aos_types::id::BASE32_LEN)?, rest.get(aos_types::id::BASE32_LEN..)?);
        let suffix = suffix.strip_prefix('-')?;
        let frame = FrameId::from_base32(b32).ok()?;
        let kind = ObjectKind::ALL.into_iter().find(|k| k.suffix() == suffix)?;
        Some(Self { frame, kind })
    }

    /// Physical location given the owning frame's durability: only volatile memory images live
    /// in tmpfs; disks (FICLONE), subvolumes and vmstate always live in the pool.
    #[must_use]
    pub fn location(&self, durability: FrameDurability) -> ObjectLocation {
        match (durability, self.kind) {
            (FrameDurability::Volatile, ObjectKind::MemImage) => ObjectLocation::VolatileTmpfs,
            _ => ObjectLocation::Pool,
        }
    }
}

impl fmt::Display for ManagedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

// ============================================================================ labels

/// Maximum number of labels on a world or frame.
pub const MAX_LABELS: usize = 32;
/// Maximum label key length in bytes.
pub const MAX_LABEL_KEY_LEN: usize = 128;
/// Maximum label value length in bytes.
pub const MAX_LABEL_VALUE_LEN: usize = 512;
/// Maximum length of owners, timeline names, pin ids and request ids.
pub const MAX_NAME_LEN: usize = 128;

/// Immutable key/value labels.
pub type Labels = BTreeMap<String, String>;

/// Validate label limits (prevents unbounded growth of `redb` records).
pub fn validate_labels(labels: &Labels) -> Result<()> {
    if labels.len() > MAX_LABELS {
        return Err(MetaError::InvalidLabels(format!(
            "{} labels exceed the limit of {MAX_LABELS}",
            labels.len()
        )));
    }
    for (k, v) in labels {
        if k.is_empty() {
            return Err(MetaError::InvalidLabels("empty label key".into()));
        }
        if k.len() > MAX_LABEL_KEY_LEN {
            return Err(MetaError::InvalidLabels(format!(
                "label key of {} bytes exceeds {MAX_LABEL_KEY_LEN}",
                k.len()
            )));
        }
        if v.len() > MAX_LABEL_VALUE_LEN {
            return Err(MetaError::InvalidLabels(format!(
                "label value of {} bytes for key {k:?} exceeds {MAX_LABEL_VALUE_LEN}",
                v.len()
            )));
        }
    }
    Ok(())
}

/// Validate a short identifier-like string (owner, timeline, pin id, request id).
pub(crate) fn validate_name(what: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > MAX_NAME_LEN || s.chars().any(char::is_control) {
        return Err(MetaError::InvalidArgument(format!(
            "{what} must be 1..={MAX_NAME_LEN} bytes without control characters"
        )));
    }
    Ok(())
}

/// `true` iff every selector pair is present in `labels`.
#[must_use]
pub fn labels_match(labels: &Labels, selector: &Labels) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

// ============================================================================ frames

/// Why a frame is being deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteReason {
    /// Explicit delete of an unheld frame.
    Requested {
        /// Caller.
        by: String,
    },
    /// Explicit abort of a frame still in `Preparing`.
    Aborted {
        /// Caller.
        by: String,
    },
    /// A deferred delete whose last hold was released (garbage collection).
    Reclaimed,
    /// Volatile frame of a previous host boot (R1).
    StaleBoot,
}

/// Frame state machine: `Preparing -> Committed -> Deleting -> (removed)`; recovery rolls every
/// `Preparing` frame back and never rolls anything forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameState {
    /// T1 intent record written before any artifact is created.
    Preparing {
        /// Persistence class.
        durability: FrameDurability,
        /// Boot the frame is being created in.
        boot_id: BootId,
        /// Lineage parent.
        parent: Option<FrameId>,
        /// Objects the producer may create.
        expected_objects: Vec<ManagedObject>,
        /// Epoch of creation.
        created_epoch: EpochId,
        /// Immutable labels.
        labels: Labels,
        /// Owner.
        owner: String,
        /// Wall-clock creation time.
        created_at_ms: u64,
        /// Durable child of a volatile parent: the full memory image must be copied and fsynced.
        requires_full_mem_promotion: bool,
        /// World the frame is captured from (fencing-checked at prepare and commit).
        source_world: Option<WorldId>,
    },
    /// T2: the unique commit point.
    Committed {
        /// Persistence class.
        durability: FrameDurability,
        /// Boot the frame was created in.
        boot_id: BootId,
        /// Lineage parent.
        parent: Option<FrameId>,
        /// Objects owned by the frame.
        objects: Vec<ManagedObject>,
        /// Guest `syncfs` completed before capture (Inspector VM eligibility).
        disk_clean: bool,
        /// Epoch of creation.
        created_epoch: EpochId,
        /// Wall-clock commit time.
        committed_at_ms: u64,
        /// Immutable labels.
        labels: Labels,
        /// Owner.
        owner: String,
    },
    /// Physical deletion in progress; resumed by recovery (R5) and GC.
    Deleting {
        /// Persistence class (decides where objects live).
        durability: FrameDurability,
        /// Objects still to destroy.
        objects: Vec<ManagedObject>,
        /// Why.
        reason: DeleteReason,
        /// Wall-clock time the delete was decided.
        marked_at_ms: u64,
        /// Owner of the frame (checked on retry of `delete_frame`).
        #[serde(default)]
        owner: Option<String>,
    },
}

impl FrameState {
    /// Short state name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            FrameState::Preparing { .. } => "Preparing",
            FrameState::Committed { .. } => "Committed",
            FrameState::Deleting { .. } => "Deleting",
        }
    }

    /// Persistence class.
    #[must_use]
    pub fn durability(&self) -> FrameDurability {
        match self {
            FrameState::Preparing { durability, .. }
            | FrameState::Committed { durability, .. }
            | FrameState::Deleting { durability, .. } => *durability,
        }
    }

    /// Objects the frame may own physically (expected objects for `Preparing`).
    #[must_use]
    pub fn objects(&self) -> &[ManagedObject] {
        match self {
            FrameState::Preparing {
                expected_objects, ..
            } => expected_objects,
            FrameState::Committed { objects, .. } | FrameState::Deleting { objects, .. } => {
                objects
            }
        }
    }

    /// Owner.
    #[must_use]
    pub fn owner(&self) -> Option<&str> {
        match self {
            FrameState::Preparing { owner, .. } | FrameState::Committed { owner, .. } => {
                Some(owner)
            }
            FrameState::Deleting { owner, .. } => owner.as_deref(),
        }
    }
}

/// A row of the `FRAMES` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameRecord {
    /// Frame id.
    pub frame_id: FrameId,
    /// State.
    pub state: FrameState,
}

// ============================================================================ holds

/// Something that keeps a committed frame from being garbage collected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hold {
    /// Head of a durable timeline (durable frames only).
    TimelineHead {
        /// Timeline name.
        timeline_name: String,
    },
    /// Base frame of a running world; released when the world ends or is lost.
    WorldBase {
        /// World.
        world_id: WorldId,
        /// Epoch the world was started in.
        epoch: EpochId,
    },
    /// Client pin with a lease (prevents leaks from dead clients).
    Pin {
        /// Pin id (unique per frame).
        pin_id: String,
        /// Owner.
        owner: String,
        /// Lease length.
        lease_ttl_ms: u64,
        /// Persisted (low-water) expiry.
        expires_at_ms: u64,
    },
    /// Lineage parent of an in-flight `Preparing` child frame; released when the child commits,
    /// aborts, or is rolled back by R3.
    PreparingParent {
        /// Child frame currently in `Preparing`.
        child_frame: FrameId,
    },
}

impl Hold {
    /// Unique key of the hold within its frame.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Hold::TimelineHead { timeline_name } => format!("timeline:{timeline_name}"),
            Hold::WorldBase { world_id, .. } => format!("world:{world_id}"),
            Hold::Pin { pin_id, .. } => format!("pin:{pin_id}"),
            Hold::PreparingParent { child_frame } => format!("preparing:{child_frame}"),
        }
    }
}

/// Request to attach a pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSpec {
    /// Pin id (unique per frame).
    pub pin_id: String,
    /// Owner; must own the frame being pinned.
    pub owner: String,
    /// Lease length (`1..=MetaConfig::max_pin_ttl_ms`).
    pub lease_ttl_ms: u64,
}

/// A row of the `TIMELINES` table. The first writer of a timeline becomes its owner; only the
/// owner may move or delete it, and only onto frames it owns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRecord {
    /// Current head (holds a `TimelineHead`).
    pub head: FrameId,
    /// Owner.
    pub owner: String,
}

// ============================================================================ worlds

/// Why a world ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorldEndReason {
    /// Explicit destroy by its owner.
    Requested {
        /// Caller.
        by: String,
    },
    /// Batch destroy through a label selector.
    BatchSelector {
        /// Caller.
        by: String,
        /// Selector used.
        selector: Labels,
    },
    /// In-memory lease expired.
    LeaseExpired,
}

/// World lifecycle. Running worlds never survive an `agentd` restart (they become `Lost`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorldState {
    /// Alive in `epoch`.
    Running {
        /// Epoch the world was started in.
        epoch: EpochId,
    },
    /// Ended normally (tombstone).
    Destroyed {
        /// Epoch the world was started in.
        epoch: EpochId,
        /// When.
        destroyed_at_ms: u64,
        /// Why.
        reason: WorldEndReason,
    },
    /// Its daemon epoch died (tombstone).
    Lost {
        /// Epoch the world was started in.
        origin_epoch: EpochId,
        /// Epoch whose recovery declared it lost.
        lost_in_epoch: EpochId,
        /// When.
        lost_at_ms: u64,
    },
}

impl WorldState {
    /// `true` for `Running`.
    #[must_use]
    pub fn is_running(&self) -> bool {
        matches!(self, WorldState::Running { .. })
    }

    /// End time of a tombstone.
    #[must_use]
    pub fn ended_at_ms(&self) -> Option<u64> {
        match self {
            WorldState::Running { .. } => None,
            WorldState::Destroyed {
                destroyed_at_ms, ..
            } => Some(*destroyed_at_ms),
            WorldState::Lost { lost_at_ms, .. } => Some(*lost_at_ms),
        }
    }
}

/// A row of the `WORLDS` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldRecord {
    /// World id.
    pub world_id: WorldId,
    /// Base frame (held by `Hold::WorldBase` while running).
    pub base_frame: FrameId,
    /// Owner.
    pub owner: String,
    /// Immutable labels.
    pub labels: Labels,
    /// Current fencing token (an idempotent replay reports the token originally issued to
    /// that request instead).
    pub fencing_token: FencingToken,
    /// Lifecycle state.
    pub state: WorldState,
}

// ============================================================================ idempotency / quarantine

/// Client-chosen idempotency key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdempotencyKey {
    /// Caller identity; must equal the request owner.
    pub owner: String,
    /// Client request id.
    pub request_id: String,
}

impl IdempotencyKey {
    /// Construct.
    pub fn new(owner: impl Into<String>, request_id: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            request_id: request_id.into(),
        }
    }
}

/// A row of the `QUARANTINE` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Original entry name in `objects/` (lossy UTF-8 for display; exact when valid UTF-8).
    pub name: String,
    /// Exact original filename when `name` is not valid UTF-8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<std::ffi::OsString>,
    /// Epoch whose recovery quarantined it (`quarantine/epoch-<n>/`).
    pub quarantined_epoch: EpochId,
    /// When.
    pub quarantined_at_ms: u64,
    /// Earliest physical purge time.
    pub purge_after_ms: u64,
}

impl QuarantineRecord {
    /// Exact OS filename inside `quarantine/epoch-<n>/`.
    #[must_use]
    pub fn file_name(&self) -> std::ffi::OsString {
        self.raw_name
            .clone()
            .unwrap_or_else(|| std::ffi::OsString::from(&self.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_roundtrip_and_parser_is_strict() {
        let f = FrameId::random();
        for k in ObjectKind::ALL {
            let o = ManagedObject::new(f, k);
            assert_eq!(ManagedObject::parse_name(&o.name()), Some(o));
        }
        let b = f.to_base32();
        for bad in [
            format!("f-{b}-disk.img.tmp"),
            format!("f-{b}-DISK.img"),
            format!("f-{}-subvol", b.to_uppercase()),
            format!("F-{b}-subvol"),
            format!("f-{b}subvol"),
            format!("f-{b}-"),
            format!("f-{}-subvol", &b[1..]),
            format!("f-8{}-subvol", &b[1..]),
            "f-".into(),
            "random.bin".into(),
            "f-é".into(),
        ] {
            assert_eq!(ManagedObject::parse_name(&bad), None, "accepted {bad:?}");
        }
    }

    #[test]
    fn pool_id_and_fencing_token() {
        let p = PoolId::random().unwrap();
        let s = p.to_string();
        assert_eq!(s.len(), 36);
        assert_eq!(PoolId::parse(&s).unwrap(), p);
        assert!(PoolId::parse(&s.to_uppercase()).is_err());
        assert!(PoolId::parse(&format!("{s}\n")).is_err());
        assert_eq!(serde_json::from_str::<PoolId>(&serde_json::to_string(&p).unwrap()).unwrap(), p);

        assert_eq!(FencingToken::FIRST.get(), 1);
        assert_eq!(FencingToken::FIRST.next().unwrap().get(), 2);
        assert!(FencingToken::new(0).is_none());
        assert!(FencingToken::new(u64::MAX).unwrap().next().is_none());
    }

    #[test]
    fn label_limits() {
        let mut l = Labels::new();
        assert!(validate_labels(&l).is_ok());
        l.insert(String::new(), "v".into());
        assert!(validate_labels(&l).is_err());
        l.clear();
        l.insert("k".repeat(MAX_LABEL_KEY_LEN + 1), "v".into());
        assert!(validate_labels(&l).is_err());
        l.clear();
        l.insert("k".into(), "v".repeat(MAX_LABEL_VALUE_LEN + 1));
        assert!(validate_labels(&l).is_err());
        l.clear();
        for i in 0..=MAX_LABELS {
            l.insert(format!("k{i}"), "v".into());
        }
        assert!(validate_labels(&l).is_err());
        l.pop_first();
        assert!(validate_labels(&l).is_ok());
        assert!(labels_match(&l, &Labels::new()));
    }
}
