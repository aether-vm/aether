//! `forkloom.v1` gRPC services (`SystemService`, `FrameService`, `WorldService`) wired to
//! `aos-meta::MetaEngine` and pluggable `TreeBackend` + `SandboxBackend`.

#![forbid(unsafe_code)]
// `tonic::Status` is 176 bytes and mandated by tonic's generated gRPC service traits.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aos_meta::{
    CommitFrameRequest, CommitProofBundle, CreateWorldRequest as MetaCreateWorldRequest,
    DeleteOutcome, FencingToken as MetaFencingToken, FrameDurability as MetaDurability,
    FrameRecord, FrameState, Hold, IdempotencyKey as MetaIdempotencyKey, Labels, ManagedObject,
    MetaEngine, ObjectKind, PinSpec as MetaPinSpec, PrepareFrameRequest, TimelineTarget,
    WorldFence, WorldRecord, WorldState,
};
use aos_types::{FrameId, Persisted, WorldId};
use tokio::sync::{mpsc, Mutex as AsyncMutex, OwnedMutexGuard};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Code, Request, Response, Status, Streaming};

use crate::backend::{
    SandboxBackend, SandboxExecRequest, SandboxExecResult, SandboxOutputChunk, SpawnWorldSpec,
    TreeBackend,
};
use crate::error::{map_meta_error, simple_status, world_lost_status, BackendError};
use crate::proto::frame_service_server::FrameService;
use crate::proto::system_service_server::SystemService;
use crate::proto::world_service_server::WorldService;
use crate::proto::{
    self, AcquireFenceRequest, AcquireFenceResponse, AdvanceTimelineRequest,
    AdvanceTimelineResponse, CheckpointRequest, CheckpointResponse,
    CreateWorldRequest, CreateWorldResponse, DeleteFrameRequest, DeleteFrameResponse,
    DeleteTimelineRequest, DeleteTimelineResponse, DestroyWorldRequest, DestroyWorldResponse,
    DriverKind, ErrorCode, ExecEvent, ExecOutputChunk, ExecRequest, ExecResult, ExportPatchRequest,
    ExportPatchResponse, FrameDurability, FrameInfo, FrameStateKind, GetFrameRequest,
    GetFrameResponse, GetWorldRequest, GetWorldResponse, HoldInfo, ImportTarRequest,
    ImportTarResponse, ListFramesRequest, ListFramesResponse, NegotiateVersionRequest,
    NegotiateVersionResponse, PatchEntry, PinFrameRequest, PinFrameResponse, RenewPinRequest,
    RenewPinResponse, RenewWorldLeaseRequest, RenewWorldLeaseResponse, TimelineInfo, WorldInfo,
    WorldStateKind,
};
use crate::{API_MAJOR, API_MINOR};

/// Default maximum streaming tar size accepted by `ImportTar` (256 MiB).
pub const DEFAULT_MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;
/// Default world lease TTL when caller omits `lease_ttl_ms` (10 minutes).
pub const DEFAULT_WORLD_LEASE_TTL_MS: u64 = 10 * 60 * 1000;
/// Default `Exec` timeout when caller omits `timeout_ms` (60 seconds).
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 60 * 1000;
/// Default `Exec` max retained bytes per stream (64 KiB).
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct CachedExec {
    request_digest: [u8; 32],
    result: ExecResult,
}

#[derive(Debug, Clone)]
struct LiveWorldMeta {
    driver: DriverKind,
    rootfs_path: PathBuf,
    lease_ttl_ms: u64,
}

type IdemKey = (String, String);

struct AgentdInner {
    meta: Mutex<MetaEngine>,
    tree: Arc<dyn TreeBackend>,
    sandbox: Arc<dyn SandboxBackend>,
    max_import_bytes: usize,
    live_worlds: Mutex<HashMap<WorldId, LiveWorldMeta>>,
    /// Per-`(owner, request_id)` async locks serializing in-flight idempotent RPCs.
    idem_locks: Mutex<HashMap<IdemKey, Arc<AsyncMutex<()>>>>,
    /// Full RPC request digests keyed by `(owner, request_id)` -> `(op_name, blake3_digest)`.
    idem_digests: Mutex<HashMap<IdemKey, (&'static str, [u8; 32])>>,
    /// Successful `CreateWorld` idempotency table keyed by `(owner, request_id)` -> `(digest, world_id)`.
    world_idem_cache: Mutex<HashMap<IdemKey, ([u8; 32], WorldId)>>,
    /// World-lifetime Exec dedup cache keyed by `(world_id, owner, request_id)` (ARCHITECTURE_V2 §7.2).
    exec_cache: Mutex<HashMap<(WorldId, String, String), CachedExec>>,
    exec_seq: AtomicU64,
}

/// Shared gRPC control-plane service implementing `SystemService`, `FrameService`, and `WorldService`.
#[derive(Clone)]
pub struct AgentdService {
    inner: Arc<AgentdInner>,
}

impl AgentdService {
    /// Construct a new control-plane service over an already-recovered [`MetaEngine`].
    pub fn new(
        meta: MetaEngine,
        tree: Arc<dyn TreeBackend>,
        sandbox: Arc<dyn SandboxBackend>,
    ) -> Self {
        Self::with_max_import_bytes(meta, tree, sandbox, DEFAULT_MAX_IMPORT_BYTES)
    }

    /// Construct with a custom `ImportTar` byte cap.
    pub fn with_max_import_bytes(
        meta: MetaEngine,
        tree: Arc<dyn TreeBackend>,
        sandbox: Arc<dyn SandboxBackend>,
        max_import_bytes: usize,
    ) -> Self {
        Self {
            inner: Arc::new(AgentdInner {
                meta: Mutex::new(meta),
                tree,
                sandbox,
                max_import_bytes,
                live_worlds: Mutex::new(HashMap::new()),
                idem_locks: Mutex::new(HashMap::new()),
                idem_digests: Mutex::new(HashMap::new()),
                world_idem_cache: Mutex::new(HashMap::new()),
                exec_cache: Mutex::new(HashMap::new()),
                exec_seq: AtomicU64::new(1),
            }),
        }
    }

    async fn lock_idem(&self, idem: Option<&MetaIdempotencyKey>) -> Option<OwnedMutexGuard<()>> {
        let k = idem?;
        let arc = {
            let mut map = self.inner.idem_locks.lock().unwrap();
            map.entry((k.owner.clone(), k.request_id.clone()))
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };
        Some(arc.lock_owned().await)
    }

    fn check_idem_digest(
        &self,
        idem: Option<&MetaIdempotencyKey>,
        caller_owner: &str,
        op: &'static str,
        digest: [u8; 32],
    ) -> Result<(), Status> {
        let Some(k) = idem else {
            return Ok(());
        };
        if k.owner != caller_owner {
            return Err(simple_status(
                Code::PermissionDenied,
                ErrorCode::OwnerMismatch,
                format!("idempotency key owner {:?} does not match caller {:?}", k.owner, caller_owner),
                k.request_id.clone(),
            ));
        }
        let guard = self.inner.idem_digests.lock().unwrap();
        if let Some((prev_op, prev_digest)) = guard.get(&(k.owner.clone(), k.request_id.clone()))
            && (*prev_op != op || *prev_digest != digest)
        {
            return Err(simple_status(
                Code::AlreadyExists,
                ErrorCode::IdempotencyConflict,
                format!(
                    "idempotency key ({:?}, {:?}) reused with different request parameters",
                    k.owner, k.request_id
                ),
                k.request_id.clone(),
            ));
        }
        Ok(())
    }

    fn store_idem_digest(
        &self,
        idem: Option<&MetaIdempotencyKey>,
        op: &'static str,
        digest: [u8; 32],
    ) {
        if let Some(k) = idem {
            self.inner
                .idem_digests
                .lock()
                .unwrap()
                .insert((k.owner.clone(), k.request_id.clone()), (op, digest));
        }
    }

    fn clear_idem_digest(&self, idem: Option<&MetaIdempotencyKey>) {
        if let Some(k) = idem {
            self.inner
                .idem_digests
                .lock()
                .unwrap()
                .remove(&(k.owner.clone(), k.request_id.clone()));
        }
    }

    /// Current daemon epoch assigned by `aos-meta` R1 recovery.
    #[must_use]
    pub fn daemon_epoch(&self) -> u64 {
        self.inner.meta.lock().unwrap().daemon_epoch().get()
    }

    fn frame_to_proto(&self, meta: &MetaEngine, rec: &FrameRecord) -> Result<FrameInfo, Status> {
        let holds_raw = meta.holds(rec.frame_id).map_err(map_meta_error)?;
        let marked = meta
            .is_marked_for_reclaim(rec.frame_id)
            .map_err(map_meta_error)?;
        let holds = holds_raw.iter().map(hold_to_proto).collect();
        let objects = rec
            .state
            .objects()
            .iter()
            .map(ManagedObject::name)
            .collect();

        let (owner, durability, state, parent, labels, disk_clean, created_epoch, committed_at_ms) =
            match &rec.state {
                FrameState::Preparing {
                    durability,
                    parent,
                    created_epoch,
                    labels,
                    owner,
                    ..
                } => (
                    owner.clone(),
                    *durability,
                    FrameStateKind::FrameStatePreparing,
                    *parent,
                    labels.clone(),
                    false,
                    created_epoch.get(),
                    0,
                ),
                FrameState::Committed {
                    durability,
                    parent,
                    disk_clean,
                    created_epoch,
                    committed_at_ms,
                    labels,
                    owner,
                    ..
                } => (
                    owner.clone(),
                    *durability,
                    FrameStateKind::FrameStateCommitted,
                    *parent,
                    labels.clone(),
                    *disk_clean,
                    created_epoch.get(),
                    *committed_at_ms,
                ),
                FrameState::Deleting {
                    durability, owner, ..
                } => (
                    owner.clone().unwrap_or_default(),
                    *durability,
                    FrameStateKind::FrameStateDeleting,
                    None,
                    Labels::new(),
                    false,
                    0,
                    0,
                ),
            };

        Ok(FrameInfo {
            frame_id: rec.frame_id.to_string(),
            owner,
            durability: durability_to_proto(durability) as i32,
            state: state as i32,
            parent_frame_id: parent.map(|id| id.to_string()).unwrap_or_default(),
            labels: labels.into_iter().collect(),
            disk_clean,
            created_epoch,
            committed_at_ms,
            objects,
            holds,
            marked_for_reclaim: marked,
        })
    }

    fn world_to_proto(&self, rec: &WorldRecord) -> WorldInfo {
        let driver = self
            .inner
            .live_worlds
            .lock()
            .unwrap()
            .get(&rec.world_id)
            .map_or(DriverKind::Namespace, |w| w.driver);
        let (state, origin_epoch, lost_in_epoch, ended_at_ms, end_reason) = match &rec.state {
            WorldState::Running { epoch } => (
                WorldStateKind::WorldStateRunning,
                epoch.get(),
                0,
                0,
                String::new(),
            ),
            WorldState::Destroyed {
                epoch,
                destroyed_at_ms,
                reason,
            } => (
                WorldStateKind::WorldStateDestroyed,
                epoch.get(),
                0,
                *destroyed_at_ms,
                format!("{reason:?}"),
            ),
            WorldState::Lost {
                origin_epoch,
                lost_in_epoch,
                lost_at_ms,
            } => (
                WorldStateKind::WorldStateLost,
                origin_epoch.get(),
                lost_in_epoch.get(),
                *lost_at_ms,
                "DaemonRestart".to_owned(),
            ),
        };
        WorldInfo {
            world_id: rec.world_id.to_string(),
            owner: rec.owner.clone(),
            base_frame_id: rec.base_frame.to_string(),
            driver: driver as i32,
            state: state as i32,
            labels: rec
                .labels
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            fencing_token: Some(proto::FencingToken {
                value: rec.fencing_token.get(),
            }),
            origin_epoch,
            lost_in_epoch,
            ended_at_ms,
            end_reason,
        }
    }

    /// Check if a world record is `WorldState::Lost`; if so, emit explicit `WorldLost` or
    /// `OutcomeUnknown` error per ARCHITECTURE_V2 §7.2.
    fn check_not_lost(
        meta: &MetaEngine,
        world_id: WorldId,
        outcome_unknown: bool,
    ) -> Result<(), Status> {
        if let Some(rec) = meta.world(world_id).map_err(map_meta_error)?
            && let WorldState::Lost {
                origin_epoch,
                lost_in_epoch,
                ..
            } = rec.state
        {
            return Err(world_lost_status(
                world_id,
                origin_epoch.get(),
                lost_in_epoch.get(),
                outcome_unknown,
            ));
        }
        Ok(())
    }
}

fn hold_to_proto(h: &Hold) -> HoldInfo {
    match h {
        Hold::TimelineHead { timeline_name } => HoldInfo {
            kind: "timeline_head".into(),
            detail: timeline_name.clone(),
            expires_at_ms: 0,
        },
        Hold::WorldBase { world_id, epoch } => HoldInfo {
            kind: "world_base".into(),
            detail: format!("{world_id}@epoch-{epoch}"),
            expires_at_ms: 0,
        },
        Hold::Pin {
            pin_id,
            owner,
            expires_at_ms,
            ..
        } => HoldInfo {
            kind: "pin".into(),
            detail: format!("{pin_id} (owner={owner})"),
            expires_at_ms: *expires_at_ms,
        },
        Hold::PreparingParent { child_frame } => HoldInfo {
            kind: "preparing_parent".into(),
            detail: child_frame.to_string(),
            expires_at_ms: 0,
        },
    }
}

fn parse_frame_id(s: &str, field: &str) -> Result<FrameId, Status> {
    s.parse::<FrameId>().map_err(|e| {
        simple_status(
            Code::InvalidArgument,
            ErrorCode::InvalidArgument,
            format!("invalid {field} {s:?}: {e}"),
            s,
        )
    })
}

fn parse_opt_frame_id(s: &str, field: &str) -> Result<Option<FrameId>, Status> {
    if s.is_empty() {
        Ok(None)
    } else {
        parse_frame_id(s, field).map(Some)
    }
}

fn parse_world_id(s: &str) -> Result<WorldId, Status> {
    s.parse::<WorldId>().map_err(|e| {
        simple_status(
            Code::InvalidArgument,
            ErrorCode::InvalidArgument,
            format!("invalid world_id {s:?}: {e}"),
            s,
        )
    })
}

fn parse_fence(tok: Option<proto::FencingToken>) -> Result<MetaFencingToken, Status> {
    let val = tok.map_or(0, |t| t.value);
    MetaFencingToken::new(val).ok_or_else(|| {
        simple_status(
            Code::InvalidArgument,
            ErrorCode::InvalidArgument,
            "fencing_token must be non-zero",
            "",
        )
    })
}

fn parse_durability(raw: i32) -> Result<MetaDurability, Status> {
    match FrameDurability::try_from(raw).unwrap_or(FrameDurability::Unspecified) {
        FrameDurability::Unspecified | FrameDurability::Durable => Ok(MetaDurability::Durable),
        FrameDurability::Volatile => Ok(MetaDurability::Volatile),
    }
}

fn durability_to_proto(d: MetaDurability) -> FrameDurability {
    match d {
        MetaDurability::Durable => FrameDurability::Durable,
        MetaDurability::Volatile => FrameDurability::Volatile,
    }
}

fn parse_idem(k: Option<proto::IdempotencyKey>) -> Option<MetaIdempotencyKey> {
    k.filter(|k| !k.request_id.is_empty())
        .map(|k| MetaIdempotencyKey::new(k.owner, k.request_id))
}

fn parse_pin(p: Option<proto::PinSpec>) -> Option<MetaPinSpec> {
    p.filter(|p| !p.pin_id.is_empty()).map(|p| MetaPinSpec {
        pin_id: p.pin_id,
        owner: p.owner,
        lease_ttl_ms: p.lease_ttl_ms,
    })
}

fn parse_labels(m: HashMap<String, String>) -> Labels {
    m.into_iter().collect()
}

fn hash_str(h: &mut blake3::Hasher, s: &str) {
    h.update(&(s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

fn hash_labels(h: &mut blake3::Hasher, labels: &Labels) {
    h.update(&(labels.len() as u64).to_le_bytes());
    for (k, v) in labels {
        hash_str(h, k);
        hash_str(h, v);
    }
}

fn hash_opt_pin(h: &mut blake3::Hasher, pin: Option<&MetaPinSpec>) {
    match pin {
        Some(p) => {
            h.update(&[1]);
            hash_str(h, &p.pin_id);
            hash_str(h, &p.owner);
            h.update(&p.lease_ttl_ms.to_le_bytes());
        }
        None => {
            h.update(&[0]);
        }
    }
}

fn hash_opt_timeline(h: &mut blake3::Hasher, tl: Option<&TimelineTarget>) {
    match tl {
        Some(t) => {
            h.update(&[1]);
            hash_str(h, &t.timeline);
            let exp = t.expected_old.map_or(String::new(), |f| f.to_string());
            hash_str(h, &exp);
        }
        None => {
            h.update(&[0]);
        }
    }
}

fn import_tar_request_digest(
    owner: &str,
    durability: MetaDurability,
    parent: Option<FrameId>,
    labels: &Labels,
    pin: Option<&MetaPinSpec>,
    timeline: Option<&TimelineTarget>,
    tar_bytes: &[u8],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_str(&mut h, "import_tar");
    hash_str(&mut h, owner);
    h.update(&[match durability {
        MetaDurability::Durable => 1,
        MetaDurability::Volatile => 2,
    }]);
    let p_str = parent.map_or(String::new(), |f| f.to_string());
    hash_str(&mut h, &p_str);
    hash_labels(&mut h, labels);
    hash_opt_pin(&mut h, pin);
    hash_opt_timeline(&mut h, timeline);
    h.update(&(tar_bytes.len() as u64).to_le_bytes());
    h.update(blake3::hash(tar_bytes).as_bytes());
    *h.finalize().as_bytes()
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_request_digest(
    wid: WorldId,
    owner: &str,
    token: MetaFencingToken,
    durability: MetaDurability,
    labels: &Labels,
    pin: Option<&MetaPinSpec>,
    timeline: Option<&TimelineTarget>,
    perform_syncfs: bool,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_str(&mut h, "checkpoint");
    hash_str(&mut h, &wid.to_string());
    hash_str(&mut h, owner);
    h.update(&token.get().to_le_bytes());
    h.update(&[match durability {
        MetaDurability::Durable => 1,
        MetaDurability::Volatile => 2,
    }]);
    hash_labels(&mut h, labels);
    hash_opt_pin(&mut h, pin);
    hash_opt_timeline(&mut h, timeline);
    h.update(&[u8::from(perform_syncfs)]);
    *h.finalize().as_bytes()
}

fn create_world_request_digest(
    owner: &str,
    base_frame: FrameId,
    driver: DriverKind,
    labels: &Labels,
    lease_ttl_ms: u64,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    hash_str(&mut h, "create_world");
    hash_str(&mut h, owner);
    hash_str(&mut h, &base_frame.to_string());
    h.update(&(driver as i32).to_le_bytes());
    hash_labels(&mut h, labels);
    h.update(&lease_ttl_ms.to_le_bytes());
    *h.finalize().as_bytes()
}

fn exec_request_digest(req: &ExecRequest) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_str(&mut hasher, "exec");
    hash_str(&mut hasher, &req.world_id);
    hash_str(&mut hasher, &req.owner);
    hasher.update(&(req.argv.len() as u64).to_le_bytes());
    for arg in &req.argv {
        hash_str(&mut hasher, arg);
    }
    let sorted_env: BTreeMap<&String, &String> = req.env.iter().collect();
    hasher.update(&(sorted_env.len() as u64).to_le_bytes());
    for (k, v) in sorted_env {
        hash_str(&mut hasher, k);
        hash_str(&mut hasher, v);
    }
    hash_str(&mut hasher, &req.cwd);
    hasher.update(&req.timeout_ms.to_le_bytes());
    hasher.update(&req.max_output_bytes.to_le_bytes());
    *hasher.finalize().as_bytes()
}

// ============================================================================ SystemService

#[tonic::async_trait]
impl SystemService for AgentdService {
    async fn negotiate_version(
        &self,
        request: Request<NegotiateVersionRequest>,
    ) -> Result<Response<NegotiateVersionResponse>, Status> {
        let req = request.into_inner();
        if req.supported_api_major != 0 && req.supported_api_major != API_MAJOR {
            return Err(simple_status(
                Code::FailedPrecondition,
                ErrorCode::InvalidArgument,
                format!(
                    "incompatible api_major: client supports {}, daemon serves {}",
                    req.supported_api_major, API_MAJOR
                ),
                req.client_name,
            ));
        }
        let daemon_epoch = self.daemon_epoch();
        Ok(Response::new(NegotiateVersionResponse {
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            api_major: API_MAJOR,
            api_minor: API_MINOR,
            daemon_epoch,
            enabled_drivers: self.inner.sandbox.enabled_drivers(),
        }))
    }
}

// ============================================================================ FrameService

#[tonic::async_trait]
impl FrameService for AgentdService {
    async fn import_tar(
        &self,
        request: Request<Streaming<ImportTarRequest>>,
    ) -> Result<Response<ImportTarResponse>, Status> {
        let mut stream = request.into_inner();
        let first = stream.next().await.transpose()?.ok_or_else(|| {
            simple_status(
                Code::InvalidArgument,
                ErrorCode::InvalidArgument,
                "ImportTar stream ended without header",
                "",
            )
        })?;
        let header = match first.chunk {
            Some(proto::import_tar_request::Chunk::Header(h)) => h,
            _ => {
                return Err(simple_status(
                    Code::InvalidArgument,
                    ErrorCode::InvalidArgument,
                    "first ImportTar message must contain header",
                    "",
                ));
            }
        };

        let mut tar_bytes = Vec::new();
        while let Some(msg) = stream.next().await.transpose()? {
            match msg.chunk {
                Some(proto::import_tar_request::Chunk::Data(chunk)) => {
                    if tar_bytes.len().saturating_add(chunk.len()) > self.inner.max_import_bytes {
                        return Err(simple_status(
                            Code::ResourceExhausted,
                            ErrorCode::ResourceExhausted,
                            format!(
                                "ImportTar stream exceeds max_import_bytes ({})",
                                self.inner.max_import_bytes
                            ),
                            "",
                        ));
                    }
                    tar_bytes.extend_from_slice(&chunk);
                }
                Some(proto::import_tar_request::Chunk::Header(_)) => {
                    return Err(simple_status(
                        Code::InvalidArgument,
                        ErrorCode::InvalidArgument,
                        "duplicate ImportTar header chunk",
                        "",
                    ));
                }
                None => {}
            }
        }

        let durability = parse_durability(header.durability)?;
        let parent = parse_opt_frame_id(&header.parent_frame_id, "parent_frame_id")?;
        let pin = parse_pin(header.pin);
        let timeline = if header.timeline_name.is_empty() {
            None
        } else {
            let expected_old =
                parse_opt_frame_id(&header.expected_old_timeline_head, "expected_old_timeline_head")?;
            Some(TimelineTarget {
                timeline: header.timeline_name.clone(),
                expected_old,
            })
        };
        let idem = parse_idem(header.idempotency_key);
        let labels = parse_labels(header.labels);
        let bytes_received = tar_bytes.len() as u64;

        let _idem_guard = self.lock_idem(idem.as_ref()).await;
        let full_digest = import_tar_request_digest(
            &header.owner,
            durability,
            parent,
            &labels,
            pin.as_ref(),
            timeline.as_ref(),
            &tar_bytes,
        );
        self.check_idem_digest(idem.as_ref(), &header.owner, "import_tar", full_digest)?;

        // T1: write Preparing intent BEFORE creating any pool object (Invariant I1).
        let (prepared, target_path, newly_created) = {
            let mut meta = self.inner.meta.lock().unwrap();
            let before_ids: HashSet<FrameId> = meta
                .frames()
                .map_err(map_meta_error)?
                .into_iter()
                .map(|f| f.frame_id)
                .collect();
            let prep = meta
                .prepare_frame(
                    &PrepareFrameRequest {
                        owner: header.owner.clone(),
                        durability,
                        parent,
                        object_kinds: vec![ObjectKind::TreeSubvol],
                        labels,
                        source_world: None,
                    },
                    idem.as_ref(),
                )
                .map_err(map_meta_error)?;
            self.store_idem_digest(idem.as_ref(), "import_tar", full_digest);
            let obj = prep.expected_objects[0];
            let path = meta.config().objects_dir().join(obj.name());
            let is_new = !before_ids.contains(&prep.frame_id);
            (prep, path, is_new)
        };

        // Check if idempotent replay returned an already-existing frame.
        if !newly_created {
            let meta = self.inner.meta.lock().unwrap();
            if let Some(rec) = meta.frame(prepared.frame_id).map_err(map_meta_error)? {
                if matches!(rec.state, FrameState::Committed { .. }) {
                    let frame = self.frame_to_proto(&meta, &rec)?;
                    let tl = if let Some(t) = &timeline {
                        meta.timeline(&t.timeline)
                            .map_err(map_meta_error)?
                            .map(|r| TimelineInfo {
                                name: t.timeline.clone(),
                                owner: r.owner,
                                head_frame_id: r.head.to_string(),
                            })
                    } else {
                        None
                    };
                    return Ok(Response::new(ImportTarResponse {
                        frame: Some(frame),
                        timeline: tl,
                        bytes_received,
                    }));
                }
                return Err(simple_status(
                    Code::Aborted,
                    ErrorCode::PreparedFrameAborted,
                    format!("frame {} is already Preparing in another operation", prepared.frame_id),
                    prepared.frame_id.to_string(),
                ));
            }
        }

        // Unpack safely & get fsync_subvolume proof; rollback Preparing frame on failure!
        let proof = match self.inner.tree.import_tar(&target_path, &tar_bytes) {
            Ok(p) => p,
            Err(e) => {
                let mut meta = self.inner.meta.lock().unwrap();
                let _ = meta.delete_frame(prepared.frame_id, &header.owner, None);
                self.clear_idem_digest(idem.as_ref());
                return Err(e.into());
            }
        };

        // T2: atomic unique commit point (Preparing -> Committed).
        let obj = prepared.expected_objects[0];
        let bundle = CommitProofBundle::new().with_persisted(Persisted::new(obj, proof));
        let mut meta = self.inner.meta.lock().unwrap();
        let committed = match meta.commit_frame(
            &CommitFrameRequest {
                frame_id: prepared.frame_id,
                owner: header.owner.clone(),
                disk_clean: true,
                fence: None,
                pin,
                timeline: timeline.clone(),
            },
            bundle,
            None,
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = meta.delete_frame(prepared.frame_id, &header.owner, None);
                self.clear_idem_digest(idem.as_ref());
                return Err(map_meta_error(e));
            }
        };

        let rec = meta
            .frame(committed.frame_id)
            .map_err(map_meta_error)?
            .ok_or_else(|| Status::internal("committed frame missing immediately after T2"))?;
        let frame = self.frame_to_proto(&meta, &rec)?;
        let tl_info = committed.timeline.map(|t| TimelineInfo {
            name: t.timeline,
            owner: header.owner,
            head_frame_id: t.head.to_string(),
        });
        Ok(Response::new(ImportTarResponse {
            frame: Some(frame),
            timeline: tl_info,
            bytes_received,
        }))
    }

    async fn get_frame(
        &self,
        request: Request<GetFrameRequest>,
    ) -> Result<Response<GetFrameResponse>, Status> {
        let req = request.into_inner();
        let fid = parse_frame_id(&req.frame_id, "frame_id")?;
        let meta = self.inner.meta.lock().unwrap();
        let rec = meta
            .frame(fid)
            .map_err(map_meta_error)?
            .ok_or_else(|| map_meta_error(aos_meta::MetaError::FrameNotFound(fid)))?;
        let frame = self.frame_to_proto(&meta, &rec)?;
        Ok(Response::new(GetFrameResponse { frame: Some(frame) }))
    }

    async fn list_frames(
        &self,
        request: Request<ListFramesRequest>,
    ) -> Result<Response<ListFramesResponse>, Status> {
        let req = request.into_inner();
        let selector = parse_labels(req.label_selector);
        let meta = self.inner.meta.lock().unwrap();
        let all = meta.frames().map_err(map_meta_error)?;
        let mut frames = Vec::new();
        for rec in &all {
            if !req.include_non_committed && !matches!(rec.state, FrameState::Committed { .. }) {
                continue;
            }
            if !req.owner.is_empty() && rec.state.owner() != Some(req.owner.as_str()) {
                continue;
            }
            if !selector.is_empty() {
                let labels = match &rec.state {
                    FrameState::Committed { labels, .. } | FrameState::Preparing { labels, .. } => {
                        Some(labels)
                    }
                    FrameState::Deleting { .. } => None,
                };
                if !labels.is_some_and(|l| selector.iter().all(|(k, v)| l.get(k) == Some(v))) {
                    continue;
                }
            }
            frames.push(self.frame_to_proto(&meta, rec)?);
        }
        Ok(Response::new(ListFramesResponse { frames }))
    }

    async fn pin_frame(
        &self,
        request: Request<PinFrameRequest>,
    ) -> Result<Response<PinFrameResponse>, Status> {
        let req = request.into_inner();
        let fid = parse_frame_id(&req.frame_id, "frame_id")?;
        let spec = parse_pin(req.pin).ok_or_else(|| {
            simple_status(
                Code::InvalidArgument,
                ErrorCode::InvalidArgument,
                "pin spec is required",
                &req.frame_id,
            )
        })?;
        let mut meta = self.inner.meta.lock().unwrap();
        let hold = meta.pin_frame(fid, &spec).map_err(map_meta_error)?;
        Ok(Response::new(PinFrameResponse {
            hold: Some(hold_to_proto(&hold)),
        }))
    }

    async fn renew_pin(
        &self,
        request: Request<RenewPinRequest>,
    ) -> Result<Response<RenewPinResponse>, Status> {
        let req = request.into_inner();
        let fid = parse_frame_id(&req.frame_id, "frame_id")?;
        let mut meta = self.inner.meta.lock().unwrap();
        let r = meta
            .renew_pin_lease(fid, &req.pin_id, &req.owner)
            .map_err(map_meta_error)?;
        Ok(Response::new(RenewPinResponse {
            expires_at_ms: r.expires_at_ms,
            persisted_to_disk: r.flushed,
        }))
    }

    async fn delete_frame(
        &self,
        request: Request<DeleteFrameRequest>,
    ) -> Result<Response<DeleteFrameResponse>, Status> {
        let req = request.into_inner();
        let fid = parse_frame_id(&req.frame_id, "frame_id")?;
        let idem = parse_idem(req.idempotency_key);
        let mut meta = self.inner.meta.lock().unwrap();
        let outcome = meta
            .delete_frame(fid, &req.owner, idem.as_ref())
            .map_err(map_meta_error)?;
        let resp = match outcome {
            DeleteOutcome::Deleted => DeleteFrameResponse {
                deleted: true,
                deferred: false,
                remaining_holds: 0,
            },
            DeleteOutcome::Deferred { holds } => DeleteFrameResponse {
                deleted: false,
                deferred: true,
                remaining_holds: u32::try_from(holds).unwrap_or(u32::MAX),
            },
        };
        Ok(Response::new(resp))
    }

    async fn advance_timeline(
        &self,
        request: Request<AdvanceTimelineRequest>,
    ) -> Result<Response<AdvanceTimelineResponse>, Status> {
        let req = request.into_inner();
        let expected_old =
            parse_opt_frame_id(&req.expected_old_frame_id, "expected_old_frame_id")?;
        let new_head = parse_frame_id(&req.new_head_frame_id, "new_head_frame_id")?;
        let idem = parse_idem(req.idempotency_key);
        let mut meta = self.inner.meta.lock().unwrap();
        let adv = meta
            .advance_timeline_cas(
                &req.timeline,
                &req.owner,
                expected_old,
                new_head,
                idem.as_ref(),
            )
            .map_err(map_meta_error)?;
        Ok(Response::new(AdvanceTimelineResponse {
            timeline: Some(TimelineInfo {
                name: adv.timeline,
                owner: req.owner,
                head_frame_id: adv.head.to_string(),
            }),
            previous_head_frame_id: adv.previous.map(|id| id.to_string()).unwrap_or_default(),
        }))
    }

    async fn delete_timeline(
        &self,
        request: Request<DeleteTimelineRequest>,
    ) -> Result<Response<DeleteTimelineResponse>, Status> {
        let req = request.into_inner();
        let idem = parse_idem(req.idempotency_key);
        let mut meta = self.inner.meta.lock().unwrap();
        let released = meta
            .delete_timeline(&req.timeline, &req.owner, idem.as_ref())
            .map_err(map_meta_error)?;
        Ok(Response::new(DeleteTimelineResponse {
            released_head_frame_id: released.to_string(),
        }))
    }

    async fn export_patch(
        &self,
        request: Request<ExportPatchRequest>,
    ) -> Result<Response<ExportPatchResponse>, Status> {
        let req = request.into_inner();
        let target_id = parse_frame_id(&req.target_frame_id, "target_frame_id")?;
        let explicit_base = parse_opt_frame_id(&req.base_frame_id, "base_frame_id")?;

        let (base_id, base_path, target_path) = {
            let meta = self.inner.meta.lock().unwrap();
            let target_rec = meta
                .frame(target_id)
                .map_err(map_meta_error)?
                .ok_or_else(|| map_meta_error(aos_meta::MetaError::FrameNotFound(target_id)))?;
            let (target_owner, target_parent, target_objs, disk_clean) = match &target_rec.state {
                FrameState::Committed {
                    owner,
                    parent,
                    objects,
                    disk_clean,
                    ..
                } => (owner.as_str(), *parent, objects.as_slice(), *disk_clean),
                other => {
                    return Err(simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::InvalidArgument,
                        format!("target frame {target_id} is {}, expected Committed", other.name()),
                        target_id.to_string(),
                    ));
                }
            };
            if !req.owner.is_empty() && req.owner != target_owner {
                return Err(simple_status(
                    Code::PermissionDenied,
                    ErrorCode::OwnerMismatch,
                    format!("frame {target_id} is not owned by {:?}", req.owner),
                    target_id.to_string(),
                ));
            }
            // ARCHITECTURE_V2 §3.4 A6b: refuse patch extraction on frames not captured DiskClean.
            if !disk_clean {
                return Err(simple_status(
                    Code::FailedPrecondition,
                    ErrorCode::DiskNotClean,
                    format!("frame {target_id} was not captured with disk_clean=true"),
                    target_id.to_string(),
                ));
            }

            let base_id = explicit_base.or(target_parent).ok_or_else(|| {
                simple_status(
                    Code::InvalidArgument,
                    ErrorCode::InvalidArgument,
                    "base_frame_id is required when target frame has no lineage parent",
                    target_id.to_string(),
                )
            })?;
            let base_rec = meta
                .frame(base_id)
                .map_err(map_meta_error)?
                .ok_or_else(|| map_meta_error(aos_meta::MetaError::FrameNotFound(base_id)))?;
            let (base_owner, base_objs) = match &base_rec.state {
                FrameState::Committed { owner, objects, .. } => (owner.as_str(), objects.as_slice()),
                other => {
                    return Err(simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::InvalidArgument,
                        format!("base frame {base_id} is {}, expected Committed", other.name()),
                        base_id.to_string(),
                    ));
                }
            };
            if !req.owner.is_empty() && req.owner != base_owner {
                return Err(simple_status(
                    Code::PermissionDenied,
                    ErrorCode::OwnerMismatch,
                    format!("base frame {base_id} is not owned by {:?}", req.owner),
                    base_id.to_string(),
                ));
            }

            let base_subvol = base_objs
                .iter()
                .find(|o| o.kind == ObjectKind::TreeSubvol)
                .ok_or_else(|| {
                    simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::DriverUnavailable,
                        "base frame has no TreeSubvol (Inspector VM block diff lands in Phase 2)",
                        base_id.to_string(),
                    )
                })?;
            let target_subvol = target_objs
                .iter()
                .find(|o| o.kind == ObjectKind::TreeSubvol)
                .ok_or_else(|| {
                    simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::DriverUnavailable,
                        "target frame has no TreeSubvol (Inspector VM block diff lands in Phase 2)",
                        target_id.to_string(),
                    )
                })?;
            let dir = meta.config().objects_dir();
            (base_id, dir.join(base_subvol.name()), dir.join(target_subvol.name()))
        };

        let bundle = self
            .inner
            .tree
            .export_patch(&base_path, &target_path)
            .map_err(Status::from)?;
        let entries = bundle
            .entries
            .into_iter()
            .map(|e| PatchEntry {
                path: e.path,
                kind: e.kind.to_owned(),
                size_bytes: e.size_bytes,
            })
            .collect();
        Ok(Response::new(ExportPatchResponse {
            base_frame_id: base_id.to_string(),
            target_frame_id: target_id.to_string(),
            unified_diff: bundle.unified_diff,
            entries,
            blake3_hex: bundle.blake3_hex,
        }))
    }
}

// ============================================================================ WorldService

#[tonic::async_trait]
impl WorldService for AgentdService {
    type ExecStream = ReceiverStream<Result<ExecEvent, Status>>;

    async fn create_world(
        &self,
        request: Request<CreateWorldRequest>,
    ) -> Result<Response<CreateWorldResponse>, Status> {
        let req = request.into_inner();
        let base_frame = parse_frame_id(&req.base_frame_id, "base_frame_id")?;
        let driver = match DriverKind::try_from(req.driver).unwrap_or(DriverKind::Unspecified) {
            DriverKind::Unspecified | DriverKind::Namespace => DriverKind::Namespace,
            DriverKind::Firecracker => DriverKind::Firecracker,
        };
        let lease_ttl_ms = if req.lease_ttl_ms == 0 {
            DEFAULT_WORLD_LEASE_TTL_MS
        } else {
            req.lease_ttl_ms
        };
        let idem = parse_idem(req.idempotency_key);
        let labels = parse_labels(req.labels);

        let _idem_guard = self.lock_idem(idem.as_ref()).await;
        let full_digest =
            create_world_request_digest(&req.owner, base_frame, driver, &labels, lease_ttl_ms);
        self.check_idem_digest(idem.as_ref(), &req.owner, "create_world", full_digest)?;

        // Check idempotent replay BEFORE validating driver / creating world.
        if let Some(ref k) = idem {
            let cached_wid = self
                .inner
                .world_idem_cache
                .lock()
                .unwrap()
                .get(&(k.owner.clone(), k.request_id.clone()))
                .copied();
            if let Some((saved_digest, wid)) = cached_wid {
                if saved_digest != full_digest {
                    return Err(simple_status(
                        Code::AlreadyExists,
                        ErrorCode::IdempotencyConflict,
                        format!(
                            "CreateWorld request_id {:?} reused with different parameters",
                            k.request_id
                        ),
                        k.request_id.clone(),
                    ));
                }
                let meta = self.inner.meta.lock().unwrap();
                let mut rec = meta
                    .world(wid)
                    .map_err(map_meta_error)?
                    .ok_or_else(|| map_meta_error(aos_meta::MetaError::WorldNotFound(wid)))?;
                rec.fencing_token = MetaFencingToken::FIRST;
                let info = self.world_to_proto(&rec);
                return Ok(Response::new(CreateWorldResponse { world: Some(info) }));
            }
        }

        // Validate driver is enabled BEFORE calling meta.create_world so a failed spawn
        // never poisons redb TBL_IDEMPOTENCY with a Destroyed world.
        let driver_name = match driver {
            DriverKind::Namespace | DriverKind::Unspecified => "namespace",
            DriverKind::Firecracker => "firecracker",
        };
        if !self
            .inner
            .sandbox
            .enabled_drivers()
            .iter()
            .any(|d| d == driver_name)
        {
            return Err(BackendError::DriverUnavailable(format!(
                "driver {driver_name:?} is not enabled on this agentd"
            ))
            .into());
        }

        let (world_rec, base_subvol_path) = {
            let mut meta = self.inner.meta.lock().unwrap();
            let base_rec = meta
                .frame(base_frame)
                .map_err(map_meta_error)?
                .ok_or_else(|| map_meta_error(aos_meta::MetaError::FrameNotFound(base_frame)))?;
            let subvol = base_rec
                .state
                .objects()
                .iter()
                .find(|o| o.kind == ObjectKind::TreeSubvol)
                .ok_or_else(|| {
                    simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::DriverUnavailable,
                        "base frame has no TreeSubvol for Namespace cold fork",
                        base_frame.to_string(),
                    )
                })?;
            let subvol_path = meta.config().objects_dir().join(subvol.name());
            let rec = meta
                .create_world(
                    &MetaCreateWorldRequest {
                        owner: req.owner.clone(),
                        base_frame,
                        labels,
                        lease_ttl_ms,
                    },
                    None,
                )
                .map_err(map_meta_error)?;
            (rec, subvol_path)
        };

        let rootfs_path = match self
            .inner
            .tree
            .create_writable_clone(&base_subvol_path, world_rec.world_id)
        {
            Ok(p) => p,
            Err(e) => {
                let mut meta = self.inner.meta.lock().unwrap();
                let _ = meta.destroy_world(
                    world_rec.world_id,
                    &req.owner,
                    world_rec.fencing_token,
                    None,
                );
                return Err(e.into());
            }
        };
        if let Err(e) = self.inner.sandbox.spawn_world(SpawnWorldSpec {
            world_id: world_rec.world_id,
            driver,
            rootfs_path: rootfs_path.clone(),
        }) {
            let _ = self.inner.tree.destroy_subvolume(&rootfs_path);
            let mut meta = self.inner.meta.lock().unwrap();
            let _ = meta.destroy_world(
                world_rec.world_id,
                &req.owner,
                world_rec.fencing_token,
                None,
            );
            return Err(e.into());
        }
        self.inner.live_worlds.lock().unwrap().insert(
            world_rec.world_id,
            LiveWorldMeta {
                driver,
                rootfs_path,
                lease_ttl_ms,
            },
        );
        if let Some(ref k) = idem {
            self.store_idem_digest(idem.as_ref(), "create_world", full_digest);
            self.inner.world_idem_cache.lock().unwrap().insert(
                (k.owner.clone(), k.request_id.clone()),
                (full_digest, world_rec.world_id),
            );
        }

        let info = self.world_to_proto(&world_rec);
        Ok(Response::new(CreateWorldResponse { world: Some(info) }))
    }

    async fn get_world(
        &self,
        request: Request<GetWorldRequest>,
    ) -> Result<Response<GetWorldResponse>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let meta = self.inner.meta.lock().unwrap();
        let rec = meta
            .world(wid)
            .map_err(map_meta_error)?
            .ok_or_else(|| map_meta_error(aos_meta::MetaError::WorldNotFound(wid)))?;
        let info = self.world_to_proto(&rec);
        Ok(Response::new(GetWorldResponse { world: Some(info) }))
    }

    async fn destroy_world(
        &self,
        request: Request<DestroyWorldRequest>,
    ) -> Result<Response<DestroyWorldResponse>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let token = parse_fence(req.fencing_token)?;
        let idem = parse_idem(req.idempotency_key);

        {
            let meta = self.inner.meta.lock().unwrap();
            Self::check_not_lost(&meta, wid, false)?;
            // Validate owner + fencing token BEFORE tearing down sandbox (unless idempotent replay).
            if idem.is_none() {
                meta.check_world_mutation(wid, &req.owner, token)
                    .map_err(map_meta_error)?;
            }
        }

        let rec = {
            let mut meta = self.inner.meta.lock().unwrap();
            meta.destroy_world(wid, &req.owner, token, idem.as_ref())
                .map_err(map_meta_error)?
        };

        let _ = self.inner.sandbox.destroy_world(wid);
        if let Some(live) = self.inner.live_worlds.lock().unwrap().remove(&wid) {
            let _ = self.inner.tree.destroy_subvolume(&live.rootfs_path);
        }
        self.inner
            .exec_cache
            .lock()
            .unwrap()
            .retain(|(w, _, _), _| *w != wid);

        let info = self.world_to_proto(&rec);
        Ok(Response::new(DestroyWorldResponse { world: Some(info) }))
    }

    async fn acquire_fence(
        &self,
        request: Request<AcquireFenceRequest>,
    ) -> Result<Response<AcquireFenceResponse>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let mut meta = self.inner.meta.lock().unwrap();
        Self::check_not_lost(&meta, wid, false)?;
        let token = meta
            .acquire_world_fence(wid, &req.owner)
            .map_err(map_meta_error)?;
        Ok(Response::new(AcquireFenceResponse {
            fencing_token: Some(proto::FencingToken { value: token.get() }),
        }))
    }

    async fn renew_world_lease(
        &self,
        request: Request<RenewWorldLeaseRequest>,
    ) -> Result<Response<RenewWorldLeaseResponse>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let token = parse_fence(req.fencing_token)?;
        let mut meta = self.inner.meta.lock().unwrap();
        Self::check_not_lost(&meta, wid, false)?;
        meta.renew_world_lease(wid, &req.owner, token)
            .map_err(map_meta_error)?;
        let ttl = self
            .inner
            .live_worlds
            .lock()
            .unwrap()
            .get(&wid)
            .map_or(DEFAULT_WORLD_LEASE_TTL_MS, |w| w.lease_ttl_ms);
        Ok(Response::new(RenewWorldLeaseResponse {
            renewed_ttl_ms: ttl,
        }))
    }

    async fn exec(
        &self,
        request: Request<ExecRequest>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let token = parse_fence(req.fencing_token)?;
        if req.argv.is_empty() {
            return Err(simple_status(
                Code::InvalidArgument,
                ErrorCode::InvalidArgument,
                "Exec argv must not be empty",
                wid.to_string(),
            ));
        }

        let idem = parse_idem(req.idempotency_key.clone());
        let has_idem = idem.is_some();

        // Check WorldLost / OutcomeUnknown first (ARCHITECTURE_V2 §7.2: never auto-replay across restart!).
        {
            let meta = self.inner.meta.lock().unwrap();
            Self::check_not_lost(&meta, wid, has_idem)?;
            meta.check_world_mutation(wid, &req.owner, token)
                .map_err(map_meta_error)?;
        }

        let digest = exec_request_digest(&req);
        let idem_guard = self.lock_idem(idem.as_ref()).await;
        if let Some(ref k) = idem {
            if k.owner != req.owner {
                return Err(simple_status(
                    Code::PermissionDenied,
                    ErrorCode::OwnerMismatch,
                    "idempotency key owner does not match Exec owner",
                    wid.to_string(),
                ));
            }
            let cache_key = (wid, k.owner.clone(), k.request_id.clone());
            let cached = self
                .inner
                .exec_cache
                .lock()
                .unwrap()
                .get(&cache_key)
                .cloned();
            if let Some(cached) = cached {
                if cached.request_digest != digest {
                    return Err(simple_status(
                        Code::AlreadyExists,
                        ErrorCode::IdempotencyConflict,
                        format!("Exec request_id {:?} reused with different payload", k.request_id),
                        k.request_id.clone(),
                    ));
                }
                let mut replayed = cached.result;
                replayed.replayed_from_cache = true;
                let (tx, rx) = mpsc::channel(2);
                let _ = tx
                    .send(Ok(ExecEvent {
                        event: Some(proto::exec_event::Event::Result(replayed)),
                    }))
                    .await;
                return Ok(Response::new(ReceiverStream::new(rx)));
            }
        }

        let seq = self.inner.exec_seq.fetch_add(1, Ordering::Relaxed);
        let exec_id = format!("exec-{seq}");
        let sbx_req = SandboxExecRequest {
            exec_id: exec_id.clone(),
            argv: req.argv.clone(),
            env: req.env.into_iter().collect(),
            cwd: (!req.cwd.is_empty()).then_some(req.cwd),
            timeout_ms: if req.timeout_ms == 0 {
                DEFAULT_EXEC_TIMEOUT_MS
            } else {
                req.timeout_ms
            },
            max_output_bytes: if req.max_output_bytes == 0 {
                DEFAULT_MAX_OUTPUT_BYTES
            } else {
                req.max_output_bytes as usize
            },
            stream: req.stream,
        };

        let (tx, rx) = mpsc::channel::<Result<ExecEvent, Status>>(32);
        let (chunk_tx, mut chunk_rx) = mpsc::channel::<SandboxOutputChunk>(32);
        let inner = self.inner.clone();

        tokio::spawn(async move {
            let _hold_idem_guard = idem_guard;
            let fwd_tx = tx.clone();
            let forwarder = tokio::spawn(async move {
                while let Some(c) = chunk_rx.recv().await {
                    let ev = ExecEvent {
                        event: Some(proto::exec_event::Event::Chunk(ExecOutputChunk {
                            stream: c.stream as i32,
                            seq: c.seq,
                            data: c.data,
                        })),
                    };
                    if fwd_tx.send(Ok(ev)).await.is_err() {
                        break;
                    }
                }
            });

            let sbx = inner.sandbox.clone();
            let exec_out =
                tokio::task::spawn_blocking(move || sbx.exec(wid, sbx_req, chunk_tx)).await;
            let _ = forwarder.await;

            match exec_out {
                Ok(Ok(res)) => {
                    let proto_res = sandbox_exec_to_proto(res);
                    if let Some(k) = idem {
                        inner.exec_cache.lock().unwrap().insert(
                            (wid, k.owner, k.request_id),
                            CachedExec {
                                request_digest: digest,
                                result: proto_res.clone(),
                            },
                        );
                    }
                    let _ = tx
                        .send(Ok(ExecEvent {
                            event: Some(proto::exec_event::Event::Result(proto_res)),
                        }))
                        .await;
                }
                Ok(Err(e)) => {
                    let _ = tx.send(Err(e.into())).await;
                }
                Err(join_err) => {
                    let _ = tx
                        .send(Err(Status::internal(format!("exec task panicked: {join_err}"))))
                        .await;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn checkpoint(
        &self,
        request: Request<CheckpointRequest>,
    ) -> Result<Response<CheckpointResponse>, Status> {
        let req = request.into_inner();
        let wid = parse_world_id(&req.world_id)?;
        let token = parse_fence(req.fencing_token)?;
        let durability = parse_durability(req.durability)?;
        let pin = parse_pin(req.pin);
        let idem = parse_idem(req.idempotency_key);
        let labels = parse_labels(req.labels);
        let timeline = if req.timeline_name.is_empty() {
            None
        } else {
            let expected_old =
                parse_opt_frame_id(&req.expected_old_timeline_head, "expected_old_timeline_head")?;
            Some(TimelineTarget {
                timeline: req.timeline_name.clone(),
                expected_old,
            })
        };

        let _idem_guard = self.lock_idem(idem.as_ref()).await;
        let full_digest = checkpoint_request_digest(
            wid,
            &req.owner,
            token,
            durability,
            &labels,
            pin.as_ref(),
            timeline.as_ref(),
            req.perform_syncfs,
        );
        self.check_idem_digest(idem.as_ref(), &req.owner, "checkpoint", full_digest)?;

        let (prepared, target_path, live_rootfs, newly_created) = {
            let mut meta = self.inner.meta.lock().unwrap();
            Self::check_not_lost(&meta, wid, false)?;
            let world_rec = meta
                .world(wid)
                .map_err(map_meta_error)?
                .ok_or_else(|| map_meta_error(aos_meta::MetaError::WorldNotFound(wid)))?;
            meta.check_world_mutation(wid, &req.owner, token)
                .map_err(map_meta_error)?;
            // Check live_worlds BEFORE calling meta.prepare_frame so a missing live session
            // never leaks a Preparing frame or PreparingParent hold!
            let live_rootfs = self
                .inner
                .live_worlds
                .lock()
                .unwrap()
                .get(&wid)
                .map(|w| w.rootfs_path.clone())
                .ok_or_else(|| {
                    simple_status(
                        Code::FailedPrecondition,
                        ErrorCode::WorldNotRunning,
                        format!("world {wid} has no active rootfs session"),
                        wid.to_string(),
                    )
                })?;
            let before_ids: HashSet<FrameId> = meta
                .frames()
                .map_err(map_meta_error)?
                .into_iter()
                .map(|f| f.frame_id)
                .collect();
            let prep = meta
                .prepare_frame(
                    &PrepareFrameRequest {
                        owner: req.owner.clone(),
                        durability,
                        parent: Some(world_rec.base_frame),
                        object_kinds: vec![ObjectKind::TreeSubvol],
                        labels,
                        source_world: Some(WorldFence {
                            world_id: wid,
                            token,
                        }),
                    },
                    idem.as_ref(),
                )
                .map_err(map_meta_error)?;
            self.store_idem_digest(idem.as_ref(), "checkpoint", full_digest);
            let obj = prep.expected_objects[0];
            let path = meta.config().objects_dir().join(obj.name());
            let is_new = !before_ids.contains(&prep.frame_id);
            (prep, path, live_rootfs, is_new)
        };

        // Check idempotent replay of an already-existing checkpoint.
        if !newly_created {
            let meta = self.inner.meta.lock().unwrap();
            if let Some(rec) = meta.frame(prepared.frame_id).map_err(map_meta_error)? {
                if let FrameState::Committed { disk_clean, .. } = &rec.state {
                    if *disk_clean != req.perform_syncfs {
                        return Err(simple_status(
                            Code::AlreadyExists,
                            ErrorCode::IdempotencyConflict,
                            "checkpoint idempotency key replayed with different perform_syncfs",
                            prepared.frame_id.to_string(),
                        ));
                    }
                    let frame = self.frame_to_proto(&meta, &rec)?;
                    let tl = if let Some(t) = &timeline {
                        meta.timeline(&t.timeline)
                            .map_err(map_meta_error)?
                            .map(|r| TimelineInfo {
                                name: t.timeline.clone(),
                                owner: r.owner,
                                head_frame_id: r.head.to_string(),
                            })
                    } else {
                        None
                    };
                    return Ok(Response::new(CheckpointResponse {
                        frame: Some(frame),
                        timeline: tl,
                    }));
                }
                return Err(simple_status(
                    Code::Aborted,
                    ErrorCode::PreparedFrameAborted,
                    format!("checkpoint frame {} is already Preparing", prepared.frame_id),
                    prepared.frame_id.to_string(),
                ));
            }
        }

        // Strict capture order: FreezeAndSync -> SnapshotReadonly + fsync_subvolume -> Unfreeze -> T2 Commit.
        let disk_clean = match self.inner.sandbox.freeze_and_sync(wid, req.perform_syncfs) {
            Ok(dc) => dc,
            Err(e) => {
                let mut meta = self.inner.meta.lock().unwrap();
                let _ = meta.delete_frame(prepared.frame_id, &req.owner, None);
                self.clear_idem_digest(idem.as_ref());
                return Err(e.into());
            }
        };

        let snap_res = self.inner.tree.snapshot_readonly(&live_rootfs, &target_path);
        let _ = self.inner.sandbox.unfreeze(wid);
        let proof = match snap_res {
            Ok(p) => p,
            Err(e) => {
                let mut meta = self.inner.meta.lock().unwrap();
                let _ = meta.delete_frame(prepared.frame_id, &req.owner, None);
                self.clear_idem_digest(idem.as_ref());
                return Err(e.into());
            }
        };

        let obj = prepared.expected_objects[0];
        let bundle = CommitProofBundle::new().with_persisted(Persisted::new(obj, proof));
        let mut meta = self.inner.meta.lock().unwrap();
        let committed = match meta.commit_frame(
            &CommitFrameRequest {
                frame_id: prepared.frame_id,
                owner: req.owner.clone(),
                disk_clean,
                fence: Some(token),
                pin,
                timeline,
            },
            bundle,
            None,
        ) {
            Ok(c) => c,
            Err(e) => {
                let _ = meta.delete_frame(prepared.frame_id, &req.owner, None);
                self.clear_idem_digest(idem.as_ref());
                return Err(map_meta_error(e));
            }
        };

        let rec = meta
            .frame(committed.frame_id)
            .map_err(map_meta_error)?
            .ok_or_else(|| Status::internal("checkpoint frame missing after T2"))?;
        let frame = self.frame_to_proto(&meta, &rec)?;
        let tl_info = committed.timeline.map(|t| TimelineInfo {
            name: t.timeline,
            owner: req.owner,
            head_frame_id: t.head.to_string(),
        });
        Ok(Response::new(CheckpointResponse {
            frame: Some(frame),
            timeline: tl_info,
        }))
    }
}

fn sandbox_exec_to_proto(r: SandboxExecResult) -> ExecResult {
    ExecResult {
        exec_id: r.exec_id,
        has_exit_code: r.exit_code.is_some(),
        exit_code: r.exit_code.unwrap_or(0),
        has_signal: r.signal.is_some(),
        signal: r.signal.unwrap_or(0),
        timed_out: r.timed_out,
        cgroup_killed: r.cgroup_killed,
        duration_ms: r.duration_ms,
        stdout: Some(r.stdout),
        stderr: Some(r.stderr),
        replayed_from_cache: false,
    }
}
