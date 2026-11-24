//! Lossless mapping from `aos-meta` / backend errors into gRPC `tonic::Status` carrying
//! machine-readable `forkloom.v1.ErrorDetail` in `x-forkloom-error-bin` metadata.

#![forbid(unsafe_code)]

use aos_meta::MetaError;
use aos_types::WorldId;
use prost::Message;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::{Code, Status};

use crate::proto::{ErrorCode, ErrorDetail};

/// Binary gRPC metadata key carrying protobuf-encoded [`ErrorDetail`].
pub const ERROR_DETAIL_BIN_KEY: &str = "x-forkloom-error-bin";
/// ASCII gRPC metadata key carrying the canonical error code name.
pub const ERROR_CODE_ASCII_KEY: &str = "x-forkloom-error-code";

/// Construct a [`tonic::Status`] with attached protobuf [`ErrorDetail`] metadata.
#[must_use]
pub fn status_with_detail(grpc_code: Code, detail: ErrorDetail) -> Status {
    let msg = detail.message.clone();
    let code_name = ErrorCode::try_from(detail.code)
        .unwrap_or(ErrorCode::Unspecified)
        .as_str_name();
    let mut status = Status::new(grpc_code, msg);
    let encoded = detail.encode_to_vec();
    if let Ok(key) = MetadataKey::from_bytes(ERROR_DETAIL_BIN_KEY.as_bytes()) {
        status
            .metadata_mut()
            .insert_bin(key, MetadataValue::from_bytes(&encoded));
    }
    if let Ok(key) = MetadataKey::from_bytes(ERROR_CODE_ASCII_KEY.as_bytes())
        && let Ok(val) = MetadataValue::try_from(code_name)
    {
        status.metadata_mut().insert(key, val);
    }
    status
}

/// Extract [`ErrorDetail`] from a [`tonic::Status`] if present.
#[must_use]
pub fn decode_error_detail(status: &Status) -> Option<ErrorDetail> {
    let raw = status.metadata().get_bin(ERROR_DETAIL_BIN_KEY)?;
    let bytes = raw.to_bytes().ok()?;
    ErrorDetail::decode(bytes.as_ref()).ok()
}

/// Build an explicit `WorldLost` error (ARCHITECTURE_V2 §7.2).
#[must_use]
pub fn world_lost_status(
    world_id: WorldId,
    origin_epoch: u64,
    lost_in_epoch: u64,
    outcome_unknown: bool,
) -> Status {
    let (code, message) = if outcome_unknown {
        (
            ErrorCode::OutcomeUnknown,
            format!(
                "world {world_id} was lost across agentd restart (origin_epoch={origin_epoch}, \
                 lost_in_epoch={lost_in_epoch}); prior Exec outcome is explicitly unknown and will not be auto-replayed"
            ),
        )
    } else {
        (
            ErrorCode::WorldLost,
            format!(
                "world {world_id} was lost across agentd restart (origin_epoch={origin_epoch}, \
                 lost_in_epoch={lost_in_epoch}); recreate from a Durable Frame"
            ),
        )
    };
    status_with_detail(
        Code::FailedPrecondition,
        ErrorDetail {
            code: code as i32,
            message,
            resource_id: world_id.to_string(),
            current_fencing_token: 0,
            presented_fencing_token: 0,
            origin_epoch,
            lost_in_epoch,
        },
    )
}

/// Convenience helper for simple structured errors.
#[must_use]
pub fn simple_status(grpc_code: Code, code: ErrorCode, message: impl Into<String>, resource_id: impl Into<String>) -> Status {
    status_with_detail(
        grpc_code,
        ErrorDetail {
            code: code as i32,
            message: message.into(),
            resource_id: resource_id.into(),
            current_fencing_token: 0,
            presented_fencing_token: 0,
            origin_epoch: 0,
            lost_in_epoch: 0,
        },
    )
}

/// Convert an [`aos_meta::MetaError`] into a structured [`tonic::Status`].
#[must_use]
pub fn map_meta_error(err: MetaError) -> Status {
    let message = err.to_string();
    match err {
        MetaError::FrameNotFound(id) => {
            simple_status(Code::NotFound, ErrorCode::FrameNotFound, message, id.to_string())
        }
        MetaError::WorldNotFound(id) => {
            simple_status(Code::NotFound, ErrorCode::WorldNotFound, message, id.to_string())
        }
        MetaError::TimelineNotFound(name) => {
            simple_status(Code::NotFound, ErrorCode::TimelineNotFound, message, name)
        }
        MetaError::PinNotFound { frame, .. } => {
            simple_status(Code::NotFound, ErrorCode::PinNotFound, message, frame.to_string())
        }
        MetaError::FencedOut {
            world,
            presented,
            current,
        } => status_with_detail(
            Code::FailedPrecondition,
            ErrorDetail {
                code: ErrorCode::FencedOut as i32,
                message,
                resource_id: world.to_string(),
                current_fencing_token: current.get(),
                presented_fencing_token: presented.get(),
                origin_epoch: 0,
                lost_in_epoch: 0,
            },
        ),
        MetaError::TimelineCasMismatch { timeline, .. } => simple_status(
            Code::Aborted,
            ErrorCode::TimelineCasMismatch,
            message,
            timeline,
        ),
        MetaError::IdempotencyConflict { request_id, .. } => simple_status(
            Code::AlreadyExists,
            ErrorCode::IdempotencyConflict,
            message,
            request_id,
        ),
        MetaError::OwnerMismatch { resource, .. } => {
            simple_status(Code::PermissionDenied, ErrorCode::OwnerMismatch, message, resource)
        }
        MetaError::WorldNotRunning(id) => {
            simple_status(Code::FailedPrecondition, ErrorCode::WorldNotRunning, message, id.to_string())
        }
        MetaError::VolatileInTimelineForbidden(id) => simple_status(
            Code::InvalidArgument,
            ErrorCode::VolatileInTimelineForbidden,
            message,
            id.to_string(),
        ),
        MetaError::FrameMarkedForDeletion(id) => simple_status(
            Code::FailedPrecondition,
            ErrorCode::FrameMarkedForDeletion,
            message,
            id.to_string(),
        ),
        MetaError::PreparedFrameAborted(id) => simple_status(
            Code::Aborted,
            ErrorCode::PreparedFrameAborted,
            message,
            id.to_string(),
        ),
        MetaError::InvalidArgument(_)
        | MetaError::InvalidLabels(_)
        | MetaError::EmptySelectorForbidden
        | MetaError::ProofRejected { .. }
        | MetaError::MemPromotionRequired { .. }
        | MetaError::StaleBoot { .. }
        | MetaError::FrameWrongState { .. } => {
            simple_status(Code::InvalidArgument, ErrorCode::InvalidArgument, message, "")
        }
        MetaError::SameFilesystemForbidden { .. }
        | MetaError::PoolLocked { .. }
        | MetaError::MissingMetaForNonEmptyPool { .. }
        | MetaError::MetaUnreadable { .. }
        | MetaError::PoolUuidMismatch { .. }
        | MetaError::UnsupportedSchema { .. }
        | MetaError::MalformedPoolUuid(_)
        | MetaError::EpochOverflow
        | MetaError::Hook { .. }
        | MetaError::OrphanCircuitBreakerTriggered { .. }
        | MetaError::MissingCommittedObject { .. }
        | MetaError::Io { .. }
        | MetaError::Db(_)
        | MetaError::Codec(_) => {
            simple_status(Code::Internal, ErrorCode::Internal, message, "")
        }
    }
}

/// Errors returned by [`crate::backend::TreeBackend`] and [`crate::backend::SandboxBackend`].
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    /// Unsafe patch rejected by `PatchPathValidator`.
    #[error("unsafe patch rejected: {0}")]
    UnsafePatch(String),
    /// Driver is not enabled or unavailable on this host.
    #[error("driver unavailable: {0}")]
    DriverUnavailable(String),
    /// Disk/tmpfs quota exhausted.
    #[error("resource exhausted: {0}")]
    ResourceExhausted(String),
    /// Invalid caller input (malformed tar, empty argv, etc.).
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Target world session not found in runtime driver.
    #[error("world session not running: {0}")]
    WorldNotRunning(WorldId),
    /// Underlying I/O or internal backend failure.
    #[error("backend error: {0}")]
    Internal(String),
}

impl From<BackendError> for Status {
    fn from(err: BackendError) -> Self {
        let msg = err.to_string();
        match err {
            BackendError::UnsafePatch(_) => {
                simple_status(Code::InvalidArgument, ErrorCode::UnsafePatch, msg, "")
            }
            BackendError::DriverUnavailable(_) => {
                simple_status(Code::Unimplemented, ErrorCode::DriverUnavailable, msg, "")
            }
            BackendError::ResourceExhausted(_) => {
                simple_status(Code::ResourceExhausted, ErrorCode::ResourceExhausted, msg, "")
            }
            BackendError::InvalidArgument(_) => {
                simple_status(Code::InvalidArgument, ErrorCode::InvalidArgument, msg, "")
            }
            BackendError::WorldNotRunning(id) => {
                simple_status(Code::FailedPrecondition, ErrorCode::WorldNotRunning, msg, id.to_string())
            }
            BackendError::Internal(_) => {
                simple_status(Code::Internal, ErrorCode::Internal, msg, "")
            }
        }
    }
}
