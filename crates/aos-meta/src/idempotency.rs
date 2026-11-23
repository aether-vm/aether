//! Idempotency protocol: `(owner, request_id)` + SHA-256 digest of the canonical request.
//!
//! The record is written in the **same** `redb` transaction as the effect it describes, so a
//! replay after any crash either finds the original response or finds nothing (and the effect
//! never happened).

use aos_types::{FrameId, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::{MetaError, Result};
use crate::model::{IdempotencyKey, validate_name};
use crate::store::{CommittedFrame, DeleteOutcome, PreparedFrame, TimelineAdvance};

/// Response persisted with the idempotency record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum IdemResponse {
    Prepared(PreparedFrame),
    Committed(CommittedFrame),
    Deleted(DeleteOutcome),
    TimelineAdvanced(TimelineAdvance),
    TimelineDeleted(FrameId),
    /// `create_world` / `destroy_world`: replays return the world's *current* record.
    World(WorldId),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct IdempotencyRecord {
    pub op: String,
    pub digest_hex: String,
    pub response: IdemResponse,
    pub recorded_at_ms: u64,
    /// Set for `prepare_frame`: if recovery rolls the frame back the record is dropped too, so a
    /// retry re-runs the whole protocol instead of returning a dead frame id.
    pub prepared_frame: Option<FrameId>,
}

/// SHA-256 of `op \0 canonical-JSON(request)` (maps are `BTreeMap`s, so the encoding is
/// deterministic).
pub(crate) fn request_digest<T: Serialize>(op: &str, req: &T) -> Result<[u8; 32]> {
    let mut buf = Vec::with_capacity(op.len() + 1 + 256);
    buf.extend_from_slice(op.as_bytes());
    buf.push(0);
    serde_json::to_writer(&mut buf, req)?;
    Ok(crate::digest::sha256(&buf))
}

pub(crate) fn validate_key(key: &IdempotencyKey, request_owner: &str) -> Result<()> {
    validate_name("idempotency owner", &key.owner)?;
    validate_name("request id", &key.request_id)?;
    if key.owner != request_owner {
        return Err(MetaError::OwnerMismatch {
            resource: format!("idempotency key {:?}", key.request_id),
            caller: request_owner.to_owned(),
        });
    }
    Ok(())
}

/// `Some(response)` for an exact replay, `Err(IdempotencyConflict)` for a reused key.
pub(crate) fn check_replay(
    existing: Option<IdempotencyRecord>,
    key: &IdempotencyKey,
    op: &str,
    digest: &[u8; 32],
) -> Result<Option<IdemResponse>> {
    match existing {
        None => Ok(None),
        Some(rec) if rec.op == op && rec.digest_hex == hex(digest) => Ok(Some(rec.response)),
        Some(_) => Err(MetaError::IdempotencyConflict {
            owner: key.owner.clone(),
            request_id: key.request_id.clone(),
        }),
    }
}

pub(crate) fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
