//! Error types for `aos-gw`.

use std::net::IpAddr;
use std::path::PathBuf;

use aos_types::{EpochId, WorldId};
use thiserror::Error;

use crate::reflection::EncodingVariant;

/// Result alias for gateway operations.
pub type Result<T> = std::result::Result<T, GwError>;

/// Unified error type for `aos-gw`.
///
/// None of these variants ever embed raw secret values.
#[derive(Debug, Error)]
pub enum GwError {
    /// Invalid policy, route, header, or secret configuration.
    #[error("invalid policy configuration: {0}")]
    InvalidPolicy(String),

    /// Invalid slot identifier.
    #[error("invalid slot id: {0}")]
    InvalidSlotId(String),

    /// Attempted to advance the gateway epoch backwards.
    #[error("epoch regression: requested {requested}, current is {current}")]
    EpochRegression {
        /// Requested epoch.
        requested: EpochId,
        /// Current gateway epoch.
        current: EpochId,
    },

    /// Binding or request references an epoch older than the current gateway epoch.
    #[error("stale epoch: binding epoch {provided} < current epoch {current}")]
    StaleEpoch {
        /// Epoch presented by the binding or caller.
        provided: EpochId,
        /// Current gateway epoch.
        current: EpochId,
    },

    /// Binding references an epoch ahead of the current gateway epoch.
    #[error("future epoch: binding epoch {provided} > current epoch {current}")]
    FutureEpoch {
        /// Epoch presented by the binding.
        provided: EpochId,
        /// Current gateway epoch.
        current: EpochId,
    },

    /// Slot is already registered to an active binding.
    #[error("duplicate active slot registration: {slot_id}")]
    DuplicateSlot {
        /// Conflicting slot identifier.
        slot_id: String,
    },

    /// No active binding matches `(slot_id, world_id, epoch)`.
    #[error("binding not found or revoked for slot {slot_id}, world {world_id}, epoch {epoch}")]
    BindingNotFound {
        /// Slot identifier.
        slot_id: String,
        /// World identifier.
        world_id: WorldId,
        /// Epoch identifier.
        epoch: EpochId,
    },

    /// Upstream target IP is blocked by the SSRF policy.
    #[error("SSRF blocked upstream IP {ip}: {reason}")]
    SsrfBlocked {
        /// Blocked IP address.
        ip: IpAddr,
        /// Why the IP was denied.
        reason: &'static str,
    },

    /// Multi-tenant shared CDN domain is forbidden for L3 blind passthrough.
    #[error("multi-tenant shared CDN domain forbidden for L3 passthrough: {domain}")]
    SharedCdnForbidden {
        /// Rejected domain or wildcard pattern.
        domain: String,
    },

    /// Invalid domain name or allowlist pattern.
    #[error("invalid domain pattern {pattern:?}: {reason}")]
    InvalidDomain {
        /// Offending domain or pattern.
        pattern: String,
        /// Reason for rejection.
        reason: &'static str,
    },

    /// Invalid DNS wire-format query.
    #[error("invalid DNS wire packet: {0}")]
    InvalidDnsPacket(&'static str),

    /// Upstream response reflected a registered secret (never contains the secret bytes).
    #[error("secret reflection detected for label {label:?} via {variant:?} encoding")]
    SecretReflected {
        /// Non-secret identifier of the matched credential.
        label: String,
        /// Encoding variant that matched.
        variant: EncodingVariant,
    },

    /// Per-world audit key slot has been crypto-shredded or does not exist.
    #[error("audit key slot missing or crypto-shredded for world {world_id}")]
    AuditKeyMissing {
        /// World whose key slot could not be loaded.
        world_id: WorldId,
    },

    /// Audit key slot file is corrupt or fails integrity check.
    #[error("corrupt audit key slot at {path}: {reason}")]
    AuditKeyCorrupt {
        /// Key slot path.
        path: PathBuf,
        /// Failure detail.
        reason: String,
    },

    /// Audit segment or hash chain integrity violation.
    #[error("audit chain verification failed for world {world_id} at segment {seq}: {reason}")]
    AuditChainTampered {
        /// World whose audit log failed verification.
        world_id: WorldId,
        /// Segment sequence number where tampering was detected.
        seq: u64,
        /// Human-readable reason.
        reason: String,
    },

    /// Cryptographic AEAD operation failed.
    #[error("AEAD cryptographic failure: {0}")]
    Crypto(String),

    /// OS CSPRNG failed.
    #[error("OS CSPRNG failure: {0}")]
    Entropy(String),

    /// JSON serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Filesystem or network I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
