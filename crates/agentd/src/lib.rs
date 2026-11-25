//! `agentd`: Forkloom single-host control-plane daemon.
//!
//! Exposes `forkloom.v1` (`SystemService`, `FrameService`, `WorldService`) strictly over a
//! permission-hardened (`0600`) Unix Domain Socket (never default-open TCP), wired to
//! `aos-meta`'s single-writer `redb` commit point and pluggable `TreeBackend` / `SandboxBackend`
//! traits for Phase 1 `aos-store` and `aos-sandbox` integration.

#![forbid(unsafe_code)]

pub mod backend;
pub mod error;
pub mod service;
pub mod transport;

/// Generated `forkloom.v1` protobuf and gRPC service/client definitions.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod proto {
    tonic::include_proto!("forkloom.v1");
}

/// Current daemon API major version (`forkloom.v1`).
pub const API_MAJOR: u32 = 1;
/// Current daemon API minor version.
pub const API_MINOR: u32 = 1;
