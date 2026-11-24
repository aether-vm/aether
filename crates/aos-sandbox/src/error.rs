//! Typed error definitions for `aos-sandbox`.

#![forbid(unsafe_code)]

use std::io;
use std::path::PathBuf;

use aos_guest::{CodecError, ErrorCode};
use thiserror::Error;

/// Errors returned by [`crate::SandboxDriver`] and [`crate::WorldHandle`] operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("invalid sandbox configuration: {0}")]
    InvalidConfig(String),

    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(&'static str),

    #[error("world already destroyed")]
    WorldDestroyed,

    #[error("cgroup error at {path}: {message}")]
    Cgroup { path: PathBuf, message: String },

    #[error("sandbox spawn failed at stage '{stage}': {message}")]
    SpawnFailed { stage: &'static str, message: String },

    #[error("guest handshake timed out or failed: {0}")]
    HandshakeFailed(String),

    #[error("guest transport codec error: {0}")]
    Codec(#[from] CodecError),

    #[error("guest protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("guest returned error ({code:?}): {message}")]
    GuestError { code: ErrorCode, message: String },

    #[error("sandbox I/O error: {0}")]
    Io(#[from] io::Error),
}

impl SandboxError {
    pub fn cgroup(path: impl Into<PathBuf>, err: impl ToString) -> Self {
        Self::Cgroup {
            path: path.into(),
            message: err.to_string(),
        }
    }

    pub fn spawn(stage: &'static str, err: impl ToString) -> Self {
        Self::SpawnFailed {
            stage,
            message: err.to_string(),
        }
    }
}
