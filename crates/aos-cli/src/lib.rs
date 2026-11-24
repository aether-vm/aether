//! `aos-cli`: thin Rust gRPC-over-UDS client library and CLI parser for Forkloom `agentd`.

#![forbid(unsafe_code)]

pub mod client;

/// Generated `forkloom.v1` protobuf and gRPC client stubs.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod proto {
    tonic::include_proto!("forkloom.v1");
}

/// Binary gRPC metadata key carrying protobuf-encoded `ErrorDetail`.
pub const ERROR_DETAIL_BIN_KEY: &str = "x-forkloom-error-bin";
/// Default Unix Domain Socket path matching `agentd`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/forkloom/agentd.sock";
/// Client API major version supported by this CLI.
pub const SUPPORTED_API_MAJOR: u32 = 1;
