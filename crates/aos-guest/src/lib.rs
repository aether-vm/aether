//! Forkloom in-guest runtime agent (`aos-guest`).
//!
//! Serves both `FirecrackerDriver` (over `AF_VSOCK`) and `NamespaceDriver` (over
//! inherited `socketpair`) with a unified length-prefixed JSON protocol supporting:
//! - [`GuestRequest::Ping`] — liveness & state/generation probe
//! - [`GuestRequest::Exec`] — per-exec sub-cgroup execution with streaming & bounded head/tail output
//! - [`GuestRequest::FreezeAndSync`] — freeze `aos.workload`, poll `cgroup.events`, `syncfs()`, return `FrozenAck { disk_clean }`
//! - [`GuestRequest::PostForkReseed`] — inject 64-byte host entropy + `RNDRESEEDCRNG`, sync `CLOCK_REALTIME`, kill external TCP sockets while preserving loopback, unfreeze `aos.workload`
//!
//! All core protocol, framing, truncation, cgroup parsing, netlink message encoding/filtering,
//! and state-machine logic is `#![forbid(unsafe_code)]` and compiles & tests cross-platform
//! (including Windows). Minimal Linux ioctls/syscalls are isolated strictly inside
//! `#[cfg(target_os = "linux")] pub mod linux_sys`.

#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![deny(unsafe_code)]

pub mod base64;
pub mod cgroup;
pub mod codec;
pub mod netlink_tcp;
pub mod protocol;
pub mod server;
pub mod state;
pub mod truncation;

#[cfg(target_os = "linux")]
pub mod linux_backend;
#[cfg(target_os = "linux")]
pub mod linux_sys;

pub use cgroup::{CgroupError, CgroupEvents, CgroupV2Controller, DEFAULT_WORKLOAD_CGROUP};
pub use codec::{CodecError, DEFAULT_MAX_FRAME_BYTES, FrameCodec};
pub use netlink_tcp::{
    InetDiagMsg, InetDiagSockId, KILLABLE_TCP_STATES_MASK, ParsedNetlinkFrame, ParsedNetlinkMsg,
    SocketAction, classify_tcp_socket, is_loopback_ip, parse_netlink_frames,
};
pub use protocol::{
    AgentState, BoundedOutput, BytesPayload, ErrorCode, GuestRequest, GuestResponse, OutputStream,
    PROTOCOL_VERSION, RESEED_ENTROPY_LEN, RequestEnvelope, ResponseEnvelope,
};
pub use server::{
    AgentServer, BackendError, ConnectionStats, ExecOutcome, ExecSpec, GuestBackend,
    HARD_MAX_STREAM_CHUNK_BYTES, SocketKillReport, SyncOutcome, max_allowed_output_bytes,
    max_allowed_stream_chunk_bytes,
};
pub use state::{AgentStateMachine, StateError};
pub use truncation::{HeadTailBuffer, drain_stream};
