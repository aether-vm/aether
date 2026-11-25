//! Length-prefixed JSON protocol types for `aos-guest` over `vsock` / `socketpair`.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::base64;

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// Exact required entropy length (bytes) for [`GuestRequest::PostForkReseed`].
pub const RESEED_ENTROPY_LEN: usize = 64;

/// Default maximum retained bytes per stdout/stderr stream in [`GuestRequest::Exec`].
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Default chunk size (bytes) when streaming stdout/stderr output chunks.
pub const DEFAULT_STREAM_CHUNK_BYTES: usize = 8 * 1024;

/// Default timeout (ms) waiting for `cgroup.events` to reach `frozen 1` / `frozen 0`.
pub const DEFAULT_FREEZE_TIMEOUT_MS: u64 = 5_000;

/// Arbitrary binary payload serialized compactly as RFC 4648 Base64 in JSON.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BytesPayload(pub Vec<u8>);

impl BytesPayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for BytesPayload {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for BytesPayload {
    fn from(s: &[u8]) -> Self {
        Self(s.to_vec())
    }
}

impl fmt::Debug for BytesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesPayload({} bytes)", self.0.len())
    }
}

impl Serialize for BytesPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::encode(&self.0);
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for BytesPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let decoded = base64::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(decoded))
    }
}

/// Lifecycle state of the in-guest agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    /// Normal operational state: accepts `Ping`, `Exec`, and `FreezeAndSync`.
    Ready,
    /// Transitioning workload cgroup into frozen state and flushing dirty pages.
    Freezing,
    /// Workload cgroup is frozen (`frozen 1`); only `Ping` and `PostForkReseed` are accepted.
    Frozen {
        /// True iff `syncfs()` succeeded while frozen (per ARCHITECTURE_V2 §3.4 A6b).
        disk_clean: bool,
    },
    /// Applying post-fork entropy reseed, wall-clock sync, external socket kill, and unfreeze.
    Reseeding,
    /// Terminal unrecoverable state (e.g., failed rollback unfreeze).
    Faulted,
}

/// Output stream discriminator for `Exec` streaming chunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// Bounded head/tail output returned in [`GuestResponse::ExecResult`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundedOutput {
    /// All bytes when `!truncated`, or retained leading bytes when `truncated`.
    pub head: BytesPayload,
    /// Empty when `!truncated`, or retained trailing bytes when `truncated`.
    pub tail: BytesPayload,
    /// Total number of bytes produced by the child on this stream.
    pub total_bytes: u64,
    /// Number of middle bytes omitted between `head` and `tail` (0 if `!truncated`).
    pub omitted_bytes: u64,
    /// True iff `total_bytes` exceeded the retention budget.
    pub truncated: bool,
}

impl BoundedOutput {
    /// Render lossy UTF-8 string with an explicit truncation marker when truncated.
    pub fn render_lossy_with_marker(&self) -> String {
        if !self.truncated {
            String::from_utf8_lossy(self.head.as_slice()).into_owned()
        } else {
            let head_str = String::from_utf8_lossy(self.head.as_slice());
            let tail_str = String::from_utf8_lossy(self.tail.as_slice());
            format!(
                "{head_str}\n... [truncated {} bytes of {} total] ...\n{tail_str}",
                self.omitted_bytes, self.total_bytes
            )
        }
    }
}

/// Request envelope sent from host (`agentd` / harness) to `aos-guest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub req_id: u64,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
    pub payload: GuestRequest,
}

fn default_protocol_version() -> u32 {
    PROTOCOL_VERSION
}

fn default_true() -> bool {
    true
}

impl RequestEnvelope {
    pub fn new(req_id: u64, payload: GuestRequest) -> Self {
        Self {
            req_id,
            protocol_version: PROTOCOL_VERSION,
            payload,
        }
    }
}

/// Response envelope sent from `aos-guest` to host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub req_id: u64,
    pub protocol_version: u32,
    pub payload: GuestResponse,
}

impl ResponseEnvelope {
    pub fn new(req_id: u64, payload: GuestResponse) -> Self {
        Self {
            req_id,
            protocol_version: PROTOCOL_VERSION,
            payload,
        }
    }
}

/// Host-to-guest RPC commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestRequest {
    /// Liveness and state/generation probe.
    Ping { nonce: u64 },

    /// Run a command inside an isolated per-exec sub-cgroup with streamed/bounded output.
    Exec {
        exec_id: String,
        argv: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
        #[serde(default)]
        max_output_bytes: Option<usize>,
        #[serde(default)]
        stream_chunk_bytes: Option<usize>,
        #[serde(default)]
        stream: bool,
        /// Start the command without waiting for it; its output is discarded.
        #[serde(default)]
        detached: bool,
    },

    /// Freeze `aos.workload`, wait for `frozen 1` in `cgroup.events`, and run `syncfs()`.
    FreezeAndSync {
        #[serde(default)]
        pre_freeze_hook: Option<Vec<String>>,
        #[serde(default)]
        freeze_timeout_ms: Option<u64>,
        #[serde(default)]
        sync_paths: Vec<String>,
        #[serde(default = "default_true")]
        perform_syncfs: bool,
    },

    /// Post-fork clone hygiene: inject 64-byte entropy + `RNDRESEEDCRNG`, sync
    /// `CLOCK_REALTIME`, kill external TCP sockets (preserving loopback), and unfreeze.
    PostForkReseed {
        entropy: BytesPayload,
        wall_time_secs: i64,
        wall_time_nanos: u32,
        #[serde(default = "default_true")]
        kill_external_tcp: bool,
        #[serde(default)]
        unfreeze_timeout_ms: Option<u64>,
        #[serde(default)]
        world_id: Option<String>,
    },
}

/// Structured machine-readable error codes returned by `aos-guest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    UnsupportedProtocolVersion,
    InvalidRequest,
    InvalidStateTransition,
    AgentFrozen,
    AgentFaulted,
    ExecFailed,
    PreFreezeHookFailed,
    FreezeTimeout,
    SyncFailed,
    ReseedFailed,
    ClockSyncFailed,
    SocketKillFailed,
    UnfreezeFailed,
    Internal,
}

/// Guest-to-host RPC responses and streaming events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuestResponse {
    Pong {
        nonce: u64,
        state: AgentState,
        uptime_ms: u64,
        pid: u32,
        epoch_generation: u64,
    },

    /// Intermediate streaming output frame emitted during `Exec` when `stream == true`.
    OutputChunk {
        exec_id: String,
        stream: OutputStream,
        seq: u64,
        data: BytesPayload,
    },

    /// Terminal completion frame for `Exec`.
    ExecResult {
        exec_id: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
        timed_out: bool,
        cgroup_killed: bool,
        duration_ms: u64,
        stdout: BoundedOutput,
        stderr: BoundedOutput,
    },

    /// Acknowledgement that `aos.workload` is frozen and (if requested) flushed clean.
    FrozenAck {
        disk_clean: bool,
        frozen_elapsed_ms: u64,
        syncfs_elapsed_ms: u64,
        synced_paths: usize,
    },

    /// Acknowledgement that post-fork reseed, clock sync, socket cleanup, and unfreeze completed.
    ReseedAck {
        entropy_injected_bytes: usize,
        crng_reseeded: bool,
        clock_synced: bool,
        killed_tcp_sockets: u64,
        preserved_loopback_sockets: u64,
        unfrozen: bool,
        epoch_generation: u64,
    },

    /// Structured error response (terminal for the associated `req_id`).
    Error { code: ErrorCode, message: String },
}
