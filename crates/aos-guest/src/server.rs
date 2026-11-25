//! Protocol dispatcher, `GuestBackend` trait, and reconnect-safe server loop.
//!
//! All control flow, validation, state transitions, and framing live here with
//! `#![forbid(unsafe_code)]`, making the entire agent logic unit-testable on any host OS.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::cgroup::validate_exec_id;
use crate::codec::{CodecError, FrameCodec};
use crate::protocol::{
    BoundedOutput, BytesPayload, DEFAULT_FREEZE_TIMEOUT_MS, DEFAULT_MAX_OUTPUT_BYTES,
    DEFAULT_STREAM_CHUNK_BYTES, ErrorCode, GuestRequest, GuestResponse, OutputStream,
    PROTOCOL_VERSION, RESEED_ENTROPY_LEN, RequestEnvelope, ResponseEnvelope,
};
use crate::state::AgentStateMachine;

/// Validated parameters handed to [`GuestBackend::run_exec`].
#[derive(Debug, Clone)]
pub struct ExecSpec {
    pub exec_id: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub timeout: Option<Duration>,
    pub max_output_bytes: usize,
    pub stream_chunk_bytes: usize,
    /// Return as soon as the command has started, with neither exit code nor output.
    pub detached: bool,
}

/// Outcome returned by [`GuestBackend::run_exec`].
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub cgroup_killed: bool,
    pub duration: Duration,
    pub stdout: BoundedOutput,
    pub stderr: BoundedOutput,
}

/// Outcome returned by [`GuestBackend::sync_filesystems`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOutcome {
    pub synced_paths: usize,
    pub elapsed: Duration,
}

/// Outcome returned by [`GuestBackend::kill_external_tcp`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SocketKillReport {
    pub killed_tcp_sockets: u64,
    pub preserved_loopback_sockets: u64,
}

/// Errors produced by a [`GuestBackend`] implementation.
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackendError {
    pub code: ErrorCode,
    pub message: String,
}

impl BackendError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Hard cap on per-chunk read buffer allocation regardless of `max_frame_bytes`.
pub const HARD_MAX_STREAM_CHUNK_BYTES: usize = 256 * 1024;

/// Conservative JSON envelope overhead reserved for an `OutputChunk` frame.
const OUTPUT_CHUNK_JSON_OVERHEAD: usize = 512;

/// Conservative JSON envelope overhead reserved for an `ExecResult` frame.
const EXEC_RESULT_JSON_OVERHEAD: usize = 1024;

/// Maximum raw byte size of a single `OutputChunk` that is guaranteed to fit inside
/// `max_frame_bytes` after 4/3x Base64 expansion + JSON envelope overhead.
pub fn max_allowed_stream_chunk_bytes(max_frame_bytes: usize) -> usize {
    let b64_budget = max_frame_bytes.saturating_sub(OUTPUT_CHUNK_JSON_OVERHEAD);
    ((b64_budget / 4) * 3).min(HARD_MAX_STREAM_CHUNK_BYTES)
}

/// Maximum per-stream retained output bytes (`stdout` and `stderr` each) guaranteed
/// to fit inside a single `ExecResult` frame after 4/3x Base64 expansion + JSON overhead.
pub fn max_allowed_output_bytes(max_frame_bytes: usize) -> usize {
    let b64_budget_per_stream = max_frame_bytes.saturating_sub(EXEC_RESULT_JSON_OVERHEAD) / 2;
    (b64_budget_per_stream / 4) * 3
}

/// Platform abstraction implemented by `LinuxGuestBackend` on Linux and mock/test
/// backends in cross-platform unit tests.
pub trait GuestBackend {
    fn run_exec(
        &self,
        spec: ExecSpec,
        on_chunk: &mut dyn FnMut(OutputStream, &[u8]) -> io::Result<()>,
    ) -> Result<ExecOutcome, BackendError>;

    fn run_pre_freeze_hook(&self, argv: &[String], timeout: Duration) -> Result<(), BackendError>;

    fn freeze_workload(&self, timeout: Duration) -> Result<Duration, BackendError>;

    fn unfreeze_workload(&self, timeout: Duration) -> Result<Duration, BackendError>;

    fn sync_filesystems(&self, paths: &[String]) -> Result<SyncOutcome, BackendError>;

    fn reseed_entropy(&self, entropy: &[u8; RESEED_ENTROPY_LEN]) -> Result<(), BackendError>;

    fn sync_clock_realtime(&self, secs: i64, nanos: u32) -> Result<(), BackendError>;

    fn kill_external_tcp(&self) -> Result<SocketKillReport, BackendError>;
}

/// Summary returned when a transport connection closes cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionStats {
    pub requests_handled: u64,
}

/// Stateful `aos-guest` protocol server.
///
/// Designed to survive transport disconnects across Firecracker snapshot/restore:
/// state (`Ready` / `Frozen` / `epoch_generation`) lives on `AgentServer` across
/// successive `serve_connection` calls.
pub struct AgentServer<B: GuestBackend> {
    backend: B,
    state: AgentStateMachine,
    codec: FrameCodec,
    started_at: Instant,
    pid: u32,
}

impl<B: GuestBackend> AgentServer<B> {
    pub fn new(backend: B) -> Self {
        Self::with_codec(backend, FrameCodec::default())
    }

    pub fn with_codec(backend: B, codec: FrameCodec) -> Self {
        Self {
            backend,
            state: AgentStateMachine::new(),
            codec,
            started_at: Instant::now(),
            pid: std::process::id(),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    pub fn state_machine(&self) -> &AgentStateMachine {
        &self.state
    }

    /// Serve framed requests on one transport stream until clean EOF.
    pub fn serve_connection<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<ConnectionStats, CodecError> {
        let mut handled = 0u64;
        while let Some(req) = self.codec.read_frame::<R, RequestEnvelope>(reader)? {
            self.handle_request(req, writer)?;
            handled += 1;
        }
        Ok(ConnectionStats {
            requests_handled: handled,
        })
    }

    /// Dispatch one decoded [`RequestEnvelope`] and write all resulting response frames.
    pub fn handle_request<W: Write>(
        &mut self,
        req: RequestEnvelope,
        writer: &mut W,
    ) -> Result<(), CodecError> {
        let req_id = req.req_id;
        if req.protocol_version != PROTOCOL_VERSION {
            let err = GuestResponse::Error {
                code: ErrorCode::UnsupportedProtocolVersion,
                message: format!(
                    "unsupported protocol_version {}, expected {PROTOCOL_VERSION}",
                    req.protocol_version
                ),
            };
            return self
                .codec
                .write_frame(writer, &ResponseEnvelope::new(req_id, err));
        }

        match req.payload {
            GuestRequest::Ping { nonce } => {
                let resp = GuestResponse::Pong {
                    nonce,
                    state: self.state.state(),
                    uptime_ms: self.started_at.elapsed().as_millis() as u64,
                    pid: self.pid,
                    epoch_generation: self.state.epoch_generation(),
                };
                self.codec
                    .write_frame(writer, &ResponseEnvelope::new(req_id, resp))
            }

            GuestRequest::Exec {
                exec_id,
                argv,
                env,
                cwd,
                timeout_ms,
                max_output_bytes,
                stream_chunk_bytes,
                stream,
                detached,
            } => {
                if let Err(err) = self.state.ensure_exec_allowed() {
                    return self.write_error(writer, req_id, err.error_code(), err.to_string());
                }
                if let Err(err) = validate_exec_id(&exec_id) {
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::InvalidRequest,
                        err.to_string(),
                    );
                }
                if argv.is_empty() || argv[0].is_empty() {
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::InvalidRequest,
                        "exec argv must be non-empty".to_owned(),
                    );
                }

                let max_out_cap = max_allowed_output_bytes(self.codec.max_frame_bytes());
                let max_chunk_cap = max_allowed_stream_chunk_bytes(self.codec.max_frame_bytes());

                let resolved_max_output = max_output_bytes.unwrap_or(DEFAULT_MAX_OUTPUT_BYTES.min(max_out_cap));
                if resolved_max_output > max_out_cap {
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::InvalidRequest,
                        format!(
                            "max_output_bytes {resolved_max_output} exceeds frame-safe limit {max_out_cap}"
                        ),
                    );
                }

                let resolved_chunk_bytes = match stream_chunk_bytes {
                    Some(0) => {
                        return self.write_error(
                            writer,
                            req_id,
                            ErrorCode::InvalidRequest,
                            "stream_chunk_bytes must be >= 1".to_owned(),
                        );
                    }
                    Some(v) if v > max_chunk_cap => {
                        return self.write_error(
                            writer,
                            req_id,
                            ErrorCode::InvalidRequest,
                            format!(
                                "stream_chunk_bytes {v} exceeds frame-safe limit {max_chunk_cap}"
                            ),
                        );
                    }
                    Some(v) => v,
                    None => DEFAULT_STREAM_CHUNK_BYTES.min(max_chunk_cap).max(1),
                };

                let spec = ExecSpec {
                    exec_id: exec_id.clone(),
                    argv,
                    env,
                    cwd,
                    timeout: timeout_ms.map(Duration::from_millis),
                    max_output_bytes: resolved_max_output,
                    stream_chunk_bytes: resolved_chunk_bytes,
                    detached,
                };

                let codec = self.codec;
                let mut stdout_seq = 0u64;
                let mut stderr_seq = 0u64;
                let mut write_err: Option<CodecError> = None;

                let outcome = self.backend.run_exec(spec, &mut |out_stream, chunk| {
                    if !stream || chunk.is_empty() {
                        return Ok(());
                    }
                    let seq = match out_stream {
                        OutputStream::Stdout => {
                            let s = stdout_seq;
                            stdout_seq += 1;
                            s
                        }
                        OutputStream::Stderr => {
                            let s = stderr_seq;
                            stderr_seq += 1;
                            s
                        }
                    };
                    let frame = ResponseEnvelope::new(
                        req_id,
                        GuestResponse::OutputChunk {
                            exec_id: exec_id.clone(),
                            stream: out_stream,
                            seq,
                            data: BytesPayload::from(chunk),
                        },
                    );
                    if let Err(e) = codec.write_frame(writer, &frame) {
                        write_err = Some(e);
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "failed to stream output chunk",
                        ));
                    }
                    Ok(())
                });

                if let Some(e) = write_err {
                    return Err(e);
                }

                match outcome {
                    Ok(res) => {
                        let resp = GuestResponse::ExecResult {
                            exec_id,
                            exit_code: res.exit_code,
                            signal: res.signal,
                            timed_out: res.timed_out,
                            cgroup_killed: res.cgroup_killed,
                            duration_ms: res.duration.as_millis() as u64,
                            stdout: res.stdout,
                            stderr: res.stderr,
                        };
                        self.codec
                            .write_frame(writer, &ResponseEnvelope::new(req_id, resp))
                    }
                    Err(err) => self.write_error(writer, req_id, err.code, err.message),
                }
            }

            GuestRequest::FreezeAndSync {
                pre_freeze_hook,
                freeze_timeout_ms,
                sync_paths,
                perform_syncfs,
            } => {
                if let Some(hook) = &pre_freeze_hook
                    && (hook.is_empty() || hook[0].is_empty())
                {
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::InvalidRequest,
                        "pre_freeze_hook argv must be non-empty when provided".to_owned(),
                    );
                }

                if let Err(err) = self.state.begin_freeze() {
                    return self.write_error(writer, req_id, err.error_code(), err.to_string());
                }

                let timeout =
                    Duration::from_millis(freeze_timeout_ms.unwrap_or(DEFAULT_FREEZE_TIMEOUT_MS));

                // Step 1a: Optional pre_freeze hook while workload is still responsive,
                // bounded by `timeout` and confined to a sub-cgroup under aos.workload.
                if let Some(hook) = pre_freeze_hook
                    && let Err(err) = self.backend.run_pre_freeze_hook(&hook, timeout)
                {
                    // Workload was never frozen yet, so rollback to Ready is clean.
                    self.state.abort_freeze(true);
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::PreFreezeHookFailed,
                        err.message,
                    );
                }

                // Step 1b: Freeze aos.workload and poll cgroup.events for `frozen 1`.
                let frozen_elapsed = match self.backend.freeze_workload(timeout) {
                    Ok(d) => d,
                    Err(err) => {
                        let rollback_ok = self.backend.unfreeze_workload(timeout).is_ok();
                        self.state.abort_freeze(rollback_ok);
                        return self.write_error(writer, req_id, err.code, err.message);
                    }
                };

                // Step 1c: syncfs() while frozen so captured block device is disk_clean.
                let (disk_clean, syncfs_elapsed, synced_paths) = if perform_syncfs {
                    let effective_paths = if sync_paths.is_empty() {
                        vec!["/".to_owned()]
                    } else {
                        sync_paths
                    };
                    match self.backend.sync_filesystems(&effective_paths) {
                        Ok(sync_out) => (true, sync_out.elapsed, sync_out.synced_paths),
                        Err(err) => {
                            let rollback_ok = self.backend.unfreeze_workload(timeout).is_ok();
                            self.state.abort_freeze(rollback_ok);
                            return self.write_error(writer, req_id, err.code, err.message);
                        }
                    }
                } else {
                    (false, Duration::ZERO, 0)
                };

                if let Err(err) = self.state.complete_freeze(disk_clean) {
                    return self.write_error(writer, req_id, err.error_code(), err.to_string());
                }

                let resp = GuestResponse::FrozenAck {
                    disk_clean,
                    frozen_elapsed_ms: frozen_elapsed.as_millis() as u64,
                    syncfs_elapsed_ms: syncfs_elapsed.as_millis() as u64,
                    synced_paths,
                };
                self.codec
                    .write_frame(writer, &ResponseEnvelope::new(req_id, resp))
            }

            GuestRequest::PostForkReseed {
                entropy,
                wall_time_secs,
                wall_time_nanos,
                kill_external_tcp,
                unfreeze_timeout_ms,
                world_id: _,
            } => {
                // Validate payload strictly BEFORE mutating state or unfreezing workload.
                let entropy_arr: [u8; RESEED_ENTROPY_LEN] = match entropy.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        return self.write_error(
                            writer,
                            req_id,
                            ErrorCode::InvalidRequest,
                            format!(
                                "post_fork_reseed entropy must be exactly {RESEED_ENTROPY_LEN} bytes, got {}",
                                entropy.len()
                            ),
                        );
                    }
                };
                if wall_time_nanos >= 1_000_000_000 {
                    return self.write_error(
                        writer,
                        req_id,
                        ErrorCode::InvalidRequest,
                        format!("invalid wall_time_nanos {wall_time_nanos} (must be < 1_000_000_000)"),
                    );
                }

                let prev_disk_clean = match self.state.begin_reseed() {
                    Ok(dc) => dc,
                    Err(err) => {
                        return self.write_error(writer, req_id, err.error_code(), err.to_string());
                    }
                };

                // 1. Inject 64-byte host entropy + RNDRESEEDCRNG.
                if let Err(err) = self.backend.reseed_entropy(&entropy_arr) {
                    self.state.abort_reseed(Some(prev_disk_clean));
                    return self.write_error(writer, req_id, err.code, err.message);
                }

                // 2. Sync CLOCK_REALTIME.
                if let Err(err) = self
                    .backend
                    .sync_clock_realtime(wall_time_secs, wall_time_nanos)
                {
                    self.state.abort_reseed(Some(prev_disk_clean));
                    return self.write_error(writer, req_id, err.code, err.message);
                }

                // 3. Sever stale external TCP connections while preserving loopback.
                let sock_report = if kill_external_tcp {
                    match self.backend.kill_external_tcp() {
                        Ok(r) => r,
                        Err(err) => {
                            self.state.abort_reseed(Some(prev_disk_clean));
                            return self.write_error(writer, req_id, err.code, err.message);
                        }
                    }
                } else {
                    SocketKillReport::default()
                };

                // 4. Unfreeze aos.workload only after entropy, clock, and sockets are clean.
                let unfreeze_timeout =
                    Duration::from_millis(unfreeze_timeout_ms.unwrap_or(DEFAULT_FREEZE_TIMEOUT_MS));
                if let Err(err) = self.backend.unfreeze_workload(unfreeze_timeout) {
                    self.state.abort_reseed(None);
                    return self.write_error(writer, req_id, err.code, err.message);
                }

                let epoch_generation = match self.state.complete_reseed() {
                    Ok(g) => g,
                    Err(err) => {
                        return self.write_error(writer, req_id, err.error_code(), err.to_string());
                    }
                };

                let resp = GuestResponse::ReseedAck {
                    entropy_injected_bytes: RESEED_ENTROPY_LEN,
                    crng_reseeded: true,
                    clock_synced: true,
                    killed_tcp_sockets: sock_report.killed_tcp_sockets,
                    preserved_loopback_sockets: sock_report.preserved_loopback_sockets,
                    unfrozen: true,
                    epoch_generation,
                };
                self.codec
                    .write_frame(writer, &ResponseEnvelope::new(req_id, resp))
            }
        }
    }

    fn write_error<W: Write>(
        &self,
        writer: &mut W,
        req_id: u64,
        code: ErrorCode,
        message: String,
    ) -> Result<(), CodecError> {
        let resp = ResponseEnvelope::new(req_id, GuestResponse::Error { code, message });
        self.codec.write_frame(writer, &resp)
    }
}
