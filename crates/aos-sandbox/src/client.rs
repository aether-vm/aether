//! Host-side framed v1 RPC client talking to `aos-guest` over any `Read` + `Write` stream.
//!
//! Used by `NamespaceDriver` over an inherited `AF_UNIX` `socketpair` (and reusable
//! by Phase 2 `FirecrackerDriver` over `virtio-vsock` UDS).

#![forbid(unsafe_code)]

use std::io::{Read, Write};

use aos_guest::{
    FrameCodec, GuestRequest, GuestResponse, PROTOCOL_VERSION, RequestEnvelope, ResponseEnvelope,
};

use crate::config::{ExecOutputChunk, ExecReply, ExecRequest, FreezeOptions, FreezeReply, PingReply};
use crate::error::SandboxError;

/// Synchronous host-to-guest RPC client speaking `aos-guest` protocol v1.
pub struct GuestRpcClient<R, W> {
    reader: R,
    writer: W,
    codec: FrameCodec,
    next_req_id: u64,
}

impl<R: Read, W: Write> GuestRpcClient<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self::with_codec(reader, writer, FrameCodec::default())
    }

    pub fn with_codec(reader: R, writer: W, codec: FrameCodec) -> Self {
        Self {
            reader,
            writer,
            codec,
            next_req_id: 1,
        }
    }

    fn alloc_req_id(&mut self) -> u64 {
        let id = self.next_req_id;
        self.next_req_id = self.next_req_id.saturating_add(1);
        id
    }

    fn send_request(&mut self, req_id: u64, payload: GuestRequest) -> Result<(), SandboxError> {
        let env = RequestEnvelope::new(req_id, payload);
        self.codec.write_frame(&mut self.writer, &env)?;
        Ok(())
    }

    fn read_response(&mut self, expected_req_id: u64) -> Result<GuestResponse, SandboxError> {
        let Some(env) = self
            .codec
            .read_frame::<R, ResponseEnvelope>(&mut self.reader)?
        else {
            return Err(SandboxError::ProtocolViolation(
                "guest transport closed unexpectedly before terminal response".to_owned(),
            ));
        };
        if env.protocol_version != PROTOCOL_VERSION {
            return Err(SandboxError::ProtocolViolation(format!(
                "unexpected guest protocol_version {}, expected {PROTOCOL_VERSION}",
                env.protocol_version
            )));
        }
        if env.req_id != expected_req_id {
            return Err(SandboxError::ProtocolViolation(format!(
                "mismatched response req_id {}, expected {expected_req_id}",
                env.req_id
            )));
        }
        Ok(env.payload)
    }

    /// Send `Ping` and verify matching `Pong`.
    pub fn ping(&mut self, nonce: u64) -> Result<PingReply, SandboxError> {
        let req_id = self.alloc_req_id();
        self.send_request(req_id, GuestRequest::Ping { nonce })?;
        match self.read_response(req_id)? {
            GuestResponse::Pong {
                nonce: got_nonce,
                state,
                uptime_ms,
                pid,
                epoch_generation,
            } => {
                if got_nonce != nonce {
                    return Err(SandboxError::ProtocolViolation(format!(
                        "pong nonce mismatch: expected {nonce}, got {got_nonce}"
                    )));
                }
                Ok(PingReply {
                    nonce: got_nonce,
                    state,
                    uptime_ms,
                    pid,
                    epoch_generation,
                })
            }
            GuestResponse::Error { code, message } => {
                Err(SandboxError::GuestError { code, message })
            }
            other => Err(SandboxError::ProtocolViolation(format!(
                "expected Pong, got {other:?}"
            ))),
        }
    }

    /// Execute a command inside the sandbox, streaming any `OutputChunk` frames
    /// to `on_chunk` until the terminal `ExecResult` arrives.
    pub fn exec_streaming<F>(
        &mut self,
        req: ExecRequest,
        mut on_chunk: F,
    ) -> Result<ExecReply, SandboxError>
    where
        F: FnMut(ExecOutputChunk),
    {
        let req_id = self.alloc_req_id();
        let expected_exec_id = req.exec_id.clone();

        self.send_request(
            req_id,
            GuestRequest::Exec {
                exec_id: req.exec_id,
                argv: req.argv,
                env: req.env,
                cwd: req.cwd,
                timeout_ms: req.timeout.map(|d| d.as_millis() as u64),
                max_output_bytes: req.max_output_bytes,
                stream_chunk_bytes: req.stream_chunk_bytes,
                stream: req.stream,
            },
        )?;

        loop {
            match self.read_response(req_id)? {
                GuestResponse::OutputChunk {
                    exec_id,
                    stream,
                    seq,
                    data,
                } => {
                    if exec_id != expected_exec_id {
                        return Err(SandboxError::ProtocolViolation(format!(
                            "OutputChunk exec_id mismatch: expected '{expected_exec_id}', got '{exec_id}'"
                        )));
                    }
                    on_chunk(ExecOutputChunk {
                        exec_id,
                        stream,
                        seq,
                        data: data.into_vec(),
                    });
                }
                GuestResponse::ExecResult {
                    exec_id,
                    exit_code,
                    signal,
                    timed_out,
                    cgroup_killed,
                    duration_ms,
                    stdout,
                    stderr,
                } => {
                    if exec_id != expected_exec_id {
                        return Err(SandboxError::ProtocolViolation(format!(
                            "ExecResult exec_id mismatch: expected '{expected_exec_id}', got '{exec_id}'"
                        )));
                    }
                    return Ok(ExecReply {
                        exec_id,
                        exit_code,
                        signal,
                        timed_out,
                        cgroup_killed,
                        duration_ms,
                        stdout,
                        stderr,
                    });
                }
                GuestResponse::Error { code, message } => {
                    return Err(SandboxError::GuestError { code, message });
                }
                other => {
                    return Err(SandboxError::ProtocolViolation(format!(
                        "unexpected response during Exec: {other:?}"
                    )));
                }
            }
        }
    }

    /// Execute a command without live chunk callbacks.
    pub fn exec(&mut self, mut req: ExecRequest) -> Result<ExecReply, SandboxError> {
        req.stream = false;
        self.exec_streaming(req, |_| {})
    }

    /// Request `FreezeAndSync` from `aos-guest`.
    pub fn freeze_and_sync(&mut self, opts: FreezeOptions) -> Result<FreezeReply, SandboxError> {
        let req_id = self.alloc_req_id();
        self.send_request(
            req_id,
            GuestRequest::FreezeAndSync {
                pre_freeze_hook: opts.pre_freeze_hook,
                freeze_timeout_ms: opts.freeze_timeout.map(|d| d.as_millis() as u64),
                sync_paths: opts.sync_paths,
                perform_syncfs: opts.perform_syncfs,
            },
        )?;
        match self.read_response(req_id)? {
            GuestResponse::FrozenAck {
                disk_clean,
                frozen_elapsed_ms,
                syncfs_elapsed_ms,
                synced_paths,
            } => Ok(FreezeReply {
                disk_clean,
                frozen_elapsed_ms,
                syncfs_elapsed_ms,
                synced_paths,
            }),
            GuestResponse::Error { code, message } => {
                Err(SandboxError::GuestError { code, message })
            }
            other => Err(SandboxError::ProtocolViolation(format!(
                "expected FrozenAck, got {other:?}"
            ))),
        }
    }
}
