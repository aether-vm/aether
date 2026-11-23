//! Shared Firecracker v1.10 / v1.11 HTTP-over-UDS schemas, client and `virtio-vsock` UDS
//! multiplexer helper implementing `aos-guest`'s v1 4-byte BE length-prefixed JSON protocol
//! (used by `F0-5`, `F0-6`, and `F0-7`).
//!
//! Verified protocol invariants (see `docs/PHASE0_FALSIFICATION.md`, `crates/aos-guest/src/protocol.rs`,
//! and Scout #7):
//! * `PUT /snapshot/load` on Firecracker v1.10/v1.11 accepts ONLY `snapshot_path`,
//!   `mem_backend: { "backend_type": "File", "backend_path": "<path>" }`,
//!   `track_dirty_pages`, and `resume_vm`. Do NOT emit `network_overrides` (v1.12+) or
//!   `vsock_override` (v1.16+); isolate concurrent clones via per-clone jailer/chroot + netns.
//! * Snapshot creation emits `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET`, dropping existing streams;
//!   guest listening `AF_VSOCK` sockets survive. Host reconnects by writing `CONNECT <port>\n`
//!   to the Firecracker vsock UDS, awaiting `OK <host_port>\n` (byte-by-byte so we never
//!   over-read into the binary frame header), and exchanging 4-byte BE length-prefixed JSON
//!   `RequestEnvelope` / `ResponseEnvelope` frames (`protocol_version = 1`).

use std::path::PathBuf;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// `aos-guest` wire protocol version (`crates/aos-guest/src/protocol.rs`).
pub const GUEST_PROTOCOL_VERSION: u32 = 1;
/// Maximum framed JSON payload size accepted from `aos-guest` (16 MiB).
pub const MAX_GUEST_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Firecracker `mem_backend` object inside `PUT /snapshot/load`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemBackend {
    /// Backend type: `"File"` (`MAP_PRIVATE` CoW on guest write) or `"Uffd"`.
    pub backend_type: String,
    /// Path to the guest memory file (or UFFD socket).
    pub backend_path: PathBuf,
}

/// Exact Firecracker v1.10 / v1.11 `PUT /snapshot/load` JSON payload.
///
/// `enable_diff_snapshots` (v1.10.x) is omitted when `false` so the payload is accepted verbatim
/// by Firecracker v1.10.1, v1.11+, and v1.12+ without version-specific unknown-field errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLoadParams {
    /// Path to `vmstate` snapshot file.
    pub snapshot_path: PathBuf,
    /// Memory backend configuration (`File` -> `MAP_PRIVATE`).
    pub mem_backend: MemBackend,
    /// Enable KVM dirty-page tracking (`enable_diff_snapshots` on v1.10.x; omitted when `false`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enable_diff_snapshots: bool,
    /// Resume vCPUs immediately on load (`true`), or leave paused (`false`).
    pub resume_vm: bool,
}

impl SnapshotLoadParams {
    /// Build a Firecracker v1.10/v1.11 `File` (`MAP_PRIVATE`) snapshot load payload.
    #[must_use]
    pub fn file_backend(
        snapshot_path: impl Into<PathBuf>,
        mem_file_path: impl Into<PathBuf>,
        enable_diff_snapshots: bool,
        resume_vm: bool,
    ) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            mem_backend: MemBackend {
                backend_type: "File".to_owned(),
                backend_path: mem_file_path.into(),
            },
            enable_diff_snapshots,
            resume_vm,
        }
    }
}

/// Firecracker `PUT /snapshot/create` JSON payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    /// `"Full"` or `"Diff"`.
    pub snapshot_type: String,
    /// Output path for `vmstate`.
    pub snapshot_path: PathBuf,
    /// Output path for memory image.
    pub mem_file_path: PathBuf,
}

impl SnapshotCreateParams {
    /// Build a full snapshot capture request.
    #[must_use]
    pub fn full(snapshot_path: impl Into<PathBuf>, mem_file_path: impl Into<PathBuf>) -> Self {
        Self {
            snapshot_type: "Full".to_owned(),
            snapshot_path: snapshot_path.into(),
            mem_file_path: mem_file_path.into(),
        }
    }
}

/// Firecracker `PATCH /vm` payload (`"Paused"` / `"Resumed"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmStatePatch {
    /// Target state (`"Paused"` or `"Resumed"`).
    pub state: &'static str,
}

/// Build an HTTP/1.1 request over the Firecracker API Unix socket.
#[must_use]
pub fn format_http_request(method: &str, path: &str, body: &str) -> String {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Parse the status code and body from a raw HTTP/1.1 response string.
pub fn parse_http_response(raw: &str) -> Result<(u16, String)> {
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .ok_or_else(|| anyhow!("malformed HTTP response (missing header separator): {raw:?}"))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty HTTP response"))?;
    let code_str = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("malformed HTTP status line: {status_line:?}"))?;
    let code: u16 = code_str
        .parse()
        .with_context(|| format!("invalid HTTP status code: {code_str:?}"))?;
    Ok((code, body.trim().to_owned()))
}

/// Encode a JSON payload using `aos-guest`'s 4-byte big-endian length-prefixed wire framing.
pub fn encode_framed_json(json_bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(!json_bytes.is_empty(), "guest frame must be non-empty");
    ensure!(
        json_bytes.len() <= MAX_GUEST_FRAME_BYTES,
        "guest frame {} bytes exceeds limit {}",
        json_bytes.len(),
        MAX_GUEST_FRAME_BYTES
    );
    let len = u32::try_from(json_bytes.len()).context("frame length overflows u32")?;
    let mut out = Vec::with_capacity(4 + json_bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(json_bytes);
    Ok(out)
}

/// Decode one 4-byte big-endian length-prefixed JSON frame from `buf`, returning `(payload, consumed)`.
pub fn decode_framed_json(buf: &[u8]) -> Result<(&[u8], usize)> {
    ensure!(buf.len() >= 4, "truncated frame header ({} bytes)", buf.len());
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    ensure!(len > 0, "zero-length guest frame rejected");
    ensure!(
        len <= MAX_GUEST_FRAME_BYTES,
        "guest frame length {len} exceeds limit {MAX_GUEST_FRAME_BYTES}"
    );
    ensure!(
        buf.len() >= 4 + len,
        "truncated guest frame body (have {}, need {})",
        buf.len() - 4,
        len
    );
    Ok((&buf[4..4 + len], 4 + len))
}

/// Format the Firecracker host-to-guest vsock UDS connect handshake line.
#[must_use]
pub fn format_vsock_connect(guest_port: u32) -> String {
    format!("CONNECT {guest_port}\n")
}

/// Parse Firecracker's `OK <host_port>\n` vsock handshake acknowledgement.
pub fn parse_vsock_ok_line(line: &str) -> Result<u32> {
    let trimmed = line.trim();
    let rest = trimmed
        .strip_prefix("OK ")
        .ok_or_else(|| anyhow!("unexpected vsock handshake response: {trimmed:?}"))?;
    let port: u32 = rest
        .parse()
        .with_context(|| format!("invalid host port in vsock OK response: {trimmed:?}"))?;
    ensure!(port > 0, "vsock OK host port must be non-zero");
    Ok(port)
}

// -----------------------------------------------------------------------------
// RFC 4648 standard Base64 (matching `crates/aos-guest/src/base64.rs`)
// -----------------------------------------------------------------------------

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard RFC 4648 Base64 with `=` padding.
#[must_use]
pub fn b64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decode standard RFC 4648 Base64 with `=` padding.
pub fn b64_decode(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    ensure!(bytes.len().is_multiple_of(4), "base64 length must be a multiple of 4");
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for (ci, chunk) in bytes.chunks_exact(4).enumerate() {
        let is_last = (ci + 1) * 4 == bytes.len();
        let v0 = b64_val(chunk[0])?;
        let v1 = b64_val(chunk[1])?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        ensure!(!pad2 || pad3, "invalid base64 padding");
        ensure!((!pad2 && !pad3) || is_last, "base64 padding in non-final block");
        let v2 = if pad2 { 0 } else { b64_val(chunk[2])? };
        let v3 = if pad3 { 0 } else { b64_val(chunk[3])? };
        let triple = (u32::from(v0) << 18)
            | (u32::from(v1) << 12)
            | (u32::from(v2) << 6)
            | u32::from(v3);
        out.push(((triple >> 16) & 0xff) as u8);
        if !pad2 {
            out.push(((triple >> 8) & 0xff) as u8);
        }
        if !pad3 {
            out.push((triple & 0xff) as u8);
        }
    }
    Ok(out)
}

fn b64_val(b: u8) -> Result<u8> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => anyhow::bail!("invalid base64 byte 0x{b:02x}"),
    }
}

// -----------------------------------------------------------------------------
// `aos-guest` v1 `RequestEnvelope` / `ResponseEnvelope` builders & parsers
// -----------------------------------------------------------------------------

/// Build an `aos-guest` v1 `Ping` request JSON payload.
pub fn guest_ping_request(req_id: u64, nonce: u64) -> Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "req_id": req_id,
        "protocol_version": GUEST_PROTOCOL_VERSION,
        "payload": {
            "type": "ping",
            "nonce": nonce,
        }
    }))
    .context("serialize aos-guest Ping request")
}

/// Build an `aos-guest` v1 `PostForkReseed` request JSON payload (exact 64-byte entropy).
pub fn guest_post_fork_reseed_request(
    req_id: u64,
    entropy_64b: &[u8; 64],
    wall_time_secs: i64,
    wall_time_nanos: u32,
    kill_external_tcp: bool,
    world_id: Option<&str>,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "req_id": req_id,
        "protocol_version": GUEST_PROTOCOL_VERSION,
        "payload": {
            "type": "post_fork_reseed",
            "entropy": b64_encode(entropy_64b),
            "wall_time_secs": wall_time_secs,
            "wall_time_nanos": wall_time_nanos,
            "kill_external_tcp": kill_external_tcp,
            "world_id": world_id,
        }
    }))
    .context("serialize aos-guest PostForkReseed request")
}

/// Build an `aos-guest` v1 non-streaming `Exec` request JSON payload.
pub fn guest_exec_request(
    req_id: u64,
    exec_id: &str,
    argv: &[String],
    timeout_ms: u64,
) -> Result<Vec<u8>> {
    ensure!(!argv.is_empty(), "guest_exec_request requires non-empty argv");
    serde_json::to_vec(&json!({
        "req_id": req_id,
        "protocol_version": GUEST_PROTOCOL_VERSION,
        "payload": {
            "type": "exec",
            "exec_id": exec_id,
            "argv": argv,
            "timeout_ms": timeout_ms,
            "stream": false,
        }
    }))
    .context("serialize aos-guest Exec request")
}

/// Parsed `aos-guest` `Pong` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPong {
    pub req_id: u64,
    pub nonce: u64,
    pub pid: u32,
    pub epoch_generation: u64,
    pub state_json: String,
}

/// Parse and validate an `aos-guest` `ResponseEnvelope` containing `Pong`.
pub fn parse_guest_pong(resp_bytes: &[u8], expected_req_id: u64, expected_nonce: u64) -> Result<GuestPong> {
    let env: Value = serde_json::from_slice(resp_bytes).context("parse aos-guest ResponseEnvelope")?;
    check_envelope_ok(&env, expected_req_id, "pong")?;
    let p = &env["payload"];
    let nonce = p["nonce"].as_u64().context("pong missing nonce")?;
    ensure!(nonce == expected_nonce, "pong nonce mismatch: got {nonce}, expected {expected_nonce}");
    Ok(GuestPong {
        req_id: expected_req_id,
        nonce,
        pid: u32::try_from(p["pid"].as_u64().context("pong missing pid")?)?,
        epoch_generation: p["epoch_generation"].as_u64().unwrap_or(0),
        state_json: p["state"].to_string(),
    })
}

/// Parsed `aos-guest` `ReseedAck` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestReseedAck {
    pub entropy_injected_bytes: usize,
    pub crng_reseeded: bool,
    pub clock_synced: bool,
    pub killed_tcp_sockets: u64,
    pub preserved_loopback_sockets: u64,
    pub unfrozen: bool,
    pub epoch_generation: u64,
}

/// Parse and validate an `aos-guest` `ResponseEnvelope` containing `ReseedAck`.
pub fn parse_guest_reseed_ack(resp_bytes: &[u8], expected_req_id: u64) -> Result<GuestReseedAck> {
    let env: Value = serde_json::from_slice(resp_bytes).context("parse aos-guest ResponseEnvelope")?;
    check_envelope_ok(&env, expected_req_id, "reseed_ack")?;
    let p = &env["payload"];
    Ok(GuestReseedAck {
        entropy_injected_bytes: usize::try_from(
            p["entropy_injected_bytes"]
                .as_u64()
                .context("reseed_ack missing entropy_injected_bytes")?,
        )?,
        crng_reseeded: p["crng_reseeded"].as_bool().unwrap_or(false),
        clock_synced: p["clock_synced"].as_bool().unwrap_or(false),
        killed_tcp_sockets: p["killed_tcp_sockets"].as_u64().unwrap_or(0),
        preserved_loopback_sockets: p["preserved_loopback_sockets"].as_u64().unwrap_or(0),
        unfrozen: p["unfrozen"].as_bool().unwrap_or(false),
        epoch_generation: p["epoch_generation"].as_u64().unwrap_or(0),
    })
}

/// Parsed `aos-guest` `ExecResult` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExecResult {
    pub exec_id: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ms: u64,
}

/// Parse and validate an `aos-guest` `ResponseEnvelope` containing `ExecResult`.
pub fn parse_guest_exec_result(resp_bytes: &[u8], expected_req_id: u64) -> Result<GuestExecResult> {
    let env: Value = serde_json::from_slice(resp_bytes).context("parse aos-guest ResponseEnvelope")?;
    check_envelope_ok(&env, expected_req_id, "exec_result")?;
    let p = &env["payload"];
    let stdout_b64 = p["stdout"]["head"].as_str().unwrap_or("");
    let stderr_b64 = p["stderr"]["head"].as_str().unwrap_or("");
    Ok(GuestExecResult {
        exec_id: p["exec_id"].as_str().unwrap_or("").to_owned(),
        exit_code: p["exit_code"].as_i64().and_then(|v| i32::try_from(v).ok()),
        timed_out: p["timed_out"].as_bool().unwrap_or(false),
        stdout: b64_decode(stdout_b64).context("decode exec stdout base64")?,
        stderr: b64_decode(stderr_b64).context("decode exec stderr base64")?,
        duration_ms: p["duration_ms"].as_u64().unwrap_or(0),
    })
}

fn check_envelope_ok(env: &Value, expected_req_id: u64, expected_type: &str) -> Result<()> {
    let proto = env["protocol_version"]
        .as_u64()
        .context("response missing protocol_version")?;
    ensure!(
        proto == u64::from(GUEST_PROTOCOL_VERSION),
        "unsupported guest protocol_version {proto}"
    );
    let req_id = env["req_id"].as_u64().context("response missing req_id")?;
    ensure!(
        req_id == expected_req_id,
        "guest response req_id mismatch: got {req_id}, expected {expected_req_id}"
    );
    let ty = env["payload"]["type"]
        .as_str()
        .context("response payload missing type")?;
    if ty == "error" {
        let code = env["payload"]["code"].as_str().unwrap_or("unknown");
        let msg = env["payload"]["message"].as_str().unwrap_or("");
        anyhow::bail!("aos-guest returned error [{code}]: {msg}");
    }
    ensure!(
        ty == expected_type,
        "unexpected aos-guest response type {ty:?}, expected {expected_type:?}"
    );
    Ok(())
}

/// Linux-only Firecracker process, HTTP-over-UDS client, and `aos-guest` framed vsock driver.
#[cfg(target_os = "linux")]
pub mod linux {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use anyhow::bail;

    use super::*;

    /// RAII handle to a spawned `firecracker` process; guarantees kill+reap on drop.
    pub struct FcProcess {
        child: Child,
        /// Path to the Firecracker API UDS.
        pub api_sock: PathBuf,
    }

    impl FcProcess {
        /// Spawn a fresh `firecracker --api-sock <api_sock>` process inside `work_dir`.
        ///
        /// Redirects `stderr` to `<work_dir>/firecracker.stderr.log` (never an unread pipe,
        /// avoiding 64 KiB pipe deadlocks).
        pub fn spawn(
            firecracker_bin: &Path,
            api_sock: &Path,
            work_dir: &Path,
            startup_timeout: Duration,
        ) -> Result<Self> {
            Self::spawn_in_netns(firecracker_bin, api_sock, work_dir, None, startup_timeout)
        }

        /// Spawn a fresh `firecracker --api-sock <api_sock>` optionally inside a Linux `ip netns`
        /// (needed on Firecracker v1.10/v1.11 so concurrent clones with snapshot-baked TAP names
        /// do not collide on `host_dev_name`).
        pub fn spawn_in_netns(
            firecracker_bin: &Path,
            api_sock: &Path,
            work_dir: &Path,
            netns: Option<&str>,
            startup_timeout: Duration,
        ) -> Result<Self> {
            let _ = std::fs::remove_file(api_sock);
            std::fs::create_dir_all(work_dir)
                .with_context(|| format!("create work dir {}", work_dir.display()))?;
            let stderr_stdio = File::create(work_dir.join("firecracker.stderr.log"))
                .map(Stdio::from)
                .unwrap_or_else(|_| Stdio::null());
            let mut cmd = if let Some(ns) = netns {
                let mut c = Command::new("ip");
                c.args(["netns", "exec", ns]).arg(firecracker_bin);
                c
            } else {
                Command::new(firecracker_bin)
            };
            let child = cmd
                .arg("--api-sock")
                .arg(api_sock)
                .current_dir(work_dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(stderr_stdio)
                .spawn()
                .with_context(|| format!("spawn {}", firecracker_bin.display()))?;
            let proc_guard = Self {
                child,
                api_sock: api_sock.to_path_buf(),
            };
            wait_for_unix_socket(api_sock, startup_timeout)?;
            Ok(proc_guard)
        }

        /// OS PID of the Firecracker VMM process.
        #[must_use]
        pub fn pid(&self) -> u32 {
            self.child.id()
        }

        /// Terminate and reap the Firecracker process explicitly.
        pub fn kill_and_wait(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_file(&self.api_sock);
        }
    }

    impl Drop for FcProcess {
        fn drop(&mut self) {
            self.kill_and_wait();
        }
    }

    /// Wait until a Unix domain socket accepts a connection.
    pub fn wait_for_unix_socket(path: &Path, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if path.exists() && UnixStream::connect(path).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for Unix socket {}", path.display());
            }
            sleep(Duration::from_millis(5));
        }
    }

    /// Minimal HTTP/1.1 client over Firecracker's API Unix socket.
    #[derive(Debug, Clone)]
    pub struct FcClient {
        api_sock: PathBuf,
        timeout: Duration,
    }

    impl FcClient {
        /// Create a client targeting `api_sock`.
        #[must_use]
        pub fn new(api_sock: impl Into<PathBuf>) -> Self {
            Self {
                api_sock: api_sock.into(),
                timeout: Duration::from_secs(30),
            }
        }

        /// Send a JSON `PUT` or `PATCH` request and assert a `2xx` response.
        ///
        /// Firecracker's `micro_http` server keeps HTTP/1.1 connections open even when
        /// `Connection: close` is sent, so we parse headers up to `\r\n\r\n` and read exact
        /// `Content-Length` bytes (0 for `204 No Content`) instead of waiting for EOF.
        pub fn request_json<T: Serialize>(&self, method: &str, path: &str, payload: &T) -> Result<()> {
            let body = serde_json::to_string(payload)?;
            let req = format_http_request(method, path, &body);
            let mut stream = UnixStream::connect(&self.api_sock)
                .with_context(|| format!("connect Firecracker API {}", self.api_sock.display()))?;
            stream.set_read_timeout(Some(self.timeout))?;
            stream.set_write_timeout(Some(self.timeout))?;
            stream.write_all(req.as_bytes())?;
            stream.flush()?;

            let (code, resp_body) = read_http_response(&mut stream)
                .with_context(|| format!("read Firecracker {method} {path} HTTP response"))?;
            ensure!(
                (200..300).contains(&code),
                "Firecracker {method} {path} returned HTTP {code}: {resp_body}"
            );
            Ok(())
        }

        /// `PUT /snapshot/load` (v1.10/v1.11 schema).
        pub fn load_snapshot(&self, params: &SnapshotLoadParams) -> Result<()> {
            self.request_json("PUT", "/snapshot/load", params)
        }

        /// `PUT /snapshot/create`.
        pub fn create_snapshot(&self, params: &SnapshotCreateParams) -> Result<()> {
            self.request_json("PUT", "/snapshot/create", params)
        }

        /// `PATCH /vm {"state":"Paused"}`.
        pub fn pause_vm(&self) -> Result<()> {
            self.request_json("PATCH", "/vm", &VmStatePatch { state: "Paused" })
        }

        /// `PATCH /vm {"state":"Resumed"}`.
        pub fn resume_vm(&self) -> Result<()> {
            self.request_json("PATCH", "/vm", &VmStatePatch { state: "Resumed" })
        }
    }

    fn read_http_response(stream: &mut UnixStream) -> Result<(u16, String)> {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let n = stream.read(&mut chunk)?;
            ensure!(n > 0, "EOF before end of HTTP response headers");
            buf.extend_from_slice(&chunk[..n]);
            ensure!(buf.len() <= 64 * 1024, "HTTP response headers exceed 64 KiB");
        };

        let head = std::str::from_utf8(&buf[..header_end - 4])
            .context("non-UTF8 HTTP response headers")?;
        let status_line = head
            .lines()
            .next()
            .ok_or_else(|| anyhow!("empty HTTP response"))?;
        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow!("malformed HTTP status line: {status_line:?}"))?
            .parse()
            .with_context(|| format!("invalid HTTP status code in {status_line:?}"))?;

        let content_length: usize = head
            .lines()
            .skip(1)
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        let mut body = buf[header_end..].to_vec();
        if code != 204 && content_length > body.len() {
            let need = content_length - body.len();
            let mut rest = vec![0u8; need];
            stream.read_exact(&mut rest)?;
            body.extend_from_slice(&rest);
        }
        body.truncate(content_length);
        Ok((code, String::from_utf8_lossy(&body).trim().to_owned()))
    }

    /// Connect to `aos-guest` over Firecracker's host `virtio-vsock` UDS using 4-byte BE
    /// length-prefixed JSON framing (`crates/aos-guest/src/codec.rs`), retrying across
    /// `VIRTIO_VSOCK_EVENT_TRANSPORT_RESET` after snapshot restore.
    pub fn vsock_exchange_framed(
        vsock_uds: &Path,
        guest_port: u32,
        request_json: &[u8],
        timeout: Duration,
    ) -> Result<(Vec<u8>, u32)> {
        let framed = encode_framed_json(request_json)?;
        let deadline = Instant::now() + timeout;
        let connect_cmd = format_vsock_connect(guest_port);
        let mut last_err = anyhow!("no vsock framed connect attempts executed");

        while Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match try_vsock_framed_once(vsock_uds, &connect_cmd, &framed, remaining) {
                Ok(ok) => return Ok(ok),
                Err(e) => {
                    last_err = e;
                    sleep(Duration::from_millis(2));
                }
            }
        }
        Err(last_err.context(format!(
            "vsock framed exchange failed on {} port {guest_port} within {:?}",
            vsock_uds.display(),
            timeout
        )))
    }

    fn try_vsock_framed_once(
        vsock_uds: &Path,
        connect_cmd: &str,
        framed_req: &[u8],
        timeout: Duration,
    ) -> Result<(Vec<u8>, u32)> {
        let mut stream = UnixStream::connect(vsock_uds)
            .with_context(|| format!("connect vsock UDS {}", vsock_uds.display()))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.write_all(connect_cmd.as_bytes())?;
        stream.flush()?;

        // Read the ASCII `OK <host_port>\n` line byte-by-byte so we do not over-read into the
        // binary 4-byte BE length header that follows on the same stream.
        let mut ok_line = Vec::with_capacity(32);
        let mut b = [0u8; 1];
        loop {
            let n = stream.read(&mut b)?;
            ensure!(n > 0, "vsock UDS closed before OK handshake");
            ok_line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
            ensure!(ok_line.len() <= 128, "vsock OK handshake line too long");
        }
        let ok_str = std::str::from_utf8(&ok_line).context("non-UTF8 vsock OK line")?;
        let host_port = parse_vsock_ok_line(ok_str)?;

        stream.write_all(framed_req)?;
        stream.flush()?;

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        ensure!(
            len > 0 && len <= MAX_GUEST_FRAME_BYTES,
            "invalid guest response frame length {len}"
        );
        let mut resp = vec![0u8; len];
        stream.read_exact(&mut resp)?;
        Ok((resp, host_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_load_schema_matches_v1_10_v1_11() {
        let params = SnapshotLoadParams::file_backend(
            "/var/lib/forkloom/snap/vmstate",
            "/var/lib/forkloom/snap/mem.img",
            false,
            true,
        );
        let v = serde_json::to_value(&params).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 3);
        assert_eq!(obj["mem_backend"]["backend_type"], "File");
        assert_eq!(obj["resume_vm"], true);
        // Must NOT emit v1.11+ `track_dirty_pages`, v1.12+ `network_overrides`, or v1.16+ `vsock_override`.
        assert!(!obj.contains_key("track_dirty_pages"));
        assert!(!obj.contains_key("enable_diff_snapshots"));
        assert!(!obj.contains_key("network_overrides"));
        assert!(!obj.contains_key("vsock_override"));
        assert!(!obj.contains_key("mem_file_path"));
    }

    #[test]
    fn http_request_and_response_roundtrip() {
        let req = format_http_request("PUT", "/snapshot/load", "{\"resume_vm\":true}");
        assert!(req.starts_with("PUT /snapshot/load HTTP/1.1\r\n"));
        assert!(req.contains("Content-Length: 18\r\n"));

        let (code, body) =
            parse_http_response("HTTP/1.1 204 No Content\r\nServer: Firecracker\r\n\r\n").unwrap();
        assert_eq!(code, 204);
        assert!(body.is_empty());

        let (err_code, err_body) =
            parse_http_response("HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"bad\"}")
                .unwrap();
        assert_eq!(err_code, 400);
        assert!(err_body.contains("fault_message"));
    }

    #[test]
    fn vsock_handshake_and_aos_guest_v1_envelopes() {
        assert_eq!(format_vsock_connect(5000), "CONNECT 5000\n");
        assert_eq!(parse_vsock_ok_line("OK 1073741824\n").unwrap(), 1_073_741_824);
        assert!(parse_vsock_ok_line("ERR busy\n").is_err());
        assert!(parse_vsock_ok_line("OK 0\n").is_err());

        // Ping request + Pong response framing
        let ping = guest_ping_request(7, 999).unwrap();
        let wire = encode_framed_json(&ping).unwrap();
        let (decoded, consumed) = decode_framed_json(&wire).unwrap();
        assert_eq!(decoded, ping.as_slice());
        assert_eq!(consumed, wire.len());
        let pong_json = br#"{"req_id":7,"protocol_version":1,"payload":{"type":"pong","nonce":999,"state":"ready","uptime_ms":12,"pid":1,"epoch_generation":2}}"#;
        let pong = parse_guest_pong(pong_json, 7, 999).unwrap();
        assert_eq!(pong.pid, 1);
        assert_eq!(pong.epoch_generation, 2);

        // PostForkReseed request + ReseedAck
        let entropy = [0xABu8; 64];
        let reseed_req =
            guest_post_fork_reseed_request(8, &entropy, 1_750_000_000, 123, true, Some("w1"))
                .unwrap();
        let rv: Value = serde_json::from_slice(&reseed_req).unwrap();
        assert_eq!(rv["payload"]["type"], "post_fork_reseed");
        assert_eq!(
            b64_decode(rv["payload"]["entropy"].as_str().unwrap()).unwrap(),
            entropy
        );
        let ack_json = br#"{"req_id":8,"protocol_version":1,"payload":{"type":"reseed_ack","entropy_injected_bytes":64,"crng_reseeded":true,"clock_synced":true,"killed_tcp_sockets":1,"preserved_loopback_sockets":2,"unfrozen":true,"epoch_generation":3}}"#;
        let ack = parse_guest_reseed_ack(ack_json, 8).unwrap();
        assert!(ack.crng_reseeded && ack.unfrozen);
        assert_eq!(ack.killed_tcp_sockets, 1);
        assert_eq!(ack.preserved_loopback_sockets, 2);

        // Exec request + ExecResult base64 stdout decode
        let exec_req =
            guest_exec_request(9, "e1", &["echo".into(), "hi".into()], 2000).unwrap();
        let ev: Value = serde_json::from_slice(&exec_req).unwrap();
        assert_eq!(ev["payload"]["type"], "exec");
        let raw_stdout = b"hello\x00world";
        let exec_resp = serde_json::to_vec(&json!({
            "req_id": 9,
            "protocol_version": 1,
            "payload": {
                "type": "exec_result",
                "exec_id": "e1",
                "exit_code": 0,
                "signal": null,
                "timed_out": false,
                "cgroup_killed": false,
                "duration_ms": 4,
                "stdout": { "head": b64_encode(raw_stdout), "tail": "", "total_bytes": raw_stdout.len(), "omitted_bytes": 0, "truncated": false },
                "stderr": { "head": "", "tail": "", "total_bytes": 0, "omitted_bytes": 0, "truncated": false }
            }
        }))
        .unwrap();
        let res = parse_guest_exec_result(&exec_resp, 9).unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert_eq!(res.stdout, raw_stdout);
    }

    #[test]
    fn base64_roundtrips_all_padding_lengths() {
        for len in [0usize, 1, 2, 3, 4, 5, 63, 64, 65] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
            let enc = b64_encode(&data);
            assert_eq!(b64_decode(&enc).unwrap(), data);
        }
    }
}
