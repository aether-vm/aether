//! L1 Explicit Reverse Proxy Gateway (`l1_proxy.rs`, ARCHITECTURE_V2 §2.2, §6, §7.4).
//!
//! Real async HTTP/1.1 reverse proxy bound physically to a `(slot_id, world_id, daemon_epoch)`
//! listener (TCP loopback for isolated tests, UDS, or pre-bound `netns` listener fd via
//! [`GatewayListener::from_std_tcp`] / [`GatewayListener::from_owned_tcp_fd`]).
//!
//! Security properties:
//! - Every connection and request verifies the epoch fence via [`EpochFenceRegistry`].
//! - Advancing the epoch or revoking the slot immediately aborts both the accept loop and all
//!   in-flight client/upstream connections.
//! - Fine-grained route authorization: `host + path_prefix + allowed_methods` with strict
//!   traversal/smuggling validation (`..`, `%2e`, `%2f`, `CONNECT`, `CL+TE`, duplicate `Host`).
//! - Hop-by-hop headers (including all headers listed in `Connection`) are stripped on both
//!   request and response paths.
//! - Host-side credential injection (Bearer or custom header) occurs strictly on the host side;
//!   real secrets never enter sandbox memory.
//! - Every upstream target IP (explicit or DNS-resolved) is validated against [`SsrfPolicy`]
//!   BEFORE connecting, and the socket connects directly to the validated `SocketAddr` (no DNS
//!   rebinding TOCTOU).
//! - Upstream response headers and body streams pass through [`ReflectionScanner`] so reflected
//!   secrets (raw, Base64, URL-encoded, hex-encoded) across arbitrary chunk boundaries are
//!   immediately aborted (zero secret bytes leaked) or redacted.

use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditOutcome, AuditRecord, AuditStore};
use crate::epoch::{BindingKey, EpochFenceRegistry, SlotBinding};
use crate::error::{GwError, Result};
use crate::policy::{
    AllowedMethod, HOP_BY_HOP_HEADERS, ProxyLimits, RouteMatch, RouteRule,
    parse_http_host_header, validate_request_path,
};

/// Transport listener bound to a single `(slot_id, world_id, daemon_epoch)` gateway identity.
///
/// Supports:
/// - Local TCP bind (cross-platform tests and loopback `netns` listeners)
/// - Pre-bound `std::net::TcpListener` / Unix `OwnedFd` (§7.4 `netns` fd handoff without
///   relying on spoofable source IPs)
/// - Unix Domain Socket (`0600` on Unix)
pub enum GatewayListener {
    /// Async TCP listener (local bind or pre-bound `netns` loopback listener fd).
    Tcp(TcpListener),
    /// Async Unix Domain Socket listener (Unix only).
    #[cfg(unix)]
    Uds(tokio::net::UnixListener),
}

impl GatewayListener {
    /// Bind a TCP listener on `addr` (e.g. `127.0.0.1:0` for tests).
    pub async fn bind_tcp(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::Tcp(listener))
    }

    /// Wrap a pre-bound `std::net::TcpListener` (e.g. bound inside a sandbox's isolated `netns`
    /// loopback and handed to `aos-gw` per ARCHITECTURE_V2 §7.4).
    pub fn from_std_tcp(std_listener: std::net::TcpListener) -> Result<Self> {
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;
        Ok(Self::Tcp(listener))
    }

    /// Wrap a pre-bound TCP listener `OwnedFd` (§7.4 `netns` fd handoff, zero `unsafe`).
    #[cfg(unix)]
    pub fn from_owned_tcp_fd(fd: std::os::fd::OwnedFd) -> Result<Self> {
        let std_listener = std::net::TcpListener::from(fd);
        Self::from_std_tcp(std_listener)
    }

    /// Bind a Unix Domain Socket at `path` with `0600` permissions.
    #[cfg(unix)]
    pub fn bind_uds(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let listener = tokio::net::UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(Self::Uds(listener))
    }

    /// Wrap a pre-bound `std::os::unix::net::UnixListener` (fd handoff).
    #[cfg(unix)]
    pub fn from_std_uds(std_listener: std::os::unix::net::UnixListener) -> Result<Self> {
        std_listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(std_listener)?;
        Ok(Self::Uds(listener))
    }

    /// Wrap a pre-bound UDS listener `OwnedFd` (zero `unsafe`).
    #[cfg(unix)]
    pub fn from_owned_uds_fd(fd: std::os::fd::OwnedFd) -> Result<Self> {
        let std_listener = std::os::unix::net::UnixListener::from(fd);
        Self::from_std_uds(std_listener)
    }

    /// Return the bound TCP socket address, if this is a TCP listener.
    pub fn local_tcp_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(l) => l.local_addr().ok(),
            #[cfg(unix)]
            Self::Uds(_) => None,
        }
    }
}

/// Running handle for an [`L1ProxyServer`] bound to a single `(slot_id, world_id, epoch)`.
#[derive(Debug)]
pub struct L1ProxyHandle {
    local_tcp_addr: Option<SocketAddr>,
    shutdown: CancellationToken,
    join: JoinHandle<()>,
}

impl L1ProxyHandle {
    /// Bound TCP address if started on a TCP listener.
    #[must_use]
    pub const fn local_tcp_addr(&self) -> Option<SocketAddr> {
        self.local_tcp_addr
    }

    /// Trigger graceful shutdown and wait for the accept loop to exit.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.join.await;
    }

    /// Await completion of the server task (e.g. after `advance_epoch` revokes its binding).
    pub async fn join(self) {
        let _ = self.join.await;
    }

    /// Returns `true` if the server accept loop has terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.join.is_finished()
    }
}

/// L1 Explicit HTTP/1.1 Reverse Proxy server bound to a single [`BindingKey`].
pub struct L1ProxyServer;

impl L1ProxyServer {
    /// Spawn an L1 reverse proxy listener physically bound to `binding_key`.
    ///
    /// Fails immediately if `binding_key` is not currently active in `registry`.
    pub fn spawn(
        listener: GatewayListener,
        binding_key: BindingKey,
        registry: Arc<EpochFenceRegistry>,
        audit: Option<Arc<AuditStore>>,
    ) -> Result<L1ProxyHandle> {
        let binding = registry.lookup(&binding_key)?;
        let binding_cancel = binding.cancel_token().clone();
        let local_tcp_addr = listener.local_tcp_addr();
        let shutdown = CancellationToken::new();
        let shutdown_child = shutdown.clone();

        let join = tokio::spawn(async move {
            run_accept_loop(
                listener,
                binding_key,
                registry,
                audit,
                binding_cancel,
                shutdown_child,
            )
            .await;
        });

        Ok(L1ProxyHandle {
            local_tcp_addr,
            shutdown,
            join,
        })
    }
}

async fn run_accept_loop(
    listener: GatewayListener,
    binding_key: BindingKey,
    registry: Arc<EpochFenceRegistry>,
    audit: Option<Arc<AuditStore>>,
    binding_cancel: CancellationToken,
    shutdown: CancellationToken,
) {
    loop {
        match &listener {
            GatewayListener::Tcp(tcp) => {
                tokio::select! {
                    biased;
                    () = binding_cancel.cancelled() => break,
                    () = shutdown.cancelled() => break,
                    accepted = tcp.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                let _ = stream.set_nodelay(true);
                                spawn_conn_task(
                                    stream,
                                    binding_key.clone(),
                                    Arc::clone(&registry),
                                    audit.clone(),
                                    shutdown.clone(),
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "L1 TCP accept error");
                            }
                        }
                    }
                }
            }
            #[cfg(unix)]
            GatewayListener::Uds(uds) => {
                tokio::select! {
                    biased;
                    () = binding_cancel.cancelled() => break,
                    () = shutdown.cancelled() => break,
                    accepted = uds.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                spawn_conn_task(
                                    stream,
                                    binding_key.clone(),
                                    Arc::clone(&registry),
                                    audit.clone(),
                                    shutdown.clone(),
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "L1 UDS accept error");
                            }
                        }
                    }
                }
            }
        }
    }
}

fn spawn_conn_task<S>(
    stream: S,
    binding_key: BindingKey,
    registry: Arc<EpochFenceRegistry>,
    audit: Option<Arc<AuditStore>>,
    shutdown: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let Ok(binding) = registry.lookup(&binding_key) else {
            return;
        };
        let _conn_guard = binding.track_connection();
        let cancel = binding.cancel_token().clone();
        let limits = binding.policy().limits;

        let io = TokioIo::new(stream);
        let svc_key = binding_key.clone();
        let svc_reg = Arc::clone(&registry);
        let svc_audit = audit.clone();

        let service = service_fn(move |req: Request<Incoming>| {
            let key = svc_key.clone();
            let reg = Arc::clone(&svc_reg);
            let aud = svc_audit.clone();
            async move {
                Ok::<Response<ProxyBody>, std::convert::Infallible>(
                    handle_request(req, &key, &reg, aud).await,
                )
            }
        });

        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .max_buf_size(limits.max_header_bytes.max(8192))
            .keep_alive(true);

        let conn = builder.serve_connection(io, service);

        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::debug!(slot = %binding_key.slot_id, "aborted in-flight L1 connection on epoch fence");
            }
            () = shutdown.cancelled() => {}
            res = conn => {
                if let Err(e) = res {
                    tracing::debug!(error = %e, "L1 HTTP/1.1 connection closed");
                }
            }
        }
    });
}

/// Custom `http_body::Body` supporting both buffered error/small responses and live streaming
/// responses with mid-stream abort capability.
enum ProxyBody {
    Buffered(Option<Bytes>),
    Stream(mpsc::Receiver<std::result::Result<Bytes, io::Error>>),
}

impl ProxyBody {
    fn from_text(text: &'static str) -> Self {
        Self::Buffered(Some(Bytes::from_static(text.as_bytes())))
    }

    fn from_bytes(bytes: Bytes) -> Self {
        Self::Buffered(Some(bytes))
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match &mut *self {
            Self::Buffered(opt) => match opt.take() {
                Some(b) if !b.is_empty() => Poll::Ready(Some(Ok(Frame::data(b)))),
                _ => Poll::Ready(None),
            },
            Self::Stream(rx) => match rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(b))) => Poll::Ready(Some(Ok(Frame::data(b)))),
                Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

fn plain_response(status: StatusCode, msg: &'static str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CONTENT_LENGTH, msg.len().to_string())
        .body(ProxyBody::from_text(msg))
        .expect("valid plain response")
}

#[allow(clippy::too_many_arguments)]
fn record_audit(
    audit: Option<&AuditStore>,
    key: &BindingKey,
    method: &str,
    host: &str,
    path: &str,
    status: Option<u16>,
    outcome: AuditOutcome,
    bytes_in: u64,
    bytes_out: u64,
    detail: Option<String>,
) {
    let Some(store) = audit else {
        return;
    };
    let rec = AuditRecord {
        timestamp_ms: AuditRecord::now_ms(),
        world_id: key.world_id,
        epoch: key.epoch,
        slot_id: key.slot_id.to_string(),
        method: method.to_owned(),
        host: host.to_owned(),
        path: path.to_owned(),
        status_code: status,
        outcome,
        bytes_in,
        bytes_out,
        detail,
    };
    if let Err(e) = store.append_record(rec) {
        tracing::warn!(error = %e, world = %key.world_id, "failed to append audit record");
    }
}

async fn handle_request(
    req: Request<Incoming>,
    binding_key: &BindingKey,
    registry: &EpochFenceRegistry,
    audit_arc: Option<Arc<AuditStore>>,
) -> Response<ProxyBody> {
    let audit = audit_arc.as_deref();
    let method_str = req.method().as_str().to_owned();
    let raw_path = req.uri().path().to_owned();

    // 1. Verify active epoch fence binding on every request.
    let binding = match registry.lookup(binding_key) {
        Ok(b) => b,
        Err(_) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                "",
                &raw_path,
                Some(StatusCode::FORBIDDEN.as_u16()),
                AuditOutcome::EpochRevoked,
                0,
                0,
                Some("binding revoked or epoch stale".into()),
            );
            return plain_response(StatusCode::FORBIDDEN, "gateway binding revoked or stale");
        }
    };

    let policy = binding.policy();
    let limits = policy.limits;
    let cancel = binding.cancel_token().clone();

    // 2. Reject CONNECT / TRACE and disallowed methods early.
    let Some(allowed_method) = AllowedMethod::from_http(req.method()) else {
        record_audit(
            audit,
            binding_key,
            &method_str,
            "",
            &raw_path,
            Some(StatusCode::METHOD_NOT_ALLOWED.as_u16()),
            AuditOutcome::Denied,
            0,
            0,
            Some("method forbidden on L1 reverse proxy".into()),
        );
        return plain_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "HTTP method forbidden on L1 reverse proxy",
        );
    };

    // 3. Enforce header count & total header byte caps.
    if let Err(msg) = check_header_limits(req.headers(), limits) {
        record_audit(
            audit,
            binding_key,
            &method_str,
            "",
            &raw_path,
            Some(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.as_u16()),
            AuditOutcome::Denied,
            0,
            0,
            Some(msg.into()),
        );
        return plain_response(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, msg);
    }

    // 4. Anti-smuggling: reject Transfer-Encoding + Content-Length or duplicate Content-Length.
    if req.headers().contains_key(header::TRANSFER_ENCODING)
        && req.headers().contains_key(header::CONTENT_LENGTH)
    {
        return plain_response(
            StatusCode::BAD_REQUEST,
            "ambiguous Content-Length and Transfer-Encoding",
        );
    }
    if req.headers().get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return plain_response(StatusCode::BAD_REQUEST, "duplicate Content-Length header");
    }

    // 5. Extract & validate Host header (mandatory, unique, consistent with absolute-form URI).
    let canonical_host = match extract_validated_host(&req) {
        Ok(h) => h,
        Err(msg) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                "",
                &raw_path,
                Some(StatusCode::BAD_REQUEST.as_u16()),
                AuditOutcome::Denied,
                0,
                0,
                Some(msg.into()),
            );
            return plain_response(StatusCode::BAD_REQUEST, msg);
        }
    };

    // 6. Validate request path against traversal / encoded smuggling.
    if validate_request_path(&raw_path).is_err() {
        record_audit(
            audit,
            binding_key,
            &method_str,
            &canonical_host,
            &raw_path,
            Some(StatusCode::BAD_REQUEST.as_u16()),
            AuditOutcome::Denied,
            0,
            0,
            Some("invalid request path".into()),
        );
        return plain_response(StatusCode::BAD_REQUEST, "invalid or unsafe request path");
    }

    // 7. Capability policy authorization: host + path_prefix + method.
    let rule: RouteRule = match policy.match_route(&canonical_host, &raw_path, allowed_method) {
        RouteMatch::Allowed(r) => r.clone(),
        RouteMatch::MethodNotAllowed => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::METHOD_NOT_ALLOWED.as_u16()),
                AuditOutcome::Denied,
                0,
                0,
                Some("HTTP method not permitted for route".into()),
            );
            return plain_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "HTTP method not permitted by capability policy",
            );
        }
        RouteMatch::Denied => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::FORBIDDEN.as_u16()),
                AuditOutcome::Denied,
                0,
                0,
                Some("host or path not permitted by capability policy".into()),
            );
            return plain_response(
                StatusCode::FORBIDDEN,
                "host or path denied by capability policy",
            );
        }
    };

    // 8. Check declared Content-Length against request body cap before reading body.
    if let Some(cl_val) = req.headers().get(header::CONTENT_LENGTH) {
        let Ok(cl_str) = cl_val.to_str() else {
            return plain_response(StatusCode::BAD_REQUEST, "invalid Content-Length header");
        };
        let Ok(cl) = cl_str.trim().parse::<usize>() else {
            return plain_response(StatusCode::BAD_REQUEST, "malformed Content-Length header");
        };
        if cl > limits.max_request_body_bytes {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::PAYLOAD_TOO_LARGE.as_u16()),
                AuditOutcome::Denied,
                cl as u64,
                0,
                Some("request body exceeds policy cap".into()),
            );
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds gateway limit",
            );
        }
    }

    // 9. Build upstream request headers (strip hop-by-hop + host-side credential injection).
    let (parts, incoming_body) = req.into_parts();
    let upstream_headers = match build_upstream_headers(&parts.headers, &rule, &binding) {
        Ok(h) => h,
        Err((status, msg)) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(status.as_u16()),
                AuditOutcome::Denied,
                0,
                0,
                Some(msg.into()),
            );
            return plain_response(status, msg);
        }
    };

    // 10. Collect incoming request body with strict byte cap, raced against epoch cancellation.
    let req_body_bytes = match collect_limited_body(
        incoming_body,
        limits.max_request_body_bytes,
        &cancel,
    )
    .await
    {
        Ok(b) => b,
        Err(BodyReadError::TooLarge) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::PAYLOAD_TOO_LARGE.as_u16()),
                AuditOutcome::Denied,
                limits.max_request_body_bytes as u64,
                0,
                Some("streamed request body exceeded limit".into()),
            );
            return plain_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds gateway limit",
            );
        }
        Err(BodyReadError::Cancelled) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::FORBIDDEN.as_u16()),
                AuditOutcome::EpochRevoked,
                0,
                0,
                Some("request cancelled by epoch fence".into()),
            );
            return plain_response(StatusCode::FORBIDDEN, "gateway binding revoked");
        }
        Err(BodyReadError::Io) => {
            return plain_response(StatusCode::BAD_REQUEST, "failed reading request body");
        }
    };
    let bytes_in = req_body_bytes.len() as u64;

    // 11. Resolve & SSRF-validate upstream SocketAddr BEFORE connecting (eliminates DNS rebinding TOCTOU).
    let target_addr = match resolve_and_validate_upstream(&rule, &policy.ssrf, &cancel).await {
        Ok(addr) => addr,
        Err(UpstreamResolveError::Ssrf(reason)) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::FORBIDDEN.as_u16()),
                AuditOutcome::SsrfBlocked,
                bytes_in,
                0,
                Some(reason),
            );
            return plain_response(StatusCode::FORBIDDEN, "upstream IP blocked by SSRF policy");
        }
        Err(UpstreamResolveError::Cancelled) => {
            return plain_response(StatusCode::FORBIDDEN, "gateway binding revoked");
        }
        Err(UpstreamResolveError::DnsFailed) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::BAD_GATEWAY.as_u16()),
                AuditOutcome::UpstreamError,
                bytes_in,
                0,
                Some("upstream DNS resolution failed".into()),
            );
            return plain_response(StatusCode::BAD_GATEWAY, "upstream DNS resolution failed");
        }
    };

    // 12. Connect to validated upstream SocketAddr with connect timeout + epoch cancellation.
    let upstream_stream = match connect_upstream(target_addr, limits, &cancel).await {
        Ok(s) => s,
        Err(ConnectError::Cancelled) => {
            return plain_response(StatusCode::FORBIDDEN, "gateway binding revoked");
        }
        Err(ConnectError::Timeout) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::GATEWAY_TIMEOUT.as_u16()),
                AuditOutcome::UpstreamError,
                bytes_in,
                0,
                Some("upstream connect timeout".into()),
            );
            return plain_response(StatusCode::GATEWAY_TIMEOUT, "upstream connect timeout");
        }
        Err(ConnectError::Io) => {
            record_audit(
                audit,
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(StatusCode::BAD_GATEWAY.as_u16()),
                AuditOutcome::UpstreamError,
                bytes_in,
                0,
                Some("upstream TCP connect failed".into()),
            );
            return plain_response(StatusCode::BAD_GATEWAY, "upstream connect failed");
        }
    };

    // 13. Perform HTTP/1.1 upstream handshake and send request.
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(upstream_stream)).await {
        Ok(pair) => pair,
        Err(_) => {
            return plain_response(StatusCode::BAD_GATEWAY, "upstream HTTP handshake failed");
        }
    };

    let conn_cancel = cancel.clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            () = conn_cancel.cancelled() => {}
            res = conn => {
                if let Err(e) = res {
                    tracing::debug!(error = %e, "upstream HTTP/1.1 connection closed");
                }
            }
        }
    });

    // Preserve exact origin-form path + optional query string.
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let Ok(upstream_uri) = Uri::try_from(path_and_query) else {
        return plain_response(StatusCode::BAD_REQUEST, "invalid request target URI");
    };

    let mut upstream_req = Request::builder()
        .method(parts.method)
        .uri(upstream_uri)
        .body(http_body_util::Full::new(req_body_bytes))
        .expect("valid upstream request");
    *upstream_req.headers_mut() = upstream_headers;

    let upstream_resp = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            return plain_response(StatusCode::FORBIDDEN, "gateway binding revoked");
        }
        res = tokio::time::timeout(limits.upstream_response_timeout, sender.send_request(upstream_req)) => {
            match res {
                Ok(Ok(r)) => r,
                Ok(Err(_)) => {
                    record_audit(
                        audit,
                        binding_key,
                        &method_str,
                        &canonical_host,
                        &raw_path,
                        Some(StatusCode::BAD_GATEWAY.as_u16()),
                        AuditOutcome::UpstreamError,
                        bytes_in,
                        0,
                        Some("upstream request failed".into()),
                    );
                    return plain_response(StatusCode::BAD_GATEWAY, "upstream request failed");
                }
                Err(_) => {
                    record_audit(
                        audit,
                        binding_key,
                        &method_str,
                        &canonical_host,
                        &raw_path,
                        Some(StatusCode::GATEWAY_TIMEOUT.as_u16()),
                        AuditOutcome::UpstreamError,
                        bytes_in,
                        0,
                        Some("upstream response timeout".into()),
                    );
                    return plain_response(StatusCode::GATEWAY_TIMEOUT, "upstream response timeout");
                }
            }
        }
    };

    // 14. Validate upstream response headers, check declared response Content-Length cap,
    //     fail closed on compressed responses when secrets are active, strip hop-by-hop headers,
    //     and scan response header values for secret reflection.
    let (resp_parts, upstream_body) = upstream_resp.into_parts();
    if check_header_limits(&resp_parts.headers, limits).is_err() {
        return plain_response(
            StatusCode::BAD_GATEWAY,
            "upstream response headers exceed gateway limit",
        );
    }
    if let Some(cl_val) = resp_parts.headers.get(header::CONTENT_LENGTH)
        && let Ok(cl_str) = cl_val.to_str()
        && let Ok(cl) = cl_str.trim().parse::<usize>()
        && cl > limits.max_response_body_bytes
    {
        record_audit(
            audit,
            binding_key,
            &method_str,
            &canonical_host,
            &raw_path,
            Some(StatusCode::BAD_GATEWAY.as_u16()),
            AuditOutcome::UpstreamError,
            bytes_in,
            0,
            Some("upstream response Content-Length exceeds cap".into()),
        );
        return plain_response(
            StatusCode::BAD_GATEWAY,
            "upstream response body exceeds gateway limit",
        );
    }

    let scanner = binding.scanner();
    if scanner.has_secrets() && has_non_identity_content_encoding(&resp_parts.headers) {
        record_audit(
            audit,
            binding_key,
            &method_str,
            &canonical_host,
            &raw_path,
            Some(StatusCode::BAD_GATEWAY.as_u16()),
            AuditOutcome::CompressedResponseBlocked,
            bytes_in,
            0,
            Some("compressed upstream response blocked while secrets active".into()),
        );
        return plain_response(
            StatusCode::BAD_GATEWAY,
            "compressed upstream response blocked while secrets are active",
        );
    }

    let (clean_resp_headers, header_redacted) =
        match sanitize_response_headers(&resp_parts.headers, scanner) {
            Ok(pair) => pair,
            Err(GwError::SecretReflected { label, variant }) => {
                record_audit(
                    audit,
                    binding_key,
                    &method_str,
                    &canonical_host,
                    &raw_path,
                    Some(StatusCode::BAD_GATEWAY.as_u16()),
                    AuditOutcome::ReflectionBlocked,
                    bytes_in,
                    0,
                    Some(format!("header reflection blocked ({label}, {variant:?})")),
                );
                return plain_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream response blocked: secret reflection detected in headers",
                );
            }
            Err(_) => {
                return plain_response(
                    StatusCode::BAD_GATEWAY,
                    "failed scanning upstream response headers",
                );
            }
        };

    // 15. Stream upstream response body through the sliding-window anti-reflection scanner.
    //
    // Pull frames until either:
    // - the first safe output chunk is ready to flush (streaming mode for large bodies), OR
    // - the entire body finishes cleanly (buffered exact Content-Length response), OR
    // - a reflection / limit / cancellation triggers BEFORE any byte is emitted (clean 502/403).
    match stream_and_scan_response(
        resp_parts.status,
        clean_resp_headers,
        header_redacted,
        upstream_body,
        Arc::clone(&binding),
        binding_key.clone(),
        method_str.clone(),
        canonical_host.clone(),
        raw_path.clone(),
        bytes_in,
        audit_arc.clone(),
    )
    .await
    {
        Ok(resp) => resp,
        Err((status, msg, outcome, detail)) => {
            record_audit(
                audit_arc.as_deref(),
                binding_key,
                &method_str,
                &canonical_host,
                &raw_path,
                Some(status.as_u16()),
                outcome,
                bytes_in,
                0,
                detail,
            );
            plain_response(status, msg)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn stream_and_scan_response(
    status: StatusCode,
    mut resp_headers: HeaderMap,
    header_redacted: bool,
    mut upstream_body: Incoming,
    binding: Arc<SlotBinding>,
    binding_key: BindingKey,
    method: String,
    host: String,
    path: String,
    bytes_in: u64,
    audit: Option<Arc<AuditStore>>,
) -> std::result::Result<Response<ProxyBody>, (StatusCode, &'static str, AuditOutcome, Option<String>)>
{
    let scanner = Arc::clone(binding.scanner());
    let limits = binding.policy().limits;
    let cancel = binding.cancel_token().clone();

    let mut stream_scan = scanner.new_owned_stream();
    let mut total_raw_read = 0usize;
    let mut first_safe_chunk: Option<Bytes> = None;
    let mut eof_reached = false;

    loop {
        let next_frame = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                return Err((
                    StatusCode::FORBIDDEN,
                    "gateway binding revoked",
                    AuditOutcome::EpochRevoked,
                    Some("response aborted by epoch fence".into()),
                ));
            }
            frame = upstream_body.frame() => frame,
        };

        match next_frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    total_raw_read = total_raw_read.saturating_add(data.len());
                    if total_raw_read > limits.max_response_body_bytes {
                        return Err((
                            StatusCode::BAD_GATEWAY,
                            "upstream response body exceeds gateway limit",
                            AuditOutcome::UpstreamError,
                            Some("response body exceeded cap".into()),
                        ));
                    }
                    match stream_scan.push_chunk(data) {
                        Ok(safe) => {
                            if !safe.is_empty() {
                                first_safe_chunk = Some(Bytes::from(safe));
                                break;
                            }
                        }
                        Err(GwError::SecretReflected { label, variant }) => {
                            return Err((
                                StatusCode::BAD_GATEWAY,
                                "upstream response blocked: secret reflection detected",
                                AuditOutcome::ReflectionBlocked,
                                Some(format!("body reflection blocked ({label}, {variant:?})")),
                            ));
                        }
                        Err(_) => {
                            return Err((
                                StatusCode::BAD_GATEWAY,
                                "upstream response scan error",
                                AuditOutcome::UpstreamError,
                                None,
                            ));
                        }
                    }
                }
            }
            Some(Err(_)) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "error reading upstream response body",
                    AuditOutcome::UpstreamError,
                    None,
                ));
            }
            None => {
                eof_reached = true;
                break;
            }
        }
    }

    if eof_reached {
        let tail = match stream_scan.finish() {
            Ok(t) => t,
            Err(GwError::SecretReflected { label, variant }) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "upstream response blocked: secret reflection detected",
                    AuditOutcome::ReflectionBlocked,
                    Some(format!("body reflection blocked ({label}, {variant:?})")),
                ));
            }
            Err(_) => {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "upstream response scan error",
                    AuditOutcome::UpstreamError,
                    None,
                ));
            }
        };

        let bytes_out = tail.len() as u64;
        let outcome = if header_redacted || !stream_scan.matches().is_empty() {
            AuditOutcome::ReflectionRedacted
        } else {
            AuditOutcome::Allowed
        };
        record_audit(
            audit.as_deref(),
            &binding_key,
            &method,
            &host,
            &path,
            Some(status.as_u16()),
            outcome,
            bytes_in,
            bytes_out,
            None,
        );

        resp_headers.remove(header::TRANSFER_ENCODING);
        resp_headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&tail.len().to_string()).expect("decimal header"),
        );

        let mut resp = Response::builder()
            .status(status)
            .body(ProxyBody::from_bytes(Bytes::from(tail)))
            .expect("valid buffered response");
        *resp.headers_mut() = resp_headers;
        return Ok(resp);
    }

    // Large / streaming response: send headers + first safe chunk immediately, then continue
    // scanning remaining upstream chunks live; abort immediately on reflection or epoch fence.
    resp_headers.remove(header::CONTENT_LENGTH);
    resp_headers.remove(header::TRANSFER_ENCODING);

    let (tx, rx) = mpsc::channel::<std::result::Result<Bytes, io::Error>>(8);
    let mut bytes_out = 0u64;
    if let Some(first) = first_safe_chunk {
        bytes_out += first.len() as u64;
        let _ = tx.send(Ok(first)).await;
    }

    tokio::spawn(async move {
        let mut outcome = AuditOutcome::Allowed;
        let mut detail: Option<String> = None;

        loop {
            let next_frame = tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    outcome = AuditOutcome::EpochRevoked;
                    detail = Some("stream aborted by epoch fence".into());
                    let _ = tx
                        .send(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "gateway binding revoked",
                        )))
                        .await;
                    break;
                }
                frame = upstream_body.frame() => frame,
            };

            match next_frame {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        total_raw_read = total_raw_read.saturating_add(data.len());
                        if total_raw_read > limits.max_response_body_bytes {
                            outcome = AuditOutcome::UpstreamError;
                            detail = Some("streamed response body exceeded cap".into());
                            let _ = tx
                                .send(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "response body limit exceeded",
                                )))
                                .await;
                            break;
                        }
                        match stream_scan.push_chunk(data) {
                            Ok(safe) => {
                                if !safe.is_empty() {
                                    bytes_out += safe.len() as u64;
                                    if tx.send(Ok(Bytes::from(safe))).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Err(GwError::SecretReflected { label, variant }) => {
                                outcome = AuditOutcome::ReflectionBlocked;
                                detail =
                                    Some(format!("stream reflection blocked ({label}, {variant:?})"));
                                let _ = tx
                                    .send(Err(io::Error::new(
                                        io::ErrorKind::PermissionDenied,
                                        "secret reflection detected",
                                    )))
                                    .await;
                                break;
                            }
                            Err(_) => {
                                outcome = AuditOutcome::UpstreamError;
                                let _ = tx
                                    .send(Err(io::Error::other("reflection scanner error")))
                                    .await;
                                break;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    outcome = AuditOutcome::UpstreamError;
                    detail = Some(format!("upstream body read error: {e}"));
                    let _ = tx
                        .send(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "upstream body error",
                        )))
                        .await;
                    break;
                }
                None => {
                    match stream_scan.finish() {
                        Ok(tail) => {
                            if !tail.is_empty() {
                                bytes_out += tail.len() as u64;
                                let _ = tx.send(Ok(Bytes::from(tail))).await;
                            }
                            if header_redacted || !stream_scan.matches().is_empty() {
                                outcome = AuditOutcome::ReflectionRedacted;
                            }
                        }
                        Err(GwError::SecretReflected { label, variant }) => {
                            outcome = AuditOutcome::ReflectionBlocked;
                            detail =
                                Some(format!("stream tail reflection blocked ({label}, {variant:?})"));
                            let _ = tx
                                .send(Err(io::Error::new(
                                    io::ErrorKind::PermissionDenied,
                                    "secret reflection detected",
                                )))
                                .await;
                        }
                        Err(_) => {
                            outcome = AuditOutcome::UpstreamError;
                            let _ = tx
                                .send(Err(io::Error::other("reflection scanner finish error")))
                                .await;
                        }
                    }
                    break;
                }
            }
        }

        record_audit(
            audit.as_deref(),
            &binding_key,
            &method,
            &host,
            &path,
            Some(status.as_u16()),
            outcome,
            bytes_in,
            bytes_out,
            detail,
        );
    });

    let mut resp = Response::builder()
        .status(status)
        .body(ProxyBody::Stream(rx))
        .expect("valid streaming response");
    *resp.headers_mut() = resp_headers;
    Ok(resp)
}

fn check_header_limits(headers: &HeaderMap, limits: ProxyLimits) -> std::result::Result<(), &'static str> {
    if headers.len() > limits.max_header_count {
        return Err("too many HTTP headers");
    }
    let total_bytes: usize = headers
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 4)
        .sum();
    if total_bytes > limits.max_header_bytes {
        return Err("HTTP headers exceed maximum allowed size");
    }
    Ok(())
}

fn extract_validated_host(req: &Request<Incoming>) -> std::result::Result<String, &'static str> {
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let Some(first) = hosts.next() else {
        return Err("missing required Host header");
    };
    if hosts.next().is_some() {
        return Err("duplicate Host headers are forbidden");
    }
    let Ok(host_str) = first.to_str() else {
        return Err("non-ASCII Host header");
    };
    let (canonical_host, _port) =
        parse_http_host_header(host_str).map_err(|_| "malformed Host header")?;

    // If request-target is absolute-form (`http://example.com/path`), authority host MUST match Host header.
    if let Some(uri_host) = req.uri().host() {
        let (uri_canonical, _) =
            parse_http_host_header(uri_host).map_err(|_| "malformed URI authority host")?;
        if uri_canonical != canonical_host {
            return Err("URI host does not match Host header");
        }
    }
    Ok(canonical_host)
}

fn collect_connection_nominated_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut extra = HashSet::new();
    for val in headers.get_all(header::CONNECTION) {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let name = token.trim().to_ascii_lowercase();
                if !name.is_empty() {
                    extra.insert(name);
                }
            }
        }
    }
    extra
}

fn build_upstream_headers(
    incoming: &HeaderMap,
    rule: &RouteRule,
    binding: &SlotBinding,
) -> std::result::Result<HeaderMap, (StatusCode, &'static str)> {
    let conn_nominated = collect_connection_nominated_headers(incoming);
    let mut out = HeaderMap::new();

    // If a credential rule requires a sandbox placeholder, verify exact match BEFORE stripping.
    if let Some(cred) = &rule.credential
        && let Some(expected_placeholder) = &cred.require_placeholder
    {
        let Ok(target_name) = HeaderName::from_bytes(cred.header_name().as_bytes()) else {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "invalid credential header"));
        };
        let mut vals = incoming.get_all(&target_name).iter();
        let Some(first) = vals.next() else {
            return Err((
                StatusCode::FORBIDDEN,
                "missing required credential placeholder header",
            ));
        };
        if vals.next().is_some() {
            return Err((
                StatusCode::FORBIDDEN,
                "duplicate credential placeholder headers",
            ));
        }
        let Ok(actual) = first.to_str() else {
            return Err((StatusCode::FORBIDDEN, "invalid credential placeholder"));
        };
        if actual.trim() != expected_placeholder.as_str() {
            return Err((StatusCode::FORBIDDEN, "credential placeholder mismatch"));
        }
    }

    let cred_header_name = rule.credential.as_ref().map(|c| c.header_name().to_owned());

    for (name, value) in incoming {
        let lower = name.as_str();
        if HOP_BY_HOP_HEADERS.contains(&lower) || conn_nominated.contains(lower) {
            continue;
        }
        // Replace Host with canonical upstream host below.
        if lower == "host" {
            continue;
        }
        // Strip sandbox-supplied Content-Length (hyper computes exact length from buffered body).
        if lower == "content-length" {
            continue;
        }
        // Strip sandbox-supplied Accept-Encoding when secrets are active so upstream cannot
        // compress reflected secrets past the anti-reflection scanner.
        if lower == "accept-encoding" && binding.scanner().has_secrets() {
            continue;
        }
        // Strip any sandbox-supplied header with the same name as our injected credential so
        // the sandbox cannot smuggle a duplicate credential header.
        if cred_header_name.as_deref() == Some(lower) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    // Set canonical upstream Host header.
    let host_val = HeaderValue::from_str(&rule.upstream_host_header())
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid upstream host header"))?;
    out.insert(header::HOST, host_val);

    // Force `Accept-Encoding: identity` when secrets are active.
    if binding.scanner().has_secrets() {
        out.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
    }

    // Inject real credential strictly on the host side.
    if let Some(cred) = &rule.credential {
        let name = HeaderName::from_bytes(cred.header_name().as_bytes())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "invalid credential header"))?;
        let formatted = cred.formatted_header_value();
        let val = HeaderValue::from_str(formatted.as_str())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "invalid credential value"))?;
        out.insert(name, val);
    }

    Ok(out)
}

fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
    for val in headers.get_all(header::CONTENT_ENCODING) {
        let Ok(s) = val.to_str() else {
            return true;
        };
        for tok in s.split(',') {
            let t = tok.trim().to_ascii_lowercase();
            if !t.is_empty() && t != "identity" {
                return true;
            }
        }
    }
    false
}

fn sanitize_response_headers(
    incoming: &HeaderMap,
    scanner: &crate::reflection::ReflectionScanner,
) -> Result<(HeaderMap, bool)> {
    let conn_nominated = collect_connection_nominated_headers(incoming);
    let mut out = HeaderMap::new();
    let mut any_redacted = false;

    for (name, value) in incoming {
        let lower = name.as_str();
        if HOP_BY_HOP_HEADERS.contains(&lower) || conn_nominated.contains(lower) {
            continue;
        }
        if scanner.has_secrets() {
            let (scanned, matches) = scanner.scan_complete(value.as_bytes())?;
            if !matches.is_empty() {
                any_redacted = true;
                let redacted_val = HeaderValue::from_bytes(&scanned).map_err(|_| {
                    GwError::InvalidPolicy("redacted header value invalid".into())
                })?;
                out.append(name.clone(), redacted_val);
                continue;
            }
        }
        out.append(name.clone(), value.clone());
    }
    Ok((out, any_redacted))
}

enum BodyReadError {
    TooLarge,
    Cancelled,
    Io,
}

async fn collect_limited_body(
    mut body: Incoming,
    max_bytes: usize,
    cancel: &CancellationToken,
) -> std::result::Result<Bytes, BodyReadError> {
    let mut buf = Vec::new();
    loop {
        let frame = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(BodyReadError::Cancelled),
            f = body.frame() => f,
        };
        match frame {
            Some(Ok(f)) => {
                if let Some(data) = f.data_ref() {
                    if buf.len().saturating_add(data.len()) > max_bytes {
                        return Err(BodyReadError::TooLarge);
                    }
                    buf.extend_from_slice(data);
                }
            }
            Some(Err(_)) => return Err(BodyReadError::Io),
            None => return Ok(Bytes::from(buf)),
        }
    }
}

enum UpstreamResolveError {
    Ssrf(String),
    DnsFailed,
    Cancelled,
}

async fn resolve_and_validate_upstream(
    rule: &RouteRule,
    ssrf: &crate::policy::SsrfPolicy,
    cancel: &CancellationToken,
) -> std::result::Result<SocketAddr, UpstreamResolveError> {
    if let Some(addr) = rule.upstream_connect_addr {
        ssrf.check_ip(addr.ip())
            .map_err(|e| UpstreamResolveError::Ssrf(e.to_string()))?;
        return Ok(addr);
    }

    let lookup = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(UpstreamResolveError::Cancelled),
        res = tokio::net::lookup_host((rule.host.as_str(), rule.upstream_port)) => res,
    };

    let addrs: Vec<SocketAddr> = lookup
        .map_err(|_| UpstreamResolveError::DnsFailed)?
        .collect();
    if addrs.is_empty() {
        return Err(UpstreamResolveError::DnsFailed);
    }

    // Fail closed if ANY returned DNS record points to a blocked SSRF address (defends against
    // dual-record DNS rebinding / split-horizon tricks).
    for addr in &addrs {
        ssrf.check_ip(addr.ip())
            .map_err(|e| UpstreamResolveError::Ssrf(e.to_string()))?;
    }

    Ok(addrs[0])
}

enum ConnectError {
    Cancelled,
    Timeout,
    Io,
}

async fn connect_upstream(
    addr: SocketAddr,
    limits: ProxyLimits,
    cancel: &CancellationToken,
) -> std::result::Result<TcpStream, ConnectError> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ConnectError::Cancelled),
        res = tokio::time::timeout(limits.upstream_connect_timeout, TcpStream::connect(addr)) => {
            match res {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    Ok(stream)
                }
                Ok(Err(_)) => Err(ConnectError::Io),
                Err(_) => Err(ConnectError::Timeout),
            }
        }
    }
}
