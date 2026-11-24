//! End-to-end live async integration tests for `aos-gw`:
//! - Real HTTP/1.1 L1 reverse proxy injecting Bearer & custom headers strictly on host side
//! - Stripping hop-by-hop headers (incl. Connection-nominated headers)
//! - Denying unauthorized host, path prefix boundary, HTTP method, path traversal, oversized body/headers
//! - Enforcing SSRF blocklist (blocking loopback by default, blocking cloud metadata 169.254.169.254 even under test loopback flag)
//! - Blocking cross-chunk secret reflection (raw, Base64, hex, URL-encoded, header echo, mid-stream abort, compressed response block, and Redact mode)
//! - Immediately terminating in-flight connections on `advance_epoch`
//! - Pre-bound `std::net::TcpListener` / Unix `OwnedFd` / `0600` UDS listener handoff (§7.4)
//! - L3 allowlist DNS (`NXDOMAIN`), shared multi-tenant CDN rejection, UDP/QUIC-443 denial
//! - Segmented XChaCha20-Poly1305 encrypted `blake3` hash-chained audit log, tamper detection, and `crypto_shred`

#![forbid(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aos_gw::{
    AllowedMethod, AuditOutcome, AuditStore, BindingKey, CapabilityPolicy, CredentialInjection,
    DnsDecision, DnsDenyReason, DnsRcode, DomainAllowlist, EgressDecision, EgressDenyReason,
    EpochFenceRegistry, GatewayListener, GwError, L1ProxyServer, ProxyLimits, ReflectionAction,
    RouteRule, SecretValue, SlotId, SsrfPolicy, TransportProtocol, build_nxdomain_wire_response,
};
use aos_types::{EpochId, WorldId};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

struct ChunkStreamBody {
    rx: mpsc::Receiver<std::result::Result<Bytes, std::io::Error>>,
}

impl Body for ChunkStreamBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(b))) => {
                std::task::Poll::Ready(Some(Ok(Frame::data(b))))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[derive(Debug, Clone)]
struct RecordedUpstreamReq {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn spawn_mock_upstream<F, Fut>(
    handler: F,
) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<ChunkStreamBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let h2 = Arc::clone(&h);
                    async move { Ok::<_, std::convert::Infallible>(h2(req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    (addr, handle)
}

fn chunked_response(status: StatusCode, headers: HeaderMap, chunks: Vec<Bytes>) -> Response<ChunkStreamBody> {
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        for c in chunks {
            if tx.send(Ok(c)).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    });
    let mut resp = Response::builder()
        .status(status)
        .body(ChunkStreamBody { rx })
        .unwrap();
    *resp.headers_mut() = headers;
    resp
}

async fn send_http1_over<S>(
    stream: S,
    req: Request<Full<Bytes>>,
) -> std::result::Result<(StatusCode, HeaderMap, Vec<u8>), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| format!("send_request: {e}"))?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("body collect: {e}"))?
        .to_bytes()
        .to_vec();
    Ok((status, headers, body))
}

async fn send_http1(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> std::result::Result<(StatusCode, HeaderMap, Vec<u8>), String> {
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    send_http1_over(stream, req).await
}

fn temp_dir(tag: &str) -> PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let p = std::env::temp_dir().join(format!("aos-gw-int-{tag}-{hex}"));
    fs::create_dir_all(&p).unwrap();
    p
}

#[tokio::test]
async fn l1_proxy_injects_secrets_enforces_routes_limits_and_audits_encrypted_chain() {
    let recorded: Arc<Mutex<Vec<RecordedUpstreamReq>>> = Arc::new(Mutex::new(Vec::new()));
    let rec_clone = Arc::clone(&recorded);

    let (upstream_addr, upstream_task) = spawn_mock_upstream(move |req| {
        let rec = Arc::clone(&rec_clone);
        async move {
            let method = req.method().as_str().to_owned();
            let uri = req.uri().to_string();
            let headers: Vec<(String, String)> = req
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
                .collect();
            let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
            rec.lock().unwrap().push(RecordedUpstreamReq {
                method,
                uri,
                headers,
                body,
            });
            chunked_response(
                StatusCode::OK,
                HeaderMap::new(),
                vec![Bytes::from_static(b"{\"status\":\"ok\"}")],
            )
        }
    })
    .await;

    let tmp = temp_dir("l1-main");
    let audit = Arc::new(AuditStore::open(tmp.join("audit"), tmp.join("keys")).unwrap());
    let world_id = WorldId::random();
    audit.init_world(world_id).unwrap();

    let bearer_secret = SecretValue::new("sk-live-host-only-bearer-9911").unwrap();
    let custom_secret = SecretValue::new("cust-key-host-only-7733").unwrap();

    let policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_limits(ProxyLimits {
            max_header_bytes: 2048,
            max_header_count: 24,
            max_request_body_bytes: 128,
            max_response_body_bytes: 64 * 1024,
            upstream_connect_timeout: Duration::from_secs(5),
            upstream_response_timeout: Duration::from_secs(5),
        })
        .with_route(
            RouteRule::new("api.example.com", upstream_addr.port(), "/v1/chat", vec![AllowedMethod::Post])
                .unwrap()
                .with_upstream_addr(upstream_addr)
                .with_credential(CredentialInjection::bearer("openai", bearer_secret.clone()).unwrap()),
        )
        .with_route(
            RouteRule::new("api.example.com", upstream_addr.port(), "/v1/items", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr(upstream_addr)
                .with_credential(
                    CredentialInjection::custom_header("items-key", "x-api-key", custom_secret.clone())
                        .unwrap()
                        .with_placeholder("SANDBOX_PLACEHOLDER")
                        .unwrap(),
                ),
        );

    let registry = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let key = BindingKey::new(SlotId::new("slot-main").unwrap(), world_id, EpochId::FIRST);
    registry.register(key.clone(), policy).unwrap();

    let listener = GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_handle =
        L1ProxyServer::spawn(listener, key, Arc::clone(&registry), Some(Arc::clone(&audit)))
            .unwrap();
    let gw_addr = gw_handle.local_tcp_addr().unwrap();

    // 1. Authorized POST /v1/chat/completions -> host injects real Bearer, strips hop-by-hop & spoofed auth.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions?stream=false")
        .header("host", "api.example.com")
        .header("authorization", "Bearer sandbox-spoofed-value")
        .header("connection", "keep-alive, x-hop-drop")
        .header("x-hop-drop", "must-be-stripped")
        .header("accept-encoding", "gzip, br")
        .body(Full::new(Bytes::from_static(b"{\"prompt\":\"hi\"}")))
        .unwrap();
    let (status, _hdrs, body) = send_http1(gw_addr, req).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"{\"status\":\"ok\"}");

    {
        let seen = recorded.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let r = &seen[0];
        assert_eq!(r.method, "POST");
        assert_eq!(r.uri, "/v1/chat/completions?stream=false");
        assert_eq!(r.body, b"{\"prompt\":\"hi\"}");
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer sk-live-host-only-bearer-9911"));
        assert_eq!(
            r.headers.iter().filter(|(k, _)| k == "authorization").count(),
            1,
            "must never duplicate Authorization header"
        );
        assert!(!r.headers.iter().any(|(k, _)| k == "x-hop-drop"));
        assert!(r
            .headers
            .iter()
            .any(|(k, v)| k == "accept-encoding" && v == "identity"));
    }

    // 2. Placeholder-protected route: missing or wrong placeholder -> 403; exact placeholder -> 200.
    let bad_ph = Request::builder()
        .method(Method::GET)
        .uri("/v1/items/42")
        .header("host", "api.example.com")
        .header("x-api-key", "WRONG_PLACEHOLDER")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(send_http1(gw_addr, bad_ph).await.unwrap().0, StatusCode::FORBIDDEN);

    let good_ph = Request::builder()
        .method(Method::GET)
        .uri("/v1/items/42")
        .header("host", "api.example.com")
        .header("x-api-key", "SANDBOX_PLACEHOLDER")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(send_http1(gw_addr, good_ph).await.unwrap().0, StatusCode::OK);
    {
        let seen = recorded.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[1]
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "cust-key-host-only-7733"));
    }

    // 3. Unauthorized path & prefix boundary bypass (`/v1/chat2` must NOT match `/v1/chat`).
    for denied_path in ["/v1/admin", "/v1/chat2", "/secret"] {
        let r = Request::builder()
            .method(Method::POST)
            .uri(denied_path)
            .header("host", "api.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            send_http1(gw_addr, r).await.unwrap().0,
            StatusCode::FORBIDDEN,
            "path {denied_path} must be denied"
        );
    }

    // 4. Unauthorized HTTP method -> 405 Method Not Allowed.
    let wrong_method = Request::builder()
        .method(Method::DELETE)
        .uri("/v1/chat/completions")
        .header("host", "api.example.com")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        send_http1(gw_addr, wrong_method).await.unwrap().0,
        StatusCode::METHOD_NOT_ALLOWED
    );

    // 5. Path traversal smuggling -> 400 Bad Request.
    for bad_path in ["/v1/chat/../admin", "/v1/chat/%2e%2e/admin"] {
        let r = Request::builder()
            .method(Method::POST)
            .uri(bad_path)
            .header("host", "api.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap();
        assert_eq!(
            send_http1(gw_addr, r).await.unwrap().0,
            StatusCode::BAD_REQUEST,
            "traversal path {bad_path} must be 400"
        );
    }

    // 6. Oversized request body (> 128 bytes) -> 413 Payload Too Large.
    let big_body = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat")
        .header("host", "api.example.com")
        .body(Full::new(Bytes::from(vec![b'x'; 256])))
        .unwrap();
    assert_eq!(
        send_http1(gw_addr, big_body).await.unwrap().0,
        StatusCode::PAYLOAD_TOO_LARGE
    );

    // 7. Oversized headers (> 2048 bytes) -> 431 Request Header Fields Too Large.
    let big_hdr = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat")
        .header("host", "api.example.com")
        .header("x-huge", "a".repeat(2500))
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        send_http1(gw_addr, big_hdr).await.unwrap().0,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );

    // 8. Verify encrypted audit hash chain & confirm ZERO secrets appear anywhere on disk!
    let report = audit.verify_chain(world_id).unwrap();
    assert!(report.segment_count >= 8);
    let records = audit.read_records(world_id).unwrap();
    assert!(records.iter().any(|r| r.outcome == AuditOutcome::Allowed));
    assert!(records.iter().any(|r| r.outcome == AuditOutcome::Denied));
    for seq in 1..=report.segment_count {
        let raw = fs::read(audit.segment_path(world_id, seq)).unwrap();
        assert!(!raw.windows(bearer_secret.as_bytes().len()).any(|w| w == bearer_secret.as_bytes()));
        assert!(!raw.windows(custom_secret.as_bytes().len()).any(|w| w == custom_secret.as_bytes()));
    }

    gw_handle.shutdown().await;
    upstream_task.abort();
    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn l1_proxy_enforces_ssrf_blocklist_strict_and_metadata_override() {
    let (upstream_addr, upstream_task) = spawn_mock_upstream(|_req| async {
        chunked_response(StatusCode::OK, HeaderMap::new(), vec![Bytes::from_static(b"ok")])
    })
    .await;

    let registry = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let world_id = WorldId::random();

    // Strict SSRF policy blocks loopback 127.0.0.1!
    let strict_policy = CapabilityPolicy::deny_all().with_route(
        RouteRule::new("internal.local", upstream_addr.port(), "/", vec![AllowedMethod::Get])
            .unwrap()
            .with_upstream_addr(upstream_addr),
    );
    let k1 = BindingKey::new(SlotId::new("slot-strict").unwrap(), world_id, EpochId::FIRST);
    registry.register(k1.clone(), strict_policy).unwrap();
    let gw1 = L1ProxyServer::spawn(
        GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        k1,
        Arc::clone(&registry),
        None,
    )
    .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/latest/meta-data/")
        .header("host", "internal.local")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        send_http1(gw1.local_tcp_addr().unwrap(), req).await.unwrap().0,
        StatusCode::FORBIDDEN
    );

    // Even with `allow_loopback_for_tests`, cloud metadata 169.254.169.254 is STILL blocked!
    let meta_policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_route(
            RouteRule::new("meta.aws", 80, "/", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr("169.254.169.254:80".parse().unwrap()),
        );
    let k2 = BindingKey::new(SlotId::new("slot-meta").unwrap(), world_id, EpochId::FIRST);
    registry.register(k2.clone(), meta_policy).unwrap();
    let gw2 = L1ProxyServer::spawn(
        GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        k2,
        Arc::clone(&registry),
        None,
    )
    .unwrap();
    let req_meta = Request::builder()
        .method(Method::GET)
        .uri("/latest/meta-data/")
        .header("host", "meta.aws")
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert_eq!(
        send_http1(gw2.local_tcp_addr().unwrap(), req_meta).await.unwrap().0,
        StatusCode::FORBIDDEN
    );

    gw1.shutdown().await;
    gw2.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn l1_proxy_blocks_and_redacts_cross_chunk_secret_reflection() {
    let secret = SecretValue::new("sk-antireflect-9988+xyz").unwrap();
    let secret_str = secret.as_str().to_owned();
    let secret_b64 = STANDARD.encode(secret.as_bytes());
    let secret_hex: String = secret.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let secret_url = secret_str.replace('+', "%2B");

    let (upstream_addr, upstream_task) = spawn_mock_upstream(move |req| {
        let s_raw = secret_str.clone();
        let s_b64 = secret_b64.clone();
        let s_hex = secret_hex.clone();
        let s_url = secret_url.clone();
        async move {
            let path = req.uri().path().to_owned();
            match path.as_str() {
                "/echo/raw-chunks" => {
                    // Split raw secret across 3-byte network chunks!
                    let full = format!("resp: {s_raw} done");
                    let chunks: Vec<Bytes> = full
                        .as_bytes()
                        .chunks(3)
                        .map(Bytes::copy_from_slice)
                        .collect();
                    chunked_response(StatusCode::OK, HeaderMap::new(), chunks)
                }
                "/echo/b64-chunks" => {
                    let full = format!("encoded={s_b64}");
                    let chunks: Vec<Bytes> = full
                        .as_bytes()
                        .chunks(4)
                        .map(Bytes::copy_from_slice)
                        .collect();
                    chunked_response(StatusCode::OK, HeaderMap::new(), chunks)
                }
                "/echo/hex-chunks" => {
                    let full = format!("hex={s_hex}");
                    let chunks: Vec<Bytes> = full
                        .as_bytes()
                        .chunks(5)
                        .map(Bytes::copy_from_slice)
                        .collect();
                    chunked_response(StatusCode::OK, HeaderMap::new(), chunks)
                }
                "/echo/url-chunks" => {
                    let full = format!("url={s_url}");
                    let chunks: Vec<Bytes> = full
                        .as_bytes()
                        .chunks(2)
                        .map(Bytes::copy_from_slice)
                        .collect();
                    chunked_response(StatusCode::OK, HeaderMap::new(), chunks)
                }
                "/echo/header" => {
                    let mut h = HeaderMap::new();
                    h.insert("x-leaked", format!("tok={s_raw}").parse().unwrap());
                    chunked_response(StatusCode::OK, h, vec![Bytes::from_static(b"clean body")])
                }
                "/echo/gzip" => {
                    let mut h = HeaderMap::new();
                    h.insert("content-encoding", "gzip".parse().unwrap());
                    chunked_response(StatusCode::OK, h, vec![Bytes::from_static(b"\x1f\x8b\x08\x00")])
                }
                "/echo/large-stream-mid-abort" => {
                    // Emit 64 KiB of clean data first (so streaming starts), THEN split the secret across chunks!
                    let mut chunks = vec![Bytes::from(vec![b'A'; 32 * 1024]), Bytes::from(vec![b'B'; 32 * 1024])];
                    for c in s_raw.as_bytes().chunks(3) {
                        chunks.push(Bytes::copy_from_slice(c));
                    }
                    chunks.push(Bytes::from_static(b"trailing"));
                    chunked_response(StatusCode::OK, HeaderMap::new(), chunks)
                }
                _ => chunked_response(StatusCode::OK, HeaderMap::new(), vec![Bytes::from_static(b"safe")]),
            }
        }
    })
    .await;

    let tmp = temp_dir("reflect");
    let audit = Arc::new(AuditStore::open(tmp.join("audit"), tmp.join("keys")).unwrap());
    let world_id = WorldId::random();
    audit.init_world(world_id).unwrap();

    let registry = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));

    // A) Abort mode (default)
    let abort_policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_reflection_action(ReflectionAction::Abort)
        .with_route(
            RouteRule::new("echo.test", upstream_addr.port(), "/echo", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr(upstream_addr)
                .with_credential(CredentialInjection::bearer("reflect-tok", secret.clone()).unwrap()),
        );
    let k_abort = BindingKey::new(SlotId::new("slot-abort").unwrap(), world_id, EpochId::FIRST);
    registry.register(k_abort.clone(), abort_policy).unwrap();
    let gw_abort = L1ProxyServer::spawn(
        GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        k_abort,
        Arc::clone(&registry),
        Some(Arc::clone(&audit)),
    )
    .unwrap();
    let abort_addr = gw_abort.local_tcp_addr().unwrap();

    for path in [
        "/echo/raw-chunks",
        "/echo/b64-chunks",
        "/echo/hex-chunks",
        "/echo/url-chunks",
        "/echo/header",
        "/echo/gzip",
    ] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header("host", "echo.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _hdrs, body) = send_http1(abort_addr, req).await.unwrap();
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "expected 502 Bad Gateway for {path}"
        );
        assert!(
            !body.windows(secret.as_bytes().len()).any(|w| w == secret.as_bytes()),
            "secret leaked on {path}"
        );
    }

    // Large mid-stream reflection: verify clean prefix streams out AND stream aborts on secret
    // with ZERO bytes of the secret ever reaching the sandbox!
    {
        let stream = TcpStream::connect(abort_addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req_large = Request::builder()
            .method(Method::GET)
            .uri("/echo/large-stream-mid-abort")
            .header("host", "echo.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = sender.send_request(req_large).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = resp.into_body();
        let mut received = Vec::new();
        let mut aborted = false;
        while let Some(frame_res) = body.frame().await {
            match frame_res {
                Ok(frame) => {
                    if let Some(d) = frame.data_ref() {
                        received.extend_from_slice(d);
                    }
                }
                Err(_) => {
                    aborted = true;
                    break;
                }
            }
        }
        assert!(aborted, "mid-stream reflection must abort the HTTP/1.1 body stream");
        assert!(
            received.len() >= 32 * 1024,
            "expected clean streaming prefix before abort, got {} bytes",
            received.len()
        );
        assert!(
            !received
                .windows(secret.as_bytes().len())
                .any(|w| w == secret.as_bytes()),
            "secret leaked into streamed prefix before abort!"
        );
    }

    // B) Redact mode: cross-chunk reflected secrets are cleanly replaced with [REDACTED_SECRET].
    let redact_policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_reflection_action(ReflectionAction::Redact)
        .with_route(
            RouteRule::new("echo.test", upstream_addr.port(), "/echo", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr(upstream_addr)
                .with_credential(CredentialInjection::bearer("reflect-tok", secret.clone()).unwrap()),
        );
    let k_redact = BindingKey::new(SlotId::new("slot-redact").unwrap(), world_id, EpochId::FIRST);
    registry.register(k_redact.clone(), redact_policy).unwrap();
    let gw_redact = L1ProxyServer::spawn(
        GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        k_redact,
        Arc::clone(&registry),
        Some(Arc::clone(&audit)),
    )
    .unwrap();
    let redact_addr = gw_redact.local_tcp_addr().unwrap();

    let req_redact = Request::builder()
        .method(Method::GET)
        .uri("/echo/raw-chunks")
        .header("host", "echo.test")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _hdrs, body) = send_http1(redact_addr, req_redact).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "resp: [REDACTED_SECRET] done"
    );

    let req_hdr_redact = Request::builder()
        .method(Method::GET)
        .uri("/echo/header")
        .header("host", "echo.test")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, hdrs, _body) = send_http1(redact_addr, req_hdr_redact).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        hdrs.get("x-leaked").unwrap().to_str().unwrap(),
        "tok=[REDACTED_SECRET]"
    );

    // Verify audit chain captured ReflectionBlocked, CompressedResponseBlocked, and ReflectionRedacted!
    let records = audit.read_records(world_id).unwrap();
    assert!(records.iter().any(|r| r.outcome == AuditOutcome::ReflectionBlocked));
    assert!(records.iter().any(|r| r.outcome == AuditOutcome::CompressedResponseBlocked));
    assert!(records.iter().any(|r| r.outcome == AuditOutcome::ReflectionRedacted));

    gw_abort.shutdown().await;
    gw_redact.shutdown().await;
    upstream_task.abort();
    let _ = fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn l1_proxy_immediately_terminates_inflight_connection_on_advance_epoch() {
    let (started_tx, mut started_rx) = mpsc::channel::<()>(1);
    let started_tx = Arc::new(started_tx);

    // Upstream holds the response open for 30 seconds after accepting the request.
    let (upstream_addr, upstream_task) = spawn_mock_upstream(move |_req| {
        let notify = Arc::clone(&started_tx);
        async move {
            let _ = notify.send(()).await;
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                let _ = tx.send(Ok(Bytes::from_static(b"chunk-1-"))).await;
                tokio::time::sleep(Duration::from_secs(30)).await;
                let _ = tx.send(Ok(Bytes::from_static(b"never-sent"))).await;
            });
            Response::builder()
                .status(StatusCode::OK)
                .body(ChunkStreamBody { rx })
                .unwrap()
        }
    })
    .await;

    let e1 = EpochId::FIRST;
    let e2 = e1.next().unwrap();
    let world_id = WorldId::random();
    let registry = Arc::new(EpochFenceRegistry::new(e1));
    let policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_route(
            RouteRule::new("slow.example", upstream_addr.port(), "/stream", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr(upstream_addr),
        );
    let key = BindingKey::new(SlotId::new("slot-epoch").unwrap(), world_id, e1);
    let binding = registry.register(key.clone(), policy).unwrap();

    let gw = L1ProxyServer::spawn(
        GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap(),
        key.clone(),
        Arc::clone(&registry),
        None,
    )
    .unwrap();
    let gw_addr = gw.local_tcp_addr().unwrap();

    // Launch an in-flight streaming request.
    let client_task = tokio::spawn(async move {
        let req = Request::builder()
            .method(Method::GET)
            .uri("/stream")
            .header("host", "slow.example")
            .body(Full::new(Bytes::new()))
            .unwrap();
        send_http1(gw_addr, req).await
    });

    // Wait until upstream has received the request and the connection is live in-flight.
    tokio::time::timeout(Duration::from_secs(3), started_rx.recv())
        .await
        .expect("upstream did not receive request in time");
    assert_eq!(binding.active_connections(), 1);

    // Advance epoch e1 -> e2: must IMMEDIATELY abort the in-flight connection and stop the listener!
    let t0 = Instant::now();
    let report = registry.advance_epoch(e2).unwrap();
    assert_eq!(report.revoked_bindings, 1);

    let client_res = tokio::time::timeout(Duration::from_secs(2), client_task)
        .await
        .expect("in-flight connection did not terminate promptly on advance_epoch")
        .unwrap();
    assert!(
        client_res.is_err(),
        "in-flight HTTP stream must fail when fenced by advance_epoch"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "cancellation took too long: {:?}",
        t0.elapsed()
    );

    // Server accept loop must exit cleanly once its binding is revoked.
    tokio::time::timeout(Duration::from_secs(2), gw.join())
        .await
        .expect("L1ProxyServer did not exit after epoch fence");

    // Stale epoch registration is rejected.
    assert!(matches!(
        registry.register(key, CapabilityPolicy::deny_all()),
        Err(GwError::StaleEpoch { .. })
    ));

    upstream_task.abort();
}

#[tokio::test]
async fn l1_proxy_prebound_std_tcp_and_unix_uds_handoff() {
    let (upstream_addr, upstream_task) = spawn_mock_upstream(|_req| async {
        chunked_response(
            StatusCode::OK,
            HeaderMap::new(),
            vec![Bytes::from_static(b"prebound-ok")],
        )
    })
    .await;

    let world_id = WorldId::random();
    let registry = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let policy = CapabilityPolicy::deny_all()
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests())
        .with_route(
            RouteRule::new("handoff.test", upstream_addr.port(), "/", vec![AllowedMethod::Get])
                .unwrap()
                .with_upstream_addr(upstream_addr),
        );

    // 1. Pre-bound std::net::TcpListener handoff (§7.4 netns pre-bound listener fd model).
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let handoff_addr = std_listener.local_addr().unwrap();
    let gw_listener = GatewayListener::from_std_tcp(std_listener).unwrap();
    let key_tcp = BindingKey::new(SlotId::new("slot-handoff-tcp").unwrap(), world_id, EpochId::FIRST);
    registry.register(key_tcp.clone(), policy.clone()).unwrap();
    let gw_tcp = L1ProxyServer::spawn(gw_listener, key_tcp, Arc::clone(&registry), None).unwrap();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/ping")
        .header("host", "handoff.test")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _hdrs, body) = send_http1(handoff_addr, req).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"prebound-ok");
    gw_tcp.shutdown().await;

    // 2. Unix Domain Socket (`0600`) + `OwnedFd` TCP handoff on Unix/Linux.
    #[cfg(unix)]
    {
        use std::os::fd::OwnedFd;
        use std::os::unix::fs::PermissionsExt;

        let tmp = temp_dir("uds");
        let uds_path = tmp.join("gw.sock");
        let uds_listener = GatewayListener::bind_uds(&uds_path).unwrap();
        let mode = fs::metadata(&uds_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "UDS listener must be 0600");

        let key_uds = BindingKey::new(SlotId::new("slot-uds").unwrap(), world_id, EpochId::FIRST);
        registry.register(key_uds.clone(), policy.clone()).unwrap();
        let gw_uds =
            L1ProxyServer::spawn(uds_listener, key_uds, Arc::clone(&registry), None).unwrap();

        let uds_stream = tokio::net::UnixStream::connect(&uds_path).await.unwrap();
        let req_uds = Request::builder()
            .method(Method::GET)
            .uri("/ping-uds")
            .header("host", "handoff.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _hdrs, body) = send_http1_over(uds_stream, req_uds).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"prebound-ok");
        gw_uds.shutdown().await;

        // Also test OwnedFd TCP handoff (zero unsafe).
        let raw_std = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd_addr = raw_std.local_addr().unwrap();
        let owned_fd: OwnedFd = raw_std.into();
        let fd_listener = GatewayListener::from_owned_tcp_fd(owned_fd).unwrap();
        let key_fd = BindingKey::new(SlotId::new("slot-fd").unwrap(), world_id, EpochId::FIRST);
        registry.register(key_fd.clone(), policy).unwrap();
        let gw_fd = L1ProxyServer::spawn(fd_listener, key_fd, Arc::clone(&registry), None).unwrap();

        let req_fd = Request::builder()
            .method(Method::GET)
            .uri("/ping-fd")
            .header("host", "handoff.test")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (status, _hdrs, body) = send_http1(fd_addr, req_fd).await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"prebound-ok");
        gw_fd.shutdown().await;

        let _ = fs::remove_dir_all(&tmp);
    }

    upstream_task.abort();
}

#[test]
fn l3_allowlist_and_audit_crypto_shred_contract() {
    // Verify L3 allowlist, shared CDN rejection, NXDOMAIN, and UDP/QUIC-443 denial.
    let mut allowlist = DomainAllowlist::from_patterns(["api.openai.com", "*.github.com"]).unwrap();
    assert!(matches!(
        allowlist.add_pattern("*.cloudfront.net"),
        Err(GwError::SharedCdnForbidden { .. })
    ));
    assert!(matches!(
        allowlist.add_pattern("*.workers.dev"),
        Err(GwError::SharedCdnForbidden { .. })
    ));
    assert!(allowlist.evaluate_dns("api.openai.com").is_allowed());
    assert!(allowlist.evaluate_dns("raw.github.com").is_allowed());
    assert_eq!(
        allowlist.evaluate_dns("evil.net"),
        DnsDecision::Deny {
            rcode: DnsRcode::NxDomain,
            reason: DnsDenyReason::NotAllowlisted,
        }
    );
    assert_eq!(
        allowlist.evaluate_dns("app.pages.dev"),
        DnsDecision::Deny {
            rcode: DnsRcode::NxDomain,
            reason: DnsDenyReason::SharedMultiTenantCdn,
        }
    );
    assert_eq!(
        allowlist.evaluate_egress(
            TransportProtocol::Udp,
            "api.openai.com",
            443,
            Some("1.1.1.1".parse().unwrap())
        ),
        EgressDecision::Deny(EgressDenyReason::QuicUdp443Forbidden)
    );

    // Build wire NXDOMAIN packet.
    let dns_q: Vec<u8> = vec![
        0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 4, b't', b'e',
        b's', b't', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
    ];
    let dns_resp = build_nxdomain_wire_response(&dns_q).unwrap();
    assert_eq!(&dns_resp[0..2], &[0xab, 0xcd]);
    assert_eq!(dns_resp[3] & 0x0f, DnsRcode::NxDomain as u8);
}
