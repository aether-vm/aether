//! Phase 1 Wave 3 `agentd` <-> `aos-gw` Integration Tests:
//! 1. `r2_recovery_fences_and_cancels_inflight_gateway_stream`:
//!    Verifies that an active `L1ProxyServer` in-flight proxied HTTP stream bound to epoch 1 is
//!    immediately cancelled when `MetaEngine::open_and_recover` runs R2 `fence_gateway(EpochId(2))`
//!    via `ProductionRecoveryHooks::with_gateway_fence`.
//! 2. `destroy_world_unbinds_gateway_and_crypto_shreds_audit`:
//!    Verifies that `CreateWorld` binds a gateway slot in `EpochFenceRegistry` and initializes the
//!    world's `0600` key slot in `AuditStore`, and that `DestroyWorld` immediately unbinds/cancels
//!    the gateway slot AND calls `AuditStore::crypto_shred(world_id)`, rendering previously written
//!    `.aseg` audit segments permanently undecryptable (`GwError::AuditKeyMissing`).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentd::backend::{
    build_ustar_archive, InMemorySandboxBackend, LocalDevTreeBackend, ProductionRecoveryHooks,
};
use agentd::proto::frame_service_client::FrameServiceClient;
use agentd::proto::frame_service_server::FrameServiceServer;
use agentd::proto::world_service_server::WorldService;
use agentd::proto::{
    self, CreateWorldRequest, DestroyWorldRequest, DriverKind, FencingToken, FrameDurability,
    ImportTarHeader, ImportTarRequest,
};
use agentd::service::AgentdService;
use aos_gw::{
    AllowedMethod, AuditOutcome, AuditRecord, AuditStore, BindingKey, CapabilityPolicy,
    EpochFenceRegistry, GatewayListener, GwError, L1ProxyServer, RouteRule, SlotId, SsrfPolicy,
};
use aos_meta::{ManualClock, MetaConfig, MetaEngine};
use aos_store::{TreeStore, TreeStoreConfig};
use aos_types::{BootId, EpochId, WorldId};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Server, Uri};
use tonic::Request;
use tower::service_fn;

static GW_TEST_SEQ: AtomicU32 = AtomicU32::new(0);
const TEST_BOOT: &str = "44444444-4444-4444-8444-444444444444";

struct GwTestEnv {
    root: PathBuf,
    cfg: MetaConfig,
    tmpfs: PathBuf,
    clock: Arc<ManualClock>,
}

impl GwTestEnv {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "forkloom-agentd-gw-{tag}-{}-{}",
            std::process::id(),
            GW_TEST_SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        let meta = root.join("meta");
        let pool = root.join("pool");
        let tmpfs = root.join("tmpfs");
        std::fs::create_dir_all(&tmpfs).unwrap();
        let mut cfg = MetaConfig::new(meta, pool);
        cfg.allow_same_fs_for_testing = true;
        Self {
            root,
            cfg,
            tmpfs,
            clock: Arc::new(ManualClock::new(1_760_000_000_000)),
        }
    }
}

impl Drop for GwTestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[allow(clippy::result_large_err)]
async fn import_tar_over_duplex(
    svc: &AgentdService,
    header: ImportTarHeader,
    tar_bytes: Vec<u8>,
) -> Result<proto::ImportTarResponse, tonic::Status> {
    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let svc_clone = svc.clone();
    let server_task = tokio::spawn(async move {
        let incoming = tokio_stream::once(Ok::<_, std::io::Error>(server_io))
            .chain(tokio_stream::pending());
        let _ = Server::builder()
            .add_service(FrameServiceServer::new(svc_clone))
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let mut client_opt = Some(client_io);
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let io = client_opt.take().expect("single connect");
            async move { Ok::<_, std::io::Error>(TokioIo::new(io)) }
        }))
        .await
        .unwrap();

    let mut client = FrameServiceClient::new(channel);
    let mut chunks = vec![ImportTarRequest {
        chunk: Some(proto::import_tar_request::Chunk::Header(header)),
    }];
    for slice in tar_bytes.chunks(4096) {
        chunks.push(ImportTarRequest {
            chunk: Some(proto::import_tar_request::Chunk::Data(slice.to_vec())),
        });
    }
    let res = client
        .import_tar(tokio_stream::iter(chunks))
        .await
        .map(|r| r.into_inner());
    drop(client);
    let _ = shutdown_tx.send(());
    let _ = server_task.await;
    res
}

#[tokio::test]
async fn r2_recovery_fences_and_cancels_inflight_gateway_stream() {
    let env = GwTestEnv::new("r2-fence-cancel");
    let store = TreeStore::open(TreeStoreConfig::for_testing(&env.cfg.pool_root)).unwrap();
    let fence = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let boot = BootId::parse(TEST_BOOT).unwrap();

    // 1. Boot Epoch 1 with ProductionRecoveryHooks wired to `fence`.
    let hooks1 = Box::new(
        ProductionRecoveryHooks::new(store.clone(), &env.tmpfs, env.root.join("cgroups"))
            .with_gateway_fence(fence.clone()),
    );
    let (engine1, summary1) =
        MetaEngine::open_and_recover(env.cfg.clone(), boot, hooks1, env.clock.clone()).unwrap();
    assert_eq!(summary1.new_epoch, EpochId::FIRST);
    assert_eq!(fence.current_epoch(), EpochId::FIRST);

    // 2. Start a slow HTTP upstream on loopback that sends headers + 1 chunk, then holds the
    //    chunked body open indefinitely until cancelled.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let (first_chunk_tx, first_chunk_rx) = oneshot::channel::<()>();
    let (_hold_tx, hold_rx) = oneshot::channel::<()>();

    let upstream_task = tokio::spawn(async move {
        let (mut sock, _) = upstream_listener.accept().await.unwrap();
        let mut req_buf = [0u8; 1024];
        let _ = sock.read(&mut req_buf).await;
        sock.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
        )
        .await
        .unwrap();
        sock.flush().await.unwrap();
        let _ = first_chunk_tx.send(());
        let _ = hold_rx.await;
    });

    // 3. Register an epoch-1 world binding in `fence` and spawn `L1ProxyServer`.
    let world_id = WorldId::random();
    let slot_id = SlotId::new("slot-epoch1").unwrap();
    let key1 = BindingKey::new(slot_id.clone(), world_id, EpochId::FIRST);
    let rule = RouteRule::new(
        "api.example.com",
        upstream_addr.port(),
        "/v1/stream",
        vec![AllowedMethod::Get],
    )
    .unwrap()
    .with_upstream_addr(upstream_addr);
    let policy = CapabilityPolicy::deny_all()
        .with_route(rule)
        .with_ssrf(SsrfPolicy::allow_loopback_for_tests());
    let binding1 = fence.register(key1.clone(), policy).unwrap();

    let gw_listener = GatewayListener::bind_tcp("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let proxy_handle = L1ProxyServer::spawn(gw_listener, key1.clone(), fence.clone(), None).unwrap();
    let proxy_addr = proxy_handle.local_tcp_addr().unwrap();

    // 4. Connect a client to the L1 proxy and read the first streamed chunk ("hello") so the
    //    stream is actively in-flight at epoch 1.
    let mut client_sock = TcpStream::connect(proxy_addr).await.unwrap();
    client_sock
        .write_all(b"GET /v1/stream HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
        .await
        .unwrap();
    first_chunk_rx.await.unwrap();

    let mut initial_buf = [0u8; 512];
    let n = client_sock.read(&mut initial_buf).await.unwrap();
    let initial_str = String::from_utf8_lossy(&initial_buf[..n]);
    assert!(
        initial_str.contains("hello"),
        "expected initial chunk from proxy, got: {initial_str:?}"
    );
    assert!(!binding1.is_revoked());
    assert_eq!(fence.active_binding_count(), 1);

    // 5. Simulate `agentd` crash & restart: drop `engine1` and run `MetaEngine::open_and_recover`
    //    into Epoch 2 with `ProductionRecoveryHooks::with_gateway_fence(fence.clone())`.
    drop(engine1);
    let hooks2 = Box::new(
        ProductionRecoveryHooks::new(store, &env.tmpfs, env.root.join("cgroups"))
            .with_gateway_fence(fence.clone()),
    );
    let (_engine2, summary2) =
        MetaEngine::open_and_recover(env.cfg.clone(), boot, hooks2, env.clock.clone()).unwrap();
    let epoch2 = EpochId::new(2).unwrap();
    assert_eq!(summary2.new_epoch, epoch2);

    // 6. R2 `fence_gateway` MUST have advanced `fence` to epoch 2, revoked `binding1`, and
    //    cancelled the in-flight proxy stream and accept loop!
    assert_eq!(fence.current_epoch(), epoch2);
    assert!(binding1.is_revoked(), "epoch-1 binding must be revoked by R2");
    assert_eq!(fence.active_binding_count(), 0);
    assert!(matches!(
        fence.lookup(&key1),
        Err(GwError::StaleEpoch { .. })
    ));

    // The in-flight client socket must terminate promptly (EOF or connection reset) within 2s.
    let mut tail_buf = Vec::new();
    let read_res =
        tokio::time::timeout(Duration::from_secs(2), client_sock.read_to_end(&mut tail_buf))
            .await
            .expect("in-flight stream must be cancelled promptly on R2 epoch advance");
    // Either clean EOF (Ok) or reset (Err) is acceptable on cancellation; it must NOT hang.
    let _ = read_res;

    tokio::time::timeout(Duration::from_secs(2), proxy_handle.join())
        .await
        .expect("L1ProxyServer accept loop must exit when epoch binding is cancelled");
    upstream_task.abort();
}

#[tokio::test]
async fn destroy_world_unbinds_gateway_and_crypto_shreds_audit() {
    let env = GwTestEnv::new("destroy-shred");
    let fence = Arc::new(EpochFenceRegistry::new(EpochId::FIRST));
    let audit = Arc::new(
        AuditStore::open(
            env.cfg.meta_dir.join("audit"),
            env.cfg.meta_dir.join("audit-keys"),
        )
        .unwrap(),
    );
    let store = TreeStore::open(TreeStoreConfig::for_testing(&env.cfg.pool_root)).unwrap();
    let hooks = Box::new(
        ProductionRecoveryHooks::new(store, &env.tmpfs, env.root.join("cgroups"))
            .with_gateway_fence(fence.clone()),
    );
    let boot = BootId::parse(TEST_BOOT).unwrap();
    let (engine, _) =
        MetaEngine::open_and_recover(env.cfg.clone(), boot, hooks, env.clock.clone()).unwrap();
    let tree = Arc::new(LocalDevTreeBackend::new(env.root.join("worlds")));
    let sandbox = Arc::new(InMemorySandboxBackend::new());
    let svc = AgentdService::new(engine, tree, sandbox).with_gateway(fence.clone(), Some(audit.clone()));

    // 1. Import base frame & create world
    let tar = build_ustar_archive(&[("app.txt", b"hello\n")]);
    let imp = import_tar_over_duplex(
        &svc,
        ImportTarHeader {
            owner: "alice".into(),
            durability: FrameDurability::Durable as i32,
            parent_frame_id: String::new(),
            labels: HashMap::new(),
            pin: None,
            timeline_name: String::new(),
            expected_old_timeline_head: String::new(),
            idempotency_key: None,
        },
        tar,
    )
    .await
    .unwrap();
    let base_fid = imp.frame.unwrap().frame_id;

    let w = svc
        .create_world(Request::new(CreateWorldRequest {
            owner: "alice".into(),
            base_frame_id: base_fid,
            driver: DriverKind::Namespace as i32,
            labels: HashMap::new(),
            lease_ttl_ms: 60_000,
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .world
        .unwrap();
    let wid: WorldId = w.world_id.parse().unwrap();
    let fence_tok = w.fencing_token.unwrap().value;

    // 2. Verify CreateWorld bound a slot in EpochFenceRegistry and initialized the audit key slot
    let slot_id = svc
        .world_gateway_slot(wid)
        .expect("world must have a bound gateway slot");
    let binding_key = BindingKey::new(slot_id.clone(), wid, EpochId::FIRST);
    let binding = fence.lookup(&binding_key).expect("binding must be active");
    assert!(!binding.is_revoked());
    assert_eq!(fence.active_binding_count(), 1);
    assert!(
        audit.key_slot_path(wid).is_file(),
        "0600 audit key slot must be initialized on CreateWorld"
    );

    // 3. Append and verify an encrypted audit segment for `wid`
    let receipt = audit
        .append_record(AuditRecord {
            timestamp_ms: AuditRecord::now_ms(),
            world_id: wid,
            epoch: EpochId::FIRST,
            slot_id: slot_id.to_string(),
            method: "POST".into(),
            host: "api.openai.com".into(),
            path: "/v1/responses".into(),
            status_code: Some(200),
            outcome: AuditOutcome::Allowed,
            bytes_in: 128,
            bytes_out: 512,
            detail: Some("openai-key".into()),
        })
        .unwrap();
    assert_eq!(receipt.seq, 1);

    let chain_report = audit.verify_chain(wid).unwrap();
    assert_eq!(chain_report.segment_count, 1);
    assert_eq!(chain_report.total_records, 1);
    let decrypted = audit.read_records(wid).unwrap();
    assert_eq!(decrypted.len(), 1);
    assert_eq!(decrypted[0].host, "api.openai.com");
    assert!(audit.segment_path(wid, 1).is_file());

    // 4. DestroyWorld -> must unbind/cancel gateway slot AND crypto_shred the world's audit key slot!
    svc.destroy_world(Request::new(DestroyWorldRequest {
        world_id: wid.to_string(),
        owner: "alice".into(),
        fencing_token: Some(FencingToken { value: fence_tok }),
        idempotency_key: None,
    }))
    .await
    .unwrap();

    assert!(svc.world_gateway_slot(wid).is_none());
    assert!(binding.is_revoked(), "gateway slot binding must be cancelled on DestroyWorld");
    assert_eq!(fence.active_binding_count(), 0);
    assert!(matches!(
        fence.lookup(&binding_key),
        Err(GwError::BindingNotFound { .. })
    ));

    // Key slot file is unlinked after CSPRNG + zero overwrite, while encrypted .aseg file remains on disk
    // and can no longer be decrypted!
    assert!(
        !audit.key_slot_path(wid).exists(),
        "key slot file must be unlinked by crypto_shred"
    );
    assert!(
        audit.segment_path(wid, 1).is_file(),
        "encrypted .aseg segment remains on disk but is permanently undecryptable"
    );
    assert!(matches!(
        audit.read_records(wid),
        Err(GwError::AuditKeyMissing { world_id }) if world_id == wid
    ));
    assert!(matches!(
        audit.verify_chain(wid),
        Err(GwError::AuditKeyMissing { world_id }) if world_id == wid
    ));
}
