//! Comprehensive Phase 1 `agentd` control-plane integration tests:
//! * Full gRPC lifecycle (`NegotiateVersion`, `ImportTar`, `GetFrame`/`ListFrames`, `PinFrame`/`RenewPin`,
//!   `CreateWorld`, streaming `Exec` + idempotency cache + conflict detection, `AcquireFence` + `FencedOut`,
//!   `RenewWorldLease`, `Checkpoint` (`disk_clean` true/false), `ExportPatch` (`DiskNotClean` & `UnsafePatch`),
//!   `AdvanceTimeline` CAS + `DeleteTimeline`, `DestroyWorld`, `DeleteFrame`).
//! * Crash/restart `WorldLost` & `OutcomeUnknown` contract (never auto-replaying `Exec`).
//! * Zero-trust `ImportTar` path traversal / `.git` rejection with zero leaked `Preparing` frames.
//! * Real Unix `0600` UDS transport end-to-end test (`#[cfg(unix)]`) verifying permissions, symlink
//!   refusal, and clean socket teardown.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use agentd::backend::{build_ustar_archive, InMemorySandboxBackend, LocalDevTreeBackend};
use agentd::error::decode_error_detail;
use agentd::proto::frame_service_server::FrameService;
use agentd::proto::system_service_server::SystemService;
use agentd::proto::world_service_server::WorldService;
use agentd::proto::{
    self, AcquireFenceRequest, AdvanceTimelineRequest, CheckpointRequest, CreateWorldRequest,
    DeleteFrameRequest, DeleteTimelineRequest, DestroyWorldRequest, DriverKind, ErrorCode,
    ExecRequest, ExportPatchRequest, FencingToken, FrameDurability, GetFrameRequest,
    GetWorldRequest, IdempotencyKey, ImportTarHeader, ImportTarRequest, ListFramesRequest,
    NegotiateVersionRequest, PinFrameRequest, PinSpec, RenewPinRequest, RenewWorldLeaseRequest,
    WorldStateKind,
};
use agentd::service::AgentdService;
use aos_meta::{FsArtifactBackend, ManualClock, MetaConfig, MetaEngine};
use aos_types::BootId;
use tokio_stream::StreamExt;
use tonic::Request;

static TEST_SEQ: AtomicU32 = AtomicU32::new(0);
const TEST_BOOT: &str = "33333333-3333-4333-8333-333333333333";

struct TestEnv {
    root: PathBuf,
    cfg: MetaConfig,
    tmpfs: PathBuf,
    clock: Arc<ManualClock>,
}

impl TestEnv {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "forkloom-agentd-{tag}-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::SeqCst)
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

    fn boot_service(&self) -> AgentdService {
        let boot = BootId::parse(TEST_BOOT).unwrap();
        let (engine, _) = MetaEngine::open_and_recover(
            self.cfg.clone(),
            boot,
            Box::new(FsArtifactBackend::new(&self.tmpfs)),
            self.clock.clone(),
        )
        .expect("open_and_recover");
        let tree = Arc::new(LocalDevTreeBackend::new(self.root.join("worlds")));
        let sandbox = Arc::new(InMemorySandboxBackend::new());
        AgentdService::new(engine, tree, sandbox)
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Drive `FrameService::import_tar` through a real `tokio::io::duplex` tonic transport so we test
/// actual client-streaming without opening any TCP port.
#[allow(clippy::result_large_err)]
async fn import_tar_over_duplex(
    svc: &AgentdService,
    header: ImportTarHeader,
    tar_bytes: Vec<u8>,
) -> Result<proto::ImportTarResponse, tonic::Status> {
    use agentd::proto::frame_service_client::FrameServiceClient;
    use agentd::proto::frame_service_server::FrameServiceServer;
    use hyper_util::rt::TokioIo;
    use tonic::transport::{Endpoint, Server, Uri};
    use tower::service_fn;

    let (client_io, server_io) = tokio::io::duplex(256 * 1024);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
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
async fn full_phase1_control_plane_lifecycle_and_fencing() {
    let env = TestEnv::new("lifecycle");
    let svc = env.boot_service();

    // 1. NegotiateVersion
    let neg = svc
        .negotiate_version(Request::new(NegotiateVersionRequest {
            client_name: "test".into(),
            client_version: "0.1.0".into(),
            supported_api_major: 1,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(neg.api_major, 1);
    assert_eq!(neg.daemon_epoch, 1);
    assert!(neg.enabled_drivers.contains(&"namespace".to_owned()));

    // Version skew rejected
    let skew = svc
        .negotiate_version(Request::new(NegotiateVersionRequest {
            client_name: "future".into(),
            client_version: "2.0.0".into(),
            supported_api_major: 99,
        }))
        .await
        .unwrap_err();
    assert_eq!(skew.code(), tonic::Code::FailedPrecondition);

    // 2. ImportTar -> Base Frame + atomic Timeline advance
    let tar = build_ustar_archive(&[("README.md", b"hello v1\n"), ("src/main.rs", b"fn main() {}\n")]);
    let imported = import_tar_over_duplex(
        &svc,
        ImportTarHeader {
            owner: "alice".into(),
            durability: FrameDurability::Durable as i32,
            parent_frame_id: String::new(),
            labels: HashMap::from([("repo".into(), "demo".into())]),
            pin: Some(PinSpec {
                pin_id: "base-pin".into(),
                owner: "alice".into(),
                lease_ttl_ms: 60_000,
            }),
            timeline_name: "main".into(),
            expected_old_timeline_head: String::new(),
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "import-1".into(),
            }),
        },
        tar,
    )
    .await
    .unwrap();
    let base_frame_id = imported.frame.as_ref().unwrap().frame_id.clone();
    assert_eq!(imported.timeline.as_ref().unwrap().head_frame_id, base_frame_id);

    // GetFrame & ListFrames & RenewPin
    let got = svc
        .get_frame(Request::new(GetFrameRequest {
            frame_id: base_frame_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .frame
        .unwrap();
    assert!(got.disk_clean);
    assert_eq!(got.holds.len(), 2); // TimelineHead + Pin

    let listed = svc
        .list_frames(Request::new(ListFramesRequest {
            owner: "alice".into(),
            label_selector: HashMap::from([("repo".into(), "demo".into())]),
            include_non_committed: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.frames.len(), 1);

    let renewed = svc
        .renew_pin(Request::new(RenewPinRequest {
            frame_id: base_frame_id.clone(),
            pin_id: "base-pin".into(),
            owner: "alice".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(renewed.expires_at_ms > 0);

    // 3. CreateWorld + Exec (streaming + idempotent replay + conflict)
    let created_world = svc
        .create_world(Request::new(CreateWorldRequest {
            owner: "alice".into(),
            base_frame_id: base_frame_id.clone(),
            driver: DriverKind::Namespace as i32,
            labels: HashMap::from([("task".into(), "patch".into())]),
            lease_ttl_ms: 60_000,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "world-1".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .world
        .unwrap();
    let wid = created_world.world_id.clone();
    let fence1 = created_world.fencing_token.unwrap().value;
    assert_eq!(fence1, 1);

    // Write a new file via streaming Exec with idempotency key
    let mut stream = svc
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence1 }),
            argv: vec!["write-file".into(), "src/new.rs".into(), "pub const X: i32 = 42;\n".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: true,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "exec-write-1".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let mut saw_chunk = false;
    let mut exec_res = None;
    while let Some(ev) = stream.next().await {
        match ev.unwrap().event.unwrap() {
            proto::exec_event::Event::Chunk(c) => {
                saw_chunk = true;
                assert!(String::from_utf8_lossy(&c.data).contains("wrote src/new.rs"));
            }
            proto::exec_event::Event::Result(r) => exec_res = Some(r),
        }
    }
    assert!(saw_chunk);
    assert_eq!(exec_res.as_ref().unwrap().exit_code, 0);
    assert!(!exec_res.as_ref().unwrap().replayed_from_cache);

    // Idempotent Exec replay returns cached result without re-running
    let mut replay_stream = svc
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence1 }),
            argv: vec!["write-file".into(), "src/new.rs".into(), "pub const X: i32 = 42;\n".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: true,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "exec-write-1".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    let replayed = replay_stream.next().await.unwrap().unwrap();
    match replayed.event.unwrap() {
        proto::exec_event::Event::Result(r) => assert!(r.replayed_from_cache),
        other => panic!("expected cached Result, got {other:?}"),
    }

    // Reusing same request_id with different argv -> IdempotencyConflict
    let conflict = svc
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence1 }),
            argv: vec!["echo".into(), "different".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: false,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "exec-write-1".into(),
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&conflict).unwrap().code,
        ErrorCode::IdempotencyConflict as i32
    );

    // 4. AcquireFence bumps token and fences out old caller!
    let fence2 = svc
        .acquire_fence(Request::new(AcquireFenceRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .fencing_token
        .unwrap()
        .value;
    assert_eq!(fence2, 2);

    let fenced = svc
        .renew_world_lease(Request::new(RenewWorldLeaseRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence1 }),
        }))
        .await
        .unwrap_err();
    let fd = decode_error_detail(&fenced).unwrap();
    assert_eq!(fd.code, ErrorCode::FencedOut as i32);
    assert_eq!(fd.presented_fencing_token, 1);
    assert_eq!(fd.current_fencing_token, 2);

    // Renew with current fence succeeds
    svc.renew_world_lease(Request::new(RenewWorldLeaseRequest {
        world_id: wid.clone(),
        owner: "alice".into(),
        fencing_token: Some(FencingToken { value: fence2 }),
    }))
    .await
    .unwrap();

    // 5. Unclean Checkpoint (`perform_syncfs=false`) -> ExportPatch MUST reject with DiskNotClean!
    let unclean_cp = svc
        .checkpoint(Request::new(CheckpointRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence2 }),
            durability: FrameDurability::Durable as i32,
            labels: HashMap::new(),
            pin: None,
            timeline_name: String::new(),
            expected_old_timeline_head: String::new(),
            perform_syncfs: false,
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .frame
        .unwrap();
    assert!(!unclean_cp.disk_clean);

    let unclean_err = svc
        .export_patch(Request::new(ExportPatchRequest {
            target_frame_id: unclean_cp.frame_id.clone(),
            base_frame_id: String::new(),
            owner: "alice".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&unclean_err).unwrap().code,
        ErrorCode::DiskNotClean as i32
    );

    // 6. Clean Checkpoint (`perform_syncfs=true`) + atomic Timeline CAS -> ExportPatch succeeds!
    let clean_cp = svc
        .checkpoint(Request::new(CheckpointRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence2 }),
            durability: FrameDurability::Durable as i32,
            labels: HashMap::new(),
            pin: None,
            timeline_name: "main".into(),
            expected_old_timeline_head: base_frame_id.clone(),
            perform_syncfs: true,
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner();
    let cp_frame_id = clean_cp.frame.unwrap().frame_id;
    assert_eq!(clean_cp.timeline.unwrap().head_frame_id, cp_frame_id);

    let patch = svc
        .export_patch(Request::new(ExportPatchRequest {
            target_frame_id: cp_frame_id.clone(),
            base_frame_id: String::new(),
            owner: "alice".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(patch.entries.len(), 1);
    assert_eq!(patch.entries[0].path, "src/new.rs");
    assert_eq!(patch.entries[0].kind, "add");
    assert!(String::from_utf8_lossy(&patch.unified_diff).contains("pub const X: i32 = 42;"));
    assert_eq!(patch.blake3_hex.len(), 64);

    // 7. Timeline CAS mismatch & DeleteTimeline & PinFrame & DestroyWorld & DeleteFrame
    let cas_err = svc
        .advance_timeline(Request::new(AdvanceTimelineRequest {
            timeline: "main".into(),
            owner: "alice".into(),
            expected_old_frame_id: base_frame_id.clone(), // stale head!
            new_head_frame_id: unclean_cp.frame_id.clone(),
            idempotency_key: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&cas_err).unwrap().code,
        ErrorCode::TimelineCasMismatch as i32
    );

    let del_tl = svc
        .delete_timeline(Request::new(DeleteTimelineRequest {
            timeline: "main".into(),
            owner: "alice".into(),
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(del_tl.released_head_frame_id, cp_frame_id);

    svc.pin_frame(Request::new(PinFrameRequest {
        frame_id: cp_frame_id.clone(),
        pin: Some(PinSpec {
            pin_id: "hold-cp".into(),
            owner: "alice".into(),
            lease_ttl_ms: 60_000,
        }),
    }))
    .await
    .unwrap();

    // Deleting pinned frame defers instead of destroying
    let deferred = svc
        .delete_frame(Request::new(DeleteFrameRequest {
            frame_id: cp_frame_id.clone(),
            owner: "alice".into(),
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!deferred.deleted && deferred.deferred && deferred.remaining_holds == 1);

    // Destroy world
    let destroyed = svc
        .destroy_world(Request::new(DestroyWorldRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence2 }),
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .world
        .unwrap();
    assert_eq!(destroyed.state, WorldStateKind::WorldStateDestroyed as i32);

    // Delete unheld unclean checkpoint succeeds immediately
    let del_ok = svc
        .delete_frame(Request::new(DeleteFrameRequest {
            frame_id: unclean_cp.frame_id,
            owner: "alice".into(),
            idempotency_key: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(del_ok.deleted && !del_ok.deferred);
}

#[tokio::test]
async fn daemon_restart_returns_explicit_world_lost_and_outcome_unknown() {
    let env = TestEnv::new("restart-lost");
    let svc1 = env.boot_service();

    let tar = build_ustar_archive(&[("app.txt", b"ok\n")]);
    let imp = import_tar_over_duplex(
        &svc1,
        ImportTarHeader {
            owner: "bob".into(),
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
    let fid = imp.frame.unwrap().frame_id;

    let w = svc1
        .create_world(Request::new(CreateWorldRequest {
            owner: "bob".into(),
            base_frame_id: fid,
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
    let wid = w.world_id;
    let fence = w.fencing_token.unwrap().value;

    // Simulate agentd crash & restart into epoch 2!
    drop(svc1);
    let svc2 = env.boot_service();
    assert_eq!(svc2.daemon_epoch(), 2);

    // GetWorld returns Lost tombstone
    let tomb = svc2
        .get_world(Request::new(GetWorldRequest {
            world_id: wid.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .world
        .unwrap();
    assert_eq!(tomb.state, WorldStateKind::WorldStateLost as i32);
    assert_eq!(tomb.origin_epoch, 1);
    assert_eq!(tomb.lost_in_epoch, 2);

    // Exec WITHOUT idempotency key -> explicit WorldLost
    let lost_err = svc2
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "bob".into(),
            fencing_token: Some(FencingToken { value: fence }),
            argv: vec!["echo".into(), "hi".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: false,
            idempotency_key: None,
        }))
        .await
        .unwrap_err();
    let d1 = decode_error_detail(&lost_err).unwrap();
    assert_eq!(d1.code, ErrorCode::WorldLost as i32);
    assert_eq!(d1.origin_epoch, 1);
    assert_eq!(d1.lost_in_epoch, 2);

    // Exec WITH idempotency key -> explicit OutcomeUnknown (NEVER auto-replayed!)
    let unknown_err = svc2
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "bob".into(),
            fencing_token: Some(FencingToken { value: fence }),
            argv: vec!["echo".into(), "hi".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: false,
            idempotency_key: Some(IdempotencyKey {
                owner: "bob".into(),
                request_id: "maybe-ran-before-crash".into(),
            }),
        }))
        .await
        .unwrap_err();
    let d2 = decode_error_detail(&unknown_err).unwrap();
    assert_eq!(d2.code, ErrorCode::OutcomeUnknown as i32);
}

#[tokio::test]
async fn import_tar_rejects_traversal_and_git_and_rolls_back_preparing_frame() {
    let env = TestEnv::new("unsafe-tar");
    let svc = env.boot_service();

    for bad_path in ["../escape.txt", ".git/config", "sub/.GIT/HEAD"] {
        let tar = build_ustar_archive(&[(bad_path, b"evil")]);
        let err = import_tar_over_duplex(
            &svc,
            ImportTarHeader {
                owner: "eve".into(),
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
        .unwrap_err();
        assert_eq!(
            decode_error_detail(&err).unwrap().code,
            ErrorCode::UnsafePatch as i32,
            "expected UnsafePatch for {bad_path}"
        );
    }

    // Zero leaked Preparing frames!
    let all = svc
        .list_frames(Request::new(ListFramesRequest {
            owner: String::new(),
            label_selector: HashMap::new(),
            include_non_committed: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(all.frames.is_empty(), "leaked frames: {:?}", all.frames);
}

#[tokio::test]
async fn idempotency_conflict_and_rollback_safety_across_import_checkpoint_world_and_exec() {
    let env = TestEnv::new("idem-hardening");
    let svc = env.boot_service();

    // 1. ImportTar idempotency: same key + same tar -> replay; same key + different tar -> IdempotencyConflict!
    let tar_a = build_ustar_archive(&[("a.txt", b"version-a\n")]);
    let tar_b = build_ustar_archive(&[("a.txt", b"version-b\n")]);
    let hdr = ImportTarHeader {
        owner: "alice".into(),
        durability: FrameDurability::Durable as i32,
        parent_frame_id: String::new(),
        labels: HashMap::new(),
        pin: None,
        timeline_name: String::new(),
        expected_old_timeline_head: String::new(),
        idempotency_key: Some(IdempotencyKey {
            owner: "alice".into(),
            request_id: "imp-idem-1".into(),
        }),
    };
    let imp1 = import_tar_over_duplex(&svc, hdr.clone(), tar_a.clone())
        .await
        .unwrap();
    let base_fid = imp1.frame.unwrap().frame_id;
    let imp_replay = import_tar_over_duplex(&svc, hdr.clone(), tar_a)
        .await
        .unwrap();
    assert_eq!(imp_replay.frame.unwrap().frame_id, base_fid);

    let imp_conflict = import_tar_over_duplex(&svc, hdr, tar_b).await.unwrap_err();
    assert_eq!(
        decode_error_detail(&imp_conflict).unwrap().code,
        ErrorCode::IdempotencyConflict as i32
    );

    // 2. CreateWorld with unsupported driver (Firecracker) must NOT poison idempotency key!
    let cw_idem = Some(IdempotencyKey {
        owner: "alice".into(),
        request_id: "cw-idem-1".into(),
    });
    let fc_err = svc
        .create_world(Request::new(CreateWorldRequest {
            owner: "alice".into(),
            base_frame_id: base_fid.clone(),
            driver: DriverKind::Firecracker as i32,
            labels: HashMap::new(),
            lease_ttl_ms: 60_000,
            idempotency_key: cw_idem.clone(),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&fc_err).unwrap().code,
        ErrorCode::DriverUnavailable as i32
    );

    // Retrying with the same key and Namespace driver succeeds and returns a RUNNING world!
    let w = svc
        .create_world(Request::new(CreateWorldRequest {
            owner: "alice".into(),
            base_frame_id: base_fid.clone(),
            driver: DriverKind::Namespace as i32,
            labels: HashMap::new(),
            lease_ttl_ms: 60_000,
            idempotency_key: cw_idem.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .world
        .unwrap();
    assert_eq!(w.state, WorldStateKind::WorldStateRunning as i32);
    let wid = w.world_id;
    let fence = w.fencing_token.unwrap().value;

    // Replaying CreateWorld with same key and different driver -> IdempotencyConflict
    let cw_driver_conflict = svc
        .create_world(Request::new(CreateWorldRequest {
            owner: "alice".into(),
            base_frame_id: base_fid.clone(),
            driver: DriverKind::Firecracker as i32,
            labels: HashMap::new(),
            lease_ttl_ms: 60_000,
            idempotency_key: cw_idem,
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&cw_driver_conflict).unwrap().code,
        ErrorCode::IdempotencyConflict as i32
    );

    // 3. Exec digest boundary collision check: argv=["echo", "A=1"], env={} vs argv=["echo"], env={"A":"1"}
    let mut s1 = svc
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence }),
            argv: vec!["echo".into(), "A=1".into()],
            env: HashMap::new(),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: false,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "exec-boundary-1".into(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();
    while s1.next().await.is_some() {}

    let boundary_err = svc
        .exec(Request::new(ExecRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence }),
            argv: vec!["echo".into()],
            env: HashMap::from([("A".into(), "1".into())]),
            cwd: String::new(),
            timeout_ms: 5_000,
            max_output_bytes: 4096,
            stream: false,
            idempotency_key: Some(IdempotencyKey {
                owner: "alice".into(),
                request_id: "exec-boundary-1".into(),
            }),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&boundary_err).unwrap().code,
        ErrorCode::IdempotencyConflict as i32
    );

    // 4. Checkpoint idempotency conflict on different perform_syncfs
    let cp_idem = Some(IdempotencyKey {
        owner: "alice".into(),
        request_id: "cp-idem-1".into(),
    });
    let cp1 = svc
        .checkpoint(Request::new(CheckpointRequest {
            world_id: wid.clone(),
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence }),
            durability: FrameDurability::Durable as i32,
            labels: HashMap::new(),
            pin: None,
            timeline_name: String::new(),
            expected_old_timeline_head: String::new(),
            perform_syncfs: true,
            idempotency_key: cp_idem.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .frame
        .unwrap();
    assert!(cp1.disk_clean);

    let cp_conflict = svc
        .checkpoint(Request::new(CheckpointRequest {
            world_id: wid,
            owner: "alice".into(),
            fencing_token: Some(FencingToken { value: fence }),
            durability: FrameDurability::Durable as i32,
            labels: HashMap::new(),
            pin: None,
            timeline_name: String::new(),
            expected_old_timeline_head: String::new(),
            perform_syncfs: false,
            idempotency_key: cp_idem,
        }))
        .await
        .unwrap_err();
    assert_eq!(
        decode_error_detail(&cp_conflict).unwrap().code,
        ErrorCode::IdempotencyConflict as i32
    );
}

#[cfg(unix)]
#[tokio::test]
async fn uds_transport_enforces_0600_perms_and_serves_grpc_end_to_end() {
    use std::os::unix::fs::PermissionsExt;

    use agentd::proto::system_service_client::SystemServiceClient;
    use agentd::transport::serve_uds;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;

    let env = TestEnv::new("uds-0600");
    let svc = env.boot_service();
    let sock_dir = env.root.join("run");
    let sock_path = sock_dir.join("agentd.sock");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let sp_server = sock_path.clone();
    let srv_handle = tokio::spawn(async move {
        serve_uds(&sp_server, svc, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // Wait for socket file
    for _ in 0..100 {
        if sock_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    let dir_mode = std::fs::symlink_metadata(&sock_dir).unwrap().permissions().mode() & 0o777;
    let sock_mode = std::fs::symlink_metadata(&sock_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700, "socket parent dir must be 0700");
    assert_eq!(sock_mode, 0o600, "agentd socket must be 0600");

    let sp_client = sock_path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let p = sp_client.clone();
            async move {
                let s = UnixStream::connect(&p).await?;
                Ok::<_, std::io::Error>(TokioIo::new(s))
            }
        }))
        .await
        .unwrap();

    let mut sys = SystemServiceClient::new(channel);
    let resp = sys
        .negotiate_version(NegotiateVersionRequest {
            client_name: "uds-test".into(),
            client_version: "0.1.0".into(),
            supported_api_major: 1,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.api_major, 1);
    assert_eq!(resp.daemon_epoch, 1);

    let _ = shutdown_tx.send(());
    srv_handle.await.unwrap().unwrap();
    assert!(!sock_path.exists(), "socket file should be removed on shutdown");

    // Also verify serve_uds refuses a symlinked parent directory!
    let real_dir = env.root.join("real-run");
    std::fs::create_dir_all(&real_dir).unwrap();
    let symlink_parent = env.root.join("symlink-run");
    std::os::unix::fs::symlink(&real_dir, &symlink_parent).unwrap();
    let bad_sock = symlink_parent.join("agentd.sock");
    let svc2 = env.boot_service();
    let sym_err = serve_uds(&bad_sock, svc2, async {}).await.unwrap_err();
    assert!(
        sym_err.to_string().contains("symlinked socket parent"),
        "expected symlinked parent rejection, got: {sym_err:#}"
    );
}
