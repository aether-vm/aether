"""In-process mock gRPC tests covering all 17 RPCs, streaming, version skew, and ErrorDetail."""

from __future__ import annotations

import io
import os
import tempfile
from concurrent import futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import grpc
import pytest

from forkloom_vm import (
    CLIENT_VERSION,
    DEFAULT_SOCKET_PATH,
    DEFAULT_TARGET,
    ERROR_CODE_ASCII_KEY,
    ERROR_DETAIL_BIN_KEY,
    SUPPORTED_API_MAJOR,
    DiskNotCleanError,
    DriverKind,
    ErrorCode,
    FencedOutError,
    ForkloomClient,
    ForkloomError,
    FrameDurability,
    FrameNotFoundError,
    FrameStateKind,
    IdempotencyConflictError,
    NotNegotiatedError,
    OutcomeUnknownError,
    OutputStreamKind,
    TimelineCasMismatchError,
    UnsafePatchError,
    VersionSkewError,
    WorldLostError,
    WorldNotFoundError,
    WorldStateKind,
    fencing_token,
    idempotency_key,
    normalize_target,
    pb,
    pin_spec,
)
from forkloom_vm._proto.forkloom.v1 import runtime_pb2_grpc as pb_grpc


def _abort_with_detail(
    context: grpc.ServicerContext,
    grpc_code: grpc.StatusCode,
    detail: pb.ErrorDetail,
    *,
    include_bin: bool = True,
    include_ascii: bool = True,
) -> None:
    trailing: list[tuple[str, str | bytes]] = []
    if include_bin:
        trailing.append((ERROR_DETAIL_BIN_KEY, detail.SerializeToString()))
    if include_ascii:
        trailing.append((ERROR_CODE_ASCII_KEY, pb.ErrorCode.Name(detail.code)))
    context.set_trailing_metadata(trailing)
    context.abort(grpc_code, detail.message)


@dataclass
class MockState:
    api_major: int = 1
    api_minor: int = 0
    daemon_version: str = "0.1.0-alpha.0"
    daemon_epoch: int = 7
    enabled_drivers: list[str] = field(default_factory=lambda: ["namespace", "firecracker"])
    negotiate_calls: int = 0
    imported_bytes: bytes = b""
    imported_header: pb.ImportTarHeader | None = None
    next_error: tuple[grpc.StatusCode, pb.ErrorDetail, bool, bool] | None = None
    exec_stream_error_after_first_chunk: tuple[grpc.StatusCode, pb.ErrorDetail] | None = None
    recorded_calls: list[str] = field(default_factory=list)


class MockAgentd(
    pb_grpc.SystemServiceServicer,
    pb_grpc.FrameServiceServicer,
    pb_grpc.WorldServiceServicer,
):
    def __init__(self, state: MockState) -> None:
        self.state = state

    def _maybe_fail(self, context: grpc.ServicerContext) -> None:
        if self.state.next_error is not None:
            grpc_code, detail, inc_bin, inc_ascii = self.state.next_error
            self.state.next_error = None
            _abort_with_detail(
                context,
                grpc_code,
                detail,
                include_bin=inc_bin,
                include_ascii=inc_ascii,
            )

    def _sample_frame(self, frame_id: str = "frm_01", owner: str = "alice") -> pb.FrameInfo:
        return pb.FrameInfo(
            frame_id=frame_id,
            owner=owner,
            durability=FrameDurability.FRAME_DURABILITY_DURABLE,
            state=FrameStateKind.FRAME_STATE_COMMITTED,
            parent_frame_id="frm_00",
            labels={"env": "test"},
            disk_clean=True,
            created_epoch=self.state.daemon_epoch,
            committed_at_ms=1_700_000_000_000,
            objects=["rootfs.subvol"],
            holds=[pb.HoldInfo(kind="pin", detail="p1", expires_at_ms=1_700_000_060_000)],
            marked_for_reclaim=False,
        )

    def _sample_world(self, world_id: str = "wld_01", owner: str = "alice") -> pb.WorldInfo:
        return pb.WorldInfo(
            world_id=world_id,
            owner=owner,
            base_frame_id="frm_01",
            driver=DriverKind.DRIVER_KIND_NAMESPACE,
            state=WorldStateKind.WORLD_STATE_RUNNING,
            labels={"task": "swe"},
            fencing_token=pb.FencingToken(value=1),
            origin_epoch=self.state.daemon_epoch,
        )

    # SystemService
    def NegotiateVersion(
        self,
        request: pb.NegotiateVersionRequest,
        context: grpc.ServicerContext,
    ) -> pb.NegotiateVersionResponse:
        self.state.negotiate_calls += 1
        self.state.recorded_calls.append("NegotiateVersion")
        self._maybe_fail(context)
        return pb.NegotiateVersionResponse(
            daemon_version=self.state.daemon_version,
            api_major=self.state.api_major,
            api_minor=self.state.api_minor,
            daemon_epoch=self.state.daemon_epoch,
            enabled_drivers=self.state.enabled_drivers,
        )

    # FrameService
    def ImportTar(
        self,
        request_iterator: Iterator[pb.ImportTarRequest],
        context: grpc.ServicerContext,
    ) -> pb.ImportTarResponse:
        self.state.recorded_calls.append("ImportTar")
        self._maybe_fail(context)
        chunks: list[bytes] = []
        header: pb.ImportTarHeader | None = None
        for idx, msg in enumerate(request_iterator):
            which = msg.WhichOneof("chunk")
            if idx == 0:
                assert which == "header", "first ImportTarRequest must carry header"
                header = msg.header
            else:
                assert which == "data", "subsequent ImportTarRequest must carry data"
                chunks.append(msg.data)
        assert header is not None
        payload = b"".join(chunks)
        self.state.imported_header = header
        self.state.imported_bytes = payload
        tl = (
            pb.TimelineInfo(name=header.timeline_name, owner=header.owner, head_frame_id="frm_imported")
            if header.timeline_name
            else None
        )
        return pb.ImportTarResponse(
            frame=self._sample_frame("frm_imported", header.owner),
            timeline=tl,
            bytes_received=len(payload),
        )

    def GetFrame(
        self, request: pb.GetFrameRequest, context: grpc.ServicerContext
    ) -> pb.GetFrameResponse:
        self.state.recorded_calls.append("GetFrame")
        self._maybe_fail(context)
        return pb.GetFrameResponse(frame=self._sample_frame(request.frame_id))

    def ListFrames(
        self, request: pb.ListFramesRequest, context: grpc.ServicerContext
    ) -> pb.ListFramesResponse:
        self.state.recorded_calls.append("ListFrames")
        self._maybe_fail(context)
        return pb.ListFramesResponse(
            frames=[self._sample_frame("frm_01", request.owner or "alice")]
        )

    def PinFrame(
        self, request: pb.PinFrameRequest, context: grpc.ServicerContext
    ) -> pb.PinFrameResponse:
        self.state.recorded_calls.append("PinFrame")
        self._maybe_fail(context)
        return pb.PinFrameResponse(
            hold=pb.HoldInfo(
                kind="pin",
                detail=f"{request.pin.pin_id} (owner={request.pin.owner})",
                expires_at_ms=request.pin.lease_ttl_ms + 1_700_000_000_000,
            )
        )

    def RenewPin(
        self, request: pb.RenewPinRequest, context: grpc.ServicerContext
    ) -> pb.RenewPinResponse:
        self.state.recorded_calls.append("RenewPin")
        self._maybe_fail(context)
        return pb.RenewPinResponse(expires_at_ms=1_700_000_120_000, persisted_to_disk=True)

    def DeleteFrame(
        self, request: pb.DeleteFrameRequest, context: grpc.ServicerContext
    ) -> pb.DeleteFrameResponse:
        self.state.recorded_calls.append("DeleteFrame")
        self._maybe_fail(context)
        return pb.DeleteFrameResponse(deleted=True, deferred=False, remaining_holds=0)

    def AdvanceTimeline(
        self, request: pb.AdvanceTimelineRequest, context: grpc.ServicerContext
    ) -> pb.AdvanceTimelineResponse:
        self.state.recorded_calls.append("AdvanceTimeline")
        self._maybe_fail(context)
        return pb.AdvanceTimelineResponse(
            timeline=pb.TimelineInfo(
                name=request.timeline,
                owner=request.owner,
                head_frame_id=request.new_head_frame_id,
            ),
            previous_head_frame_id=request.expected_old_frame_id,
        )

    def DeleteTimeline(
        self, request: pb.DeleteTimelineRequest, context: grpc.ServicerContext
    ) -> pb.DeleteTimelineResponse:
        self.state.recorded_calls.append("DeleteTimeline")
        self._maybe_fail(context)
        return pb.DeleteTimelineResponse(released_head_frame_id="frm_01")

    def ExportPatch(
        self, request: pb.ExportPatchRequest, context: grpc.ServicerContext
    ) -> pb.ExportPatchResponse:
        self.state.recorded_calls.append("ExportPatch")
        self._maybe_fail(context)
        return pb.ExportPatchResponse(
            base_frame_id=request.base_frame_id or "frm_00",
            target_frame_id=request.target_frame_id,
            unified_diff=b"--- a/hello.txt\n+++ b/hello.txt\n@@ -1 +1 @@\n-old\n+new\n",
            entries=[pb.PatchEntry(path="hello.txt", kind="modify", size_bytes=4)],
            blake3_hex="a" * 64,
        )

    # WorldService
    def CreateWorld(
        self, request: pb.CreateWorldRequest, context: grpc.ServicerContext
    ) -> pb.CreateWorldResponse:
        self.state.recorded_calls.append("CreateWorld")
        self._maybe_fail(context)
        return pb.CreateWorldResponse(world=self._sample_world("wld_created", request.owner))

    def GetWorld(
        self, request: pb.GetWorldRequest, context: grpc.ServicerContext
    ) -> pb.GetWorldResponse:
        self.state.recorded_calls.append("GetWorld")
        self._maybe_fail(context)
        return pb.GetWorldResponse(world=self._sample_world(request.world_id))

    def DestroyWorld(
        self, request: pb.DestroyWorldRequest, context: grpc.ServicerContext
    ) -> pb.DestroyWorldResponse:
        self.state.recorded_calls.append("DestroyWorld")
        self._maybe_fail(context)
        w = self._sample_world(request.world_id, request.owner)
        w.state = WorldStateKind.WORLD_STATE_DESTROYED
        w.end_reason = "ClientRequested"
        return pb.DestroyWorldResponse(world=w)

    def AcquireFence(
        self, request: pb.AcquireFenceRequest, context: grpc.ServicerContext
    ) -> pb.AcquireFenceResponse:
        self.state.recorded_calls.append("AcquireFence")
        self._maybe_fail(context)
        return pb.AcquireFenceResponse(fencing_token=pb.FencingToken(value=2))

    def RenewWorldLease(
        self, request: pb.RenewWorldLeaseRequest, context: grpc.ServicerContext
    ) -> pb.RenewWorldLeaseResponse:
        self.state.recorded_calls.append("RenewWorldLease")
        self._maybe_fail(context)
        return pb.RenewWorldLeaseResponse(renewed_ttl_ms=600_000)

    def Exec(
        self, request: pb.ExecRequest, context: grpc.ServicerContext
    ) -> Iterator[pb.ExecEvent]:
        self.state.recorded_calls.append("Exec")
        self._maybe_fail(context)
        yield pb.ExecEvent(
            chunk=pb.ExecOutputChunk(
                stream=OutputStreamKind.OUTPUT_STREAM_STDOUT,
                seq=1,
                data=b"hello ",
            )
        )
        if self.state.exec_stream_error_after_first_chunk is not None:
            grpc_code, detail = self.state.exec_stream_error_after_first_chunk
            self.state.exec_stream_error_after_first_chunk = None
            _abort_with_detail(context, grpc_code, detail)
        yield pb.ExecEvent(
            chunk=pb.ExecOutputChunk(
                stream=OutputStreamKind.OUTPUT_STREAM_STDERR,
                seq=2,
                data=b"warn\n",
            )
        )
        yield pb.ExecEvent(
            chunk=pb.ExecOutputChunk(
                stream=OutputStreamKind.OUTPUT_STREAM_STDOUT,
                seq=3,
                data=b"world\n",
            )
        )
        yield pb.ExecEvent(
            result=pb.ExecResult(
                exec_id="exec_01",
                has_exit_code=True,
                exit_code=0,
                duration_ms=12,
                stdout=pb.BoundedOutput(head=b"hello world\n", total_bytes=12),
                stderr=pb.BoundedOutput(head=b"warn\n", total_bytes=5),
                replayed_from_cache=False,
            )
        )

    def Checkpoint(
        self, request: pb.CheckpointRequest, context: grpc.ServicerContext
    ) -> pb.CheckpointResponse:
        self.state.recorded_calls.append("Checkpoint")
        self._maybe_fail(context)
        tl = (
            pb.TimelineInfo(
                name=request.timeline_name,
                owner=request.owner,
                head_frame_id="frm_ckpt",
            )
            if request.timeline_name
            else None
        )
        return pb.CheckpointResponse(
            frame=self._sample_frame("frm_ckpt", request.owner),
            timeline=tl,
        )


@pytest.fixture()
def mock_server() -> Iterator[tuple[str, MockState]]:
    state = MockState()
    servicer = MockAgentd(state)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    pb_grpc.add_SystemServiceServicer_to_server(servicer, server)
    pb_grpc.add_FrameServiceServicer_to_server(servicer, server)
    pb_grpc.add_WorldServiceServicer_to_server(servicer, server)

    tmp_dir: tempfile.TemporaryDirectory[str] | None = None
    if os.name == "posix":
        tmp_dir = tempfile.TemporaryDirectory(prefix="forkloom-uds-")
        sock_path = Path(tmp_dir.name) / "agentd.sock"
        target = f"unix://{sock_path}"
        bound = server.add_insecure_port(target)
        assert bound != 0
    else:
        port = server.add_insecure_port("127.0.0.1:0")
        assert port != 0
        target = f"127.0.0.1:{port}"

    server.start()
    try:
        yield target, state
    finally:
        server.stop(grace=0).wait()
        if tmp_dir is not None:
            tmp_dir.cleanup()


def test_target_normalization_and_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORKLOOM_SOCKET", raising=False)
    assert normalize_target() == DEFAULT_TARGET
    assert normalize_target("/run/forkloom/agentd.sock") == DEFAULT_TARGET
    assert normalize_target("unix:///tmp/custom.sock") == "unix:///tmp/custom.sock"
    assert normalize_target("./local.sock") == "unix:./local.sock"
    assert normalize_target("127.0.0.1:50051") == "127.0.0.1:50051"

    monkeypatch.setenv("FORKLOOM_SOCKET", "/tmp/env-agentd.sock")
    assert normalize_target() == "unix:///tmp/env-agentd.sock"

    k1 = idempotency_key("alice")
    k2 = idempotency_key("alice", "req-1")
    assert k1.owner == "alice" and len(k1.request_id) == 32
    assert k2.owner == "alice" and k2.request_id == "req-1"
    with pytest.raises(ValueError):
        idempotency_key("", "req-1")

    tok = fencing_token(42)
    assert tok.value == 42
    assert fencing_token(tok).value == 42
    with pytest.raises(ValueError):
        fencing_token(0)
    with pytest.raises(ValueError):
        fencing_token(-1)

    pin = pin_spec("pin-1", "alice", 30_000)
    assert pin.pin_id == "pin-1"
    assert pin.lease_ttl_ms == 30_000
    assert DEFAULT_SOCKET_PATH == "/run/forkloom/agentd.sock"


def test_all_17_rpcs_and_streaming(mock_server: tuple[str, MockState]) -> None:
    target, state = mock_server

    with ForkloomClient.connect(target) as client:
        assert client.server_info is not None
        assert client.server_info.api_major == SUPPORTED_API_MAJOR
        assert client.server_info.daemon_epoch == 7
        assert state.negotiate_calls == 1

        # 2. ImportTar (client-streaming over bytes with multi-chunk split)
        tar_payload = b"tar-header" + (b"x" * 100) + b"tar-footer"
        imp = client.import_tar(
            "alice",
            io.BytesIO(tar_payload),
            durability=FrameDurability.FRAME_DURABILITY_DURABLE,
            labels={"repo": "forkloom"},
            pin=pin_spec("p-init", "alice", 60_000),
            timeline_name="main",
            idempotency_key=idempotency_key("alice", "imp-1"),
            chunk_size=32,
        )
        assert imp.frame.frame_id == "frm_imported"
        assert imp.timeline.name == "main"
        assert imp.bytes_received == len(tar_payload)
        assert state.imported_bytes == tar_payload
        assert state.imported_header is not None
        assert state.imported_header.owner == "alice"

        # 3. GetFrame
        gf = client.get_frame("frm_01")
        assert gf.frame.frame_id == "frm_01"

        # 4. ListFrames
        lf = client.list_frames(owner="alice", label_selector={"env": "test"})
        assert len(lf.frames) == 1

        # 5. PinFrame
        pf = client.pin_frame("frm_01", pin_spec("p2", "alice", 15_000))
        assert pf.hold.kind == "pin"

        # 6. RenewPin
        rp = client.renew_pin("frm_01", "p2", "alice")
        assert rp.persisted_to_disk is True

        # 7. AdvanceTimeline
        at = client.advance_timeline(
            "main",
            "alice",
            "frm_02",
            expected_old_frame_id="frm_01",
            idempotency_key=idempotency_key("alice", "adv-1"),
        )
        assert at.timeline.head_frame_id == "frm_02"
        assert at.previous_head_frame_id == "frm_01"

        # 8. DeleteTimeline
        dt = client.delete_timeline("main", "alice", idempotency_key=idempotency_key("alice", "dt-1"))
        assert dt.released_head_frame_id == "frm_01"

        # 9. ExportPatch
        ep = client.export_patch("frm_02", "alice", base_frame_id="frm_01")
        assert b"+new" in ep.unified_diff
        assert ep.entries[0].path == "hello.txt"

        # 10. DeleteFrame
        df = client.delete_frame("frm_01", "alice", idempotency_key=idempotency_key("alice", "df-1"))
        assert df.deleted is True

        # 11. CreateWorld
        cw = client.create_world(
            "alice",
            "frm_01",
            driver=DriverKind.DRIVER_KIND_NAMESPACE,
            labels={"run": "1"},
            lease_ttl_ms=60_000,
            idempotency_key=idempotency_key("alice", "cw-1"),
        )
        wid = cw.world.world_id
        tok = cw.world.fencing_token
        assert wid == "wld_created"
        assert tok.value == 1

        # 12. GetWorld
        gw = client.get_world(wid)
        assert gw.world.world_id == wid

        # 13. AcquireFence
        af = client.acquire_fence(wid, "alice")
        tok = af.fencing_token
        assert tok.value == 2

        # 14. RenewWorldLease
        rl = client.renew_world_lease(wid, "alice", tok)
        assert rl.renewed_ttl_ms == 600_000

        # 15. Exec (server-streaming)
        events = list(
            client.exec(
                wid,
                "alice",
                tok,
                ["/bin/echo", "hello world"],
                env={"FOO": "bar"},
                cwd="/workspace",
                timeout_ms=5_000,
                max_output_bytes=4096,
                stream=True,
                idempotency_key=idempotency_key("alice", "exec-1"),
            )
        )
        chunks = [e.chunk for e in events if e.WhichOneof("event") == "chunk"]
        results = [e.result for e in events if e.WhichOneof("event") == "result"]
        assert len(chunks) == 3
        assert b"".join(
            c.data for c in chunks if c.stream == OutputStreamKind.OUTPUT_STREAM_STDOUT
        ) == b"hello world\n"
        assert len(results) == 1
        assert results[0].exit_code == 0

        # Also test exec_collect convenience helper
        seen_chunks: list[bytes] = []
        res = client.exec_collect(
            wid,
            "alice",
            tok.value,
            ["/bin/true"],
            on_chunk=lambda c: seen_chunks.append(c.data),
        )
        assert res.exec_id == "exec_01"
        assert seen_chunks == [b"hello ", b"warn\n", b"world\n"]

        # 16. Checkpoint
        ck = client.checkpoint(
            wid,
            "alice",
            tok,
            durability=FrameDurability.FRAME_DURABILITY_DURABLE,
            timeline_name="main",
            perform_syncfs=True,
            idempotency_key=idempotency_key("alice", "ckpt-1"),
        )
        assert ck.frame.frame_id == "frm_ckpt"
        assert ck.timeline.name == "main"

        # 17. DestroyWorld
        dw = client.destroy_world(wid, "alice", tok, idempotency_key=idempotency_key("alice", "dw-1"))
        assert dw.world.state == WorldStateKind.WORLD_STATE_DESTROYED

    expected_rpcs = {
        "NegotiateVersion",
        "ImportTar",
        "GetFrame",
        "ListFrames",
        "PinFrame",
        "RenewPin",
        "DeleteFrame",
        "AdvanceTimeline",
        "DeleteTimeline",
        "ExportPatch",
        "CreateWorld",
        "GetWorld",
        "DestroyWorld",
        "AcquireFence",
        "RenewWorldLease",
        "Exec",
        "Checkpoint",
    }
    assert expected_rpcs.issubset(set(state.recorded_calls))
    assert len(expected_rpcs) == 17
    assert CLIENT_VERSION == "0.1.0a0"


def test_version_skew_and_mandatory_handshake(mock_server: tuple[str, MockState]) -> None:
    target, state = mock_server

    # auto_negotiate=False rejects stateful RPCs before negotiate_version()
    with ForkloomClient(target, auto_negotiate=False) as client:
        with pytest.raises(NotNegotiatedError):
            client.get_frame("frm_01")
        assert state.negotiate_calls == 0
        info = client.negotiate_version()
        assert info.api_major == 1
        assert client.get_frame("frm_01").frame.frame_id == "frm_01"

    # Server returning api_major != 1 raises VersionSkewError
    state.api_major = 2
    with ForkloomClient(target) as client:
        with pytest.raises(VersionSkewError) as exc_info:
            client.negotiate_version()
        assert exc_info.value.daemon_api_major == 2
        assert exc_info.value.supported_api_major == 1

    # Auto-negotiate on first RPC also catches version skew
    with ForkloomClient(target, auto_negotiate=True) as client:
        with pytest.raises(VersionSkewError):
            client.list_frames(owner="alice")


@pytest.mark.parametrize(
    ("grpc_code", "detail", "expected_cls"),
    [
        (
            grpc.StatusCode.FAILED_PRECONDITION,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_WORLD_LOST,
                message="world lost across restart",
                resource_id="wld_99",
                origin_epoch=3,
                lost_in_epoch=4,
            ),
            WorldLostError,
        ),
        (
            grpc.StatusCode.FAILED_PRECONDITION,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_OUTCOME_UNKNOWN,
                message="exec outcome unknown",
                resource_id="wld_99",
                origin_epoch=3,
                lost_in_epoch=4,
            ),
            OutcomeUnknownError,
        ),
        (
            grpc.StatusCode.FAILED_PRECONDITION,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_FENCED_OUT,
                message="stale fencing token",
                resource_id="wld_99",
                current_fencing_token=9,
                presented_fencing_token=4,
            ),
            FencedOutError,
        ),
        (
            grpc.StatusCode.ALREADY_EXISTS,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_IDEMPOTENCY_CONFLICT,
                message="idempotency conflict",
                resource_id="req-123",
            ),
            IdempotencyConflictError,
        ),
        (
            grpc.StatusCode.FAILED_PRECONDITION,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_DISK_NOT_CLEAN,
                message="disk not clean",
                resource_id="frm_dirty",
            ),
            DiskNotCleanError,
        ),
        (
            grpc.StatusCode.INVALID_ARGUMENT,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_UNSAFE_PATCH,
                message="path traversal rejected",
            ),
            UnsafePatchError,
        ),
        (
            grpc.StatusCode.ABORTED,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_TIMELINE_CAS_MISMATCH,
                message="cas mismatch",
                resource_id="main",
            ),
            TimelineCasMismatchError,
        ),
        (
            grpc.StatusCode.NOT_FOUND,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_FRAME_NOT_FOUND,
                message="frame missing",
                resource_id="frm_404",
            ),
            FrameNotFoundError,
        ),
    ],
)
def test_structured_error_detail_decoding(
    mock_server: tuple[str, MockState],
    grpc_code: grpc.StatusCode,
    detail: pb.ErrorDetail,
    expected_cls: type[ForkloomError],
) -> None:
    target, state = mock_server
    with ForkloomClient.connect(target) as client:
        state.next_error = (grpc_code, detail, True, True)
        with pytest.raises(expected_cls) as exc_info:
            client.get_frame("frm_01")
        err = exc_info.value
        assert err.grpc_code == grpc_code
        assert err.error_code == detail.code
        assert err.message == detail.message
        assert err.resource_id == detail.resource_id
        assert err.current_fencing_token == detail.current_fencing_token
        assert err.presented_fencing_token == detail.presented_fencing_token
        assert err.origin_epoch == detail.origin_epoch
        assert err.lost_in_epoch == detail.lost_in_epoch


def test_ascii_only_fallback_and_streaming_exec_error(
    mock_server: tuple[str, MockState],
) -> None:
    target, state = mock_server
    with ForkloomClient.connect(target) as client:
        # ASCII-only x-forkloom-error-code header fallback (no binary ErrorDetail)
        state.next_error = (
            grpc.StatusCode.NOT_FOUND,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_WORLD_NOT_FOUND,
                message="world not found ascii-only",
            ),
            False,
            True,
        )
        with pytest.raises(WorldNotFoundError) as exc_info:
            client.get_world("wld_missing")
        assert exc_info.value.error_code == ErrorCode.ERROR_CODE_WORLD_NOT_FOUND
        assert "world not found" in exc_info.value.message

        # Mid-stream error during Exec yields first chunk then raises OutcomeUnknownError
        state.exec_stream_error_after_first_chunk = (
            grpc.StatusCode.FAILED_PRECONDITION,
            pb.ErrorDetail(
                code=ErrorCode.ERROR_CODE_OUTCOME_UNKNOWN,
                message="daemon restarted mid-exec",
                resource_id="wld_01",
                origin_epoch=7,
                lost_in_epoch=8,
            ),
        )
        received: list[bytes] = []
        with pytest.raises(OutcomeUnknownError) as stream_exc:
            for ev in client.exec("wld_01", "alice", 1, ["/bin/sleep", "10"]):
                if ev.WhichOneof("event") == "chunk":
                    received.append(ev.chunk.data)
        assert received == [b"hello "]
        assert stream_exc.value.origin_epoch == 7
        assert stream_exc.value.lost_in_epoch == 8
