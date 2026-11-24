"""Thin synchronous gRPC client for Forkloom (`SystemService`, `FrameService`, `WorldService`)."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from typing import BinaryIO

import grpc

from ._proto.forkloom.v1 import runtime_pb2 as pb
from ._proto.forkloom.v1 import runtime_pb2_grpc as pb_grpc
from .errors import (
    ForkloomError,
    NotNegotiatedError,
    VersionSkewError,
    decode_grpc_error,
)
from .types import (
    CLIENT_VERSION,
    DEFAULT_CLIENT_NAME,
    SUPPORTED_API_MAJOR,
    FencingTokenInput,
    fencing_token as make_fencing_token,
    normalize_target,
)

TarPayload = bytes | bytearray | memoryview | BinaryIO | Iterable[bytes]

DEFAULT_IMPORT_CHUNK_SIZE: int = 64 * 1024


def _iter_tar_chunks(payload: TarPayload, chunk_size: int) -> Iterator[bytes]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")

    if isinstance(payload, (bytes, bytearray, memoryview)):
        view = memoryview(payload)
        for offset in range(0, len(view), chunk_size):
            yield bytes(view[offset : offset + chunk_size])
        return

    read_fn = getattr(payload, "read", None)
    if callable(read_fn):
        while True:
            chunk = read_fn(chunk_size)
            if not chunk:
                break
            if isinstance(chunk, (bytearray, memoryview)):
                chunk = bytes(chunk)
            yield chunk
        return

    for chunk in payload:  # type: ignore[union-attr]
        if not chunk:
            continue
        if isinstance(chunk, (bytearray, memoryview)):
            chunk = bytes(chunk)
        if len(chunk) <= chunk_size:
            yield chunk
        else:
            view = memoryview(chunk)
            for offset in range(0, len(view), chunk_size):
                yield bytes(view[offset : offset + chunk_size])


class ForkloomClient:
    """Thin gRPC client for `agentd`'s `forkloom.v1` services over Unix Domain Socket.

    By default, connects to ``$FORKLOOM_SOCKET`` or ``unix:///run/forkloom/agentd.sock``
    and performs the mandatory `SystemService.NegotiateVersion` handshake verifying
    ``api_major == 1`` before issuing stateful RPCs.
    """

    def __init__(
        self,
        target: str | os.PathLike[str] | None = None,
        *,
        client_name: str = DEFAULT_CLIENT_NAME,
        client_version: str = CLIENT_VERSION,
        timeout: float | None = None,
        auto_negotiate: bool = True,
        channel: grpc.Channel | None = None,
        channel_options: Sequence[tuple[str, object]] | None = None,
    ) -> None:
        self.target: str = normalize_target(target)
        self.client_name: str = client_name
        self.client_version: str = client_version
        self.default_timeout: float | None = timeout
        self._auto_negotiate: bool = auto_negotiate
        self._owns_channel: bool = channel is None
        self._channel: grpc.Channel = (
            channel
            if channel is not None
            else grpc.insecure_channel(
                self.target,
                options=list(channel_options) if channel_options else None,
            )
        )
        self._system = pb_grpc.SystemServiceStub(self._channel)
        self._frames = pb_grpc.FrameServiceStub(self._channel)
        self._worlds = pb_grpc.WorldServiceStub(self._channel)
        self._server_info: pb.NegotiateVersionResponse | None = None

    @classmethod
    def connect(
        cls,
        target: str | os.PathLike[str] | None = None,
        *,
        client_name: str = DEFAULT_CLIENT_NAME,
        client_version: str = CLIENT_VERSION,
        timeout: float | None = None,
        auto_negotiate: bool = True,
        channel: grpc.Channel | None = None,
        channel_options: Sequence[tuple[str, object]] | None = None,
    ) -> ForkloomClient:
        """Create a client and immediately execute the mandatory `NegotiateVersion` handshake."""
        client = cls(
            target,
            client_name=client_name,
            client_version=client_version,
            timeout=timeout,
            auto_negotiate=auto_negotiate,
            channel=channel,
            channel_options=channel_options,
        )
        try:
            client.negotiate_version(timeout=timeout)
        except Exception:
            client.close()
            raise
        return client

    @property
    def server_info(self) -> pb.NegotiateVersionResponse | None:
        """Cached `NegotiateVersionResponse` from the last successful handshake."""
        return self._server_info

    def close(self) -> None:
        """Close the underlying gRPC channel if owned by this client."""
        if self._owns_channel:
            self._channel.close()

    def __enter__(self) -> ForkloomClient:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _effective_timeout(self, timeout: float | None) -> float | None:
        return self.default_timeout if timeout is None else timeout

    def _ensure_negotiated(self, timeout: float | None = None) -> None:
        if self._server_info is not None:
            return
        if self._auto_negotiate:
            self.negotiate_version(timeout=timeout)
            return
        raise NotNegotiatedError(
            "negotiate_version() must succeed before issuing stateful Forkloom RPCs"
        )

    # =========================================================================
    # SystemService (1 RPC)
    # =========================================================================

    def negotiate_version(
        self,
        *,
        client_name: str | None = None,
        client_version: str | None = None,
        supported_api_major: int = SUPPORTED_API_MAJOR,
        timeout: float | None = None,
    ) -> pb.NegotiateVersionResponse:
        """Perform `SystemService.NegotiateVersion` and enforce ``api_major == 1``."""
        req = pb.NegotiateVersionRequest(
            client_name=client_name or self.client_name,
            client_version=client_version or self.client_version,
            supported_api_major=supported_api_major,
        )
        try:
            resp = self._system.NegotiateVersion(
                req,
                timeout=self._effective_timeout(timeout),
            )
        except grpc.RpcError as exc:
            err = decode_grpc_error(exc)
            if exc.code() == grpc.StatusCode.FAILED_PRECONDITION and (
                "api_major" in err.message.lower()
                or "version" in err.message.lower()
            ):
                raise VersionSkewError(
                    err.message,
                    supported_api_major=supported_api_major,
                    grpc_code=err.grpc_code,
                    detail=err.detail,
                    cause=exc,
                ) from exc
            raise err from exc

        if resp.api_major != SUPPORTED_API_MAJOR:
            raise VersionSkewError(
                f"Incompatible Forkloom daemon API major version: daemon serves "
                f"v{resp.api_major}.{resp.api_minor} (daemon_version={resp.daemon_version!r}), "
                f"client requires api_major == {SUPPORTED_API_MAJOR}",
                daemon_api_major=int(resp.api_major),
                supported_api_major=SUPPORTED_API_MAJOR,
                daemon_version=resp.daemon_version,
            )

        self._server_info = resp
        return resp

    # =========================================================================
    # FrameService (9 RPCs)
    # =========================================================================

    def import_tar(
        self,
        owner: str,
        tar_data: TarPayload,
        *,
        durability: int = pb.FRAME_DURABILITY_DURABLE,
        parent_frame_id: str = "",
        labels: Mapping[str, str] | None = None,
        pin: pb.PinSpec | None = None,
        timeline_name: str = "",
        expected_old_timeline_head: str = "",
        idempotency_key: pb.IdempotencyKey | None = None,
        chunk_size: int = DEFAULT_IMPORT_CHUNK_SIZE,
        timeout: float | None = None,
    ) -> pb.ImportTarResponse:
        """Stream a tar archive into a new immutable Frame (`FrameService.ImportTar`)."""
        self._ensure_negotiated(timeout=timeout)
        header = pb.ImportTarHeader(
            owner=owner,
            durability=durability,
            parent_frame_id=parent_frame_id,
            labels=dict(labels) if labels else None,
            pin=pin,
            timeline_name=timeline_name,
            expected_old_timeline_head=expected_old_timeline_head,
            idempotency_key=idempotency_key,
        )

        def _request_stream() -> Iterator[pb.ImportTarRequest]:
            yield pb.ImportTarRequest(header=header)
            for chunk in _iter_tar_chunks(tar_data, chunk_size):
                yield pb.ImportTarRequest(data=chunk)

        try:
            return self._frames.ImportTar(
                _request_stream(),
                timeout=self._effective_timeout(timeout),
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def get_frame(
        self,
        frame_id: str,
        *,
        timeout: float | None = None,
    ) -> pb.GetFrameResponse:
        """Fetch metadata and holds for a Frame (`FrameService.GetFrame`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.GetFrameRequest(frame_id=frame_id)
        try:
            return self._frames.GetFrame(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def list_frames(
        self,
        *,
        owner: str = "",
        label_selector: Mapping[str, str] | None = None,
        include_non_committed: bool = False,
        timeout: float | None = None,
    ) -> pb.ListFramesResponse:
        """List frames filtered by owner/labels (`FrameService.ListFrames`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.ListFramesRequest(
            owner=owner,
            label_selector=dict(label_selector) if label_selector else None,
            include_non_committed=include_non_committed,
        )
        try:
            return self._frames.ListFrames(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def pin_frame(
        self,
        frame_id: str,
        pin: pb.PinSpec,
        *,
        timeout: float | None = None,
    ) -> pb.PinFrameResponse:
        """Attach a GC-preventing pin lease to a Frame (`FrameService.PinFrame`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.PinFrameRequest(frame_id=frame_id, pin=pin)
        try:
            return self._frames.PinFrame(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def renew_pin(
        self,
        frame_id: str,
        pin_id: str,
        owner: str,
        *,
        timeout: float | None = None,
    ) -> pb.RenewPinResponse:
        """Renew an existing pin lease (`FrameService.RenewPin`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.RenewPinRequest(frame_id=frame_id, pin_id=pin_id, owner=owner)
        try:
            return self._frames.RenewPin(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def delete_frame(
        self,
        frame_id: str,
        owner: str,
        *,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.DeleteFrameResponse:
        """Delete or defer-reclaim a Frame (`FrameService.DeleteFrame`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.DeleteFrameRequest(
            frame_id=frame_id,
            owner=owner,
            idempotency_key=idempotency_key,
        )
        try:
            return self._frames.DeleteFrame(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def advance_timeline(
        self,
        timeline: str,
        owner: str,
        new_head_frame_id: str,
        *,
        expected_old_frame_id: str = "",
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.AdvanceTimelineResponse:
        """CAS-advance a Timeline head to a Durable Frame (`FrameService.AdvanceTimeline`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.AdvanceTimelineRequest(
            timeline=timeline,
            owner=owner,
            expected_old_frame_id=expected_old_frame_id,
            new_head_frame_id=new_head_frame_id,
            idempotency_key=idempotency_key,
        )
        try:
            return self._frames.AdvanceTimeline(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def delete_timeline(
        self,
        timeline: str,
        owner: str,
        *,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.DeleteTimelineResponse:
        """Delete a Timeline and release its head hold (`FrameService.DeleteTimeline`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.DeleteTimelineRequest(
            timeline=timeline,
            owner=owner,
            idempotency_key=idempotency_key,
        )
        try:
            return self._frames.DeleteTimeline(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def export_patch(
        self,
        target_frame_id: str,
        owner: str,
        *,
        base_frame_id: str = "",
        timeout: float | None = None,
    ) -> pb.ExportPatchResponse:
        """Export a validated unified diff patch between two Frames (`FrameService.ExportPatch`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.ExportPatchRequest(
            target_frame_id=target_frame_id,
            base_frame_id=base_frame_id,
            owner=owner,
        )
        try:
            return self._frames.ExportPatch(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    # =========================================================================
    # WorldService (7 RPCs)
    # =========================================================================

    def create_world(
        self,
        owner: str,
        base_frame_id: str,
        *,
        driver: int = pb.DRIVER_KIND_NAMESPACE,
        labels: Mapping[str, str] | None = None,
        lease_ttl_ms: int = 0,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.CreateWorldResponse:
        """Create a stateful sandbox World from a Base Frame (`WorldService.CreateWorld`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.CreateWorldRequest(
            owner=owner,
            base_frame_id=base_frame_id,
            driver=driver,
            labels=dict(labels) if labels else None,
            lease_ttl_ms=lease_ttl_ms,
            idempotency_key=idempotency_key,
        )
        try:
            return self._worlds.CreateWorld(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def get_world(
        self,
        world_id: str,
        *,
        timeout: float | None = None,
    ) -> pb.GetWorldResponse:
        """Fetch World state, epoch, and fencing token (`WorldService.GetWorld`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.GetWorldRequest(world_id=world_id)
        try:
            return self._worlds.GetWorld(req, timeout=self._effective_timeout(timeout))
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def destroy_world(
        self,
        world_id: str,
        owner: str,
        fencing_token: FencingTokenInput,
        *,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.DestroyWorldResponse:
        """Destroy a running World (`WorldService.DestroyWorld`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.DestroyWorldRequest(
            world_id=world_id,
            owner=owner,
            fencing_token=make_fencing_token(fencing_token),
            idempotency_key=idempotency_key,
        )
        try:
            return self._worlds.DestroyWorld(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def acquire_fence(
        self,
        world_id: str,
        owner: str,
        *,
        timeout: float | None = None,
    ) -> pb.AcquireFenceResponse:
        """Monotonically bump a World's fencing token (`WorldService.AcquireFence`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.AcquireFenceRequest(world_id=world_id, owner=owner)
        try:
            return self._worlds.AcquireFence(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def renew_world_lease(
        self,
        world_id: str,
        owner: str,
        fencing_token: FencingTokenInput,
        *,
        timeout: float | None = None,
    ) -> pb.RenewWorldLeaseResponse:
        """Renew a World's lease TTL (`WorldService.RenewWorldLease`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.RenewWorldLeaseRequest(
            world_id=world_id,
            owner=owner,
            fencing_token=make_fencing_token(fencing_token),
        )
        try:
            return self._worlds.RenewWorldLease(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc

    def exec(
        self,
        world_id: str,
        owner: str,
        fencing_token: FencingTokenInput,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str = "",
        timeout_ms: int = 0,
        max_output_bytes: int = 0,
        stream: bool = True,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> Iterator[pb.ExecEvent]:
        """Execute a command in a World and stream `ExecEvent` messages (`WorldService.Exec`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.ExecRequest(
            world_id=world_id,
            owner=owner,
            fencing_token=make_fencing_token(fencing_token),
            argv=list(argv),
            env=dict(env) if env else None,
            cwd=cwd,
            timeout_ms=timeout_ms,
            max_output_bytes=max_output_bytes,
            stream=stream,
            idempotency_key=idempotency_key,
        )

        def _event_stream() -> Iterator[pb.ExecEvent]:
            try:
                call = self._worlds.Exec(req, timeout=self._effective_timeout(timeout))
                for event in call:
                    yield event
            except grpc.RpcError as exc:
                raise decode_grpc_error(exc) from exc

        return _event_stream()

    def exec_collect(
        self,
        world_id: str,
        owner: str,
        fencing_token: FencingTokenInput,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        cwd: str = "",
        timeout_ms: int = 0,
        max_output_bytes: int = 0,
        stream: bool = True,
        idempotency_key: pb.IdempotencyKey | None = None,
        on_chunk: Callable[[pb.ExecOutputChunk], None] | None = None,
        timeout: float | None = None,
    ) -> pb.ExecResult:
        """Consume an `Exec` stream, optionally invoking `on_chunk`, and return `ExecResult`."""
        terminal: pb.ExecResult | None = None
        for event in self.exec(
            world_id,
            owner,
            fencing_token,
            argv,
            env=env,
            cwd=cwd,
            timeout_ms=timeout_ms,
            max_output_bytes=max_output_bytes,
            stream=stream,
            idempotency_key=idempotency_key,
            timeout=timeout,
        ):
            kind = event.WhichOneof("event")
            if kind == "chunk" and on_chunk is not None:
                on_chunk(event.chunk)
            elif kind == "result":
                terminal = event.result
        if terminal is None:
            raise ForkloomError("Exec stream terminated without a terminal ExecResult")
        return terminal

    def checkpoint(
        self,
        world_id: str,
        owner: str,
        fencing_token: FencingTokenInput,
        *,
        durability: int = pb.FRAME_DURABILITY_DURABLE,
        labels: Mapping[str, str] | None = None,
        pin: pb.PinSpec | None = None,
        timeline_name: str = "",
        expected_old_timeline_head: str = "",
        perform_syncfs: bool = False,
        idempotency_key: pb.IdempotencyKey | None = None,
        timeout: float | None = None,
    ) -> pb.CheckpointResponse:
        """Snapshot a World into a new immutable Frame (`WorldService.Checkpoint`)."""
        self._ensure_negotiated(timeout=timeout)
        req = pb.CheckpointRequest(
            world_id=world_id,
            owner=owner,
            fencing_token=make_fencing_token(fencing_token),
            durability=durability,
            labels=dict(labels) if labels else None,
            pin=pin,
            timeline_name=timeline_name,
            expected_old_timeline_head=expected_old_timeline_head,
            perform_syncfs=perform_syncfs,
            idempotency_key=idempotency_key,
        )
        try:
            return self._worlds.Checkpoint(
                req, timeout=self._effective_timeout(timeout)
            )
        except grpc.RpcError as exc:
            raise decode_grpc_error(exc) from exc
