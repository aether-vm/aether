"""Structured Forkloom gRPC error hierarchy & `x-forkloom-error-bin` metadata decoder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple

import grpc
from google.protobuf.message import DecodeError

from ._proto.forkloom.v1 import runtime_pb2 as pb

#: Binary gRPC trailing metadata key carrying protobuf-encoded `forkloom.v1.ErrorDetail`.
ERROR_DETAIL_BIN_KEY: str = "x-forkloom-error-bin"
#: ASCII gRPC trailing metadata key carrying the canonical `ErrorCode` enum name.
ERROR_CODE_ASCII_KEY: str = "x-forkloom-error-code"


@dataclass(frozen=True)
class ErrorDetailInfo:
    """Decoded `forkloom.v1.ErrorDetail` payload extracted from gRPC status metadata."""

    code: int
    code_name: str
    message: str
    resource_id: str = ""
    current_fencing_token: int = 0
    presented_fencing_token: int = 0
    origin_epoch: int = 0
    lost_in_epoch: int = 0


class ForkloomError(Exception):
    """Base exception for all Forkloom client and daemon errors."""

    error_code: int = pb.ERROR_CODE_UNSPECIFIED

    def __init__(
        self,
        message: str,
        *,
        error_code: int | None = None,
        grpc_code: grpc.StatusCode | None = None,
        detail: ErrorDetailInfo | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.message: str = message
        self.error_code: int = (
            error_code if error_code is not None else type(self).error_code
        )
        self.grpc_code: grpc.StatusCode | None = grpc_code
        self.detail: ErrorDetailInfo | None = detail
        self.cause: BaseException | None = cause

    @property
    def resource_id(self) -> str:
        return self.detail.resource_id if self.detail is not None else ""

    @property
    def current_fencing_token(self) -> int:
        return self.detail.current_fencing_token if self.detail is not None else 0

    @property
    def presented_fencing_token(self) -> int:
        return self.detail.presented_fencing_token if self.detail is not None else 0

    @property
    def origin_epoch(self) -> int:
        return self.detail.origin_epoch if self.detail is not None else 0

    @property
    def lost_in_epoch(self) -> int:
        return self.detail.lost_in_epoch if self.detail is not None else 0


class VersionSkewError(ForkloomError):
    """Raised when `agentd` reports an incompatible `api_major` during `NegotiateVersion`."""

    def __init__(
        self,
        message: str,
        *,
        daemon_api_major: int | None = None,
        supported_api_major: int = 1,
        daemon_version: str = "",
        grpc_code: grpc.StatusCode | None = None,
        detail: ErrorDetailInfo | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(
            message,
            error_code=pb.ERROR_CODE_INVALID_ARGUMENT,
            grpc_code=grpc_code,
            detail=detail,
            cause=cause,
        )
        self.daemon_api_major = daemon_api_major
        self.supported_api_major = supported_api_major
        self.daemon_version = daemon_version


class NotNegotiatedError(ForkloomError):
    """Raised when a stateful RPC is issued before `negotiate_version()` completes."""


class WorldLostError(ForkloomError):
    """World died across an `agentd` crash/restart and will never be auto-replayed."""

    error_code = pb.ERROR_CODE_WORLD_LOST


class OutcomeUnknownError(ForkloomError):
    """Side-effecting `Exec` outcome across a daemon restart is explicitly unknown."""

    error_code = pb.ERROR_CODE_OUTCOME_UNKNOWN


class FencedOutError(ForkloomError):
    """Caller presented a stale fencing token after ownership takeover."""

    error_code = pb.ERROR_CODE_FENCED_OUT


class FrameNotFoundError(ForkloomError):
    error_code = pb.ERROR_CODE_FRAME_NOT_FOUND


class WorldNotFoundError(ForkloomError):
    error_code = pb.ERROR_CODE_WORLD_NOT_FOUND


class TimelineNotFoundError(ForkloomError):
    error_code = pb.ERROR_CODE_TIMELINE_NOT_FOUND


class TimelineCasMismatchError(ForkloomError):
    error_code = pb.ERROR_CODE_TIMELINE_CAS_MISMATCH


class IdempotencyConflictError(ForkloomError):
    error_code = pb.ERROR_CODE_IDEMPOTENCY_CONFLICT


class OwnerMismatchError(ForkloomError):
    error_code = pb.ERROR_CODE_OWNER_MISMATCH


class ResourceExhaustedError(ForkloomError):
    error_code = pb.ERROR_CODE_RESOURCE_EXHAUSTED


class UnsafePatchError(ForkloomError):
    error_code = pb.ERROR_CODE_UNSAFE_PATCH


class DiskNotCleanError(ForkloomError):
    error_code = pb.ERROR_CODE_DISK_NOT_CLEAN


class InvalidArgumentError(ForkloomError):
    error_code = pb.ERROR_CODE_INVALID_ARGUMENT


class DriverUnavailableError(ForkloomError):
    error_code = pb.ERROR_CODE_DRIVER_UNAVAILABLE


class WorldNotRunningError(ForkloomError):
    error_code = pb.ERROR_CODE_WORLD_NOT_RUNNING


class VolatileInTimelineForbiddenError(ForkloomError):
    error_code = pb.ERROR_CODE_VOLATILE_IN_TIMELINE_FORBIDDEN


class PinNotFoundError(ForkloomError):
    error_code = pb.ERROR_CODE_PIN_NOT_FOUND


class FrameMarkedForDeletionError(ForkloomError):
    error_code = pb.ERROR_CODE_FRAME_MARKED_FOR_DELETION


class PreparedFrameAbortedError(ForkloomError):
    error_code = pb.ERROR_CODE_PREPARED_FRAME_ABORTED


class InternalError(ForkloomError):
    error_code = pb.ERROR_CODE_INTERNAL


ERROR_CODE_CLASSES: dict[int, type[ForkloomError]] = {
    pb.ERROR_CODE_WORLD_LOST: WorldLostError,
    pb.ERROR_CODE_OUTCOME_UNKNOWN: OutcomeUnknownError,
    pb.ERROR_CODE_FENCED_OUT: FencedOutError,
    pb.ERROR_CODE_FRAME_NOT_FOUND: FrameNotFoundError,
    pb.ERROR_CODE_WORLD_NOT_FOUND: WorldNotFoundError,
    pb.ERROR_CODE_TIMELINE_NOT_FOUND: TimelineNotFoundError,
    pb.ERROR_CODE_TIMELINE_CAS_MISMATCH: TimelineCasMismatchError,
    pb.ERROR_CODE_IDEMPOTENCY_CONFLICT: IdempotencyConflictError,
    pb.ERROR_CODE_OWNER_MISMATCH: OwnerMismatchError,
    pb.ERROR_CODE_RESOURCE_EXHAUSTED: ResourceExhaustedError,
    pb.ERROR_CODE_UNSAFE_PATCH: UnsafePatchError,
    pb.ERROR_CODE_DISK_NOT_CLEAN: DiskNotCleanError,
    pb.ERROR_CODE_INVALID_ARGUMENT: InvalidArgumentError,
    pb.ERROR_CODE_DRIVER_UNAVAILABLE: DriverUnavailableError,
    pb.ERROR_CODE_WORLD_NOT_RUNNING: WorldNotRunningError,
    pb.ERROR_CODE_VOLATILE_IN_TIMELINE_FORBIDDEN: VolatileInTimelineForbiddenError,
    pb.ERROR_CODE_PIN_NOT_FOUND: PinNotFoundError,
    pb.ERROR_CODE_FRAME_MARKED_FOR_DELETION: FrameMarkedForDeletionError,
    pb.ERROR_CODE_PREPARED_FRAME_ABORTED: PreparedFrameAbortedError,
    pb.ERROR_CODE_INTERNAL: InternalError,
}


def error_code_name(code: int) -> str:
    """Return the canonical protobuf enum name for an ``ErrorCode`` integer."""
    try:
        return pb.ErrorCode.Name(code)
    except ValueError:
        return f"ERROR_CODE_UNKNOWN({code})"


def parse_error_code_name(raw_name: str) -> int:
    """Parse an ASCII `x-forkloom-error-code` value into an ``ErrorCode`` integer."""
    cleaned = raw_name.strip().upper()
    if not cleaned:
        return pb.ERROR_CODE_UNSPECIFIED
    candidates = [cleaned]
    if not cleaned.startswith("ERROR_CODE_"):
        candidates.append(f"ERROR_CODE_{cleaned}")
    for name in candidates:
        try:
            return int(pb.ErrorCode.Value(name))
        except ValueError:
            continue
    return pb.ERROR_CODE_UNSPECIFIED


def decode_error_detail(raw: bytes) -> ErrorDetailInfo:
    """Decode raw protobuf bytes from `x-forkloom-error-bin` into `ErrorDetailInfo`."""
    proto_detail = pb.ErrorDetail()
    proto_detail.ParseFromString(raw)
    return ErrorDetailInfo(
        code=int(proto_detail.code),
        code_name=error_code_name(int(proto_detail.code)),
        message=proto_detail.message,
        resource_id=proto_detail.resource_id,
        current_fencing_token=int(proto_detail.current_fencing_token),
        presented_fencing_token=int(proto_detail.presented_fencing_token),
        origin_epoch=int(proto_detail.origin_epoch),
        lost_in_epoch=int(proto_detail.lost_in_epoch),
    )


def _extract_metadata(
    exc: grpc.RpcError,
) -> tuple[bytes | None, str | None]:
    bin_val: bytes | None = None
    ascii_val: str | None = None

    sources: list[Iterable[Tuple[str, str | bytes]]] = []
    for attr in ("trailing_metadata", "initial_metadata"):
        getter = getattr(exc, attr, None)
        if callable(getter):
            md = getter()
            if md:
                sources.append(md)

    for md in sources:
        for key, value in md:
            lower_key = key.lower()
            if lower_key == ERROR_DETAIL_BIN_KEY and bin_val is None:
                if isinstance(value, bytes):
                    bin_val = value
                elif isinstance(value, str):
                    bin_val = value.encode("latin-1")
            elif lower_key == ERROR_CODE_ASCII_KEY and ascii_val is None:
                if isinstance(value, bytes):
                    ascii_val = value.decode("utf-8", errors="replace")
                else:
                    ascii_val = str(value)
    return bin_val, ascii_val


def decode_grpc_error(exc: grpc.RpcError) -> ForkloomError:
    """Convert a ``grpc.RpcError`` into the corresponding structured ``ForkloomError``."""
    grpc_code = exc.code() if hasattr(exc, "code") and callable(exc.code) else None
    grpc_details = (
        exc.details() if hasattr(exc, "details") and callable(exc.details) else None
    ) or str(exc)

    bin_val, ascii_val = _extract_metadata(exc)
    detail: ErrorDetailInfo | None = None
    code: int = pb.ERROR_CODE_UNSPECIFIED

    if bin_val is not None:
        try:
            detail = decode_error_detail(bin_val)
            code = detail.code
        except DecodeError:
            detail = None

    if code == pb.ERROR_CODE_UNSPECIFIED and ascii_val is not None:
        code = parse_error_code_name(ascii_val)
        if detail is None and code != pb.ERROR_CODE_UNSPECIFIED:
            detail = ErrorDetailInfo(
                code=code,
                code_name=error_code_name(code),
                message=grpc_details,
            )

    message = detail.message if (detail is not None and detail.message) else grpc_details
    exc_cls = ERROR_CODE_CLASSES.get(code, ForkloomError)
    return exc_cls(
        message,
        error_code=code,
        grpc_code=grpc_code,
        detail=detail,
        cause=exc,
    )
