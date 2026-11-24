from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class FrameDurability(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FRAME_DURABILITY_UNSPECIFIED: _ClassVar[FrameDurability]
    FRAME_DURABILITY_DURABLE: _ClassVar[FrameDurability]
    FRAME_DURABILITY_VOLATILE: _ClassVar[FrameDurability]

class FrameStateKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FRAME_STATE_UNSPECIFIED: _ClassVar[FrameStateKind]
    FRAME_STATE_PREPARING: _ClassVar[FrameStateKind]
    FRAME_STATE_COMMITTED: _ClassVar[FrameStateKind]
    FRAME_STATE_DELETING: _ClassVar[FrameStateKind]

class WorldStateKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    WORLD_STATE_UNSPECIFIED: _ClassVar[WorldStateKind]
    WORLD_STATE_RUNNING: _ClassVar[WorldStateKind]
    WORLD_STATE_DESTROYED: _ClassVar[WorldStateKind]
    WORLD_STATE_LOST: _ClassVar[WorldStateKind]

class DriverKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DRIVER_KIND_UNSPECIFIED: _ClassVar[DriverKind]
    DRIVER_KIND_NAMESPACE: _ClassVar[DriverKind]
    DRIVER_KIND_FIRECRACKER: _ClassVar[DriverKind]

class OutputStreamKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OUTPUT_STREAM_UNSPECIFIED: _ClassVar[OutputStreamKind]
    OUTPUT_STREAM_STDOUT: _ClassVar[OutputStreamKind]
    OUTPUT_STREAM_STDERR: _ClassVar[OutputStreamKind]

class ErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ERROR_CODE_UNSPECIFIED: _ClassVar[ErrorCode]
    ERROR_CODE_WORLD_LOST: _ClassVar[ErrorCode]
    ERROR_CODE_OUTCOME_UNKNOWN: _ClassVar[ErrorCode]
    ERROR_CODE_FENCED_OUT: _ClassVar[ErrorCode]
    ERROR_CODE_FRAME_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_WORLD_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_TIMELINE_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_TIMELINE_CAS_MISMATCH: _ClassVar[ErrorCode]
    ERROR_CODE_IDEMPOTENCY_CONFLICT: _ClassVar[ErrorCode]
    ERROR_CODE_OWNER_MISMATCH: _ClassVar[ErrorCode]
    ERROR_CODE_RESOURCE_EXHAUSTED: _ClassVar[ErrorCode]
    ERROR_CODE_UNSAFE_PATCH: _ClassVar[ErrorCode]
    ERROR_CODE_DISK_NOT_CLEAN: _ClassVar[ErrorCode]
    ERROR_CODE_INVALID_ARGUMENT: _ClassVar[ErrorCode]
    ERROR_CODE_DRIVER_UNAVAILABLE: _ClassVar[ErrorCode]
    ERROR_CODE_WORLD_NOT_RUNNING: _ClassVar[ErrorCode]
    ERROR_CODE_VOLATILE_IN_TIMELINE_FORBIDDEN: _ClassVar[ErrorCode]
    ERROR_CODE_PIN_NOT_FOUND: _ClassVar[ErrorCode]
    ERROR_CODE_FRAME_MARKED_FOR_DELETION: _ClassVar[ErrorCode]
    ERROR_CODE_PREPARED_FRAME_ABORTED: _ClassVar[ErrorCode]
    ERROR_CODE_INTERNAL: _ClassVar[ErrorCode]
FRAME_DURABILITY_UNSPECIFIED: FrameDurability
FRAME_DURABILITY_DURABLE: FrameDurability
FRAME_DURABILITY_VOLATILE: FrameDurability
FRAME_STATE_UNSPECIFIED: FrameStateKind
FRAME_STATE_PREPARING: FrameStateKind
FRAME_STATE_COMMITTED: FrameStateKind
FRAME_STATE_DELETING: FrameStateKind
WORLD_STATE_UNSPECIFIED: WorldStateKind
WORLD_STATE_RUNNING: WorldStateKind
WORLD_STATE_DESTROYED: WorldStateKind
WORLD_STATE_LOST: WorldStateKind
DRIVER_KIND_UNSPECIFIED: DriverKind
DRIVER_KIND_NAMESPACE: DriverKind
DRIVER_KIND_FIRECRACKER: DriverKind
OUTPUT_STREAM_UNSPECIFIED: OutputStreamKind
OUTPUT_STREAM_STDOUT: OutputStreamKind
OUTPUT_STREAM_STDERR: OutputStreamKind
ERROR_CODE_UNSPECIFIED: ErrorCode
ERROR_CODE_WORLD_LOST: ErrorCode
ERROR_CODE_OUTCOME_UNKNOWN: ErrorCode
ERROR_CODE_FENCED_OUT: ErrorCode
ERROR_CODE_FRAME_NOT_FOUND: ErrorCode
ERROR_CODE_WORLD_NOT_FOUND: ErrorCode
ERROR_CODE_TIMELINE_NOT_FOUND: ErrorCode
ERROR_CODE_TIMELINE_CAS_MISMATCH: ErrorCode
ERROR_CODE_IDEMPOTENCY_CONFLICT: ErrorCode
ERROR_CODE_OWNER_MISMATCH: ErrorCode
ERROR_CODE_RESOURCE_EXHAUSTED: ErrorCode
ERROR_CODE_UNSAFE_PATCH: ErrorCode
ERROR_CODE_DISK_NOT_CLEAN: ErrorCode
ERROR_CODE_INVALID_ARGUMENT: ErrorCode
ERROR_CODE_DRIVER_UNAVAILABLE: ErrorCode
ERROR_CODE_WORLD_NOT_RUNNING: ErrorCode
ERROR_CODE_VOLATILE_IN_TIMELINE_FORBIDDEN: ErrorCode
ERROR_CODE_PIN_NOT_FOUND: ErrorCode
ERROR_CODE_FRAME_MARKED_FOR_DELETION: ErrorCode
ERROR_CODE_PREPARED_FRAME_ABORTED: ErrorCode
ERROR_CODE_INTERNAL: ErrorCode

class NegotiateVersionRequest(_message.Message):
    __slots__ = ("client_name", "client_version", "supported_api_major")
    CLIENT_NAME_FIELD_NUMBER: _ClassVar[int]
    CLIENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    SUPPORTED_API_MAJOR_FIELD_NUMBER: _ClassVar[int]
    client_name: str
    client_version: str
    supported_api_major: int
    def __init__(self, client_name: _Optional[str] = ..., client_version: _Optional[str] = ..., supported_api_major: _Optional[int] = ...) -> None: ...

class NegotiateVersionResponse(_message.Message):
    __slots__ = ("daemon_version", "api_major", "api_minor", "daemon_epoch", "enabled_drivers")
    DAEMON_VERSION_FIELD_NUMBER: _ClassVar[int]
    API_MAJOR_FIELD_NUMBER: _ClassVar[int]
    API_MINOR_FIELD_NUMBER: _ClassVar[int]
    DAEMON_EPOCH_FIELD_NUMBER: _ClassVar[int]
    ENABLED_DRIVERS_FIELD_NUMBER: _ClassVar[int]
    daemon_version: str
    api_major: int
    api_minor: int
    daemon_epoch: int
    enabled_drivers: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, daemon_version: _Optional[str] = ..., api_major: _Optional[int] = ..., api_minor: _Optional[int] = ..., daemon_epoch: _Optional[int] = ..., enabled_drivers: _Optional[_Iterable[str]] = ...) -> None: ...

class ErrorDetail(_message.Message):
    __slots__ = ("code", "message", "resource_id", "current_fencing_token", "presented_fencing_token", "origin_epoch", "lost_in_epoch")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_ID_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PRESENTED_FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_EPOCH_FIELD_NUMBER: _ClassVar[int]
    LOST_IN_EPOCH_FIELD_NUMBER: _ClassVar[int]
    code: ErrorCode
    message: str
    resource_id: str
    current_fencing_token: int
    presented_fencing_token: int
    origin_epoch: int
    lost_in_epoch: int
    def __init__(self, code: _Optional[_Union[ErrorCode, str]] = ..., message: _Optional[str] = ..., resource_id: _Optional[str] = ..., current_fencing_token: _Optional[int] = ..., presented_fencing_token: _Optional[int] = ..., origin_epoch: _Optional[int] = ..., lost_in_epoch: _Optional[int] = ...) -> None: ...

class IdempotencyKey(_message.Message):
    __slots__ = ("owner", "request_id")
    OWNER_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    owner: str
    request_id: str
    def __init__(self, owner: _Optional[str] = ..., request_id: _Optional[str] = ...) -> None: ...

class FencingToken(_message.Message):
    __slots__ = ("value",)
    VALUE_FIELD_NUMBER: _ClassVar[int]
    value: int
    def __init__(self, value: _Optional[int] = ...) -> None: ...

class PinSpec(_message.Message):
    __slots__ = ("pin_id", "owner", "lease_ttl_ms")
    PIN_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    LEASE_TTL_MS_FIELD_NUMBER: _ClassVar[int]
    pin_id: str
    owner: str
    lease_ttl_ms: int
    def __init__(self, pin_id: _Optional[str] = ..., owner: _Optional[str] = ..., lease_ttl_ms: _Optional[int] = ...) -> None: ...

class HoldInfo(_message.Message):
    __slots__ = ("kind", "detail", "expires_at_ms")
    KIND_FIELD_NUMBER: _ClassVar[int]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    detail: str
    expires_at_ms: int
    def __init__(self, kind: _Optional[str] = ..., detail: _Optional[str] = ..., expires_at_ms: _Optional[int] = ...) -> None: ...

class FrameInfo(_message.Message):
    __slots__ = ("frame_id", "owner", "durability", "state", "parent_frame_id", "labels", "disk_clean", "created_epoch", "committed_at_ms", "objects", "holds", "marked_for_reclaim")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    DURABILITY_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    PARENT_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    DISK_CLEAN_FIELD_NUMBER: _ClassVar[int]
    CREATED_EPOCH_FIELD_NUMBER: _ClassVar[int]
    COMMITTED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    OBJECTS_FIELD_NUMBER: _ClassVar[int]
    HOLDS_FIELD_NUMBER: _ClassVar[int]
    MARKED_FOR_RECLAIM_FIELD_NUMBER: _ClassVar[int]
    frame_id: str
    owner: str
    durability: FrameDurability
    state: FrameStateKind
    parent_frame_id: str
    labels: _containers.ScalarMap[str, str]
    disk_clean: bool
    created_epoch: int
    committed_at_ms: int
    objects: _containers.RepeatedScalarFieldContainer[str]
    holds: _containers.RepeatedCompositeFieldContainer[HoldInfo]
    marked_for_reclaim: bool
    def __init__(self, frame_id: _Optional[str] = ..., owner: _Optional[str] = ..., durability: _Optional[_Union[FrameDurability, str]] = ..., state: _Optional[_Union[FrameStateKind, str]] = ..., parent_frame_id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., disk_clean: _Optional[bool] = ..., created_epoch: _Optional[int] = ..., committed_at_ms: _Optional[int] = ..., objects: _Optional[_Iterable[str]] = ..., holds: _Optional[_Iterable[_Union[HoldInfo, _Mapping]]] = ..., marked_for_reclaim: _Optional[bool] = ...) -> None: ...

class TimelineInfo(_message.Message):
    __slots__ = ("name", "owner", "head_frame_id")
    NAME_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    HEAD_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    name: str
    owner: str
    head_frame_id: str
    def __init__(self, name: _Optional[str] = ..., owner: _Optional[str] = ..., head_frame_id: _Optional[str] = ...) -> None: ...

class WorldInfo(_message.Message):
    __slots__ = ("world_id", "owner", "base_frame_id", "driver", "state", "labels", "fencing_token", "origin_epoch", "lost_in_epoch", "ended_at_ms", "end_reason")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    BASE_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ORIGIN_EPOCH_FIELD_NUMBER: _ClassVar[int]
    LOST_IN_EPOCH_FIELD_NUMBER: _ClassVar[int]
    ENDED_AT_MS_FIELD_NUMBER: _ClassVar[int]
    END_REASON_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    base_frame_id: str
    driver: DriverKind
    state: WorldStateKind
    labels: _containers.ScalarMap[str, str]
    fencing_token: FencingToken
    origin_epoch: int
    lost_in_epoch: int
    ended_at_ms: int
    end_reason: str
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ..., base_frame_id: _Optional[str] = ..., driver: _Optional[_Union[DriverKind, str]] = ..., state: _Optional[_Union[WorldStateKind, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ..., origin_epoch: _Optional[int] = ..., lost_in_epoch: _Optional[int] = ..., ended_at_ms: _Optional[int] = ..., end_reason: _Optional[str] = ...) -> None: ...

class BoundedOutput(_message.Message):
    __slots__ = ("head", "tail", "total_bytes", "omitted_bytes", "truncated")
    HEAD_FIELD_NUMBER: _ClassVar[int]
    TAIL_FIELD_NUMBER: _ClassVar[int]
    TOTAL_BYTES_FIELD_NUMBER: _ClassVar[int]
    OMITTED_BYTES_FIELD_NUMBER: _ClassVar[int]
    TRUNCATED_FIELD_NUMBER: _ClassVar[int]
    head: bytes
    tail: bytes
    total_bytes: int
    omitted_bytes: int
    truncated: bool
    def __init__(self, head: _Optional[bytes] = ..., tail: _Optional[bytes] = ..., total_bytes: _Optional[int] = ..., omitted_bytes: _Optional[int] = ..., truncated: _Optional[bool] = ...) -> None: ...

class ImportTarHeader(_message.Message):
    __slots__ = ("owner", "durability", "parent_frame_id", "labels", "pin", "timeline_name", "expected_old_timeline_head", "idempotency_key")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    OWNER_FIELD_NUMBER: _ClassVar[int]
    DURABILITY_FIELD_NUMBER: _ClassVar[int]
    PARENT_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_NAME_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_OLD_TIMELINE_HEAD_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    owner: str
    durability: FrameDurability
    parent_frame_id: str
    labels: _containers.ScalarMap[str, str]
    pin: PinSpec
    timeline_name: str
    expected_old_timeline_head: str
    idempotency_key: IdempotencyKey
    def __init__(self, owner: _Optional[str] = ..., durability: _Optional[_Union[FrameDurability, str]] = ..., parent_frame_id: _Optional[str] = ..., labels: _Optional[_Mapping[str, str]] = ..., pin: _Optional[_Union[PinSpec, _Mapping]] = ..., timeline_name: _Optional[str] = ..., expected_old_timeline_head: _Optional[str] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class ImportTarRequest(_message.Message):
    __slots__ = ("header", "data")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    header: ImportTarHeader
    data: bytes
    def __init__(self, header: _Optional[_Union[ImportTarHeader, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ImportTarResponse(_message.Message):
    __slots__ = ("frame", "timeline", "bytes_received")
    FRAME_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    BYTES_RECEIVED_FIELD_NUMBER: _ClassVar[int]
    frame: FrameInfo
    timeline: TimelineInfo
    bytes_received: int
    def __init__(self, frame: _Optional[_Union[FrameInfo, _Mapping]] = ..., timeline: _Optional[_Union[TimelineInfo, _Mapping]] = ..., bytes_received: _Optional[int] = ...) -> None: ...

class GetFrameRequest(_message.Message):
    __slots__ = ("frame_id",)
    FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    frame_id: str
    def __init__(self, frame_id: _Optional[str] = ...) -> None: ...

class GetFrameResponse(_message.Message):
    __slots__ = ("frame",)
    FRAME_FIELD_NUMBER: _ClassVar[int]
    frame: FrameInfo
    def __init__(self, frame: _Optional[_Union[FrameInfo, _Mapping]] = ...) -> None: ...

class ListFramesRequest(_message.Message):
    __slots__ = ("owner", "label_selector", "include_non_committed")
    class LabelSelectorEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    OWNER_FIELD_NUMBER: _ClassVar[int]
    LABEL_SELECTOR_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_NON_COMMITTED_FIELD_NUMBER: _ClassVar[int]
    owner: str
    label_selector: _containers.ScalarMap[str, str]
    include_non_committed: bool
    def __init__(self, owner: _Optional[str] = ..., label_selector: _Optional[_Mapping[str, str]] = ..., include_non_committed: _Optional[bool] = ...) -> None: ...

class ListFramesResponse(_message.Message):
    __slots__ = ("frames",)
    FRAMES_FIELD_NUMBER: _ClassVar[int]
    frames: _containers.RepeatedCompositeFieldContainer[FrameInfo]
    def __init__(self, frames: _Optional[_Iterable[_Union[FrameInfo, _Mapping]]] = ...) -> None: ...

class PinFrameRequest(_message.Message):
    __slots__ = ("frame_id", "pin")
    FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    frame_id: str
    pin: PinSpec
    def __init__(self, frame_id: _Optional[str] = ..., pin: _Optional[_Union[PinSpec, _Mapping]] = ...) -> None: ...

class PinFrameResponse(_message.Message):
    __slots__ = ("hold",)
    HOLD_FIELD_NUMBER: _ClassVar[int]
    hold: HoldInfo
    def __init__(self, hold: _Optional[_Union[HoldInfo, _Mapping]] = ...) -> None: ...

class RenewPinRequest(_message.Message):
    __slots__ = ("frame_id", "pin_id", "owner")
    FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    PIN_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    frame_id: str
    pin_id: str
    owner: str
    def __init__(self, frame_id: _Optional[str] = ..., pin_id: _Optional[str] = ..., owner: _Optional[str] = ...) -> None: ...

class RenewPinResponse(_message.Message):
    __slots__ = ("expires_at_ms", "persisted_to_disk")
    EXPIRES_AT_MS_FIELD_NUMBER: _ClassVar[int]
    PERSISTED_TO_DISK_FIELD_NUMBER: _ClassVar[int]
    expires_at_ms: int
    persisted_to_disk: bool
    def __init__(self, expires_at_ms: _Optional[int] = ..., persisted_to_disk: _Optional[bool] = ...) -> None: ...

class DeleteFrameRequest(_message.Message):
    __slots__ = ("frame_id", "owner", "idempotency_key")
    FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    frame_id: str
    owner: str
    idempotency_key: IdempotencyKey
    def __init__(self, frame_id: _Optional[str] = ..., owner: _Optional[str] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class DeleteFrameResponse(_message.Message):
    __slots__ = ("deleted", "deferred", "remaining_holds")
    DELETED_FIELD_NUMBER: _ClassVar[int]
    DEFERRED_FIELD_NUMBER: _ClassVar[int]
    REMAINING_HOLDS_FIELD_NUMBER: _ClassVar[int]
    deleted: bool
    deferred: bool
    remaining_holds: int
    def __init__(self, deleted: _Optional[bool] = ..., deferred: _Optional[bool] = ..., remaining_holds: _Optional[int] = ...) -> None: ...

class AdvanceTimelineRequest(_message.Message):
    __slots__ = ("timeline", "owner", "expected_old_frame_id", "new_head_frame_id", "idempotency_key")
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_OLD_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    NEW_HEAD_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    timeline: str
    owner: str
    expected_old_frame_id: str
    new_head_frame_id: str
    idempotency_key: IdempotencyKey
    def __init__(self, timeline: _Optional[str] = ..., owner: _Optional[str] = ..., expected_old_frame_id: _Optional[str] = ..., new_head_frame_id: _Optional[str] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class AdvanceTimelineResponse(_message.Message):
    __slots__ = ("timeline", "previous_head_frame_id")
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_HEAD_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    timeline: TimelineInfo
    previous_head_frame_id: str
    def __init__(self, timeline: _Optional[_Union[TimelineInfo, _Mapping]] = ..., previous_head_frame_id: _Optional[str] = ...) -> None: ...

class DeleteTimelineRequest(_message.Message):
    __slots__ = ("timeline", "owner", "idempotency_key")
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    timeline: str
    owner: str
    idempotency_key: IdempotencyKey
    def __init__(self, timeline: _Optional[str] = ..., owner: _Optional[str] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class DeleteTimelineResponse(_message.Message):
    __slots__ = ("released_head_frame_id",)
    RELEASED_HEAD_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    released_head_frame_id: str
    def __init__(self, released_head_frame_id: _Optional[str] = ...) -> None: ...

class ExportPatchRequest(_message.Message):
    __slots__ = ("target_frame_id", "base_frame_id", "owner")
    TARGET_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    BASE_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    target_frame_id: str
    base_frame_id: str
    owner: str
    def __init__(self, target_frame_id: _Optional[str] = ..., base_frame_id: _Optional[str] = ..., owner: _Optional[str] = ...) -> None: ...

class PatchEntry(_message.Message):
    __slots__ = ("path", "kind", "size_bytes")
    PATH_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
    path: str
    kind: str
    size_bytes: int
    def __init__(self, path: _Optional[str] = ..., kind: _Optional[str] = ..., size_bytes: _Optional[int] = ...) -> None: ...

class ExportPatchResponse(_message.Message):
    __slots__ = ("base_frame_id", "target_frame_id", "unified_diff", "entries", "blake3_hex")
    BASE_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    TARGET_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    UNIFIED_DIFF_FIELD_NUMBER: _ClassVar[int]
    ENTRIES_FIELD_NUMBER: _ClassVar[int]
    BLAKE3_HEX_FIELD_NUMBER: _ClassVar[int]
    base_frame_id: str
    target_frame_id: str
    unified_diff: bytes
    entries: _containers.RepeatedCompositeFieldContainer[PatchEntry]
    blake3_hex: str
    def __init__(self, base_frame_id: _Optional[str] = ..., target_frame_id: _Optional[str] = ..., unified_diff: _Optional[bytes] = ..., entries: _Optional[_Iterable[_Union[PatchEntry, _Mapping]]] = ..., blake3_hex: _Optional[str] = ...) -> None: ...

class CreateWorldRequest(_message.Message):
    __slots__ = ("owner", "base_frame_id", "driver", "labels", "lease_ttl_ms", "idempotency_key")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    OWNER_FIELD_NUMBER: _ClassVar[int]
    BASE_FRAME_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    LEASE_TTL_MS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    owner: str
    base_frame_id: str
    driver: DriverKind
    labels: _containers.ScalarMap[str, str]
    lease_ttl_ms: int
    idempotency_key: IdempotencyKey
    def __init__(self, owner: _Optional[str] = ..., base_frame_id: _Optional[str] = ..., driver: _Optional[_Union[DriverKind, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., lease_ttl_ms: _Optional[int] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class CreateWorldResponse(_message.Message):
    __slots__ = ("world",)
    WORLD_FIELD_NUMBER: _ClassVar[int]
    world: WorldInfo
    def __init__(self, world: _Optional[_Union[WorldInfo, _Mapping]] = ...) -> None: ...

class GetWorldRequest(_message.Message):
    __slots__ = ("world_id",)
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    def __init__(self, world_id: _Optional[str] = ...) -> None: ...

class GetWorldResponse(_message.Message):
    __slots__ = ("world",)
    WORLD_FIELD_NUMBER: _ClassVar[int]
    world: WorldInfo
    def __init__(self, world: _Optional[_Union[WorldInfo, _Mapping]] = ...) -> None: ...

class DestroyWorldRequest(_message.Message):
    __slots__ = ("world_id", "owner", "fencing_token", "idempotency_key")
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    fencing_token: FencingToken
    idempotency_key: IdempotencyKey
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ..., fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class DestroyWorldResponse(_message.Message):
    __slots__ = ("world",)
    WORLD_FIELD_NUMBER: _ClassVar[int]
    world: WorldInfo
    def __init__(self, world: _Optional[_Union[WorldInfo, _Mapping]] = ...) -> None: ...

class AcquireFenceRequest(_message.Message):
    __slots__ = ("world_id", "owner")
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ...) -> None: ...

class AcquireFenceResponse(_message.Message):
    __slots__ = ("fencing_token",)
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    fencing_token: FencingToken
    def __init__(self, fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ...) -> None: ...

class RenewWorldLeaseRequest(_message.Message):
    __slots__ = ("world_id", "owner", "fencing_token")
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    fencing_token: FencingToken
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ..., fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ...) -> None: ...

class RenewWorldLeaseResponse(_message.Message):
    __slots__ = ("renewed_ttl_ms",)
    RENEWED_TTL_MS_FIELD_NUMBER: _ClassVar[int]
    renewed_ttl_ms: int
    def __init__(self, renewed_ttl_ms: _Optional[int] = ...) -> None: ...

class ExecRequest(_message.Message):
    __slots__ = ("world_id", "owner", "fencing_token", "argv", "env", "cwd", "timeout_ms", "max_output_bytes", "stream", "idempotency_key")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    ARGV_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    CWD_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MS_FIELD_NUMBER: _ClassVar[int]
    MAX_OUTPUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    STREAM_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    fencing_token: FencingToken
    argv: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    cwd: str
    timeout_ms: int
    max_output_bytes: int
    stream: bool
    idempotency_key: IdempotencyKey
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ..., fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ..., argv: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., cwd: _Optional[str] = ..., timeout_ms: _Optional[int] = ..., max_output_bytes: _Optional[int] = ..., stream: _Optional[bool] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class ExecOutputChunk(_message.Message):
    __slots__ = ("stream", "seq", "data")
    STREAM_FIELD_NUMBER: _ClassVar[int]
    SEQ_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    stream: OutputStreamKind
    seq: int
    data: bytes
    def __init__(self, stream: _Optional[_Union[OutputStreamKind, str]] = ..., seq: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class ExecResult(_message.Message):
    __slots__ = ("exec_id", "has_exit_code", "exit_code", "has_signal", "signal", "timed_out", "cgroup_killed", "duration_ms", "stdout", "stderr", "replayed_from_cache")
    EXEC_ID_FIELD_NUMBER: _ClassVar[int]
    HAS_EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    EXIT_CODE_FIELD_NUMBER: _ClassVar[int]
    HAS_SIGNAL_FIELD_NUMBER: _ClassVar[int]
    SIGNAL_FIELD_NUMBER: _ClassVar[int]
    TIMED_OUT_FIELD_NUMBER: _ClassVar[int]
    CGROUP_KILLED_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    REPLAYED_FROM_CACHE_FIELD_NUMBER: _ClassVar[int]
    exec_id: str
    has_exit_code: bool
    exit_code: int
    has_signal: bool
    signal: int
    timed_out: bool
    cgroup_killed: bool
    duration_ms: int
    stdout: BoundedOutput
    stderr: BoundedOutput
    replayed_from_cache: bool
    def __init__(self, exec_id: _Optional[str] = ..., has_exit_code: _Optional[bool] = ..., exit_code: _Optional[int] = ..., has_signal: _Optional[bool] = ..., signal: _Optional[int] = ..., timed_out: _Optional[bool] = ..., cgroup_killed: _Optional[bool] = ..., duration_ms: _Optional[int] = ..., stdout: _Optional[_Union[BoundedOutput, _Mapping]] = ..., stderr: _Optional[_Union[BoundedOutput, _Mapping]] = ..., replayed_from_cache: _Optional[bool] = ...) -> None: ...

class ExecEvent(_message.Message):
    __slots__ = ("chunk", "result")
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    chunk: ExecOutputChunk
    result: ExecResult
    def __init__(self, chunk: _Optional[_Union[ExecOutputChunk, _Mapping]] = ..., result: _Optional[_Union[ExecResult, _Mapping]] = ...) -> None: ...

class CheckpointRequest(_message.Message):
    __slots__ = ("world_id", "owner", "fencing_token", "durability", "labels", "pin", "timeline_name", "expected_old_timeline_head", "perform_syncfs", "idempotency_key")
    class LabelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    WORLD_ID_FIELD_NUMBER: _ClassVar[int]
    OWNER_FIELD_NUMBER: _ClassVar[int]
    FENCING_TOKEN_FIELD_NUMBER: _ClassVar[int]
    DURABILITY_FIELD_NUMBER: _ClassVar[int]
    LABELS_FIELD_NUMBER: _ClassVar[int]
    PIN_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_NAME_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_OLD_TIMELINE_HEAD_FIELD_NUMBER: _ClassVar[int]
    PERFORM_SYNCFS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    world_id: str
    owner: str
    fencing_token: FencingToken
    durability: FrameDurability
    labels: _containers.ScalarMap[str, str]
    pin: PinSpec
    timeline_name: str
    expected_old_timeline_head: str
    perform_syncfs: bool
    idempotency_key: IdempotencyKey
    def __init__(self, world_id: _Optional[str] = ..., owner: _Optional[str] = ..., fencing_token: _Optional[_Union[FencingToken, _Mapping]] = ..., durability: _Optional[_Union[FrameDurability, str]] = ..., labels: _Optional[_Mapping[str, str]] = ..., pin: _Optional[_Union[PinSpec, _Mapping]] = ..., timeline_name: _Optional[str] = ..., expected_old_timeline_head: _Optional[str] = ..., perform_syncfs: _Optional[bool] = ..., idempotency_key: _Optional[_Union[IdempotencyKey, _Mapping]] = ...) -> None: ...

class CheckpointResponse(_message.Message):
    __slots__ = ("frame", "timeline")
    FRAME_FIELD_NUMBER: _ClassVar[int]
    TIMELINE_FIELD_NUMBER: _ClassVar[int]
    frame: FrameInfo
    timeline: TimelineInfo
    def __init__(self, frame: _Optional[_Union[FrameInfo, _Mapping]] = ..., timeline: _Optional[_Union[TimelineInfo, _Mapping]] = ...) -> None: ...
