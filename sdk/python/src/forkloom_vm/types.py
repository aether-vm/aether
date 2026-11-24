"""Common constants, target normalization, and protobuf value helpers for Forkloom."""

from __future__ import annotations

import os
import re
import uuid
from typing import TypeAlias

from ._proto.forkloom.v1 import runtime_pb2 as pb

#: Package version lockstep-aligned with `agentd`.
CLIENT_VERSION: str = "0.1.0a0"
#: Required `forkloom.v1` API major version verified during `NegotiateVersion`.
SUPPORTED_API_MAJOR: int = 1
#: Default client identifier sent in `NegotiateVersionRequest.client_name`.
DEFAULT_CLIENT_NAME: str = "forkloom-py"
#: Default `agentd` Unix Domain Socket path (`crates/agentd/src/transport.rs`).
DEFAULT_SOCKET_PATH: str = "/run/forkloom/agentd.sock"
#: Default gRPC UDS target URI.
DEFAULT_TARGET: str = f"unix://{DEFAULT_SOCKET_PATH}"
#: Environment variable overriding the default socket path.
SOCKET_ENV_VAR: str = "FORKLOOM_SOCKET"

FencingTokenInput: TypeAlias = int | pb.FencingToken

# Re-exported protobuf enums for concise caller imports.
FrameDurability = pb.FrameDurability
FrameStateKind = pb.FrameStateKind
WorldStateKind = pb.WorldStateKind
DriverKind = pb.DriverKind
OutputStreamKind = pb.OutputStreamKind
ErrorCode = pb.ErrorCode

_URI_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_HOST_PORT_RE = re.compile(r"^(?:\[[^\]]+\]|[a-zA-Z0-9.-]+):\d+$")


def normalize_target(target: str | os.PathLike[str] | None = None) -> str:
    """Normalize a socket path or gRPC target into a gRPC channel target string.

    Defaults to ``$FORKLOOM_SOCKET`` or ``unix:///run/forkloom/agentd.sock``.
    Bare Unix filesystem paths (e.g. ``/run/forkloom/agentd.sock`` or
    ``./agentd.sock``) are normalized to ``unix://...`` / ``unix:...`` URIs so
    Unix Domain Sockets remain the default transport.
    """
    raw = os.fspath(target) if target is not None else os.environ.get(
        SOCKET_ENV_VAR, DEFAULT_SOCKET_PATH
    )
    raw = raw.strip()
    if not raw:
        raw = DEFAULT_SOCKET_PATH

    if raw.startswith(("unix://", "unix:")):
        return raw
    if _HOST_PORT_RE.match(raw):
        return raw
    if _URI_SCHEME_RE.match(raw):
        # Preserve explicit gRPC resolver schemes (dns:, ipv4:, ipv6:, etc.).
        # On Windows drive paths like C:\foo won't normally be UDS, pass through.
        return raw
    if raw.startswith("/"):
        return f"unix://{raw}"
    return f"unix:{raw}"


def idempotency_key(owner: str, request_id: str | None = None) -> pb.IdempotencyKey:
    """Create a ``forkloom.v1.IdempotencyKey`` (auto-generating a UUIDv4 if omitted)."""
    if not owner:
        raise ValueError("owner must be non-empty")
    rid = request_id if request_id is not None else uuid.uuid4().hex
    if not rid:
        raise ValueError("request_id must be non-empty")
    return pb.IdempotencyKey(owner=owner, request_id=rid)


def fencing_token(value: FencingTokenInput) -> pb.FencingToken:
    """Create or validate a monotonic non-zero ``forkloom.v1.FencingToken``."""
    if isinstance(value, pb.FencingToken):
        if value.value <= 0:
            raise ValueError("fencing_token must be > 0")
        return value
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError("fencing_token must be a positive integer")
    return pb.FencingToken(value=value)


def pin_spec(pin_id: str, owner: str, lease_ttl_ms: int = 0) -> pb.PinSpec:
    """Create a ``forkloom.v1.PinSpec``."""
    if not pin_id:
        raise ValueError("pin_id must be non-empty")
    if not owner:
        raise ValueError("owner must be non-empty")
    if lease_ttl_ms < 0:
        raise ValueError("lease_ttl_ms must be >= 0")
    return pb.PinSpec(pin_id=pin_id, owner=owner, lease_ttl_ms=lease_ttl_ms)
