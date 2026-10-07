"""Bounded caller-declared INT10/AH=0F video-state query contract for initialized real16 replay.

Layer: dosunit concrete execution contracts.
Responsibility: declare the typed policy, identity projection, manifest
parsing, deterministic report payload and receipt predicate for the
video-state query (INT 0x10, AH=0x0F) available to whole-program replay.
The contract is an explicit synthetic environment declaration: the caller
states the exact display mode (AL), screen-column count (AH) and active
page (BH) a query observes, plus the segmented service ``entry`` the
declared IVT slot 0x10 must target. Nothing here models an installed BIOS
or infers host video state; the declared fields are bounded
caller-supplied data, never proof of real firmware behavior. The
execution owner — not this module — checks the live IVT slot, the
interrupt frame, executable-alias and service scope before consuming one
declared answer, and performs every guest write. An accepted query's
response effect is the three documented register-byte updates
(AL=mode, AH=columns, BH=page); preserving every other register bit, flag
and segment is the executor's obligation, as are architectural INT stack
writes. No other INT10 service is modeled.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.runtime.real16_replay_model import SegOffset

# INT10/AH=0F is Get Video State; it is the only admitted video service.
VIDEO_VECTOR: int = 0x10
VIDEO_FUNCTION: int = 0x0F

# The deterministic report payload for one answered query:
# vector, function, then the declared mode, columns and page bytes.
VIDEO_QUERY_PREFIX: bytes = bytes((VIDEO_VECTOR, VIDEO_FUNCTION))
VIDEO_QUERY_EVENT_BYTES: int = 5

_U8_MAX: int = 0xFF


def _checked_u8(value: int, name: str) -> int:
    """Validate one 8-bit domain field, rejecting bool masquerades."""
    if type(value) is not int or not 0 <= value <= _U8_MAX:
        raise ValueError(f"{name} must be an 8-bit unsigned integer")
    return value


@dataclass(frozen=True, slots=True)
class VideoQueryPolicy:
    """Explicit caller-declared video-state answer and service entry.

    ``mode``, ``columns`` and ``page`` are the exact AL, AH and BH bytes a
    single INT 0x10/AH=0x0F query observes. ``entry`` is the segmented
    service target the caller declares for IVT slot 0x10; the executor
    must confirm the live vector still targets it, that the interrupt
    frame does not alias it and that the dispatch stays inside the
    declared service scope before consuming these bytes. The policy is
    immutable, has no defaults and carries no runtime state: one declared
    policy answers every admitted query identically and never claims an
    installed BIOS exists.
    """

    mode: int
    columns: int
    page: int
    entry: SegOffset

    def __post_init__(self) -> None:
        """Bind the declared bytes and reject untyped segmented coordinates."""
        _checked_u8(self.mode, "video mode")
        _checked_u8(self.columns, "video columns")
        _checked_u8(self.page, "video page")
        if not isinstance(self.entry, SegOffset):
            raise ValueError("video query entry requires explicit segmented coordinates")
        if type(self.entry.segment) is not int or type(self.entry.offset) is not int:
            raise ValueError("video query entry coordinates must be integer words")


def video_query_event_data(policy: VideoQueryPolicy) -> bytes:
    """Return the deterministic 5-byte report payload for one answered query.

    The payload is vector, function, then the declared mode, columns and
    page bytes — the complete declared response so a report reader never
    needs to re-derive it. ``entry`` is service routing evidence owned by
    the executor's IVT checks, not part of the answer payload.
    """
    if not isinstance(policy, VideoQueryPolicy):
        raise ValueError("video query event data requires a declared VideoQueryPolicy")
    data = VIDEO_QUERY_PREFIX + bytes((policy.mode, policy.columns, policy.page))
    if not video_query_receipt_complete(data):
        raise ValueError("invalid video query receipt")
    return data


def video_query_receipt_complete(data: bytes) -> bool:
    """Reject truncated, extended or differently selected service receipts."""
    return (
        type(data) is bytes
        and len(data) == VIDEO_QUERY_EVENT_BYTES
        and data[:2] == VIDEO_QUERY_PREFIX
    )


def video_policy_document(policy: VideoQueryPolicy | None) -> dict[str, object] | None:
    """Project the declared video state and entry into deterministic identity data."""
    if policy is None:
        return None
    if not isinstance(policy, VideoQueryPolicy):
        raise ValueError("video document requires a declared VideoQueryPolicy or None")
    return {
        "mode": policy.mode,
        "columns": policy.columns,
        "page": policy.page,
        "entry": {"segment": policy.entry.segment, "offset": policy.entry.offset},
    }


def _integer(value: object, name: str) -> int:
    """Accept explicit JSON integers/hex strings, never bool or float aliases."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name}: invalid integer") from error
    raise ValueError(f"{name}: expected integer")


def _object(value: object, keys: set[str], name: str) -> dict[str, object]:
    """Require exactly the declared JSON members, without ignored fields."""
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name}: expected exactly {sorted(keys)}")
    return value


def parse_video_policy(value: object) -> VideoQueryPolicy | None:
    """Read an explicit video-state object; absence keeps the service refused.

    The object must declare exactly ``mode``, ``columns``, ``page`` and
    ``entry`` — unknown or missing fields are malformed. Each state field
    must be an explicit integer or hexadecimal string inside the 8-bit
    domain; ``entry`` must declare exactly ``segment`` and ``offset`` as
    explicit integers or hexadecimal strings inside the 16-bit word
    domain. ``None`` declares "no video-state service" and every query
    refuses.
    """
    if value is None:
        return None
    declared = _object(value, {"mode", "columns", "page", "entry"}, "bios_video")
    entry = _object(declared["entry"], {"segment", "offset"}, "bios_video entry")
    return VideoQueryPolicy(
        _integer(declared["mode"], "bios_video mode"),
        _integer(declared["columns"], "bios_video columns"),
        _integer(declared["page"], "bios_video page"),
        SegOffset(
            _integer(entry["segment"], "bios_video entry segment"),
            _integer(entry["offset"], "bios_video entry offset"),
        ),
    )
