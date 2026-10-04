"""Explicit live-IVT DOS vector services for initialized real16 execution.

Layer: dosunit concrete execution contracts.
Responsibility: bind INT21 vector query/update summaries to declared IVT bytes
and one unchanged external DOS entry. No interrupt handler body is inferred;
redirecting DOS dispatch or writing an active return frame remains unsupported.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.real16_replay_model import LinearRange, SegOffset

IVT_BYTES: int = 1024
VECTOR_BYTES: int = 4
DOS_VECTOR: int = 0x21
DOS_VECTOR_RANGE: LinearRange = LinearRange(DOS_VECTOR * VECTOR_BYTES, VECTOR_BYTES)


class VectorRefusal(StrEnum):
    """Unmodeled dispatch or a vector operation outside its declared scope."""

    DOS_REDIRECTED = "dos_vector_redirected"
    DOS_UPDATE = "dos_vector_update_requires_handler_execution"
    FRAME_ALIAS = "interrupt_frame_overlaps_dos_vector"
    OWNED_HANDLER = "dos_vector_points_to_program_code"
    POLICY_REQUIRED = "declared_dos_vector_requires_policy"


def vector_bytes(target: SegOffset) -> bytes:
    """Encode an IVT far pointer in architectural offset-then-segment order."""
    return target.offset.to_bytes(2, "little") + target.segment.to_bytes(2, "little")


@dataclass(frozen=True, slots=True)
class VectorPolicy:
    """Declare the external DOS entry whose unchanged IVT slot enables summaries.

    The IVT itself is supplied through the ordinary initial-memory declaration,
    not synthesized from this policy. AH35 reads live slots; AH25 writes live
    slots; changing slot21 needs an actual handler execution model. Writing
    its existing pointer back is admitted because DOS dispatch stays unchanged.
    """

    dos_entry: SegOffset

    def __post_init__(self) -> None:
        """Reject untyped coordinates, including bool masquerades."""
        if not isinstance(self.dos_entry, SegOffset):
            raise ValueError("DOS vector entry requires explicit segmented coordinates")
        if type(self.dos_entry.segment) is not int or type(self.dos_entry.offset) is not int:
            raise ValueError("DOS vector coordinates must be integer words")


def check_vector_policy(policy: VectorPolicy | None, memory: ProgramMemoryLayout) -> None:
    """Require every IVT byte to be explicitly initialized before execution."""
    if policy is None:
        return
    if not isinstance(policy, VectorPolicy):
        raise ValueError("vector_policy requires a typed VectorPolicy")
    if not memory.contains(0, IVT_BYTES):
        raise ValueError("vector policy requires the complete declared 1024-byte IVT")


def vector_policy_document(policy: VectorPolicy | None) -> dict[str, object] | None:
    """Bind enabled vector services and the external DOS entry into identities."""
    if policy is None:
        return None
    return {"dos_entry": {"segment": policy.dos_entry.segment, "offset": policy.dos_entry.offset}}


def parse_vector_policy(value: object) -> VectorPolicy | None:
    """Parse an explicit DOS entry; missing policy leaves AH25/AH35 refused."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"dos_entry"}:
        raise ValueError("dos_vectors requires exactly dos_entry")
    entry = value["dos_entry"]
    if not isinstance(entry, dict) or set(entry) != {"segment", "offset"}:
        raise ValueError("dos_entry requires segment and offset")
    segment, offset = entry["segment"], entry["offset"]
    if type(segment) is not int or type(offset) is not int:
        raise ValueError("dos_entry coordinates must be integer words")
    return VectorPolicy(SegOffset(segment, offset))


def vector_event_data(function: int, vector: int, before: bytes, after: bytes) -> bytes:
    """Retain the exact observed or changed slot, independent of code addresses."""
    data = bytes((DOS_VECTOR, function, vector)) + before + after
    if not vector_receipt_complete(data):
        raise ValueError("invalid DOS vector receipt")
    return data


def vector_receipt_complete(data: bytes) -> bool:
    """Reject malformed query/update evidence and unsupported DOS redirection."""
    if type(data) is not bytes or len(data) != 11 or data[0] != DOS_VECTOR:
        return False
    if data[1] == 0x35:
        return data[3:7] == data[7:11]
    return data[1] == 0x25 and (data[2] != DOS_VECTOR or data[3:7] == data[7:11])
